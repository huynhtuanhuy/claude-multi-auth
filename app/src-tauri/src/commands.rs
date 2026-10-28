//! The app's commands. Each one runs a `cma` command in-process
//! (`cma::embed`) on a blocking thread, so it takes the same lock →
//! recover → sync path as the CLI and returns the same JSON document (no
//! token is ever in it). Consent questions are native dialogs, shown only
//! after the command released its locks; nothing is ever consented to
//! without the user.
//!
//! Inputs from the webview are validated here before anything runs:
//! account keys must name a stored account exactly, setting names are a
//! fixed list, and free text has length and control-character limits.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use cma::{AliasCmd, Cmd, ConfigCmd, DesktopCmd, SwitchArgs};
use cma_core::paths::Paths;
use cma_core::registry::Registry;
use serde::Deserialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::{login, tray};

/// Longest alias the app accepts.
pub const ALIAS_MAX: usize = 64;
/// Settings the app may change (as `cma config set`).
pub const SETTING_KEYS: [&str; 5] = [
    "session_follow",
    "live_usage",
    "live_interval_secs",
    "default_target",
    "refresh_grace_secs",
];

/// App-wide state shared by commands, the tray and the watcher.
#[derive(Default)]
pub struct AppState {
    /// Serializes the app's own cma commands, so a background usage
    /// refresh and a click never trade `locked` errors with each other.
    pub gate: Mutex<()>,
    /// Bumped whenever cma state may have changed; the settings window
    /// polls it.
    pub stamp: AtomicU64,
    /// `registry.json` modification time last seen (by the watcher or
    /// after one of our commands).
    pub seen_mtime: Mutex<Option<SystemTime>>,
    /// A view the settings window should show next (`add`, `settings`).
    pub section: Mutex<Option<String>>,
    pub login_in_progress: AtomicBool,
    /// A problem the last `status` or command reported (sync error, state
    /// uncertain), shown in the tray until a later run clears it.
    pub problem: Mutex<Option<String>>,
    /// Quit has begun: no new cma operation may start (the exit would cut
    /// it off).
    pub quitting: AtomicBool,
}

impl AppState {
    pub fn bump(&self) {
        self.stamp.fetch_add(1, Ordering::SeqCst);
    }
}

/// A document shaped like `cma --json` output, for errors the app itself
/// detects (bad input, a failed blocking task).
pub fn error_doc(code: &str, message: impl Into<String>, hint: Option<&str>) -> Value {
    json!({
        "schema_version": 1,
        "ok": false,
        "data": null,
        "warnings": [],
        "error": {"code": code, "message": message.into(), "hint": hint},
        "state_uncertain": false,
    })
}

pub fn ok_doc(data: Value) -> Value {
    json!({
        "schema_version": 1,
        "ok": true,
        "data": data,
        "warnings": [],
        "error": null,
        "state_uncertain": false,
    })
}

/// Ask the user in a native dialog; `true` only when they agreed. Must not
/// run on the main thread (it blocks until answered).
pub fn ask(app: &AppHandle, question: &str) -> bool {
    ask_with(app, question, "Continue", "Cancel")
}

/// [`ask`] with other button labels (`yes` is the agreeing one).
fn ask_with(app: &AppHandle, question: &str, yes: &str, no: &str) -> bool {
    app.dialog()
        .message(question)
        .title("Claude Multi Auth")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(yes.into(), no.into()))
        .blocking_show()
}

/// Run one cma command on this (blocking, non-main) thread, waiting for
/// the app's other commands to finish first.
pub fn run_cmd(app: &AppHandle, cmd: Cmd, mutating: bool) -> Value {
    let state = app.state::<AppState>();
    if quitting(&state) {
        return quitting_doc();
    }
    let guard = state.gate.lock().unwrap_or_else(|e| e.into_inner());
    // Checked again once the gate is ours: Quit may have begun while this
    // command waited for it.
    if quitting(&state) {
        return quitting_doc();
    }
    run_locked(app, cmd, mutating, guard)
}

/// [`run_cmd`] only if no other app command is running (background work).
pub fn try_run_cmd(app: &AppHandle, cmd: Cmd) -> Option<Value> {
    let state = app.state::<AppState>();
    if quitting(&state) {
        return None;
    }
    let guard = state.gate.try_lock().ok()?;
    if quitting(&state) {
        return None;
    }
    Some(run_locked(app, cmd, true, guard))
}

pub fn quitting(state: &AppState) -> bool {
    state.quitting.load(Ordering::SeqCst)
}

pub fn quitting_doc() -> Value {
    error_doc(
        "quitting",
        "The app is quitting; nothing was started.",
        None,
    )
}

/// Whether `cmd` goes through cma's sync (`sync::begin`), so a success
/// shows the live login was read and recorded without a problem.
pub fn syncs(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::List { .. }
            | Cmd::Status
            | Cmd::Switch(_)
            | Cmd::Remove { .. }
            | Cmd::Alias(_)
            | Cmd::Usage { .. }
            | Cmd::Config(ConfigCmd::Set { .. })
            | Cmd::ImportCurrent { .. }
            | Cmd::Import { .. }
            | Cmd::Export { .. }
            | Cmd::Desktop(_)
    )
}

fn run_locked(
    app: &AppHandle,
    cmd: Cmd,
    mutating: bool,
    guard: std::sync::MutexGuard<'_, ()>,
) -> Value {
    let h = app.clone();
    let synced = syncs(&cmd) && !matches!(cmd, Cmd::Status);
    // `desktop link` asks "Signed in?" and "Switch back?", where No is an
    // answer, not a Cancel.
    let (yes, no) = if matches!(cmd, Cmd::Desktop(DesktopCmd::Link { .. })) {
        ("Yes", "No")
    } else {
        ("Continue", "Cancel")
    };
    let doc = run_asking(cmd, move |q| ask_with(&h, q, yes, no), cma::embed::run);
    drop(guard);
    note_problem(app, &doc, synced);
    if mutating {
        after_change(app);
    }
    doc
}

/// Run `cmd` through `run` (`cma::embed::run`, or a test environment's),
/// with consent questions answered by `ask`, and mark a refusal that
/// follows the user's Cancel as cancelled.
pub fn run_asking<R>(cmd: Cmd, ask: impl Fn(&str) -> bool + 'static, run: R) -> Value
where
    R: FnOnce(Cmd, Box<dyn Fn(&str) -> bool>) -> cma::embed::Finished,
{
    let declined = Arc::new(AtomicBool::new(false));
    let d = declined.clone();
    let done = run(
        cmd,
        Box::new(move |q: &str| {
            let yes = ask(q);
            if !yes {
                d.store(true, Ordering::SeqCst);
            }
            yes
        }),
    );
    mark_cancelled(done.document, declined.load(Ordering::SeqCst))
}

/// The user's own Cancel in a dialog.
pub fn cancelled_doc() -> Value {
    error_doc("cancelled", "Cancelled; nothing was changed.", None)
}

/// A `confirmation_required` that follows the user's Cancel becomes
/// `cancelled` (shown as a neutral note). One with a hint stays an error:
/// cma gave up because what needed consent kept changing, or the Cancel
/// came after something was already changed (`desktop link` stopped once
/// the previous Desktop login was stored) and the hint says how to go on.
pub fn mark_cancelled(doc: Value, declined: bool) -> Value {
    if declined && doc["error"]["code"] == "confirmation_required" && doc["error"]["hint"].is_null()
    {
        let mut c = cancelled_doc();
        c["warnings"] = doc["warnings"].clone();
        c
    } else {
        doc
    }
}

/// Remember (for the tray) a state-uncertain result, and forget a sync
/// problem only once a command that syncs succeeded. (`status` reports a
/// failed sync without failing, so `get_state` sets the problem from its
/// data instead.)
fn note_problem(app: &AppHandle, doc: &Value, synced: bool) {
    let state = app.state::<AppState>();
    let mut p = state.problem.lock().unwrap_or_else(|e| e.into_inner());
    *p = next_problem(p.take(), doc, synced);
}

/// The tray's problem after a command returned `doc`.
pub fn next_problem(current: Option<String>, doc: &Value, synced: bool) -> Option<String> {
    if doc["state_uncertain"] == true {
        return Some(
            doc["error"]["message"]
                .as_str()
                .unwrap_or("an operation could not be rolled back completely")
                .to_string(),
        );
    }
    if synced && doc["ok"] == true {
        return None;
    }
    current
}

/// What `status` says needs resolving: a kept journal or uncertain state,
/// or a failed sync.
pub fn status_problem(status: &Value) -> Option<String> {
    if status["state_uncertain"] == true || !status["data"]["pending_journal"].is_null() {
        return Some("Unfinished cma operation: changes are refused until it is resolved".into());
    }
    if let Some(m) = status["data"]["sync_error"]["message"].as_str() {
        return Some(format!("cma could not sync: {m}"));
    }
    if status["ok"] == false {
        return status["error"]["message"]
            .as_str()
            .map(|m| format!("cma status failed: {m}"));
    }
    None
}

/// Ask `question` first; run only after the user agreed.
pub fn confirm_first(
    ask: impl FnOnce(&str) -> bool,
    question: &str,
    run: impl FnOnce() -> Value,
) -> Value {
    if ask(question) {
        run()
    } else {
        cancelled_doc()
    }
}

/// The question before a restore, naming the backup and what it puts back.
pub fn restore_question(id: &str, backups: &Value) -> String {
    let b = backups["data"]["backups"]
        .as_array()
        .and_then(|l| l.iter().find(|b| b["id"] == id));
    let mut q = match b.and_then(|b| b["op"].as_str()) {
        Some(op) => format!("Restore backup {id} (made by {op})?"),
        None => format!("Restore backup {id}?"),
    };
    q.push_str("\n\nIt puts back the values that operation replaced");
    let entries: Vec<&str> = b
        .and_then(|b| b["entries"].as_array())
        .map(|e| e.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if entries.is_empty() {
        q.push('.');
    } else {
        q.push(':');
        for e in entries {
            q.push_str(&format!("\n• {e}"));
        }
    }
    q.push_str("\n\nThis can change which account Claude Code uses. What is there now is kept in a new backup, so the restore can be undone.");
    q
}

/// The question before removing an account.
pub fn remove_question(reg: &Registry, key: &str) -> String {
    let who = reg
        .account(key)
        .map(tray::label)
        .unwrap_or_else(|| key.to_string());
    let mut q = format!(
        "Remove {who} from cma?\n\nIts stored login is removed from cma (a copy is kept in a backup). The Claude Code login itself is not changed."
    );
    if reg.active.cli.as_deref() == Some(key) {
        q.push_str("\n\nIt is the active Claude Code account; cma asks once more.");
    }
    q
}

/// Something may have changed: remember the registry's mtime as seen (so
/// the watcher does not report our own write again), refresh the tray and
/// tell the settings window.
pub fn after_change(app: &AppHandle) {
    let state = app.state::<AppState>();
    if let Ok(p) = Paths::from_system() {
        *state.seen_mtime.lock().unwrap_or_else(|e| e.into_inner()) =
            registry_mtime(&p.registry_file());
    }
    state.bump();
    tray::refresh(app);
}

pub fn registry_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Run `f` on a blocking thread (never on the async runtime's or the main
/// thread: cma uses blocking I/O and its sessions are `!Send`).
async fn blocking(f: impl FnOnce() -> Value + Send + 'static) -> Value {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| error_doc("internal", "an app command failed unexpectedly", None))
}

// ---- input validation ------------------------------------------------

/// An input error as a document.
#[derive(Debug, PartialEq, Eq)]
pub struct Invalid(pub String);

impl Invalid {
    pub fn doc(&self) -> Value {
        error_doc("invalid", self.0.clone(), None)
    }
}

/// Free text from the webview: at most `max` characters, no control
/// characters. Empty (after trimming) is `None`.
pub fn text(what: &str, v: Option<&str>, max: usize) -> Result<Option<String>, Invalid> {
    let Some(v) = v else { return Ok(None) };
    let v = v.trim();
    if v.is_empty() {
        return Ok(None);
    }
    if v.chars().count() > max {
        return Err(Invalid(format!("{what} is longer than {max} characters")));
    }
    if v.chars().any(char::is_control) {
        return Err(Invalid(format!("{what} contains a control character")));
    }
    Ok(Some(v.to_string()))
}

/// The key must name a stored account, and cma's query for it must
/// resolve to that same account (an alias equal to another account's key
/// would otherwise win).
pub fn check_key(reg: &Registry, key: &str) -> Result<(), Invalid> {
    if !reg.accounts.iter().any(|a| a.key == key) {
        return Err(Invalid(format!("no stored account has key {key:?}")));
    }
    match cma_core::selector::select(&reg.accounts, key) {
        Ok(a) if a.key == key => Ok(()),
        _ => Err(Invalid(format!(
            "account key {key:?} is ambiguous (an alias or email matches it); use the command line"
        ))),
    }
}

fn registry() -> Result<Registry, Value> {
    let p = Paths::from_system().map_err(|e| error_doc(e.code(), e.to_string(), None))?;
    Registry::load(&p.registry_file()).map_err(|e| error_doc(e.code(), e.to_string(), None))
}

fn stored_key(key: &str) -> Result<(), Value> {
    check_key(&registry()?, key).map_err(|e| e.doc())
}

pub fn check_setting(key: &str, value: &str) -> Result<(), Invalid> {
    if !SETTING_KEYS.contains(&key) {
        return Err(Invalid(format!("unknown setting {key:?}")));
    }
    if text("value", Some(value), 32)?.is_none() {
        return Err(Invalid("a setting value cannot be empty".into()));
    }
    Ok(())
}

/// Backup ids as `cma backups` lists them.
pub fn check_backup_id(id: &str) -> Result<(), Invalid> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(Invalid(format!("{id:?} is not a backup id")))
    }
}

/// `cma switch <key> --cli|--desktop|--both`. Every consent (running
/// sessions, a live login cma does not store, quitting Claude Desktop) is
/// asked in a dialog, never given up front.
pub fn switch_cmd(key: &str, target: &str) -> Result<Cmd, Invalid> {
    let (cli, desktop, both) = match target {
        "cli" => (true, false, false),
        "desktop" => (false, true, false),
        "both" => (false, false, true),
        _ => return Err(Invalid(format!("unknown switch target {target:?}"))),
    };
    Ok(Cmd::Switch(SwitchArgs {
        query: Some(key.to_string()),
        cli,
        desktop,
        both,
        strict: false,
        force: false,
        replace_live: false,
        yes: false,
    }))
}

/// Switch from anywhere (a tray click or the window): validated, then run
/// with consent asked in dialogs.
pub fn switch_blocking(app: &AppHandle, key: &str, target: &str) -> Value {
    let cmd = match switch_cmd(key, target) {
        Ok(c) => c,
        Err(e) => return e.doc(),
    };
    if let Err(d) = stored_key(key) {
        return d;
    }
    run_cmd(app, cmd, true)
}

/// `cma desktop link <key>`: its three questions (quit Desktop? signed in?
/// switch back?) are dialogs.
pub fn desktop_link_cmd(key: &str) -> Cmd {
    Cmd::Desktop(DesktopCmd::Link {
        query: key.to_string(),
        yes: false,
        replace_live: false,
    })
}

/// Link Claude Desktop to a stored account from anywhere (a tray click or
/// the window).
pub fn desktop_link_blocking(app: &AppHandle, key: &str) -> Value {
    if let Err(d) = stored_key(key) {
        return d;
    }
    run_cmd(app, desktop_link_cmd(key), true)
}

pub fn set_setting_blocking(app: &AppHandle, key: &str, value: &str) -> Value {
    if let Err(e) = check_setting(key, value) {
        return e.doc();
    }
    run_cmd(
        app,
        Cmd::Config(ConfigCmd::Set {
            key: key.to_string(),
            value: value.trim().to_string(),
        }),
        true,
    )
}

// ---- Tauri commands --------------------------------------------------

#[tauri::command]
pub async fn get_state(app: AppHandle) -> Value {
    blocking(move || {
        let list = run_cmd(&app, Cmd::List { live: false }, false);
        let status = run_cmd(&app, Cmd::Status, false);
        let settings = run_cmd(&app, Cmd::Config(ConfigCmd::Get { key: None }), false);
        *app.state::<AppState>()
            .problem
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = status_problem(&status);
        // `list` may have stored a refreshed live login: not a change the
        // window has to be told about again.
        if let Ok(p) = Paths::from_system() {
            let state = app.state::<AppState>();
            *state.seen_mtime.lock().unwrap_or_else(|e| e.into_inner()) =
                registry_mtime(&p.registry_file());
        }
        tray::refresh(&app);
        let state = app.state::<AppState>();
        json!({
            "list": list,
            "status": status,
            "settings": settings,
            "app": {
                "desktop_available": true,
                "launch_at_login": crate::launch_at_login(&app),
                "login_in_progress": state.login_in_progress.load(Ordering::SeqCst),
                "cli_install": install_status(),
            },
        })
    })
    .await
}

/// Cheap: the change stamp, and a view the window should switch to.
#[tauri::command]
pub fn poll(app: AppHandle) -> Value {
    let state = app.state::<AppState>();
    let section = state
        .section
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    json!({"stamp": state.stamp.load(Ordering::SeqCst), "section": section})
}

#[tauri::command]
pub async fn switch(app: AppHandle, key: String, target: String) -> Value {
    blocking(move || switch_blocking(&app, &key, &target)).await
}

#[tauri::command]
pub async fn remove(app: AppHandle, key: String) -> Value {
    blocking(move || {
        let reg = match registry() {
            Ok(r) => r,
            Err(d) => return d,
        };
        if let Err(e) = check_key(&reg, &key) {
            return e.doc();
        }
        let q = remove_question(&reg, &key);
        confirm_first(
            |q| ask(&app, q),
            &q,
            || {
                run_cmd(
                    &app,
                    Cmd::Remove {
                        queries: vec![key],
                        all: false,
                        force: false,
                    },
                    true,
                )
            },
        )
    })
    .await
}

#[tauri::command]
pub async fn set_alias(app: AppHandle, key: String, alias: Option<String>) -> Value {
    blocking(move || {
        if let Err(d) = stored_key(&key) {
            return d;
        }
        let alias = match text("alias", alias.as_deref(), ALIAS_MAX) {
            Ok(a) => a,
            Err(e) => return e.doc(),
        };
        let cmd = match alias {
            Some(alias) => Cmd::Alias(AliasCmd::Set { query: key, alias }),
            None => Cmd::Alias(AliasCmd::Clear { query: key }),
        };
        run_cmd(&app, cmd, true)
    })
    .await
}

#[tauri::command]
pub async fn set_setting(app: AppHandle, key: String, value: String) -> Value {
    blocking(move || set_setting_blocking(&app, &key, &value)).await
}

#[tauri::command]
pub async fn refresh_usage(app: AppHandle) -> Value {
    blocking(move || run_cmd(&app, Cmd::Usage { query: None }, true)).await
}

#[tauri::command]
pub async fn list_backups(app: AppHandle) -> Value {
    blocking(move || run_cmd(&app, Cmd::Backups, false)).await
}

#[tauri::command]
pub async fn restore(app: AppHandle, id: String, force: bool) -> Value {
    blocking(move || {
        if let Err(e) = check_backup_id(&id) {
            return e.doc();
        }
        // Always asked first in a native dialog (the webview cannot skip
        // it). `force` only allows cma's own conflict / older-login
        // question, which the user answers in a second dialog (no `--yes`).
        let backups = run_cmd(&app, Cmd::Backups, false);
        let q = restore_question(&id, &backups);
        confirm_first(
            |q| ask(&app, q),
            &q,
            || {
                run_cmd(
                    &app,
                    Cmd::Restore {
                        id,
                        force,
                        yes: false,
                        replace_live: false,
                    },
                    true,
                )
            },
        )
    })
    .await
}

#[tauri::command]
pub async fn resolve_journal(app: AppHandle) -> Value {
    blocking(move || run_cmd(&app, Cmd::ResolveJournal { yes: false }, true)).await
}

#[tauri::command]
pub async fn desktop_link(app: AppHandle, key: String) -> Value {
    blocking(move || desktop_link_blocking(&app, &key)).await
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoginOptions {
    pub email: Option<String>,
    pub alias: Option<String>,
    pub org: Option<String>,
    pub sso: bool,
    pub console: bool,
}

#[tauri::command]
pub async fn start_login(app: AppHandle, options: LoginOptions) -> Value {
    blocking(move || match login::LoginArgs::validate(&options) {
        Ok(args) => login::start(&app, args),
        Err(e) => e.doc(),
    })
    .await
}

#[tauri::command]
pub async fn install_cli(app: AppHandle) -> Value {
    blocking(move || {
        let home = match Paths::from_system() {
            Ok(p) => p.home,
            Err(e) => return error_doc(e.code(), e.to_string(), None),
        };
        let bin = match login::cma_binary() {
            Ok(b) => b,
            Err(d) => return d,
        };
        let warning = match install_allowed(&bin, dev_install_allowed()) {
            Ok(w) => w,
            Err(d) => return d,
        };
        let replace = |old: Option<&Path>| {
            let what = match old {
                Some(o) => format!("already links to {}", o.display()),
                None => "is a link whose target could not be read".to_string(),
            };
            ask(
                &app,
                &format!(
                    "{} {what}, not to this app's cma.\n\nReplace that link?",
                    link_path(&home).display(),
                ),
            )
        };
        match install_link(&bin, &home, &replace) {
            Ok(link) => {
                let mut d = ok_doc(json!({
                    "link": link,
                    "target": bin,
                    "path_hint": "add ~/.local/bin to PATH if your shell does not find cma (zsh: export PATH=\"$HOME/.local/bin:$PATH\" in ~/.zshrc)",
                }));
                if let Some(w) = warning {
                    d["warnings"] = json!([{"code": "dev_binary", "message": w}]);
                }
                d
            }
            Err(e) => e,
        }
    })
    .await
}

/// Environment variable that lets a debug build link an unbundled cma.
pub const DEV_ALLOW_INSTALL_ENV: &str = "CMA_DEV_ALLOW_INSTALL";

fn dev_install_allowed() -> bool {
    cfg!(debug_assertions) && std::env::var(DEV_ALLOW_INSTALL_ENV).as_deref() == Ok("1")
}

/// Install CLI links only the cma inside an app bundle. A debug build may
/// link another one when explicitly allowed, with a warning (a dev binary
/// may have been rebuilt by `cargo test` with test backends).
pub fn install_allowed(bin: &Path, dev_allowed: bool) -> Result<Option<String>, Value> {
    let in_bundle = bin
        .to_str()
        .is_some_and(|s| s.contains(".app/Contents/MacOS/"));
    if in_bundle {
        return Ok(None);
    }
    if dev_allowed {
        return Ok(Some(format!(
            "linked a development cma ({}) that is not inside an app bundle; rebuild it with `cargo build -p cma` (not `cargo test`) before using it",
            bin.display()
        )));
    }
    Err(error_doc(
        "not_bundled",
        format!(
            "{} is not inside an app bundle, so Install CLI does not link it",
            bin.display()
        ),
        Some(
            "use the bundled app, or link a development cma yourself; debug builds can set CMA_DEV_ALLOW_INSTALL=1",
        ),
    ))
}

#[tauri::command]
pub async fn set_launch_at_login(app: AppHandle, enabled: bool) -> Value {
    use tauri_plugin_autostart::ManagerExt;
    blocking(move || {
        let al = app.autolaunch();
        let r = if enabled { al.enable() } else { al.disable() };
        match r {
            Ok(()) => ok_doc(json!({"enabled": enabled})),
            Err(e) => error_doc(
                "launch_at_login",
                format!("could not change launch at login: {e}"),
                None,
            ),
        }
    })
    .await
}

// ---- Install CLI ------------------------------------------------------

/// `~/.local/bin/cma`.
pub fn link_path(home: &Path) -> PathBuf {
    home.join(".local/bin/cma")
}

fn install_status() -> Value {
    let Ok(p) = Paths::from_system() else {
        return json!({"link": null, "installed": false, "other_file": false, "other_link": false, "target": null});
    };
    let ours = login::cma_binary().ok();
    link_status(&link_path(&p.home), ours.as_deref())
}

/// What `link` is: our link (`installed`), a link elsewhere
/// (`other_link`), another file (`other_file`), or nothing.
pub fn link_status(link: &Path, ours: Option<&Path>) -> Value {
    let (installed, other_link, other_file, target) = match std::fs::symlink_metadata(link) {
        Ok(m) if m.file_type().is_symlink() => {
            let t = std::fs::read_link(link).ok();
            let mine = t.is_some() && t.as_deref() == ours;
            (mine, !mine, false, t)
        }
        Ok(_) => (false, false, true, None),
        Err(_) => (false, false, false, None),
    };
    json!({"link": link, "installed": installed, "other_link": other_link, "other_file": other_file, "target": target})
}

/// The filesystem calls Install CLI makes after the first rename, so tests
/// can inject failures.
pub struct InstallFs<'a> {
    /// Atomically exchange two paths (`RENAME_SWAP`).
    pub swap: &'a dyn Fn(&Path, &Path) -> std::io::Result<()>,
    pub read_link: &'a dyn Fn(&Path) -> std::io::Result<PathBuf>,
}

fn real_swap(a: &Path, b: &Path) -> std::io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    renameat_with(CWD, a, CWD, b, RenameFlags::EXCHANGE).map_err(Into::into)
}

pub const REAL_FS: InstallFs<'static> = InstallFs {
    swap: &real_swap,
    read_link: &|p| std::fs::read_link(p),
};

/// Point `~/.local/bin/cma` at `bin`, without a race. See [`install_link_with`].
pub fn install_link(
    bin: &Path,
    home: &Path,
    replace: &dyn Fn(Option<&Path>) -> bool,
) -> Result<PathBuf, Value> {
    install_link_with(bin, home, replace, &REAL_FS)
}

/// A link made under a temporary name is renamed into place only when
/// nothing is there (`RENAME_EXCL`). Otherwise, if a symlink is there, the
/// user is asked (also when its target cannot be read), then the two are
/// swapped (`RENAME_SWAP`) and the swapped-out entry is checked: it must
/// still be the link the user approved, or it is swapped back. If swapping
/// back fails, the temporary name, which then holds the previous entry, is
/// kept and named in the error. Any other file is refused and left alone.
pub fn install_link_with(
    bin: &Path,
    home: &Path,
    replace: &dyn Fn(Option<&Path>) -> bool,
    fs: &InstallFs<'_>,
) -> Result<PathBuf, Value> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    let link = link_path(home);
    let dir = link.parent().expect("has a parent").to_path_buf();
    let io = |what: &str, e: std::io::Error| {
        error_doc("io", format!("{what} {}: {e}", dir.display()), None)
    };
    let not_link = || {
        error_doc(
            "exists",
            format!(
                "{} exists and is not a symlink; it was left alone",
                link.display()
            ),
            Some("remove or rename it yourself, then Install CLI again"),
        )
    };
    std::fs::create_dir_all(&dir).map_err(|e| io("could not create", e))?;
    let tmp = dir.join(format!(".cma.install-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(bin, &tmp).map_err(|e| io("could not write in", e))?;
    let cleanup = |r: Result<PathBuf, Value>| {
        let _ = std::fs::remove_file(&tmp);
        r
    };
    match renameat_with(CWD, &tmp, CWD, &link, RenameFlags::NOREPLACE) {
        Ok(()) => return Ok(link),
        Err(e) if e == rustix::io::Errno::EXIST => {}
        Err(e) => return cleanup(Err(io("could not write in", e.into()))),
    }
    let approved = match std::fs::symlink_metadata(&link) {
        Ok(m) if m.file_type().is_symlink() => (fs.read_link)(&link).ok(),
        Ok(_) => return cleanup(Err(not_link())),
        Err(e) => return cleanup(Err(io("could not read", e))),
    };
    if approved.as_deref() == Some(bin) {
        return cleanup(Ok(link));
    }
    // A link whose target cannot be read is asked about too.
    if !replace(approved.as_deref()) {
        return cleanup(Err(cancelled_doc()));
    }
    if let Err(e) = (fs.swap)(&tmp, &link) {
        return cleanup(Err(io("could not write in", e)));
    }
    // `tmp` now holds what was at `link`. It is dropped only if it is the
    // link the user approved (or, for an unreadable target, still a link
    // whose target cannot be read).
    let swapped_out = match std::fs::symlink_metadata(&tmp) {
        Ok(m) if m.file_type().is_symlink() => Some((fs.read_link)(&tmp).ok()),
        _ => None,
    };
    if swapped_out.as_ref() == Some(&approved) {
        return cleanup(Ok(link));
    }
    match (fs.swap)(&tmp, &link) {
        Ok(()) => cleanup(Err(error_doc(
            "changed",
            format!(
                "{} changed while you were asked; it was left as it is now",
                link.display()
            ),
            Some("run Install CLI again"),
        ))),
        // Not removed: `tmp` holds the previous entry.
        Err(e) => Err(error_doc(
            "io",
            format!(
                "{} changed while you were asked, and putting it back failed ({e}): the previous entry is now at {}",
                link.display(),
                tmp.display()
            ),
            Some("move that file back to ~/.local/bin/cma yourself"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cma_core::registry::Account;

    fn reg(accounts: &[(&str, Option<&str>, &str)]) -> Registry {
        Registry {
            accounts: accounts
                .iter()
                .map(|(k, alias, email)| Account {
                    key: k.to_string(),
                    alias: alias.map(String::from),
                    email: email.to_string(),
                    ..Account::default()
                })
                .collect(),
            ..Registry::default()
        }
    }

    #[test]
    fn keys_must_name_one_stored_account_exactly() {
        let r = reg(&[("A::oA", None, "a@x.test"), ("B::oB", None, "b@x.test")]);
        assert!(check_key(&r, "A::oA").is_ok());
        assert!(check_key(&r, "A::").is_err(), "a prefix is not a key");
        assert!(check_key(&r, "1").is_err(), "a row number is not a key");
        assert!(check_key(&r, "C::oC").is_err());
        // An alias equal to another account's key would win in cma's query.
        let r = reg(&[
            ("A::oA", None, "a@x.test"),
            ("B::oB", Some("A::oA"), "b@x.test"),
        ]);
        assert!(check_key(&r, "A::oA").is_err());
    }

    #[test]
    fn free_text_is_bounded_and_kept_literally() {
        assert_eq!(text("alias", Some("  "), 64), Ok(None));
        assert_eq!(text("alias", None, 64), Ok(None));
        assert_eq!(
            text("alias", Some("\"; rm -rf ~"), 64),
            Ok(Some("\"; rm -rf ~".into()))
        );
        assert!(text("alias", Some("a\u{7}b"), 64).is_err());
        assert!(text("alias", Some(&"é".repeat(65)), 64).is_err());
        assert!(text("alias", Some(&"é".repeat(64)), 64).is_ok());
    }

    #[test]
    fn settings_and_backup_ids_are_checked() {
        assert!(check_setting("live_usage", "true").is_ok());
        assert!(check_setting("usage_disclaimer_shown", "true").is_err());
        assert!(check_setting("live_usage", " ").is_err());
        assert!(check_backup_id("20261027T101010Z-switch-ab12").is_ok());
        assert!(check_backup_id("../x").is_err());
        assert!(check_backup_id(".hidden").is_err());
        assert!(check_backup_id("").is_err());
    }

    fn never(_: Option<&Path>) -> bool {
        panic!("asked to replace a link")
    }

    #[test]
    fn install_creates_a_link_and_leaves_other_files_alone() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        let bin = home.join("cma-bin");
        let link = install_link(&bin, home, &never).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), bin);
        // Again, same target: nothing to ask.
        install_link(&bin, home, &never).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), bin);
        assert_eq!(link_status(&link, Some(&bin))["installed"], true);
        // A real file is never replaced.
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&link, b"mine").unwrap();
        let e = install_link(&bin, home, &never).unwrap_err();
        assert_eq!(e["error"]["code"], "exists");
        assert_eq!(std::fs::read(&link).unwrap(), b"mine");
        assert_eq!(link_status(&link, Some(&bin))["other_file"], true);
        let leftovers: Vec<_> = std::fs::read_dir(link.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    }

    #[test]
    fn a_link_to_another_cma_is_replaced_only_after_asking() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        let theirs = home.join("their-cma");
        let ours = home.join("our-cma");
        let link = install_link(&theirs, home, &never).unwrap();
        let st = link_status(&link, Some(&ours));
        assert_eq!(st["installed"], false);
        assert_eq!(st["other_link"], true);
        let asked = std::cell::RefCell::new(Vec::new());
        let no = |old: Option<&Path>| {
            asked.borrow_mut().push(old.unwrap().to_path_buf());
            false
        };
        let e = install_link(&ours, home, &no).unwrap_err();
        assert_eq!(e["error"]["code"], "cancelled");
        assert_eq!(*asked.borrow(), std::slice::from_ref(&theirs));
        assert_eq!(std::fs::read_link(&link).unwrap(), theirs);
        let yes = |_: Option<&Path>| true;
        install_link(&ours, home, &yes).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), ours);
        assert_eq!(
            std::fs::read_dir(home.join(".local/bin")).unwrap().count(),
            1
        );
    }

    /// A link to another cma, with the setup the swap tests share.
    fn foreign_link() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let theirs = d.path().join("their-cma");
        let ours = d.path().join("our-cma");
        let link = install_link(&theirs, d.path(), &never).unwrap();
        (d, theirs, ours, link)
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_file_that_replaces_the_link_during_the_question_is_put_back() {
        let (d, _theirs, ours, link) = foreign_link();
        let l = link.clone();
        let race = move |_: Option<&Path>| {
            std::fs::remove_file(&l).unwrap();
            std::fs::write(&l, b"mine").unwrap();
            true
        };
        let e = install_link(&ours, d.path(), &race).unwrap_err();
        assert_eq!(e["error"]["code"], "changed");
        assert_eq!(std::fs::read(&link).unwrap(), b"mine");
        assert_eq!(entries(link.parent().unwrap()), ["cma"]);
    }

    #[test]
    fn a_different_link_placed_during_the_question_is_put_back() {
        let (d, _theirs, ours, link) = foreign_link();
        let other = d.path().join("other-cma");
        let (l, o) = (link.clone(), other.clone());
        let race = move |_: Option<&Path>| {
            std::fs::remove_file(&l).unwrap();
            std::os::unix::fs::symlink(&o, &l).unwrap();
            true
        };
        let e = install_link(&ours, d.path(), &race).unwrap_err();
        assert_eq!(e["error"]["code"], "changed");
        assert_eq!(std::fs::read_link(&link).unwrap(), other);
        assert_eq!(entries(link.parent().unwrap()), ["cma"]);
    }

    #[test]
    fn a_failed_swap_back_keeps_the_previous_entry_and_names_it() {
        let (d, _theirs, ours, link) = foreign_link();
        let l = link.clone();
        let race = move |_: Option<&Path>| {
            std::fs::remove_file(&l).unwrap();
            std::fs::write(&l, b"mine").unwrap();
            true
        };
        let calls = std::cell::Cell::new(0);
        let swap = |a: &Path, b: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                real_swap(a, b)
            } else {
                Err(std::io::Error::other("injected"))
            }
        };
        let fs = InstallFs {
            swap: &swap,
            read_link: &|p| std::fs::read_link(p),
        };
        let e = install_link_with(&ours, d.path(), &race, &fs).unwrap_err();
        let msg = e["error"]["message"].as_str().unwrap().to_string();
        let dir = link.parent().unwrap();
        let tmp = dir.join(format!(".cma.install-{}", std::process::id()));
        assert!(msg.contains(tmp.to_str().unwrap()), "{msg}");
        assert_eq!(
            std::fs::read(&tmp).unwrap(),
            b"mine",
            "the user's file is kept"
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), ours);
    }

    #[test]
    fn a_link_whose_target_cannot_be_read_is_still_asked_about() {
        let (d, _theirs, ours, link) = foreign_link();
        let unreadable =
            |_: &Path| -> std::io::Result<PathBuf> { Err(std::io::Error::other("injected")) };
        let fs = InstallFs {
            swap: &real_swap,
            read_link: &unreadable,
        };
        let asked = std::cell::RefCell::new(Vec::new());
        let no = |old: Option<&Path>| {
            asked.borrow_mut().push(old.map(Path::to_path_buf));
            false
        };
        let e = install_link_with(&ours, d.path(), &no, &fs).unwrap_err();
        assert_eq!(e["error"]["code"], "cancelled");
        assert_eq!(*asked.borrow(), [None]);
        let yes = |_: Option<&Path>| true;
        install_link_with(&ours, d.path(), &yes, &fs).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), ours);
    }

    #[test]
    fn only_syncing_commands_clear_a_sync_problem() {
        let ok = ok_doc(json!({}));
        let p = Some("cma could not sync: locked".to_string());
        assert_eq!(next_problem(p.clone(), &ok, false), p);
        assert_eq!(next_problem(p.clone(), &ok, true), None);
        let failed = error_doc("locked", "m", None);
        assert_eq!(next_problem(p.clone(), &failed, true), p);
        let mut uncertain = error_doc("state_uncertain", "rollback failed", None);
        uncertain["state_uncertain"] = json!(true);
        assert_eq!(
            next_problem(None, &uncertain, false).as_deref(),
            Some("rollback failed")
        );
        assert!(syncs(&Cmd::Usage { query: None }));
        assert!(syncs(&switch_cmd("A::oA", "cli").unwrap()));
        assert!(syncs(&desktop_link_cmd("A::oA")));
        assert!(!syncs(&Cmd::Backups));
        assert!(!syncs(&Cmd::Config(ConfigCmd::Get { key: None })));
        assert!(!syncs(&Cmd::Restore {
            id: "x".into(),
            force: false,
            yes: false,
            replace_live: false,
        }));
    }

    #[test]
    fn only_a_bundled_cma_is_installed_unless_a_dev_build_allows_it() {
        let bundled = Path::new("/Applications/Claude Multi Auth.app/Contents/MacOS/cma");
        assert_eq!(install_allowed(bundled, false).unwrap(), None);
        let dev = Path::new("/repo/target/debug/cma");
        let e = install_allowed(dev, false).unwrap_err();
        assert_eq!(e["error"]["code"], "not_bundled");
        assert!(
            install_allowed(dev, true)
                .unwrap()
                .unwrap()
                .contains("cargo build -p cma")
        );
    }

    #[test]
    fn restore_and_remove_are_asked_first_and_cancel_runs_nothing() {
        let ran = std::cell::Cell::new(false);
        let d = confirm_first(
            |_| false,
            "q",
            || {
                ran.set(true);
                ok_doc(json!({}))
            },
        );
        assert!(!ran.get());
        assert_eq!(d["error"]["code"], "cancelled");
        let asked = std::cell::RefCell::new(String::new());
        let d = confirm_first(
            |q| {
                *asked.borrow_mut() = q.to_string();
                true
            },
            "Restore?",
            || {
                ran.set(true);
                ok_doc(json!({}))
            },
        );
        assert!(ran.get());
        assert_eq!(d["ok"], true);
        assert_eq!(*asked.borrow(), "Restore?");
    }

    #[test]
    fn the_questions_name_what_changes() {
        let backups = json!({"ok": true, "data": {"backups": [
            {"id": "b1", "op": "switch", "entries": ["keychain:Claude Code-credentials", "file:~/.claude.json#oauthAccount"]},
        ]}});
        let q = restore_question("b1", &backups);
        assert!(q.starts_with("Restore backup b1 (made by switch)?"), "{q}");
        assert!(q.contains("• keychain:Claude Code-credentials"), "{q}");
        assert!(q.contains("new backup"), "{q}");
        let q = restore_question("b2", &backups);
        assert!(q.starts_with("Restore backup b2?"), "{q}");
        let mut r = reg(&[
            ("A::oA", Some("work"), "a@x.test"),
            ("B::oB", None, "b@x.test"),
        ]);
        r.active.cli = Some("A::oA".into());
        let q = remove_question(&r, "B::oB");
        assert!(q.starts_with("Remove b@x.test from cma?"), "{q}");
        assert!(!q.contains("active"), "{q}");
        let q = remove_question(&r, "A::oA");
        assert!(q.starts_with("Remove work (a@x.test) from cma?"), "{q}");
        assert!(q.contains("active Claude Code account"), "{q}");
    }

    #[test]
    fn status_problems_reach_the_tray() {
        let ok = json!({"ok": true, "state_uncertain": false, "data": {"pending_journal": null, "sync_error": null}});
        assert_eq!(status_problem(&ok), None);
        let j = json!({"ok": true, "state_uncertain": true, "data": {"pending_journal": {"op": "switch"}, "sync_error": null}});
        assert!(status_problem(&j).unwrap().contains("Unfinished"));
        let s = json!({"ok": true, "state_uncertain": false, "data": {"pending_journal": null, "sync_error": {"message": "locked"}}});
        assert_eq!(status_problem(&s).unwrap(), "cma could not sync: locked");
    }

    #[test]
    fn only_a_cancel_after_the_users_no_is_shown_as_cancelled() {
        let gave_up = error_doc(
            "confirmation_required",
            "what needed confirmation kept changing between prompts; nothing was changed",
            Some("run the command again"),
        );
        assert_eq!(
            mark_cancelled(gave_up.clone(), false)["error"]["code"],
            "confirmation_required"
        );
        let declined = error_doc(
            "confirmation_required",
            "Claude Desktop is running; cma quits it; nothing was changed",
            None,
        );
        assert_eq!(
            mark_cancelled(declined.clone(), false)["error"]["code"],
            "confirmation_required"
        );
        assert_eq!(mark_cancelled(declined, true)["error"]["code"], "cancelled");
        // A Cancel after something changed keeps cma's message and hint.
        let stopped = error_doc(
            "confirmation_required",
            "link of b@x.test stopped after storing the previous Claude Desktop login; Desktop stays signed out",
            Some("the previous login is stored: `cma switch --desktop a@x.test` puts it back"),
        );
        let d = mark_cancelled(stopped.clone(), true);
        assert_eq!(d, stopped);
        assert_eq!(
            mark_cancelled(gave_up.clone(), true)["error"]["code"],
            "confirmation_required"
        );
        let other = error_doc("locked", "m", None);
        assert_eq!(mark_cancelled(other, true)["error"]["code"], "locked");
    }

    #[test]
    fn app_documents_have_the_cma_envelope() {
        let d = error_doc("invalid", "m", None);
        assert_eq!(d["schema_version"], 1);
        assert_eq!(d["ok"], false);
        assert_eq!(d["error"]["hint"], Value::Null);
        assert_eq!(ok_doc(json!({}))["ok"], true);
    }
}
