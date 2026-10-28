//! Isolated `claude auth login` that never touches the live login.
//!
//! 1. Under the cma lock: recover an interrupted op, sync the live item,
//!    sweep leftovers (`login-*` dirs older than 1 h and their hashed items).
//! 2. `dir = <CMA_HOME>/login-<ms>/` (0700); back up the live item
//!    (pre-login backup, kept for manual recovery) and record its hash; list
//!    the `Claude Code-credentials*` items.
//! 3. Run `claude auth login …` with a cleared environment (allowlist) plus
//!    `CLAUDE_CONFIG_DIR = CLAUDE_SECURESTORAGE_CONFIG_DIR = dir` (the raw
//!    string; its hash names the item), inherited stdio. Ctrl-C sets a flag
//!    (forwarded to the child) and the cleanup guard runs; a second Ctrl-C
//!    terminates at once, and the next login's sweep removes what is left.
//! 4. Exactly one new item, with the expected name, must appear; a failed
//!    Keychain listing or read is fatal.
//! 5. Take the cma lock (recover + sync). If the live item's hash changed,
//!    abort with `live_item_changed_during_login`: nothing stored, the live
//!    item is **not** restored (cma wrote nothing there; most likely Claude
//!    refreshed it), the pre-login backup is kept.
//! 6. Identify the new credential by its token (`/api/oauth/profile`); with
//!    `--org`, a different org ⇒ `org_mismatch`, nothing stored.
//! 7. Store it under `<accountUuid>::<organizationUuid>`, replacing an older
//!    grant of the same key (which stays valid server-side: re-login does not
//!    revoke).
//! 8. Re-login of the active CLI account: the new
//!    grant also goes into the live item, through the switch path
//!    ([`crate::switch::write_live_oauth`]: journal + backup, RMW inside
//!    `.storage-write` replacing only `claudeAiOauth`, the live credential
//!    must still be the one stored before this login, read-back +
//!    fingerprint post-check). Otherwise the next sync would see the old
//!    live grant as the active account's newer bytes and store it over the
//!    new one. This also covers a live login sync found signed out for this
//!    account (`needs_login`). When the live login is not confirmed as this
//!    account (unidentified, no credential), it is left alone and a warning
//!    says so. `~/.claude.json` is not touched (same account).
//! 9. Delete the hashed item, then the dir.
//!
//! `--console`: Claude Code leaves the hashed item as `{}` and where it keeps
//! the API key is unknown, so unless a `claudeAiOauth` credential appears the
//! login fails closed (`unsupported`), storing nothing.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::account::{StoreOpts, store_credential};
use crate::backup::Backup;
use crate::cli_target::{
    Ctx, LIVE_SERVICE_BASE, LiveTarget, Warning, is_blanked, keychain_account, oauth_fingerprint,
    oauth_of, service_for_dir, stored_oauth,
};
use crate::error::{Error, Result, ToolFailure};
use crate::fsutil;
use crate::identity::resolve;
use crate::journal::{ActiveJournal, Journal};
use crate::paths::Env;
use crate::registry::AccountKind;
use crate::secret::{CommandRunner, MemoryStore, ProcessRunner, SECURITY_PROGRAM, SecretStore};
use crate::sync::begin;
use crate::sync::{LiveState, Session};

/// Environment variables passed through to `claude auth login`.
pub const ENV_ALLOWLIST: [&str; 9] = [
    "HOME", "PATH", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "SHELL", "TMPDIR",
];
/// Leftover login dirs older than this are swept.
pub const SWEEP_AGE_MS: i64 = 3_600_000;
const DIR_PREFIX: &str = "login-";
const MARKER: &str = ".cma-login.json";

#[derive(Debug, Clone, Default)]
pub struct LoginOpts {
    pub email: Option<String>,
    pub sso: bool,
    pub console: bool,
    /// Expected organization: uuid or name (case-insensitive).
    pub org: Option<String>,
    pub alias: Option<String>,
}

/// The process to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginCommand {
    pub program: String,
    pub args: Vec<String>,
    /// The complete child environment (the parent's is cleared).
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginExit {
    pub code: Option<i32>,
    pub interrupted: bool,
}

/// Runs `claude auth login`. Injected so tests never spawn it.
pub trait LoginSpawner {
    fn run(&self, cmd: &LoginCommand) -> Result<LoginExit>;
}

/// Lists (service, account) of Keychain items whose service starts with a
/// prefix. Attribute names only, never secret data.
pub trait ItemLister {
    fn list(&self, prefix: &str) -> Result<Vec<(String, String)>>;
}

impl ItemLister for MemoryStore {
    fn list(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        Ok(self.names_with_prefix(prefix))
    }
}

/// `security dump-keychain` without `-a`/`-d`: attributes only. The output
/// is kept in a zeroized buffer, parsed for `svce`/`acct`, never printed.
#[derive(Debug, Default, Clone, Copy)]
pub struct DumpKeychainLister;

impl ItemLister for DumpKeychainLister {
    fn list(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let fail = |code, class| Error::ExternalTool {
            program: "security",
            sub: "dump-keychain",
            code,
            class,
        };
        let out = ProcessRunner
            .run(
                Path::new(SECURITY_PROGRAM),
                &[OsString::from("dump-keychain")],
                None,
            )
            .map_err(|_| fail(None, ToolFailure::SpawnFailed))?;
        if out.code != Some(0) {
            return Err(fail(out.code, out.stderr_class));
        }
        let text = Zeroizing::new(String::from_utf8_lossy(out.stdout.expose()).into_owned());
        Ok(parse_dump(&text, prefix))
    }
}

fn blob_value<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(attr)?;
    let rest = rest.strip_prefix("<blob>=\"")?;
    rest.strip_suffix('"')
}

/// Parse `security dump-keychain` output into (service, account) pairs.
pub fn parse_dump(text: &str, prefix: &str) -> Vec<(String, String)> {
    let mut out = BTreeSet::new();
    let (mut svce, mut acct): (Option<String>, Option<String>) = (None, None);
    let mut flush = |s: &mut Option<String>, a: &mut Option<String>| {
        if let (Some(s), Some(a)) = (s.take(), a.take())
            && s.starts_with(prefix)
        {
            out.insert((s, a));
        }
        *a = None;
    };
    for line in text.lines() {
        if line.starts_with("keychain:") {
            flush(&mut svce, &mut acct);
        } else if let Some(v) = blob_value(line, "\"svce\"") {
            svce = Some(v.to_string());
        } else if let Some(v) = blob_value(line, "\"acct\"") {
            acct = Some(v.to_string());
        }
    }
    flush(&mut svce, &mut acct);
    out.into_iter().collect()
}

/// The child environment: allowlisted parent variables, then both config
/// dir variables set to the raw `dir` string. Nothing else (no
/// `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, or a parent
/// `CLAUDE_SECURESTORAGE_CONFIG_DIR`) reaches the child.
pub fn login_env(parent: &dyn Env, dir: &str) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = ENV_ALLOWLIST
        .iter()
        .filter_map(|k| parent.var(k).map(|v| ((*k).to_string(), v)))
        .collect();
    env.push(("CLAUDE_CONFIG_DIR".into(), dir.into()));
    env.push(("CLAUDE_SECURESTORAGE_CONFIG_DIR".into(), dir.into()));
    env
}

pub fn login_args(o: &LoginOpts) -> Vec<String> {
    let mut a = vec!["auth".to_string(), "login".to_string()];
    if let Some(e) = &o.email {
        a.push("--email".into());
        a.push(e.clone());
    }
    if o.sso {
        a.push("--sso".into());
    }
    if o.console {
        a.push("--console".into());
    }
    a
}

/// Written into each login dir so the sweep deletes exactly the item that
/// dir's login could have created.
#[derive(Debug, Serialize, Deserialize)]
struct Marker {
    raw_dir: String,
    service: String,
    account: String,
    created_ms: i64,
}

/// Deletes the hashed item, then the dir. Runs on every exit path.
struct LoginDir<'a> {
    store: &'a dyn SecretStore,
    dir: PathBuf,
    service: String,
    account: String,
    done: bool,
}

impl LoginDir<'_> {
    fn cleanup(&mut self) -> Vec<Warning> {
        self.done = true;
        let mut w = Vec::new();
        match self.store.delete(&self.service, &self.account) {
            Ok(_) => {
                if let Err(e) = std::fs::remove_dir_all(&self.dir) {
                    w.push(Warning::new(
                        "login_cleanup",
                        format!("could not remove {} ({})", self.dir.display(), e.kind()),
                    ));
                }
            }
            Err(e) => w.push(Warning::new(
                "login_cleanup",
                format!(
                    "could not delete Keychain item {:?} ({e}); the next login retries",
                    self.service
                ),
            )),
        }
        w
    }
}

impl Drop for LoginDir<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.cleanup();
        }
    }
}

/// Remove `login-*` dirs older than [`SWEEP_AGE_MS`] and their hashed items
/// (only the name computed from the dir's own raw path).
pub fn sweep(
    paths: &crate::paths::Paths,
    env: &dyn Env,
    store: &dyn SecretStore,
    now_ms: i64,
) -> Result<Vec<Warning>> {
    let mut warnings = Vec::new();
    let rd = match std::fs::read_dir(&paths.cma_home) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(warnings),
        Err(e) => return Err(Error::io(&paths.cma_home, e)),
    };
    for e in rd.filter_map(|e| e.ok()) {
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        let Some(ms) = name
            .strip_prefix(DIR_PREFIX)
            .and_then(|m| m.parse::<i64>().ok())
        else {
            continue;
        };
        if now_ms - ms < SWEEP_AGE_MS || !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = paths.cma_home.join(&name);
        let Some(raw) = dir.to_str().map(str::to_string) else {
            continue;
        };
        let Ok(service) = service_for_dir(&raw) else {
            continue;
        };
        let account = fsutil::read_nofollow(&dir.join(MARKER))
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<Marker>(&b).ok())
            .filter(|m| m.raw_dir == raw && m.service == service)
            .map(|m| m.account)
            .unwrap_or_else(|| keychain_account(env));
        let mut g = LoginDir {
            store,
            dir,
            service,
            account,
            done: false,
        };
        let w = g.cleanup();
        if w.is_empty() {
            warnings.push(Warning::new(
                "login_swept",
                format!("removed leftover login dir {name}"),
            ));
        }
        warnings.extend(w);
    }
    Ok(warnings)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginReport {
    pub key: String,
    pub email: String,
    pub org_name: String,
    pub kind: AccountKind,
    pub replaced: bool,
    pub warnings: Vec<Warning>,
}

fn org_matches(want: &str, uuid: &str, name: &str) -> bool {
    want == uuid || (!name.is_empty() && want.eq_ignore_ascii_case(name))
}

/// Run an isolated login and store its credential (see the module docs).
pub fn login(
    ctx: &Ctx<'_>,
    spawner: &dyn LoginSpawner,
    lister: &dyn ItemLister,
    opts: &LoginOpts,
) -> Result<LoginReport> {
    let paths = ctx.paths;
    let live = ctx.live()?;
    // Start-up under the cma lock, before the browser flow: recover an
    // interrupted op (it may rewrite the live item, which would otherwise
    // look like a change during login), sync (a broken live item fails
    // now, not after the user logged in), sweep. The lock is released
    // before `claude auth login` runs.
    let mut warnings = {
        let mut s = begin(ctx)?;
        let sw = sweep(paths, ctx.env, ctx.store, ctx.now_ms())?;
        s.warnings.extend(sw);
        s.end()
    };

    let mut ms = ctx.now_ms();
    let dir = loop {
        let d = paths.cma_home.join(format!("{DIR_PREFIX}{ms}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&d) {
            Ok(()) => break d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => ms += 1,
            Err(e) => return Err(Error::io(&d, e)),
        }
    };
    let raw = dir
        .to_str()
        .ok_or_else(|| Error::Unsupported("a non-UTF-8 cma home path".into()))?
        .to_string();
    let account = keychain_account(ctx.env);
    let service = match service_for_dir(&raw) {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    let mut guard = LoginDir {
        store: ctx.store,
        dir: dir.clone(),
        service: service.clone(),
        account: account.clone(),
        done: false,
    };
    let marker = Marker {
        raw_dir: raw.clone(),
        service: service.clone(),
        account: account.clone(),
        created_ms: ms,
    };
    fsutil::atomic_write_mode(
        &dir.join(MARKER),
        &serde_json::to_vec(&marker).map_err(|e| Error::json("login marker", &e))?,
        0o600,
    )?;

    // Pre-login backup of the live item; its hash is the guard value.
    let mut backup = Backup::create(paths, ctx.store, ctx.locker, "login")?;
    let pre_hash = backup.snapshot_keychain(&live.service, &live.account)?;
    let backup_id = backup.id().to_string();
    drop(backup);
    let before = lister.list(LIVE_SERVICE_BASE)?;
    if before.iter().any(|(s, _)| *s == service) {
        return Err(Error::Invalid {
            what: "login dir (its Keychain item already exists)",
            value: service,
        });
    }

    let cmd = LoginCommand {
        program: "claude".into(),
        args: login_args(opts),
        env: login_env(ctx.env, &raw),
    };
    let exit = spawner.run(&cmd)?;
    if exit.interrupted {
        return Err(Error::Interrupted);
    }
    if exit.code != Some(0) {
        return Err(Error::ExternalTool {
            program: "claude",
            sub: "auth login",
            code: exit.code,
            class: ToolFailure::Other,
        });
    }
    let after = lister.list(LIVE_SERVICE_BASE)?;
    let new: Vec<&(String, String)> = after.iter().filter(|i| !before.contains(i)).collect();
    if new.len() != 1 || new[0].0 != service || new[0].1 != account {
        return Err(Error::Unidentified(format!(
            "the login created {} new Claude Code Keychain item(s); expected exactly one named {service:?}",
            new.len()
        )));
    }

    let mut s = begin(ctx)?;
    let now_live = ctx.store.get(&live.service, &live.account)?;
    let now_hash = now_live.as_ref().map(|v| v.sha256_hex());
    // Fingerprint of the live credential as it is now (for step 8).
    let live_fp = match &now_live {
        Some(v) => oauth_of(v.expose())?.map(|o| oauth_fingerprint(&o)),
        None => None,
    };
    drop(now_live);
    if now_hash != pre_hash {
        return Err(Error::LiveItemChangedDuringLogin { backup_id });
    }
    let item = ctx
        .store
        .get(&service, &account)?
        .ok_or_else(|| Error::NotFound(format!("Keychain item {service:?} after login")))?;
    let hint = fsutil::read_nofollow(&dir.join(".claude.json"))?
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("oauthAccount").cloned());
    let oauth = match oauth_of(item.expose())? {
        Some(o) => o,
        None if opts.console => {
            return Err(Error::Unsupported(
                "Console login: Claude Code stored no Claude.ai credential and where it keeps the Console API key is not known yet; nothing was stored".into(),
            ));
        }
        None => {
            return Err(Error::Unidentified(
                "the login produced no claudeAiOauth credential".into(),
            ));
        }
    };
    drop(item);
    if is_blanked(&oauth) {
        return Err(Error::NeedsLogin(
            "the new login is already signed out".into(),
        ));
    }
    let (key, profile) = resolve(&s.registry, ctx.profile, &oauth, ctx.now_ms(), None).require()?;
    let Some(profile) = profile else {
        // A brand-new grant can only be identified by the profile endpoint.
        return Err(Error::Unidentified(
            "the new credential was not confirmed by /api/oauth/profile".into(),
        ));
    };
    if let Some(want) = &opts.org
        && !org_matches(want, &profile.org_uuid, &profile.org_name)
    {
        return Err(Error::OrgMismatch {
            wanted: want.clone(),
            got: format!("{} ({})", profile.org_name, profile.org_uuid),
        });
    }
    let kind = if opts.console {
        AccountKind::Console
    } else {
        AccountKind::Oauth
    };
    // Re-login of the active account whose live login sync just confirmed:
    // the live item gets the new grant too (step 8).
    // The live credential must still be: the one stored for it (sync
    // confirmed the live login as this account and stored it), or the
    // signed-out one sync attributed to it (`needs_login`, the usual reason
    // to log in again).
    let expected_live_fp = if s.registry.active.cli.as_deref() != Some(key.as_str()) {
        None
    } else if s.live
        == (LiveState::Identified {
            key: key.clone(),
            managed: true,
        })
    {
        Some(
            stored_oauth(ctx.store, &key)?
                .map(|o| oauth_fingerprint(&o))
                .ok_or_else(|| Error::NotFound(format!("stored credential of {key}")))?,
        )
    } else if s.live == (LiveState::NeedsLogin { key: key.clone() }) {
        Some(live_fp.ok_or_else(|| Error::NotFound("the live credential".into()))?)
    } else {
        None
    };
    let stored = store_credential(
        &mut s,
        &key,
        Some(&profile),
        &oauth,
        &StoreOpts {
            kind,
            alias: opts.alias.as_deref(),
            oauth_account_hint: hint.as_ref(),
        },
    )?;
    if let Some(fp) = &expected_live_fp {
        write_new_grant_live(&s, &live, &key, &oauth, fp)?;
        warnings.push(Warning::new(
            "live_login_updated",
            format!(
                "{key} is the active CLI account: the live Claude Code login now uses the new grant"
            ),
        ));
    } else if s.registry.active.cli.as_deref() == Some(key.as_str()) {
        warnings.push(Warning::new(
            "live_login_not_updated",
            format!("{key} is the active CLI account but the live login could not be confirmed as it, so it was left unchanged"),
        ));
    }
    warnings.append(&mut s.warnings);
    drop(s);
    if stored.replaced {
        warnings.push(Warning::new(
            "grant_replaced",
            format!("replaced the stored login of {key}; the older grant was not revoked and stays valid server-side"),
        ));
    }
    warnings.extend(guard.cleanup());
    Ok(LoginReport {
        key,
        email: profile.email,
        org_name: profile.org_name,
        kind,
        replaced: stored.replaced,
        warnings,
    })
}

/// Put a re-logged active account's new grant into the live item (module
/// docs, step 8). `expected_fp`: the stored (= live, per sync) credential
/// before this login.
fn write_new_grant_live(
    s: &Session<'_>,
    live: &LiveTarget,
    key: &str,
    oauth: &Value,
    expected_fp: &str,
) -> Result<()> {
    let ctx = s.ctx;
    let paths = ctx.paths;
    let mut b = Backup::create(paths, ctx.store, ctx.locker, "login-live")?;
    let mut j = ActiveJournal::begin(
        paths,
        s.lock(),
        Journal {
            op: "login".into(),
            target: "cli".into(),
            from: Some(key.into()),
            to: Some(key.into()),
            backup_id: b.id().to_string(),
            steps_done: Vec::new(),
            extra: serde_json::Map::new(),
        },
    )?;
    let r = (|| {
        let others = crate::switch::write_live_oauth(&mut b, live, oauth, Some(expected_fp))?;
        j.step("keychain")?;
        crate::switch::post_check_live(ctx.store, live, &oauth_fingerprint(oauth), &others)
    })();
    match r {
        Ok(()) => j.finish(),
        Err(e) => {
            drop(b);
            Err(crate::switch::abort_op(j, ctx, "updating the live login", e).0)
        }
    }
}

/// While a login runs, SIGINT sets a flag (the first Ctrl-C) or terminates
/// (the second). signal-hook keeps its process-wide handler installed after
/// the login's actions are unregistered, which would leave SIGINT ignored
/// for the rest of the process; this always-registered action, armed
/// outside a login, takes the default action (terminate) instead.
static SIGINT_DEFAULT: std::sync::Mutex<Option<Arc<AtomicBool>>> = std::sync::Mutex::new(None);

/// The flag of the post-login default SIGINT action, registered once.
fn sigint_default_flag() -> std::io::Result<Arc<AtomicBool>> {
    let mut g = SIGINT_DEFAULT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(f) = &*g {
        return Ok(f.clone());
    }
    let f = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register_conditional_default(signal_hook::consts::SIGINT, f.clone())?;
    *g = Some(f.clone());
    Ok(f)
}

/// Spawns the real `claude auth login` with inherited stdio.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClaudeLoginSpawner;

impl LoginSpawner for ClaudeLoginSpawner {
    fn run(&self, cmd: &LoginCommand) -> Result<LoginExit> {
        spawn_login(cmd, Stdio::inherit())
    }
}

/// [`ClaudeLoginSpawner`] with the child's stdout sent to this process's
/// stderr, so a caller's stdout carries only its own output (`--json`).
#[derive(Debug, Default, Clone, Copy)]
pub struct ClaudeLoginSpawnerToStderr;

impl LoginSpawner for ClaudeLoginSpawnerToStderr {
    fn run(&self, cmd: &LoginCommand) -> Result<LoginExit> {
        spawn_login(cmd, Stdio::from(std::io::stderr()))
    }
}

fn spawn_login(cmd: &LoginCommand, stdout: Stdio) -> Result<LoginExit> {
    {
        use signal_hook::consts::SIGINT;
        let spawn_err = |_| Error::ExternalTool {
            program: "claude",
            sub: "auth login",
            code: None,
            class: ToolFailure::SpawnFailed,
        };
        let restore = sigint_default_flag().map_err(spawn_err)?;
        let flag = Arc::new(AtomicBool::new(false));
        // First Ctrl-C sets the flag; a second one (flag already set)
        // terminates with the default action.
        let ids = [
            signal_hook::flag::register_conditional_default(SIGINT, flag.clone())
                .map_err(spawn_err)?,
            signal_hook::flag::register(SIGINT, flag.clone()).map_err(spawn_err)?,
        ];
        restore.store(false, Ordering::SeqCst);
        let result = (|| {
            let mut child = Command::new(&cmd.program)
                .args(&cmd.args)
                .env_clear()
                .envs(cmd.env.iter().map(|(k, v)| (k, v)))
                .stdin(Stdio::inherit())
                .stdout(stdout)
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(spawn_err)?;
            let mut forwarded = false;
            loop {
                if let Some(st) = child.try_wait().map_err(spawn_err)? {
                    return Ok(LoginExit {
                        code: st.code(),
                        interrupted: flag.load(Ordering::SeqCst),
                    });
                }
                if flag.load(Ordering::SeqCst) && !forwarded {
                    // The terminal already signals the whole process group;
                    // this covers a SIGINT sent to cma alone.
                    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                        let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
                    }
                    forwarded = true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })();
        for id in ids {
            signal_hook::low_level::unregister(id);
        }
        // Ctrl-C terminates again, as before the login.
        restore.store(true, Ordering::SeqCst);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_target::testkit::*;
    use crate::cli_target::{OWN_SERVICE, live_service, oauth_only_item, stored_oauth};
    use crate::paths::MapEnv;
    use crate::registry::Registry;
    use crate::secret::Secret;
    use crate::sync::tests::{add_account, set_active};
    use std::cell::RefCell;

    type Behave = Box<dyn Fn(&LoginCommand, &MemoryStore)>;

    /// Fake `claude auth login`: records the command and acts on the store
    /// the way the real one would.
    struct FakeClaude<'a> {
        store: &'a MemoryStore,
        seen: RefCell<Vec<LoginCommand>>,
        behave: Behave,
        exit: LoginExit,
    }

    impl LoginSpawner for FakeClaude<'_> {
        fn run(&self, cmd: &LoginCommand) -> Result<LoginExit> {
            self.seen.borrow_mut().push(cmd.clone());
            (self.behave)(cmd, self.store);
            Ok(self.exit)
        }
    }

    fn env_of<'c>(cmd: &'c LoginCommand, k: &str) -> Option<&'c str> {
        cmd.env
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }

    /// Writes `oauth` into the item named by the child env (as Claude does)
    /// and an `oauthAccount` into `<dir>/.claude.json`.
    fn writes(oauth: Value, acct_uuid: &'static str, org: &'static str) -> Behave {
        Box::new(move |cmd, store| {
            let dir = env_of(cmd, "CLAUDE_SECURESTORAGE_CONFIG_DIR").unwrap();
            let env = MapEnv::new(cmd.env.clone());
            let svc = live_service(&env).unwrap();
            let acct = keychain_account(&env);
            store.set(&svc, &acct, &oauth_only_item(&oauth)).unwrap();
            std::fs::write(
                Path::new(dir).join(".claude.json"),
                serde_json::to_vec(&serde_json::json!({"oauthAccount": {"accountUuid": acct_uuid, "organizationUuid": org, "emailAddress": "hint@x", "billingType": "x"}})).unwrap(),
            )
            .unwrap();
        })
    }

    fn ok_exit() -> LoginExit {
        LoginExit {
            code: Some(0),
            interrupted: false,
        }
    }

    fn fake<'a>(w: &'a World, behave: Behave) -> FakeClaude<'a> {
        FakeClaude {
            store: &w.store,
            seen: RefCell::new(Vec::new()),
            behave,
            exit: ok_exit(),
        }
    }

    fn login_dirs(w: &World) -> usize {
        std::fs::read_dir(&w.paths.cma_home)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(DIR_PREFIX)
            })
            .count()
    }

    fn hashed_items(w: &World) -> usize {
        w.store.names_with_prefix("Claude Code-credentials-").len()
    }

    #[test]
    fn login_stores_new_account_and_leaves_live_untouched() {
        // A parent env with CLAUDE_SECURESTORAGE_CONFIG_DIR="" (which alone
        // would mean "the main item") and override tokens.
        let w = World::with_env(&[
            ("CLAUDE_SECURESTORAGE_CONFIG_DIR", ""),
            ("CLAUDE_CODE_OAUTH_TOKEN", "parent-token"),
            ("ANTHROPIC_API_KEY", "sk-parent"),
            ("SOMETHING_ELSE", "x"),
        ]);
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&a));
        let live_before = w.live_bytes().unwrap();
        let b = oauth("B");
        w.profile.add("at-B", "B", "oB", "b@x");
        let claude = fake(&w, writes(b.clone(), "B", "oB"));
        let ctx = w.ctx();
        let r = login(
            &ctx,
            &claude,
            &w.store,
            &LoginOpts {
                alias: Some("second".into()),
                email: Some("b@x".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.key, "B::oB");
        assert!(!r.replaced);
        // The child env: allowlist + both config dirs = the raw dir string.
        let cmd = claude.seen.borrow()[0].clone();
        assert_eq!(cmd.program, "claude");
        assert_eq!(cmd.args, vec!["auth", "login", "--email", "b@x"]);
        let dir = env_of(&cmd, "CLAUDE_CONFIG_DIR").unwrap();
        assert_eq!(env_of(&cmd, "CLAUDE_SECURESTORAGE_CONFIG_DIR"), Some(dir));
        assert!(dir.starts_with(w.paths.cma_home.to_str().unwrap()));
        for k in [
            "CLAUDE_CODE_OAUTH_TOKEN",
            "ANTHROPIC_API_KEY",
            "SOMETHING_ELSE",
            "CMA_HOME",
        ] {
            assert!(env_of(&cmd, k).is_none(), "{k} leaked");
        }
        assert_eq!(env_of(&cmd, "USER"), Some(USER));
        // ...so it targeted the hashed item, not the main one.
        let env = MapEnv::new(cmd.env.clone());
        assert_eq!(live_service(&env).unwrap(), service_for_dir(dir).unwrap());
        assert_ne!(live_service(&env).unwrap(), LIVE_SERVICE_BASE);
        assert_eq!(w.live_bytes().unwrap(), live_before, "live item untouched");
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b);
        let reg = Registry::load(&w.paths.registry_file()).unwrap();
        let acct = reg.account("B::oB").unwrap();
        assert_eq!(acct.alias.as_deref(), Some("second"));
        assert_eq!(acct.email, "b@x");
        assert_eq!(acct.oauth_account.as_ref().unwrap()["billingType"], "x");
        assert_eq!(reg.active.cli.as_deref(), Some("A::oA"), "active unchanged");
        // Cleaned up: no hashed item, no login dir.
        assert_eq!(hashed_items(&w), 0);
        assert_eq!(login_dirs(&w), 0);
    }

    #[test]
    fn live_item_change_during_login_aborts_without_restore() {
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&a));
        let before = w.live_bytes().unwrap();
        let refreshed = live_item(&oauth("A-refreshed"));
        let r2 = refreshed.clone();
        let live = w.live();
        w.profile.add("at-B", "B", "oB", "b@x");
        let inner = writes(oauth("B"), "B", "oB");
        let claude = fake(
            &w,
            Box::new(move |cmd, store| {
                inner(cmd, store);
                // Claude Code refreshed the live token meanwhile.
                store
                    .set(&live.service, &live.account, &Secret::new(r2.clone()))
                    .unwrap();
            }),
        );
        let ctx = w.ctx();
        let e = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap_err();
        let Error::LiveItemChangedDuringLogin { backup_id } = &e else {
            panic!("{e:?}");
        };
        assert_eq!(e.code(), "live_item_changed_during_login");
        // Not restored: the refreshed bytes stay.
        assert_eq!(w.live_bytes().unwrap(), refreshed);
        // Pre-login backup kept, holding the pre-login bytes.
        let m: Value = serde_json::from_slice(
            &std::fs::read(w.paths.backups_dir().join(backup_id).join("manifest.json")).unwrap(),
        )
        .unwrap();
        let acct = m["entries"][0]["backup_account"].as_str().unwrap();
        assert_eq!(
            w.store
                .get(crate::backup::BACKUP_SERVICE, acct)
                .unwrap()
                .unwrap()
                .expose(),
            &before[..]
        );
        // Nothing stored; temp state cleaned.
        assert!(stored_oauth(&w.store, "B::oB").unwrap().is_none());
        assert_eq!(hashed_items(&w), 0);
        assert_eq!(login_dirs(&w), 0);
    }

    #[test]
    fn relogin_replaces_grant_and_org_mismatch_stores_nothing() {
        let w = World::new();
        let b1 = oauth("B1");
        add_account(&w, "B::oB", "b@x", &b1);
        let b2 = oauth("B2");
        w.profile.add("at-B2", "B", "oB", "b@x");
        let ctx = w.ctx();
        let claude = fake(&w, writes(b2.clone(), "B", "oB"));
        let e = login(
            &ctx,
            &claude,
            &w.store,
            &LoginOpts {
                org: Some("other-org".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), "org_mismatch");
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b1);
        let r = login(
            &ctx,
            &claude,
            &w.store,
            &LoginOpts {
                org: Some("org ob".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(r.replaced);
        assert!(
            r.warnings
                .iter()
                .any(|x| x.code == "grant_replaced" && x.message.contains("not revoked"))
        );
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b2);
        assert_eq!(hashed_items(&w), 0);
    }

    #[test]
    fn console_login_with_empty_item_fails_closed() {
        let w = World::new();
        let claude = fake(
            &w,
            Box::new(|cmd, store| {
                let env = MapEnv::new(cmd.env.clone());
                store
                    .set(
                        &live_service(&env).unwrap(),
                        &keychain_account(&env),
                        &Secret::new(b"{}".to_vec()),
                    )
                    .unwrap();
            }),
        );
        let ctx = w.ctx();
        let e = login(
            &ctx,
            &claude,
            &w.store,
            &LoginOpts {
                console: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), "unsupported");
        assert!(
            claude.seen.borrow()[0]
                .args
                .contains(&"--console".to_string())
        );
        assert_eq!(w.store.count(OWN_SERVICE), 0);
        assert_eq!(hashed_items(&w), 0);
        assert_eq!(login_dirs(&w), 0);
    }

    #[test]
    fn unexpected_items_unidentified_and_interrupt_clean_up() {
        let w = World::new();
        let ctx = w.ctx();
        // An extra, differently named item appears: fail closed, delete only
        // the expected name.
        let inner = writes(oauth("B"), "B", "oB");
        let claude = fake(
            &w,
            Box::new(move |cmd, store| {
                inner(cmd, store);
                store
                    .set(
                        "Claude Code-credentials-deadbeef",
                        USER,
                        &Secret::new(b"{}".to_vec()),
                    )
                    .unwrap();
            }),
        );
        let e = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap_err();
        assert_eq!(e.code(), "unidentified");
        assert_eq!(
            w.store.names_with_prefix("Claude Code-credentials-"),
            vec![(
                "Claude Code-credentials-deadbeef".to_string(),
                USER.to_string()
            )]
        );
        w.store
            .delete("Claude Code-credentials-deadbeef", USER)
            .unwrap();
        // No profile for the new token: unidentified, nothing stored.
        let claude = fake(&w, writes(oauth("C"), "C", "oC"));
        let e = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap_err();
        assert_eq!(e.code(), "unidentified");
        assert_eq!(w.store.count(OWN_SERVICE), 0);
        // Ctrl-C while the login runs.
        let mut claude = fake(&w, writes(oauth("D"), "D", "oD"));
        claude.exit = LoginExit {
            code: None,
            interrupted: true,
        };
        assert!(matches!(
            login(&ctx, &claude, &w.store, &LoginOpts::default()),
            Err(Error::Interrupted)
        ));
        assert_eq!(hashed_items(&w), 0);
        assert_eq!(login_dirs(&w), 0);
    }

    #[test]
    fn login_recovers_a_crashed_switch_before_the_browser_flow() {
        use crate::switch::failpoint::{self, Act};
        use crate::switch::{Confirm, SwitchOpts, switch_cli};
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        add_account(&w, "B::oB", "b@x", &oauth("B"));
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&a));
        let before = w.live_bytes().unwrap();
        let ctx = w.ctx();
        {
            let mut s = begin(&ctx).unwrap();
            failpoint::set(|step, _| {
                if step == "keychain" {
                    Act::Crash
                } else {
                    Act::Continue
                }
            });
            let procs = crate::procs::tests::FakeProcs::default();
            let r = switch_cli(
                &mut s,
                "B::oB",
                &SwitchOpts {
                    confirm: Confirm::NonInteractive { force: false },
                    replace_live: Confirm::NonInteractive { force: false },
                    procs: &procs,
                },
            );
            failpoint::clear();
            assert!(matches!(r, Err(Error::Interrupted)));
        }
        assert!(w.paths.journal_file().exists());
        w.profile.add("at-C", "C", "oC", "c@x");
        let claude = fake(&w, writes(oauth("C"), "C", "oC"));
        let r = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap();
        assert_eq!(r.key, "C::oC");
        assert!(
            r.warnings.iter().any(|x| x.code == "recovered"),
            "{:?}",
            r.warnings
        );
        assert_eq!(w.live_bytes().unwrap(), before, "rolled back to A");
        assert!(!w.paths.journal_file().exists());
    }

    struct BrokenLister;
    impl ItemLister for BrokenLister {
        fn list(&self, _: &str) -> Result<Vec<(String, String)>> {
            Err(Error::ExternalTool {
                program: "security",
                sub: "dump-keychain",
                code: Some(1),
                class: ToolFailure::Other,
            })
        }
    }

    #[test]
    fn listing_failure_is_fatal_before_spawn() {
        let w = World::new();
        let claude = fake(&w, writes(oauth("B"), "B", "oB"));
        let ctx = w.ctx();
        assert!(login(&ctx, &claude, &BrokenLister, &LoginOpts::default()).is_err());
        assert!(claude.seen.borrow().is_empty());
        assert_eq!(login_dirs(&w), 0);
    }

    #[test]
    fn sweep_removes_only_old_dirs_and_their_computed_items() {
        let w = World::new();
        let old = w
            .paths
            .cma_home
            .join(format!("{DIR_PREFIX}{}", NOW_MS - 2 * SWEEP_AGE_MS));
        let young = w
            .paths
            .cma_home
            .join(format!("{DIR_PREFIX}{}", NOW_MS - 1000));
        for d in [&old, &young] {
            std::fs::create_dir(d).unwrap();
        }
        let svc = |d: &PathBuf| service_for_dir(d.to_str().unwrap()).unwrap();
        for d in [&old, &young] {
            w.store
                .set(&svc(d), USER, &Secret::new(b"{}".to_vec()))
                .unwrap();
        }
        let ws = sweep(&w.paths, &w.env, &w.store, NOW_MS).unwrap();
        assert_eq!(ws.len(), 1, "{ws:?}");
        assert!(!old.exists() && young.exists());
        assert!(w.store.get(&svc(&old), USER).unwrap().is_none());
        assert!(w.store.get(&svc(&young), USER).unwrap().is_some());
    }

    #[test]
    fn parse_dump_reads_svce_and_acct_only() {
        let text = r#"keychain: "/Users/me/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="Claude Code-credentials"
    "acct"<blob>="me"
    "svce"<blob>="Claude Code-credentials"
keychain: "/Users/me/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>="me"
    "svce"<blob>="Claude Code-credentials-fa973b43"
keychain: "/Users/me/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>=0x00FF  "\000\377"
    "svce"<blob>="Claude Code-credentials-0000aaaa"
keychain: "/Users/me/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>="x"
    "svce"<blob>="other"
"#;
        assert_eq!(
            parse_dump(text, "Claude Code-credentials"),
            vec![
                ("Claude Code-credentials".to_string(), "me".to_string()),
                (
                    "Claude Code-credentials-fa973b43".to_string(),
                    "me".to_string()
                ),
            ]
        );
    }

    /// Real `security dump-keychain` (attributes only), dummy item in
    /// service `claude-multi-auth-test`. Run with
    /// `cargo test -p cma-core -- --ignored keychain`.
    #[test]
    #[ignore = "touches the real Keychain (service claude-multi-auth-test)"]
    fn keychain_dump_lister_sees_test_item() {
        use crate::secret::SecurityCliStore;
        const SVC: &str = "claude-multi-auth-test";
        const ACCT: &str = "cma-core-test-dump-lister";
        let store = SecurityCliStore::new();
        let _ = store.delete(SVC, ACCT);
        store
            .set(SVC, ACCT, &Secret::new(br#"{"dummy":"lister"}"#.to_vec()))
            .unwrap();
        let listed = DumpKeychainLister.list(SVC);
        let _ = store.delete(SVC, ACCT);
        let listed = listed.unwrap();
        assert!(
            listed.contains(&(SVC.to_string(), ACCT.to_string())),
            "{} items listed",
            listed.len()
        );
        assert!(listed.iter().all(|(s, _)| s.starts_with(SVC)));
    }

    #[test]
    fn env_allowlist_is_exact() {
        let parent = MapEnv::new([
            ("HOME", "/h"),
            ("PATH", "/p"),
            ("TERM", "xterm"),
            ("CLAUDE_CONFIG_DIR", "/parent"),
            ("CLAUDE_SECURESTORAGE_CONFIG_DIR", ""),
            ("AWS_SECRET_ACCESS_KEY", "x"),
        ]);
        let env = login_env(&parent, "/c/login-1");
        assert_eq!(
            env,
            vec![
                ("HOME".to_string(), "/h".to_string()),
                ("PATH".into(), "/p".into()),
                ("TERM".into(), "xterm".into()),
                ("CLAUDE_CONFIG_DIR".into(), "/c/login-1".into()),
                (
                    "CLAUDE_SECURESTORAGE_CONFIG_DIR".into(),
                    "/c/login-1".into()
                ),
            ]
        );
    }

    #[test]
    fn relogin_of_the_active_account_updates_the_live_item() {
        let w = World::new();
        let b1 = oauth("B1");
        add_account(&w, "B::oB", "b@x", &b1);
        set_active(&w, Some("B::oB"));
        w.set_live(&live_item(&b1));
        let live_before = w.live_bytes().unwrap();
        let b2 = oauth("B2");
        w.profile.add("at-B2", "B", "oB", "b@x");
        let claude = fake(&w, writes(b2.clone(), "B", "oB"));
        let ctx = w.ctx();
        let r = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap();
        assert!(r.replaced);
        assert!(
            r.warnings.iter().any(|x| x.code == "live_login_updated"),
            "{:?}",
            r.warnings
        );
        // stored == live == B2; only claudeAiOauth changed, under the lock.
        let live_after = w.live_bytes().unwrap();
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b2);
        assert_eq!(oauth_of(&live_after).unwrap().unwrap(), b2);
        assert_eq!(
            crate::cli_target::RawItem::parse(&live_after)
                .unwrap()
                .others(),
            crate::cli_target::RawItem::parse(&live_before)
                .unwrap()
                .others()
        );
        assert_eq!(
            w.locker.acquired.get(),
            1,
            "live write under .storage-write"
        );
        assert!(!w.paths.journal_file().exists());
        // The old live item is in the backup.
        let backups = crate::backup::BACKUP_SERVICE;
        assert!(
            w.store.count(backups) >= 2,
            "pre-login + live-update backups"
        );
        // The next command keeps B2: the old grant is not restored.
        let s = begin(&ctx).unwrap();
        assert!(
            s.warnings.iter().all(|x| x.code != "live_account_changed"),
            "{:?}",
            s.warnings
        );
        drop(s);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b2);
        assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), b2);
    }

    #[test]
    fn relogin_of_an_inactive_account_leaves_the_live_item() {
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        add_account(&w, "B::oB", "b@x", &oauth("B1"));
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&a));
        let before = w.live_bytes().unwrap();
        w.profile.add("at-B2", "B", "oB", "b@x");
        let claude = fake(&w, writes(oauth("B2"), "B", "oB"));
        let ctx = w.ctx();
        let r = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap();
        assert!(r.warnings.iter().all(|x| x.code != "live_login_updated"));
        assert_eq!(w.live_bytes().unwrap(), before);
        assert_eq!(w.locker.acquired.get(), 0);
    }

    #[test]
    fn failed_live_read_after_login_stores_nothing() {
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&a));
        let before = w.live_bytes().unwrap();
        w.profile.add("at-B", "B", "oB", "b@x");
        let fg = crate::cli_target::testkit::FailGet::live(&w);
        let armed = fg.armed.clone();
        let inner = writes(oauth("B"), "B", "oB");
        // The live item becomes unreadable once `claude auth login` ran, so
        // the post-login reads (sync, then the live-hash guard) fail.
        let claude = fake(
            &w,
            Box::new(move |cmd, store| {
                inner(cmd, store);
                armed.set(true);
            }),
        );
        let ctx = w.ctx_with(&fg);
        let e = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap_err();
        assert_eq!(e.code(), "external_tool", "{e}");
        fg.armed.set(false);
        assert!(stored_oauth(&w.store, "B::oB").unwrap().is_none());
        assert_eq!(w.live_bytes().unwrap(), before);
        assert_eq!(hashed_items(&w), 0);
        assert_eq!(login_dirs(&w), 0);
    }

    /// Lists once, then fails (the listing after `claude auth login`).
    struct FailsSecondTime<'a>(&'a MemoryStore, std::cell::Cell<u32>);
    impl ItemLister for FailsSecondTime<'_> {
        fn list(&self, prefix: &str) -> Result<Vec<(String, String)>> {
            self.1.set(self.1.get() + 1);
            if self.1.get() > 1 {
                return BrokenLister.list(prefix);
            }
            self.0.list(prefix)
        }
    }

    #[test]
    fn listing_failure_after_login_stores_nothing_and_cleans_up() {
        let w = World::new();
        w.profile.add("at-B", "B", "oB", "b@x");
        let claude = fake(&w, writes(oauth("B"), "B", "oB"));
        let lister = FailsSecondTime(&w.store, Default::default());
        let ctx = w.ctx();
        let e = login(&ctx, &claude, &lister, &LoginOpts::default()).unwrap_err();
        assert_eq!(e.code(), "external_tool", "{e}");
        assert_eq!(lister.1.get(), 2);
        assert_eq!(claude.seen.borrow().len(), 1, "the login ran");
        assert!(stored_oauth(&w.store, "B::oB").unwrap().is_none());
        assert_eq!(w.store.count(OWN_SERVICE), 0);
        // The item the login created is deleted by its computed name.
        assert_eq!(hashed_items(&w), 0);
        assert_eq!(login_dirs(&w), 0);
    }

    #[test]
    fn default_sigint_is_restored_after_the_login_process() {
        // A harmless program stands in for `claude`.
        let exit = ClaudeLoginSpawner
            .run(&LoginCommand {
                program: "/usr/bin/true".into(),
                args: vec![],
                env: vec![],
            })
            .unwrap();
        assert_eq!(exit.code, Some(0));
        assert!(!exit.interrupted);
        assert!(
            sigint_default_flag().unwrap().load(Ordering::SeqCst),
            "after the login, SIGINT takes the default action again"
        );
    }

    #[test]
    fn relogin_of_a_signed_out_active_account_updates_the_live_item() {
        let w = World::new();
        // World's ~/.claude.json oauthAccount names A.
        add_account(&w, "A::oA", "a@x", &oauth("A1"));
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&blanked()));
        let a2 = oauth("A2");
        w.profile.add("at-A2", "A", "oA", "a@x");
        let claude = fake(&w, writes(a2.clone(), "A", "oA"));
        let ctx = w.ctx();
        let r = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap();
        assert!(
            r.warnings.iter().any(|x| x.code == "live_login_updated"),
            "{:?}",
            r.warnings
        );
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a2);
        assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), a2);
        assert!(!w.paths.journal_file().exists());
        let s = begin(&ctx).unwrap();
        assert!(
            s.warnings
                .iter()
                .all(|x| x.code != "needs_login" && x.code != "live_account_changed"),
            "{:?}",
            s.warnings
        );
        assert_eq!(
            s.live,
            crate::sync::LiveState::Identified {
                key: "A::oA".into(),
                managed: true
            }
        );
    }

    #[test]
    fn relogin_of_the_active_account_with_an_unconfirmed_live_login_leaves_it() {
        let w = World::new();
        add_account(&w, "A::oA", "a@x", &oauth("A1"));
        set_active(&w, Some("A::oA"));
        // Unknown token, no profile: unidentified; active.cli stays A.
        let other = live_item(&oauth("unknown"));
        w.set_live(&other);
        w.profile.add("at-A2", "A", "oA", "a@x");
        let claude = fake(&w, writes(oauth("A2"), "A", "oA"));
        let ctx = w.ctx();
        let r = login(&ctx, &claude, &w.store, &LoginOpts::default()).unwrap();
        assert!(
            r.warnings
                .iter()
                .any(|x| x.code == "live_login_not_updated"),
            "{:?}",
            r.warnings
        );
        assert_eq!(w.live_bytes().unwrap(), other);
        assert_eq!(w.locker.acquired.get(), 0);
    }
}
