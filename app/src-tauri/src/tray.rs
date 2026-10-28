//! The menubar menu. Rebuilt from `registry.json` and the account Claude
//! Desktop's `config.json` names (both read-only, no lock, no Keychain
//! access) whenever state may have changed; the menu text is decided by
//! [`model`], a plain function, and turned into Tauri items by [`build`].
//!
//! Clicks run on the main thread, so every action that runs a cma command
//! (or shows a dialog) moves to its own thread first.

use std::sync::atomic::Ordering;

use cma_core::paths::Paths;
use cma_core::registry::{Account, Registry, SessionFollow};
use serde_json::Value;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager};

use crate::commands::{self, AppState};

pub const TRAY_ID: &str = "main";

/// One menu line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// Disabled text.
    Info(String),
    Separator,
    /// An account with its switch actions (a submenu).
    Account {
        title: String,
        items: Vec<Item>,
    },
    Toggle {
        id: &'static str,
        title: String,
        checked: bool,
    },
    Action {
        id: &'static str,
        title: String,
    },
}

/// One action in an account's submenu; `id` is `<action>:<key>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: String,
    pub title: String,
    pub enabled: bool,
}

fn item(id: String, title: &str, enabled: bool) -> Item {
    Item {
        id,
        title: title.into(),
        enabled,
    }
}

/// `alias (email)`, or the email, or the key.
pub fn label(a: &Account) -> String {
    let base = if a.email.is_empty() {
        a.key.clone()
    } else {
        a.email.clone()
    };
    match &a.alias {
        Some(al) => format!("{al} ({base})"),
        None => base,
    }
}

fn pct(a: &Account, window: &str) -> Option<i64> {
    let u = a.usage.windows.get(window)?.get("utilization")?.as_f64()?;
    Some(u.round() as i64)
}

/// `CLI: alice@x (max) · 5h 42% · 7d 18%`.
pub fn header(reg: &Registry) -> String {
    let Some(a) = reg.active.cli.as_deref().and_then(|k| reg.account(k)) else {
        return "CLI: no cma account active".into();
    };
    let mut s = format!("CLI: {}", label(a));
    if !a.plan.is_empty() {
        s.push_str(&format!(" ({})", a.plan));
    }
    for (w, name) in [("five_hour", "5h"), ("seven_day", "7d")] {
        if let Some(p) = pct(a, w) {
            s.push_str(&format!(" · {name} {p}%"));
        }
    }
    s
}

/// Whether cma stores a Claude Desktop login for the account.
fn desktop_linked(reg: &Registry, a: &Account) -> bool {
    !a.account_uuid.is_empty() && reg.desktop.iter().any(|l| l.account_uuid == a.account_uuid)
}

/// `Desktop: alice@x`, with `(not linked)` when cma stores no Desktop
/// login for it. `live`: the account uuid Desktop's `config.json` names, or
/// why it could not be read.
pub fn desktop_line(reg: &Registry, live: Result<Option<&str>, &str>) -> String {
    let uuid = match live {
        Err(e) => return format!("Desktop: login unreadable ({e})"),
        Ok(None) => return "Desktop: not signed in".into(),
        Ok(Some(u)) => u,
    };
    let Some(a) = reg.accounts.iter().find(|a| a.account_uuid == uuid) else {
        return "Desktop: signed in as an account cma does not store".into();
    };
    let mut s = format!("Desktop: {}", label(a));
    if !desktop_linked(reg, a) {
        s.push_str(" (not linked)");
    }
    s
}

/// An account's submenu: switch Claude Code, switch Claude Desktop (or
/// link it first), or both. `desktop_on`: Desktop is signed in as it now.
pub fn account_items(reg: &Registry, a: &Account, desktop_on: bool) -> Vec<Item> {
    let key = &a.key;
    let cli_active = reg.active.cli.as_deref() == Some(key.as_str());
    let linked = desktop_linked(reg, a);
    let cli = if cli_active {
        item(format!("cli:{key}"), "Active for Claude Code", false)
    } else if a.has_cli {
        item(format!("cli:{key}"), "Switch CLI", true)
    } else {
        item(
            format!("cli:{key}"),
            "Switch CLI (no Claude Code login)",
            false,
        )
    };
    let desktop = match (linked, desktop_on) {
        (true, true) => item(format!("desktop:{key}"), "Active for Claude Desktop", false),
        (true, false) => item(format!("desktop:{key}"), "Switch Desktop", true),
        (false, _) => item(format!("link:{key}"), "Link Desktop…", true),
    };
    let both = item(
        format!("both:{key}"),
        "Switch CLI + Desktop",
        linked && a.has_cli && !(cli_active && desktop_on),
    );
    vec![cli, desktop, both]
}

/// The menu, top to bottom. `desktop`: the account uuid Claude Desktop is
/// signed in as (or why that could not be read). `error`: the registry
/// could not be read. `problem`: an unfinished operation, uncertain state
/// or sync error to resolve in the settings window.
pub fn model(
    reg: &Registry,
    desktop: Result<Option<&str>, &str>,
    error: Option<&str>,
    problem: Option<&str>,
) -> Vec<Entry> {
    let mut m = Vec::new();
    match error {
        Some(e) => m.push(Entry::Info(format!("cma state unreadable: {e}"))),
        None => m.push(Entry::Info(header(reg))),
    }
    if let Some(p) = problem {
        m.push(Entry::Info(format!("⚠ {p}")));
        m.push(Entry::Action {
            id: "resolve",
            title: "Resolve…".into(),
        });
        m.push(Entry::Separator);
    }
    for a in &reg.accounts {
        let active = reg.active.cli.as_deref() == Some(a.key.as_str());
        let desktop_on = !a.account_uuid.is_empty() && desktop == Ok(Some(&a.account_uuid));
        let mut title = format!("{} {}", if active { "✓" } else { "  " }, label(a));
        if !a.org_name.is_empty() {
            title.push_str(&format!(" — {}", a.org_name));
        }
        if desktop_on {
            title.push_str("  · Desktop");
        }
        if a.needs_login {
            title.push_str("  (needs login)");
        }
        m.push(Entry::Account {
            title,
            items: account_items(reg, a, desktop_on),
        });
    }
    if reg.accounts.is_empty() && error.is_none() {
        m.push(Entry::Info("No accounts yet".into()));
    }
    m.push(Entry::Separator);
    if error.is_none() {
        m.push(Entry::Info(desktop_line(reg, desktop)));
    }
    m.push(Entry::Separator);
    m.push(Entry::Toggle {
        id: "follow",
        title: "Session follow (Desktop)".into(),
        checked: reg.settings.session_follow == SessionFollow::On,
    });
    m.push(Entry::Action {
        id: "add",
        title: "Add account…".into(),
    });
    m.push(Entry::Action {
        id: "settings",
        title: "Settings…".into(),
    });
    m.push(Entry::Action {
        id: "quit",
        title: "Quit".into(),
    });
    m
}

/// What needs resolving: an operation journal on disk (checked directly,
/// so it shows even before the window ran `status`), else what the last
/// command or `status` reported.
fn problem(app: &AppHandle) -> Option<String> {
    let journal = Paths::from_system()
        .ok()
        .is_some_and(|p| std::fs::symlink_metadata(p.journal_file()).is_ok());
    if journal {
        return Some("Unfinished cma operation: changes are refused until it is resolved".into());
    }
    app.state::<AppState>()
        .problem
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn load() -> (Registry, Option<String>) {
    let r = Paths::from_system().and_then(|p| Registry::load(&p.registry_file()));
    match r {
        Ok(r) => (r, None),
        Err(e) => (Registry::default(), Some(e.to_string())),
    }
}

/// The account uuid Claude Desktop's `config.json` names now.
fn desktop_live() -> Result<Option<String>, String> {
    Paths::from_system()
        .and_then(|p| cma_core::desktop_target::live_account(&p))
        .map_err(|e| e.to_string())
}

/// Build Tauri menu items from the model.
pub fn build(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let (reg, err) = load();
    let live = desktop_live();
    let live = match &live {
        Ok(u) => Ok(u.as_deref()),
        Err(e) => Err(e.as_str()),
    };
    let problem = problem(app);
    let menu = Menu::new(app)?;
    for e in model(&reg, live, err.as_deref(), problem.as_deref()) {
        match e {
            Entry::Info(t) => menu.append(&MenuItem::new(app, t, false, None::<&str>)?)?,
            Entry::Separator => menu.append(&PredefinedMenuItem::separator(app)?)?,
            Entry::Account { title, items } => {
                let sub = Submenu::new(app, title, true)?;
                for i in items {
                    sub.append(&MenuItem::with_id(
                        app,
                        i.id,
                        i.title,
                        i.enabled,
                        None::<&str>,
                    )?)?;
                }
                menu.append(&sub)?;
            }
            Entry::Toggle { id, title, checked } => menu.append(&CheckMenuItem::with_id(
                app,
                id,
                title,
                true,
                checked,
                None::<&str>,
            )?)?,
            Entry::Action { id, title } => {
                menu.append(&MenuItem::with_id(app, id, title, true, None::<&str>)?)?
            }
        }
    }
    Ok(menu)
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .icon_as_template(true)
        .tooltip("Claude Multi Auth")
        .show_menu_on_left_click(true)
        .menu(&build(app)?)
        .on_menu_event(|app, event| handle(app, event.id().as_ref()))
        .build(app)?;
    Ok(())
}

/// Rebuild the menu (any thread).
pub fn refresh(app: &AppHandle) {
    if let Some(tray) = app.tray_by_id(TRAY_ID)
        && let Ok(menu) = build(app)
    {
        let _ = tray.set_menu(Some(menu));
    }
}

fn handle(app: &AppHandle, id: &str) {
    match id {
        "quit" => quit(app),
        "resolve" => crate::open_settings(app, Some("accounts")),
        "settings" => crate::open_settings(app, Some("settings")),
        "add" => crate::open_settings(app, Some("add")),
        "follow" => {
            let app = app.clone();
            std::thread::spawn(move || {
                let (reg, _) = load();
                let next = match reg.settings.session_follow {
                    SessionFollow::On => "off",
                    SessionFollow::Off => "on",
                };
                let doc = commands::set_setting_blocking(&app, "session_follow", next);
                report(&app, &doc, None);
                refresh(&app);
            });
        }
        _ => {
            let Some((action, key)) = id.split_once(':') else {
                return;
            };
            if !matches!(action, "cli" | "desktop" | "both" | "link") {
                return;
            }
            let (app, action, key) = (app.clone(), action.to_string(), key.to_string());
            std::thread::spawn(move || {
                let doc = if action == "link" {
                    commands::desktop_link_blocking(&app, &key)
                } else {
                    commands::switch_blocking(&app, &key, &action)
                };
                let done = done_message(&action, &doc["data"], &|k| {
                    let (reg, _) = load();
                    reg.account(k).map(label).unwrap_or_else(|| k.to_string())
                });
                report(&app, &doc, done.as_deref());
            });
        }
    }
}

/// The notification after a successful tray action (`name`: an account
/// key's label).
pub fn done_message(action: &str, data: &Value, name: &dyn Fn(&str) -> String) -> Option<String> {
    if action == "link" {
        let t = name(data["key"].as_str()?);
        return Some(if data["restored_previous"].is_null() {
            format!("Linked {t} to Claude Desktop; Claude Desktop now uses it.")
        } else {
            format!("Linked {t} to Claude Desktop; Claude Desktop is back on the previous account.")
        });
    }
    let t = name(data["to"].as_str()?);
    Some(match action {
        "desktop" => format!("Claude Desktop now uses {t}."),
        "both" if data["desktop"]["switched"] == false && !data["desktop"]["reason"].is_null() => {
            format!("Claude Code now uses {t}; Claude Desktop was not switched.")
        }
        "both" => {
            format!("Claude Code and Claude Desktop now use {t}. New claude sessions use it.")
        }
        _ => format!("Claude Code now uses {t}. New claude sessions use it."),
    })
}

/// Quit, but never in the middle of an app command: if one is running
/// (possibly waiting on a dialog), ask, then wait for it to finish.
fn quit(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        if let Ok(g) = state.gate.try_lock() {
            // From here no new operation starts (they check the flag after
            // taking the gate), and the gate is never released before the
            // process exits.
            state.quitting.store(true, Ordering::SeqCst);
            std::mem::forget(g);
            app.exit(0);
            return;
        }
        if commands::ask(
            &app,
            "A cma operation is still running (it may be waiting for an answer in another dialog).\n\nQuit as soon as it finishes?",
        ) {
            // Queued and background operations refuse from now on; the
            // running one finishes first.
            state.quitting.store(true, Ordering::SeqCst);
            let g = state.gate.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::forget(g);
            app.exit(0);
        }
    });
}

/// Show a command's outcome from a tray action: an error (with its hint) in
/// a dialog, success and warnings as a notification. Not on the main
/// thread.
fn report(app: &AppHandle, doc: &Value, done: Option<&str>) {
    let warnings: Vec<&str> = doc["warnings"]
        .as_array()
        .map(|w| w.iter().filter_map(|x| x["message"].as_str()).collect())
        .unwrap_or_default();
    if doc["ok"] != true {
        let mut msg = doc["error"]["message"]
            .as_str()
            .unwrap_or("the command failed")
            .to_string();
        if let Some(h) = doc["error"]["hint"].as_str() {
            msg.push_str(&format!("\n\nHint: {h}"));
        }
        // The user's own Cancel: a quiet note, not an error box. (cma
        // giving up on a question that kept changing stays an error.)
        if doc["error"]["code"] == "cancelled" {
            crate::notify(app, "Claude Multi Auth", "Cancelled; nothing was changed.");
            return;
        }
        use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
        app.dialog()
            .message(msg)
            .title("Claude Multi Auth")
            .kind(MessageDialogKind::Error)
            .blocking_show();
        return;
    }
    let mut body = done.unwrap_or_default().to_string();
    for w in warnings {
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(w);
    }
    if !body.is_empty() {
        crate::notify(app, "Claude Multi Auth", &body);
    }
    app.state::<AppState>().bump();
}

#[cfg(test)]
mod tests {
    use super::*;
    use cma_core::registry::DesktopLink;
    use serde_json::json;

    const DA: &str = "3a000000-0000-4000-8000-00000000000a";
    const DB: &str = "7b000000-0000-4000-8000-00000000000b";
    const DC: &str = "5c000000-0000-4000-8000-00000000000c";

    fn acct(key: &str, email: &str) -> Account {
        Account {
            key: key.into(),
            email: email.into(),
            has_cli: true,
            ..Account::default()
        }
    }

    fn link(r: &mut Registry, uuid: &str) {
        r.desktop.push(DesktopLink {
            account_uuid: uuid.into(),
            ..DesktopLink::default()
        });
    }

    /// A (CLI active, Desktop linked and signed in), B (linked), C (not
    /// linked, needs login).
    fn three() -> Registry {
        let mut r = Registry::default();
        let mut a = acct(&format!("{DA}::oA"), "a@x.test");
        a.account_uuid = DA.into();
        a.org_name = "Team A".into();
        a.alias = Some("work".into());
        let mut b = acct(&format!("{DB}::oB"), "b@x.test");
        b.account_uuid = DB.into();
        let mut c = acct(&format!("{DC}::oC"), "c@x.test");
        c.account_uuid = DC.into();
        c.needs_login = true;
        r.accounts = vec![a, b, c];
        r.active.cli = Some(format!("{DA}::oA"));
        link(&mut r, DA);
        link(&mut r, DB);
        r
    }

    fn submenu(m: &[Entry], n: usize) -> (String, Vec<(String, String, bool)>) {
        match &m[n] {
            Entry::Account { title, items } => (
                title.clone(),
                items
                    .iter()
                    .map(|i| (i.id.clone(), i.title.clone(), i.enabled))
                    .collect(),
            ),
            e => panic!("not an account: {e:?}"),
        }
    }

    fn it(id: String, title: &str, enabled: bool) -> (String, String, bool) {
        (id, title.into(), enabled)
    }

    #[test]
    fn header_shows_the_active_account_plan_and_usage() {
        let mut r = Registry::default();
        assert_eq!(header(&r), "CLI: no cma account active");
        let mut a = acct("A::oA", "alice@x.test");
        a.plan = "max".into();
        a.usage
            .windows
            .insert("five_hour".into(), json!({"utilization": 41.6}));
        a.usage
            .windows
            .insert("seven_day".into(), json!({"utilization": 18.0}));
        r.accounts.push(a);
        r.active.cli = Some("A::oA".into());
        assert_eq!(header(&r), "CLI: alice@x.test (max) · 5h 42% · 7d 18%");
    }

    #[test]
    fn accounts_show_the_desktop_account_and_switch_or_link_actions() {
        let r = three();
        let (ka, kb, kc) = (
            format!("{DA}::oA"),
            format!("{DB}::oB"),
            format!("{DC}::oC"),
        );
        let m = model(&r, Ok(Some(DA)), None, None);
        let (title, items) = submenu(&m, 1);
        assert_eq!(title, "✓ work (a@x.test) — Team A  · Desktop");
        assert_eq!(
            items,
            [
                it(format!("cli:{ka}"), "Active for Claude Code", false),
                it(format!("desktop:{ka}"), "Active for Claude Desktop", false),
                it(format!("both:{ka}"), "Switch CLI + Desktop", false),
            ]
        );
        // Linked: Desktop and both can switch to it.
        let (title, items) = submenu(&m, 2);
        assert_eq!(title, "   b@x.test");
        assert_eq!(
            items,
            [
                it(format!("cli:{kb}"), "Switch CLI", true),
                it(format!("desktop:{kb}"), "Switch Desktop", true),
                it(format!("both:{kb}"), "Switch CLI + Desktop", true),
            ]
        );
        // Not linked: link it first; both needs the link.
        let (title, items) = submenu(&m, 3);
        assert_eq!(title, "   c@x.test  (needs login)");
        assert_eq!(
            items,
            [
                it(format!("cli:{kc}"), "Switch CLI", true),
                it(format!("link:{kc}"), "Link Desktop…", true),
                it(format!("both:{kc}"), "Switch CLI + Desktop", false),
            ]
        );
        assert!(m.contains(&Entry::Info("Desktop: work (a@x.test)".into())));
        assert!(m.contains(&Entry::Toggle {
            id: "follow",
            title: "Session follow (Desktop)".into(),
            checked: false,
        }));
        let ids: Vec<&str> = m
            .iter()
            .filter_map(|e| match e {
                Entry::Action { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(ids, ["add", "settings", "quit"]);
    }

    #[test]
    fn the_desktop_line_names_who_desktop_is_signed_in_as() {
        let r = three();
        assert_eq!(desktop_line(&r, Ok(Some(DB))), "Desktop: b@x.test");
        assert_eq!(
            desktop_line(&r, Ok(Some(DC))),
            "Desktop: c@x.test (not linked)"
        );
        assert_eq!(desktop_line(&r, Ok(None)), "Desktop: not signed in");
        assert_eq!(
            desktop_line(&r, Ok(Some("00000000-0000-4000-8000-000000000000"))),
            "Desktop: signed in as an account cma does not store"
        );
        assert_eq!(
            desktop_line(&r, Err("bad json")),
            "Desktop: login unreadable (bad json)"
        );
        // Signed in as B: B's Desktop item is the active one, A's switches.
        let m = model(&r, Ok(Some(DB)), None, None);
        assert!(submenu(&m, 1).1[1].2);
        assert_eq!(submenu(&m, 2).1[1].1, "Active for Claude Desktop");
        assert!(submenu(&m, 2).0.ends_with("· Desktop"));
    }

    #[test]
    fn a_desktop_only_account_cannot_switch_claude_code() {
        let mut r = three();
        r.accounts[1].has_cli = false;
        let m = model(&r, Ok(None), None, None);
        let (_, items) = submenu(&m, 2);
        assert_eq!(items[0].1, "Switch CLI (no Claude Code login)");
        assert!(!items[0].2);
        assert!(items[1].2, "Desktop can still switch to it");
        assert!(!items[2].2, "both needs a Claude Code login");
    }

    #[test]
    fn tray_notifications_name_what_switched() {
        let name = |k: &str| format!("<{k}>");
        let d = json!({"to": "B::oB", "desktop": null});
        assert_eq!(
            done_message("cli", &d, &name).unwrap(),
            "Claude Code now uses <B::oB>. New claude sessions use it."
        );
        let d = json!({"to": "B::oB", "desktop": {"switched": true}});
        assert_eq!(
            done_message("desktop", &d, &name).unwrap(),
            "Claude Desktop now uses <B::oB>."
        );
        assert!(
            done_message("both", &d, &name)
                .unwrap()
                .starts_with("Claude Code and Claude Desktop now use <B::oB>.")
        );
        let d =
            json!({"to": "B::oB", "desktop": {"switched": false, "reason": "desktop_not_linked"}});
        assert!(
            done_message("both", &d, &name)
                .unwrap()
                .contains("Claude Desktop was not switched")
        );
        let d = json!({"key": "B::oB", "restored_previous": null});
        assert!(
            done_message("link", &d, &name)
                .unwrap()
                .ends_with("now uses it.")
        );
        let d = json!({"key": "B::oB", "restored_previous": {"switched": true}});
        assert!(
            done_message("link", &d, &name)
                .unwrap()
                .contains("back on the previous account")
        );
        assert_eq!(done_message("desktop", &Value::Null, &name), None);
    }

    #[test]
    fn a_problem_is_shown_with_a_resolve_action() {
        let m = model(
            &Registry::default(),
            Ok(None),
            None,
            Some("Unfinished cma operation"),
        );
        assert_eq!(m[1], Entry::Info("⚠ Unfinished cma operation".into()));
        assert_eq!(
            m[2],
            Entry::Action {
                id: "resolve",
                title: "Resolve…".into()
            }
        );
        assert!(
            !model(&Registry::default(), Ok(None), None, None)
                .iter()
                .any(|e| matches!(e, Entry::Action { id: "resolve", .. }))
        );
    }

    #[test]
    fn an_unreadable_registry_is_shown() {
        let m = model(
            &Registry::default(),
            Ok(None),
            Some("registry_too_new"),
            None,
        );
        assert_eq!(
            m[0],
            Entry::Info("cma state unreadable: registry_too_new".into())
        );
    }
}
