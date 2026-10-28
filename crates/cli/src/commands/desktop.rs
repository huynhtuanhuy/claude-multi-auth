//! Claude Desktop commands: `desktop link|unlink|import-current`, and the
//! Desktop half of `switch --desktop` / `--both`.
//!
//! Desktop is quit (with consent, or `--yes`) before any lock is taken:
//! waiting up to 20 s for it to exit must not hold the cma lock. The op
//! then runs under the lock and keeps checking that Desktop stays quit.
//! Desktop is started again afterwards, also after a failure that left
//! nothing uncertain. Questions are asked with no lock held (see
//! [`super::Consents`]).

use std::cell::Cell;
use std::time::Duration;

use cma_core::desktop_app::{DesktopApp, QUIT_TIMEOUT, quit_and_wait};
use cma_core::desktop_target::{
    DesktopOpts, DesktopReport, check_switch, launch_and_verify, link_live, live_account,
    stash_live, switch_desktop as core_switch, unlink as core_unlink,
};
use cma_core::registry::Registry;
use cma_core::switch::Confirm;
use serde_json::{Value, json};

use super::{CmdResult, Consents, ask, interactive, label, select_key, start, with_consents};
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

/// How long to wait for Desktop to show up after a launch.
const LAUNCH_WAIT: Duration = Duration::from_secs(10);

const QUIT_EXPLANATION: &str = "Claude Desktop is running; cma quits it (never forced) to change its login, and starts it again afterwards";

/// Quit Desktop if it runs, with consent. Runs with no lock held.
fn quit_desktop(
    app: &dyn DesktopApp,
    c: &Consents,
    tty: bool,
    yes: bool,
    quit: &Cell<bool>,
) -> Result<(), CliError> {
    if app.running()?.is_empty() {
        return Ok(());
    }
    if !yes {
        let agreed = tty && c.check(&format!("{QUIT_EXPLANATION}\nQuit Claude Desktop now?"));
        if !agreed {
            return Err(CliError::new(
                "confirmation_required",
                if tty {
                    format!("{QUIT_EXPLANATION}; nothing was changed")
                } else {
                    format!("{QUIT_EXPLANATION}; pass --yes")
                },
            ));
        }
    }
    quit_and_wait(app, QUIT_TIMEOUT)?;
    quit.set(true);
    Ok(())
}

fn replace_confirm<'a>(
    tty: bool,
    flag: bool,
    ask_replace: &'a dyn Fn(&str) -> bool,
) -> Confirm<'a> {
    if flag || !tty {
        Confirm::NonInteractive { force: flag }
    } else {
        Confirm::Interactive(ask_replace)
    }
}

/// After a failed op: start Desktop again if cma quit it, unless the
/// failure left state uncertain (recovery needs Desktop quit).
fn relaunch_after_failure(app: &dyn DesktopApp, quit: bool, e: &CliError, out: &mut Out) {
    if quit
        && !matches!(e.code.as_str(), "state_uncertain" | "desktop_running")
        && app.launch().is_ok()
    {
        out.warn(
            "desktop_relaunched",
            "Claude Desktop was started again; its login did not change",
        );
    }
}

fn report_json(r: &DesktopReport) -> Value {
    json!({
        "switched": !r.already_active,
        "from": r.from,
        "to": r.to,
        "already_active": r.already_active,
        "backup_id": r.backup_id,
        "session_follow": r.session_follow,
        "sessions_moved": r.sessions_moved,
        "sessions_renamed": r.sessions_renamed,
        "sessions_left": r.sessions_left,
    })
}

/// Who a Desktop account uuid is, for messages.
fn who(reg: &Registry, uuid: &str) -> String {
    reg.accounts
        .iter()
        .find(|a| a.account_uuid == uuid)
        .map(super::label_of)
        .unwrap_or_else(|| uuid.to_string())
}

/// Result of the Desktop half of a switch.
pub struct DesktopSwitched {
    pub data: Value,
    pub human: String,
}

/// A Desktop switch checked and prepared: consents given, Desktop quit.
pub struct Prepared {
    key: String,
    uuid: String,
    /// cma quit Desktop (it starts it again afterwards).
    pub quit: bool,
    /// Consent to move away a live login cma does not store.
    replace_ok: bool,
}

/// Everything that can refuse a Desktop switch before any write: link,
/// complete stored login, volume, the `--replace-live` consent and the
/// quit (asked or `--yes`; Desktop must then exit within 20 s). Desktop
/// is quit at the end. No lock is held.
pub fn prepare_switch(
    deps: &Deps,
    out: &mut Out,
    key: &str,
    yes: bool,
    replace_live: bool,
) -> Result<Prepared, CliError> {
    let reg = Registry::load(&deps.paths.registry_file())?;
    let acct = reg
        .account(key)
        .ok_or_else(|| CliError::new("not_found", format!("account {key}")))?;
    let uuid = acct.account_uuid.clone();
    let name = label(&reg, key);
    if !reg.desktop.iter().any(|l| l.account_uuid == uuid) {
        return Err(CliError::new(
            "desktop_not_linked",
            format!("{name} has no Claude Desktop login stored by cma"),
        )
        .with_hint(format!(
            "run `cma desktop link {}` once (or `cma desktop import-current` while Desktop is signed in as it)",
            super::query_for(&reg, key)
        )));
    }
    let app = deps.desktop.as_ref();
    let tty = interactive(out);
    let quit = Cell::new(false);
    let replace_ok = Cell::new(replace_live);
    let already = live_account(&deps.paths)?.as_deref() == Some(uuid.as_str());
    with_consents(tty, |c| {
        let question =
            check_switch(&deps.paths, deps.store.as_ref(), &reg, &uuid).map_err(CliError::from)?;
        if let Some(m) = question
            && !replace_live
        {
            if tty && c.check(&format!("{m}\nMove it away?")) {
                replace_ok.set(true);
            } else {
                return Err(CliError::new(
                    "confirmation_required",
                    if tty {
                        format!("{m}; nothing was changed")
                    } else {
                        format!("{m}; pass --replace-live")
                    },
                ));
            }
        }
        if !already {
            quit_desktop(app, c, tty, yes, &quit)?;
        }
        Ok(())
    })?;
    Ok(Prepared {
        key: key.to_string(),
        uuid,
        quit: quit.get(),
        replace_ok: replace_ok.get(),
    })
}

/// After a failed switch half: start Desktop again if cma quit it.
pub fn relaunch_if_quit(deps: &Deps, p: &Prepared, e: &CliError, out: &mut Out) {
    relaunch_after_failure(deps.desktop.as_ref(), p.quit, e, out);
}

/// Test builds only: `CMA_TEST_DESKTOP_HALF` makes the Desktop half of a
/// switch fail: `fail` (cleanly, nothing written), `fail_after_refresh`
/// (cleanly, after "Claude Code" refreshed the live login, so putting the
/// CLI back conflicts) or `state_uncertain`.
#[cfg(feature = "test-backends")]
fn injected_failure(deps: &Deps) -> Result<(), CliError> {
    match deps.env.var("CMA_TEST_DESKTOP_HALF").as_deref() {
        Some("fail") => Err(CliError::new(
            "not_found",
            "injected: the stored Claude Desktop login vanished",
        )),
        Some("fail_after_refresh") => {
            let live = cma_core::cli_target::LiveTarget::from_env(deps.env.as_ref())?;
            if let Some(cur) = deps.store.get(&live.service, &live.account)? {
                let mut v: Value = serde_json::from_slice(cur.expose()).unwrap_or_default();
                v["claudeAiOauth"]["accessToken"] = json!("dummy-access-refreshed");
                deps.store.set(
                    &live.service,
                    &live.account,
                    &cma_core::secret::Secret::new(v.to_string().into_bytes()),
                )?;
            }
            Err(CliError::new(
                "not_found",
                "injected: the stored Claude Desktop login vanished",
            ))
        }
        Some("state_uncertain") => Err(CliError::new(
            "state_uncertain",
            "injected: Desktop rollback incomplete",
        )),
        _ => Ok(()),
    }
}

/// Switch Claude Desktop to the account stored under `key`.
pub fn switch_desktop(
    deps: &Deps,
    out: &mut Out,
    key: &str,
    yes: bool,
    replace_live: bool,
) -> Result<DesktopSwitched, CliError> {
    let p = prepare_switch(deps, out, key, yes, replace_live)?;
    run_switch(deps, out, &p)
}

/// The prepared switch, under the lock. On failure Desktop is started
/// again (unless state is uncertain).
pub fn run_switch(deps: &Deps, out: &mut Out, p: &Prepared) -> Result<DesktopSwitched, CliError> {
    let app = deps.desktop.as_ref();
    let tty = interactive(out);
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let uuid = p.uuid.clone();
    let reg = Registry::load(&deps.paths.registry_file())?;
    let name = label(&reg, &p.key);
    let replace_live = p.replace_ok;
    let quit = Cell::new(p.quit);
    let r = with_consents(tty, |_c| {
        #[cfg(feature = "test-backends")]
        injected_failure(deps)?;
        let mut s = start(&ctx, out)?;
        let opts = DesktopOpts {
            app,
            replace_live: Confirm::NonInteractive {
                force: replace_live,
            },
        };
        Ok(core_switch(&mut s, &uuid, &opts)?)
    });
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            relaunch_after_failure(app, quit.get(), &e, out);
            return Err(e);
        }
    };
    let shown_in_prompt = !out.json && tty && !replace_live;
    out.warn_all(
        r.warnings
            .iter()
            .filter(|w| !(shown_in_prompt && w.code == "live_login_replaced"))
            .cloned(),
    );
    #[cfg(feature = "test-backends")]
    if deps.env.var("CMA_TEST_DESKTOP_HALF").as_deref() == Some("crash_in_launch") {
        // As if killed (Ctrl-C) while waiting for Desktop to start.
        std::process::exit(9);
    }
    if quit.get() || !r.already_active {
        out.warn_all(launch_and_verify(
            app,
            &deps.paths,
            Some(&uuid),
            LAUNCH_WAIT,
        ));
    }
    let reg = Registry::load(&deps.paths.registry_file())?;
    let human = if r.already_active {
        format!("{name} already is the active Claude Desktop account")
    } else {
        let from = r
            .from
            .as_deref()
            .map(|u| who(&reg, u))
            .unwrap_or_else(|| "-".into());
        let mut h = format!("switched Claude Desktop: {from} -> {name}");
        if r.session_follow {
            h.push_str(&format!(
                " ({} session entr{} moved)",
                r.sessions_moved,
                if r.sessions_moved == 1 { "y" } else { "ies" }
            ));
        }
        h
    };
    Ok(DesktopSwitched {
        data: report_json(&r),
        human,
    })
}

/// `cma desktop import-current`: link the account Desktop is signed in to.
pub fn import_current(deps: &Deps, out: &mut Out, alias: Option<&str>, yes: bool) -> CmdResult {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let tty = interactive(out);
    let (r, reg) = with_consents(tty, |c| {
        let mut s = start(&ctx, out)?;
        let ask_only = |m: &str| c.check(&format!("{m}\nSave it?"));
        let confirm = replace_confirm(tty, yes, &ask_only);
        let r = link_live(&mut s, &confirm, alias)?;
        Ok((r, s.registry.clone()))
    })?;
    out.warn_all(r.warnings.iter().cloned());
    let name = label(&reg, &r.key);
    let human = if r.already_linked {
        format!(
            "Claude Desktop is signed in as {name}, already linked; it is the active Desktop account"
        )
    } else if r.created_desktop_only {
        format!("linked Claude Desktop's login as the new Desktop-only account {name}")
    } else {
        format!("linked Claude Desktop's login to {name}")
    };
    Ok(Outcome::new(
        json!({
            "account_uuid": r.account_uuid,
            "org_uuid": r.org_uuid,
            "key": r.key,
            "created_desktop_only": r.created_desktop_only,
            "already_linked": r.already_linked,
        }),
        human,
    ))
}

/// `cma desktop link <query>`: store the live login, let the user sign in
/// as the account in a signed-out Desktop, store that login, then keep it
/// or put the previous one back.
pub fn link(deps: &Deps, out: &mut Out, query: &str, yes: bool, replace_live: bool) -> CmdResult {
    let reg = Registry::load(&deps.paths.registry_file())?;
    let key = select_key(&reg, query)?;
    let name = label(&reg, &key);
    let uuid = reg
        .account(&key)
        .map(|a| a.account_uuid.clone())
        .unwrap_or_default();
    // Desktop is already signed in as it: nothing to sign in.
    if live_account(&deps.paths)?.as_deref() == Some(uuid.as_str()) {
        return import_current(deps, out, None, yes);
    }
    let tty = interactive(out);
    if !tty {
        return Err(CliError::new(
            "confirmation_required",
            format!("linking signs Claude Desktop in as {name} while you watch, which needs a terminal or the app"),
        )
        .with_hint("sign in to Claude Desktop as that account yourself, then run `cma desktop import-current`"));
    }
    let app = deps.desktop.as_ref();
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);

    // Step 1: store the live login; Desktop starts signed out.
    let quit = Cell::new(false);
    let stash = with_consents(tty, |c| {
        quit_desktop(app, c, tty, yes, &quit)?;
        let mut s = start(&ctx, out)?;
        let ask_replace = |m: &str| c.check(&format!("{m}\nMove it away?"));
        let opts = DesktopOpts {
            app,
            replace_live: replace_confirm(tty, replace_live, &ask_replace),
        };
        Ok(stash_live(&mut s, &opts)?)
    });
    let stash = match stash {
        Ok(r) => r,
        Err(e) => {
            relaunch_after_failure(app, quit.get(), &e, out);
            return Err(e);
        }
    };
    let json_mode = out.json;
    out.warn_all(
        stash
            .warnings
            .iter()
            .filter(|w| !(!json_mode && !replace_live && w.code == "live_login_replaced"))
            .cloned(),
    );
    let previous = stash.from.clone();
    let reg = Registry::load(&deps.paths.registry_file())?;
    let back_hint = match previous.as_deref() {
        Some(p) if reg.desktop.iter().any(|l| l.account_uuid == p) => format!(
            "the previous login ({}) is stored: `cma switch --desktop {}` puts it back",
            who(&reg, p),
            reg.accounts
                .iter()
                .find(|a| a.account_uuid == p)
                .map(|a| super::query_for(&reg, &a.key))
                .unwrap_or_else(|| p.to_string())
        ),
        Some(_) => format!(
            "the previous login was not linked, so cma kept it only in backup {}; to use that account in Claude Desktop again, sign in as it and run `cma desktop import-current` (or `cma desktop link <account>` for a stored account); once linked, `cma switch --desktop <account>` switches to it",
            stash.backup_id.as_deref().unwrap_or("-")
        ),
        None => "Claude Desktop was not signed in before".into(),
    };
    for w in launch_and_verify(app, &deps.paths, None, LAUNCH_WAIT) {
        out.warn(w.code, w.message);
    }
    let signed_in = ask(&format!(
        "Claude Desktop opened on a fresh sign-in screen. Sign in there as {name}, wait until it shows your account, then come back. cma then quits Claude Desktop again to store the login.\nSigned in?"
    ));
    if !signed_in {
        return Err(CliError::new(
            "confirmation_required",
            format!("link of {name} stopped after storing the previous Claude Desktop login; Desktop stays signed out"),
        )
        .with_hint(back_hint));
    }

    // Step 2: quit, store the new login.
    let quit2 = Cell::new(false);
    let linked = with_consents(tty, |c| {
        quit_desktop(app, c, tty, true, &quit2)?;
        let mut s = start(&ctx, out)?;
        let ask_only = |m: &str| c.check(&format!("{m}\nSave it?"));
        Ok(link_live(
            &mut s,
            &replace_confirm(tty, false, &ask_only),
            None,
        )?)
    });
    let linked = match linked {
        Ok(r) => r,
        Err(e) => {
            relaunch_after_failure(app, quit2.get(), &e, out);
            return Err(e.with_hint(back_hint));
        }
    };
    out.warn_all(linked.warnings.iter().cloned());
    if linked.account_uuid != uuid {
        out.warn(
            "desktop_account_mismatch",
            format!(
                "Claude Desktop was signed in as {}, not {name}; that login was linked instead",
                linked.account_uuid
            ),
        );
    }
    let reg = Registry::load(&deps.paths.registry_file())?;
    let new_name = label(&reg, &linked.key);

    // Keep the new login, or put the previous one back.
    let mut final_uuid = linked.account_uuid.clone();
    let mut restored = None;
    if let Some(p) = previous.as_deref()
        && p != linked.account_uuid
        && reg.desktop.iter().any(|l| l.account_uuid == p)
        && ask(&format!(
            "{new_name} is linked and signed in to Claude Desktop now.\nSwitch Claude Desktop back to the previous login, {}? (no keeps {new_name})",
            who(&reg, p)
        ))
    {
        let r = with_consents(tty, |_c| {
            let mut s = start(&ctx, out)?;
            let opts = DesktopOpts {
                app,
                replace_live: Confirm::NonInteractive { force: false },
            };
            Ok(core_switch(&mut s, p, &opts)?)
        });
        match r {
            Ok(r) => {
                out.warn_all(r.warnings.iter().cloned());
                final_uuid = p.to_string();
                restored = Some(report_json(&r));
            }
            Err(e) => {
                let _ = app.launch();
                return Err(e);
            }
        }
    }
    out.warn_all(launch_and_verify(
        app,
        &deps.paths,
        Some(&final_uuid),
        LAUNCH_WAIT,
    ));
    let mut human = format!("linked {new_name} to Claude Desktop");
    if restored.is_some() {
        human.push_str(&format!(
            "; Claude Desktop is back on {}",
            who(&reg, &final_uuid)
        ));
    }
    Ok(Outcome::new(
        json!({
            "account_uuid": linked.account_uuid,
            "org_uuid": linked.org_uuid,
            "key": linked.key,
            "created_desktop_only": linked.created_desktop_only,
            "previous": previous,
            "stash_backup_id": stash.backup_id,
            "restored_previous": restored,
            "active": final_uuid,
        }),
        human,
    ))
}

/// `cma desktop unlink [query]`.
pub fn unlink(deps: &Deps, out: &mut Out, query: Option<&str>) -> CmdResult {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let mut s = start(&ctx, out)?;
    let uuid = match query {
        Some(q) => {
            let key = select_key(&s.registry, q)?;
            s.registry
                .account(&key)
                .map(|a| a.account_uuid.clone())
                .unwrap_or_default()
        }
        None => s.registry.active.desktop.clone().ok_or_else(|| {
            CliError::new("not_found", "no active Claude Desktop account")
                .with_hint("name the account: `cma desktop unlink <query>`")
        })?,
    };
    let name = who(&s.registry, &uuid);
    let r = core_unlink(&mut s, &uuid)?;
    let mut human = format!("unlinked {name} from Claude Desktop");
    if let Some(b) = &r.backup_id {
        human.push_str(&format!(" (its stored login is in backup {b})"));
    }
    if r.was_active {
        human.push_str("; the live Desktop login is unchanged");
    }
    Ok(Outcome::new(
        json!({
            "account_uuid": r.account_uuid,
            "backup_id": r.backup_id,
            "removed_accounts": r.removed_accounts,
            "was_active": r.was_active,
        }),
        human,
    ))
}

/// For `status`: the Desktop side.
pub fn status_json(deps: &Deps, reg: &Registry, out: &mut Out) -> (Value, String) {
    let live = match live_account(&deps.paths) {
        Ok(l) => l,
        Err(e) => {
            out.warn("desktop_config_unreadable", e.to_string());
            None
        }
    };
    let running = match deps.desktop.running() {
        Ok(r) => Some(!r.is_empty()),
        Err(e) => {
            out.warn(
                "process_list_failed",
                format!("could not list processes: {e}"),
            );
            None
        }
    };
    let linked: Vec<&str> = reg
        .desktop
        .iter()
        .map(|l| l.account_uuid.as_str())
        .collect();
    if let (Some(a), l) = (reg.active.desktop.as_deref(), live.as_deref())
        && Some(a) != l
    {
        out.warn(
            "desktop_account_changed",
            format!(
                "Claude Desktop is signed in as {} now, not {} as cma last left it",
                l.map(|u| who(reg, u)).unwrap_or_else(|| "nobody".into()),
                who(reg, a)
            ),
        );
    }
    let text = match live.as_deref() {
        Some(u) => {
            let mut t = who(reg, u);
            if !linked.contains(&u) {
                t.push_str(" (not linked; `cma desktop import-current` links it)");
            }
            t
        }
        None => "not signed in".into(),
    };
    let data = json!({
        "active": reg.active.desktop,
        "available": true,
        "live_account": live,
        "linked": linked,
        "running": running,
    });
    (data, text)
}
