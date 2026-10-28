//! `cma switch [query] [--cli|--desktop|--both]`.
//!
//! `--desktop` (or a Desktop `default_target`) switches Claude Desktop
//! (see [`super::desktop`]). `--both` first checks everything that can
//! refuse the Desktop half and gets every consent (and quits Desktop), then
//! switches the CLI, then Desktop, recorded as one unit
//! ([`cma_core::journal::BothRecord`]). A clean Desktop failure puts the
//! CLI back (exit 1); a failed put-back or an uncertain Desktop half is
//! exit 2 with the record kept. Exit 3 only for an account not linked to
//! Desktop (`--strict` refuses that up front).
//!
//! Separate consents: `--force` for running `claude` sessions,
//! `--replace-live` for replacing a live login cma does not store, `--yes`
//! for quitting Claude Desktop. Prompts are shown with no lock held (see
//! [`super::Consents`]).

use std::time::{Duration, Instant};

use cma_core::journal::{BothActive, BothRecord};
use cma_core::registry::{Registry, Target};
use cma_core::switch::{Confirm, SwitchOpts, SwitchReport, switch_cli};
use serde_json::{Value, json};

use super::{
    CmdResult, interactive, label, label_of, query_for, select_key, start, terminal, with_consents,
};
use crate::SwitchArgs;
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

/// Longer than this inside `.storage-write` is reported: Claude Code treats
/// the lock as stale after 15 s and may take it over.
pub const STORAGE_LOCK_SLOW: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Cli,
    Desktop,
    Both,
}

pub fn run(deps: &Deps, out: &mut Out, a: &SwitchArgs) -> CmdResult {
    let started = Instant::now();
    let which = if a.both {
        Which::Both
    } else if a.desktop {
        Which::Desktop
    } else if a.cli {
        Which::Cli
    } else {
        let reg = Registry::load(&deps.paths.registry_file())?;
        match reg.settings.default_target {
            Target::Cli => Which::Cli,
            Target::Desktop => Which::Desktop,
        }
    };

    // The picker runs before any lock is taken (it waits on the user).
    let picked = match &a.query {
        Some(_) => None,
        None => Some(pick(
            &Registry::load(&deps.paths.registry_file())?,
            out,
            which,
        )?),
    };
    let key = match &picked {
        Some(k) => k.clone(),
        None => select_key(
            &Registry::load(&deps.paths.registry_file())?,
            a.query.as_deref().unwrap_or_default(),
        )?,
    };

    if which == Which::Desktop {
        let d = super::desktop::switch_desktop(deps, out, &key, a.yes, a.replace_live)?;
        let reg = Registry::load(&deps.paths.registry_file())?;
        let from = d.data["from"].as_str().and_then(|u| key_for_uuid(&reg, u));
        let data = json!({
            "target": "desktop",
            "from": from,
            "to": key,
            "already_active": d.data["already_active"],
            "running_sessions": 0,
            "backup_id": d.data["backup_id"],
            "elapsed_ms": started.elapsed().as_millis() as u64,
            "storage_lock_held_ms": Value::Null,
            "desktop": d.data,
        });
        return Ok(Outcome::new(data, d.human));
    }

    if which == Which::Both {
        let reg = Registry::load(&deps.paths.registry_file())?;
        let acct = reg.account(&key);
        if acct.is_some_and(|x| !x.has_cli)
            && cma_core::cli_target::stored_oauth(deps.store.as_ref(), &key)?.is_none()
        {
            return Err(CliError::new(
                "invalid",
                format!("{} is a Desktop-only account (no Claude Code login), so --both cannot switch Claude Code to it", label(&reg, &key)),
            )
            .with_hint("use --desktop, or `cma login` to add its Claude Code login"));
        }
        if a.strict {
            strict_desktop_check(&reg, &key)?;
        }
    }
    // --both: everything that can refuse the Desktop half is checked, and
    // every consent obtained (and Desktop quit), before Claude Code
    // changes. Not linked (without --strict): Claude Code only, exit 3.
    let prepared = if which == Which::Both {
        let reg = Registry::load(&deps.paths.registry_file())?;
        let uuid = reg
            .account(&key)
            .map(|x| x.account_uuid.clone())
            .unwrap_or_default();
        if reg.desktop.iter().any(|l| l.account_uuid == uuid) {
            // Finish any earlier interrupted `--both` before this one
            // writes its own record.
            let profile = deps.profile();
            let ctx = deps.ctx(&profile);
            drop(start(&ctx, out)?);
            Some(super::desktop::prepare_switch(
                deps,
                out,
                &key,
                a.yes,
                a.replace_live,
            )?)
        } else {
            None
        }
    } else {
        None
    };

    // `--both` is journaled as one unit: the record is written before
    // Claude Code changes and removed once both halves are done (or Claude
    // Code was put back). If this process dies in between, the next
    // command puts Claude Code back too.
    let _both = prepared.as_ref().map(|_| BothActive::enter());
    let mut record = BothRecord::new(
        Registry::load(&deps.paths.registry_file())?.active.cli,
        key.clone(),
    );
    if prepared.is_some() {
        write_both(deps, &record)?;
    }
    let (r, reg) = match switch_cli_part(deps, out, a, &key) {
        Ok(x) => x,
        Err(e) => {
            if let Some(p) = &prepared {
                let _ = cma_core::journal::both_clear(&deps.paths);
                super::desktop::relaunch_if_quit(deps, p, &e, out);
            }
            return Err(e);
        }
    };
    if prepared.is_some() {
        record.cli_from = r.from.clone();
        record.cli_backup_id = r.backup_id.clone().filter(|_| !r.already_active);
        write_both(deps, &record)?;
        #[cfg(feature = "test-backends")]
        if deps.env.var("CMA_TEST_DESKTOP_HALF").as_deref() == Some("crash") {
            // As if the process were killed during the Desktop half.
            std::process::exit(9);
        }
    }
    let tty = interactive(out);
    let prompted = |code: &str| match code {
        "running_sessions" => !a.force,
        "live_login_replaced" => !a.replace_live,
        _ => false,
    };
    let shown_in_prompt = !out.json && tty;
    out.warn_all(
        r.warnings
            .iter()
            .filter(|w| !(shown_in_prompt && prompted(w.code)))
            .cloned(),
    );
    let elapsed = started.elapsed();
    let held = deps.locker.max_hold();
    if let Some(h) = held
        && h > STORAGE_LOCK_SLOW
    {
        out.warn(
            "storage_lock_slow",
            format!(
                "Claude Code's .storage-write lock was held for {} ms during the switch (a Keychain prompt?); Claude Code treats it as stale after 15 s",
                h.as_millis()
            ),
        );
    }
    let to = label(&reg, &r.to);
    let mut h = if r.already_active {
        format!("{to} already is the active Claude Code account")
    } else {
        let from = r
            .from
            .as_deref()
            .map(|k| label(&reg, k))
            .unwrap_or_else(|| "-".into());
        format!(
            "switched Claude Code: {from} -> {to} ({} ms{})",
            elapsed.as_millis(),
            held.map(|h| format!(", Claude Code lock held {} ms", h.as_millis()))
                .unwrap_or_default()
        )
    };
    let mut partial = false;
    let desktop = match (&prepared, which) {
        (Some(p), _) => match super::desktop::run_switch(deps, out, p) {
            Ok(d) => {
                cma_core::journal::both_clear(&deps.paths)?;
                h.push('\n');
                h.push_str(&d.human);
                Some(d.data)
            }
            // Desktop's own rollback did not complete: that is the
            // command's result (exit 2), whatever Claude Code did.
            Err(e) if e.code == "state_uncertain" => {
                return Err(CliError {
                    message: format!(
                        "{} (Claude Code was switched to {to} before; the `--both` record is kept, so once the Desktop half is rolled back the next command puts Claude Code back too, unless `cma resolve-journal` accepts the state)",
                        e.message
                    ),
                    ..e
                });
            }
            // Desktop runs and its half's journal is kept (cma never
            // rolls back under a running Desktop): the record stays, and
            // once Desktop is quit the next command rolls back both halves.
            Err(e) if std::fs::symlink_metadata(deps.paths.journal_file()).is_ok() => {
                return Err(CliError {
                    message: format!(
                        "{} Claude Code was switched to {to} before; the `--both` record is kept, so after Claude Desktop is quit the next command puts Claude Code back too",
                        e.message
                    ),
                    ..e
                });
            }
            // A clean Desktop failure: put Claude Code back too.
            Err(e) => return Err(roll_back_cli(deps, out, &r, &reg, e)),
        },
        (None, Which::Both) => {
            partial = true;
            out.warn(
                "desktop_not_linked",
                format!(
                    "Claude Desktop was not switched: {to} has no Claude Desktop login stored by cma (`cma desktop link` adds one); Claude Code was switched"
                ),
            );
            Some(json!({
                "switched": false,
                "reason": "desktop_not_linked",
                "message": format!("{to} has no Claude Desktop login stored by cma"),
                "hint": Value::Null,
            }))
        }
        (None, _) => None,
    };
    let data = json!({
        "target": if which == Which::Both { "both" } else { "cli" },
        "from": r.from,
        "to": r.to,
        "already_active": r.already_active,
        "running_sessions": r.running_sessions,
        "backup_id": r.backup_id,
        "elapsed_ms": started.elapsed().as_millis() as u64,
        "storage_lock_held_ms": held.map(|h| h.as_millis() as u64),
        "desktop": desktop,
    });
    let mut o = Outcome::new(data, h);
    o.partial = partial;
    Ok(o)
}

/// The registry key of an account with Desktop uuid `uuid` (its linked org
/// first).
fn key_for_uuid(reg: &Registry, uuid: &str) -> Option<String> {
    let org = reg
        .desktop
        .iter()
        .find(|l| l.account_uuid == uuid)
        .map(|l| l.last_org_uuid.as_str());
    reg.accounts
        .iter()
        .filter(|a| a.account_uuid == uuid)
        .max_by_key(|a| Some(a.org_uuid.as_str()) == org)
        .map(|a| a.key.clone())
}

/// `--both --strict`: refuse before touching Claude Code unless the
/// account is linked to Desktop (the rest is checked by
/// [`super::desktop::prepare_switch`]).
fn strict_desktop_check(reg: &Registry, key: &str) -> Result<(), CliError> {
    let uuid = reg
        .account(key)
        .map(|a| a.account_uuid.clone())
        .unwrap_or_default();
    if !reg.desktop.iter().any(|l| l.account_uuid == uuid) {
        return Err(CliError::new(
            "desktop_not_linked",
            format!(
                "--both --strict: {} has no Claude Desktop login stored by cma, so nothing was switched",
                label(reg, key)
            ),
        )
        .with_hint(format!(
            "run `cma desktop link {}` first",
            query_for(reg, key)
        )));
    }
    Ok(())
}

/// `--both`: the Desktop half failed cleanly after Claude Code switched.
/// Restore what the Claude Code switch wrote (journaled, like `cma
/// restore`); the result is Desktop's error (exit 1), or `state_uncertain`
/// (exit 2) when Claude Code cannot be put back.
fn roll_back_cli(
    deps: &Deps,
    out: &mut Out,
    r: &SwitchReport,
    reg: &Registry,
    desktop_err: CliError,
) -> CliError {
    let to = label(reg, &r.to);
    let what = format!(
        "Claude Desktop could not be switched ({}: {})",
        desktop_err.code, desktop_err.message
    );
    let Some(id) = r.backup_id.as_deref().filter(|_| !r.already_active) else {
        return CliError {
            message: format!("{what}; Claude Code was already on {to}"),
            ..desktop_err
        };
    };
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let res = (|| -> Result<(), CliError> {
        let mut s = start(&ctx, out)?;
        let restorer = cma_core::backup::Restorer::load(
            &deps.paths,
            deps.store.as_ref(),
            &deps.locker,
            &cma_core::backup::Allowlist::for_paths(&deps.paths),
            id,
        )?;
        let rep = restorer.restore_user(s.lock(), false)?;
        if rep.state_uncertain() {
            return Err(CliError::new(
                "state_uncertain",
                format!(
                    "restoring backup {id} left {} item(s) uncertain",
                    rep.uncertain.len()
                ),
            ));
        }
        s.registry.active.cli = r.from.clone();
        s.save()?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            let _ = cma_core::journal::both_clear(&deps.paths);
            let from = r
                .from
                .as_deref()
                .map(|k| label(reg, k))
                .unwrap_or_else(|| "its previous login".into());
            CliError {
                message: format!("{what}; Claude Code was switched back to {from}, so nothing changed"),
                ..desktop_err
            }
        }
        Err(e) => CliError::new(
            "state_uncertain",
            format!(
                "{what}, and putting Claude Code back failed ({}: {}); Claude Code stays on {to} and the `--both` record is kept (`cma status` shows it)",
                e.code, e.message
            ),
        )
        .with_hint(format!(
            "run `cma status`; every command retries putting Claude Code back; `cma restore {id}` does it explicitly, and `cma resolve-journal --yes` accepts Claude Code staying switched"
        )),
    }
}

fn write_both(deps: &Deps, r: &BothRecord) -> Result<(), CliError> {
    let lock = cma_core::lock::CmaLock::acquire(&deps.paths.lock_file())?;
    Ok(cma_core::journal::both_write(&deps.paths, &lock, r)?)
}

/// The Claude Code half: consent loop around [`switch_cli`].
fn switch_cli_part(
    deps: &Deps,
    out: &mut Out,
    a: &SwitchArgs,
    key: &str,
) -> Result<(SwitchReport, Registry), CliError> {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let tty = interactive(out);
    with_consents(tty, |c| {
        let mut s = start(&ctx, out)?;
        let ask_sessions = |m: &str| c.check(&format!("{m}\nSwitch anyway?"));
        let ask_replace = |m: &str| c.check(&format!("{m}\nReplace it?"));
        let confirm = if a.force || !tty {
            Confirm::NonInteractive { force: a.force }
        } else {
            Confirm::Interactive(&ask_sessions)
        };
        let replace_live = if a.replace_live || !tty {
            Confirm::NonInteractive {
                force: a.replace_live,
            }
        } else {
            Confirm::Interactive(&ask_replace)
        };
        let r = switch_cli(
            &mut s,
            key,
            &SwitchOpts {
                confirm,
                replace_live,
                procs: deps.procs.as_ref(),
            },
        )?;
        Ok((r, s.registry.clone()))
    })
}

/// Interactive picker; `--json` and non-terminals need a query.
fn pick(reg: &Registry, out: &Out, which: Which) -> Result<String, CliError> {
    if !terminal(out) {
        return Err(CliError::new(
            "invalid",
            "an account query is required without a terminal (and with --json)",
        )
        .with_hint("pass a row number, alias, email or key prefix (see `cma list`)"));
    }
    if reg.accounts.is_empty() {
        return Err(CliError::new("not_found", "no accounts stored")
            .with_hint("add one with `cma login` or `cma import-current`"));
    }
    let items: Vec<String> = reg
        .accounts
        .iter()
        .map(|a| {
            let mut s = label_of(a);
            if reg.active.cli.as_deref() == Some(a.key.as_str()) {
                s.push_str("  (active)");
            }
            if a.needs_login {
                s.push_str("  [needs login]");
            }
            s
        })
        .collect();
    let default = reg
        .active
        .cli
        .as_deref()
        .and_then(|k| reg.accounts.iter().position(|a| a.key == k))
        .unwrap_or(0);
    let i = dialoguer::Select::new()
        .with_prompt(match which {
            Which::Cli => "Switch Claude Code to",
            Which::Desktop => "Switch Claude Desktop to",
            Which::Both => "Switch Claude Code and Claude Desktop to",
        })
        .items(&items)
        .default(default)
        .interact_opt()
        .map_err(|_| CliError::new("interrupted", "picker cancelled"))?
        .ok_or_else(|| CliError::new("interrupted", "picker cancelled"))?;
    Ok(reg.accounts[i].key.clone())
}
