//! `cma backups`, `cma restore <id>`, `cma clean`.
//!
//! These never run crash recovery or sync, so `backups` and `clean` keep
//! working after a recovery that left state uncertain (journal kept, exit 2
//! from every other command). `restore` is itself a journaled operation and
//! refuses while that journal exists. `resolve-journal` accepts the state
//! such a journal left (it archives the journal and keeps the backup).

use cma_core::backup::{self, Allowlist, DEFAULT_KEEP, Restorer};
use cma_core::cli_target::{LiveTarget, is_blanked, oauth_fingerprint, stored_oauth};
use cma_core::journal;
use cma_core::lock::CmaLock;
use cma_core::registry::Registry;
use serde_json::json;

use super::{CmdResult, Consents, interactive, label, query_for, with_consents};
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

pub fn list(deps: &Deps) -> CmdResult {
    let items = backup::list(&deps.paths)?;
    let data: Vec<_> = items
        .iter()
        .map(|b| {
            json!({
                "id": b.id,
                "op": b.op,
                "created_at": b.created_at,
                "entries": b.entries,
                "in_journal": b.in_journal,
                "problem": b.problem,
            })
        })
        .collect();
    let mut h = String::new();
    for b in &items {
        h.push_str(&b.id);
        if b.in_journal {
            h.push_str("  (unfinished operation)");
        }
        h.push('\n');
        match &b.problem {
            Some(p) => h.push_str(&format!("    unreadable: {p}\n")),
            None => {
                for e in &b.entries {
                    h.push_str(&format!("    {e}\n"));
                }
            }
        }
    }
    if items.is_empty() {
        h.push_str("no backups");
    }
    Ok(Outcome::new(json!({"backups": data}), h))
}

fn lock(deps: &Deps, out: &mut Out) -> Result<CmaLock, CliError> {
    for m in deps.paths.ensure_cma_home()? {
        out.warn("time_machine", m);
    }
    Ok(CmaLock::acquire(&deps.paths.lock_file())?)
}

pub fn restore(
    deps: &Deps,
    out: &mut Out,
    id: &str,
    force: bool,
    yes: bool,
    replace_live: bool,
) -> CmdResult {
    // A restore is itself journaled, so it cannot run while an unfinished
    // operation's journal is kept. Refuse before the conflict and
    // older-login checks, which would otherwise answer with a code that
    // suggests --force (or ask for consent) for a restore that cannot run.
    if std::fs::symlink_metadata(deps.paths.journal_file()).is_ok() {
        // restore does not run recovery itself, so the journal may belong
        // to a crash that no command has tried to roll back yet.
        return Err(CliError::new(
            "state_uncertain",
            "an unfinished operation's journal exists, and restore is itself a journaled operation, so it cannot run now",
        )
        .with_hint(
            "run `cma status`: it rolls the interrupted operation back, or keeps its journal if it cannot (then `cma resolve-journal` accepts the current state); `cma restore` works again afterwards",
        ));
    }
    let tty = interactive(out);
    if force && !yes && !tty {
        return Err(CliError::new(
            "confirmation_required",
            "restore --force can replace a newer token (for example one Claude Code refreshed since the operation) with an older one; pass --yes with --force",
        ));
    }
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let live = ctx.live()?;
    let mut older: Option<String> = None;
    // A forced restore actually overwrote values changed since the op.
    let mut overwrote_newer = false;
    // Claude Desktop must stay quit while a restore writes its files.
    let desktop_guard = || -> cma_core::Result<()> {
        let run = deps.desktop.running()?;
        if run.is_empty() {
            Ok(())
        } else {
            Err(cma_core::desktop_app::running_error(
                "Claude Desktop started during the restore",
                &run,
            ))
        }
    };
    let mut recaptured: Option<String> = None;
    let mut parked: Option<cma_core::desktop_target::Parked> = None;
    let r = with_consents(tty, |c| {
        recaptured = None;
        parked = None;
        older = None;
        overwrote_newer = false;
        let lock = lock(deps, out)?;
        let restorer = Restorer::load(
            &deps.paths,
            deps.store.as_ref(),
            &deps.locker,
            &Allowlist::for_paths(&deps.paths),
            id,
        )?
        .with_guard(&desktop_guard);
        // A backup of a Claude Desktop op moves Desktop's own files: only
        // while Desktop is quit.
        let desktop = cma_core::desktop_target::touches_desktop(&deps.paths, restorer.manifest());
        if desktop {
            let run = deps.desktop.running()?;
            if !run.is_empty() {
                return Err(CliError::from(cma_core::desktop_app::running_error(
                    &format!(
                        "{id} changes Claude Desktop's login files, which cma restores only while Claude Desktop is quit"
                    ),
                    &run,
                )));
            }
        }
        // A restore that would put an account's older login live while cma
        // holds a newer one for it: `cma switch` is what the user wants.
        if let Some(a) = older_login(deps, &restorer, &live)? {
            let reg = Registry::load(&deps.paths.registry_file())?;
            let who = label(&reg, &a);
            let msg = format!(
                "{id} would put an older login of {who} live in Claude Code, while cma holds a newer one for it; its refresh token may already be spent"
            );
            let hint = format!(
                "run `cma switch {}` instead: it puts cma's newer login live without discarding anything",
                query_for(&reg, &a)
            );
            if !force {
                return Err(CliError::new(
                    "restore_older_login",
                    format!("{msg}; pass --force to restore it anyway (it asks first; --force --yes with --json or without a terminal)"),
                )
                .with_hint(hint));
            }
            older_consent(yes, c, &msg).map_err(|e| e.with_hint(hint))?;
            older = Some(a);
        }
        match restorer.restore_user(&lock, false) {
            Err(cma_core::Error::RestoreConflict(items)) if force => {
                let msg = format!(
                    "changed since {id}: {}. Most likely Claude Code refreshed the live login's token; restoring replaces that newer value with the older one (it is kept in the restore's own backup)",
                    items.join(", ")
                );
                if yes || c.check(&format!("{msg}\nRestore anyway?")) {
                    overwrote_newer = true;
                    // A Desktop switch: first store the live Desktop login
                    // (with what Desktop changed since) under its account,
                    // or refuse when that cannot be done safely.
                    if desktop {
                        let m = restorer.manifest();
                        let hint = |e: cma_core::Error| desktop_switch_hint(deps, m, e.into());
                        // A login path whose moved copy is gone cannot come
                        // back with its keys: refuse before changing anything.
                        if m.entries.iter().any(|e| {
                            matches!(e, cma_core::backup::Entry::Move { to, .. } if std::fs::symlink_metadata(to).is_err())
                                && cma_core::desktop_target::is_identity_entry(&deps.paths, e)
                        }) {
                            return Err(hint(cma_core::Error::DesktopRestoreRefused(
                                "part of the Claude Desktop login this backup moved is no longer where it was moved to".into(),
                            )));
                        }
                        recaptured = cma_core::desktop_target::recapture_for_restore(
                            &deps.paths,
                            deps.store.as_ref(),
                            &deps.locker,
                            &lock,
                            m,
                        )
                        .map_err(hint)?;
                        if recaptured.is_none() {
                            let ask_replace = |q: &str| c.check(&format!("{q}\nMove it away?"));
                            let confirm = if replace_live || !tty {
                                cma_core::switch::Confirm::NonInteractive {
                                    force: replace_live,
                                }
                            } else {
                                cma_core::switch::Confirm::Interactive(&ask_replace)
                            };
                            parked = cma_core::desktop_target::park_live_for_restore(
                                &deps.paths,
                                deps.store.as_ref(),
                                &deps.locker,
                                &lock,
                                deps.desktop.as_ref(),
                                &confirm,
                                m,
                            )
                            .map_err(|e| match e {
                                cma_core::Error::ConfirmationRequired(_) => e.into(),
                                other => hint(other),
                            })?;
                        }
                        // A Desktop login's files and keys go back together
                        // or not at all: a forced restore that would skip a
                        // login path but force its keys is refused.
                        let after = (|| -> Result<cma_core::backup::RestoreReport, CliError> {
                            #[cfg(feature = "test-backends")]
                            injected_after_park(deps, parked.is_some())?;
                            match restorer.restore_user(&lock, false) {
                                Err(cma_core::Error::RestoreConflict(items)) => {
                                    let mixed = m.entries.iter().any(|e| {
                                        matches!(e, cma_core::backup::Entry::Move { .. })
                                            && cma_core::desktop_target::is_identity_entry(
                                                &deps.paths,
                                                e,
                                            )
                                            && items.contains(&e.label())
                                    });
                                    if mixed {
                                        return Err(hint(cma_core::Error::DesktopRestoreRefused(
                                            "Claude Desktop's login files changed in a way the restore cannot put back together with its config.json keys".into(),
                                        )));
                                    }
                                }
                                r => return Ok(r?),
                            }
                            Ok(restorer.restore_user(&lock, true)?)
                        })();
                        // Anything failing after the park puts the live
                        // login back (or says where it is).
                        return match (after, &parked) {
                            (Err(e), Some(p)) => Err(undo_park(deps, &lock, &p.backup_id, e)),
                            (r, _) => r,
                        };
                    }
                    Ok(restorer.restore_user(&lock, true)?)
                } else {
                    Err(CliError::new(
                        "confirmation_required",
                        format!("{msg}; restore cancelled"),
                    ))
                }
            }
            Err(e @ cma_core::Error::RestoreConflict(_)) if desktop => {
                Err(desktop_switch_hint(deps, restorer.manifest(), e.into()))
            }
            r => Ok(r?),
        }
    })?;
    if let Some(p) = &parked {
        let whose = match (&p.account, &p.auto_linked) {
            (Some(a), Some(_)) => format!("stored under {a}, which cma linked just now"),
            (Some(a), None) => format!("stored under {a}"),
            (None, _) => "kept only in that backup".to_string(),
        };
        out.warn(
            "desktop_parked",
            format!(
                "the live Claude Desktop login was moved out first into backup {} ({whose}); `cma restore {}` puts it back",
                p.backup_id, p.backup_id
            ),
        );
    }
    if let Some(b) = &recaptured {
        out.warn(
            "desktop_recaptured",
            format!("the live Claude Desktop login was moved out first, under its account when cma links it (backup {b}), so the restore puts the old login's files and keys back together and nothing Desktop refreshed is lost"),
        );
    }
    for w in &r.warnings {
        out.warn("restore", w.clone());
    }
    if !r.skipped.is_empty() {
        out.warn(
            "restore_skipped",
            format!(
                "left where they are because they changed after the operation moved them: {}",
                r.skipped.join(", ")
            ),
        );
    }
    resync_desktop(deps)?;
    if r.state_uncertain() {
        return Err(CliError::new(
            "state_uncertain",
            format!(
                "restore of {id} left {} item(s) uncertain (changed by another writer or not writable): {}",
                r.uncertain.len(),
                r.uncertain.join(", ")
            ),
        ));
    }
    if let Some(b) = &r.backup_id
        && (overwrote_newer || older.is_some())
        && !r.restored.is_empty()
    {
        let mut m = format!(
            "what this restore overwrote is kept in backup {b}; to undo, run `cma restore {b}` before any other cma command"
        );
        if let Some(a) = &older {
            let reg = Registry::load(&deps.paths.registry_file())?;
            m.push_str(&format!(
                ", then `cma switch {}` to use cma's newer login for {}",
                query_for(&reg, a),
                label(&reg, a)
            ));
        }
        out.warn("restore_undo", m);
    }
    let mut h = format!(
        "restored {} item(s) from {id}, {} unchanged",
        r.restored.len(),
        r.unchanged.len()
    );
    if let Some(b) = &r.backup_id {
        h.push_str(&format!(
            "\nwhat it overwrote is in backup {b} (undo: `cma restore {b}`)"
        ));
    }
    let data = json!({
        "id": r.id,
        "restored": r.restored,
        "unchanged": r.unchanged,
        "uncertain": r.uncertain,
        "skipped": r.skipped,
        "parked_backup_id": parked.as_ref().map(|p| p.backup_id.clone()),
        "recaptured_backup_id": recaptured,
        "backup_id": r.backup_id,
    });
    Ok(Outcome::new(data, h))
}

/// Consent to put an older login live (`--force` given): `--yes`, or a
/// y/N prompt asked by the consent loop with no lock held.
fn older_consent(yes: bool, c: &Consents, msg: &str) -> Result<(), CliError> {
    if yes || c.check(&format!("{msg}\nRestore the older login anyway?")) {
        Ok(())
    } else {
        Err(CliError::new(
            "confirmation_required",
            format!("{msg}; restore cancelled"),
        ))
    }
}

/// The stored account whose older login restoring `restorer` would put
/// live, when cma holds a different (newer) login for it that still works.
/// Compares fingerprints only.
fn older_login(
    deps: &Deps,
    restorer: &Restorer<'_>,
    live: &LiveTarget,
) -> Result<Option<String>, CliError> {
    let Some(fp) = restorer.restored_oauth_fingerprint(&live.service, &live.account)? else {
        return Ok(None);
    };
    let reg = Registry::load(&deps.paths.registry_file())?;
    let Some(key) = reg.account_for_fingerprint(&fp).map(str::to_string) else {
        return Ok(None);
    };
    let Some(acct) = reg.account(&key) else {
        return Ok(None);
    };
    if acct.needs_login {
        return Ok(None);
    }
    let stored = stored_oauth(deps.store.as_ref(), &key)?;
    Ok(match stored {
        Some(o) if oauth_fingerprint(&o) != fp && !is_blanked(&o) => Some(key),
        _ => None,
    })
}

/// `cma resolve-journal`: accept the state an operation left when its
/// rollback could not complete (exit 2). Recovery runs first, as in every
/// mutating command: a journal it rolls back completely is simply gone
/// (reported, exit 0). Only a journal recovery keeps is resolved: archived
/// into its backup dir and removed; the backup is kept, so
/// `cma restore <id>` stays possible. Asks first (or needs `--yes`), with
/// no lock held while asking.
pub fn resolve_journal(deps: &Deps, out: &mut Out, yes: bool) -> CmdResult {
    let tty = interactive(out);
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let res = with_consents(tty, |c| {
        let lock = lock(deps, out)?;
        if std::fs::symlink_metadata(deps.paths.journal_file()).is_err() {
            return resolve_both(deps, &ctx, &lock, c, tty, yes);
        }
        // Same as every command's start: never roll back a Claude Desktop
        // op while Desktop runs, and stop if it starts midway.
        let why = match cma_core::sync::guarded_recover(&ctx, &lock) {
            Ok(None) => return Ok(None),
            Ok(Some(rec)) if !rec.state_uncertain() => {
                return Ok(Some(ResolveOutcome::Recovered(rec)));
            }
            Ok(Some(rec)) => format!(
                "its rollback left {} item(s) uncertain ({})",
                rec.report.uncertain.len(),
                rec.report.uncertain.join(", ")
            ),
            // Recovery cannot run at all: only resolving ends this.
            Err(e)
                if matches!(
                    e.code(),
                    "backup_missing" | "manifest_rejected" | "invalid_json" | "state_uncertain"
                ) =>
            {
                format!("recovery cannot roll it back ({e})")
            }
            Err(e) => return Err(e.into()),
        };
        let what = match journal::read(&deps.paths) {
            Ok(Some(j)) => format!(
                "the unfinished {} ({}) with backup {}",
                j.op, j.target, j.backup_id
            ),
            _ => "an unreadable operation journal".to_string(),
        };
        let msg = format!(
            "{what}: {why}; resolving accepts the current state and lets cma make changes again (the backup is kept for `cma restore`)"
        );
        // The question names the journal, so a different journal asks again.
        let q = format!("{msg}\nResolve it?");
        if !(yes || (tty && c.check(&q))) {
            let tail = if tty {
                "nothing resolved"
            } else {
                "pass --yes"
            };
            return Err(CliError::new(
                "confirmation_required",
                format!("{msg}; {tail}"),
            ));
        }
        let r = journal::resolve(&deps.paths, &lock)?.map(ResolveOutcome::Accepted);
        // Accepting the state covers an interrupted `--both` too.
        journal::both_clear(&deps.paths)?;
        Ok(r)
    })?;
    let r = match res {
        None => {
            return Err(
                CliError::new("not_found", "there is no unfinished operation journal")
                    .with_hint("nothing to resolve; `cma status` shows the current state"),
            );
        }
        Some(ResolveOutcome::Recovered(rec)) => {
            for w in &rec.warnings {
                out.warn("recovered", w.clone());
            }
            let j = &rec.journal;
            let data = json!({
                "resolved": false,
                "recovered": true,
                "journal": {"op": j.op, "target": j.target, "from": j.from, "to": j.to, "backup_id": j.backup_id},
                "archived": null,
            });
            return Ok(Outcome::new(
                data,
                format!(
                    "the unfinished {} ({}) was rolled back completely; nothing left to resolve",
                    j.op, j.target
                ),
            ));
        }
        Some(ResolveOutcome::Accepted(r)) => r,
        Some(ResolveOutcome::Both { recovered, message }) => {
            let data = json!({"resolved": !recovered, "recovered": recovered, "journal": null, "archived": null, "both": true});
            if recovered {
                out.warn("recovered", message.clone());
            }
            return Ok(Outcome::new(data, message));
        }
    };
    let j = r.journal.as_ref().map(|j| {
        json!({"op": j.op, "target": j.target, "from": j.from, "to": j.to, "backup_id": j.backup_id})
    });
    let mut h = match &r.journal {
        Some(j) => format!(
            "resolved the unfinished {} ({}); cma accepts the current state and can make changes again",
            j.op, j.target
        ),
        None => "resolved an unreadable operation journal; cma can make changes again".to_string(),
    };
    if let Some(j) = &r.journal {
        h.push_str(&format!(
            "\nbackup {} is kept: `cma backups` shows what it holds, `cma restore {}` puts it back",
            j.backup_id, j.backup_id
        ));
    }
    if let Some(p) = &r.archived {
        h.push_str(&format!("\njournal archived to {}", p.display()));
    }
    Ok(Outcome::new(
        json!({"resolved": true, "recovered": false, "journal": j, "archived": r.archived}),
        h,
    ))
}

/// No operation journal: an interrupted `switch --both` record, if any.
/// Putting Claude Code back is retried first; if that still fails, the
/// user may accept the state (the record is removed).
fn resolve_both(
    deps: &Deps,
    ctx: &cma_core::cli_target::Ctx<'_>,
    lock: &CmaLock,
    c: &Consents,
    tty: bool,
    yes: bool,
) -> Result<Option<ResolveOutcome>, CliError> {
    let Some(rec) = journal::both_read(&deps.paths)? else {
        return Ok(None);
    };
    match cma_core::sync::recover_both(ctx, lock) {
        Ok(Some(m)) => Ok(Some(ResolveOutcome::Both {
            recovered: true,
            message: m,
        })),
        Ok(None) => Ok(None),
        Err(e) => {
            let msg = format!(
                "{e}; resolving accepts Claude Code staying on {} (backup {} is kept for `cma restore`)",
                rec.cli_to,
                rec.cli_backup_id.as_deref().unwrap_or("-")
            );
            if !(yes || (tty && c.check(&format!("{msg}\nResolve it?")))) {
                return Err(CliError::new(
                    "confirmation_required",
                    format!(
                        "{msg}; {}",
                        if tty {
                            "nothing resolved"
                        } else {
                            "pass --yes"
                        }
                    ),
                ));
            }
            journal::both_clear(&deps.paths)?;
            Ok(Some(ResolveOutcome::Both {
                recovered: false,
                message: format!(
                    "resolved the interrupted `switch --both`: Claude Code stays on {}",
                    rec.cli_to
                ),
            }))
        }
    }
}

enum ResolveOutcome {
    /// No journal; an interrupted `switch --both` was finished or accepted.
    Both { recovered: bool, message: String },
    /// Recovery rolled the operation back completely; the journal is gone.
    Recovered(journal::Recovery),
    /// Recovery kept the journal; the user accepted the state.
    Accepted(journal::Resolution),
}

pub fn clean(deps: &Deps, out: &mut Out, keep: Option<usize>) -> CmdResult {
    let lock = lock(deps, out)?;
    let keep = keep.unwrap_or(DEFAULT_KEEP);
    let r = backup::clean(&deps.paths, &lock, deps.store.as_ref(), keep)?;
    let skipped: Vec<_> = r
        .skipped
        .iter()
        .map(|s| json!({"id": s.id, "reason": s.reason}))
        .collect();
    let mut h = format!(
        "removed {} backup(s), kept the newest {keep}",
        r.removed.len()
    );
    for s in &r.skipped {
        h.push_str(&format!("\nkept {}: {}", s.id, s.reason));
    }
    Ok(Outcome::new(
        json!({"removed": r.removed, "skipped": skipped, "keep": keep}),
        h,
    ))
}

/// The restore failed after it parked the live Desktop login: put it back,
/// or say exactly where it is (message, hint and `data`).
fn undo_park(deps: &Deps, lock: &CmaLock, park_id: &str, e: CliError) -> CliError {
    let r = cma_core::desktop_target::undo_park(
        &deps.paths,
        deps.store.as_ref(),
        &deps.locker,
        lock,
        deps.desktop.as_ref(),
        park_id,
    );
    let (tail, hint, undone, code) = match r {
        Ok(true) => (
            format!(
                "the live Claude Desktop login cma had moved out first was put back (backup {park_id})"
            ),
            e.hint.clone().unwrap_or_default(),
            true,
            e.code.clone(),
        ),
        Ok(false) => (
            format!(
                "the live Claude Desktop login cma had moved out first is in backup {park_id}; Claude Desktop is running, so it is not put back yet"
            ),
            format!(
                "quit Claude Desktop, then run any cma command: it puts the login back from backup {park_id} (`cma restore {park_id}` does the same once nothing is pending)"
            ),
            false,
            "desktop_running".to_string(),
        ),
        Err(x) => (
            format!(
                "the live Claude Desktop login cma had moved out first is in backup {park_id}, and putting it back failed ({x})"
            ),
            format!("run `cma status`; `cma restore {park_id}` puts the login back"),
            false,
            if x.code() == "state_uncertain" {
                "state_uncertain".to_string()
            } else {
                e.code.clone()
            },
        ),
    };
    CliError {
        code,
        message: format!("{}; {tail}", e.message),
        hint: Some(hint).filter(|h| !h.is_empty()),
        data: Some(Box::new(
            json!({"parked_backup_id": park_id, "park_undone": undone}),
        )),
    }
}

/// Test builds only: `CMA_TEST_DESKTOP_HALF=fail_after_park` makes a forced
/// restore fail right after it parked the live login; `..._running` also
/// starts the fake Desktop first (as an auto-update relaunch would).
#[cfg(feature = "test-backends")]
fn injected_after_park(deps: &Deps, parked: bool) -> Result<(), CliError> {
    let mode = deps.env.var("CMA_TEST_DESKTOP_HALF");
    if !parked
        || !mode
            .as_deref()
            .is_some_and(|m| m.starts_with("fail_after_park"))
    {
        return Ok(());
    }
    if mode.as_deref() == Some("fail_after_park_running")
        && let Some(dir) = deps.env.var("CMA_FAKE_DIR")
    {
        let _ = std::fs::write(
            std::path::Path::new(&dir).join("ps.txt"),
            "9001 1 /Applications/Claude.app/Contents/MacOS/Claude\n",
        );
    }
    Err(CliError::new(
        "not_found",
        "injected: the restore failed after the park",
    ))
}

/// For a Desktop switch, the safe undo is switching back: say so.
fn desktop_switch_hint(deps: &Deps, m: &cma_core::backup::Manifest, e: CliError) -> CliError {
    let reg = Registry::load(&deps.paths.registry_file()).unwrap_or_default();
    let target = cma_core::desktop_target::previous_account(&deps.paths, m)
        .and_then(|u| {
            reg.accounts
                .iter()
                .find(|a| a.account_uuid == u)
                .map(|a| query_for(&reg, &a.key))
                .or(Some(u))
        })
        .unwrap_or_else(|| "<account>".into());
    e.with_hint(format!(
        "this backup is a Claude Desktop switch, and Claude Desktop changed its login since (it refreshes tokens and session state while it runs). To undo it, run `cma switch --desktop {target}`: it stores the current login first and loses nothing. `--force` restores anyway after storing the current login under its account (refused when that is not safe)"
    ))
}

/// After a restore: `active.desktop` follows what Desktop's `config.json`
/// names now (a linked account, else none).
fn resync_desktop(deps: &Deps) -> Result<(), CliError> {
    let _lock = CmaLock::acquire(&deps.paths.lock_file())?;
    let mut reg = Registry::load(&deps.paths.registry_file())?;
    let live = cma_core::desktop_target::live_account(&deps.paths)?
        .filter(|u| reg.desktop.iter().any(|l| l.account_uuid == *u));
    if reg.active.desktop != live {
        reg.active.desktop = live;
        reg.save(&deps.paths.registry_file())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_login_consent_is_asked_on_a_terminal_without_yes() {
        let asked = std::cell::Cell::new(0);
        let yes = |q: &str| {
            assert!(q.ends_with("Restore the older login anyway?"), "{q}");
            asked.set(asked.get() + 1);
            true
        };
        assert!(super::super::consent_loop(true, &yes, |c| older_consent(false, c, "m")).is_ok());
        assert_eq!(asked.get(), 1);
        let no = |_: &str| false;
        let e =
            super::super::consent_loop(true, &no, |c| older_consent(false, c, "m")).unwrap_err();
        assert_eq!(e.code, "confirmation_required");
        // On a terminal the explanation was shown above the prompt and is
        // not repeated in the error.
        assert_eq!(e.message, "restore cancelled");
        // --yes needs no prompt.
        let never = |_: &str| -> bool { panic!("asked despite --yes") };
        assert!(super::super::consent_loop(true, &never, |c| older_consent(true, c, "m")).is_ok());
    }
}
