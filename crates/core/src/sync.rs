//! Command start-up for the CLI target: lock, crash recovery, live sync.
//!
//! Every mutating CLI-target operation takes a [`Session`], and the only way
//! to get one is [`begin`], which holds the cma lock, rolls back an
//! interrupted op, loads the registry and syncs the live item. A failure in
//! any of these aborts the command.
//!
//! # Live sync rules
//!
//! The live `claudeAiOauth` is identified from the token
//! ([`crate::identity`]), never from `oauthAccount`. Then:
//!
//! - identity = `active.cli` = stored account K, bytes differ ⇒ store them as
//!   K's latest credential, add the fingerprint, set `last_active_at`;
//! - identity = stored account K ≠ `active.cli` ⇒ the live login changed
//!   outside cma: write no credential, warn `live_account_changed`, set
//!   `active.cli = K` only (and the previous active account's
//!   `last_active_at` = now, so it gets the refresh grace). (The phase text also says "K and bytes differ ⇒
//!   store"; when K is not the active account this rule wins: nothing is
//!   filed under any account on a change cma did not make. The next command,
//!   with K now active, stores the bytes.)
//! - identity is an account cma does not manage, or there is no live item
//!   ⇒ warn, clear `active.cli` (its account's `last_active_at` = now);
//! - blanked (signed out by Claude Code) ⇒ write nothing. It is never
//!   looked up by fingerprint (blanked bytes of different accounts can be
//!   identical). When `active.cli` = K and the `~/.claude.json`
//!   `oauthAccount` hint names K too, it is K's signed-out login:
//!   `needs_login` for K. Otherwise it is unidentified;
//! - unidentified ⇒ write nothing and warn.
//!
//! Recovery runs before sync, so a switch journal never exists here.

use serde_json::Value;

use crate::backup::Allowlist;
use crate::cli_target::{
    Ctx, OWN_SERVICE, Warning, is_blanked, oauth_fingerprint, oauth_of, oauth_only_item,
};
use crate::error::{Error, Result};
use crate::identity::{Resolved, resolve};
use crate::lock::CmaLock;
use crate::registry::Registry;

/// What the live item turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveState {
    /// No live item.
    Absent,
    /// The item has no `claudeAiOauth` (e.g. only `mcpOAuth`, or a Console
    /// login's `{}`).
    NoCredential,
    /// Identified as `key`; `managed` when cma stores that account.
    Identified {
        key: String,
        managed: bool,
    },
    NeedsLogin {
        key: String,
    },
    Unidentified {
        reason: String,
    },
}

/// Result of [`sync_live`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub live: LiveState,
    /// The live bytes were stored under the active account.
    pub stored: bool,
    /// The registry changed and must be saved.
    pub registry_changed: bool,
    pub warnings: Vec<Warning>,
}

fn describe(reg: &Registry, key: &str) -> String {
    match reg.account(key) {
        Some(a) if !a.email.is_empty() => format!("{} ({key})", a.email),
        _ => key.to_string(),
    }
}

/// Sync the live item into the registry (see the module docs). Reading the
/// live item, parsing it and storing it are all fatal on failure.
pub fn sync_live(ctx: &Ctx<'_>, lock: &CmaLock, reg: &mut Registry) -> Result<SyncReport> {
    lock.check_for(ctx.paths)?;
    let mut r = SyncReport {
        live: LiveState::Absent,
        stored: false,
        registry_changed: false,
        warnings: ctx.env_warnings(),
    };
    r.warnings.extend(ctx.plaintext_warning());
    let live = ctx.live()?;
    let Some(bytes) = ctx.store.get(&live.service, &live.account)? else {
        if let Some(prev) = reg.active.cli.take() {
            left_outside(ctx, reg, &prev);
            r.warnings.push(Warning::new(
                "live_account_changed",
                format!(
                    "there is no live CLI login any more (was {}); changed outside cma",
                    describe(reg, &prev)
                ),
            ));
            r.registry_changed = true;
        }
        return Ok(r);
    };
    let Some(oauth) = oauth_of(bytes.expose())? else {
        r.live = LiveState::NoCredential;
        if let Some(prev) = &reg.active.cli {
            r.warnings.push(Warning::new(
                "live_account_changed",
                format!(
                    "the live CLI item holds no Claude.ai credential (was {}); nothing stored",
                    describe(reg, prev)
                ),
            ));
        }
        return Ok(r);
    };
    drop(bytes);
    if is_blanked(&oauth) {
        let hint = crate::fsutil::read_nofollow(&ctx.paths.claude_json)?
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.get("oauthAccount").cloned());
        match &reg.active.cli {
            Some(k)
                if hint
                    .as_ref()
                    .is_some_and(|h| crate::account::hint_matches(h, k)) =>
            {
                r.warnings.push(Warning::new(
                    "needs_login",
                    format!(
                        "the live CLI login of {} is signed out; log in again",
                        describe(reg, k)
                    ),
                ));
                r.live = LiveState::NeedsLogin { key: k.clone() };
            }
            _ => {
                let reason = "the live CLI login is signed out (blanked by Claude Code) and is not the active account's".to_string();
                r.warnings.push(Warning::new(
                    if reg.active.cli.is_some() {
                        "live_account_changed"
                    } else {
                        "live_unidentified"
                    },
                    format!("{reason}; nothing stored"),
                ));
                r.live = LiveState::Unidentified { reason };
            }
        }
        return Ok(r);
    }
    match resolve(reg, ctx.profile, &oauth, ctx.now_ms(), None) {
        Resolved::Identified { key, .. } if reg.account(&key).is_some() => {
            r.live = LiveState::Identified {
                key: key.clone(),
                managed: true,
            };
            if reg.active.cli.as_deref() == Some(key.as_str()) {
                store_if_changed(ctx, reg, &key, &oauth, &mut r)?;
            } else {
                let msg = match &reg.active.cli {
                    Some(prev) => format!(
                        "the live CLI login is now {} (changed outside cma; was {}); nothing stored",
                        describe(reg, &key),
                        describe(reg, prev)
                    ),
                    None => format!(
                        "the live CLI login is {} (changed outside cma); nothing stored",
                        describe(reg, &key)
                    ),
                };
                r.warnings.push(Warning::new("live_account_changed", msg));
                if let Some(prev) = reg.active.cli.clone() {
                    left_outside(ctx, reg, &prev);
                }
                reg.active.cli = Some(key);
                r.registry_changed = true;
            }
        }
        Resolved::Identified { key, profile, .. } => {
            let who = profile
                .map(|p| format!("{} ({key})", p.email))
                .unwrap_or_else(|| key.clone());
            r.warnings.push(Warning::new(
                "live_account_changed",
                format!("the live CLI login is {who}, which cma does not manage; `import-current` adds it"),
            ));
            if let Some(prev) = reg.active.cli.take() {
                left_outside(ctx, reg, &prev);
                r.registry_changed = true;
            }
            r.live = LiveState::Identified {
                key,
                managed: false,
            };
        }
        Resolved::Unidentified { reason, .. } => {
            let code = if reg.active.cli.is_some() {
                "live_account_changed"
            } else {
                "live_unidentified"
            };
            r.warnings.push(Warning::new(
                code,
                format!("the live CLI login could not be identified ({reason}); nothing stored"),
            ));
            r.live = LiveState::Unidentified { reason };
        }
    }
    Ok(r)
}

/// `prev` stopped being the live login outside cma, just now as far as cma
/// can tell: sessions may still run on its token, so it gets the refresh
/// grace like an account switched away from.
fn left_outside(ctx: &Ctx<'_>, reg: &mut Registry, prev: &str) {
    let now = ctx.now_secs();
    if let Some(a) = reg.account_mut(prev) {
        a.last_active_at = now;
    }
}

fn store_if_changed(
    ctx: &Ctx<'_>,
    reg: &mut Registry,
    key: &str,
    oauth: &Value,
    r: &mut SyncReport,
) -> Result<()> {
    let fp = oauth_fingerprint(oauth);
    let stored_fp = ctx
        .store
        .get(OWN_SERVICE, key)?
        .map(|s| oauth_of(s.expose()))
        .transpose()?
        .flatten()
        .map(|o| oauth_fingerprint(&o));
    if stored_fp.as_deref() == Some(fp.as_str()) {
        return Ok(());
    }
    ctx.store.set(OWN_SERVICE, key, &oauth_only_item(oauth))?;
    reg.add_fingerprint(fp, key);
    let now = ctx.now_secs();
    if let Some(a) = reg.account_mut(key) {
        a.last_active_at = now;
        a.has_cli = true;
        a.needs_login = false;
    }
    r.stored = true;
    r.registry_changed = true;
    Ok(())
}

/// A started command: the cma lock is held for the session's lifetime.
pub struct Session<'c> {
    pub ctx: &'c Ctx<'c>,
    lock: CmaLock,
    pub registry: Registry,
    pub warnings: Vec<Warning>,
    pub live: LiveState,
}

impl<'c> Session<'c> {
    pub fn lock(&self) -> &CmaLock {
        &self.lock
    }

    pub fn save(&self) -> Result<()> {
        self.registry.save(&self.ctx.paths.registry_file())
    }

    /// Release the cma lock (e.g. before a long interactive login).
    pub fn end(self) -> Vec<Warning> {
        self.warnings
    }
}

/// Refuse while Claude Desktop runs when the pending journal (or its
/// backup) touches Desktop's files: rolling it back would write under it.
pub fn desktop_gate(ctx: &Ctx<'_>) -> Result<()> {
    let paths = ctx.paths;
    if let Some(j) = crate::journal::read(paths)?
        && (j.target == crate::desktop_target::JOURNAL_TARGET
            || crate::backup::Restorer::load(
                paths,
                ctx.store,
                ctx.locker,
                &Allowlist::for_paths(paths),
                &j.backup_id,
            )
            .is_ok_and(|r| crate::desktop_target::touches_desktop(paths, r.manifest())))
    {
        let run = crate::desktop_app::desktop_processes(&ctx.procs.list()?, &paths.desktop_dir);
        if !run.is_empty() {
            return Err(crate::desktop_app::running_error(
                &format!(
                    "an interrupted Claude Desktop operation ({}, backup {}) is rolled back only while Claude Desktop is quit; quit it and run the command again",
                    j.op, j.backup_id
                ),
                &run,
            ));
        }
    }
    Ok(())
}

/// [`crate::journal::recover`] with the Desktop gate before it and a
/// check before every replayed write into the Desktop dir. After a Desktop
/// op is rolled back, `active.desktop` follows what Desktop names again.
pub fn guarded_recover(ctx: &Ctx<'_>, lock: &CmaLock) -> Result<Option<crate::journal::Recovery>> {
    desktop_gate(ctx)?;
    let paths = ctx.paths;
    let desktop_guard = || -> Result<()> {
        let run = crate::desktop_app::desktop_processes(&ctx.procs.list()?, &paths.desktop_dir);
        if run.is_empty() {
            Ok(())
        } else {
            Err(crate::desktop_app::running_error(
                "Claude Desktop started while cma rolled back an interrupted operation",
                &run,
            ))
        }
    };
    let rec = crate::journal::recover_guarded(
        paths,
        lock,
        ctx.store,
        ctx.locker,
        &Allowlist::for_paths(paths),
        Some(&desktop_guard),
    )?;
    if let Some(r) = &rec {
        crate::journal::both_mark_rolled_back(paths, lock, &r.journal.backup_id)?;
    }
    if let Some(r) = &rec
        && !r.state_uncertain()
        && r.journal.target == crate::desktop_target::JOURNAL_TARGET
    {
        let mut reg = Registry::load(&paths.registry_file())?;
        let live = crate::desktop_target::live_account(paths)?
            .filter(|u| reg.desktop.iter().any(|l| l.account_uuid == *u));
        if reg.active.desktop != live {
            reg.active.desktop = live;
            reg.save(&paths.registry_file())?;
        }
    }
    Ok(rec)
}

/// Finish an interrupted `switch --both` (see [`crate::journal::BothRecord`]):
/// the Desktop half did not complete, so the Claude Code half is put back
/// through its backup (journaled, only over values the switch wrote). Runs
/// after [`guarded_recover`] rolled the Desktop half itself back.
pub fn recover_both(ctx: &Ctx<'_>, lock: &CmaLock) -> Result<Option<String>> {
    let paths = ctx.paths;
    if crate::journal::both_active_here() {
        return Ok(None);
    }
    let Some(rec) = crate::journal::both_read(paths)? else {
        return Ok(None);
    };
    // Its `cma` process still runs (e.g. waiting for Desktop to start):
    // it is not interrupted, and only it decides.
    if rec.owner_alive() {
        return Ok(None);
    }
    // The Desktop half's journal began and was not rolled back: it
    // finished, so the switch as a whole did; only the record was left.
    let finished = rec.desktop_backup_id.is_some() && !rec.desktop_rolled_back;
    let Some(id) = rec.cli_backup_id.clone().filter(|_| !finished) else {
        crate::journal::both_clear(paths)?;
        return Ok(None);
    };
    let res = crate::backup::Restorer::load(
        paths,
        ctx.store,
        ctx.locker,
        &Allowlist::for_paths(paths),
        &id,
    )
    .and_then(|r| r.restore_user(lock, false));
    match res {
        Ok(rep) if !rep.state_uncertain() => {
            let mut reg = Registry::load(&paths.registry_file())?;
            reg.active.cli = rec.cli_from.clone();
            reg.save(&paths.registry_file())?;
            crate::journal::both_clear(paths)?;
            Ok(Some(format!(
                "an interrupted `switch --both` to {} did not finish its Claude Desktop half; Claude Code was put back too (backup {id})",
                rec.cli_to
            )))
        }
        Ok(_) | Err(_) => Err(Error::StateUncertain(format!(
            "an interrupted `switch --both` to {} did not finish its Claude Desktop half, and Claude Code could not be put back from backup {id} (it changed since, e.g. a token refresh); the record is kept. `cma restore {id}` puts Claude Code back (see also the latest desktop-switch backup in `cma backups`), or `cma resolve-journal --yes` accepts Claude Code staying on {}",
            rec.cli_to, rec.cli_to
        ))),
    }
}

/// Recovery at command start: an interrupted op (guarded), then an
/// interrupted `switch --both`. Returns warnings.
fn recover_all(ctx: &Ctx<'_>, lock: &CmaLock) -> Result<Vec<Warning>> {
    let paths = ctx.paths;
    let mut warnings = Vec::new();
    if let Some(rec) = guarded_recover(ctx, lock)? {
        if rec.state_uncertain() {
            let mut msg = format!(
                "recovery of the interrupted {} left {} item(s) uncertain; backup {} and the journal are kept: {}",
                rec.journal.op,
                rec.report.uncertain.len(),
                rec.report.id,
                rec.warnings.join("; ")
            );
            if rec.journal.target == crate::desktop_target::JOURNAL_TARGET {
                msg.push_str(&crate::desktop_target::interrupted_hint(
                    paths,
                    &rec.report.id,
                ));
            }
            return Err(Error::StateUncertain(msg));
        }
        warnings.extend(
            rec.warnings
                .into_iter()
                .map(|m| Warning::new("recovered", m)),
        );
    }
    if let Some(m) = recover_both(ctx, lock)? {
        warnings.push(Warning::new("recovered", m));
    }
    Ok(warnings)
}

/// Start a mutating CLI-target command: create/verify `CMA_HOME`, take the
/// cma lock, recover an interrupted op (an uncertain recovery aborts),
/// load the registry and sync the live item (a failure aborts).
pub fn begin<'c>(ctx: &'c Ctx<'c>) -> Result<Session<'c>> {
    let paths = ctx.paths;
    let mut warnings: Vec<Warning> = paths
        .ensure_cma_home()?
        .into_iter()
        .map(|m| Warning::new("time_machine", m))
        .collect();
    let lock = CmaLock::acquire(&paths.lock_file())?;
    for w in recover_all(ctx, &lock)? {
        warnings.push(w);
    }
    let mut registry = Registry::load(&paths.registry_file())?;
    let report = sync_live(ctx, &lock, &mut registry)?;
    if report.registry_changed {
        registry.save(&paths.registry_file())?;
    }
    warnings.extend(report.warnings);
    Ok(Session {
        ctx,
        lock,
        registry,
        warnings,
        live: report.live,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cli_target::testkit::*;
    use crate::cli_target::{oauth_fingerprint, stored_oauth};
    use crate::registry::Account;
    use crate::secret::SecretStore;

    pub fn add_account(w: &World, key: &str, email: &str, oauth: &Value) {
        let mut reg = Registry::load(&w.paths.registry_file()).unwrap();
        let (a, o) = key.split_once("::").unwrap();
        reg.accounts.push(Account {
            key: key.into(),
            account_uuid: a.into(),
            org_uuid: o.into(),
            email: email.into(),
            has_cli: true,
            ..Default::default()
        });
        reg.add_fingerprint(oauth_fingerprint(oauth), key);
        reg.save(&w.paths.registry_file()).unwrap();
        w.store
            .set(OWN_SERVICE, key, &oauth_only_item(oauth))
            .unwrap();
    }

    pub fn set_active(w: &World, key: Option<&str>) {
        let mut reg = Registry::load(&w.paths.registry_file()).unwrap();
        reg.active.cli = key.map(Into::into);
        reg.save(&w.paths.registry_file()).unwrap();
    }

    fn reg(w: &World) -> Registry {
        Registry::load(&w.paths.registry_file()).unwrap()
    }

    #[test]
    fn oauth_account_says_b_but_bytes_are_a_stores_nothing_under_b() {
        let w = World::new();
        let (a, b) = (oauth("A"), oauth("B"));
        add_account(&w, "A::oA", "a@x", &a);
        add_account(&w, "B::oB", "b@x", &b);
        set_active(&w, Some("B::oB"));
        // ~/.claude.json says B, the live token is A's (rotated bytes, but
        // the fingerprint map knows the exact bytes).
        let mut cj = w.claude_json();
        cj["oauthAccount"] = serde_json::json!({"accountUuid": "B", "organizationUuid": "oB"});
        std::fs::write(&w.paths.claude_json, serde_json::to_vec(&cj).unwrap()).unwrap();
        w.set_live(&live_item(&a));
        let ctx = w.ctx();
        let s = begin(&ctx).unwrap();
        assert!(
            s.warnings.iter().any(|x| x.code == "live_account_changed"),
            "{:?}",
            s.warnings
        );
        drop(s);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b);
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a);
        assert_eq!(reg(&w).active.cli.as_deref(), Some("A::oA"));
    }

    #[test]
    fn active_account_new_bytes_are_stored_after_profile_check() {
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        set_active(&w, Some("A::oA"));
        // Claude refreshed A: new bytes, unknown fingerprint, profile says A.
        let a2 = oauth("A2");
        w.profile.add("at-A2", "A", "oA", "a@x");
        w.set_live(&live_item(&a2));
        let ctx = w.ctx();
        let s = begin(&ctx).unwrap();
        assert_eq!(
            s.live,
            LiveState::Identified {
                key: "A::oA".into(),
                managed: true
            }
        );
        drop(s);
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a2);
        let r = reg(&w);
        assert_eq!(
            r.account_for_fingerprint(&oauth_fingerprint(&a2)),
            Some("A::oA")
        );
        assert_eq!(r.account("A::oA").unwrap().last_active_at, NOW_MS / 1000);
    }

    #[test]
    fn identity_not_active_writes_no_credential() {
        let w = World::new();
        let (a, b) = (oauth("A"), oauth("B"));
        add_account(&w, "A::oA", "a@x", &a);
        add_account(&w, "B::oB", "b@x", &b);
        set_active(&w, Some("A::oA"));
        // B logged in outside cma with fresh bytes.
        let b2 = oauth("B2");
        w.profile.add("at-B2", "B", "oB", "b@x");
        w.set_live(&live_item(&b2));
        let ctx = w.ctx();
        drop(begin(&ctx).unwrap());
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b);
        assert_eq!(reg(&w).active.cli.as_deref(), Some("B::oB"));
    }

    #[test]
    fn account_left_outside_cma_gets_the_refresh_grace() {
        for live in ["managed", "unmanaged", "absent"] {
            let w = World::new();
            add_account(&w, "A::oA", "a@x", &oauth("A"));
            add_account(&w, "B::oB", "b@x", &oauth("B"));
            set_active(&w, Some("A::oA"));
            let mut r = reg(&w);
            r.account_mut("A::oA").unwrap().last_active_at = 5;
            r.save(&w.paths.registry_file()).unwrap();
            match live {
                "managed" => {
                    w.profile.add("at-B2", "B", "oB", "b@x");
                    w.set_live(&live_item(&oauth("B2")));
                }
                "unmanaged" => {
                    w.profile.add("at-X", "X", "oX", "x@x");
                    w.set_live(&live_item(&oauth("X")));
                }
                _ => {}
            }
            let ctx = w.ctx();
            drop(begin(&ctx).unwrap());
            let r = reg(&w);
            assert_ne!(r.active.cli.as_deref(), Some("A::oA"), "{live}");
            // Sessions may still run on A's token: A is treated as active
            // until now, so the grace keeps refresh away from it.
            assert_eq!(
                r.account("A::oA").unwrap().last_active_at,
                NOW_MS / 1000,
                "{live}"
            );
            assert_eq!(r.account("B::oB").unwrap().last_active_at, 0, "{live}");
        }
    }

    #[test]
    fn unidentified_and_blanked_write_nothing() {
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        set_active(&w, Some("A::oA"));
        // ~/.claude.json names B: a blanked live login is then not A's.
        let mut cj = w.claude_json();
        cj["oauthAccount"] = serde_json::json!({"accountUuid": "B", "organizationUuid": "oB"});
        std::fs::write(&w.paths.claude_json, serde_json::to_vec(&cj).unwrap()).unwrap();
        for live in [blanked(), oauth("unknown")] {
            w.set_live(&live_item(&live));
            let ctx = w.ctx();
            let s = begin(&ctx).unwrap();
            assert!(
                matches!(s.live, LiveState::Unidentified { .. }),
                "{:?}",
                s.live
            );
            drop(s);
            assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a);
            assert_eq!(w.store.count(OWN_SERVICE), 1);
        }
    }

    #[test]
    fn blanked_live_of_the_active_account_is_needs_login() {
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        set_active(&w, Some("A::oA"));
        // World's ~/.claude.json oauthAccount is A/oA.
        w.set_live(&live_item(&blanked()));
        let reg_before = std::fs::read(w.paths.registry_file()).unwrap();
        let ctx = w.ctx();
        let s = begin(&ctx).unwrap();
        assert_eq!(
            s.live,
            LiveState::NeedsLogin {
                key: "A::oA".into()
            }
        );
        assert!(
            s.warnings
                .iter()
                .any(|x| x.code == "needs_login" && x.message.contains("a@x")),
            "{:?}",
            s.warnings
        );
        assert_eq!(w.profile.calls.get(), 0, "a blanked token is never sent");
        drop(s);
        // No write: the stored credential, the registry (no fingerprint of
        // the blanked bytes) and active.cli are unchanged.
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a);
        assert_eq!(w.store.count(OWN_SERVICE), 1);
        assert_eq!(std::fs::read(w.paths.registry_file()).unwrap(), reg_before);
        let r = reg(&w);
        assert_eq!(
            r.account_for_fingerprint(&oauth_fingerprint(&blanked())),
            None
        );
        assert_eq!(r.active.cli.as_deref(), Some("A::oA"));
        // No active account: unidentified, not needs_login.
        set_active(&w, None);
        let s = begin(&ctx).unwrap();
        assert!(
            matches!(s.live, LiveState::Unidentified { .. }),
            "{:?}",
            s.live
        );
    }

    #[test]
    fn failed_live_read_aborts_begin() {
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&a));
        let fg = FailGet::live(&w);
        fg.armed.set(true);
        let ctx = w.ctx_with(&fg);
        let e = begin(&ctx)
            .err()
            .expect("a failed read must abort, not mean absent");
        assert_eq!(e.code(), "external_tool", "{e}");
        // Not treated as "no live login": active.cli kept, nothing written.
        assert_eq!(reg(&w).active.cli.as_deref(), Some("A::oA"));
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a);
    }

    #[test]
    fn duplicate_claude_ai_oauth_in_live_item_aborts() {
        let w = World::new();
        w.set_live(
            br#"{"claudeAiOauth":{"accessToken":"at-A"},"claudeAiOauth":{"accessToken":"at-B"}}"#,
        );
        let ctx = w.ctx();
        assert!(matches!(begin(&ctx), Err(Error::Invalid { .. })));
    }

    #[test]
    fn unreadable_live_item_aborts() {
        let w = World::new();
        w.set_live(b"not json");
        let ctx = w.ctx();
        assert!(matches!(begin(&ctx), Err(Error::Json { .. })));
        w.set_live(b"[1,2]");
        assert!(matches!(begin(&ctx), Err(Error::Invalid { .. })));
    }

    #[test]
    fn absent_live_clears_active_with_warning() {
        let w = World::new();
        add_account(&w, "A::oA", "a@x", &oauth("A"));
        set_active(&w, Some("A::oA"));
        let ctx = w.ctx();
        let s = begin(&ctx).unwrap();
        assert_eq!(s.live, LiveState::Absent);
        assert!(s.warnings.iter().any(|x| x.code == "live_account_changed"));
        drop(s);
        assert_eq!(reg(&w).active.cli, None);
    }
}
