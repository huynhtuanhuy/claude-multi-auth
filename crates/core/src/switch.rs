//! Switch the live Claude Code CLI login to a stored account.
//!
//! Order: the caller's [`Session`] already holds the cma lock and ran
//! recovery and sync. Then: take the target's per-account lock
//! ([`AccountLock`], held until the end) and re-read its stored credential;
//! if the live login is one cma does not store (unmanaged, or unidentified
//! and not signed out), confirm (hint: `import-current` first) or `force`;
//! check for running `claude` sessions (confirm, or `force` when
//! non-interactive); backup + journal; read-modify-write of the live item
//! replacing only `claudeAiOauth`, inside Claude Code's `.storage-write`
//! lock; replace only `oauthAccount` in `~/.claude.json`; post-check; update
//! the registry; delete the journal.
//!
//! The RMW writes only if the live credential is still the one sync stored
//! for the account being switched away from (or, when the live login is not
//! a stored account, the one read at the start of the switch). A refresh
//! by a running session in between (its refresh token is rotated) makes the
//! switch fail with `concurrent_write` before anything is written; the next
//! command's sync stores the new pair, and a retry succeeds.
//!
//! Post-check: the Keychain fingerprint and the other keys decide success
//! (else rollback). `oauthAccount.accountUuid` not naming the target (a
//! running session rewrote `~/.claude.json` from memory) is only the
//! warning `oauth_account_reverted`: identity never comes from it.
//!
//! A failure after the journal began rolls back byte-exact, but only over
//! values that still equal what cma wrote (another writer's newer value is
//! never overwritten: that is `state_uncertain`, exit 2, journal kept). A
//! crash leaves the journal, and the next [`crate::sync::begin`] rolls back.
//!
//! Missing Claude Code state fails closed before anything is written: no
//! secure-storage dir (`~/.claude` or `CLAUDE_SECURESTORAGE_CONFIG_DIR`, where
//! the `.storage-write` lock lives) or no `~/.claude.json` ⇒ "run `claude`
//! once first". cma never creates either: a one-key `.claude.json` could make
//! Claude Code treat the machine as a fresh install.

use serde_json::{Map, Value};

use crate::backup::Allowlist;
use crate::cli_target::{
    LiveTarget, OAUTH_KEY, RawItem, Warning, is_blanked, oauth_fingerprint, oauth_of,
    replace_oauth, stored_oauth,
};
use crate::error::{Error, Result};
use crate::journal::{ActiveJournal, Journal};
use crate::lock::AccountLock;
use crate::procs::{ProcessLister, RUNNING_SESSIONS_WARNING, running_cli_sessions};
use crate::registry::{Account, AccountKind};
use crate::sync::{LiveState, Session};

/// How to handle running `claude` sessions.
pub enum Confirm<'a> {
    /// Ask the user; the callback gets the warning and returns the answer.
    Interactive(&'a dyn Fn(&str) -> bool),
    /// `--json` / app: never ask; proceed only with `force`.
    NonInteractive { force: bool },
}

pub struct SwitchOpts<'a> {
    /// Consent to switch while `claude` sessions run (`--force`).
    pub confirm: Confirm<'a>,
    /// Consent to replace a live login cma does not store (it survives only
    /// in the backup; `--replace-live`). Separate from `confirm`, so consent
    /// for running sessions never also discards an unstored login.
    pub replace_live: Confirm<'a>,
    pub procs: &'a dyn ProcessLister,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchReport {
    pub from: Option<String>,
    pub to: String,
    /// The target already was the live login; nothing was written.
    pub already_active: bool,
    pub running_sessions: usize,
    pub backup_id: Option<String>,
    pub warnings: Vec<Warning>,
}

/// The warning shown when `n` sessions run.
pub fn running_sessions_message(n: usize) -> String {
    format!("{n} running Claude Code session(s): {RUNNING_SESSIONS_WARNING}")
}

fn oauth_account_for(a: &Account) -> Value {
    a.oauth_account.clone().unwrap_or_else(|| {
        serde_json::json!({
            "accountUuid": a.account_uuid,
            "organizationUuid": a.org_uuid,
            "emailAddress": a.email,
            "organizationName": a.org_name,
        })
    })
}

#[cfg(test)]
pub(crate) mod failpoint {
    //! Test-only hook run after each step: fail (in-command rollback) or
    //! crash (leave the journal, as a killed process would).
    use std::cell::RefCell;

    use crate::secret::SecretStore;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Act {
        Continue,
        Fail,
        Crash,
    }

    type Hook = Box<dyn FnMut(&str, &dyn SecretStore) -> Act>;

    thread_local! {
        pub static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    }

    pub fn set(f: impl FnMut(&str, &dyn SecretStore) -> Act + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub fn clear() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }

    pub fn hit(step: &str, store: &dyn SecretStore) -> Act {
        HOOK.with(|h| match h.borrow_mut().as_mut() {
            Some(f) => f(step, store),
            None => Act::Continue,
        })
    }
}

/// Outcome of the steps after the journal began.
enum StepErr {
    Failed(Error),
    #[cfg(test)]
    Crashed,
}

impl From<Error> for StepErr {
    fn from(e: Error) -> Self {
        StepErr::Failed(e)
    }
}

#[cfg(test)]
fn point(step: &str, store: &dyn crate::secret::SecretStore) -> std::result::Result<(), StepErr> {
    match failpoint::hit(step, store) {
        failpoint::Act::Continue => Ok(()),
        failpoint::Act::Fail => Err(StepErr::Failed(Error::Invalid {
            what: "injected failure",
            value: step.into(),
        })),
        failpoint::Act::Crash => Err(StepErr::Crashed),
    }
}

#[cfg(not(test))]
fn point(_: &str, _: &dyn crate::secret::SecretStore) -> std::result::Result<(), StepErr> {
    Ok(())
}

/// Ask (interactive) or require `force` (non-interactive) before a step
/// that discards or disturbs something. Used for running sessions and for a
/// live login cma does not store.
/// `flag` is the option a non-interactive caller passes to consent.
pub(crate) fn confirm(c: &Confirm<'_>, msg: &str, cancelled: &str, flag: &str) -> Result<()> {
    match c {
        Confirm::Interactive(ask) => {
            if ask(msg) {
                Ok(())
            } else {
                Err(Error::ConfirmationRequired(format!("{msg}; {cancelled}")))
            }
        }
        Confirm::NonInteractive { force: false } => {
            Err(Error::ConfirmationRequired(format!("{msg}; pass {flag}")))
        }
        Confirm::NonInteractive { force: true } => Ok(()),
    }
}

/// Top-level keys of an item other than `claudeAiOauth`, as raw text.
type Others = Vec<(String, String)>;

fn others_of(bytes: &[u8]) -> Result<Others> {
    Ok(RawItem::parse(bytes)?
        .others()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

/// Read-modify-write of the live item inside `.storage-write`, replacing
/// only `claudeAiOauth` with `oauth`. `expected_live_fp` is the fingerprint
/// the live `claudeAiOauth` must still have (`None`: no credential): if
/// Claude Code refreshed or replaced it since cma looked, nothing is written
/// and the result is [`Error::ConcurrentWrite`] (no backup entry is made, so
/// the op's rollback has nothing to undo). Returns the other keys as the
/// RMW saw them, for [`post_check_live`].
pub(crate) fn write_live_oauth(
    b: &mut crate::backup::Backup<'_>,
    live: &LiveTarget,
    oauth: &Value,
    expected_live_fp: Option<&str>,
) -> Result<Others> {
    let mut others: Option<Others> = None;
    b.modify_keychain(&live.service, &live.account, |cur| {
        let cur = cur.map(|c| c.expose());
        let cur_fp = match cur {
            Some(bytes) => oauth_of(bytes)?.map(|o| oauth_fingerprint(&o)),
            None => None,
        };
        if cur_fp.as_deref() != expected_live_fp {
            return Err(Error::ConcurrentWrite(
                "the live Claude Code login changed since cma read it (most likely Claude Code refreshed its token); retry the command".into(),
            ));
        }
        others = Some(match cur {
            Some(bytes) => others_of(bytes)?,
            None => Vec::new(),
        });
        replace_oauth(cur, oauth)
    })?;
    Ok(others.unwrap_or_default())
}

/// Read the live item back: it must hold exactly `target_fp` and the other
/// keys the RMW saw.
pub(crate) fn post_check_live(
    store: &dyn crate::secret::SecretStore,
    live: &LiveTarget,
    target_fp: &str,
    others: &Others,
) -> Result<()> {
    let now_live = store
        .get(&live.service, &live.account)?
        .ok_or_else(|| Error::StateUncertain("live item vanished after the write".into()))?;
    let fp_ok = oauth_of(now_live.expose())?.is_some_and(|o| oauth_fingerprint(&o) == target_fp);
    let others_now = others_of(now_live.expose())?;
    if !fp_ok || &others_now != others {
        return Err(Error::Invalid {
            what: "post-check (live item does not hold exactly the target credential)",
            value: OAUTH_KEY.into(),
        });
    }
    Ok(())
}

/// Roll back a failed op in-command. Returns the error to report and
/// whether everything was restored.
pub(crate) fn abort_op(
    j: ActiveJournal,
    ctx: &crate::cli_target::Ctx<'_>,
    op: &str,
    e: Error,
) -> (Error, bool) {
    let paths = ctx.paths;
    match j.abort(paths, ctx.store, ctx.locker, &Allowlist::for_paths(paths)) {
        Ok(rb) if rb.state_uncertain() => (
            Error::StateUncertain(format!(
                "{op} failed ({e}); rollback left {} item(s) uncertain ({}); backup {} and journal kept",
                rb.uncertain.len(),
                rb.uncertain.join(", "),
                rb.id
            )),
            false,
        ),
        Ok(_) => (e, true),
        Err(rb_err) => (
            Error::StateUncertain(format!(
                "{op} failed ({e}) and rollback failed ({rb_err}); journal kept"
            )),
            false,
        ),
    }
}

/// Switch the CLI target to stored account `key`.
pub fn switch_cli(s: &mut Session<'_>, key: &str, opts: &SwitchOpts<'_>) -> Result<SwitchReport> {
    let ctx = s.ctx;
    let paths = ctx.paths;
    let target = s
        .registry
        .account(key)
        .cloned()
        .ok_or_else(|| Error::NotFound(format!("account {key}")))?;
    if target.kind == AccountKind::Console {
        return Err(Error::Unsupported(
            "switching the CLI to a Console (API billing) account".into(),
        ));
    }
    if target.needs_login {
        return Err(Error::NeedsLogin(format!("{key}: run `cma login` again")));
    }
    // Held to the end: a token refresh of the target (which rotates its
    // refresh token) either finished before this read or starts after the
    // switch made it the live account, which refresh never touches.
    let account_lock = AccountLock::acquire(paths, key)?;
    // An interrupted refresh may have left the valid grant aside while the
    // stored item holds a spent one: resolve it first (offline), and never
    // put a spent grant live.
    let recovered = match crate::refresh::recover_offline(ctx.store, ctx.now_ms, &account_lock, key)
    {
        Ok(r) => r,
        Err(Error::RefreshPending(m)) => {
            return Err(Error::RefreshPending(format!(
                "{m}; switching to {key} now would make a spent token live, so nothing was switched: run `cma usage` to finish the refresh, then switch again"
            )));
        }
        Err(Error::NeedsLogin(m)) => {
            if let Some(a) = s.registry.account_mut(key) {
                a.needs_login = true;
                s.save()?;
            }
            return Err(Error::NeedsLogin(m));
        }
        Err(e) => return Err(e),
    };
    if let Some(fp) = &recovered.promoted {
        s.registry.add_fingerprint(fp.clone(), key);
        s.save()?;
    }
    let oauth = stored_oauth(ctx.store, key)?
        .ok_or_else(|| Error::NotFound(format!("stored credential of {key}")))?;
    if is_blanked(&oauth) {
        return Err(Error::NeedsLogin(format!(
            "the stored credential of {key} is signed out"
        )));
    }
    let target_fp = oauth_fingerprint(&oauth);
    let from = s.registry.active.cli.clone();
    let mut report = SwitchReport {
        from: from.clone(),
        to: key.into(),
        already_active: false,
        running_sessions: 0,
        backup_id: None,
        warnings: recovered.warnings,
    };

    let live = ctx.live()?;
    // First read outside any lock (a Keychain prompt shows here).
    let live_bytes = ctx.store.get(&live.service, &live.account)?;
    let live_oauth = match &live_bytes {
        Some(b) => {
            RawItem::parse(b.expose())?;
            oauth_of(b.expose())?
        }
        None => None,
    };
    drop(live_bytes);
    let live_fp = live_oauth.as_ref().map(oauth_fingerprint);
    if from.as_deref() == Some(key) && live_fp.as_deref() == Some(target_fp.as_str()) {
        report.already_active = true;
        return Ok(report);
    }

    // What the live credential must still be at write time. When sync
    // identified it as the account being switched away from, that is the
    // credential sync stored for it: a refresh since then (e.g. while the
    // user answered a prompt) would otherwise be overwritten and its
    // rotated refresh token lost. Otherwise it is what was read just now
    // (and, for a login cma does not store, what the user confirmed to
    // replace).
    let expected_live_fp = match (&s.live, from.as_deref()) {
        (
            LiveState::Identified {
                key: k,
                managed: true,
            },
            Some(f),
        ) if k == f => Some(
            stored_oauth(ctx.store, f)?
                .map(|o| oauth_fingerprint(&o))
                .ok_or_else(|| Error::NotFound(format!("stored credential of {f}")))?,
        ),
        _ => live_fp.clone(),
    };

    for (dir, what) in [
        (&paths.secure_storage_dir, "Claude Code config dir"),
        (&paths.claude_json, "Claude Code settings file"),
    ] {
        if std::fs::symlink_metadata(dir).is_err() {
            return Err(Error::NotFound(format!(
                "{what} {} (run `claude` once before switching; cma does not create it)",
                dir.display()
            )));
        }
    }

    // A live login cma does not store would survive only in the backup.
    let unstored = match &s.live {
        LiveState::Identified {
            key: k,
            managed: false,
        } => Some(format!("{k}, which cma does not store")),
        LiveState::Unidentified { reason } => {
            Some(format!("a login cma could not identify ({reason})"))
        }
        _ => None,
    };
    if let Some(who) = unstored
        && live_oauth.as_ref().is_some_and(|o| !is_blanked(o))
    {
        let msg = format!(
            "the live CLI login is {who}; switching replaces it and keeps it only in the backup. Run `cma import-current` first to keep it as an account"
        );
        confirm(
            &opts.replace_live,
            &msg,
            "switch cancelled",
            "--replace-live",
        )?;
        report
            .warnings
            .push(Warning::new("live_login_replaced", msg));
    }

    let pids = running_cli_sessions(opts.procs)?;
    report.running_sessions = pids.len();
    if !pids.is_empty() {
        let msg = running_sessions_message(pids.len());
        confirm(&opts.confirm, &msg, "switch cancelled", "--force")?;
        report.warnings.push(Warning::new("running_sessions", msg));
    }

    let mut b = crate::backup::Backup::create(paths, ctx.store, ctx.locker, "switch")?;
    report.backup_id = Some(b.id().to_string());
    let mut j = ActiveJournal::begin(
        paths,
        s.lock(),
        Journal {
            op: "switch".into(),
            target: "cli".into(),
            from: from.clone(),
            to: Some(key.into()),
            backup_id: b.id().to_string(),
            steps_done: Vec::new(),
            extra: Map::new(),
        },
    )?;

    let mut new_registry = s.registry.clone();
    let mut warnings = Vec::new();
    let steps = (|| -> std::result::Result<(), StepErr> {
        // Read-modify-write inside `.storage-write`: only claudeAiOauth.
        let others = write_live_oauth(&mut b, &live, &oauth, expected_live_fp.as_deref())?;
        j.step("keychain")?;
        point("keychain", ctx.store)?;

        b.write_json_keys(
            &paths.claude_json,
            &[("oauthAccount".into(), Some(oauth_account_for(&target)))],
            &[],
        )?;
        j.step("claude_json")?;
        point("claude_json", ctx.store)?;

        // Post-check. The Keychain decides success; `oauthAccount` is only
        // display metadata that a running session may rewrite from memory
        // at any time, so a mismatch is a warning, not a rollback.
        post_check_live(ctx.store, &live, &target_fp, &others)?;
        let cj: Value = serde_json::from_slice(
            &crate::fsutil::read_nofollow(&paths.claude_json)?.unwrap_or_default(),
        )
        .map_err(|e| Error::json("claude.json", &e))?;
        if cj["oauthAccount"]["accountUuid"].as_str() != Some(target.account_uuid.as_str()) {
            warnings.push(Warning::new(
                "oauth_account_reverted",
                "~/.claude.json `oauthAccount` no longer names the new account (a running Claude Code session most likely rewrote it); the login itself switched, and only names shown by Claude Code may be stale",
            ));
        }
        point("post_check", ctx.store)?;

        let now = ctx.now_secs();
        if let Some(prev) = from.as_deref().and_then(|f| new_registry.account_mut(f)) {
            prev.last_active_at = now;
        }
        new_registry.active.cli = Some(key.into());
        new_registry.save(&paths.registry_file())?;
        j.step("registry")?;
        Ok(())
    })();

    match steps {
        Ok(()) => {
            j.finish()?;
            s.registry = new_registry;
            s.live = LiveState::Identified {
                key: key.into(),
                managed: true,
            };
            report.warnings.extend(warnings);
            Ok(report)
        }
        #[cfg(test)]
        Err(StepErr::Crashed) => {
            std::mem::forget(j);
            Err(Error::Interrupted)
        }
        Err(StepErr::Failed(e)) => {
            drop(b);
            let (e, clean) = abort_op(j, ctx, "switch", e);
            if clean {
                // The registry on disk may hold the new state if the
                // failure came after its save; put the old one back.
                s.registry.save(&paths.registry_file())?;
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::failpoint::{self, Act};
    use super::*;
    use crate::cli_target::testkit::*;
    use crate::cli_target::{OWN_SERVICE, oauth_only_item};
    use crate::procs::tests::{FakeProcs, p};
    use crate::registry::Registry;
    use crate::secret::{Secret, SecretStore};
    use crate::sync::begin;
    use crate::sync::tests::{add_account, set_active};

    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            failpoint::clear();
        }
    }

    /// A and B stored, A active and live (with an mcpOAuth key).
    fn setup() -> (World, Value, Value) {
        let w = World::new();
        let (a, b) = (oauth("A"), oauth("B"));
        add_account(&w, "A::oA", "a@x", &a);
        add_account(&w, "B::oB", "b@x", &b);
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&a));
        (w, a, b)
    }

    fn no_procs() -> FakeProcs {
        FakeProcs::default()
    }

    fn opts<'a>(procs: &'a FakeProcs, force: bool) -> SwitchOpts<'a> {
        SwitchOpts {
            confirm: Confirm::NonInteractive { force },
            replace_live: Confirm::NonInteractive { force },
            procs,
        }
    }

    fn reg(w: &World) -> Registry {
        Registry::load(&w.paths.registry_file()).unwrap()
    }

    #[test]
    fn switch_waits_for_the_target_account_lock_and_reads_after_it() {
        let (w, _a, _b) = setup();
        let rotated = oauth("B2");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|sc| {
            let (paths, store, rotated) = (&w.paths, &w.store, &rotated);
            sc.spawn(move || {
                // A refresher holding B's lock rotates its stored grant.
                let g = AccountLock::acquire(paths, "B::oB").unwrap();
                tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(200));
                store
                    .set(OWN_SERVICE, "B::oB", &oauth_only_item(rotated))
                    .unwrap();
                drop(g);
            });
            rx.recv().unwrap();
            let ctx = w.ctx();
            let mut s = begin(&ctx).unwrap();
            let procs = no_procs();
            switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap();
        });
        assert_eq!(
            oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(),
            rotated
        );
    }

    #[test]
    fn switch_replaces_only_claude_ai_oauth_and_oauth_account() {
        use std::os::unix::fs::PermissionsExt;
        let (w, a, b) = setup();
        let before = w.live_bytes().unwrap();
        std::fs::set_permissions(&w.paths.claude_json, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = no_procs();
        let r = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap();
        assert!(!r.already_active);
        assert_eq!(
            w.locker.acquired.get(),
            1,
            "live write under .storage-write"
        );
        let after = w.live_bytes().unwrap();
        let (rb, ra) = (
            RawItem::parse(&before).unwrap(),
            RawItem::parse(&after).unwrap(),
        );
        assert_eq!(rb.others(), ra.others(), "mcpOAuth byte-equal");
        assert_eq!(after, replace_oauth(Some(&before), &b).unwrap().expose());
        assert_eq!(oauth_of(&after).unwrap().unwrap(), b);
        // Unrelated ~/.claude.json keys kept.
        let cj = w.claude_json();
        assert_eq!(cj["numStartups"], 7);
        assert_eq!(cj["projects"]["/p"]["k"], 1);
        assert_eq!(cj["oauthAccount"]["accountUuid"], "B");
        assert_eq!(cj["oauthAccount"]["emailAddress"], "b@x");
        assert_eq!(
            crate::fsutil::existing_mode(&w.paths.claude_json).unwrap(),
            Some(0o644),
            "~/.claude.json keeps its mode"
        );
        drop(s);
        let r = reg(&w);
        assert_eq!(r.active.cli.as_deref(), Some("B::oB"));
        assert_eq!(r.account("A::oA").unwrap().last_active_at, NOW_MS / 1000);
        assert!(!w.paths.journal_file().exists());
        // The old account's stored credential is untouched.
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a);
        // Next command: sync sees B, active; nothing to store.
        let s = begin(&ctx).unwrap();
        assert_eq!(
            s.live,
            LiveState::Identified {
                key: "B::oB".into(),
                managed: true
            }
        );
        assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    }

    #[test]
    fn already_active_is_a_no_op() {
        let (w, _, _) = setup();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = no_procs();
        let r = switch_cli(&mut s, "A::oA", &opts(&procs, false)).unwrap();
        assert!(r.already_active);
        assert_eq!(w.locker.acquired.get(), 0);
    }

    #[test]
    fn crash_between_keychain_and_claude_json_rolls_back_next_command() {
        let (w, _, _) = setup();
        let before = w.live_bytes().unwrap();
        let cj_before = std::fs::read(&w.paths.claude_json).unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let _reset = Reset;
        failpoint::set(|step, _| {
            if step == "keychain" {
                Act::Crash
            } else {
                Act::Continue
            }
        });
        let procs = no_procs();
        assert!(matches!(
            switch_cli(&mut s, "B::oB", &opts(&procs, false)),
            Err(Error::Interrupted)
        ));
        failpoint::clear();
        drop(s);
        assert!(w.paths.journal_file().exists(), "crash leaves the journal");
        assert_ne!(w.live_bytes().unwrap(), before, "B was written");
        let s = begin(&ctx).unwrap();
        assert!(
            s.warnings.iter().any(|x| x.code == "recovered"),
            "{:?}",
            s.warnings
        );
        assert_eq!(
            w.live_bytes().unwrap(),
            before,
            "rolled back to A byte-exact"
        );
        assert_eq!(std::fs::read(&w.paths.claude_json).unwrap(), cj_before);
        assert!(!w.paths.journal_file().exists());
        assert_eq!(s.registry.active.cli.as_deref(), Some("A::oA"));
    }

    #[test]
    fn failure_after_write_rolls_back_in_command() {
        let (w, _, _) = setup();
        let before = w.live_bytes().unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let _reset = Reset;
        failpoint::set(|step, _| {
            if step == "post_check" {
                Act::Fail
            } else {
                Act::Continue
            }
        });
        let procs = no_procs();
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        assert!(matches!(e, Error::Invalid { .. }), "{e:?}");
        assert_eq!(w.live_bytes().unwrap(), before);
        assert_eq!(w.claude_json()["oauthAccount"]["accountUuid"], "A");
        assert!(!w.paths.journal_file().exists());
        assert_eq!(reg(&w).active.cli.as_deref(), Some("A::oA"));
    }

    #[test]
    fn rollback_never_overwrites_a_newer_live_value() {
        let (w, _, _) = setup();
        let before = w.live_bytes().unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let _reset = Reset;
        let refreshed = live_item(&oauth("B-refreshed"));
        let r2 = refreshed.clone();
        let live = w.live();
        failpoint::set(move |step, store: &dyn SecretStore| {
            if step == "claude_json" {
                // Claude refreshed B's token after cma's write, then cma fails.
                store
                    .set(&live.service, &live.account, &Secret::new(r2.clone()))
                    .unwrap();
                Act::Fail
            } else {
                Act::Continue
            }
        });
        let procs = no_procs();
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        assert_eq!(e.code(), "state_uncertain", "{e}");
        assert_eq!(w.live_bytes().unwrap(), refreshed, "newer value left alone");
        assert!(w.paths.journal_file().exists(), "journal kept");
        // oauthAccount (still cma's write) was rolled back.
        assert_eq!(w.claude_json()["oauthAccount"]["accountUuid"], "A");
        // The backup is kept: its dir, and the Keychain copy of A's item.
        let backups: Vec<_> = std::fs::read_dir(w.paths.backups_dir())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(backups.len(), 1, "{backups:?}");
        assert!(backups[0].join("manifest.json").exists());
        assert_eq!(w.store.count(crate::backup::BACKUP_SERVICE), 1);
        let m: Value =
            serde_json::from_slice(&std::fs::read(backups[0].join("manifest.json")).unwrap())
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
    }

    #[test]
    fn running_sessions_need_force_or_confirmation() {
        let (w, _, _) = setup();
        let before = w.live_bytes().unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = FakeProcs(vec![p(10, 1, "-zsh"), p(11, 10, "claude")], false);
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        assert_eq!(e.code(), "confirmation_required");
        assert!(e.to_string().contains("within ~30s"), "{e}");
        assert!(
            e.to_string()
                .contains("/status keeps showing the old account name")
        );
        let no = |_: &str| false;
        let e = switch_cli(
            &mut s,
            "B::oB",
            &SwitchOpts {
                confirm: Confirm::Interactive(&no),
                replace_live: Confirm::Interactive(&no),
                procs: &procs,
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), "confirmation_required");
        assert_eq!(w.live_bytes().unwrap(), before);
        assert_eq!(
            w.store.count(crate::backup::BACKUP_SERVICE),
            0,
            "nothing begun"
        );
        let asked = std::cell::Cell::new(None::<String>);
        let yes = |m: &str| {
            asked.set(Some(m.to_string()));
            true
        };
        let r = switch_cli(
            &mut s,
            "B::oB",
            &SwitchOpts {
                confirm: Confirm::Interactive(&yes),
                replace_live: Confirm::Interactive(&yes),
                procs: &procs,
            },
        )
        .unwrap();
        assert_eq!(r.running_sessions, 1);
        assert!(
            asked
                .take()
                .unwrap()
                .starts_with("1 running Claude Code session(s)")
        );
        // Process listing failure is fatal.
        let broken = FakeProcs(vec![], true);
        assert!(switch_cli(&mut s, "A::oA", &opts(&broken, true)).is_err());
    }

    #[test]
    fn missing_claude_state_fails_closed() {
        let (w, _, _) = setup();
        let ctx = w.ctx();
        std::fs::remove_file(&w.paths.claude_json).unwrap();
        let mut s = begin(&ctx).unwrap();
        let procs = no_procs();
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        assert_eq!(e.code(), "not_found");
        assert!(!w.paths.claude_json.exists(), "not created");
        std::fs::remove_dir(&w.paths.secure_storage_dir).unwrap();
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        assert!(e.to_string().contains("run `claude` once"), "{e}");
    }

    #[test]
    fn refuses_non_object_live_item_signed_out_and_console_targets() {
        let (w, _, _) = setup();
        let ctx = w.ctx();
        let procs = no_procs();
        {
            let mut s = begin(&ctx).unwrap();
            w.set_live(b"[]");
            assert!(matches!(
                switch_cli(&mut s, "B::oB", &opts(&procs, false)),
                Err(Error::Invalid { .. })
            ));
        }
        w.set_live(&live_item(&oauth("A")));
        w.store
            .set(OWN_SERVICE, "B::oB", &oauth_only_item(&blanked()))
            .unwrap();
        let mut s = begin(&ctx).unwrap();
        assert_eq!(
            switch_cli(&mut s, "B::oB", &opts(&procs, false))
                .unwrap_err()
                .code(),
            "needs_login"
        );
        s.registry.account_mut("B::oB").unwrap().kind = AccountKind::Console;
        assert_eq!(
            switch_cli(&mut s, "B::oB", &opts(&procs, false))
                .unwrap_err()
                .code(),
            "unsupported"
        );
    }

    #[test]
    fn absent_live_item_gets_only_claude_ai_oauth() {
        let (w, _, b) = setup();
        let l = w.live();
        w.store.delete(&l.service, &l.account).unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = no_procs();
        switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap();
        assert_eq!(w.live_bytes().unwrap(), oauth_only_item(&b).expose());
    }

    #[test]
    fn refresh_between_sync_and_switch_aborts_and_keeps_the_rotated_token() {
        let (w, a, _) = setup();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        // A running session refreshes A after sync stored it (e.g. while the
        // user answers the running-sessions prompt): A's refresh token is
        // rotated, and only the live item holds the new pair.
        let a2 = oauth("A2");
        let refreshed = live_item(&a2);
        w.set_live(&refreshed);
        let procs = no_procs();
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        assert_eq!(e.code(), "concurrent_write", "{e}");
        assert_eq!(w.live_bytes().unwrap(), refreshed, "nothing written");
        assert_eq!(w.claude_json()["oauthAccount"]["accountUuid"], "A");
        assert!(!w.paths.journal_file().exists(), "journal clean");
        assert_eq!(w.store.count(crate::backup::BACKUP_SERVICE), 0);
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a);
        drop(s);
        assert_eq!(reg(&w).active.cli.as_deref(), Some("A::oA"));
        // The next command stores the rotated pair under A; the switch then
        // succeeds.
        w.profile.add("at-A2", "A", "oA", "a@x");
        let mut s = begin(&ctx).unwrap();
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a2);
        switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap();
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a2);
    }

    #[test]
    fn refresh_during_the_prompt_aborts() {
        let (w, _, _) = setup();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = FakeProcs(vec![p(11, 1, "claude")], false);
        let refreshed = live_item(&oauth("A2"));
        let yes = |_: &str| {
            w.set_live(&refreshed);
            true
        };
        let e = switch_cli(
            &mut s,
            "B::oB",
            &SwitchOpts {
                confirm: Confirm::Interactive(&yes),
                replace_live: Confirm::Interactive(&yes),
                procs: &procs,
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), "concurrent_write", "{e}");
        assert_eq!(w.live_bytes().unwrap(), refreshed);
        assert!(!w.paths.journal_file().exists());
    }

    /// Live = C: unmanaged (profile says C, not stored) or unidentified.
    fn unstored_live(w: &World, managed_profile: bool) -> Vec<u8> {
        if managed_profile {
            w.profile.add("at-C", "C", "oC", "c@x");
        }
        let item = live_item(&oauth("C"));
        w.set_live(&item);
        item
    }

    #[test]
    fn unstored_live_login_needs_confirmation() {
        for managed_profile in [true, false] {
            let (w, _, b) = setup();
            let item = unstored_live(&w, managed_profile);
            let ctx = w.ctx();
            let mut s = begin(&ctx).unwrap();
            if managed_profile {
                assert_eq!(
                    s.live,
                    LiveState::Identified {
                        key: "C::oC".into(),
                        managed: false
                    }
                );
            } else {
                assert!(matches!(s.live, LiveState::Unidentified { .. }));
            }
            let procs = no_procs();
            // --json without --force.
            let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
            assert_eq!(e.code(), "confirmation_required");
            assert!(e.to_string().contains("import-current"), "{e}");
            assert!(e.to_string().contains("pass --replace-live"), "{e}");
            // Interactive: N.
            let asked = std::cell::Cell::new(0);
            let no = |m: &str| {
                assert!(m.contains("`cma import-current` first"), "{m}");
                asked.set(asked.get() + 1);
                false
            };
            let e = switch_cli(
                &mut s,
                "B::oB",
                &SwitchOpts {
                    confirm: Confirm::Interactive(&no),
                    replace_live: Confirm::Interactive(&no),
                    procs: &procs,
                },
            )
            .unwrap_err();
            assert_eq!(e.code(), "confirmation_required");
            assert_eq!(asked.get(), 1);
            assert_eq!(w.live_bytes().unwrap(), item, "nothing written");
            assert_eq!(w.store.count(crate::backup::BACKUP_SERVICE), 0);
            assert!(!w.paths.journal_file().exists());
            // Interactive: y.
            let yes = |_: &str| true;
            let r = switch_cli(
                &mut s,
                "B::oB",
                &SwitchOpts {
                    confirm: Confirm::Interactive(&yes),
                    replace_live: Confirm::Interactive(&yes),
                    procs: &procs,
                },
            )
            .unwrap();
            assert!(r.warnings.iter().any(|x| x.code == "live_login_replaced"));
            assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), b);
            // C survives in the backup.
            assert_eq!(w.store.count(crate::backup::BACKUP_SERVICE), 1);
            // --force (from a fresh unstored login again).
            drop(s);
            w.set_live(&item);
            let mut s = begin(&ctx).unwrap();
            switch_cli(&mut s, "B::oB", &opts(&procs, true)).unwrap();
            assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), b);
        }
    }

    #[test]
    fn running_sessions_consent_does_not_replace_an_unstored_login() {
        let (w, _, b) = setup();
        let item = unstored_live(&w, true);
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = FakeProcs(vec![p(11, 1, "claude")], false);
        // --force (sessions) alone: the unstored login still needs its own consent.
        let only_force = SwitchOpts {
            confirm: Confirm::NonInteractive { force: true },
            replace_live: Confirm::NonInteractive { force: false },
            procs: &procs,
        };
        let e = switch_cli(&mut s, "B::oB", &only_force).unwrap_err();
        assert_eq!(e.code(), "confirmation_required");
        assert!(e.to_string().contains("pass --replace-live"), "{e}");
        assert!(!e.to_string().contains("pass --force"), "{e}");
        assert_eq!(w.live_bytes().unwrap(), item, "nothing written");
        // --replace-live alone: running sessions still need --force.
        let only_replace = SwitchOpts {
            confirm: Confirm::NonInteractive { force: false },
            replace_live: Confirm::NonInteractive { force: true },
            procs: &procs,
        };
        let e = switch_cli(&mut s, "B::oB", &only_replace).unwrap_err();
        assert_eq!(e.code(), "confirmation_required");
        assert!(e.to_string().contains("pass --force"), "{e}");
        assert_eq!(w.live_bytes().unwrap(), item, "nothing written");
        // Both.
        let both = SwitchOpts {
            confirm: Confirm::NonInteractive { force: true },
            replace_live: Confirm::NonInteractive { force: true },
            procs: &procs,
        };
        let r = switch_cli(&mut s, "B::oB", &both).unwrap();
        assert!(r.warnings.iter().any(|x| x.code == "live_login_replaced"));
        assert!(r.warnings.iter().any(|x| x.code == "running_sessions"));
        assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), b);
    }

    #[test]
    fn stored_or_signed_out_live_login_needs_no_confirmation() {
        // Managed live login (A) is the setup: no prompt. A blanked live
        // login is dead, so replacing it needs no confirmation either.
        let (w, _, _) = setup();
        w.set_live(&live_item(&blanked()));
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = no_procs();
        let never = |m: &str| -> bool { panic!("asked: {m}") };
        switch_cli(
            &mut s,
            "B::oB",
            &SwitchOpts {
                confirm: Confirm::Interactive(&never),
                replace_live: Confirm::Interactive(&never),
                procs: &procs,
            },
        )
        .unwrap();
    }

    #[test]
    fn oauth_account_rewritten_by_a_session_warns_without_rollback() {
        let (w, _, b) = setup();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let _reset = Reset;
        let cj_path = w.paths.claude_json.clone();
        failpoint::set(move |step, _| {
            if step == "claude_json" {
                // A running session rewrites ~/.claude.json from memory.
                let mut cj: Value =
                    serde_json::from_slice(&std::fs::read(&cj_path).unwrap()).unwrap();
                cj["oauthAccount"] =
                    serde_json::json!({"accountUuid": "A", "organizationUuid": "oA"});
                std::fs::write(&cj_path, serde_json::to_vec(&cj).unwrap()).unwrap();
            }
            Act::Continue
        });
        let procs = no_procs();
        let r = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap();
        assert!(
            r.warnings
                .iter()
                .any(|x| x.code == "oauth_account_reverted"),
            "{:?}",
            r.warnings
        );
        assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), b);
        assert!(!w.paths.journal_file().exists());
        drop(s);
        assert_eq!(reg(&w).active.cli.as_deref(), Some("B::oB"));
    }

    #[test]
    fn failed_live_read_in_switch_aborts() {
        let (w, _, _) = setup();
        let before = w.live_bytes().unwrap();
        let fg = crate::cli_target::testkit::FailGet::live(&w);
        let ctx = w.ctx_with(&fg);
        let mut s = begin(&ctx).unwrap();
        fg.armed.set(true);
        let procs = no_procs();
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        assert_eq!(e.code(), "external_tool", "{e}");
        fg.armed.set(false);
        assert_eq!(w.live_bytes().unwrap(), before);
        assert_eq!(w.store.count(crate::backup::BACKUP_SERVICE), 0);
        assert!(!w.paths.journal_file().exists());
        assert_eq!(w.claude_json()["oauthAccount"]["accountUuid"], "A");
    }

    fn keep_aside(w: &World, key: &str, kept: &Value, ids: Option<(&str, &str)>, from: &Value) {
        w.store
            .set(
                crate::backup::BACKUP_SERVICE,
                &crate::refresh::post_refresh_account(key),
                &crate::refresh::post_refresh_item(
                    kept,
                    ids.map(|i| i.0),
                    ids.map(|i| i.1),
                    Some(&oauth_fingerprint(from)),
                )
                .unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn switch_stores_a_kept_refreshed_pair_before_making_it_live() {
        let (w, _a, b) = setup();
        let b2 = oauth("B2");
        keep_aside(&w, "B::oB", &b2, Some(("B", "oB")), &b);
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = no_procs();
        let r = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap();
        drop(s);
        assert!(r.warnings.iter().any(|x| x.code == "refresh_recovered"));
        // The valid grant went live, not the spent one.
        assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), b2);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b2);
        assert_eq!(
            reg(&w).account_for_fingerprint(&oauth_fingerprint(&b2)),
            Some("B::oB")
        );
        assert!(
            w.store
                .get(
                    crate::backup::BACKUP_SERVICE,
                    &crate::refresh::post_refresh_account("B::oB")
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn switch_refuses_while_a_kept_pair_needs_a_lookup() {
        let (w, a, b) = setup();
        keep_aside(&w, "B::oB", &oauth("B2"), None, &b);
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = no_procs();
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        drop(s);
        assert_eq!(e.code(), "refresh_pending");
        assert!(e.to_string().contains("cma usage"), "{e}");
        assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), a);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b);
        assert!(
            w.store
                .get(
                    crate::backup::BACKUP_SERVICE,
                    &crate::refresh::post_refresh_account("B::oB")
                )
                .unwrap()
                .is_some(),
            "kept for a later check"
        );
        assert_eq!(reg(&w).active.cli.as_deref(), Some("A::oA"));
    }

    #[test]
    fn switch_refuses_a_kept_pair_of_another_account_and_flags_needs_login() {
        let (w, a, b) = setup();
        keep_aside(&w, "B::oB", &oauth("C2"), Some(("C", "oC")), &b);
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let procs = no_procs();
        let e = switch_cli(&mut s, "B::oB", &opts(&procs, false)).unwrap_err();
        drop(s);
        assert_eq!(e.code(), "needs_login");
        assert_eq!(oauth_of(&w.live_bytes().unwrap()).unwrap().unwrap(), a);
        assert!(reg(&w).account("B::oB").unwrap().needs_login);
    }
}
