//! Write-ahead journal for multi-step mutations, and crash recovery.
//!
//! `op.journal` is written before the first mutation, updated after each
//! step and deleted on success. If a command dies mid-op, the next command
//! calls [`recover`] under the cma lock and rolls back using the journal's
//! backup. When rollback leaves the state uncertain the journal stays and
//! blocks new ops until the user acknowledges it with [`resolve`].

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::backup::{Allowlist, RestoreReport, Restorer};
use crate::error::{Error, Result};
use crate::fsutil;
use crate::lock::{CmaLock, StorageLockAcquirer};
use crate::paths::Paths;
use crate::secret::SecretStore;

/// File name, inside the backup dir, of a journal acknowledged by [`resolve`].
pub const RESOLVED_JOURNAL: &str = "resolved-journal.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Journal {
    pub op: String,
    pub target: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub backup_id: String,
    #[serde(default)]
    pub steps_done: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An open journal. Dropping it without [`ActiveJournal::finish`] leaves the
/// file in place, which is exactly what a crash looks like.
#[derive(Debug)]
pub struct ActiveJournal {
    path: PathBuf,
    journal: Journal,
}

fn write(path: &Path, j: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(j).map_err(|e| Error::json("journal", &e))?;
    fsutil::atomic_write_mode(path, &bytes, 0o600)
}

/// Read the journal, if one exists.
pub fn read(paths: &Paths) -> Result<Option<Journal>> {
    match fsutil::read_nofollow(&paths.journal_file())? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Error::json("journal", &e)),
        None => Ok(None),
    }
}

impl ActiveJournal {
    /// Start an op. Refuses if a journal already exists (recover first).
    pub fn begin(paths: &Paths, lock: &CmaLock, journal: Journal) -> Result<Self> {
        lock.check_for(paths)?;
        let path = paths.journal_file();
        if fsutil::read_nofollow(&path)?.is_some() {
            return Err(Error::StateUncertain(
                "an unfinished operation journal exists; run recovery first".into(),
            ));
        }
        write(&path, &journal)?;
        Ok(ActiveJournal { path, journal })
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Record a completed step.
    pub fn step(&mut self, name: &str) -> Result<()> {
        self.journal.steps_done.push(name.to_string());
        write(&self.path, &self.journal)
    }

    /// [`ActiveJournal::abort`], checking `guard` before every rollback
    /// write inside the Desktop dir: if it trips, the journal stays (the
    /// next command rolls back once Desktop is quit) and the error says so.
    pub fn abort_guarded(
        self,
        paths: &Paths,
        store: &dyn SecretStore,
        locker: &dyn StorageLockAcquirer,
        allow: &Allowlist,
        guard: crate::backup::DesktopGuard<'_>,
    ) -> Result<RestoreReport> {
        let report = Restorer::load(paths, store, locker, allow, &self.journal.backup_id)?
            .with_guard(guard)
            .rollback()?;
        if !report.state_uncertain() {
            self.finish()?;
        }
        Ok(report)
    }

    /// The op succeeded: delete the journal (durably).
    pub fn finish(self) -> Result<()> {
        fsutil::remove_file_durable(&self.path).map(|_| ())
    }

    /// The op failed in-command: roll back now. On full success the journal
    /// is deleted; if anything is uncertain the journal and backup are kept.
    pub fn abort(
        self,
        paths: &Paths,
        store: &dyn SecretStore,
        locker: &dyn StorageLockAcquirer,
        allow: &Allowlist,
    ) -> Result<RestoreReport> {
        let report =
            Restorer::load(paths, store, locker, allow, &self.journal.backup_id)?.rollback()?;
        if !report.state_uncertain() {
            self.finish()?;
        }
        Ok(report)
    }
}

/// File name, in `CMA_HOME`, of the record of a running `switch --both`.
pub const BOTH_FILE: &str = "both.journal";

/// `switch --both` as one unit: written before the Claude Code half,
/// updated with its backup once it switched, removed when both halves are
/// done (or Claude Code was put back). Found by the next command, it means
/// the Desktop half never finished: [`crate::sync::begin`] puts Claude Code
/// back too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BothRecord {
    /// The Claude Code account before the switch.
    pub cli_from: Option<String>,
    pub cli_to: String,
    /// Backup of the Claude Code half (`None`: it had not switched yet).
    pub cli_backup_id: Option<String>,
    /// The `cma` process running this `--both`, and when it started: while
    /// it runs, nobody else acts on the record.
    #[serde(default)]
    pub owner_pid: u32,
    #[serde(default)]
    pub owner_start: Option<String>,
    /// Backup of the Desktop half, recorded once its journal began. Set
    /// and no rollback seen: the Desktop half finished.
    #[serde(default)]
    pub desktop_backup_id: Option<String>,
    /// Recovery rolled the Desktop half back (Claude Code must follow).
    #[serde(default)]
    pub desktop_rolled_back: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl BothRecord {
    /// A record owned by this process.
    pub fn new(cli_from: Option<String>, cli_to: String) -> Self {
        let pid = std::process::id();
        BothRecord {
            cli_from,
            cli_to,
            cli_backup_id: None,
            owner_pid: pid,
            owner_start: crate::procs::process_start(pid),
            desktop_backup_id: None,
            desktop_rolled_back: false,
            extra: Map::new(),
        }
    }

    /// Whether the process that wrote the record may still run. Fails
    /// safe: only a definite "gone" (no such pid, or the pid now belongs to
    /// a process with another start time) counts as dead; anything cma
    /// cannot check counts as alive.
    pub fn owner_alive(&self) -> bool {
        self.owner_alive_with(&crate::procs::probe_start)
    }

    pub fn owner_alive_with(&self, probe: &dyn Fn(u32) -> crate::procs::ProcStart) -> bool {
        use crate::procs::ProcStart;
        if self.owner_pid == 0 {
            return false;
        }
        match probe(self.owner_pid) {
            ProcStart::Gone => false,
            ProcStart::Unknown => true,
            ProcStart::Started(now) => match &self.owner_start {
                Some(then) => *then == now,
                None => true,
            },
        }
    }
}

/// The Desktop op with backup `id` was rolled back: if a `--both` record
/// names it as its Desktop half, Claude Code must be put back too.
pub fn both_mark_rolled_back(paths: &Paths, lock: &CmaLock, id: &str) -> Result<()> {
    if let Some(mut r) = both_read(paths)?
        && r.desktop_backup_id.as_deref() == Some(id)
        && !r.desktop_rolled_back
    {
        r.desktop_rolled_back = true;
        both_write(paths, lock, &r)?;
    }
    Ok(())
}

/// The Desktop half's journal began with backup `id`: note it in this
/// thread's `--both` record.
pub fn both_note_desktop_backup(paths: &Paths, lock: &CmaLock, id: &str) -> Result<()> {
    if !both_active_here() {
        return Ok(());
    }
    if let Some(mut r) = both_read(paths)? {
        r.desktop_backup_id = Some(id.to_string());
        both_write(paths, lock, &r)?;
    }
    Ok(())
}

thread_local! {
    static BOTH_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Held by the `switch --both` that owns the record, so its own commands'
/// recovery does not treat it as interrupted. Dropping it (also on a
/// panic) ends that.
pub struct BothActive(());

impl BothActive {
    pub fn enter() -> Self {
        BOTH_ACTIVE.with(|b| b.set(true));
        BothActive(())
    }
}

impl Drop for BothActive {
    fn drop(&mut self) {
        let _ = BOTH_ACTIVE.try_with(|b| b.set(false));
    }
}

pub fn both_active_here() -> bool {
    BOTH_ACTIVE.with(|b| b.get())
}

pub fn both_read(paths: &Paths) -> Result<Option<BothRecord>> {
    match fsutil::read_nofollow(&paths.cma_home.join(BOTH_FILE))? {
        Some(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| Error::json("both journal", &e)),
        None => Ok(None),
    }
}

pub fn both_write(paths: &Paths, lock: &CmaLock, r: &BothRecord) -> Result<()> {
    lock.check_for(paths)?;
    let bytes = serde_json::to_vec_pretty(r).map_err(|e| Error::json("both journal", &e))?;
    fsutil::atomic_write_mode(&paths.cma_home.join(BOTH_FILE), &bytes, 0o600)
}

pub fn both_clear(paths: &Paths) -> Result<()> {
    fsutil::remove_file_durable(&paths.cma_home.join(BOTH_FILE)).map(|_| ())
}

/// Outcome of [`recover`].
#[derive(Debug, Clone, PartialEq)]
pub struct Recovery {
    pub journal: Journal,
    pub report: RestoreReport,
    /// Human-readable lines for `warnings[]`.
    pub warnings: Vec<String>,
}

impl Recovery {
    pub fn state_uncertain(&self) -> bool {
        self.report.state_uncertain()
    }
}

/// Run at the start of every command, under the cma lock. If a journal
/// exists, roll the interrupted op back using its backup. The journal is
/// deleted only when every entry is back at its pre-image.
///
/// A journal whose backup is gone yields [`Error::BackupMissing`]; the
/// journal is kept until the user acknowledges it with [`resolve`].
pub fn recover(
    paths: &Paths,
    lock: &CmaLock,
    store: &dyn SecretStore,
    locker: &dyn StorageLockAcquirer,
    allow: &Allowlist,
) -> Result<Option<Recovery>> {
    recover_guarded(paths, lock, store, locker, allow, None)
}

/// [`recover`], checking `guard` before every replayed write inside the
/// Claude Desktop dir (an error keeps the journal).
pub fn recover_guarded(
    paths: &Paths,
    lock: &CmaLock,
    store: &dyn SecretStore,
    locker: &dyn StorageLockAcquirer,
    allow: &Allowlist,
    guard: Option<crate::backup::DesktopGuard<'_>>,
) -> Result<Option<Recovery>> {
    lock.check_for(paths)?;
    let Some(journal) = read(paths)? else {
        return Ok(None);
    };
    let mut restorer = Restorer::load(paths, store, locker, allow, &journal.backup_id)?;
    if let Some(g) = guard {
        restorer = restorer.with_guard(g);
    }
    let report = restorer.rollback()?;
    let mut warnings = vec![format!(
        "rolled back interrupted {} ({}) using backup {}: {} restored, {} unchanged",
        journal.op,
        journal.target,
        journal.backup_id,
        report.restored.len(),
        report.unchanged.len()
    )];
    warnings.extend(report.warnings.iter().cloned());
    if !report.state_uncertain() {
        fsutil::remove_file_durable(&paths.journal_file())?;
    }
    Ok(Some(Recovery {
        journal,
        report,
        warnings,
    }))
}

/// Outcome of [`resolve`].
#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    /// The acknowledged journal (`None` if it could not be parsed).
    pub journal: Option<Journal>,
    /// Where the journal was archived (inside its backup dir), if it was.
    pub archived: Option<PathBuf>,
}

/// The user accepts the current state after a `state_uncertain` recovery
/// (or a missing backup): the journal is archived into its backup dir as
/// [`RESOLVED_JOURNAL`] and removed, so new ops can start. The backup itself
/// is kept, so `restore <id>` stays possible. Retrying is just [`recover`].
pub fn resolve(paths: &Paths, lock: &CmaLock) -> Result<Option<Resolution>> {
    lock.check_for(paths)?;
    let path = paths.journal_file();
    let Some(bytes) = fsutil::read_nofollow(&path)? else {
        return Ok(None);
    };
    let journal: Option<Journal> = serde_json::from_slice(&bytes).ok();
    let mut archived = None;
    if let Some(j) = &journal
        && crate::backup::is_valid_id(&j.backup_id)
    {
        let dir = paths.backups_dir().join(&j.backup_id);
        if std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            let dest = dir.join(RESOLVED_JOURNAL);
            fsutil::atomic_write_mode(&dest, &bytes, 0o600)?;
            archived = Some(dest);
        }
    }
    fsutil::remove_file_durable(&path)?;
    Ok(Some(Resolution { journal, archived }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::Backup;
    use crate::backup::tests::{CRED, test_paths};
    use crate::lock::tests::FakeLocker;
    use crate::secret::{MemoryStore, Secret};
    use serde_json::json;

    fn s(v: &str) -> Secret {
        Secret::new(v.as_bytes().to_vec())
    }

    fn journal(backup_id: &str) -> Journal {
        Journal {
            op: "switch".into(),
            target: "cli".into(),
            from: Some("a::o".into()),
            to: Some("b::o".into()),
            backup_id: backup_id.into(),
            steps_done: vec![],
            extra: Map::new(),
        }
    }

    /// Run a switch-like op that dies after the Keychain step.
    fn crashing_op(p: &Paths, store: &MemoryStore) -> String {
        let lk = FakeLocker::default();
        let lock = CmaLock::acquire(&p.lock_file()).unwrap();
        let mut b = Backup::create(p, store, &lk, "switch").unwrap();
        let mut j = ActiveJournal::begin(p, &lock, journal(b.id())).unwrap();
        b.write_keychain(CRED, "me", &s("B-TOKEN")).unwrap();
        j.step("keychain").unwrap();
        b.write_json_keys(
            &p.claude_json,
            &[("oauthAccount".into(), Some(json!({"accountUuid": "B"})))],
            &[],
        )
        .unwrap();
        // Crash: neither finish() nor abort().
        b.id().to_string()
    }

    #[test]
    fn crash_is_rolled_back_by_next_recover() {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let store = MemoryStore::new();
        let lk = FakeLocker::default();
        store.set(CRED, "me", &s("A-TOKEN")).unwrap();
        std::fs::write(
            &p.claude_json,
            br#"{"oauthAccount":{"accountUuid":"A"},"x":1}"#,
        )
        .unwrap();
        let id = crashing_op(&p, &store);
        let j = read(&p).unwrap().unwrap();
        assert_eq!(j.steps_done, vec!["keychain"]);
        assert_eq!(j.backup_id, id);

        let lock = CmaLock::acquire(&p.lock_file()).unwrap();
        let allow = Allowlist::for_paths(&p);
        let rec = recover(&p, &lock, &store, &lk, &allow).unwrap().unwrap();
        assert!(!rec.state_uncertain(), "{rec:?}");
        assert_eq!(rec.report.restored.len(), 2);
        assert_eq!(lk.acquired.get(), 1, "live item rolled back under the lock");
        assert!(rec.warnings[0].contains("rolled back"));
        assert_eq!(store.get(CRED, "me").unwrap().unwrap().expose(), b"A-TOKEN");
        let obj: Value = serde_json::from_slice(&std::fs::read(&p.claude_json).unwrap()).unwrap();
        assert_eq!(obj["oauthAccount"]["accountUuid"], "A");
        assert_eq!(obj["x"], 1);
        assert!(read(&p).unwrap().is_none(), "journal deleted");
        // Nothing left to do.
        assert!(recover(&p, &lock, &store, &lk, &allow).unwrap().is_none());
    }

    #[test]
    fn recover_keeps_journal_when_state_uncertain_and_resolve_clears_it() {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let store = MemoryStore::new();
        let lk = FakeLocker::default();
        store.set(CRED, "me", &s("A-TOKEN")).unwrap();
        let id = crashing_op(&p, &store);
        // Claude refreshed after cma's write.
        store.set(CRED, "me", &s("B-ROTATED")).unwrap();
        let lock = CmaLock::acquire(&p.lock_file()).unwrap();
        let allow = Allowlist::for_paths(&p);
        let rec = recover(&p, &lock, &store, &lk, &allow).unwrap().unwrap();
        assert!(rec.state_uncertain());
        assert!(rec.warnings.iter().any(|w| w.contains("state uncertain")));
        assert_eq!(
            store.get(CRED, "me").unwrap().unwrap().expose(),
            b"B-ROTATED"
        );
        assert!(read(&p).unwrap().is_some(), "journal kept");
        assert!(p.backups_dir().join(&id).is_dir(), "backup kept");
        // A new op refuses to start over an unresolved journal.
        let err = ActiveJournal::begin(&p, &lock, journal(&id)).unwrap_err();
        assert_eq!(err.code(), "state_uncertain");

        // The user accepts the current state.
        let res = resolve(&p, &lock).unwrap().unwrap();
        assert_eq!(res.journal.unwrap().backup_id, id);
        let archived = res.archived.unwrap();
        assert_eq!(archived, p.backups_dir().join(&id).join(RESOLVED_JOURNAL));
        assert!(archived.is_file());
        assert!(read(&p).unwrap().is_none(), "block cleared");
        assert!(p.backups_dir().join(&id).is_dir(), "backup kept");
        assert_eq!(
            store.get(CRED, "me").unwrap().unwrap().expose(),
            b"B-ROTATED"
        );
        assert!(recover(&p, &lock, &store, &lk, &allow).unwrap().is_none());
        ActiveJournal::begin(&p, &lock, journal(&id))
            .unwrap()
            .finish()
            .unwrap();
        assert!(resolve(&p, &lock).unwrap().is_none());
    }

    #[test]
    fn recover_with_storage_lock_unavailable_keeps_journal() {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let store = MemoryStore::new();
        store.set(CRED, "me", &s("A-TOKEN")).unwrap();
        crashing_op(&p, &store);
        let lock = CmaLock::acquire(&p.lock_file()).unwrap();
        let allow = Allowlist::for_paths(&p);
        let lk = FakeLocker {
            fail: true,
            ..Default::default()
        };
        let rec = recover(&p, &lock, &store, &lk, &allow).unwrap().unwrap();
        assert!(rec.state_uncertain());
        assert_eq!(store.get(CRED, "me").unwrap().unwrap().expose(), b"B-TOKEN");
        assert!(read(&p).unwrap().is_some(), "journal kept");
        // Once the lock is available again, a retry completes.
        let ok = FakeLocker::default();
        let rec = recover(&p, &lock, &store, &ok, &allow).unwrap().unwrap();
        assert!(!rec.state_uncertain(), "{rec:?}");
        assert_eq!(store.get(CRED, "me").unwrap().unwrap().expose(), b"A-TOKEN");
        assert!(read(&p).unwrap().is_none());
    }

    #[test]
    fn recover_with_missing_backup_gives_clear_code_until_resolved() {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let store = MemoryStore::new();
        let lk = FakeLocker::default();
        let id = crashing_op(&p, &store);
        std::fs::remove_dir_all(p.backups_dir().join(&id)).unwrap();
        let lock = CmaLock::acquire(&p.lock_file()).unwrap();
        let allow = Allowlist::for_paths(&p);
        for _ in 0..2 {
            let err = recover(&p, &lock, &store, &lk, &allow).unwrap_err();
            assert_eq!(err.code(), "backup_missing", "{err}");
            assert!(read(&p).unwrap().is_some());
        }
        let res = resolve(&p, &lock).unwrap().unwrap();
        assert!(res.archived.is_none(), "no backup dir to archive into");
        assert!(recover(&p, &lock, &store, &lk, &allow).unwrap().is_none());
    }

    #[test]
    fn clean_never_removes_the_open_journals_backup() {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let store = MemoryStore::new();
        store.set(CRED, "me", &s("A-TOKEN")).unwrap();
        let id = crashing_op(&p, &store);
        let lock = CmaLock::acquire(&p.lock_file()).unwrap();
        let rep = crate::backup::clean(&p, &lock, &store, 0).unwrap();
        assert!(rep.removed.is_empty());
        assert_eq!(rep.skipped[0].id, id);
        // recover still works afterwards.
        let lk = FakeLocker::default();
        let rec = recover(&p, &lock, &store, &lk, &Allowlist::for_paths(&p))
            .unwrap()
            .unwrap();
        assert!(!rec.state_uncertain(), "{rec:?}");
    }

    #[test]
    fn finish_deletes_and_abort_rolls_back() {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let store = MemoryStore::new();
        let lk = FakeLocker::default();
        store.set(CRED, "me", &s("A")).unwrap();
        let lock = CmaLock::acquire(&p.lock_file()).unwrap();
        let allow = Allowlist::for_paths(&p);

        let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
        let j = ActiveJournal::begin(&p, &lock, journal(b.id())).unwrap();
        b.write_keychain(CRED, "me", &s("B")).unwrap();
        j.finish().unwrap();
        assert!(read(&p).unwrap().is_none());
        assert_eq!(store.get(CRED, "me").unwrap().unwrap().expose(), b"B");

        let mut b = Backup::create(&p, &store, &lk, "switch-again").unwrap();
        let j = ActiveJournal::begin(&p, &lock, journal(b.id())).unwrap();
        b.write_keychain(CRED, "me", &s("C")).unwrap();
        let r = j.abort(&p, &store, &lk, &allow).unwrap();
        assert!(!r.state_uncertain());
        assert_eq!(store.get(CRED, "me").unwrap().unwrap().expose(), b"B");
        assert!(read(&p).unwrap().is_none());
    }

    #[test]
    fn journal_refuses_a_lock_for_another_home() {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let other = CmaLock::acquire(&t.path().join("other.lock")).unwrap();
        let err = ActiveJournal::begin(&p, &other, journal("20260101T000000Z-switch")).unwrap_err();
        assert_eq!(err.code(), "invalid");
        assert!(resolve(&p, &other).is_err());
    }

    #[test]
    fn a_both_owner_counts_as_dead_only_when_definitely_gone() {
        use crate::procs::ProcStart;
        let mut r = BothRecord::new(None, "k".into());
        r.owner_pid = 4242;
        r.owner_start = Some("Wed Oct 28 10:00:00 2026".into());
        // `ps` failed: could not check, so alive.
        assert!(r.owner_alive_with(&|_| ProcStart::Unknown));
        // ESRCH / nothing listed: dead.
        assert!(!r.owner_alive_with(&|_| ProcStart::Gone));
        // Same start: alive; another start (pid reused): dead.
        assert!(r.owner_alive_with(&|_| ProcStart::Started("Wed Oct 28 10:00:00 2026".into())));
        assert!(!r.owner_alive_with(&|_| ProcStart::Started("Thu Oct 29 09:00:00 2026".into())));
        // Start never captured: cannot compare, so alive while the pid runs.
        r.owner_start = None;
        assert!(r.owner_alive_with(&|_| ProcStart::Started("x".into())));
        // This process, probed for real.
        let me = BothRecord::new(None, "k".into());
        assert!(me.owner_alive());
    }

    #[test]
    fn journal_unknown_fields_and_mode() {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let lock = CmaLock::acquire(&p.lock_file()).unwrap();
        let mut jj = journal("20260101T000000Z-switch");
        jj.extra.insert("future".into(), json!(1));
        let mut j = ActiveJournal::begin(&p, &lock, jj.clone()).unwrap();
        j.step("one").unwrap();
        let back = read(&p).unwrap().unwrap();
        assert_eq!(back.extra["future"], 1);
        assert_eq!(back.steps_done, vec!["one"]);
        assert_eq!(
            fsutil::existing_mode(&p.journal_file()).unwrap(),
            Some(0o600)
        );
    }
}
