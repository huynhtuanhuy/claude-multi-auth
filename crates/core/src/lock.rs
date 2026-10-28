//! Locks: cma's own process lock and Claude Code's `.storage-write` lock.
//!
//! # Lock order
//!
//! Always acquire in this order, and release in reverse:
//!
//! 1. the cma lock ([`CmaLock`], `<CMA_HOME>/.lock`);
//! 2. a per-account lock ([`AccountLock`], `<CMA_HOME>/locks/<hash>.lock`),
//!    at most one per thread. It serializes everything that reads a stored
//!    credential in order to use or replace its refresh token: a token
//!    refresh holds it across read → POST → write (without the cma lock, so
//!    network calls never block other commands), and a switch takes the
//!    target's lock (inside the cma lock) before reading its credential.
//!    A refresher releases it before taking the cma lock for its registry
//!    write;
//! 3. Claude Code's `.storage-write` lock ([`StorageWriteLock`]) — last and
//!    briefest.
//!
//! `.storage-write` is held only around the read-check-write of the live
//! `Claude Code-credentials` item. It is never held across a network call
//! (token refresh, usage fetch) or across a Keychain read that could show a
//! prompt: read the item once *before* taking the lock so any prompt happens
//! then. Claude Code gives up on the lock after about 7.5 s
//! (100+200+400+800+6×1000 ms) and may then take a plaintext fallback path,
//! so holding it long is harmful.
//!
//! Debug builds assert the order on each thread: taking the cma lock, or a
//! second `.storage-write` lock, while this thread holds `.storage-write`
//! panics; so does taking the cma lock or a second per-account lock while
//! this thread holds a per-account lock, or a per-account lock while it
//! holds `.storage-write`. [`StorageWriteLock`] and [`AccountLock`] are
//! `!Send`, so the guards are released on the thread that took them and the
//! per-thread check stays exact.
//!
//! # `.storage-write` takeover
//!
//! Follows proper-lockfile (Claude Code 2.1.310): atomic `mkdir`, stale after
//! 15 s by mtime, mtime refreshed while held. The holder remembers the
//! `(dev, ino, mtime)` it last saw after its own update. On every refresh,
//! on [`StorageWriteLock::is_compromised`] and before release it compares the
//! directory against that stamp; a mismatch (the directory was removed and
//! re-created by someone who judged it stale), or no successful refresh
//! within `stale` (e.g. the process was suspended), marks the lock
//! compromised, and a compromised lock is never `rmdir`ed.
//!
//! A contender that finds a stale lock re-stats it immediately before
//! removing it and removes it only if the stamp is unchanged. A residual race
//! remains, as in proper-lockfile itself: between that re-stat and the
//! `rmdir`, another contender can remove the stale lock and create its own,
//! which this `rmdir` then removes. Both would then believe they hold the
//! lock. The window is a few microseconds and needs two contenders racing
//! over a lock that is already stale; it cannot be closed while staying
//! interoperable with proper-lockfile's `mkdir`/`rmdir` protocol.

use std::cell::Cell;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crate::error::{Error, Result};
use crate::paths::Paths;

pub const CMA_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(50);

thread_local! {
    /// Number of `.storage-write` locks this thread holds (lock-order check).
    static STORAGE_HELD: Cell<u32> = const { Cell::new(0) };
    /// Number of per-account locks this thread holds (lock-order check).
    static ACCOUNT_HELD: Cell<u32> = const { Cell::new(0) };
    /// Number of cma locks this thread holds.
    static CMA_HELD: Cell<u32> = const { Cell::new(0) };
    /// Called by [`AccountLock::acquire`] on this thread when the account
    /// lock is busy, with the account key, before it waits.
    static ACCOUNT_WAIT_NOTIFIER: std::cell::RefCell<Option<WaitNotifier>> =
        const { std::cell::RefCell::new(None) };
}

/// Called with the account key when an account lock is busy.
pub type WaitNotifier = Box<dyn Fn(&str)>;

/// Set (or clear) what [`AccountLock::acquire`] calls on this thread when
/// an account lock is busy (another process is refreshing that account's
/// token), so a front end can say what it waits for instead of waiting
/// silently for up to [`ACCOUNT_LOCK_TIMEOUT`]. Per thread: worker threads
/// (usage fetches) keep waiting silently.
pub fn set_account_wait_notifier(f: Option<WaitNotifier>) {
    ACCOUNT_WAIT_NOTIFIER.with(|n| *n.borrow_mut() = f);
}

fn notify_account_wait(key: &str) {
    ACCOUNT_WAIT_NOTIFIER.with(|n| {
        if let Some(f) = n.borrow().as_ref() {
            f(key);
        }
    });
}

/// Whether the current thread holds a [`CmaLock`].
pub fn cma_lock_held_here() -> bool {
    CMA_HELD.with(|c| c.get() > 0)
}

/// Whether the current thread holds a [`StorageWriteLock`].
pub fn storage_lock_held_here() -> bool {
    STORAGE_HELD.with(|c| c.get() > 0)
}

/// Whether the current thread holds an [`AccountLock`].
pub fn account_lock_held_here() -> bool {
    ACCOUNT_HELD.with(|c| c.get() > 0)
}

/// Open `path` (0600, no symlink) and take an exclusive `flock` on it,
/// polling until `timeout`; `what` names it in [`Error::Locked`].
fn flock_timeout(path: &Path, timeout: Duration, what: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    return Err(Error::Locked { what: what.into() });
                }
                std::thread::sleep(POLL);
            }
            Err(TryLockError::Error(e)) => return Err(Error::io(path, e)),
        }
    }
}

/// Exclusive lock on `<CMA_HOME>/.lock`, released on drop. `!Send`, so
/// [`cma_lock_held_here`] stays exact.
#[derive(Debug)]
pub struct CmaLock {
    _file: File,
    path: PathBuf,
    _not_send: PhantomData<*const ()>,
}

impl CmaLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        Self::acquire_timeout(path, CMA_LOCK_TIMEOUT)
    }

    pub fn acquire_timeout(path: &Path, timeout: Duration) -> Result<Self> {
        debug_assert!(
            !storage_lock_held_here(),
            "lock order: the cma lock must be taken before .storage-write"
        );
        debug_assert!(
            !account_lock_held_here(),
            "lock order: the cma lock must be taken before a per-account lock"
        );
        debug_assert!(
            !cma_lock_held_here(),
            "the cma lock is already held by this thread (it would wait for itself)"
        );
        let file = flock_timeout(path, timeout, "cma")?;
        CMA_HELD.with(|c| c.set(c.get() + 1));
        Ok(CmaLock {
            _file: file,
            path: path.to_path_buf(),
            _not_send: PhantomData,
        })
    }

    /// The lock file this guard holds.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Refuse a guard that is not for `paths`' lock file.
    pub fn check_for(&self, paths: &Paths) -> Result<()> {
        if self.path == paths.lock_file() {
            Ok(())
        } else {
            Err(Error::Invalid {
                what: "cma lock (not this CMA_HOME's lock file)",
                value: self.path.display().to_string(),
            })
        }
    }
}

impl Drop for CmaLock {
    fn drop(&mut self) {
        CMA_HELD.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

/// Room for a refresh's Keychain calls on top of its HTTP requests.
const ACCOUNT_LOCK_MARGIN_SECS: u64 = 10;

/// How long [`AccountLock::acquire`] waits: longer than the slowest
/// possible refresh ([`crate::refresh::REFRESH_MAX_REQUESTS`] requests of
/// at most [`crate::http::TIMEOUT`] each, plus a margin), so a waiting
/// refresher, switch, login, import, export or remove gets the lock instead
/// of failing. A switch waits for it while holding the cma lock, so other
/// commands (10 s cma-lock wait) can fail `locked` during a slow refresh.
pub const ACCOUNT_LOCK_TIMEOUT: Duration = Duration::from_secs(
    crate::http::TIMEOUT.as_secs() * crate::refresh::REFRESH_MAX_REQUESTS
        + ACCOUNT_LOCK_MARGIN_SECS,
);

/// Directory of the per-account lock files.
pub fn account_locks_dir(paths: &Paths) -> PathBuf {
    paths.cma_home.join("locks")
}

/// Lock file of an account. The key comes from a user-editable file, so it
/// is hashed rather than used as a file name.
pub fn account_lock_path(paths: &Paths, key: &str) -> PathBuf {
    let h = crate::secret::sha256_hex(key.as_bytes());
    account_locks_dir(paths).join(format!("{}.lock", &h[..16]))
}

/// Exclusive per-account lock (see the module docs for its place in the
/// lock order), released on drop. `!Send`.
#[derive(Debug)]
pub struct AccountLock {
    _file: File,
    key: String,
    _not_send: PhantomData<*const ()>,
}

impl AccountLock {
    /// Take the lock of account `key`, waiting up to
    /// [`ACCOUNT_LOCK_TIMEOUT`]. May be called with or without the cma lock
    /// held, never while holding `.storage-write` or another account lock.
    /// When the lock is busy, the notifier set with
    /// [`set_account_wait_notifier`] (if any) is called first.
    pub fn acquire(paths: &Paths, key: &str) -> Result<Self> {
        Self::acquire_notify(paths, key, || notify_account_wait(key))
    }

    /// [`AccountLock::acquire`], calling `on_wait` once when the lock is
    /// busy (another process is refreshing this account), so a caller can
    /// say what it is waiting for before the wait of up to
    /// [`ACCOUNT_LOCK_TIMEOUT`].
    pub fn acquire_notify(paths: &Paths, key: &str, on_wait: impl FnOnce()) -> Result<Self> {
        match Self::acquire_timeout(paths, key, Duration::ZERO) {
            Err(Error::Locked { .. }) => {
                on_wait();
                Self::acquire_timeout(paths, key, ACCOUNT_LOCK_TIMEOUT)
            }
            r => r,
        }
    }

    pub fn acquire_timeout(paths: &Paths, key: &str, timeout: Duration) -> Result<Self> {
        debug_assert!(
            !storage_lock_held_here(),
            "lock order: a per-account lock must be taken before .storage-write"
        );
        debug_assert!(
            !account_lock_held_here(),
            "lock order: at most one per-account lock per thread"
        );
        let dir = account_locks_dir(paths);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| Error::io(&dir, e))?;
        let file = flock_timeout(
            &account_lock_path(paths, key),
            timeout,
            &format!("account {key}"),
        )?;
        ACCOUNT_HELD.with(|c| c.set(c.get() + 1));
        Ok(AccountLock {
            _file: file,
            key: key.to_string(),
            _not_send: PhantomData,
        })
    }

    /// The account this guard locks.
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl Drop for AccountLock {
    fn drop(&mut self) {
        ACCOUNT_HELD.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

/// proper-lockfile parameters used by Claude Code 2.1.310 for
/// `<dir>/.storage-write`.
#[derive(Debug, Clone, Copy)]
pub struct StorageLockOptions {
    pub retries: u32,
    pub min_timeout: Duration,
    pub max_timeout: Duration,
    /// A lock directory whose mtime is older than this is stale.
    pub stale: Duration,
    /// How often the holder refreshes the mtime (proper-lockfile: stale / 2).
    pub update: Duration,
}

impl Default for StorageLockOptions {
    fn default() -> Self {
        StorageLockOptions {
            retries: 10,
            min_timeout: Duration::from_millis(100),
            max_timeout: Duration::from_millis(1000),
            stale: Duration::from_secs(15),
            update: Duration::from_millis(7500),
        }
    }
}

impl StorageLockOptions {
    /// Delay before retry `n` (0-based): exponential, factor 2, capped.
    fn backoff(&self, n: u32) -> Duration {
        let ms = self.min_timeout.as_millis() as u64 * 2u64.saturating_pow(n);
        Duration::from_millis(ms).min(self.max_timeout)
    }
}

/// Path of the lock directory for a secure-storage dir.
pub fn storage_write_lock_path(dir: &Path) -> PathBuf {
    dir.join(".storage-write.lock")
}

/// A held `.storage-write` lock, as seen by code that writes the live item.
pub trait StorageGuard: std::fmt::Debug {
    /// True when exclusivity can no longer be trusted. Callers check this
    /// right before the protected write and refuse when it is set.
    fn is_compromised(&self) -> bool;
}

/// Something that can take Claude Code's `.storage-write` lock. Injected into
/// backup and rollback so tests can substitute a fake.
pub trait StorageLockAcquirer {
    fn acquire(&self) -> Result<Box<dyn StorageGuard>>;
}

/// The real acquirer for one secure-storage dir.
#[derive(Debug, Clone)]
pub struct ClaudeStorageLock {
    dir: PathBuf,
    opts: StorageLockOptions,
}

impl ClaudeStorageLock {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        ClaudeStorageLock {
            dir: dir.into(),
            opts: StorageLockOptions::default(),
        }
    }

    /// For [`Paths::secure_storage_dir`].
    pub fn for_paths(paths: &Paths) -> Self {
        Self::new(paths.secure_storage_dir.clone())
    }

    pub fn with_options(mut self, opts: StorageLockOptions) -> Self {
        self.opts = opts;
        self
    }
}

impl StorageLockAcquirer for ClaudeStorageLock {
    fn acquire(&self) -> Result<Box<dyn StorageGuard>> {
        Ok(Box::new(StorageWriteLock::acquire_with(
            &self.dir, self.opts,
        )?))
    }
}

/// Identity of the lock directory: a re-created directory differs in inode
/// and (normally) mtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    mtime: SystemTime,
}

fn stamp(path: &Path) -> std::io::Result<Stamp> {
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_dir() {
        return Err(std::io::Error::new(ErrorKind::NotADirectory, "not a dir"));
    }
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        mtime: m.modified()?,
    })
}

fn age(t: SystemTime) -> Duration {
    SystemTime::now().duration_since(t).unwrap_or_default()
}

fn touch_dir(path: &Path, when: SystemTime) -> std::io::Result<()> {
    File::open(path)?.set_modified(when)
}

/// Remove a stale lock only if it still has the stamp that was judged stale.
/// Returns whether it was removed by us.
fn remove_if_unchanged(path: &Path, seen: Stamp) -> std::io::Result<bool> {
    match stamp(path) {
        Ok(now) if now == seen => match std::fs::remove_dir(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        },
        Ok(_) => Ok(false),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
struct Holder {
    /// Stamp observed right after our last successful update.
    last: Stamp,
    /// Wall-clock time of that update (wall clock, so a suspended process
    /// sees the gap on resume).
    updated_at: SystemTime,
}

#[derive(Debug)]
struct Shared {
    path: PathBuf,
    stale: Duration,
    holder: Mutex<Holder>,
    compromised: AtomicBool,
}

impl Shared {
    /// Compare the directory with our stamp; mark compromised on mismatch.
    fn verify(&self, h: &Holder) -> bool {
        if self.compromised.load(Ordering::SeqCst) {
            return false;
        }
        let ok = age(h.updated_at) <= self.stale && stamp(&self.path).is_ok_and(|s| s == h.last);
        if !ok {
            self.compromised.store(true, Ordering::SeqCst);
        }
        ok
    }

    /// One refresh: verify, then set the mtime to now and record the stamp.
    fn tick(&self) -> bool {
        let mut h = self.holder.lock().unwrap_or_else(|e| e.into_inner());
        if !self.verify(&h) {
            return false;
        }
        let now = SystemTime::now();
        match touch_dir(&self.path, now).and_then(|()| stamp(&self.path)) {
            Ok(s) => {
                h.last = s;
                h.updated_at = now;
                true
            }
            Err(_) => {
                self.compromised.store(true, Ordering::SeqCst);
                false
            }
        }
    }

    fn check(&self) -> bool {
        let h = self.holder.lock().unwrap_or_else(|e| e.into_inner());
        self.verify(&h)
    }
}

/// Claude Code's `.storage-write` lock, held as the directory
/// `<dir>/.storage-write.lock` (atomic `mkdir`). The mtime is refreshed while
/// held; the directory is removed on drop unless the lock was compromised.
#[derive(Debug)]
pub struct StorageWriteLock {
    shared: Arc<Shared>,
    stop: Option<Sender<()>>,
    refresher: Option<JoinHandle<()>>,
    /// `!Send`: released on the thread that took it (lock-order check).
    _not_send: PhantomData<*const ()>,
}

impl StorageWriteLock {
    /// Acquire the lock for secure-storage dir `dir` (see
    /// [`crate::paths::Paths::secure_storage_dir`]).
    pub fn acquire(dir: &Path) -> Result<Self> {
        Self::acquire_with(dir, StorageLockOptions::default())
    }

    pub fn acquire_with(dir: &Path, opts: StorageLockOptions) -> Result<Self> {
        debug_assert!(
            !storage_lock_held_here(),
            "lock order: .storage-write is not re-entrant"
        );
        let path = storage_write_lock_path(dir);
        let mut attempt = 0u32;
        loop {
            match std::fs::create_dir(&path) {
                Ok(()) => return Self::held(path, opts),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    match stamp(&path) {
                        Ok(seen) if age(seen.mtime) > opts.stale => {
                            // Stale: re-check right before removing, then retry
                            // at once (proper-lockfile does not back off here).
                            remove_if_unchanged(&path, seen).map_err(|e| Error::io(&path, e))?;
                            continue;
                        }
                        Ok(_) => {}
                        // Released between mkdir and stat: retry at once.
                        Err(e) if e.kind() == ErrorKind::NotFound => continue,
                        Err(e) => return Err(Error::io(&path, e)),
                    }
                    if attempt >= opts.retries {
                        return Err(Error::Locked {
                            what: format!("Claude Code storage ({})", path.display()),
                        });
                    }
                    std::thread::sleep(opts.backoff(attempt));
                    attempt += 1;
                }
                Err(e) => return Err(Error::io(&path, e)),
            }
        }
    }

    fn held(path: PathBuf, opts: StorageLockOptions) -> Result<Self> {
        let last = match stamp(&path) {
            Ok(s) => s,
            Err(e) => {
                // We just created it: remove it so Claude Code does not wait
                // 15 s for it to go stale (longer than its retry budget).
                let _ = std::fs::remove_dir(&path);
                return Err(Error::io(&path, e));
            }
        };
        STORAGE_HELD.with(|c| c.set(c.get() + 1));
        let shared = Arc::new(Shared {
            path,
            stale: opts.stale,
            holder: Mutex::new(Holder {
                last,
                updated_at: SystemTime::now(),
            }),
            compromised: AtomicBool::new(false),
        });
        let (tx, rx) = mpsc::channel::<()>();
        let s = shared.clone();
        let refresher = std::thread::spawn(move || {
            while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(opts.update) {
                if !s.tick() {
                    return;
                }
            }
        });
        Ok(StorageWriteLock {
            shared,
            stop: Some(tx),
            refresher: Some(refresher),
            _not_send: PhantomData,
        })
    }

    pub fn path(&self) -> &Path {
        &self.shared.path
    }

    /// True when the lock directory is no longer the one we hold (removed,
    /// or removed and re-created by another process), or when no refresh
    /// succeeded within `stale`. Checks the directory now, not only at the
    /// last refresh. The caller must not trust its exclusivity.
    pub fn is_compromised(&self) -> bool {
        !self.shared.check()
    }

    /// Run one refresh now (what the background thread does each `update`).
    #[cfg(test)]
    fn refresh_now(&self) -> bool {
        self.shared.tick()
    }

    /// Pretend the last successful refresh happened `by` earlier.
    #[cfg(test)]
    fn backdate_update(&self, by: Duration) {
        let mut h = self.shared.holder.lock().unwrap();
        h.updated_at -= by;
    }
}

impl StorageGuard for StorageWriteLock {
    fn is_compromised(&self) -> bool {
        StorageWriteLock::is_compromised(self)
    }
}

impl Drop for StorageWriteLock {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(h) = self.refresher.take() {
            let _ = h.join();
        }
        // Do not remove a directory that another process now owns.
        if self.shared.check() {
            let _ = std::fs::remove_dir(&self.shared.path);
        }
        STORAGE_HELD.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::time::Instant;

    /// Fake acquirer: counts acquisitions, can fail, hand out a compromised
    /// guard, or run a hook just before the guard is returned (models
    /// another writer changing the item between cma's check and its lock).
    #[derive(Default)]
    pub struct FakeLocker {
        pub acquired: Cell<u32>,
        pub fail: bool,
        pub compromised: bool,
        /// The guard reports compromised from its Nth check on (0 = never),
        /// modelling a lock lost while held.
        pub lost_at_check: u32,
        pub on_acquire: RefCell<Option<Box<dyn FnMut()>>>,
    }

    #[derive(Debug)]
    struct FakeGuard {
        compromised: bool,
        lost_at_check: u32,
        checks: Cell<u32>,
    }

    impl StorageGuard for FakeGuard {
        fn is_compromised(&self) -> bool {
            self.checks.set(self.checks.get() + 1);
            self.compromised || (self.lost_at_check > 0 && self.checks.get() >= self.lost_at_check)
        }
    }

    impl StorageLockAcquirer for FakeLocker {
        fn acquire(&self) -> Result<Box<dyn StorageGuard>> {
            self.acquired.set(self.acquired.get() + 1);
            if self.fail {
                return Err(Error::Locked {
                    what: "fake storage".into(),
                });
            }
            if let Some(f) = self.on_acquire.borrow_mut().as_mut() {
                f();
            }
            Ok(Box::new(FakeGuard {
                compromised: self.compromised,
                lost_at_check: self.lost_at_check,
                checks: Cell::new(0),
            }))
        }
    }

    fn fast() -> StorageLockOptions {
        StorageLockOptions {
            retries: 3,
            min_timeout: Duration::from_millis(10),
            max_timeout: Duration::from_millis(20),
            stale: Duration::from_secs(5),
            // Long: tests drive refreshes with `refresh_now()`.
            update: Duration::from_secs(60),
        }
    }

    #[test]
    fn backoff_matches_proper_lockfile_defaults() {
        let o = StorageLockOptions::default();
        let d: Vec<u64> = (0..10).map(|n| o.backoff(n).as_millis() as u64).collect();
        assert_eq!(d, [100, 200, 400, 800, 1000, 1000, 1000, 1000, 1000, 1000]);
        assert_eq!(o.stale, Duration::from_secs(15));
    }

    #[test]
    fn cma_lock_serializes_two_threads() {
        let t = tempfile::tempdir().unwrap();
        let path = Arc::new(t.path().join(".lock"));
        let inside = Arc::new(AtomicBool::new(false));
        let log = Arc::new(Mutex::new(Vec::new()));
        let handles: Vec<_> = (0..2)
            .map(|i| {
                let (path, inside, log) = (path.clone(), inside.clone(), log.clone());
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        let _g = CmaLock::acquire(&path).unwrap();
                        assert!(!inside.swap(true, Ordering::SeqCst), "two holders at once");
                        log.lock().unwrap().push(i);
                        std::thread::sleep(Duration::from_millis(5));
                        inside.store(false, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(log.lock().unwrap().len(), 10);
    }

    #[test]
    fn cma_lock_times_out() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join(".lock");
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        std::thread::scope(|sc| {
            let p = &p;
            sc.spawn(move || {
                let _held = CmaLock::acquire(p).unwrap();
                held_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            });
            held_rx.recv().unwrap();
            let start = Instant::now();
            let err = CmaLock::acquire_timeout(p, Duration::from_millis(150)).unwrap_err();
            assert!(matches!(err, Error::Locked { .. }));
            assert!(start.elapsed() >= Duration::from_millis(150));
            done_tx.send(()).unwrap();
        });
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "already held by this thread")]
    fn cma_lock_taken_twice_on_one_thread_fails_at_once() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join(".lock");
        let _held = CmaLock::acquire(&p).unwrap();
        let _again = CmaLock::acquire(&p);
    }

    #[test]
    fn account_lock_notice_fires_only_when_busy() {
        let (_t, paths) = temp_paths();
        let mut fired = false;
        drop(AccountLock::acquire_notify(&paths, "A::oA", || fired = true).unwrap());
        assert!(!fired);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        std::thread::scope(|sc| {
            let paths = &paths;
            sc.spawn(move || {
                let g = AccountLock::acquire(paths, "A::oA").unwrap();
                held_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(150));
                drop(g);
            });
            held_rx.recv().unwrap();
            let mut fired = 0;
            let _g = AccountLock::acquire_notify(paths, "A::oA", || fired += 1).unwrap();
            assert_eq!(fired, 1);
        });
    }

    #[test]
    fn acquire_calls_this_threads_wait_notifier_when_busy() {
        let (_t, paths) = temp_paths();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let sink = seen.clone();
        set_account_wait_notifier(Some(Box::new(move |k| sink.borrow_mut().push(k.into()))));
        drop(AccountLock::acquire(&paths, "A::oA").unwrap());
        assert!(seen.borrow().is_empty(), "free lock: no notice");
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        std::thread::scope(|sc| {
            let paths = &paths;
            sc.spawn(move || {
                // Another thread has no notifier: its own waits stay silent.
                let g = AccountLock::acquire(paths, "A::oA").unwrap();
                held_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(150));
                drop(g);
            });
            held_rx.recv().unwrap();
            let _g = AccountLock::acquire(paths, "A::oA").unwrap();
        });
        set_account_wait_notifier(None);
        assert_eq!(*seen.borrow(), vec!["A::oA".to_string()]);
    }

    #[test]
    fn storage_lock_mkdir_and_rmdir_on_release() {
        let t = tempfile::tempdir().unwrap();
        let lock_dir = storage_write_lock_path(t.path());
        {
            let g = StorageWriteLock::acquire_with(t.path(), fast()).unwrap();
            assert!(lock_dir.is_dir());
            assert_eq!(g.path(), lock_dir);
            assert!(storage_lock_held_here());
        }
        assert!(!lock_dir.exists());
        assert!(!storage_lock_held_here());
    }

    #[test]
    fn storage_lock_contention_gives_locked() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().to_path_buf();
        let (tx, rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        // Hold it on another thread (the guard is per-thread).
        let holder = std::thread::spawn(move || {
            let _held = StorageWriteLock::acquire_with(&dir, fast()).unwrap();
            tx.send(()).unwrap();
            done_rx.recv().unwrap();
        });
        rx.recv().unwrap();
        let err = StorageWriteLock::acquire_with(t.path(), fast()).unwrap_err();
        assert!(matches!(err, Error::Locked { .. }));
        // The holder's directory is untouched by the loser.
        assert!(storage_write_lock_path(t.path()).is_dir());
        done_tx.send(()).unwrap();
        holder.join().unwrap();
    }

    #[test]
    fn storage_lock_waits_for_release() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().to_path_buf();
        let (tx, rx) = mpsc::channel();
        let releaser = std::thread::spawn(move || {
            let held = StorageWriteLock::acquire_with(&dir, fast()).unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(30));
            drop(held);
        });
        rx.recv().unwrap();
        // Up to ~200 × 20 ms of retries: generous against a 30 ms hold.
        let opts = StorageLockOptions {
            retries: 200,
            ..fast()
        };
        let g = StorageWriteLock::acquire_with(t.path(), opts).unwrap();
        releaser.join().unwrap();
        assert!(g.path().is_dir());
        assert!(!g.is_compromised());
    }

    #[test]
    fn stale_lock_is_taken_over() {
        let t = tempfile::tempdir().unwrap();
        let lock_dir = storage_write_lock_path(t.path());
        std::fs::create_dir(&lock_dir).unwrap();
        // Default options: stale after 15 s. Make it 20 s old.
        touch_dir(&lock_dir, SystemTime::now() - Duration::from_secs(20)).unwrap();
        let start = Instant::now();
        let g = StorageWriteLock::acquire(t.path()).unwrap();
        // No backoff on stale; the bound is generous for a loaded machine.
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "no backoff on stale"
        );
        assert!(
            age(std::fs::metadata(g.path()).unwrap().modified().unwrap()) < Duration::from_secs(5)
        );
        assert!(!g.is_compromised());
    }

    #[test]
    fn fresh_lock_is_not_taken_over() {
        let t = tempfile::tempdir().unwrap();
        let lock_dir = storage_write_lock_path(t.path());
        std::fs::create_dir(&lock_dir).unwrap();
        touch_dir(&lock_dir, SystemTime::now() - Duration::from_secs(10)).unwrap();
        let opts = StorageLockOptions {
            stale: Duration::from_secs(15),
            ..fast()
        };
        assert!(matches!(
            StorageWriteLock::acquire_with(t.path(), opts),
            Err(Error::Locked { .. })
        ));
        assert!(lock_dir.is_dir());
    }

    #[test]
    fn refresh_updates_mtime_and_keeps_ownership() {
        let t = tempfile::tempdir().unwrap();
        let g = StorageWriteLock::acquire_with(t.path(), fast()).unwrap();
        let first = std::fs::metadata(g.path()).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(g.refresh_now());
        let second = std::fs::metadata(g.path()).unwrap().modified().unwrap();
        assert!(second > first, "mtime not refreshed");
        assert!(!g.is_compromised());
        assert!(g.refresh_now(), "a second refresh still sees our own stamp");
    }

    #[test]
    fn background_refresh_runs() {
        let t = tempfile::tempdir().unwrap();
        let opts = StorageLockOptions {
            update: Duration::from_millis(20),
            ..fast()
        };
        let g = StorageWriteLock::acquire_with(t.path(), opts).unwrap();
        let first = std::fs::metadata(g.path()).unwrap().modified().unwrap();
        // Poll with a generous deadline instead of sleeping across one tick.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let now = std::fs::metadata(g.path()).unwrap().modified().unwrap();
            if now > first {
                break;
            }
            assert!(Instant::now() < deadline, "background refresh never ran");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!g.is_compromised());
    }

    #[test]
    fn takeover_within_one_interval_is_detected_and_not_removed() {
        let t = tempfile::tempdir().unwrap();
        // `update` is 60 s: no background refresh happens during the test.
        let g = StorageWriteLock::acquire_with(t.path(), fast()).unwrap();
        // Another process judges it stale, removes it and takes it over.
        std::fs::remove_dir(g.path()).unwrap();
        std::fs::create_dir(g.path()).unwrap();
        touch_dir(g.path(), SystemTime::now() + Duration::from_secs(2)).unwrap();
        assert!(g.is_compromised(), "takeover detected without a tick");
        assert!(
            !g.refresh_now(),
            "refresh must not touch the new owner's dir"
        );
        let p = g.path().to_path_buf();
        drop(g);
        assert!(
            p.is_dir(),
            "released lock must not remove the new owner's dir"
        );
    }

    #[test]
    fn foreign_mtime_change_is_detected() {
        let t = tempfile::tempdir().unwrap();
        let g = StorageWriteLock::acquire_with(t.path(), fast()).unwrap();
        touch_dir(g.path(), SystemTime::now() + Duration::from_secs(3)).unwrap();
        assert!(g.is_compromised());
        let p = g.path().to_path_buf();
        drop(g);
        assert!(p.is_dir());
    }

    #[test]
    fn missed_refresh_beyond_stale_is_compromised() {
        let t = tempfile::tempdir().unwrap();
        let g = StorageWriteLock::acquire_with(t.path(), fast()).unwrap();
        assert!(!g.is_compromised());
        g.backdate_update(Duration::from_secs(6));
        assert!(g.is_compromised(), "suspended longer than stale");
        let p = g.path().to_path_buf();
        drop(g);
        assert!(p.is_dir(), "not removed once compromised");
    }

    #[test]
    fn stale_removal_rechecks_the_stamp() {
        let t = tempfile::tempdir().unwrap();
        let p = storage_write_lock_path(t.path());
        std::fs::create_dir(&p).unwrap();
        touch_dir(&p, SystemTime::now() - Duration::from_secs(60)).unwrap();
        let seen = stamp(&p).unwrap();
        // Someone else replaced the stale lock with a fresh one meanwhile.
        std::fs::remove_dir(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        touch_dir(&p, SystemTime::now() + Duration::from_secs(1)).unwrap();
        assert!(!remove_if_unchanged(&p, seen).unwrap());
        assert!(p.is_dir(), "fresh lock left alone");
        // Unchanged stale lock is removed.
        let now = stamp(&p).unwrap();
        assert!(remove_if_unchanged(&p, now).unwrap());
        assert!(!p.exists());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "lock order")]
    fn cma_lock_after_storage_lock_panics_in_debug() {
        let t = tempfile::tempdir().unwrap();
        let _s = StorageWriteLock::acquire_with(t.path(), fast()).unwrap();
        let _c = CmaLock::acquire(&t.path().join(".lock"));
    }

    #[test]
    fn missing_parent_dir_is_io_error() {
        let t = tempfile::tempdir().unwrap();
        let err = StorageWriteLock::acquire_with(&t.path().join("nope"), fast()).unwrap_err();
        assert!(matches!(err, Error::Io { .. }));
    }

    #[test]
    fn real_acquirer_returns_guard() {
        let t = tempfile::tempdir().unwrap();
        let a = ClaudeStorageLock::new(t.path()).with_options(fast());
        let g = a.acquire().unwrap();
        assert!(!g.is_compromised());
        assert!(storage_write_lock_path(t.path()).is_dir());
        drop(g);
        assert!(!storage_write_lock_path(t.path()).exists());
    }

    fn temp_paths() -> (tempfile::TempDir, Paths) {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let env = crate::paths::MapEnv::new([
            ("HOME", home.to_str().unwrap()),
            ("CMA_HOME", home.join("cma").to_str().unwrap()),
            ("CMA_ALLOW_HOME_OVERRIDE", "1"),
        ]);
        let paths = Paths::from_env(&env).unwrap();
        paths.ensure_cma_home().unwrap();
        (t, paths)
    }

    #[test]
    fn account_lock_excludes_per_key_only() {
        let (_t, paths) = temp_paths();
        let a = AccountLock::acquire(&paths, "A::oA").unwrap();
        assert_eq!(a.key(), "A::oA");
        let p = paths.clone();
        // Another thread: same key times out, another key is free.
        std::thread::spawn(move || {
            let same = AccountLock::acquire_timeout(&p, "A::oA", Duration::from_millis(120));
            assert!(matches!(same, Err(Error::Locked { what }) if what == "account A::oA"));
            AccountLock::acquire_timeout(&p, "B::oB", Duration::from_millis(120)).unwrap();
        })
        .join()
        .unwrap();
        drop(a);
        let p = paths.clone();
        std::thread::spawn(move || {
            AccountLock::acquire_timeout(&p, "A::oA", Duration::from_millis(120)).unwrap();
        })
        .join()
        .unwrap();
        let f = account_lock_path(&paths, "A::oA");
        assert!(f.starts_with(account_locks_dir(&paths)));
        assert!(!f.to_string_lossy().contains("::"));
        assert_eq!(crate::fsutil::existing_mode(&f).unwrap(), Some(0o600));
    }

    #[test]
    fn account_lock_inside_cma_lock_then_storage_lock_is_in_order() {
        let (_t, paths) = temp_paths();
        let _c = CmaLock::acquire(&paths.lock_file()).unwrap();
        let _a = AccountLock::acquire(&paths, "A::oA").unwrap();
        assert!(account_lock_held_here());
        let _s = StorageWriteLock::acquire_with(&paths.cma_home, fast()).unwrap();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "lock order")]
    fn cma_lock_after_account_lock_panics_in_debug() {
        let (_t, paths) = temp_paths();
        let _a = AccountLock::acquire(&paths, "A::oA").unwrap();
        let _c = CmaLock::acquire(&paths.lock_file());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "lock order")]
    fn second_account_lock_panics_in_debug() {
        let (_t, paths) = temp_paths();
        let _a = AccountLock::acquire(&paths, "A::oA").unwrap();
        let _b = AccountLock::acquire(&paths, "B::oB");
    }
}
