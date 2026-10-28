//! Backups taken before every mutation, rollback, scoped user restore, clean.
//!
//! Secret pre-images never touch disk: Keychain values (and secret JSON keys)
//! are copied into Keychain service [`BACKUP_SERVICE`], account `<id>/<n>`.
//! `manifest.json` holds only metadata, hashes and non-secret values.
//!
//! The manifest is the write-ahead log. Each entry, including the name of
//! its Keychain backup item, is saved before that item is created, and the
//! hash of every value cma is about to write is saved before the write. A
//! crash at any point therefore leaves either nothing or a manifest entry
//! that names everything that exists.
//!
//! Restoring an entry is only allowed while its current value still equals
//! one of the values cma wrote; a value equal to the pre-image needs nothing;
//! anything else was changed by another writer and is left alone (rollback
//! reports `state_uncertain`; user restore refuses unless forced). For the
//! live `Claude Code-credentials` item that check and the write happen inside
//! Claude Code's `.storage-write` lock (see [`crate::lock`] for the order).

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::fsutil;
use crate::journal::{ActiveJournal, Journal};
use crate::lock::{CmaLock, StorageGuard, StorageLockAcquirer};
use crate::paths::Paths;
use crate::secret::{Secret, SecretStore, sha256_hex};

pub const BACKUP_SERVICE: &str = "claude-multi-auth-backup";
pub const DEFAULT_KEEP: usize = 10;
/// Newest manifest layout this build understands.
pub const MANIFEST_SCHEMA: u32 = 1;
/// Keychain services a manifest may name for restore.
const SERVICE_PREFIXES: [&str; 2] = ["Claude Code-credentials", "claude-multi-auth"];
/// Services Claude Code itself writes under its `.storage-write` lock.
const LIVE_SERVICE_PREFIX: &str = "Claude Code-credentials";

static ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{8}T\d{6}Z-[a-z-]+$").expect("valid regex"));
static COPY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^files/\d+$").expect("valid regex"));
static OP_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z-]+$").expect("valid regex"));

pub fn is_valid_id(id: &str) -> bool {
    ID_RE.is_match(id)
}

/// Whether writes to this Keychain service must hold `.storage-write`.
pub fn needs_storage_lock(service: &str) -> bool {
    service.starts_with(LIVE_SERVICE_PREFIX)
}

fn manifest_schema_v1() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    Keychain {
        service: String,
        account: String,
        existed: bool,
        /// sha256 of the pre-image (`None` when absent).
        sha256: Option<String>,
        /// Account of the pre-image copy in [`BACKUP_SERVICE`]. Saved before
        /// the copy is made, so the item may be absent after a crash.
        backup_account: Option<String>,
        /// sha256 of every value cma wrote to the item during the op, each
        /// recorded before its write; `None` means cma deleted the item.
        #[serde(default)]
        after_sha256: Vec<Option<String>>,
    },
    JsonKeys {
        path: PathBuf,
        keys: Vec<String>,
        file_existed: bool,
        /// Non-secret pre-image values of keys that were present.
        before: Map<String, Value>,
        /// Keys whose pre-image values live in the Keychain backup item.
        #[serde(default)]
        secret_keys: Vec<String>,
        #[serde(default)]
        secret_backup_account: Option<String>,
        /// sha256 of the Keychain backup item's bytes.
        #[serde(default)]
        secret_sha256: Option<String>,
        /// Hash of the `keys` subset before and after cma's write.
        before_sha256: String,
        after_sha256: Option<String>,
    },
    File {
        path: PathBuf,
        sha256_before: Option<String>,
        sha256_after: Option<String>,
        /// cma removed the file (instead of writing `sha256_after`).
        #[serde(default)]
        removes: bool,
        /// Copy of the pre-image, relative to the backup dir.
        copy: Option<String>,
        /// Account of the pre-image in [`BACKUP_SERVICE`], for a file whose
        /// content is secret (never copied to disk). Saved before the copy
        /// is made.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_backup_account: Option<String>,
    },
    Move {
        from: PathBuf,
        to: PathBuf,
        /// Signature of the moved entry at its destination (see
        /// [`tree_sig`]), recorded right after the move. When set, restore
        /// treats a destination whose signature changed as changed by
        /// someone else. `None`: only existence is checked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sig: Option<String>,
        /// Directories cma created for this move (outermost first); rollback
        /// removes them again when they are empty.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        created_dirs: Vec<PathBuf>,
    },
}

impl Entry {
    pub fn label(&self) -> String {
        match self {
            Entry::Keychain {
                service, account, ..
            } => format!("keychain {service}/{account}"),
            Entry::JsonKeys { path, keys, .. } => {
                format!("{} keys {}", path.display(), keys.join(","))
            }
            Entry::File { path, .. } => format!("file {}", path.display()),
            Entry::Move { from, to, .. } => {
                format!("move {} -> {}", from.display(), to.display())
            }
        }
    }

    /// Whether cma recorded a write for this entry.
    fn was_written(&self) -> bool {
        match self {
            Entry::Keychain { after_sha256, .. } => !after_sha256.is_empty(),
            Entry::JsonKeys { after_sha256, .. } => after_sha256.is_some(),
            Entry::File {
                sha256_after,
                removes,
                ..
            } => sha256_after.is_some() || *removes,
            Entry::Move { .. } => true,
        }
    }

    /// Every value cma wrote (`None` = absent).
    fn afters(&self) -> Vec<Option<&str>> {
        match self {
            Entry::Keychain { after_sha256, .. } => {
                after_sha256.iter().map(|a| a.as_deref()).collect()
            }
            Entry::JsonKeys { after_sha256, .. } => {
                after_sha256.iter().map(|a| Some(a.as_str())).collect()
            }
            Entry::File {
                sha256_after,
                removes,
                ..
            } => {
                if *removes {
                    vec![None]
                } else {
                    sha256_after.iter().map(|a| Some(a.as_str())).collect()
                }
            }
            Entry::Move { .. } => Vec::new(),
        }
    }

    /// Keychain backup accounts this entry names.
    fn backup_account(&self) -> Option<&str> {
        match self {
            Entry::Keychain { backup_account, .. } => backup_account.as_deref(),
            Entry::JsonKeys {
                secret_backup_account,
                ..
            }
            | Entry::File {
                secret_backup_account,
                ..
            } => secret_backup_account.as_deref(),
            Entry::Move { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default = "manifest_schema_v1")]
    pub schema_version: u32,
    pub id: String,
    pub op: String,
    pub created_at: i64,
    pub entries: Vec<Entry>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Paths a manifest may touch.
#[derive(Debug, Clone)]
pub struct Allowlist {
    files: Vec<PathBuf>,
    roots: Vec<PathBuf>,
}

/// Canonicalize the longest existing ancestor and append the rest, so paths
/// that do not exist yet still resolve symlinks in their parents.
///
/// This is a path check, not an fd-based one: a same-uid process could swap
/// a directory for a symlink after the check. That attacker is outside the
/// threat model; the final component is still opened with `O_NOFOLLOW`.
fn canonicalize_lenient(path: &Path) -> Result<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut rest = Vec::new();
    loop {
        match std::fs::canonicalize(&existing) {
            Ok(c) => {
                let mut out = c;
                for part in rest.iter().rev() {
                    out.push(part);
                }
                return Ok(out);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = existing
                    .file_name()
                    .ok_or_else(|| Error::io(path, e))?
                    .to_os_string();
                rest.push(name);
                if !existing.pop() {
                    return Ok(path.to_path_buf());
                }
            }
            Err(e) => return Err(Error::io(path, e)),
        }
    }
}

impl Allowlist {
    /// `.claude.json`, Desktop's `config.json` and identity paths (from
    /// [`crate::desktop_target::identity`]), the Desktop session roots (from
    /// [`crate::sessions::layout`]) and `CMA_HOME`. Built from the shipped
    /// data, so crash recovery of a Desktop op accepts its own manifest.
    pub fn for_paths(paths: &Paths) -> Self {
        let mut files = vec![paths.claude_json.clone()];
        files.extend(crate::desktop_target::identity().allowlisted_files(&paths.desktop_dir));
        let mut roots = crate::sessions::layout().roots(&paths.desktop_dir);
        roots.push(paths.cma_home.clone());
        Allowlist { files, roots }
    }

    /// Add exact files (e.g. the Desktop identity set).
    pub fn with_files(mut self, files: impl IntoIterator<Item = PathBuf>) -> Self {
        self.files.extend(files);
        self
    }

    /// Add roots whose descendants are allowed.
    pub fn with_roots(mut self, roots: impl IntoIterator<Item = PathBuf>) -> Self {
        self.roots.extend(roots);
        self
    }

    /// The canonical form of `path` if it is allowed.
    pub fn check(&self, path: &Path) -> Result<PathBuf> {
        let reject = |why: &str| Error::ManifestRejected(format!("{}: {why}", path.display()));
        if !path.is_absolute() {
            return Err(reject("not absolute"));
        }
        if path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(reject("contains . or .."));
        }
        let canon = canonicalize_lenient(path)?;
        for f in &self.files {
            if canonicalize_lenient(f)? == canon {
                return Ok(canon);
            }
        }
        for r in &self.roots {
            let r = canonicalize_lenient(r)?;
            if canon != r && canon.starts_with(&r) {
                return Ok(canon);
            }
        }
        Err(reject("outside the allowlist"))
    }

    fn check_service(&self, service: &str) -> Result<()> {
        if service != BACKUP_SERVICE && SERVICE_PREFIXES.iter().any(|p| service.starts_with(p)) {
            Ok(())
        } else {
            Err(Error::ManifestRejected(format!(
                "keychain service {service:?} not allowed"
            )))
        }
    }

    /// Validate every path and name in a manifest.
    pub fn check_manifest(&self, m: &Manifest) -> Result<()> {
        if m.schema_version > MANIFEST_SCHEMA {
            return Err(Error::ManifestRejected(format!(
                "schema_version {} is newer than supported {MANIFEST_SCHEMA}",
                m.schema_version
            )));
        }
        if !is_valid_id(&m.id) {
            return Err(Error::ManifestRejected(format!("invalid id {:?}", m.id)));
        }
        let own = |acct: Option<&str>| match acct {
            Some(a) if !a.starts_with(&format!("{}/", m.id)) => Err(Error::ManifestRejected(
                format!("backup account {a:?} does not belong to {}", m.id),
            )),
            _ => Ok(()),
        };
        for e in &m.entries {
            own(e.backup_account())?;
            match e {
                Entry::Keychain { service, .. } => self.check_service(service)?,
                Entry::JsonKeys { path, .. } => {
                    self.check(path)?;
                }
                Entry::File { path, copy, .. } => {
                    self.check(path)?;
                    if let Some(c) = copy
                        && !COPY_RE.is_match(c)
                    {
                        return Err(Error::ManifestRejected(format!("invalid copy {c:?}")));
                    }
                }
                Entry::Move {
                    from,
                    to,
                    created_dirs,
                    ..
                } => {
                    self.check(from)?;
                    self.check(to)?;
                    for d in created_dirs {
                        self.check(d)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn new_id(op: &str) -> String {
    let fmt = time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");
    let ts = time::OffsetDateTime::now_utc()
        .format(&fmt)
        .expect("formattable timestamp");
    format!("{ts}-{op}")
}

fn read_json_object(path: &Path) -> Result<Option<Map<String, Value>>> {
    let Some(bytes) = fsutil::read_nofollow(path)? else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(bytes);
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(m)) => Ok(Some(m)),
        Ok(_) => Err(Error::Invalid {
            what: "JSON file (not an object)",
            value: path.display().to_string(),
        }),
        Err(e) => Err(Error::json("JSON file", &e)),
    }
}

fn write_json_object(path: &Path, obj: &Map<String, Value>) -> Result<()> {
    let mut bytes =
        Zeroizing::new(serde_json::to_vec_pretty(obj).map_err(|e| Error::json("JSON file", &e))?);
    bytes.push(b'\n');
    fsutil::atomic_write(path, &bytes)
}

fn apply_updates(obj: &mut Map<String, Value>, updates: &[(String, Option<Value>)]) {
    for (k, v) in updates {
        match v {
            Some(v) => {
                obj.insert(k.clone(), v.clone());
            }
            None => {
                obj.shift_remove(k);
            }
        }
    }
}

/// Hash of the `keys` subset of an object (present keys only, in `keys` order).
pub fn keys_hash(obj: &Map<String, Value>, keys: &[String]) -> String {
    let mut sub = Map::new();
    for k in keys {
        if let Some(v) = obj.get(k) {
            sub.insert(k.clone(), v.clone());
        }
    }
    let bytes = Zeroizing::new(serde_json::to_vec(&Value::Object(sub)).expect("serializable"));
    sha256_hex(&bytes)
}

fn file_hash(path: &Path) -> Result<Option<String>> {
    Ok(fsutil::read_nofollow(path)?.map(|b| sha256_hex(&Zeroizing::new(b))))
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Take `.storage-write` for `service` if it needs it, refusing a guard that
/// is already compromised.
fn storage_guard(
    locker: &dyn StorageLockAcquirer,
    service: &str,
) -> Result<Option<Box<dyn StorageGuard>>> {
    if !needs_storage_lock(service) {
        return Ok(None);
    }
    let g = locker.acquire()?;
    if g.is_compromised() {
        return Err(Error::StateUncertain(
            "Claude Code storage lock compromised; nothing written".into(),
        ));
    }
    Ok(Some(g))
}

/// Refuse right before the protected write if the lock was lost meanwhile
/// (e.g. the process was suspended past `stale` and Claude took it over).
fn check_guard(guard: &Option<Box<dyn StorageGuard>>) -> Result<()> {
    if guard.as_ref().is_some_and(|g| g.is_compromised()) {
        return Err(Error::StateUncertain(
            "Claude Code storage lock compromised before the write; nothing written".into(),
        ));
    }
    Ok(())
}

/// One op's backup, built up while the op mutates state (write-ahead: each
/// entry, including the hash of what will be written, is saved before the
/// write happens).
pub struct Backup<'a> {
    store: &'a dyn SecretStore,
    locker: &'a dyn StorageLockAcquirer,
    allow: Allowlist,
    dir: PathBuf,
    manifest: Manifest,
}

impl<'a> Backup<'a> {
    pub fn create(
        paths: &Paths,
        store: &'a dyn SecretStore,
        locker: &'a dyn StorageLockAcquirer,
        op: &str,
    ) -> Result<Self> {
        if !OP_RE.is_match(op) {
            return Err(Error::Invalid {
                what: "backup op",
                value: op.into(),
            });
        }
        let root = paths.backups_dir();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .map_err(|e| Error::io(&root, e))?;
        let mut tries = 0;
        let (id, dir) = loop {
            let id = new_id(op);
            let dir = root.join(&id);
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => break (id, dir),
                // Same op within the same second: wait for the next second.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 3 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(400));
                }
                Err(e) => return Err(Error::io(&dir, e)),
            }
        };
        let b = Backup {
            store,
            locker,
            allow: Allowlist::for_paths(paths),
            dir,
            manifest: Manifest {
                schema_version: MANIFEST_SCHEMA,
                id,
                op: op.into(),
                created_at: now_unix(),
                entries: Vec::new(),
                extra: Map::new(),
            },
        };
        b.save()?;
        Ok(b)
    }

    /// Extend the allowlist (e.g. for the Desktop identity set).
    pub fn allow(mut self, f: impl FnOnce(Allowlist) -> Allowlist) -> Self {
        self.allow = f(self.allow);
        self
    }

    pub fn id(&self) -> &str {
        &self.manifest.id
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// This backup's directory (inside `CMA_HOME`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn save(&self) -> Result<()> {
        let bytes =
            serde_json::to_vec_pretty(&self.manifest).map_err(|e| Error::json("manifest", &e))?;
        fsutil::atomic_write_mode(&self.dir.join("manifest.json"), &bytes, 0o600)
    }

    fn next_backup_account(&self) -> String {
        format!("{}/{}", self.manifest.id, self.manifest.entries.len())
    }

    /// Back up a Keychain item and write `value` into it.
    ///
    /// For `Claude Code-credentials*` the item is read once outside the lock
    /// (any Keychain prompt happens then), then re-read inside
    /// `.storage-write` and written only if it still holds the value read
    /// first; otherwise [`Error::ConcurrentWrite`] and nothing is written.
    pub fn write_keychain(&mut self, service: &str, account: &str, value: &Secret) -> Result<()> {
        self.put_keychain(service, account, Some(value), None)
    }

    /// Back up a Keychain item and delete it.
    pub fn delete_keychain(&mut self, service: &str, account: &str) -> Result<()> {
        self.put_keychain(service, account, None, None)
    }

    /// Read-modify-write of a Keychain item: `modify` receives the value
    /// read (outside the lock, so any prompt happens then) and returns the
    /// new value. The write happens only if, inside `.storage-write` for
    /// `Claude Code-credentials*`, the item still holds exactly what
    /// `modify` saw; otherwise [`Error::ConcurrentWrite`] and nothing is
    /// written. The result is therefore a read-modify-write inside the lock.
    pub fn modify_keychain(
        &mut self,
        service: &str,
        account: &str,
        modify: impl FnOnce(Option<&Secret>) -> Result<Secret>,
    ) -> Result<()> {
        self.put_keychain_with(service, account, |cur| modify(cur).map(Some), None)
    }

    /// Back up a Keychain item without changing it. The entry records no
    /// write, so in-command rollback and user restore skip it: it exists for
    /// manual recovery only (e.g. the pre-login copy of the live item).
    /// Returns the sha256 of the value backed up (`None` when absent).
    pub fn snapshot_keychain(&mut self, service: &str, account: &str) -> Result<Option<String>> {
        self.allow.check_service(service)?;
        if let Some(Entry::Keychain { sha256, .. }) = self.manifest.entries.iter().find(|e| {
            matches!(e, Entry::Keychain { service: s, account: a, .. } if s == service && a == account)
        }) {
            return Ok(sha256.clone());
        }
        let pre = self.store.get(service, account)?;
        let pre_hash = pre.as_ref().map(Secret::sha256_hex);
        let backup_account = pre.as_ref().map(|_| self.next_backup_account());
        self.manifest.entries.push(Entry::Keychain {
            service: service.into(),
            account: account.into(),
            existed: pre.is_some(),
            sha256: pre_hash.clone(),
            backup_account: backup_account.clone(),
            after_sha256: Vec::new(),
        });
        self.save()?;
        if let (Some(acct), Some(cur)) = (&backup_account, &pre) {
            self.store.set(BACKUP_SERVICE, acct, cur)?;
        }
        Ok(pre_hash)
    }

    /// `expect`: when set, the current value's hash must be one of these.
    fn put_keychain(
        &mut self,
        service: &str,
        account: &str,
        value: Option<&Secret>,
        expect: Option<&[Option<String>]>,
    ) -> Result<()> {
        self.put_keychain_with(service, account, |_| Ok(value.cloned()), expect)
    }

    /// `make` computes the value to write (`None` deletes) from the value
    /// read first.
    fn put_keychain_with(
        &mut self,
        service: &str,
        account: &str,
        make: impl FnOnce(Option<&Secret>) -> Result<Option<Secret>>,
        expect: Option<&[Option<String>]>,
    ) -> Result<()> {
        self.allow.check_service(service)?;
        let label = format!("keychain {service}/{account}");
        // Outside `.storage-write`: this read may show a Keychain prompt.
        let pre = self.store.get(service, account)?;
        let pre_hash = pre.as_ref().map(Secret::sha256_hex);
        pre_check(expect, &pre_hash, &label)?;
        let value = make(pre.as_ref())?;
        let after = value.as_ref().map(Secret::sha256_hex);
        let existing = self.manifest.entries.iter().position(|e| {
            matches!(e, Entry::Keychain { service: s, account: a, .. } if s == service && a == account)
        });
        let idx = match existing {
            // Second write in the same op: the original pre-image stays, and
            // the item must still hold what cma wrote last.
            Some(i) => {
                let Entry::Keychain {
                    sha256,
                    after_sha256,
                    ..
                } = &self.manifest.entries[i]
                else {
                    unreachable!("matched a keychain entry")
                };
                let last = after_sha256
                    .last()
                    .cloned()
                    .unwrap_or_else(|| sha256.clone());
                if last != pre_hash {
                    return Err(Error::ConcurrentWrite(label));
                }
                i
            }
            None => {
                let backup_account = pre.as_ref().map(|_| self.next_backup_account());
                self.manifest.entries.push(Entry::Keychain {
                    service: service.into(),
                    account: account.into(),
                    existed: pre.is_some(),
                    sha256: pre_hash.clone(),
                    backup_account: backup_account.clone(),
                    after_sha256: Vec::new(),
                });
                // Write-ahead: the manifest names the backup item first.
                self.save()?;
                if let (Some(acct), Some(cur)) = (&backup_account, &pre) {
                    self.store.set(BACKUP_SERVICE, acct, cur)?;
                }
                self.manifest.entries.len() - 1
            }
        };
        drop(pre);
        let guard = storage_guard(self.locker, service)?;
        // Inside the lock: the item must still hold what was read above.
        let cur = self.store.get(service, account)?.map(|s| s.sha256_hex());
        if cur != pre_hash {
            return Err(Error::ConcurrentWrite(label));
        }
        if let Entry::Keychain { after_sha256, .. } = &mut self.manifest.entries[idx] {
            after_sha256.push(after);
        }
        self.save()?;
        check_guard(&guard)?;
        let r = match &value {
            Some(v) => self.store.set(service, account, v),
            None => self.store.delete(service, account).map(|_| ()),
        };
        drop(guard);
        r
    }

    /// Back up `keys` of a JSON object file and apply `updates` (`None`
    /// removes the key). Values of `secret_keys` are backed up into the
    /// Keychain, never into the manifest. Other keys are left untouched: the
    /// file is re-read right before the write and only `updates` are applied
    /// to that fresh copy. If the target keys changed in between, nothing is
    /// written ([`Error::ConcurrentWrite`]).
    pub fn write_json_keys(
        &mut self,
        path: &Path,
        updates: &[(String, Option<Value>)],
        secret_keys: &[&str],
    ) -> Result<()> {
        self.put_json_keys(path, updates, secret_keys, None)
    }

    fn put_json_keys(
        &mut self,
        path: &Path,
        updates: &[(String, Option<Value>)],
        secret_keys: &[&str],
        expect: Option<&[String]>,
    ) -> Result<()> {
        let path = self.allow.check(path)?;
        let current = read_json_object(&path)?;
        let file_existed = current.is_some();
        let mut current = current.unwrap_or_default();
        let keys: Vec<String> = updates.iter().map(|(k, _)| k.clone()).collect();
        let before_sha256 = keys_hash(&current, &keys);
        let label = format!("{} keys {}", path.display(), keys.join(","));
        if let Some(exp) = expect
            && !exp.contains(&before_sha256)
        {
            return Err(Error::ConcurrentWrite(label));
        }
        let mut before = Map::new();
        let mut secret = Map::new();
        for k in &keys {
            if let Some(v) = current.get(k) {
                if secret_keys.contains(&k.as_str()) {
                    secret.insert(k.clone(), v.clone());
                } else {
                    before.insert(k.clone(), v.clone());
                }
            }
        }
        apply_updates(&mut current, updates);
        let after = keys_hash(&current, &keys);
        drop(current);
        let (secret_backup_account, secret_bytes) = if secret.is_empty() {
            (None, None)
        } else {
            let bytes = Zeroizing::new(
                serde_json::to_vec(&Value::Object(secret))
                    .map_err(|e| Error::json("JSON keys", &e))?,
            );
            (Some(self.next_backup_account()), Some(bytes))
        };
        self.manifest.entries.push(Entry::JsonKeys {
            path: path.clone(),
            before_sha256: before_sha256.clone(),
            keys: keys.clone(),
            file_existed,
            before,
            secret_keys: secret_keys.iter().map(|s| s.to_string()).collect(),
            secret_backup_account: secret_backup_account.clone(),
            secret_sha256: secret_bytes.as_ref().map(|b| sha256_hex(b)),
            after_sha256: None,
        });
        let idx = self.manifest.entries.len() - 1;
        // Write-ahead: the manifest names the backup item first.
        self.save()?;
        if let (Some(acct), Some(mut bytes)) = (secret_backup_account, secret_bytes) {
            let s = Secret::new(std::mem::take(&mut *bytes));
            self.store.set(BACKUP_SERVICE, &acct, &s)?;
        }
        // Slow work is done: re-read and apply only the updates.
        let mut fresh = read_json_object(&path)?.unwrap_or_default();
        if keys_hash(&fresh, &keys) != before_sha256 {
            return Err(Error::ConcurrentWrite(label));
        }
        apply_updates(&mut fresh, updates);
        if let Entry::JsonKeys { after_sha256, .. } = &mut self.manifest.entries[idx] {
            *after_sha256 = Some(after);
        }
        self.save()?;
        write_json_object(&path, &fresh)
    }

    /// Back up a non-secret file and replace it with `bytes`.
    pub fn write_file(&mut self, path: &Path, bytes: &[u8]) -> Result<()> {
        self.put_file(path, Some(bytes), None)
    }

    /// Back up a non-secret file and remove it.
    pub fn remove_file(&mut self, path: &Path) -> Result<()> {
        self.put_file(path, None, None)
    }

    fn put_file(
        &mut self,
        path: &Path,
        bytes: Option<&[u8]>,
        expect: Option<&[Option<String>]>,
    ) -> Result<()> {
        let path = self.allow.check(path)?;
        let before = fsutil::read_nofollow(&path)?;
        let before_hash = before.as_deref().map(sha256_hex);
        pre_check(expect, &before_hash, &format!("file {}", path.display()))?;
        let copy = match &before {
            Some(b) => {
                let rel = format!("files/{}", self.manifest.entries.len());
                let files = self.dir.join("files");
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&files)
                    .map_err(|e| Error::io(&files, e))?;
                fsutil::atomic_write_mode(&self.dir.join(&rel), b, 0o600)?;
                Some(rel)
            }
            None => None,
        };
        self.manifest.entries.push(Entry::File {
            path: path.clone(),
            sha256_before: before_hash,
            sha256_after: bytes.map(sha256_hex),
            removes: bytes.is_none(),
            copy,
            secret_backup_account: None,
        });
        self.save()?;
        match bytes {
            Some(b) => fsutil::atomic_write(&path, b),
            None => remove_file_if_exists(&path),
        }
    }

    /// Back up a file whose content is secret and replace it with `value`
    /// (`None` removes it). The pre-image goes into the Keychain backup,
    /// never to disk. `expect`: when set, the current hash must be one of
    /// these.
    pub fn write_secret_file(&mut self, path: &Path, value: Option<&Secret>) -> Result<()> {
        self.put_secret_file(path, value, None)
    }

    fn put_secret_file(
        &mut self,
        path: &Path,
        value: Option<&Secret>,
        expect: Option<&[Option<String>]>,
    ) -> Result<()> {
        let path = self.allow.check(path)?;
        let before = fsutil::read_nofollow(&path)?.map(Secret::new);
        let before_hash = before.as_ref().map(Secret::sha256_hex);
        pre_check(expect, &before_hash, &format!("file {}", path.display()))?;
        let acct = before.as_ref().map(|_| self.next_backup_account());
        self.manifest.entries.push(Entry::File {
            path: path.clone(),
            sha256_before: before_hash,
            sha256_after: value.map(Secret::sha256_hex),
            removes: value.is_none(),
            copy: None,
            secret_backup_account: acct.clone(),
        });
        // Write-ahead: the manifest names the backup item first.
        self.save()?;
        if let (Some(a), Some(b)) = (&acct, &before) {
            self.store.set(BACKUP_SERVICE, a, b)?;
        }
        match value {
            Some(v) => fsutil::atomic_write(&path, v.expose()),
            None => remove_file_if_exists(&path),
        }
    }

    /// Record and perform a rename (session follow).
    pub fn move_path(&mut self, from: &Path, to: &Path) -> Result<()> {
        self.move_paths(&[(from.to_path_buf(), to.to_path_buf())], false)
    }

    /// Record and perform several renames with one manifest write: every
    /// entry is saved before any rename happens (a rename not done yet is
    /// simply still at its source, which rollback treats as unchanged).
    /// Missing parents of a destination are created (0700). With `sign`,
    /// each moved entry's [`tree_sig`] is recorded after the renames, so a
    /// user restore leaves alone what changed after the move.
    pub fn move_paths(&mut self, moves: &[(PathBuf, PathBuf)], sign: bool) -> Result<()> {
        if moves.is_empty() {
            return Ok(());
        }
        let mut checked = Vec::with_capacity(moves.len());
        for (from, to) in moves {
            let from = self.allow.check(from)?;
            let to = self.allow.check(to)?;
            if std::fs::symlink_metadata(&to).is_ok() {
                return Err(Error::Invalid {
                    what: "move destination (exists)",
                    value: to.display().to_string(),
                });
            }
            checked.push((from, to));
        }
        let first = self.manifest.entries.len();
        let mut planned: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        for (from, to) in &checked {
            // Missing parents, outermost first; only allowlisted ones are
            // recorded (an allowlist root itself is left if created).
            let mut missing = Vec::new();
            let mut cur = to.parent();
            while let Some(d) = cur {
                if std::fs::symlink_metadata(d).is_ok() || planned.contains(d) {
                    break;
                }
                missing.push(d.to_path_buf());
                cur = d.parent();
            }
            missing.reverse();
            let created_dirs: Vec<PathBuf> = missing
                .into_iter()
                .filter(|d| {
                    planned.insert(d.clone());
                    self.allow.check(d).is_ok()
                })
                .collect();
            self.manifest.entries.push(Entry::Move {
                from: from.clone(),
                to: to.clone(),
                sig: None,
                created_dirs,
            });
        }
        self.save()?;
        for (from, to) in &checked {
            if let Some(parent) = to.parent() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| Error::io(parent, e))?;
            }
            std::fs::rename(from, to).map_err(|e| Error::io(from, e))?;
        }
        if sign {
            for e in &mut self.manifest.entries[first..] {
                if let Entry::Move { to, sig, .. } = e {
                    *sig = Some(tree_sig(to)?);
                }
            }
            self.save()?;
        }
        Ok(())
    }
}

/// Remove directories cma created (innermost first) that are empty again.
fn remove_created_dirs(dirs: &[PathBuf]) {
    for d in dirs.iter().rev() {
        let _ = std::fs::remove_dir(d);
    }
}

/// Whether an entry writes inside `dir` (as given or canonical).
pub fn entry_touches(e: &Entry, dir: &Path) -> bool {
    let canon = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let inside = |p: &Path| p.starts_with(dir) || p.starts_with(&canon);
    match e {
        Entry::JsonKeys { path, .. } | Entry::File { path, .. } => inside(path),
        Entry::Move { from, to, .. } => inside(from) || inside(to),
        Entry::Keychain { .. } => false,
    }
}

/// Signature of a file or directory tree: entry count, total size and the
/// newest mtime (ns) over every entry, symlinks not followed. Cheap enough
/// for session dirs; it changes when anything inside is added, removed,
/// resized or rewritten.
pub fn tree_sig(path: &Path) -> Result<String> {
    let mut count: u64 = 0;
    let mut size: u64 = 0;
    let mut newest: i128 = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let m = std::fs::symlink_metadata(&p).map_err(|e| Error::io(&p, e))?;
        count += 1;
        size += m.len();
        let mt = i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec());
        newest = newest.max(mt);
        if m.is_dir() {
            for e in std::fs::read_dir(&p).map_err(|e| Error::io(&p, e))? {
                stack.push(e.map_err(|e| Error::io(&p, e))?.path());
            }
        }
    }
    Ok(format!("{count}:{size}:{newest}"))
}

/// Refuse when `expect` is set and `cur` is not one of its values.
fn pre_check<T: PartialEq>(expect: Option<&[T]>, cur: &T, label: &str) -> Result<()> {
    match expect {
        Some(exp) if !exp.contains(cur) => Err(Error::ConcurrentWrite(label.into())),
        _ => Ok(()),
    }
}

/// Where an entry's current value stands relative to the op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Equals a value cma wrote: safe to restore.
    AtAfter,
    /// Already equals the pre-image (write never happened, or restored).
    AtBefore,
    /// Changed by someone else since cma's write.
    Changed,
}

fn classify(cur: Option<&str>, before: Option<&str>, afters: &[Option<&str>]) -> State {
    if afters.contains(&cur) {
        State::AtAfter
    } else if cur == before {
        State::AtBefore
    } else {
        State::Changed
    }
}

/// A loaded, validated backup.
/// Checked before each replayed write inside Claude Desktop's dir (Desktop
/// must stay quit); an error stops the replay and keeps the journal.
pub type DesktopGuard<'a> = &'a dyn Fn() -> Result<()>;

pub struct Restorer<'a> {
    paths: Paths,
    store: &'a dyn SecretStore,
    locker: &'a dyn StorageLockAcquirer,
    allow: Allowlist,
    dir: PathBuf,
    manifest: Manifest,
    guard: Option<DesktopGuard<'a>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub id: String,
    pub restored: Vec<String>,
    pub unchanged: Vec<String>,
    /// Entries changed by another writer, or that could not be checked or
    /// written, and were left alone.
    pub uncertain: Vec<String>,
    /// User restore with `force`: moved entries changed since the move,
    /// deliberately left where they are (not uncertain: nothing is unknown
    /// about them).
    pub skipped: Vec<String>,
    pub warnings: Vec<String>,
    /// User restore: the backup of the values it overwrote.
    pub backup_id: Option<String>,
}

impl RestoreReport {
    pub fn state_uncertain(&self) -> bool {
        !self.uncertain.is_empty()
    }
}

/// Outcome of replaying one entry.
enum Replay {
    Restored,
    Unchanged,
    Changed,
}

/// Read and parse `backups/<id>/manifest.json`.
fn load_manifest(dir: &Path, id: &str) -> Result<Manifest> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => return Err(Error::Symlink(dir.to_path_buf())),
        Ok(m) if !m.is_dir() => {
            return Err(Error::ManifestRejected(format!(
                "backup {id} is not a directory"
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::BackupMissing { id: id.into() });
        }
        Err(e) => return Err(Error::io(dir, e)),
    }
    let bytes = fsutil::read_nofollow(&dir.join("manifest.json"))?
        .ok_or_else(|| Error::BackupMissing { id: id.into() })?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|e| Error::json("manifest", &e))?;
    if manifest.id != id {
        return Err(Error::ManifestRejected(format!(
            "manifest id {:?} does not match {id}",
            manifest.id
        )));
    }
    Ok(manifest)
}

impl<'a> Restorer<'a> {
    pub fn load(
        paths: &Paths,
        store: &'a dyn SecretStore,
        locker: &'a dyn StorageLockAcquirer,
        allow: &Allowlist,
        id: &str,
    ) -> Result<Self> {
        if !is_valid_id(id) {
            return Err(Error::ManifestRejected(format!("invalid backup id {id:?}")));
        }
        let dir = paths.backups_dir().join(id);
        let manifest = load_manifest(&dir, id)?;
        allow.check_manifest(&manifest)?;
        Ok(Restorer {
            paths: paths.clone(),
            store,
            locker,
            allow: allow.clone(),
            dir,
            manifest,
            guard: None,
        })
    }

    /// Check `guard` before every replayed write inside the Desktop dir.
    pub fn with_guard(mut self, guard: DesktopGuard<'a>) -> Self {
        self.guard = Some(guard);
        self
    }

    fn check_guard_for(&self, e: &Entry) -> Result<()> {
        match self.guard {
            Some(g) if entry_touches(e, &self.paths.desktop_dir) => g(),
            _ => Ok(()),
        }
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The `claudeAiOauth` fingerprint ([`crate::cli_target::oauth_fingerprint`])
    /// that a restore would put back into Keychain item `service`/`account`,
    /// or `None` when the op did not write that item or its pre-image holds
    /// no OAuth credential. Only a hash leaves this function, never a token.
    pub fn restored_oauth_fingerprint(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<String>> {
        let Some(e) = self.manifest.entries.iter().find(|e| {
            e.was_written()
                && matches!(e, Entry::Keychain { service: s, account: a, .. } if s == service && a == account)
        }) else {
            return Ok(None);
        };
        let Some(pre) = self.keychain_pre_image(e)? else {
            return Ok(None);
        };
        Ok(crate::cli_target::oauth_of(pre.expose())?
            .map(|o| crate::cli_target::oauth_fingerprint(&o)))
    }

    fn state(&self, e: &Entry) -> Result<State> {
        let afters = e.afters();
        Ok(match e {
            Entry::Keychain {
                service,
                account,
                sha256,
                ..
            } => {
                let cur = self.store.get(service, account)?.map(|s| s.sha256_hex());
                classify(cur.as_deref(), sha256.as_deref(), &afters)
            }
            Entry::JsonKeys {
                path,
                keys,
                before_sha256,
                ..
            } => {
                let cur = read_json_object(path)?.unwrap_or_default();
                let cur = keys_hash(&cur, keys);
                classify(Some(&cur), Some(before_sha256), &afters)
            }
            Entry::File {
                path,
                sha256_before,
                ..
            } => {
                let cur = file_hash(path)?;
                classify(cur.as_deref(), sha256_before.as_deref(), &afters)
            }
            Entry::Move { from, to, sig, .. } => {
                let from_exists = std::fs::symlink_metadata(from).is_ok();
                let to_exists = std::fs::symlink_metadata(to).is_ok();
                match (from_exists, to_exists) {
                    (false, true) => match sig {
                        Some(s) if tree_sig(to)? != *s => State::Changed,
                        _ => State::AtAfter,
                    },
                    (true, false) => State::AtBefore,
                    _ => State::Changed,
                }
            }
        })
    }

    fn backup_item(&self, acct: &str) -> Result<Secret> {
        self.store
            .get(BACKUP_SERVICE, acct)?
            .ok_or_else(|| Error::NotFound(format!("Keychain backup item {acct}")))
    }

    /// The Keychain pre-image of a keychain entry, verified against its hash.
    fn keychain_pre_image(&self, e: &Entry) -> Result<Option<Secret>> {
        let Entry::Keychain {
            existed,
            sha256,
            backup_account,
            ..
        } = e
        else {
            return Ok(None);
        };
        if !*existed {
            return Ok(None);
        }
        let acct = backup_account
            .as_deref()
            .ok_or_else(|| Error::ManifestRejected("keychain entry without backup".into()))?;
        let pre = self.backup_item(acct)?;
        if Some(pre.sha256_hex()) != *sha256 {
            return Err(Error::StateUncertain(format!(
                "Keychain backup {acct} does not match its manifest hash"
            )));
        }
        Ok(Some(pre))
    }

    /// The pre-image bytes of a file entry: its on-disk copy, or its
    /// Keychain backup item (verified against its hash); `None` when the
    /// file did not exist.
    fn file_pre_image(&self, e: &Entry) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Entry::File {
            copy,
            secret_backup_account,
            sha256_before,
            ..
        } = e
        else {
            return Ok(None);
        };
        if let Some(rel) = copy {
            return Ok(Some(Zeroizing::new(
                fsutil::read_nofollow(&self.dir.join(rel))?
                    .ok_or_else(|| Error::NotFound(format!("backup copy {rel}")))?,
            )));
        }
        if let Some(acct) = secret_backup_account {
            let s = self.backup_item(acct)?;
            if Some(s.sha256_hex()) != *sha256_before {
                return Err(Error::StateUncertain(format!(
                    "Keychain backup {acct} does not match its manifest hash"
                )));
            }
            return Ok(Some(Zeroizing::new(s.expose().to_vec())));
        }
        Ok(None)
    }

    /// The secret pre-image values of a json_keys entry.
    fn json_secret_values(&self, e: &Entry) -> Result<Map<String, Value>> {
        let Entry::JsonKeys {
            secret_backup_account: Some(acct),
            secret_sha256,
            ..
        } = e
        else {
            return Ok(Map::new());
        };
        let s = self.backup_item(acct)?;
        if secret_sha256.as_ref().is_some_and(|h| *h != s.sha256_hex()) {
            return Err(Error::StateUncertain(format!(
                "Keychain backup {acct} does not match its manifest hash"
            )));
        }
        match serde_json::from_slice::<Value>(s.expose()) {
            Ok(Value::Object(m)) => Ok(m),
            _ => Err(Error::StateUncertain(format!(
                "Keychain backup {acct} is not a JSON object"
            ))),
        }
    }

    /// Put the pre-image back, but only over a value cma wrote. The check is
    /// repeated right before the write: inside `.storage-write` for the live
    /// item, and on a fresh read of the file for JSON keys and files.
    fn replay(&self, e: &Entry) -> Result<Replay> {
        let recheck = |s: State| match s {
            State::AtAfter => None,
            State::AtBefore => Some(Replay::Unchanged),
            State::Changed => Some(Replay::Changed),
        };
        match e {
            Entry::Keychain {
                service, account, ..
            } => {
                // Fetched outside the lock: it is cma's own item.
                let pre = self.keychain_pre_image(e)?;
                let guard = storage_guard(self.locker, service).map_err(|err| match err {
                    Error::StateUncertain(m) => Error::StateUncertain(m),
                    other => Error::StateUncertain(format!(
                        "Claude Code storage lock unavailable ({other})"
                    )),
                })?;
                if let Some(r) = recheck(self.state(e)?) {
                    return Ok(r);
                }
                check_guard(&guard)?;
                match pre {
                    Some(p) => self.store.set(service, account, &p)?,
                    None => {
                        self.store.delete(service, account)?;
                    }
                }
                drop(guard);
                Ok(Replay::Restored)
            }
            Entry::JsonKeys {
                path,
                keys,
                file_existed,
                before,
                ..
            } => {
                let secret = self.json_secret_values(e)?;
                // Re-read right before the write; only `keys` change.
                if let Some(r) = recheck(self.state(e)?) {
                    return Ok(r);
                }
                let mut obj = read_json_object(path)?.unwrap_or_default();
                for k in keys {
                    match before.get(k).or_else(|| secret.get(k)) {
                        Some(v) => {
                            obj.insert(k.clone(), v.clone());
                        }
                        None => {
                            obj.shift_remove(k);
                        }
                    }
                }
                if !file_existed && obj.is_empty() {
                    remove_file_if_exists(path)?;
                } else {
                    write_json_object(path, &obj)?;
                }
                Ok(Replay::Restored)
            }
            Entry::File { path, .. } => {
                let bytes = self.file_pre_image(e)?;
                if let Some(r) = recheck(self.state(e)?) {
                    return Ok(r);
                }
                match bytes {
                    Some(b) => fsutil::atomic_write(path, &b)?,
                    None => remove_file_if_exists(path)?,
                }
                Ok(Replay::Restored)
            }
            Entry::Move {
                from,
                to,
                created_dirs,
                ..
            } => {
                if let Some(r) = recheck(self.state(e)?) {
                    return Ok(r);
                }
                std::fs::rename(to, from).map_err(|e| Error::io(to, e))?;
                remove_created_dirs(created_dirs);
                Ok(Replay::Restored)
            }
        }
    }

    /// In-command rollback (failure or journal recovery): byte-exact replay
    /// of every pre-image, newest entry first, but only over values that
    /// still equal what cma wrote. Every entry is attempted; entries that
    /// changed, or whose state could not be read or written, are left alone
    /// and reported as uncertain.
    pub fn rollback(&self) -> Result<RestoreReport> {
        let mut r = RestoreReport {
            id: self.manifest.id.clone(),
            ..Default::default()
        };
        for e in self.manifest.entries.iter().rev() {
            if !e.was_written() {
                r.unchanged.push(e.label());
                continue;
            }
            // First read outside any lock (a Keychain prompt shows here).
            let outcome = match self.state(e) {
                Ok(State::AtAfter) => {
                    if let Err(g) = self.check_guard_for(e) {
                        return Err(Error::DesktopRunning(format!(
                            "{g}; rollback of {} stopped before its next step and its journal is kept: quit Claude Desktop, then run any cma command",
                            self.manifest.id
                        )));
                    }
                    self.replay(e)
                }
                Ok(State::AtBefore) => Ok(Replay::Unchanged),
                Ok(State::Changed) => Ok(Replay::Changed),
                Err(err) => Err(err),
            };
            match outcome {
                Ok(Replay::Restored) => r.restored.push(e.label()),
                Ok(Replay::Unchanged) => r.unchanged.push(e.label()),
                Ok(Replay::Changed) => r.uncertain.push(e.label()),
                Err(err) => r.uncertain.push(format!("{} ({err})", e.label())),
            }
        }
        if r.state_uncertain() {
            r.warnings.push(format!(
                "state uncertain: {} item(s) changed after cma wrote them or could not be rolled back; backup {} kept",
                r.uncertain.len(),
                r.id
            ));
        }
        Ok(r)
    }

    /// User `cma restore <id>`: only entries this op wrote; refuses when any
    /// of them changed since the op unless `force`. The restore is itself a
    /// journaled op with its own backup (`RestoreReport::backup_id`), so the
    /// values it overwrites can be restored in turn.
    pub fn restore_user(&self, lock: &CmaLock, force: bool) -> Result<RestoreReport> {
        lock.check_for(&self.paths)?;
        let mut r = RestoreReport {
            id: self.manifest.id.clone(),
            ..Default::default()
        };
        let mut plan = Vec::new();
        let mut conflicts = Vec::new();
        let entries = &self.manifest.entries;
        for (i, e) in entries
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, e)| e.was_written())
        {
            let mut s = self.state(e)?;
            // A move whose source a later move of this op refilled (a
            // Desktop login swapped for another at the same path): the
            // later entry, replayed first, empties the source again.
            if s == State::Changed
                && let Entry::Move { from, to, sig, .. } = e
                && std::fs::symlink_metadata(to).is_ok()
                && entries[i + 1..]
                    .iter()
                    .any(|l| matches!(l, Entry::Move { to: t, .. } if t == from))
                && match sig {
                    Some(sg) => tree_sig(to)? == *sg,
                    None => true,
                }
            {
                s = State::AtAfter;
            }
            if s == State::Changed {
                conflicts.push(e.label());
            }
            plan.push((e, s));
        }
        if !conflicts.is_empty() && !force {
            return Err(Error::RestoreConflict(conflicts));
        }
        if plan.iter().all(|(_, s)| *s == State::AtBefore) {
            r.unchanged = plan.iter().map(|(e, _)| e.label()).collect();
            return Ok(r);
        }
        let allow = self.allow.clone();
        let mut b =
            Backup::create(&self.paths, self.store, self.locker, "restore")?.allow(|_| allow);
        let mut j = ActiveJournal::begin(
            &self.paths,
            lock,
            Journal {
                op: "restore".into(),
                target: "backup".into(),
                from: Some(self.manifest.id.clone()),
                to: None,
                backup_id: b.id().to_string(),
                steps_done: Vec::new(),
                extra: Map::new(),
            },
        )?;
        let mut tripped: Option<Error> = None;
        let result = (|| -> Result<()> {
            for (e, s) in &plan {
                match s {
                    State::AtBefore => {
                        r.unchanged.push(e.label());
                        continue;
                    }
                    // A forced Move over a changed layout cannot be replayed.
                    State::Changed if matches!(e, Entry::Move { .. }) => {
                        r.skipped.push(e.label());
                        continue;
                    }
                    _ => {}
                }
                if let Err(g) = self.check_guard_for(e) {
                    tripped = Some(g);
                    return Err(Error::Interrupted);
                }
                self.apply_through(&mut b, e, force)?;
                j.step(&e.label())?;
                r.restored.push(e.label());
            }
            Ok(())
        })();
        r.backup_id = Some(b.id().to_string());
        if let Some(g) = tripped {
            // Rolling back now would write under a running Desktop too:
            // the journal stays, and the next command rolls it back once
            // Desktop is quit.
            drop(b);
            // Leave the journal file in place (as a crash would).
            std::mem::forget(j);
            return Err(Error::DesktopRunning(format!(
                "{g}; the restore stopped before its next step and its journal is kept: quit Claude Desktop, then run any cma command (it rolls the partial restore back)"
            )));
        }
        if let Err(err) = result {
            drop(b);
            // Never roll back under a running Desktop: with a guard, a trip
            // keeps the journal (the next command rolls back once quit).
            let rb = match self.guard {
                Some(g) => {
                    match j.abort_guarded(&self.paths, self.store, self.locker, &self.allow, g) {
                        Err(Error::DesktopRunning(m)) => {
                            return Err(Error::DesktopRunning(format!(
                                "restore failed ({err}) and {m}"
                            )));
                        }
                        r => r?,
                    }
                }
                None => j.abort(&self.paths, self.store, self.locker, &self.allow)?,
            };
            return Err(if rb.state_uncertain() {
                Error::StateUncertain(format!(
                    "restore failed ({err}) and its rollback left {} item(s) uncertain; backup {} kept",
                    rb.uncertain.len(),
                    rb.id
                ))
            } else {
                err
            });
        }
        j.finish()?;
        r.warnings.push(
            "restored tokens may have been rotated since this backup; re-login if they fail".into(),
        );
        Ok(r)
    }

    /// Write one entry's pre-image through `b`, so the current value is
    /// backed up first. Unless `force`, the current value must still be one
    /// cma wrote in the original op.
    fn apply_through(&self, b: &mut Backup<'_>, e: &Entry, force: bool) -> Result<()> {
        match e {
            Entry::Keychain {
                service,
                account,
                after_sha256,
                ..
            } => {
                let pre = self.keychain_pre_image(e)?;
                let expect = (!force).then_some(after_sha256.as_slice());
                b.put_keychain(service, account, pre.as_ref(), expect)
            }
            Entry::JsonKeys {
                path,
                keys,
                before,
                secret_keys,
                after_sha256,
                ..
            } => {
                let secret = self.json_secret_values(e)?;
                let updates: Vec<(String, Option<Value>)> = keys
                    .iter()
                    .map(|k| (k.clone(), before.get(k).or_else(|| secret.get(k)).cloned()))
                    .collect();
                let sk: Vec<&str> = secret_keys.iter().map(String::as_str).collect();
                let after: Vec<String> = after_sha256.iter().cloned().collect();
                let expect = (!force).then_some(after.as_slice());
                b.put_json_keys(path, &updates, &sk, expect)
            }
            Entry::File {
                path,
                sha256_after,
                removes,
                secret_backup_account,
                ..
            } => {
                let bytes = self.file_pre_image(e)?;
                let after: Vec<Option<String>> = if *removes {
                    vec![None]
                } else {
                    vec![sha256_after.clone()]
                };
                let expect = (!force).then_some(after.as_slice());
                if secret_backup_account.is_some() {
                    let s = bytes.map(|mut b| Secret::new(std::mem::take(&mut *b)));
                    b.put_secret_file(path, s.as_ref(), expect)
                } else {
                    b.put_file(path, bytes.as_deref().map(Vec::as_slice), expect)
                }
            }
            Entry::Move {
                from,
                to,
                created_dirs,
                ..
            } => {
                b.move_path(to, from)?;
                remove_created_dirs(created_dirs);
                Ok(())
            }
        }
    }
}

/// One backup as `cma backups` shows it (no secret material: entry labels
/// name Keychain items and files, never their values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub id: String,
    /// Empty when the manifest could not be read (see `problem`).
    pub op: String,
    pub created_at: i64,
    pub entries: Vec<String>,
    /// The unfinished operation journal uses this backup.
    pub in_journal: bool,
    /// Why the manifest could not be read, if it could not.
    pub problem: Option<String>,
}

/// Every backup under `backups/`, newest first. Read-only; needs no lock.
pub fn list(paths: &Paths) -> Result<Vec<Listed>> {
    let protect = crate::journal::read(paths)
        .ok()
        .flatten()
        .map(|j| j.backup_id);
    let root = paths.backups_dir();
    let mut ids: Vec<String> = match std::fs::read_dir(&root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| is_valid_id(n))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(&root, e)),
    };
    ids.sort_by(|a, b| b.cmp(a));
    Ok(ids
        .into_iter()
        .map(|id| {
            let in_journal = protect.as_deref() == Some(id.as_str());
            match load_manifest(&root.join(&id), &id) {
                Ok(m) => Listed {
                    id,
                    op: m.op.clone(),
                    created_at: m.created_at,
                    entries: m.entries.iter().map(Entry::label).collect(),
                    in_journal,
                    problem: None,
                },
                Err(e) => Listed {
                    id,
                    op: String::new(),
                    created_at: 0,
                    entries: Vec::new(),
                    in_journal,
                    problem: Some(e.to_string()),
                },
            }
        })
        .collect())
}

/// A backup `clean` left in place, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanReport {
    pub removed: Vec<String>,
    pub skipped: Vec<Skipped>,
}

/// Delete all but the newest `keep` backups and their Keychain items.
///
/// Never deleted: the backup named by the unfinished operation journal (read
/// here, not trusted from the caller), and any backup whose manifest is
/// missing (unless the directory is empty), unreadable, unparseable or from
/// a newer schema; those are reported in `skipped`, because their manifest
/// is the only record of the Keychain items they own.
pub fn clean(
    paths: &Paths,
    lock: &CmaLock,
    store: &dyn SecretStore,
    keep: usize,
) -> Result<CleanReport> {
    lock.check_for(paths)?;
    let protect = crate::journal::read(paths)?.map(|j| j.backup_id);
    let root = paths.backups_dir();
    let mut ids: Vec<String> = match std::fs::read_dir(&root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            // `DirEntry::file_type` does not follow symlinks.
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| is_valid_id(n))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CleanReport::default()),
        Err(e) => return Err(Error::io(&root, e)),
    };
    // The id starts with a UTC timestamp, so lexical order is age order.
    ids.sort_by(|a, b| b.cmp(a));
    let mut report = CleanReport::default();
    for id in ids.into_iter().skip(keep) {
        let skip = |report: &mut CleanReport, reason: String| {
            report.skipped.push(Skipped {
                id: id.clone(),
                reason,
            })
        };
        if protect.as_deref() == Some(id.as_str()) {
            skip(
                &mut report,
                "used by the unfinished operation journal".into(),
            );
            continue;
        }
        let dir = root.join(&id);
        let manifest = match load_manifest(&dir, &id) {
            Ok(m) if m.schema_version > MANIFEST_SCHEMA => {
                skip(
                    &mut report,
                    format!(
                        "manifest schema_version {} is newer than supported",
                        m.schema_version
                    ),
                );
                continue;
            }
            Ok(m) => Some(m),
            Err(Error::BackupMissing { .. }) => None,
            Err(err) => {
                skip(&mut report, format!("manifest unreadable ({err})"));
                continue;
            }
        };
        match manifest {
            Some(m) => {
                let prefix = format!("{id}/");
                let mut failed = None;
                for a in m.entries.iter().filter_map(Entry::backup_account) {
                    if !a.starts_with(&prefix) {
                        continue;
                    }
                    // An item named write-ahead but never created is fine.
                    if let Err(err) = store.delete(BACKUP_SERVICE, a) {
                        failed = Some(err);
                        break;
                    }
                }
                if let Some(err) = failed {
                    skip(&mut report, format!("Keychain delete failed ({err})"));
                    continue;
                }
                std::fs::remove_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
            }
            None => {
                // Created but the manifest never saved: nothing can exist
                // outside the directory, so only an empty one is removed.
                match std::fs::remove_dir(&dir) {
                    Ok(()) => {}
                    Err(_) => {
                        skip(&mut report, "manifest missing".into());
                        continue;
                    }
                }
            }
        }
        report.removed.push(id);
    }
    Ok(report)
}

#[cfg(test)]
pub(crate) mod tests;
