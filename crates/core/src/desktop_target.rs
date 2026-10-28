//! Claude Desktop target: per-account login snapshots, link, switch.
//!
//! # What a Desktop login is
//!
//! The shipped identity data (`data/desktop_identity.json`, from the local
//! swap experiment on Desktop 4.29.0) lists it: some `config.json` keys
//! (`lastKnownAccountUuid`, `oauth:*`, …) and storage paths under
//! `~/Library/Application Support/Claude` (Cookies, Local Storage, …; a
//! file path takes its SQLite sidecars with it). Everything else in the
//! Desktop dir (MCP config, window state, device registry, caches) stays.
//! Desktop must be quit while any of it changes; cma never logs Desktop out
//! (that revokes the session server-side) and never force-quits it.
//!
//! # Where cma keeps a login that is not live
//!
//! Per account, `<CMA_HOME>/desktop/<account_uuid>/` (0700):
//! `files/<path>` holds the storage paths (moved, never copied; `Cookies`
//! is encrypted with this Mac's `Claude Safe Storage` key, but Local
//! Storage, Session Storage, IndexedDB and the JSON files are plain, so the
//! directory gets the same protection as the Desktop dir: 0700, owned by
//! the user), and `snapshot.json` (0600) lists what is
//! there with hashes. `config.json` values and secret files (Desktop's
//! `config.json.journal`) go into Keychain service [`DESKTOP_SERVICE`],
//! account `<account_uuid>/<key>` (`<account_uuid>/file:<name>`), never to
//! disk. While an account is the live Desktop login its directory holds no
//! paths: the live dir is its only copy, so every switch re-captures the
//! newest state (rotated tokens included).
//!
//! # A switch
//!
//! The caller quits Desktop first (with consent) and holds a [`Session`].
//! Then: preflight (the target's snapshot is complete, `config.json`
//! exists, Desktop dir and `CMA_HOME` are on one volume) → backup + journal
//! (target `desktop`) → move the live login into its owner's snapshot (or,
//! for a login cma does not store, into the backup after consent) → move
//! the target's paths in place → merge the target's keys into `config.json`
//! (every other key preserved) → session follow → post-check → registry.
//! Before every write step [`Guard`] re-checks that Desktop is still quit;
//! if it appeared (an auto-update relaunch), the op aborts and rolls back.
//! Every step goes through [`Backup`], so rollback and `cma restore` work as
//! for the CLI target; recovery of an interrupted Desktop op waits until
//! Desktop is quit (see [`crate::sync::begin`]).

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::backup::Backup;
use crate::cli_target::Warning;
use crate::desktop_app::{DesktopApp, Guard, POLL};
use crate::error::{Error, Result};
use crate::fsutil;
use crate::journal::{ActiveJournal, Journal};
use crate::registry::{Account, AccountKind, DesktopLink, SessionFollow};
use crate::secret::{Secret, SecretStore};
use crate::sessions::{self, MOVED_SESSIONS_CAVEAT, is_uuid};
use crate::switch::{Confirm, abort_op, confirm};
use crate::sync::Session;

/// Keychain service of stored Desktop `config.json` values.
pub const DESKTOP_SERVICE: &str = "claude-multi-auth-desktop";
/// Per-account snapshot metadata file.
pub const SNAPSHOT_FILE: &str = "snapshot.json";
/// Journal target of ops that write the Desktop dir.
pub const JOURNAL_TARGET: &str = "desktop";

const IDENTITY_JSON: &str = include_str!("../data/desktop_identity.json");
const IDENTITY_SCHEMA: u32 = 1;
const SNAPSHOT_SCHEMA: u32 = 1;

// ---------------------------------------------------------------------------
// Identity data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    Exact,
    Prefix,
    /// The key, then a full uuid (e.g. `dxt:allowlistCache:<org>`).
    UuidSuffix,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct KeyPattern {
    pub kind: KeyKind,
    pub key: String,
}

impl KeyPattern {
    pub fn matches(&self, k: &str) -> bool {
        match self.kind {
            KeyKind::Exact => k == self.key,
            KeyKind::Prefix => k.starts_with(&self.key),
            KeyKind::UuidSuffix => k.strip_prefix(&self.key).is_some_and(is_uuid),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Identity {
    pub schema_version: u32,
    /// The `config.json` key naming the signed-in account.
    pub account_key: String,
    pub config_keys: Vec<KeyPattern>,
    /// Storage paths moved as a whole (relative to the Desktop dir).
    pub paths: Vec<String>,
    /// Suffixes of files that travel with a path (SQLite sidecars).
    #[serde(default)]
    pub sidecars: Vec<String>,
    /// Files whose content is secret: kept in the Keychain, not on disk.
    #[serde(default)]
    pub secret_files: Vec<String>,
    /// Left in place (documentation; never touched).
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn safe_rel(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && rel
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

impl Identity {
    pub fn parse(text: &str) -> Result<Identity> {
        let id: Identity =
            serde_json::from_str(text).map_err(|e| Error::json("desktop identity data", &e))?;
        let bad = |v: &str| Error::Invalid {
            what: "desktop identity data",
            value: v.to_string(),
        };
        if id.schema_version != IDENTITY_SCHEMA {
            return Err(bad("schema_version"));
        }
        for p in id.paths.iter().chain(&id.secret_files) {
            if !safe_rel(p) || p == "config.json" {
                return Err(bad(p));
            }
        }
        if id.sidecars.iter().any(|s| s.contains('/')) {
            return Err(bad("sidecars"));
        }
        if !id.matches_key(&id.account_key) {
            return Err(bad("account_key is not an identity key"));
        }
        Ok(id)
    }

    pub fn matches_key(&self, k: &str) -> bool {
        self.config_keys.iter().any(|p| p.matches(k))
    }

    /// Every path that moves: each listed path and its sidecars.
    pub fn units(&self) -> Vec<String> {
        let mut v = Vec::new();
        for p in &self.paths {
            v.push(p.clone());
            for s in &self.sidecars {
                v.push(format!("{p}{s}"));
            }
        }
        v
    }

    /// `config.json`, every unit and secret file, absolute.
    pub fn allowlisted_files(&self, desktop_dir: &Path) -> Vec<PathBuf> {
        let mut v = vec![desktop_dir.join("config.json")];
        v.extend(self.units().iter().map(|u| desktop_dir.join(u)));
        v.extend(self.secret_files.iter().map(|f| desktop_dir.join(f)));
        v
    }
}

/// The shipped identity data.
pub fn identity() -> &'static Identity {
    static I: LazyLock<Identity> = LazyLock::new(|| {
        Identity::parse(IDENTITY_JSON).expect("shipped desktop identity data is valid")
    });
    &I
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub fn store_root(paths: &crate::paths::Paths) -> PathBuf {
    paths.cma_home.join("desktop")
}

/// `<CMA_HOME>/desktop/<uuid>`; the uuid must be a lowercase uuid.
pub fn store_dir(paths: &crate::paths::Paths, uuid: &str) -> Result<PathBuf> {
    if !is_uuid(uuid) {
        return Err(Error::Invalid {
            what: "Desktop account uuid",
            value: uuid.chars().take(40).collect(),
        });
    }
    Ok(store_root(paths).join(uuid))
}

fn files_dir(paths: &crate::paths::Paths, uuid: &str) -> Result<PathBuf> {
    Ok(store_dir(paths, uuid)?.join("files"))
}

fn ensure_private_dir(p: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .map_err(|e| Error::io(p, e))
}

fn kc_key(uuid: &str, key: &str) -> String {
    format!("{uuid}/{key}")
}

fn kc_file(uuid: &str, name: &str) -> String {
    format!("{uuid}/file:{name}")
}

fn exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashed {
    pub name: String,
    pub sha256: String,
}

/// `snapshot.json`: what a stored login consists of (names and hashes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub schema_version: u32,
    pub account_uuid: String,
    pub captured_at: i64,
    pub units: Vec<String>,
    pub config_keys: Vec<Hashed>,
    #[serde(default)]
    pub secret_files: Vec<Hashed>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub fn read_meta(paths: &crate::paths::Paths, uuid: &str) -> Result<Option<SnapshotMeta>> {
    let p = store_dir(paths, uuid)?.join(SNAPSHOT_FILE);
    match fsutil::read_nofollow(&p)? {
        Some(b) => {
            let m: SnapshotMeta =
                serde_json::from_slice(&b).map_err(|e| Error::json("desktop snapshot", &e))?;
            if m.schema_version > SNAPSHOT_SCHEMA || m.account_uuid != uuid {
                return Err(Error::Invalid {
                    what: "desktop snapshot",
                    value: p.display().to_string(),
                });
            }
            Ok(Some(m))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Live state
// ---------------------------------------------------------------------------

fn config_path(paths: &crate::paths::Paths) -> PathBuf {
    paths.desktop_dir.join("config.json")
}

fn read_config(paths: &crate::paths::Paths) -> Result<Option<Map<String, Value>>> {
    let p = config_path(paths);
    let Some(bytes) = fsutil::read_nofollow(&p)? else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(bytes);
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(m)) => Ok(Some(m)),
        Ok(_) => Err(Error::Invalid {
            what: "Claude Desktop config.json (not an object)",
            value: p.display().to_string(),
        }),
        Err(e) => Err(Error::json("Claude Desktop config.json", &e)),
    }
}

/// The account Desktop's `config.json` names (`lastKnownAccountUuid`), if
/// it names a uuid.
pub fn live_account(paths: &crate::paths::Paths) -> Result<Option<String>> {
    Ok(read_config(paths)?.and_then(|c| {
        c.get(&identity().account_key)
            .and_then(Value::as_str)
            .filter(|s| is_uuid(s))
            .map(str::to_string)
    }))
}

/// A stored login, loaded and verified (values are secret).
struct Loaded {
    meta: SnapshotMeta,
    values: Vec<(String, Value)>,
    files: Vec<(String, Secret)>,
}

fn load_snapshot(
    paths: &crate::paths::Paths,
    store: &dyn SecretStore,
    uuid: &str,
) -> Result<Loaded> {
    let meta = read_meta(paths, uuid)?.ok_or_else(|| {
        Error::DesktopNotLinked(format!("cma holds no Claude Desktop login for {uuid}"))
    })?;
    let files = files_dir(paths, uuid)?;
    if meta.units.is_empty() && meta.config_keys.is_empty() {
        return Err(Error::DesktopNotLinked(format!(
            "the stored Claude Desktop login of {uuid} is empty"
        )));
    }
    for u in &meta.units {
        if !identity().units().contains(u) || !exists(&files.join(u)) {
            return Err(Error::NotFound(format!(
                "stored Claude Desktop login of {uuid} is incomplete ({u}); link it again"
            )));
        }
    }
    let item = |acct: String, h: &Hashed| -> Result<Secret> {
        let s = store.get(DESKTOP_SERVICE, &acct)?.ok_or_else(|| {
            Error::NotFound(format!(
                "stored Claude Desktop login of {uuid} is incomplete (Keychain item {acct})"
            ))
        })?;
        if s.sha256_hex() != h.sha256 {
            return Err(Error::Invalid {
                what: "stored Claude Desktop value (hash mismatch)",
                value: acct,
            });
        }
        Ok(s)
    };
    let mut values = Vec::new();
    for h in &meta.config_keys {
        if !identity().matches_key(&h.name) {
            return Err(Error::Invalid {
                what: "stored Claude Desktop key",
                value: h.name.clone(),
            });
        }
        let s = item(kc_key(uuid, &h.name), h)?;
        let v: Value = serde_json::from_slice(s.expose())
            .map_err(|e| Error::json("stored Claude Desktop value", &e))?;
        values.push((h.name.clone(), v));
    }
    let mut secret = Vec::new();
    for h in &meta.secret_files {
        if !identity().secret_files.contains(&h.name) {
            return Err(Error::Invalid {
                what: "stored Claude Desktop file",
                value: h.name.clone(),
            });
        }
        secret.push((h.name.clone(), item(kc_file(uuid, &h.name), h)?));
    }
    if !values
        .iter()
        .any(|(k, v)| *k == identity().account_key && v.as_str() == Some(uuid))
    {
        return Err(Error::Invalid {
            what: "stored Claude Desktop login (names another account)",
            value: uuid.into(),
        });
    }
    Ok(Loaded {
        meta,
        values,
        files: secret,
    })
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// Where the live login goes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Owner {
    /// Into this linked account's snapshot.
    Account(String),
    /// Into the op's backup only (a login cma does not store, or none).
    Aside,
}

/// Move the live login out of the Desktop dir. Returns the identity keys
/// that were live (the config merge removes them).
fn capture(
    b: &mut Backup<'_>,
    paths: &crate::paths::Paths,
    guard: &Guard<'_>,
    owner: &Owner,
    now: i64,
) -> Result<()> {
    let dd = &paths.desktop_dir;
    let id = identity();
    let cfg = read_config(paths)?.unwrap_or_default();
    let live_keys: Vec<(String, Value)> = cfg
        .iter()
        .filter(|(k, _)| id.matches_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    drop(cfg);
    let live_units: Vec<String> = id
        .units()
        .into_iter()
        .filter(|u| exists(&dd.join(u)))
        .collect();
    let mut live_secret = Vec::new();
    for n in &id.secret_files {
        if let Some(bytes) = fsutil::read_nofollow(&dd.join(n))? {
            live_secret.push((n.clone(), Secret::new(bytes)));
        }
    }
    match owner {
        Owner::Account(u) => {
            let dir = store_dir(paths, u)?;
            let files = dir.join("files");
            ensure_private_dir(&files)?;
            let old = read_meta(paths, u)?;
            // A stale copy (the login changed outside cma since it was
            // stored) goes into the backup.
            let stale: Vec<(PathBuf, PathBuf)> = id
                .units()
                .into_iter()
                .filter(|x| exists(&files.join(x)))
                .map(|x| (files.join(&x), b.dir().join("replaced").join(u).join(&x)))
                .collect();
            b.move_paths(&stale, false)?;
            guard.check("moving the live Claude Desktop login")?;
            let moves: Vec<(PathBuf, PathBuf)> = live_units
                .iter()
                .map(|x| (dd.join(x), files.join(x)))
                .collect();
            b.move_paths(&moves, false)?;
            let mut hashed = Vec::new();
            for (k, v) in &live_keys {
                let s = Secret::new(serde_json::to_vec(v).map_err(|e| Error::json("value", &e))?);
                b.write_keychain(DESKTOP_SERVICE, &kc_key(u, k), &s)?;
                hashed.push(Hashed {
                    name: k.clone(),
                    sha256: s.sha256_hex(),
                });
            }
            let mut hashed_files = Vec::new();
            for (n, s) in &live_secret {
                b.write_keychain(DESKTOP_SERVICE, &kc_file(u, n), s)?;
                hashed_files.push(Hashed {
                    name: n.clone(),
                    sha256: s.sha256_hex(),
                });
                guard.check("removing a secret Claude Desktop file")?;
                b.write_secret_file(&dd.join(n), None)?;
            }
            if let Some(old) = old {
                for h in old.config_keys {
                    if !live_keys.iter().any(|(k, _)| *k == h.name) {
                        b.delete_keychain(DESKTOP_SERVICE, &kc_key(u, &h.name))?;
                    }
                }
                for h in old.secret_files {
                    if !live_secret.iter().any(|(n, _)| *n == h.name) {
                        b.delete_keychain(DESKTOP_SERVICE, &kc_file(u, &h.name))?;
                    }
                }
            }
            let meta = SnapshotMeta {
                schema_version: SNAPSHOT_SCHEMA,
                account_uuid: u.clone(),
                captured_at: now,
                units: live_units,
                config_keys: hashed,
                secret_files: hashed_files,
                extra: Map::new(),
            };
            let mut bytes =
                serde_json::to_vec_pretty(&meta).map_err(|e| Error::json("snapshot", &e))?;
            bytes.push(b'\n');
            b.write_file(&dir.join(SNAPSHOT_FILE), &bytes)?;
        }
        Owner::Aside => {
            guard.check("moving the live Claude Desktop login aside")?;
            let moves: Vec<(PathBuf, PathBuf)> = live_units
                .iter()
                .map(|x| (dd.join(x), b.dir().join("stash").join(x)))
                .collect();
            b.move_paths(&moves, false)?;
            for (n, _) in &live_secret {
                guard.check("removing a secret Claude Desktop file")?;
                b.write_secret_file(&dd.join(n), None)?;
            }
        }
    }
    Ok(())
}

/// Put a stored login's paths and secret files in place.
fn apply(
    b: &mut Backup<'_>,
    paths: &crate::paths::Paths,
    guard: &Guard<'_>,
    uuid: &str,
    loaded: &Loaded,
) -> Result<()> {
    let dd = &paths.desktop_dir;
    let files = files_dir(paths, uuid)?;
    // Nothing of the identity should be live now; anything that is (a path
    // the captured login did not have) is moved aside, not overwritten.
    let leftover: Vec<(PathBuf, PathBuf)> = identity()
        .units()
        .into_iter()
        .filter(|x| exists(&dd.join(x)))
        .map(|x| (dd.join(&x), b.dir().join("stash").join(&x)))
        .collect();
    b.move_paths(&leftover, false)?;
    guard.check("putting the stored Claude Desktop login in place")?;
    let moves: Vec<(PathBuf, PathBuf)> = loaded
        .meta
        .units
        .iter()
        .map(|x| (files.join(x), dd.join(x)))
        .collect();
    b.move_paths(&moves, false)?;
    for (n, s) in &loaded.files {
        guard.check("writing a secret Claude Desktop file")?;
        b.write_secret_file(&dd.join(n), Some(s))?;
    }
    Ok(())
}

/// Remove every live identity key from `config.json` and set `set`; every
/// other key is preserved. Pre-images go to the Keychain backup.
fn merge_config(
    b: &mut Backup<'_>,
    paths: &crate::paths::Paths,
    guard: &Guard<'_>,
    set: &[(String, Value)],
) -> Result<()> {
    let cfg = read_config(paths)?.unwrap_or_default();
    let mut updates: Vec<(String, Option<Value>)> = cfg
        .keys()
        .filter(|k| identity().matches_key(k))
        .map(|k| (k.clone(), None))
        .collect();
    drop(cfg);
    for (k, v) in set {
        match updates.iter_mut().find(|(u, _)| u == k) {
            Some(slot) => slot.1 = Some(v.clone()),
            None => updates.push((k.clone(), Some(v.clone()))),
        }
    }
    if updates.is_empty() {
        return Ok(());
    }
    let names: Vec<String> = updates.iter().map(|(k, _)| k.clone()).collect();
    let secret: Vec<&str> = names.iter().map(String::as_str).collect();
    guard.check("writing config.json")?;
    b.write_json_keys(&config_path(paths), &updates, &secret)
}

fn preflight(paths: &crate::paths::Paths) -> Result<()> {
    let cfg = config_path(paths);
    if !exists(&cfg) {
        return Err(Error::NotFound(format!(
            "Claude Desktop settings file {} (start Claude Desktop once first; cma does not create it)",
            cfg.display()
        )));
    }
    let dev = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.dev())
            .map_err(|e| Error::io(p, e))
    };
    if dev(&paths.desktop_dir)? != dev(&paths.cma_home)? {
        return Err(Error::Unsupported(format!(
            "Claude Desktop's data ({}) and cma's home ({}) are on different volumes; cma moves Desktop logins and needs both on one",
            paths.desktop_dir.display(),
            paths.cma_home.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
fn point(step: &str, store: &dyn SecretStore) -> std::result::Result<(), StepErr> {
    use crate::switch::failpoint::{Act, hit};
    match hit(step, store) {
        Act::Continue => Ok(()),
        Act::Fail => Err(StepErr::Failed(Error::Invalid {
            what: "injected failure",
            value: step.into(),
        })),
        Act::Crash => Err(StepErr::Crashed),
    }
}

#[cfg(not(test))]
fn point(_: &str, _: &dyn SecretStore) -> std::result::Result<(), StepErr> {
    Ok(())
}

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

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Options of a Desktop op.
pub struct DesktopOpts<'a> {
    /// Desktop control. The caller has quit Desktop already; the op only
    /// checks (and keeps checking) that it stays quit.
    pub app: &'a dyn DesktopApp,
    /// Consent to move away a live Desktop login cma does not store (it
    /// survives only in the backup; `--replace-live`).
    pub replace_live: Confirm<'a>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesktopReport {
    /// The account whose login was live before (as `config.json` named it).
    pub from: Option<String>,
    /// The account now live (`None`: signed out, after a link's first step).
    pub to: Option<String>,
    pub already_active: bool,
    pub backup_id: Option<String>,
    /// Session follow was on and ran.
    pub session_follow: bool,
    pub sessions_moved: usize,
    /// Moved entries that got a `.cma-<ts>` suffix.
    pub sessions_renamed: Vec<String>,
    /// What stayed in place.
    pub sessions_left: Vec<String>,
    pub warnings: Vec<Warning>,
}

fn ensure_quit(app: &dyn DesktopApp) -> Result<()> {
    let run = app.running()?;
    if run.is_empty() {
        Ok(())
    } else {
        Err(crate::desktop_app::running_error(
            "quit Claude Desktop before cma changes its login",
            &run,
        ))
    }
}

fn is_linked(s: &Session<'_>, uuid: &str) -> bool {
    s.registry.desktop.iter().any(|l| l.account_uuid == uuid)
}

/// Decide where the live login goes; asks before moving away a login cma
/// does not store.
fn owner_for(
    s: &Session<'_>,
    live: Option<&str>,
    opts: &DesktopOpts<'_>,
    report: &mut DesktopReport,
) -> Result<Owner> {
    if let (Some(active), live) = (s.registry.active.desktop.as_deref(), live)
        && Some(active) != live
    {
        report.warnings.push(Warning::new(
            "desktop_account_changed",
            format!(
                "Claude Desktop is signed in as {} now, not {active} as cma last left it (changed outside cma)",
                live.unwrap_or("nobody")
            ),
        ));
    }
    Ok(match live {
        Some(u) if is_linked(s, u) => Owner::Account(u.to_string()),
        Some(u) => {
            let msg = format!(
                "the live Claude Desktop login is {u}, which cma does not store; this moves it into the backup only (`cma clean` eventually deletes it). Run `cma desktop import-current` first to keep it as an account"
            );
            confirm(&opts.replace_live, &msg, "cancelled", "--replace-live")?;
            report
                .warnings
                .push(Warning::new("live_login_replaced", msg));
            Owner::Aside
        }
        None => {
            // Something of a login is live, but its account cannot be read
            // (key missing or not a uuid, e.g. after a Desktop update): it
            // is not known to be worthless, so ask like for any login cma
            // does not store.
            if live_identity_present(s.ctx.paths)? {
                let msg = "Claude Desktop holds login data whose account cma cannot identify (config.json names no account it can read); this moves it into the backup only (`cma clean` eventually deletes it)".to_string();
                confirm(&opts.replace_live, &msg, "cancelled", "--replace-live")?;
                report
                    .warnings
                    .push(Warning::new("live_login_replaced", msg));
            }
            Owner::Aside
        }
    })
}

/// Whether any identity path, secret file or identity key is live.
fn live_identity_present(paths: &crate::paths::Paths) -> Result<bool> {
    let dd = &paths.desktop_dir;
    let id = identity();
    if id.units().iter().any(|u| exists(&dd.join(u)))
        || id.secret_files.iter().any(|f| exists(&dd.join(f)))
    {
        return Ok(true);
    }
    Ok(read_config(paths)?.is_some_and(|c| c.keys().any(|k| id.matches_key(k))))
}

/// What to do after an interrupted Desktop op could not be rolled back
/// (e.g. Desktop ran on the half-moved dir): nothing cma moved is lost.
pub fn interrupted_hint(paths: &crate::paths::Paths, backup_id: &str) -> String {
    format!(
        ". Nothing cma moved is lost: stored Claude Desktop logins stay under {}/<account uuid>/files/ and what this op replaced is in backup {backup_id}. To go on: quit Claude Desktop, run `cma resolve-journal --yes` (it keeps those files), then `cma switch --desktop <account>`; if Desktop then asks you to sign in, sign in and run `cma desktop import-current`",
        store_root(paths).display()
    )
}

/// Journaled body shared by switch (`target` set) and the first step of a
/// link (`target` none: Desktop ends up signed out).
fn run_op(
    s: &mut Session<'_>,
    op: &str,
    target: Option<&str>,
    opts: &DesktopOpts<'_>,
    report: &mut DesktopReport,
) -> Result<()> {
    let ctx = s.ctx;
    let paths = ctx.paths;
    ensure_quit(opts.app)?;
    preflight(paths)?;
    let loaded = match target {
        Some(t) => Some(load_snapshot(paths, ctx.store, t)?),
        None => None,
    };
    let live = live_account(paths)?;
    report.from = live.clone();
    let registry_before = s.registry.clone();
    // A live login of a stored account that was never linked is linked now,
    // so it is stored under its account instead of only in the backup.
    if let Some(u) = live.as_deref()
        && !is_linked(s, u)
        && s.registry.accounts.iter().any(|a| a.account_uuid == u)
    {
        let org = pick_org(s, u);
        // Saved with the op's registry step; undone if the op fails.
        s.registry.desktop.push(DesktopLink {
            account_uuid: u.to_string(),
            last_org_uuid: org,
            linked_at: ctx.now_secs(),
            extra: Map::new(),
        });
        report.warnings.push(Warning::new(
            "desktop_auto_linked",
            format!("Claude Desktop was signed in as {u}, a stored account cma had not linked yet; it is linked now and its login is stored under it"),
        ));
    }
    let owner = match owner_for(s, live.as_deref(), opts, report) {
        Ok(o) => o,
        Err(e) => {
            s.registry = registry_before;
            return Err(e);
        }
    };
    let follow = s.registry.settings.session_follow == SessionFollow::On;
    let new_org = target.and_then(|t| {
        s.registry
            .desktop
            .iter()
            .find(|l| l.account_uuid == t)
            .map(|l| l.last_org_uuid.clone())
    });

    let mut b = match Backup::create(paths, ctx.store, ctx.locker, op) {
        Ok(b) => b,
        Err(e) => {
            s.registry = registry_before;
            return Err(e);
        }
    };
    report.backup_id = Some(b.id().to_string());
    let report_id = b.id().to_string();
    let journal = Journal {
        op: op.into(),
        target: JOURNAL_TARGET.into(),
        from: live.clone(),
        to: target.map(str::to_string),
        backup_id: b.id().to_string(),
        steps_done: Vec::new(),
        extra: Map::new(),
    };
    let mut j = match ActiveJournal::begin(paths, s.lock(), journal) {
        Ok(j) => j,
        Err(e) => {
            s.registry = registry_before;
            return Err(e);
        }
    };
    // A running `switch --both` learns that its Desktop half has a journal
    // now: from here, recovery knows whether this half finished.
    crate::journal::both_note_desktop_backup(paths, s.lock(), &report_id)?;
    let guard = Guard { app: opts.app };
    let now = ctx.now_secs();
    let mut new_registry = s.registry.clone();
    let mut extra_warnings = Vec::new();
    let steps = (|| -> std::result::Result<(), StepErr> {
        capture(&mut b, paths, &guard, &owner, now)?;
        j.step("capture")?;
        point("capture", ctx.store)?;
        if let (Some(t), Some(l)) = (target, &loaded) {
            apply(&mut b, paths, &guard, t, l)?;
            j.step("apply")?;
            point("apply", ctx.store)?;
        }
        let set = loaded.as_ref().map(|l| l.values.as_slice()).unwrap_or(&[]);
        merge_config(&mut b, paths, &guard, set)?;
        j.step("config")?;
        point("config", ctx.store)?;

        if let (true, Owner::Account(old), Some(t)) = (follow, &owner, target) {
            match new_org.as_deref().filter(|o| is_uuid(o)) {
                Some(org) if old != t => {
                    let ts = b.id().split('-').next().unwrap_or("x").to_string();
                    let plan =
                        sessions::plan(sessions::layout(), &paths.desktop_dir, old, t, org, &ts)?;
                    guard.check("moving sessions")?;
                    b.move_paths(&plan.moves, true)?;
                    j.step("sessions")?;
                    report.session_follow = true;
                    report.sessions_moved = plan.moves.len();
                    report.sessions_renamed =
                        plan.renamed.iter().map(|p| p.display().to_string()).collect();
                    report.sessions_left = plan.left;
                    if !plan.moves.is_empty() {
                        extra_warnings.push(Warning::new("sessions_moved", MOVED_SESSIONS_CAVEAT));
                    }
                    if !report.sessions_renamed.is_empty() {
                        extra_warnings.push(Warning::new(
                            "sessions_renamed",
                            format!(
                                "{} moved session entr{} already existed in the new account's folder; both were kept, the moved one with a .cma-{ts} suffix",
                                report.sessions_renamed.len(),
                                if report.sessions_renamed.len() == 1 { "y" } else { "ies" }
                            ),
                        ));
                    }
                    point("sessions", ctx.store)?;
                }
                Some(_) => {}
                None => extra_warnings.push(Warning::new(
                    "session_follow_skipped",
                    format!("session follow is on, but cma does not know which organization {t} uses in Claude Desktop; sessions stayed in place (link it again to record it)"),
                )),
            }
        }

        // Post-check.
        let now_live = live_account(paths)?;
        if now_live.as_deref() != target {
            return Err(StepErr::Failed(Error::Invalid {
                what: "post-check (config.json does not name the target account)",
                value: target.unwrap_or("none").into(),
            }));
        }
        if let Some(l) = &loaded
            && let Some(u) = l
                .meta
                .units
                .iter()
                .find(|u| !exists(&paths.desktop_dir.join(u)))
        {
            return Err(StepErr::Failed(Error::Invalid {
                what: "post-check (stored Claude Desktop path not in place)",
                value: u.clone(),
            }));
        }
        point("post_check", ctx.store)?;

        new_registry.active.desktop = target.map(str::to_string);
        new_registry.save(&paths.registry_file())?;
        j.step("registry")?;
        Ok(())
    })();
    match steps {
        Ok(()) => {
            j.finish()?;
            // Both halves of a running `switch --both` are done.
            if crate::journal::both_active_here() {
                crate::journal::both_clear(paths)?;
            }
            s.registry = new_registry;
            report.to = target.map(str::to_string);
            report.warnings.extend(extra_warnings);
            Ok(())
        }
        #[cfg(test)]
        Err(StepErr::Crashed) => {
            std::mem::forget(j);
            Err(Error::Interrupted)
        }
        Err(StepErr::Failed(e)) => {
            drop(b);
            s.registry = registry_before;
            let (e, clean) = abort_desktop(
                j,
                paths,
                ctx.store,
                ctx.locker,
                opts.app,
                "Claude Desktop switch",
                e,
            );
            let e = match e {
                Error::StateUncertain(m) => {
                    Error::StateUncertain(format!("{m}{}", interrupted_hint(paths, &report_id)))
                }
                other => other,
            };
            if clean {
                crate::journal::both_mark_rolled_back(paths, s.lock(), &report_id)?;
                s.registry.save(&paths.registry_file())?;
            }
            Err(e)
        }
    }
}

/// Roll back a failed Desktop op in-command, but never while Claude Desktop
/// runs (cma never writes into Desktop's data while it runs): then
/// the journal is kept and the error is `desktop_running`; quitting Desktop
/// and running any command rolls it back. Desktop starting during the
/// rollback stops it the same way. Returns the error and whether
/// everything was restored.
fn abort_desktop(
    j: ActiveJournal,
    paths: &crate::paths::Paths,
    store: &dyn SecretStore,
    locker: &dyn crate::lock::StorageLockAcquirer,
    app: &dyn DesktopApp,
    op: &str,
    e: Error,
) -> (Error, bool) {
    let keep = |why: String| {
        Error::DesktopRunning(format!(
            "{op} failed ({e}) and {why}; cma does not write while Claude Desktop runs, so nothing was rolled back yet and the journal is kept: quit Claude Desktop, then run any cma command (it rolls the operation back)"
        ))
    };
    match app.running() {
        Ok(run) if !run.is_empty() => {
            std::mem::forget(j);
            return (
                keep(format!(
                    "Claude Desktop is running ({})",
                    crate::desktop_app::describe(&run).join(", ")
                )),
                false,
            );
        }
        Ok(_) => {}
        Err(err) => {
            std::mem::forget(j);
            return (
                keep(format!(
                    "cma could not check whether Claude Desktop runs ({err})"
                )),
                false,
            );
        }
    }
    let guard = || -> Result<()> {
        let run = app.running()?;
        if run.is_empty() {
            Ok(())
        } else {
            Err(crate::desktop_app::running_error(
                "Claude Desktop started",
                &run,
            ))
        }
    };
    let allow = crate::backup::Allowlist::for_paths(paths);
    match j.abort_guarded(paths, store, locker, &allow, &guard) {
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
        Err(Error::DesktopRunning(m)) => (keep(format!("then {m}")), false),
        Err(rb_err) => (
            Error::StateUncertain(format!(
                "{op} failed ({e}) and rollback failed ({rb_err}); journal kept"
            )),
            false,
        ),
    }
}

/// Everything a switch to `uuid` can be refused for before it writes,
/// checked without writing (the caller asks consents and quits Desktop only
/// after this passes). Returns the question to ask when the live login
/// would be moved away into the backup only (`--replace-live`).
pub fn check_switch(
    paths: &crate::paths::Paths,
    store: &dyn SecretStore,
    registry: &crate::registry::Registry,
    uuid: &str,
) -> Result<Option<String>> {
    if !registry.desktop.iter().any(|l| l.account_uuid == uuid) {
        return Err(Error::DesktopNotLinked(format!(
            "{uuid} has no Claude Desktop login stored by cma"
        )));
    }
    let live = live_account(paths)?;
    if live.as_deref() == Some(uuid) {
        return Ok(None);
    }
    preflight(paths)?;
    load_snapshot(paths, store, uuid)?;
    Ok(match live.as_deref() {
        Some(u)
            if registry.desktop.iter().any(|l| l.account_uuid == u)
                || registry.accounts.iter().any(|a| a.account_uuid == u) =>
        {
            None
        }
        Some(u) => Some(format!(
            "the live Claude Desktop login is {u}, which cma does not store; switching moves it into the backup only (`cma clean` eventually deletes it). Run `cma desktop import-current` first to keep it as an account"
        )),
        None if live_identity_present(paths)? => Some(
            "Claude Desktop holds login data whose account cma cannot identify; switching moves it into the backup only (`cma clean` eventually deletes it)".to_string(),
        ),
        None => None,
    })
}

/// Switch Claude Desktop to linked account `uuid`. Desktop must be quit.
pub fn switch_desktop(
    s: &mut Session<'_>,
    uuid: &str,
    opts: &DesktopOpts<'_>,
) -> Result<DesktopReport> {
    if !is_linked(s, uuid) {
        return Err(Error::DesktopNotLinked(format!(
            "{uuid} has no Claude Desktop login stored by cma"
        )));
    }
    let mut report = DesktopReport::default();
    let live = live_account(s.ctx.paths)?;
    if live.as_deref() == Some(uuid) {
        // Already live: nothing to move (Desktop may run).
        report.from = live.clone();
        report.to = live;
        report.already_active = true;
        if s.registry.active.desktop.as_deref() != Some(uuid) {
            s.registry.active.desktop = Some(uuid.to_string());
            s.save()?;
        }
        return Ok(report);
    }
    run_op(s, "desktop-switch", Some(uuid), opts, &mut report)?;
    Ok(report)
}

/// First step of `desktop link`: move the live login into its owner's
/// snapshot (or the backup) so Desktop starts signed out. Desktop must be
/// quit.
pub fn stash_live(s: &mut Session<'_>, opts: &DesktopOpts<'_>) -> Result<DesktopReport> {
    let mut report = DesktopReport::default();
    run_op(s, "desktop-link", None, opts, &mut report)?;
    Ok(report)
}

/// Outcome of [`link_live`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkReport {
    pub account_uuid: String,
    pub org_uuid: String,
    /// Registry key of the account the login belongs to.
    pub key: String,
    /// A Desktop-only account (no Claude Code login) was added.
    pub created_desktop_only: bool,
    pub already_linked: bool,
    pub warnings: Vec<Warning>,
}

fn newest_org_dir(paths: &crate::paths::Paths, uuid: &str, among: &[String]) -> Option<String> {
    let base = paths.desktop_dir.join("claude-code-sessions").join(uuid);
    let rd = std::fs::read_dir(&base).ok()?;
    rd.filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if !is_uuid(&name) || (!among.is_empty() && !among.contains(&name)) {
                return None;
            }
            let m = e.metadata().ok()?;
            Some((m.modified().ok()?, name))
        })
        .max()
        .map(|(_, n)| n)
}

/// The organization a Desktop login uses: the link's, else the only stored
/// account's, else the one whose session folder changed last.
fn pick_org(s: &Session<'_>, uuid: &str) -> String {
    pick_org_in(s.ctx.paths, &s.registry, uuid)
}

fn pick_org_in(
    paths: &crate::paths::Paths,
    registry: &crate::registry::Registry,
    uuid: &str,
) -> String {
    if let Some(l) = registry.desktop.iter().find(|l| l.account_uuid == uuid)
        && is_uuid(&l.last_org_uuid)
    {
        return l.last_org_uuid.clone();
    }
    let orgs: Vec<String> = registry
        .accounts
        .iter()
        .filter(|a| a.account_uuid == uuid && is_uuid(&a.org_uuid))
        .map(|a| a.org_uuid.clone())
        .collect();
    match orgs.as_slice() {
        [one] => one.clone(),
        many => newest_org_dir(paths, uuid, many)
            .or_else(|| many.first().cloned())
            .or_else(|| newest_org_dir(paths, uuid, &[]))
            .unwrap_or_default(),
    }
}

/// Link the account Desktop is signed in to now (no Desktop file changes):
/// a stored account with that uuid, or (after `desktop_only` consent) a new
/// Desktop-only account. Sets `active.desktop`. Desktop may run.
pub fn link_live(
    s: &mut Session<'_>,
    desktop_only: &Confirm<'_>,
    alias: Option<&str>,
) -> Result<LinkReport> {
    let paths = s.ctx.paths;
    let live = live_account(paths)?.ok_or_else(|| {
        Error::NotFound(
            "a signed-in Claude Desktop account (its config.json names none; sign in to Claude Desktop first)".into(),
        )
    })?;
    let accounts: Vec<&Account> = s
        .registry
        .accounts
        .iter()
        .filter(|a| a.account_uuid == live)
        .collect();
    let existing = s
        .registry
        .desktop
        .iter()
        .find(|l| l.account_uuid == live)
        .cloned();
    let org = pick_org(s, &live);
    let mut warnings = Vec::new();
    let mut created = false;
    let key = match accounts
        .iter()
        .find(|a| a.org_uuid == org)
        .or(accounts.first())
    {
        Some(a) => a.key.clone(),
        None => {
            let msg = format!(
                "Claude Desktop is signed in as {live}, which no stored account matches; save it as a Desktop-only account (no Claude Code login; `cma login` adds one, which usage needs)"
            );
            confirm(desktop_only, &msg, "nothing was linked", "--yes")?;
            let key = Account::key_for(&live, &org);
            s.registry.accounts.push(Account {
                key: key.clone(),
                kind: AccountKind::Oauth,
                account_uuid: live.clone(),
                org_uuid: org.clone(),
                alias: alias.map(str::to_string),
                added_at: s.ctx.now_secs(),
                has_cli: false,
                ..Account::default()
            });
            created = true;
            key
        }
    };
    if org.is_empty() {
        warnings.push(Warning::new(
            "desktop_org_unknown",
            "cma could not tell which organization this Claude Desktop login uses, so session follow cannot move sessions into it",
        ));
    }
    let now = s.ctx.now_secs();
    match s
        .registry
        .desktop
        .iter_mut()
        .find(|l| l.account_uuid == live)
    {
        Some(l) => {
            if !org.is_empty() {
                l.last_org_uuid = org.clone();
            }
        }
        None => s.registry.desktop.push(DesktopLink {
            account_uuid: live.clone(),
            last_org_uuid: org.clone(),
            linked_at: now,
            extra: Map::new(),
        }),
    }
    s.registry.active.desktop = Some(live.clone());
    s.save()?;
    Ok(LinkReport {
        account_uuid: live,
        org_uuid: org,
        key,
        created_desktop_only: created,
        already_linked: existing.is_some(),
        warnings,
    })
}

/// Outcome of [`unlink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkReport {
    pub account_uuid: String,
    pub backup_id: Option<String>,
    /// Desktop-only accounts removed with the link.
    pub removed_accounts: Vec<String>,
    pub was_active: bool,
}

/// Forget the Desktop login cma stores for `uuid`: its snapshot moves into
/// a backup (restorable), its Keychain values are deleted (pre-images in
/// the backup). A Desktop-only account goes with it. The live Desktop dir
/// is not touched, so Desktop may run.
pub fn unlink(s: &mut Session<'_>, uuid: &str) -> Result<UnlinkReport> {
    if !is_linked(s, uuid) {
        return Err(Error::DesktopNotLinked(format!(
            "{uuid} is not linked to Claude Desktop"
        )));
    }
    let ctx = s.ctx;
    let paths = ctx.paths;
    let meta = read_meta(paths, uuid)?;
    let dir = store_dir(paths, uuid)?;
    let mut b = Backup::create(paths, ctx.store, ctx.locker, "desktop-unlink")?;
    let mut j = ActiveJournal::begin(
        paths,
        s.lock(),
        Journal {
            op: "desktop-unlink".into(),
            target: "desktop-store".into(),
            from: Some(uuid.into()),
            to: None,
            backup_id: b.id().to_string(),
            steps_done: Vec::new(),
            extra: Map::new(),
        },
    )?;
    let mut reg = s.registry.clone();
    let was_active = reg.active.desktop.as_deref() == Some(uuid);
    let removed: Vec<String> = reg
        .accounts
        .iter()
        .filter(|a| {
            a.account_uuid == uuid
                && !a.has_cli
                && ctx
                    .store
                    .get(crate::cli_target::OWN_SERVICE, &a.key)
                    .ok()
                    .flatten()
                    .is_none()
        })
        .map(|a| a.key.clone())
        .collect();
    let r = (|| -> Result<()> {
        if let Some(m) = &meta {
            for h in &m.config_keys {
                b.delete_keychain(DESKTOP_SERVICE, &kc_key(uuid, &h.name))?;
            }
            for h in &m.secret_files {
                b.delete_keychain(DESKTOP_SERVICE, &kc_file(uuid, &h.name))?;
            }
        }
        if exists(&dir) {
            let to = b.dir().join("unlinked").join(uuid);
            b.move_paths(&[(dir.clone(), to)], false)?;
        }
        j.step("store")?;
        reg.desktop.retain(|l| l.account_uuid != uuid);
        reg.accounts.retain(|a| !removed.contains(&a.key));
        if was_active {
            reg.active.desktop = None;
        }
        reg.save(&paths.registry_file())?;
        j.step("registry")?;
        Ok(())
    })();
    match r {
        Ok(()) => {
            j.finish()?;
            let backup_id = Some(b.id().to_string());
            s.registry = reg;
            Ok(UnlinkReport {
                account_uuid: uuid.into(),
                backup_id,
                removed_accounts: removed,
                was_active,
            })
        }
        Err(e) => {
            drop(b);
            let (e, clean) = abort_op(j, ctx, "Claude Desktop unlink", e);
            if clean {
                s.registry.save(&paths.registry_file())?;
            }
            Err(e)
        }
    }
}

/// After a switch: start Desktop and, best effort, check that it still
/// names `target` once it runs. Problems are warnings: the switch itself is
/// done.
pub fn launch_and_verify(
    app: &dyn DesktopApp,
    paths: &crate::paths::Paths,
    target: Option<&str>,
    wait: Duration,
) -> Vec<Warning> {
    let mut w = Vec::new();
    if let Err(e) = app.launch() {
        w.push(Warning::new(
            "desktop_launch_failed",
            format!("could not start Claude Desktop ({e}); start it yourself"),
        ));
        return w;
    }
    let polls = (wait.as_millis() / POLL.as_millis().max(1)).max(1);
    let mut started = false;
    for _ in 0..polls {
        if app.running().map(|r| !r.is_empty()).unwrap_or(false) {
            started = true;
            break;
        }
        app.pause(POLL);
    }
    if !started {
        w.push(Warning::new(
            "desktop_not_started",
            "Claude Desktop did not show up as running yet; check that it opened",
        ));
        return w;
    }
    if let Some(t) = target {
        match live_account(paths) {
            Ok(Some(u)) if u == t => {}
            Ok(other) => w.push(Warning::new(
                "desktop_verify_failed",
                format!(
                    "after starting, Claude Desktop names {} instead of {t}; if it asks you to sign in, run `cma restore` with the switch's backup id",
                    other.as_deref().unwrap_or("no account")
                ),
            )),
            Err(e) => w.push(Warning::new(
                "desktop_verify_failed",
                format!("could not read Claude Desktop's config.json after starting it ({e})"),
            )),
        }
    }
    w
}

/// The uuid of the store directory `p` lies in (`<CMA_HOME>/desktop/<uuid>/…`).
fn store_uuid_of(paths: &crate::paths::Paths, p: &Path) -> Option<String> {
    let root = store_root(paths);
    let canon = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    [root, canon].iter().find_map(|r| {
        let rest = p.strip_prefix(r).ok()?;
        let first = rest.components().next()?.as_os_str().to_str()?.to_string();
        is_uuid(&first).then_some(first)
    })
}

/// `p` relative to the Desktop dir (as given or canonical).
fn rel_in_desktop(paths: &crate::paths::Paths, p: &Path) -> Option<String> {
    let dd = &paths.desktop_dir;
    let canon = std::fs::canonicalize(dd).unwrap_or_else(|_| dd.clone());
    [dd.clone(), canon]
        .iter()
        .find_map(|r| p.strip_prefix(r).ok().map(|x| x.display().to_string()))
}

/// The account whose login a Desktop op moved out of the Desktop dir into
/// its store (switching back to it is the safe undo).
pub fn previous_account(
    paths: &crate::paths::Paths,
    m: &crate::backup::Manifest,
) -> Option<String> {
    m.entries.iter().find_map(|e| match e {
        crate::backup::Entry::Move { from, to, .. } if rel_in_desktop(paths, from).is_some() => {
            store_uuid_of(paths, to)
        }
        _ => None,
    })
}

/// The account whose stored login a Desktop op put in place.
pub fn incoming_account(
    paths: &crate::paths::Paths,
    m: &crate::backup::Manifest,
) -> Option<String> {
    m.entries.iter().find_map(|e| match e {
        crate::backup::Entry::Move { from, to, .. } if rel_in_desktop(paths, to).is_some() => {
            store_uuid_of(paths, from)
        }
        _ => None,
    })
}

/// Before a forced `cma restore` of a Desktop switch: store the live login's
/// current `config.json` values and secret files under the account Desktop
/// runs now (the one the switch put in place), so the restore, which moves
/// that account's files back into its store, leaves its stored login
/// consistent (tokens Desktop rotated meanwhile are kept). Journaled, with
/// its own backup; returns that backup's id, or `None` when the manifest
/// does not swap a Desktop login.
///
/// Refuses ([`Error::DesktopRestoreRefused`]) when that cannot be done
/// safely: Desktop now names another account, the account is not linked,
/// or Desktop added identity keys, paths or files the restore would not move
/// back. Desktop must be quit (the caller checks).
pub fn recapture_for_restore(
    paths: &crate::paths::Paths,
    store: &dyn SecretStore,
    locker: &dyn crate::lock::StorageLockAcquirer,
    lock: &crate::lock::CmaLock,
    m: &crate::backup::Manifest,
) -> Result<Option<String>> {
    use crate::backup::Entry;
    let Some(incoming) = incoming_account(paths, m) else {
        return Ok(None);
    };
    let back = previous_account(paths, m)
        .map(|p| format!("`cma switch --desktop <the account {p}>`"))
        .unwrap_or_else(|| "`cma switch --desktop <account>`".into());
    let refuse = |why: String| {
        Err(Error::DesktopRestoreRefused(format!(
            "{why}, so a forced restore would leave its stored Claude Desktop login inconsistent; use {back} instead (it stores the current login first)"
        )))
    };
    let live = live_account(paths)?;
    if live.as_deref() != Some(incoming.as_str()) {
        return refuse(format!(
            "Claude Desktop is signed in as {} now, not {incoming} as this switch left it",
            live.as_deref().unwrap_or("nobody")
        ));
    }
    let reg = crate::registry::Registry::load(&paths.registry_file())?;
    if !reg.desktop.iter().any(|l| l.account_uuid == incoming) {
        return refuse(format!("{incoming} is no longer linked"));
    }
    let id = identity();
    let cfg = read_config(paths)?.unwrap_or_default();
    let live_keys: Vec<(String, Value)> = cfg
        .iter()
        .filter(|(k, _)| id.matches_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    drop(cfg);
    let entry_keys: Vec<String> = m
        .entries
        .iter()
        .find_map(|e| match e {
            Entry::JsonKeys { path, keys, .. }
                if rel_in_desktop(paths, path).as_deref() == Some("config.json") =>
            {
                Some(keys.clone())
            }
            _ => None,
        })
        .unwrap_or_default();
    if let Some((k, _)) = live_keys.iter().find(|(k, _)| !entry_keys.contains(k)) {
        return refuse(format!(
            "Claude Desktop added the identity key {k} after the switch"
        ));
    }
    let moved_in: Vec<String> = m
        .entries
        .iter()
        .filter_map(|e| match e {
            Entry::Move { from, to, .. }
                if store_uuid_of(paths, from).as_deref() == Some(incoming.as_str()) =>
            {
                rel_in_desktop(paths, to)
            }
            _ => None,
        })
        .collect();
    let dd = &paths.desktop_dir;
    let live_units: Vec<String> = id
        .units()
        .into_iter()
        .filter(|u| exists(&dd.join(u)))
        .collect();
    if let Some(u) = live_units.iter().find(|u| !moved_in.contains(u)) {
        return refuse(format!("Claude Desktop created {u} after the switch"));
    }
    let mut live_secret = Vec::new();
    for n in &id.secret_files {
        if let Some(bytes) = fsutil::read_nofollow(&dd.join(n))? {
            let written = m.entries.iter().any(|e| {
                matches!(e, Entry::File { path, .. } if rel_in_desktop(paths, path).as_deref() == Some(n.as_str()))
            });
            if !written {
                return refuse(format!("Claude Desktop created {n} after the switch"));
            }
            live_secret.push((n.clone(), Secret::new(bytes)));
        }
    }

    let old = read_meta(paths, &incoming)?;
    let dir = store_dir(paths, &incoming)?;
    let mut b = Backup::create(paths, store, locker, "desktop-recapture")?;
    let j = ActiveJournal::begin(
        paths,
        lock,
        Journal {
            op: "desktop-recapture".into(),
            target: JOURNAL_TARGET.into(),
            from: Some(incoming.clone()),
            to: Some(incoming.clone()),
            backup_id: b.id().to_string(),
            steps_done: Vec::new(),
            extra: Map::new(),
        },
    )?;
    let r = (|| -> Result<()> {
        let mut hashed = Vec::new();
        for (k, v) in &live_keys {
            let s = Secret::new(serde_json::to_vec(v).map_err(|e| Error::json("value", &e))?);
            b.write_keychain(DESKTOP_SERVICE, &kc_key(&incoming, k), &s)?;
            hashed.push(Hashed {
                name: k.clone(),
                sha256: s.sha256_hex(),
            });
        }
        let mut hashed_files = Vec::new();
        for (n, s) in &live_secret {
            b.write_keychain(DESKTOP_SERVICE, &kc_file(&incoming, n), s)?;
            hashed_files.push(Hashed {
                name: n.clone(),
                sha256: s.sha256_hex(),
            });
        }
        if let Some(old) = &old {
            for h in &old.config_keys {
                if !live_keys.iter().any(|(k, _)| *k == h.name) {
                    b.delete_keychain(DESKTOP_SERVICE, &kc_key(&incoming, &h.name))?;
                }
            }
            for h in &old.secret_files {
                if !live_secret.iter().any(|(n, _)| *n == h.name) {
                    b.delete_keychain(DESKTOP_SERVICE, &kc_file(&incoming, &h.name))?;
                }
            }
        }
        ensure_private_dir(&dir)?;
        let meta = SnapshotMeta {
            schema_version: SNAPSHOT_SCHEMA,
            account_uuid: incoming.clone(),
            captured_at: time::OffsetDateTime::now_utc().unix_timestamp(),
            units: live_units.clone(),
            config_keys: hashed,
            secret_files: hashed_files,
            extra: Map::new(),
        };
        let mut bytes =
            serde_json::to_vec_pretty(&meta).map_err(|e| Error::json("snapshot", &e))?;
        bytes.push(b'\n');
        b.write_file(&dir.join(SNAPSHOT_FILE), &bytes)
    })();
    let id_str = b.id().to_string();
    match r {
        Ok(()) => {
            j.finish()?;
            Ok(Some(id_str))
        }
        Err(e) => {
            drop(b);
            let rb = j.abort(
                paths,
                store,
                locker,
                &crate::backup::Allowlist::for_paths(paths),
            )?;
            Err(if rb.state_uncertain() {
                Error::StateUncertain(format!(
                    "storing the live Claude Desktop login before the restore failed ({e}) and its rollback left items uncertain; backup {id_str} kept"
                ))
            } else {
                e
            })
        }
    }
}

/// Whether an entry is part of a Desktop login (identity paths, secret
/// files, `config.json` keys), as opposed to session moves.
pub fn is_identity_entry(paths: &crate::paths::Paths, e: &crate::backup::Entry) -> bool {
    use crate::backup::Entry;
    let id = identity();
    let ident = |p: &Path| {
        rel_in_desktop(paths, p).is_some_and(|r| {
            r == "config.json" || id.units().contains(&r) || id.secret_files.contains(&r)
        })
    };
    match e {
        Entry::JsonKeys { path, .. } | Entry::File { path, .. } => ident(path),
        Entry::Move { from, to, .. } => ident(from) || ident(to),
        Entry::Keychain { .. } => false,
    }
}

/// Before a forced `cma restore` of a backup that moved a Desktop login
/// aside without putting a stored one in place (`desktop link`'s first
/// step): move the live login out first, under its account when it is a
/// linked one, otherwise into this op's backup (files and keys together),
/// so the restore puts the old login's files and keys back together and
/// never mixes them with the live one. Journaled; returns the backup id,
/// or `None` when there is nothing to do (the manifest swaps in a stored
/// login: see [`recapture_for_restore`]; or nothing of a login is live).
pub fn park_live_for_restore(
    paths: &crate::paths::Paths,
    store: &dyn SecretStore,
    locker: &dyn crate::lock::StorageLockAcquirer,
    lock: &crate::lock::CmaLock,
    app: &dyn DesktopApp,
    replace_live: &Confirm<'_>,
    m: &crate::backup::Manifest,
) -> Result<Option<Parked>> {
    if incoming_account(paths, m).is_some()
        || !m.entries.iter().any(|e| is_identity_entry(paths, e))
        || !live_identity_present(paths)?
    {
        return Ok(None);
    }
    ensure_quit(app)?;
    preflight(paths)?;
    let mut reg = crate::registry::Registry::load(&paths.registry_file())?;
    let live = live_account(paths)?;
    // Same rules as a switch: a linked account keeps its login; a stored
    // but unlinked one is linked first; anything else needs consent.
    let mut auto_linked = None;
    let owner = match live.as_deref() {
        Some(u) if reg.desktop.iter().any(|l| l.account_uuid == u) => Owner::Account(u.into()),
        Some(u) if reg.accounts.iter().any(|a| a.account_uuid == u) => {
            let org = pick_org_in(paths, &reg, u);
            reg.desktop.push(DesktopLink {
                account_uuid: u.into(),
                last_org_uuid: org,
                linked_at: time::OffsetDateTime::now_utc().unix_timestamp(),
                extra: Map::new(),
            });
            auto_linked = Some(u.to_string());
            Owner::Account(u.into())
        }
        Some(u) => {
            confirm(
                replace_live,
                &format!(
                    "the live Claude Desktop login is {u}, which cma does not store; the restore moves it into a backup only (`cma clean` eventually deletes it). Run `cma desktop import-current` first to keep it as an account"
                ),
                "nothing was restored",
                "--replace-live",
            )?;
            Owner::Aside
        }
        None => {
            confirm(
                replace_live,
                "Claude Desktop holds login data whose account cma cannot identify; the restore moves it into a backup only (`cma clean` eventually deletes it)",
                "nothing was restored",
                "--replace-live",
            )?;
            Owner::Aside
        }
    };
    let mut b = Backup::create(paths, store, locker, "desktop-park")?;
    let j = ActiveJournal::begin(
        paths,
        lock,
        Journal {
            op: "desktop-park".into(),
            target: JOURNAL_TARGET.into(),
            from: live.clone(),
            to: None,
            backup_id: b.id().to_string(),
            steps_done: Vec::new(),
            extra: Map::new(),
        },
    )?;
    let guard = Guard { app };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let r = capture(&mut b, paths, &guard, &owner, now)
        .and_then(|()| merge_config(&mut b, paths, &guard, &[]));
    let id = b.id().to_string();
    match r {
        Ok(()) => {
            j.finish()?;
            if auto_linked.is_some() {
                reg.save(&paths.registry_file())?;
            }
            Ok(Some(Parked {
                backup_id: id,
                account: match owner {
                    Owner::Account(u) => Some(u),
                    Owner::Aside => None,
                },
                auto_linked,
            }))
        }
        Err(e) => {
            drop(b);
            let (e, _) = abort_desktop(
                j,
                paths,
                store,
                locker,
                app,
                "moving the live Claude Desktop login aside before the restore",
                e,
            );
            Err(e)
        }
    }
}

/// The restore that parked the live login failed: put the parked login back
/// (journaled rollback of the park's backup). Never while Desktop runs:
/// then the journal is kept and the first command after Desktop is quit
/// puts it back. Returns whether it is back now.
pub fn undo_park(
    paths: &crate::paths::Paths,
    store: &dyn SecretStore,
    locker: &dyn crate::lock::StorageLockAcquirer,
    lock: &crate::lock::CmaLock,
    app: &dyn DesktopApp,
    park_id: &str,
) -> Result<bool> {
    let j = ActiveJournal::begin(
        paths,
        lock,
        Journal {
            op: "desktop-unpark".into(),
            target: JOURNAL_TARGET.into(),
            from: None,
            to: None,
            backup_id: park_id.to_string(),
            steps_done: Vec::new(),
            extra: Map::new(),
        },
    )?;
    match app.running() {
        Ok(run) if run.is_empty() => {}
        _ => {
            std::mem::forget(j);
            return Ok(false);
        }
    }
    let guard = || -> Result<()> {
        let run = app.running()?;
        if run.is_empty() {
            Ok(())
        } else {
            Err(crate::desktop_app::running_error(
                "Claude Desktop started",
                &run,
            ))
        }
    };
    let allow = crate::backup::Allowlist::for_paths(paths);
    match j.abort_guarded(paths, store, locker, &allow, &guard) {
        Ok(rb) if !rb.state_uncertain() => Ok(true),
        Ok(rb) => Err(Error::StateUncertain(format!(
            "putting the parked Claude Desktop login back left {} item(s) uncertain; backup {park_id} and the journal are kept",
            rb.uncertain.len()
        ))),
        Err(Error::DesktopRunning(_)) => Ok(false),
        Err(e) => Err(Error::StateUncertain(format!(
            "putting the parked Claude Desktop login back failed ({e}); backup {park_id} and the journal are kept"
        ))),
    }
}

/// Where [`park_live_for_restore`] put the live login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parked {
    /// Its backup (`cma restore <id>` puts the parked login back).
    pub backup_id: String,
    /// The linked account it was stored under; `None`: only in the backup.
    pub account: Option<String>,
    /// That account was linked just now.
    pub auto_linked: Option<String>,
}

/// Whether a backup manifest touches the Desktop dir (its restore needs
/// Desktop quit).
pub fn touches_desktop(paths: &crate::paths::Paths, m: &crate::backup::Manifest) -> bool {
    m.entries
        .iter()
        .any(|e| crate::backup::entry_touches(e, &paths.desktop_dir))
}

#[cfg(test)]
mod tests;
