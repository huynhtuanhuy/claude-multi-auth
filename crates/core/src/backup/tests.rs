use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::*;
use crate::error::ToolFailure;
use crate::lock::tests::FakeLocker;
use crate::paths::MapEnv;
use crate::secret::MemoryStore;
use serde_json::json;

pub const CRED: &str = "Claude Code-credentials";
const OWN: &str = "claude-multi-auth";

pub fn test_paths(t: &Path) -> Paths {
    let home = t.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let p = Paths::from_env(&MapEnv::new([
        ("HOME", home.to_str().unwrap()),
        ("CMA_HOME", home.join("cma").to_str().unwrap()),
        ("CMA_ALLOW_HOME_OVERRIDE", "1"),
    ]))
    .unwrap();
    p.ensure_cma_home().unwrap();
    p
}

fn s(v: &str) -> Secret {
    Secret::new(v.as_bytes().to_vec())
}

fn get(store: &dyn SecretStore, svc: &str) -> Option<Vec<u8>> {
    store.get(svc, "me").unwrap().map(|s| s.expose().to_vec())
}

fn restorer<'a>(
    p: &Paths,
    store: &'a dyn SecretStore,
    lk: &'a dyn StorageLockAcquirer,
    id: &str,
) -> Restorer<'a> {
    Restorer::load(p, store, lk, &Allowlist::for_paths(p), id).unwrap()
}

fn cma_lock(p: &Paths) -> CmaLock {
    CmaLock::acquire(&p.lock_file()).unwrap()
}

fn manifest_on_disk(p: &Paths, id: &str) -> Manifest {
    let bytes = std::fs::read(p.backups_dir().join(id).join("manifest.json")).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// What a store hook makes `set` do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Store,
    /// Fail without storing (models a crash or a `security` failure).
    Fail,
}

type SetHook = Box<dyn FnMut(&str, &str) -> Act>;
type GetHook = Box<dyn FnMut(&str, &str)>;

/// MemoryStore with hooks, to inject failures and concurrent changes.
#[derive(Default)]
pub struct HookStore {
    pub inner: MemoryStore,
    pub on_set: RefCell<Option<SetHook>>,
    pub on_get: RefCell<Option<GetHook>>,
}

impl HookStore {
    fn on_set(&self, f: impl FnMut(&str, &str) -> Act + 'static) {
        *self.on_set.borrow_mut() = Some(Box::new(f));
    }
    fn on_get(&self, f: impl FnMut(&str, &str) + 'static) {
        *self.on_get.borrow_mut() = Some(Box::new(f));
    }
}

impl SecretStore for HookStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>> {
        if let Some(f) = self.on_get.borrow_mut().as_mut() {
            f(service, account);
        }
        self.inner.get(service, account)
    }
    fn set(&self, service: &str, account: &str, value: &Secret) -> Result<()> {
        let act = match self.on_set.borrow_mut().as_mut() {
            Some(f) => f(service, account),
            None => Act::Store,
        };
        match act {
            Act::Store => self.inner.set(service, account, value),
            Act::Fail => Err(Error::ExternalTool {
                program: "security",
                sub: "-i",
                code: Some(1),
                class: ToolFailure::Other,
            }),
        }
    }
    fn delete(&self, service: &str, account: &str) -> Result<bool> {
        self.inner.delete(service, account)
    }
}

#[test]
fn id_format_and_regex() {
    let id = new_id("switch");
    assert!(is_valid_id(&id), "{id}");
    for bad in ["../x", "20261026T101022Z-sw1tch", "20261026T101022Z-", "x"] {
        assert!(!is_valid_id(bad), "{bad}");
    }
}

#[test]
fn keychain_backup_never_on_disk_and_byte_exact_rollback() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    store.set(CRED, "me", &s("PRE-IMAGE-TOKEN")).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("NEW-TOKEN")).unwrap();
    assert_eq!(lk.acquired.get(), 1, "live item written under the lock");
    b.write_keychain(OWN, "me", &s("fresh")).unwrap();
    assert_eq!(lk.acquired.get(), 1, "cma's own items need no storage lock");
    let id = b.id().to_string();
    assert_eq!(get(&store, CRED).unwrap(), b"NEW-TOKEN");
    // Pre-image in the backup service, not in any file.
    assert_eq!(store.count(BACKUP_SERVICE), 1);
    let manifest =
        std::fs::read_to_string(p.backups_dir().join(&id).join("manifest.json")).unwrap();
    assert!(!manifest.contains("PRE-IMAGE") && !manifest.contains("NEW-TOKEN"));

    let r = restorer(&p, &store, &lk, &id).rollback().unwrap();
    assert!(!r.state_uncertain(), "{r:?}");
    assert_eq!(r.restored.len(), 2);
    assert_eq!(
        lk.acquired.get(),
        2,
        "rollback of the live item takes the lock"
    );
    assert_eq!(get(&store, CRED).unwrap(), b"PRE-IMAGE-TOKEN");
    assert!(get(&store, OWN).is_none(), "absent before ⇒ deleted");
}

#[test]
fn byte_exact_rollback_of_binary_values_with_trailing_newline() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    let mut pre: Vec<u8> = (0u8..=255).collect();
    pre.extend_from_slice(b"\r\n \n");
    store.set(CRED, "me", &Secret::new(pre.clone())).unwrap();
    let f = p.cma_home.join("blob.bin");
    std::fs::write(&f, &pre).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("new")).unwrap();
    b.write_file(&f, b"new\n").unwrap();
    let r = restorer(&p, &store, &lk, b.id()).rollback().unwrap();
    assert!(!r.state_uncertain(), "{r:?}");
    assert_eq!(get(&store, CRED).unwrap(), pre);
    assert_eq!(std::fs::read(&f).unwrap(), pre);
}

#[test]
fn rollback_leaves_value_changed_by_another_writer() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    store.set(CRED, "me", &s("A")).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    // Claude refreshes and writes its own rotated pair.
    store.set(CRED, "me", &s("B-rotated-by-claude")).unwrap();
    let id = b.id().to_string();
    let r = restorer(&p, &store, &lk, &id).rollback().unwrap();
    assert!(r.state_uncertain());
    assert_eq!(get(&store, CRED).unwrap(), b"B-rotated-by-claude");
    // Backup kept.
    assert_eq!(store.count(BACKUP_SERVICE), 1);
    assert!(p.backups_dir().join(&id).is_dir());
}

#[test]
fn crash_after_manifest_save_before_live_write_is_noop() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = HookStore::default();
    let lk = FakeLocker::default();
    store.inner.set(CRED, "me", &s("A")).unwrap();
    store.on_set(|svc, _| if svc == CRED { Act::Fail } else { Act::Store });
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    assert!(b.write_keychain(CRED, "me", &s("B")).is_err());
    let id = b.id().to_string();
    drop(b);
    // The manifest recorded the intended write before it failed.
    match &manifest_on_disk(&p, &id).entries[0] {
        Entry::Keychain { after_sha256, .. } => assert_eq!(after_sha256.len(), 1),
        e => panic!("{e:?}"),
    }
    let r = restorer(&p, &store, &lk, &id).rollback().unwrap();
    assert!(!r.state_uncertain(), "{r:?}");
    assert_eq!(r.unchanged.len(), 1);
    assert_eq!(get(&store, CRED).unwrap(), b"A");
}

#[test]
fn rollback_rechecks_inside_storage_lock_and_does_not_write_over_a_change() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = Rc::new(MemoryStore::new());
    store.set(CRED, "me", &s("A")).unwrap();
    let lk = FakeLocker::default();
    let mut b = Backup::create(&p, &*store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    let id = b.id().to_string();
    drop(b);
    // Claude refreshes between cma's first check and cma taking the lock.
    let racing = FakeLocker::default();
    let st = store.clone();
    *racing.on_acquire.borrow_mut() = Some(Box::new(move || {
        st.set(CRED, "me", &s("B-rotated")).unwrap();
    }));
    let r = restorer(&p, &*store, &racing, &id).rollback().unwrap();
    assert_eq!(racing.acquired.get(), 1);
    assert!(r.state_uncertain(), "{r:?}");
    assert_eq!(get(&*store, CRED).unwrap(), b"B-rotated", "no write");
}

#[test]
fn rollback_refuses_without_a_trustworthy_lock() {
    for (fail, compromised) in [(true, false), (false, true)] {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let store = MemoryStore::new();
        let lk = FakeLocker::default();
        store.set(CRED, "me", &s("A")).unwrap();
        let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
        b.write_keychain(CRED, "me", &s("B")).unwrap();
        let bad = FakeLocker {
            fail,
            compromised,
            ..Default::default()
        };
        let r = restorer(&p, &store, &bad, b.id()).rollback().unwrap();
        assert!(r.state_uncertain(), "fail={fail} compromised={compromised}");
        assert!(
            r.uncertain[0].contains("state uncertain"),
            "{:?}",
            r.uncertain
        );
        assert_eq!(get(&store, CRED).unwrap(), b"B");
    }
}

#[test]
fn write_keychain_refuses_when_claude_writes_before_the_lock() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = Rc::new(MemoryStore::new());
    store.set(CRED, "me", &s("A")).unwrap();
    let lk = FakeLocker::default();
    let st = store.clone();
    *lk.on_acquire.borrow_mut() = Some(Box::new(move || {
        st.set(CRED, "me", &s("A-rotated")).unwrap();
    }));
    let mut b = Backup::create(&p, &*store, &lk, "switch").unwrap();
    let err = b.write_keychain(CRED, "me", &s("B")).unwrap_err();
    assert_eq!(err.code(), "concurrent_write");
    assert_eq!(get(&*store, CRED).unwrap(), b"A-rotated");
    // Nothing was written, so rollback has nothing to do and is certain.
    let plain = FakeLocker::default();
    let r = restorer(&p, &*store, &plain, b.id()).rollback().unwrap();
    assert!(!r.state_uncertain(), "{r:?}");
    assert_eq!(get(&*store, CRED).unwrap(), b"A-rotated");
}

#[test]
fn write_keychain_refuses_compromised_or_missing_lock() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    store.set(CRED, "me", &s("A")).unwrap();
    for lk in [
        FakeLocker {
            fail: true,
            ..Default::default()
        },
        FakeLocker {
            compromised: true,
            ..Default::default()
        },
    ]
    .into_iter()
    .zip(["switch", "switch-again"])
    {
        let (lk, op) = lk;
        let mut b = Backup::create(&p, &store, &lk, op).unwrap();
        assert!(b.write_keychain(CRED, "me", &s("B")).is_err());
        assert_eq!(get(&store, CRED).unwrap(), b"A");
    }
}

#[test]
fn lock_lost_between_acquire_and_write_means_no_write() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    store.set(CRED, "me", &s("A")).unwrap();
    // Second check (right before the write) sees the lock lost.
    let losing = FakeLocker {
        lost_at_check: 2,
        ..Default::default()
    };
    let mut b = Backup::create(&p, &store, &losing, "switch").unwrap();
    let err = b.write_keychain(CRED, "me", &s("B")).unwrap_err();
    assert_eq!(err.code(), "state_uncertain");
    assert_eq!(get(&store, CRED).unwrap(), b"A", "write refused");
    let lk = FakeLocker::default();
    let r = restorer(&p, &store, &lk, b.id()).rollback().unwrap();
    assert!(
        !r.state_uncertain(),
        "recorded but unwritten is a no-op: {r:?}"
    );
    drop(b);

    // Same for rollback.
    let mut b = Backup::create(&p, &store, &lk, "switch-again").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    let r = restorer(&p, &store, &losing, b.id()).rollback().unwrap();
    assert!(r.state_uncertain(), "{r:?}");
    assert_eq!(get(&store, CRED).unwrap(), b"B", "rollback write refused");
}

#[test]
fn crash_between_manifest_and_backup_item_leaves_a_named_absent_item() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = HookStore::default();
    let lk = FakeLocker::default();
    store.inner.set(CRED, "me", &s("A")).unwrap();
    store.on_set(|svc, _| {
        if svc == BACKUP_SERVICE {
            Act::Fail
        } else {
            Act::Store
        }
    });
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    assert!(b.write_keychain(CRED, "me", &s("B")).is_err());
    let id = b.id().to_string();
    drop(b);
    match &manifest_on_disk(&p, &id).entries[0] {
        Entry::Keychain {
            backup_account,
            after_sha256,
            ..
        } => {
            assert_eq!(backup_account.as_deref(), Some(format!("{id}/0").as_str()));
            assert!(after_sha256.is_empty());
        }
        e => panic!("{e:?}"),
    }
    assert_eq!(store.inner.count(BACKUP_SERVICE), 0);
    assert_eq!(get(&store, CRED).unwrap(), b"A");
    let r = restorer(&p, &store, &lk, &id).rollback().unwrap();
    assert!(!r.state_uncertain(), "{r:?}");
    // clean handles the named-but-absent item.
    let rep = clean(&p, &cma_lock(&p), &store, 0).unwrap();
    assert_eq!(rep.removed, vec![id]);
}

#[test]
fn crash_after_backup_item_is_found_by_clean() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = HookStore::default();
    let lk = FakeLocker::default();
    store.inner.set(CRED, "me", &s("A")).unwrap();
    store.on_set(|svc, _| if svc == CRED { Act::Fail } else { Act::Store });
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    assert!(b.write_keychain(CRED, "me", &s("B")).is_err());
    let id = b.id().to_string();
    drop(b);
    assert_eq!(store.inner.count(BACKUP_SERVICE), 1, "pre-image copied");
    let rep = clean(&p, &cma_lock(&p), &store, 0).unwrap();
    assert_eq!(rep.removed, vec![id]);
    assert_eq!(store.inner.count(BACKUP_SERVICE), 0, "no orphaned token");
}

#[test]
fn double_write_rolls_back_and_a_crash_between_writes_is_certain() {
    // Both writes land.
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = HookStore::default();
    let lk = FakeLocker::default();
    store.inner.set(CRED, "me", &s("A")).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    b.write_keychain(CRED, "me", &s("C")).unwrap();
    assert_eq!(b.manifest().entries.len(), 1);
    let r = restorer(&p, &store, &lk, b.id()).rollback().unwrap();
    assert!(!r.state_uncertain(), "{r:?}");
    assert_eq!(get(&store, CRED).unwrap(), b"A");

    // Crash after the second write was recorded but before it landed.
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let writes = Rc::new(Cell::new(0));
    let w = writes.clone();
    store.inner.set(CRED, "me", &s("A")).unwrap();
    store.on_set(move |svc, _| {
        if svc == CRED {
            w.set(w.get() + 1);
            if w.get() == 2 {
                return Act::Fail;
            }
        }
        Act::Store
    });
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    assert!(b.write_keychain(CRED, "me", &s("C")).is_err());
    assert_eq!(get(&store, CRED).unwrap(), b"B");
    match &manifest_on_disk(&p, b.id()).entries[0] {
        Entry::Keychain { after_sha256, .. } => assert_eq!(after_sha256.len(), 2),
        e => panic!("{e:?}"),
    }
    *store.on_set.borrow_mut() = None;
    let r = restorer(&p, &store, &lk, b.id()).rollback().unwrap();
    assert!(!r.state_uncertain(), "first cma value still counts: {r:?}");
    assert_eq!(get(&store, CRED).unwrap(), b"A");
}

#[test]
fn second_write_refuses_if_claude_changed_the_item_since_cma_wrote() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    store.set(CRED, "me", &s("A")).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    store.set(CRED, "me", &s("B-rotated")).unwrap();
    let err = b.write_keychain(CRED, "me", &s("C")).unwrap_err();
    assert!(matches!(err, Error::ConcurrentWrite(_)));
    assert_eq!(get(&store, CRED).unwrap(), b"B-rotated");
}

#[test]
fn rollback_continues_past_an_entry_whose_state_cannot_be_read() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    store.set(CRED, "me", &s("A")).unwrap();
    std::fs::write(&p.claude_json, br#"{"oauthAccount":{"accountUuid":"A"}}"#).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    b.write_json_keys(
        &p.claude_json,
        &[("oauthAccount".into(), Some(json!({"accountUuid": "B"})))],
        &[],
    )
    .unwrap();
    // The newest entry cannot be read any more.
    std::fs::write(&p.claude_json, b"{not json").unwrap();
    let r = restorer(&p, &store, &lk, b.id()).rollback().unwrap();
    assert!(r.state_uncertain());
    assert_eq!(r.uncertain.len(), 1);
    assert!(r.uncertain[0].contains("invalid JSON"), "{:?}", r.uncertain);
    assert_eq!(r.restored, vec![format!("keychain {CRED}/me")]);
    assert_eq!(
        get(&store, CRED).unwrap(),
        b"A",
        "older entry still rolled back"
    );
}

#[test]
fn json_keys_scoped_backup_and_restore() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    std::fs::write(
        &p.claude_json,
        serde_json::to_vec(
            &json!({"numStartups": 3, "oauthAccount": {"accountUuid": "A"}, "projects": {}}),
        )
        .unwrap(),
    )
    .unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_json_keys(
        &p.claude_json,
        &[("oauthAccount".into(), Some(json!({"accountUuid": "B"})))],
        &[],
    )
    .unwrap();
    let id = b.id().to_string();
    drop(b);
    // Claude rewrites unrelated keys meanwhile.
    let mut obj: Map<String, Value> =
        serde_json::from_slice(&std::fs::read(&p.claude_json).unwrap()).unwrap();
    assert_eq!(obj["oauthAccount"]["accountUuid"], "B");
    obj.insert("numStartups".into(), json!(4));
    std::fs::write(&p.claude_json, serde_json::to_vec(&obj).unwrap()).unwrap();

    let r = restorer(&p, &store, &lk, &id)
        .restore_user(&cma_lock(&p), false)
        .unwrap();
    assert_eq!(r.restored.len(), 1);
    assert!(r.warnings.iter().any(|w| w.contains("rotated")));
    let obj: Value = serde_json::from_slice(&std::fs::read(&p.claude_json).unwrap()).unwrap();
    assert_eq!(obj["oauthAccount"]["accountUuid"], "A");
    assert_eq!(obj["numStartups"], 4, "unrelated keys keep the newer value");
}

/// A JSON file with a secret key (Desktop-style) and an unrelated key.
fn desktop_cfg(p: &Paths) -> PathBuf {
    std::fs::create_dir_all(&p.desktop_dir).unwrap();
    let cfg = p.desktop_dir.join("config.json");
    std::fs::write(&cfg, br#"{"oauth:tokenCache":"CIPHERTEXT-BLOB","other":1}"#).unwrap();
    cfg
}

fn set_key(path: &Path, k: &str, v: Value) {
    let mut obj: Map<String, Value> =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    obj.insert(k.into(), v);
    std::fs::write(path, serde_json::to_vec(&obj).unwrap()).unwrap();
}

fn read_obj(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn json_secret_keys_go_to_keychain() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    let cfg = desktop_cfg(&p);
    let mut b = Backup::create(&p, &store, &lk, "desktop-switch").unwrap();
    b.write_json_keys(
        &cfg,
        &[("oauth:tokenCache".into(), Some(json!("NEW-BLOB")))],
        &["oauth:tokenCache"],
    )
    .unwrap();
    let id = b.id().to_string();
    let manifest =
        std::fs::read_to_string(p.backups_dir().join(&id).join("manifest.json")).unwrap();
    assert!(!manifest.contains("CIPHERTEXT-BLOB"));
    restorer(&p, &store, &lk, &id).rollback().unwrap();
    let obj = read_obj(&cfg);
    assert_eq!(obj["oauth:tokenCache"], "CIPHERTEXT-BLOB");
    assert_eq!(obj["other"], 1);
}

#[test]
fn json_secret_backup_with_wrong_hash_is_not_restored() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    let cfg = desktop_cfg(&p);
    let mut b = Backup::create(&p, &store, &lk, "desktop-switch").unwrap();
    b.write_json_keys(
        &cfg,
        &[("oauth:tokenCache".into(), Some(json!("NEW-BLOB")))],
        &["oauth:tokenCache"],
    )
    .unwrap();
    let acct = format!("{}/0", b.id());
    store
        .set(
            BACKUP_SERVICE,
            &acct,
            &s(r#"{"oauth:tokenCache":"TAMPERED"}"#),
        )
        .unwrap();
    let r = restorer(&p, &store, &lk, b.id()).rollback().unwrap();
    assert!(r.state_uncertain());
    assert_eq!(read_obj(&cfg)["oauth:tokenCache"], "NEW-BLOB");
}

#[test]
fn json_write_rereads_and_keeps_concurrent_change_to_other_keys() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = HookStore::default();
    let lk = FakeLocker::default();
    let cfg = desktop_cfg(&p);
    // While cma backs up the secret key, Desktop rewrites another key.
    let c = cfg.clone();
    store.on_set(move |svc, _| {
        if svc == BACKUP_SERVICE {
            set_key(&c, "other", json!(2));
        }
        Act::Store
    });
    let mut b = Backup::create(&p, &store, &lk, "desktop-switch").unwrap();
    b.write_json_keys(
        &cfg,
        &[("oauth:tokenCache".into(), Some(json!("NEW-BLOB")))],
        &["oauth:tokenCache"],
    )
    .unwrap();
    let obj = read_obj(&cfg);
    assert_eq!(obj["oauth:tokenCache"], "NEW-BLOB");
    assert_eq!(obj["other"], 2, "concurrent change to another key kept");
}

#[test]
fn json_write_refuses_when_target_key_changes_concurrently() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = HookStore::default();
    let lk = FakeLocker::default();
    let cfg = desktop_cfg(&p);
    let c = cfg.clone();
    store.on_set(move |svc, _| {
        if svc == BACKUP_SERVICE {
            set_key(&c, "oauth:tokenCache", json!("DESKTOP-NEWER"));
        }
        Act::Store
    });
    let mut b = Backup::create(&p, &store, &lk, "desktop-switch").unwrap();
    let err = b
        .write_json_keys(
            &cfg,
            &[("oauth:tokenCache".into(), Some(json!("NEW-BLOB")))],
            &["oauth:tokenCache"],
        )
        .unwrap_err();
    assert!(matches!(err, Error::ConcurrentWrite(_)), "{err:?}");
    assert_eq!(read_obj(&cfg)["oauth:tokenCache"], "DESKTOP-NEWER");
    *store.on_set.borrow_mut() = None;
    let r = restorer(&p, &store, &lk, b.id()).rollback().unwrap();
    assert!(!r.state_uncertain(), "nothing written: {r:?}");
    assert_eq!(read_obj(&cfg)["oauth:tokenCache"], "DESKTOP-NEWER");
}

#[test]
fn json_rollback_rereads_and_keeps_concurrent_change_to_other_keys() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = HookStore::default();
    let lk = FakeLocker::default();
    let cfg = desktop_cfg(&p);
    let mut b = Backup::create(&p, &store, &lk, "desktop-switch").unwrap();
    b.write_json_keys(
        &cfg,
        &[("oauth:tokenCache".into(), Some(json!("NEW-BLOB")))],
        &["oauth:tokenCache"],
    )
    .unwrap();
    let id = b.id().to_string();
    drop(b);
    // Desktop rewrites another key while rollback fetches the backup item.
    let c = cfg.clone();
    store.on_get(move |svc, _| {
        if svc == BACKUP_SERVICE {
            set_key(&c, "other", json!(3));
        }
    });
    let r = restorer(&p, &store, &lk, &id).rollback().unwrap();
    assert!(!r.state_uncertain(), "{r:?}");
    let obj = read_obj(&cfg);
    assert_eq!(obj["oauth:tokenCache"], "CIPHERTEXT-BLOB");
    assert_eq!(obj["other"], 3, "concurrent change to another key kept");
}

#[test]
fn user_restore_refuses_changed_value_and_forced_restore_backs_it_up() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    store.set(CRED, "me", &s("A")).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    let id = b.id().to_string();
    drop(b);
    store.set(CRED, "me", &s("C-newer")).unwrap();
    let rs = restorer(&p, &store, &lk, &id);
    let lock = cma_lock(&p);
    match rs.restore_user(&lock, false) {
        Err(Error::RestoreConflict(list)) => assert!(list[0].contains(CRED)),
        other => panic!("{other:?}"),
    }
    assert_eq!(get(&store, CRED).unwrap(), b"C-newer");
    let before = lk.acquired.get();
    let r = rs.restore_user(&lock, true).unwrap();
    assert_eq!(r.restored.len(), 1);
    assert_eq!(get(&store, CRED).unwrap(), b"A");
    assert!(lk.acquired.get() > before, "restore wrote under the lock");
    assert!(
        crate::journal::read(&p).unwrap().is_none(),
        "journal finished"
    );
    // The overwritten value was backed up and can be brought back.
    let new_id = r.backup_id.unwrap();
    assert_ne!(new_id, id);
    let r2 = restorer(&p, &store, &lk, &new_id).rollback().unwrap();
    assert!(!r2.state_uncertain(), "{r2:?}");
    assert_eq!(get(&store, CRED).unwrap(), b"C-newer");
}

#[test]
fn user_restore_succeeds_when_unchanged() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    store.set(CRED, "me", &s("A")).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    let r = restorer(&p, &store, &lk, b.id())
        .restore_user(&cma_lock(&p), false)
        .unwrap();
    assert_eq!(r.restored.len(), 1);
    assert!(r.backup_id.is_some());
    assert_eq!(get(&store, CRED).unwrap(), b"A");
}

#[test]
fn failed_user_restore_is_rolled_back_and_journal_cleared() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = HookStore::default();
    let lk = FakeLocker::default();
    store.inner.set(CRED, "me", &s("A")).unwrap();
    store.inner.set(OWN, "me", &s("own-A")).unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_keychain(CRED, "me", &s("B")).unwrap();
    b.write_keychain(OWN, "me", &s("own-B")).unwrap();
    let id = b.id().to_string();
    drop(b);
    // Newest first: OWN is restored, then the CRED write fails.
    store.on_set(|svc, _| if svc == CRED { Act::Fail } else { Act::Store });
    let err = restorer(&p, &store, &lk, &id)
        .restore_user(&cma_lock(&p), false)
        .unwrap_err();
    assert!(matches!(err, Error::ExternalTool { .. }), "{err:?}");
    assert_eq!(
        get(&store, OWN).unwrap(),
        b"own-B",
        "partial restore undone"
    );
    assert_eq!(get(&store, CRED).unwrap(), b"B");
    assert!(crate::journal::read(&p).unwrap().is_none());
}

#[test]
fn file_and_move_entries_round_trip() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    let root = p.desktop_dir.join("claude-code-sessions");
    std::fs::create_dir_all(root.join("acctA/org1")).unwrap();
    std::fs::write(root.join("acctA/org1/s.json"), b"session").unwrap();
    let f = p.cma_home.join("note.txt");
    std::fs::write(&f, b"before").unwrap();
    let gone = p.cma_home.join("gone.txt");
    std::fs::write(&gone, b"keep me").unwrap();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    b.write_file(&f, b"after").unwrap();
    b.remove_file(&gone).unwrap();
    assert!(!gone.exists());
    std::fs::create_dir_all(root.join("acctB")).unwrap();
    b.move_path(&root.join("acctA/org1"), &root.join("acctB/org1"))
        .unwrap();
    assert!(root.join("acctB/org1/s.json").exists());
    let r = restorer(&p, &store, &lk, b.id()).rollback().unwrap();
    assert!(!r.state_uncertain(), "{r:?}");
    assert_eq!(std::fs::read(&f).unwrap(), b"before");
    assert_eq!(std::fs::read(&gone).unwrap(), b"keep me");
    assert!(root.join("acctA/org1/s.json").exists());
    assert!(!root.join("acctB/org1").exists());
}

fn write_manifest(p: &Paths, m: &Manifest) {
    let dir = p.backups_dir().join(&m.id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec(m).unwrap()).unwrap();
}

fn manifest(id: &str, entries: Vec<Entry>) -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA,
        id: id.into(),
        op: "switch".into(),
        created_at: 0,
        entries,
        extra: Map::new(),
    }
}

fn kc_entry(acct: Option<String>) -> Entry {
    Entry::Keychain {
        service: CRED.into(),
        account: "me".into(),
        existed: true,
        sha256: None,
        backup_account: acct,
        after_sha256: vec![],
    }
}

#[test]
fn manifest_with_dotdot_or_outside_path_rejected() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    let allow = Allowlist::for_paths(&p);
    let id = "20261026T101022Z-switch".to_string();
    let load = || Restorer::load(&p, &store, &lk, &allow, &id).map(|_| ());
    let bad_paths = [
        p.cma_home.join("../escape.json"),
        p.home.join(".ssh/authorized_keys"),
        PathBuf::from("relative.json"),
        p.desktop_dir.join("claude-code-sessions"), // the root itself
    ];
    for bad in bad_paths {
        write_manifest(
            &p,
            &manifest(
                &id,
                vec![Entry::File {
                    path: bad.clone(),
                    sha256_before: None,
                    sha256_after: Some("x".into()),
                    removes: false,
                    copy: None,
                    secret_backup_account: None,
                }],
            ),
        );
        assert!(
            matches!(load(), Err(Error::ManifestRejected(_))),
            "{}",
            bad.display()
        );
    }
    // Symlink inside an allowed root pointing outside it.
    std::fs::create_dir_all(p.desktop_dir.join("claude-code-sessions")).unwrap();
    std::os::unix::fs::symlink(&p.home, p.desktop_dir.join("claude-code-sessions/evil")).unwrap();
    write_manifest(
        &p,
        &manifest(
            &id,
            vec![Entry::Move {
                from: p.desktop_dir.join("claude-code-sessions/evil/.zshrc"),
                to: p.desktop_dir.join("claude-code-sessions/x"),
                sig: None,
                created_dirs: vec![],
            }],
        ),
    );
    assert!(matches!(load(), Err(Error::ManifestRejected(_))));
    // Bad service, foreign backup account.
    for e in [
        Entry::Keychain {
            service: "login-keychain-thing".into(),
            account: "me".into(),
            existed: false,
            sha256: None,
            backup_account: None,
            after_sha256: vec![Some("x".into())],
        },
        kc_entry(Some("20200101T000000Z-other/0".into())),
    ] {
        write_manifest(&p, &manifest(&id, vec![e]));
        assert!(matches!(load(), Err(Error::ManifestRejected(_))));
    }
    // Newer schema.
    let mut m = manifest(&id, vec![]);
    m.schema_version = MANIFEST_SCHEMA + 1;
    write_manifest(&p, &m);
    assert!(matches!(load(), Err(Error::ManifestRejected(_))));
    assert!(matches!(
        Restorer::load(&p, &store, &lk, &allow, "../../etc"),
        Err(Error::ManifestRejected(_))
    ));
}

#[test]
fn symlinked_backup_dir_and_missing_backup_rejected() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    let allow = Allowlist::for_paths(&p);
    let real = t.path().join("elsewhere");
    let id = "20261026T101022Z-switch";
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(
        real.join("manifest.json"),
        serde_json::to_vec(&manifest(id, vec![])).unwrap(),
    )
    .unwrap();
    std::fs::create_dir_all(p.backups_dir()).unwrap();
    std::os::unix::fs::symlink(&real, p.backups_dir().join(id)).unwrap();
    assert!(matches!(
        Restorer::load(&p, &store, &lk, &allow, id),
        Err(Error::Symlink(_))
    ));
    let err = Restorer::load(&p, &store, &lk, &allow, "20261026T101023Z-switch")
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.code(), "backup_missing");
}

#[test]
fn backup_rejects_write_outside_allowlist() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let lk = FakeLocker::default();
    let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
    let outside = p.home.join("other.json");
    assert!(matches!(
        b.write_file(&outside, b"x"),
        Err(Error::ManifestRejected(_))
    ));
    assert!(!outside.exists());
}

#[test]
fn clean_keeps_newest_protects_journal_backup_and_deletes_keychain_items() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let ids = [
        "20260101T000000Z-switch",
        "20260102T000000Z-switch",
        "20260103T000000Z-switch",
    ];
    for id in ids {
        let acct = format!("{id}/0");
        store.set(BACKUP_SERVICE, &acct, &s("old")).unwrap();
        write_manifest(&p, &manifest(id, vec![kc_entry(Some(acct))]));
    }
    // The open journal names the oldest backup; clean finds it itself.
    std::fs::write(
        p.journal_file(),
        serde_json::to_vec(
            &json!({"op":"switch","target":"cli","from":null,"to":null,"backup_id":ids[0]}),
        )
        .unwrap(),
    )
    .unwrap();
    let rep = clean(&p, &cma_lock(&p), &store, 1).unwrap();
    assert_eq!(rep.removed, vec![ids[1].to_string()]);
    assert_eq!(rep.skipped.len(), 1);
    assert_eq!(rep.skipped[0].id, ids[0]);
    assert_eq!(store.count(BACKUP_SERVICE), 2);
    assert!(p.backups_dir().join(ids[0]).is_dir(), "protected");
    assert!(p.backups_dir().join(ids[2]).is_dir(), "newest kept");
}

#[test]
fn list_shows_newest_first_with_labels_journal_mark_and_problems() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    assert!(list(&p).unwrap().is_empty(), "no backups dir yet");
    let (a, b) = ("20260101T000000Z-switch", "20260102T000000Z-store");
    write_manifest(&p, &manifest(a, vec![kc_entry(Some(format!("{a}/0")))]));
    std::fs::create_dir_all(p.backups_dir().join(b)).unwrap();
    std::fs::write(p.backups_dir().join(b).join("manifest.json"), b"{").unwrap();
    std::fs::write(
        p.journal_file(),
        serde_json::to_vec(
            &json!({"op":"switch","target":"cli","from":null,"to":null,"backup_id":a}),
        )
        .unwrap(),
    )
    .unwrap();
    let l = list(&p).unwrap();
    assert_eq!(l.len(), 2);
    assert_eq!(l[0].id, b);
    assert!(l[0].problem.is_some());
    assert!(!l[0].in_journal);
    assert_eq!(l[1].id, a);
    assert_eq!(l[1].op, "switch");
    assert!(l[1].in_journal);
    assert!(
        l[1].entries[0].starts_with("keychain "),
        "{:?}",
        l[1].entries
    );
}

#[test]
fn clean_skips_unreadable_or_newer_manifests() {
    let t = tempfile::tempdir().unwrap();
    let p = test_paths(t.path());
    let store = MemoryStore::new();
    let bad = "20260101T000000Z-switch";
    let newer = "20260102T000000Z-switch";
    let no_manifest = "20260103T000000Z-switch";
    let empty = "20260104T000000Z-switch";
    let good = "20260105T000000Z-switch";
    for id in [bad, newer, good] {
        store
            .set(BACKUP_SERVICE, &format!("{id}/0"), &s("old"))
            .unwrap();
    }
    // Unknown entry kind from a newer cma: not parseable here.
    std::fs::create_dir_all(p.backups_dir().join(bad)).unwrap();
    std::fs::write(
        p.backups_dir().join(bad).join("manifest.json"),
        serde_json::to_vec(&json!({"id": bad, "op":"switch","created_at":0,
            "entries":[{"kind":"future_thing","backup_account": format!("{bad}/0")}]}))
        .unwrap(),
    )
    .unwrap();
    let mut m = manifest(newer, vec![kc_entry(Some(format!("{newer}/0")))]);
    m.schema_version = MANIFEST_SCHEMA + 1;
    write_manifest(&p, &m);
    std::fs::create_dir_all(p.backups_dir().join(no_manifest).join("files")).unwrap();
    std::fs::create_dir_all(p.backups_dir().join(empty)).unwrap();
    write_manifest(
        &p,
        &manifest(good, vec![kc_entry(Some(format!("{good}/0")))]),
    );

    let rep = clean(&p, &cma_lock(&p), &store, 0).unwrap();
    let mut removed = rep.removed.clone();
    removed.sort();
    assert_eq!(removed, vec![empty.to_string(), good.to_string()]);
    let mut skipped: Vec<&str> = rep.skipped.iter().map(|s| s.id.as_str()).collect();
    skipped.sort();
    assert_eq!(skipped, vec![bad, newer, no_manifest]);
    for id in [bad, newer, no_manifest] {
        assert!(p.backups_dir().join(id).is_dir(), "{id} kept");
    }
    // Only the good backup's item was deleted.
    assert_eq!(store.count(BACKUP_SERVICE), 2);
    assert!(
        store
            .get(BACKUP_SERVICE, &format!("{bad}/0"))
            .unwrap()
            .is_some()
    );
}

/// `{:?}` and `{}` of every core error variant reachable with secret
/// values in the inputs never contain the secret.
mod leak {
    use super::*;
    use proptest::prelude::*;
    use regex::Regex;

    fn check(e: &Error, secret: &str) {
        let long_hex = Regex::new(r"[0-9a-fA-F]{33,}").unwrap();
        for out in [format!("{e:?}"), format!("{e}")] {
            assert!(!out.contains(secret), "secret leaked: {out}");
            assert!(!long_hex.is_match(&out), "long hex run: {out}");
        }
    }

    fn all_variants(secret: &str) -> Vec<Error> {
        let t = tempfile::tempdir().unwrap();
        let p = test_paths(t.path());
        let store = MemoryStore::new();
        let lk = FakeLocker::default();
        let sec = Secret::new(secret.as_bytes().to_vec());
        let lock = cma_lock(&p);
        let mut errs = Vec::new();

        // RestoreConflict: the live item now holds the secret.
        store.set(CRED, "me", &s("A")).unwrap();
        let mut b = Backup::create(&p, &store, &lk, "switch").unwrap();
        b.write_keychain(CRED, "me", &sec).unwrap();
        let id = b.id().to_string();
        drop(b);
        store
            .set(CRED, "me", &Secret::new(format!("{secret}0").into_bytes()))
            .unwrap();
        errs.push(
            restorer(&p, &store, &lk, &id)
                .restore_user(&lock, false)
                .unwrap_err(),
        );

        // StateUncertain: the backup item holds the secret but its hash
        // does not match the manifest.
        store.set(CRED, "me", &sec).unwrap();
        store
            .set(
                BACKUP_SERVICE,
                &format!("{id}/0"),
                &Secret::new(format!("{secret}1").into_bytes()),
            )
            .unwrap();
        errs.push(
            restorer(&p, &store, &lk, &id)
                .restore_user(&lock, false)
                .unwrap_err(),
        );
        let r = restorer(&p, &store, &lk, &id).rollback().unwrap();
        assert!(r.state_uncertain());
        for line in r.uncertain.iter().chain(&r.warnings) {
            assert!(!line.contains(secret), "{line}");
        }

        // ConcurrentWrite: Claude writes the secret before cma's lock.
        let racing = FakeLocker::default();
        let st = Rc::new(MemoryStore::new());
        st.set(CRED, "me", &s("A")).unwrap();
        let st2 = st.clone();
        let sec2 = sec.clone();
        *racing.on_acquire.borrow_mut() =
            Some(Box::new(move || st2.set(CRED, "me", &sec2).unwrap()));
        let mut b = Backup::create(&p, &*st, &racing, "race").unwrap();
        errs.push(b.write_keychain(CRED, "me", &s("B")).unwrap_err());
        drop(b);

        // Json and Invalid: JSON files whose contents are the secret.
        std::fs::write(&p.claude_json, format!("{{\"oauthAccount\": \"{secret}\" ")).unwrap();
        let mut b = Backup::create(&p, &store, &lk, "json").unwrap();
        errs.push(
            b.write_json_keys(&p.claude_json, &[("oauthAccount".into(), None)], &[])
                .unwrap_err(),
        );
        std::fs::write(&p.claude_json, format!("\"{secret}\"")).unwrap();
        errs.push(
            b.write_json_keys(&p.claude_json, &[("oauthAccount".into(), None)], &[])
                .unwrap_err(),
        );

        // Symlink: a symlink to a file holding the secret, at a path cma
        // opens with O_NOFOLLOW.
        let target = t.path().join("target.json");
        std::fs::write(&target, format!("{{\"k\":\"{secret}\"}}")).unwrap();
        let link = p.cma_home.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        errs.push(fsutil::read_nofollow(&link).unwrap_err());
        errs.push(fsutil::atomic_write(&link, sec.expose()).unwrap_err());

        // Io: a directory where a file holding the secret is expected.
        let d = p.cma_home.join("dir.bin");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("inner"), secret).unwrap();
        errs.push(b.write_file(&d, sec.expose()).unwrap_err());
        drop(b);

        // ManifestRejected / BackupMissing: manifests carrying secret hashes.
        let bad_id = "20260101T000000Z-switch";
        let mut m = manifest(bad_id, vec![kc_entry(Some("20200101T000000Z-x/0".into()))]);
        if let Entry::Keychain { sha256, .. } = &mut m.entries[0] {
            *sha256 = Some(sha256_hex(secret.as_bytes()));
        }
        write_manifest(&p, &m);
        let allow = Allowlist::for_paths(&p);
        errs.push(
            Restorer::load(&p, &store, &lk, &allow, bad_id)
                .map(|_| ())
                .unwrap_err(),
        );
        errs.push(
            Restorer::load(&p, &store, &lk, &allow, "20260101T000001Z-switch")
                .map(|_| ())
                .unwrap_err(),
        );

        // UnsafeHome: an open-mode CMA_HOME holding a file with the secret.
        let open = t.path().join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::write(open.join("x"), secret).unwrap();
        let op = Paths::from_env(&MapEnv::new([
            ("HOME", p.home.to_str().unwrap()),
            ("CMA_HOME", open.to_str().unwrap()),
            ("CMA_ALLOW_HOME_OVERRIDE", "1"),
        ]))
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        errs.push(op.ensure_cma_home().unwrap_err());

        // Invalid: a hex-only Keychain name is refused and echoed truncated.
        errs.push(
            crate::secret::validate_name("keychain account", &format!("{secret}\"")).unwrap_err(),
        );
        errs
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn core_error_variants_never_show_secret(secret in "[0-9a-f]{40,300}") {
            let errs = all_variants(&secret);
            let codes: std::collections::BTreeSet<&str> = errs.iter().map(Error::code).collect();
            for want in ["restore_conflict", "state_uncertain", "concurrent_write", "invalid_json",
                         "invalid", "symlink", "io", "manifest_rejected", "backup_missing",
                         "unsafe_home"] {
                prop_assert!(codes.contains(want), "missing {} in {:?}", want, codes);
            }
            for e in &errs {
                check(e, &secret);
            }
        }
    }
}
