//! Export and import of stored CLI credentials.
//!
//! An export file holds a refresh token in plain text, so it is written only
//! after an explicit confirmation, mode 0600 inside a 0700 directory, and
//! never over an existing file. Import identifies every credential by its
//! token (fail closed); the file's own `account_key` is only checked against
//! that, never trusted. Desktop credentials are machine-bound and are not
//! exported.
//!
//! Importing over an account cma already stores needs explicit consent:
//! an export is a snapshot, and its refresh
//! token may have been rotated since (by cma or Claude Code), so replacing
//! a newer stored grant with it can leave the account needing a new login.
//! Interactive callers may ask; `--json` callers must pass `--replace`
//! ([`Confirm::NonInteractive`] `force`).

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::account::{StoreOpts, Stored, store_credential};
use crate::cli_target::{OAUTH_KEY, Warning, oauth_fingerprint, stored_oauth};
use crate::error::{Error, Result};
use crate::fsutil;
use crate::identity::resolve;
use crate::lock::AccountLock;
use crate::registry::AccountKind;
use crate::switch::{Confirm, confirm};
use crate::sync::Session;

/// Options of [`import`].
pub struct ImportOpts<'a> {
    /// Needs a single file.
    pub alias: Option<&'a str>,
    /// Consent to replace accounts that are already stored: ask
    /// (interactive), or `force` = the `--replace` flag.
    pub replace: Confirm<'a>,
}

/// Outcome of [`import`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub stored: Vec<Stored>,
    /// Accounts whose stored credential already was the imported one
    /// (nothing written, no consent needed).
    pub unchanged: Vec<String>,
    pub warnings: Vec<Warning>,
}

/// Export file name suffix.
pub const EXPORT_SUFFIX: &str = ".credential.json";
/// `format` value of an export file.
pub const EXPORT_FORMAT: &str = "cma-credential/1";

/// The confirmation text a caller must show before [`export`].
pub const EXPORT_WARNING: &str = "the exported files contain refresh tokens: anyone who reads them can use these accounts until the tokens expire";

fn export_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(Error::Symlink(dir.to_path_buf())),
        Ok(m) if !m.is_dir() => Err(Error::Invalid {
            what: "export dir (not a directory)",
            value: dir.display().to_string(),
        }),
        Ok(m) if m.mode() & 0o777 != 0o700 => Err(Error::Invalid {
            what: "export dir (must be mode 0700; use a new directory)",
            value: dir.display().to_string(),
        }),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::io(dir, e)),
        Err(e) => Err(Error::io(dir, e)),
    }
}

/// Write `<key>.credential.json` for each key into `dir`. `confirmed` must
/// be true (the caller showed [`EXPORT_WARNING`] and the user agreed).
pub fn export(
    s: &Session<'_>,
    dir: &Path,
    keys: &[String],
    confirmed: bool,
) -> Result<Vec<PathBuf>> {
    if !confirmed {
        return Err(Error::ConfirmationRequired(EXPORT_WARNING.into()));
    }
    let mut todo = Vec::new();
    for key in keys {
        let a = s
            .registry
            .account(key)
            .ok_or_else(|| Error::NotFound(format!("account {key}")))?;
        if a.kind != AccountKind::Oauth {
            return Err(Error::Unsupported(format!(
                "exporting {key} (not a Claude.ai login)"
            )));
        }
        // Under the account's lock: never a grant a refresh is rotating.
        let oauth = {
            let _account = AccountLock::acquire(s.ctx.paths, key)?;
            stored_oauth(s.ctx.store, key)?
        }
        .ok_or_else(|| Error::NotFound(format!("stored credential of {key}")))?;
        let path = dir.join(format!("{key}{EXPORT_SUFFIX}"));
        todo.push((a, oauth, path));
    }
    export_dir(dir)?;
    for (_, _, path) in &todo {
        if fsutil::existing_mode(path)?.is_some() {
            return Err(Error::Invalid {
                what: "export file (already exists)",
                value: path.display().to_string(),
            });
        }
    }
    let mut written = Vec::new();
    for (a, oauth, path) in todo {
        let doc = serde_json::json!({
            "format": EXPORT_FORMAT,
            "account_key": a.key,
            "email": a.email,
            "org_name": a.org_name,
            "credential": { OAUTH_KEY: oauth },
        });
        let mut bytes =
            Zeroizing::new(serde_json::to_vec_pretty(&doc).map_err(|e| Error::json("export", &e))?);
        drop(doc);
        bytes.push(b'\n');
        fsutil::atomic_write_mode(&path, &bytes, 0o600)?;
        written.push(path);
    }
    Ok(written)
}

/// Files an import of `path` reads: the file itself, or every
/// `*.credential.json` directly inside a directory.
fn import_files(path: &Path) -> Result<Vec<PathBuf>> {
    let m = std::fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    if m.file_type().is_symlink() {
        return Err(Error::Symlink(path.to_path_buf()));
    }
    if !m.is_dir() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut v: Vec<PathBuf> = std::fs::read_dir(path)
        .map_err(|e| Error::io(path, e))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(EXPORT_SUFFIX))
        .collect();
    v.sort();
    if v.is_empty() {
        return Err(Error::NotFound(format!(
            "*{EXPORT_SUFFIX} files in {}",
            path.display()
        )));
    }
    Ok(v)
}

/// Import exported credentials (or a raw `{"claudeAiOauth": …}` item). Each
/// is identified by its token and stored; nothing is deleted. Replacing an
/// account that is already stored needs `opts.replace` consent (module
/// docs); without it nothing is imported.
pub fn import(s: &mut Session<'_>, path: &Path, opts: &ImportOpts<'_>) -> Result<ImportReport> {
    let alias = opts.alias;
    let files = import_files(path)?;
    if alias.is_some() && files.len() != 1 {
        return Err(Error::Invalid {
            what: "--alias with several files",
            value: path.display().to_string(),
        });
    }
    // Identify every file first: one bad file imports nothing.
    let mut todo = Vec::new();
    for f in &files {
        let bytes = Zeroizing::new(
            fsutil::read_nofollow(f)?.ok_or_else(|| Error::NotFound(f.display().to_string()))?,
        );
        reject_duplicate_keys(&bytes, f)?;
        let doc: Value =
            serde_json::from_slice(&bytes).map_err(|e| Error::json("credential file", &e))?;
        let claimed = doc
            .get("account_key")
            .and_then(Value::as_str)
            .map(str::to_string);
        let oauth = doc
            .get("credential")
            .unwrap_or(&doc)
            .get(OAUTH_KEY)
            .filter(|v| v.is_object())
            .cloned()
            .ok_or_else(|| Error::Invalid {
                what: "credential file (no claudeAiOauth)",
                value: f.display().to_string(),
            })?;
        drop(doc);
        let (key, profile) =
            resolve(&s.registry, s.ctx.profile, &oauth, s.ctx.now_ms(), None).require()?;
        if let Some(c) = claimed
            && c != key
        {
            return Err(Error::Unidentified(format!(
                "{} claims {c} but its token belongs to {key}",
                f.display()
            )));
        }
        todo.push((key, profile, oauth));
    }
    // A credential identical to the stored one changes nothing: no consent,
    // no write.
    let mut unchanged = Vec::new();
    let mut fresh = Vec::new();
    for (key, profile, oauth) in todo {
        match stored_oauth(s.ctx.store, &key)? {
            Some(cur) if oauth_fingerprint(&cur) == oauth_fingerprint(&oauth) => {
                if !unchanged.contains(&key) {
                    unchanged.push(key);
                }
            }
            _ => fresh.push((key, profile, oauth)),
        }
    }
    let todo = fresh;
    // Consent before anything is written: one prompt for all files.
    let mut existing = Vec::new();
    for (key, _, _) in &todo {
        if s.ctx
            .store
            .get(crate::cli_target::OWN_SERVICE, key)?
            .is_some()
            && !existing.contains(key)
        {
            existing.push(key.clone());
        }
    }
    let mut warnings = Vec::new();
    if !existing.is_empty() {
        let msg = format!(
            "{} already stored; importing replaces the stored grant, and an exported grant may already have been rotated (then the account needs `cma login` again)",
            existing.join(", ")
        );
        confirm(&opts.replace, &msg, "import cancelled", "--replace")?;
        for key in &existing {
            warnings.push(Warning::new(
                "grant_may_be_rotated",
                format!("replaced the stored login of {key} with the imported one; if its refresh token was rotated after the export, {key} needs `cma login` again"),
            ));
        }
    }
    let mut out = Vec::new();
    for (key, profile, oauth) in todo {
        out.push(store_credential(
            s,
            &key,
            profile.as_ref(),
            &oauth,
            &StoreOpts {
                kind: AccountKind::Oauth,
                alias,
                oauth_account_hint: None,
            },
        )?);
    }
    Ok(ImportReport {
        stored: out,
        unchanged,
        warnings,
    })
}

/// Fails when any JSON object in `bytes` repeats a key: `serde_json::Value`
/// silently keeps the last one, so such a file is ambiguous. Only the
/// position is reported (key names and values stay out of messages).
fn reject_duplicate_keys(bytes: &[u8], file: &Path) -> Result<()> {
    use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

    const DUP: &str = "duplicate key";

    struct NoDup;
    impl<'de> Deserialize<'de> for NoDup {
        fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            d.deserialize_any(NoDupVisitor)
        }
    }
    struct NoDupVisitor;
    impl<'de> Visitor<'de> for NoDupVisitor {
        type Value = NoDup;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, _: bool) -> std::result::Result<NoDup, E> {
            Ok(NoDup)
        }
        fn visit_i64<E>(self, _: i64) -> std::result::Result<NoDup, E> {
            Ok(NoDup)
        }
        fn visit_u64<E>(self, _: u64) -> std::result::Result<NoDup, E> {
            Ok(NoDup)
        }
        fn visit_f64<E>(self, _: f64) -> std::result::Result<NoDup, E> {
            Ok(NoDup)
        }
        fn visit_str<E>(self, _: &str) -> std::result::Result<NoDup, E> {
            Ok(NoDup)
        }
        fn visit_unit<E>(self) -> std::result::Result<NoDup, E> {
            Ok(NoDup)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<NoDup, A::Error> {
            while a.next_element::<NoDup>()?.is_some() {}
            Ok(NoDup)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> std::result::Result<NoDup, A::Error> {
            let mut seen = std::collections::HashSet::new();
            while let Some(k) = m.next_key::<String>()? {
                if !seen.insert(k) {
                    return Err(de::Error::custom(DUP));
                }
                m.next_value::<NoDup>()?;
            }
            Ok(NoDup)
        }
    }
    match serde_json::from_slice::<NoDup>(bytes) {
        Err(e) if e.to_string().starts_with(DUP) => Err(Error::Invalid {
            what: "credential file (a JSON object repeats a key, so the credential is ambiguous; nothing was imported; export it again)",
            value: format!("{} line {} column {}", file.display(), e.line(), e.column()),
        }),
        // Other parse errors are reported by the real parse.
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::remove;
    use crate::cli_target::testkit::*;
    use crate::sync::begin;
    use crate::sync::tests::add_account;
    use std::os::unix::fs::PermissionsExt;

    fn opts(alias: Option<&str>, replace: bool) -> ImportOpts<'_> {
        ImportOpts {
            alias,
            replace: Confirm::NonInteractive { force: replace },
        }
    }

    #[test]
    fn import_over_a_stored_account_needs_replace() {
        let w = World::new();
        let (b_old, b_new) = (oauth("B-old"), oauth("B-new"));
        add_account(&w, "B::oB", "b@x", &b_new);
        w.profile.add("at-B-old", "B", "oB", "b@x");
        let f = w.tmp.path().join("b.credential.json");
        let doc =
            serde_json::json!({"account_key": "B::oB", "credential": {"claudeAiOauth": b_old}});
        std::fs::write(&f, serde_json::to_vec(&doc).unwrap()).unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        // --json without --replace.
        let e = import(&mut s, &f, &opts(None, false)).unwrap_err();
        assert_eq!(e.code(), "confirmation_required");
        assert!(e.to_string().contains("pass --replace"), "{e}");
        assert!(e.to_string().contains("rotated"), "{e}");
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b_new);
        // Interactive, answered no.
        let asked = std::cell::Cell::new(0);
        let no = |m: &str| {
            assert!(m.contains("B::oB already stored"), "{m}");
            asked.set(asked.get() + 1);
            false
        };
        let e = import(
            &mut s,
            &f,
            &ImportOpts {
                alias: None,
                replace: Confirm::Interactive(&no),
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), "confirmation_required");
        assert_eq!(asked.get(), 1);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b_new);
        // Interactive, answered yes.
        let yes = |_: &str| true;
        let r = import(
            &mut s,
            &f,
            &ImportOpts {
                alias: None,
                replace: Confirm::Interactive(&yes),
            },
        )
        .unwrap();
        assert!(r.stored[0].replaced);
        assert!(
            r.warnings
                .iter()
                .any(|x| x.code == "grant_may_be_rotated" && x.message.contains("B::oB")),
            "{:?}",
            r.warnings
        );
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b_old);
        // --replace, over a stored grant that differs again.
        let b_newer = oauth("B-newer");
        crate::secret::SecretStore::set(
            &w.store,
            crate::cli_target::OWN_SERVICE,
            "B::oB",
            &crate::cli_target::oauth_only_item(&b_newer),
        )
        .unwrap();
        let r = import(&mut s, &f, &opts(None, true)).unwrap();
        assert!(r.stored[0].replaced);
        assert_eq!(r.warnings.len(), 1);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b_old);
    }

    #[test]
    fn importing_the_stored_credential_again_needs_no_consent() {
        let w = World::new();
        let b = oauth("B");
        add_account(&w, "B::oB", "b@x", &b);
        let f = w.tmp.path().join("b.credential.json");
        let doc = serde_json::json!({"account_key": "B::oB", "credential": {"claudeAiOauth": b}});
        std::fs::write(&f, serde_json::to_vec(&doc).unwrap()).unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let backups = w.store.count(crate::backup::BACKUP_SERVICE);
        let never = |m: &str| -> bool { panic!("asked: {m}") };
        let r = import(
            &mut s,
            &f,
            &ImportOpts {
                alias: None,
                replace: Confirm::Interactive(&never),
            },
        )
        .unwrap();
        assert!(r.stored.is_empty());
        assert_eq!(r.unchanged, vec!["B::oB".to_string()]);
        assert!(r.warnings.is_empty());
        // --json without --replace works too, and nothing is written.
        let r = import(&mut s, &f, &opts(None, false)).unwrap();
        assert_eq!(r.unchanged, vec!["B::oB".to_string()]);
        assert_eq!(w.store.count(crate::backup::BACKUP_SERVICE), backups);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b);
    }

    #[test]
    fn import_refuses_duplicate_keys_with_a_clear_message() {
        let w = World::new();
        w.profile.add("at-B", "B", "oB", "b@x");
        let b = serde_json::to_string(&oauth("B")).unwrap();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        for (name, text) in [
            (
                "top.credential.json",
                format!(r#"{{"credential": {{"claudeAiOauth": {b}}}, "credential": {{}}}}"#),
            ),
            (
                "inner.credential.json",
                format!(r#"{{"claudeAiOauth": {b}, "claudeAiOauth": {b}}}"#),
            ),
        ] {
            let f = w.tmp.path().join(name);
            std::fs::write(&f, text).unwrap();
            let e = import(&mut s, &f, &opts(None, true)).unwrap_err();
            assert_eq!(e.code(), "invalid", "{e}");
            let msg = e.to_string();
            assert!(msg.contains("repeats a key"), "{msg}");
            assert!(msg.contains("nothing was imported"), "{msg}");
            assert!(!msg.contains("at-B") && !msg.contains("rt-B"), "{msg}");
        }
        assert!(stored_oauth(&w.store, "B::oB").unwrap().is_none());
    }

    #[test]
    fn export_import_round_trip() {
        let w = World::new();
        let (a, b) = (oauth("A"), oauth("B"));
        add_account(&w, "A::oA", "a@x", &a);
        add_account(&w, "B::oB", "b@x", &b);
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let dir = w.tmp.path().join("export");
        let keys = vec!["A::oA".to_string(), "B::oB".to_string()];
        assert_eq!(
            export(&s, &dir, &keys, false).unwrap_err().code(),
            "confirmation_required"
        );
        assert!(!dir.exists());
        let files = export(&s, &dir, &keys, true).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for f in &files {
            assert_eq!(fsutil::existing_mode(f).unwrap(), Some(0o600));
        }
        assert!(export(&s, &dir, &keys, true).is_err(), "never overwrites");
        // Remove both, then import the directory back.
        remove(&mut s, "A::oA", true).unwrap();
        remove(&mut s, "B::oB", true).unwrap();
        w.profile.add("at-A", "A", "oA", "a@x");
        w.profile.add("at-B", "B", "oB", "b@x");
        let got = import(&mut s, &dir, &opts(None, false)).unwrap().stored;
        assert_eq!(got.len(), 2);
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b);
        assert_eq!(s.registry.account("B::oB").unwrap().email, "b@x");
        // Files are not deleted by import.
        assert!(files.iter().all(|f| f.exists()));
    }

    #[test]
    fn import_refuses_mismatched_claim_and_unidentified() {
        let w = World::new();
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let f = w.tmp.path().join("x.credential.json");
        let doc = serde_json::json!({"account_key": "B::oB", "credential": {"claudeAiOauth": oauth("A")}});
        std::fs::write(&f, serde_json::to_vec(&doc).unwrap()).unwrap();
        // Unknown token: no identity.
        assert_eq!(
            import(&mut s, &f, &opts(None, false)).unwrap_err().code(),
            "unidentified"
        );
        w.profile.add("at-A", "A", "oA", "a@x");
        let e = import(&mut s, &f, &opts(None, false)).unwrap_err();
        assert!(e.to_string().contains("claims B::oB"), "{e}");
        assert!(stored_oauth(&w.store, "A::oA").unwrap().is_none());
        assert!(stored_oauth(&w.store, "B::oB").unwrap().is_none());
        // A raw Claude item is accepted too.
        std::fs::write(&f, live_item(&oauth("A"))).unwrap();
        let got = import(&mut s, &f, &opts(Some("raw"), false))
            .unwrap()
            .stored;
        assert_eq!(got[0].key, "A::oA");
        assert_eq!(
            s.registry.account("A::oA").unwrap().alias.as_deref(),
            Some("raw")
        );
    }

    #[test]
    fn export_dir_must_be_private() {
        let w = World::new();
        add_account(&w, "A::oA", "a@x", &oauth("A"));
        let ctx = w.ctx();
        let s = begin(&ctx).unwrap();
        let dir = w.tmp.path().join("open");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(export(&s, &dir, &["A::oA".into()], true).is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[test]
    fn export_reads_the_grant_after_a_running_refresh() {
        use crate::secret::SecretStore;
        let w = World::new();
        add_account(&w, "A::oA", "a@x", &oauth("A"));
        let rotated = oauth("A2");
        let (tx, rx) = std::sync::mpsc::channel();
        let files = std::thread::scope(|sc| {
            let (paths, store, rotated) = (&w.paths, &w.store, &rotated);
            sc.spawn(move || {
                // A refresher holding A's lock rotates its stored grant.
                let g = AccountLock::acquire(paths, "A::oA").unwrap();
                tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(200));
                store
                    .set(
                        crate::cli_target::OWN_SERVICE,
                        "A::oA",
                        &crate::cli_target::oauth_only_item(rotated),
                    )
                    .unwrap();
                drop(g);
            });
            rx.recv().unwrap();
            let ctx = w.ctx();
            let s = begin(&ctx).unwrap();
            export(&s, &w.tmp.path().join("ex"), &["A::oA".into()], true).unwrap()
        });
        let doc: Value = serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
        assert_eq!(doc["credential"][OAUTH_KEY], rotated);
    }
}
