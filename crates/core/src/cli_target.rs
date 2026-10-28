//! Claude Code CLI target: where the live credential lives, how it is shaped,
//! and the context every CLI-target operation runs with.
//!
//! # Live item
//!
//! Keychain service, per Claude Code 2.1.310 (verified
//! against that version): `Claude Code-credentials` plus a suffix. The suffix is empty
//! unless `CLAUDE_SECURESTORAGE_CONFIG_DIR` is set (it takes precedence; an
//! empty string means no suffix) or `CLAUDE_CONFIG_DIR` is set, in which case
//! it is `-` + the first 8 hex chars of sha256 of the **raw** directory
//! string: no trailing-slash trimming, no symlink resolution. The binary also
//! NFC-normalizes the string; only ASCII paths were verified, so a
//! non-ASCII directory is refused instead of guessed.
//!
//! Keychain account: `$USER` if it matches `^[a-zA-Z0-9._-]+$`, else
//! `claude-code-user`.
//!
//! The item is a JSON object. Its `claudeAiOauth` key is the credential;
//! every other top-level key (`mcpOAuth`, …) belongs to Claude Code and is
//! carried through byte-for-byte by [`replace_oauth`].

use std::path::PathBuf;

use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use serde_json::Value;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::identity::ProfileClient;
use crate::lock::StorageLockAcquirer;
use crate::paths::{Env, Paths};
use crate::secret::{Secret, SecretStore, sha256_hex};

/// Base Keychain service of Claude Code's credential item.
pub const LIVE_SERVICE_BASE: &str = "Claude Code-credentials";
/// Keychain account used when `$USER` is unusable.
pub const FALLBACK_KEYCHAIN_ACCOUNT: &str = "claude-code-user";
/// cma's own Keychain service for stored credentials (account = key).
pub const OWN_SERVICE: &str = "claude-multi-auth";
/// Top-level key of the credential inside the item.
pub const OAUTH_KEY: &str = "claudeAiOauth";
/// Claude Code's plaintext fallback file (cma never uses or creates it).
pub const PLAINTEXT_CREDENTIALS_FILE: &str = ".credentials.json";
/// Environment variables that override the Keychain login in `claude`.
pub const OVERRIDE_ENV_VARS: [&str; 2] = ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"];

/// A user-facing warning (`warnings[]` in the JSON envelope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub code: &'static str,
    pub message: String,
}

impl Warning {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Warning {
            code,
            message: message.into(),
        }
    }
}

/// Service name for a config dir given as a raw string.
pub fn service_for_dir(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Ok(LIVE_SERVICE_BASE.to_string());
    }
    if !raw.is_ascii() {
        return Err(Error::Unsupported(
            "a Claude config dir with non-ASCII characters (Claude Code NFC-normalizes it before hashing; only ASCII paths are verified)".into(),
        ));
    }
    Ok(format!(
        "{LIVE_SERVICE_BASE}-{}",
        &sha256_hex(raw.as_bytes())[..8]
    ))
}

/// Keychain account rule.
pub fn keychain_account(env: &dyn Env) -> String {
    match env.var("USER") {
        Some(u)
            if !u.is_empty()
                && u.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) =>
        {
            u
        }
        _ => FALLBACK_KEYCHAIN_ACCOUNT.to_string(),
    }
}

/// Service of the live item for the caller's environment.
pub fn live_service(env: &dyn Env) -> Result<String> {
    match env.var("CLAUDE_SECURESTORAGE_CONFIG_DIR") {
        Some(s) => service_for_dir(&s),
        None => match env.var("CLAUDE_CONFIG_DIR").filter(|c| !c.is_empty()) {
            Some(c) => service_for_dir(&c),
            None => Ok(LIVE_SERVICE_BASE.to_string()),
        },
    }
}

/// Where the live CLI login lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveTarget {
    pub service: String,
    pub account: String,
}

impl LiveTarget {
    pub fn from_env(env: &dyn Env) -> Result<Self> {
        Ok(LiveTarget {
            service: live_service(env)?,
            account: keychain_account(env),
        })
    }
}

/// Milliseconds since the Unix epoch.
pub fn system_now_ms() -> i64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    d.as_millis() as i64
}

/// Everything a CLI-target operation needs, injected so tests use
/// `MemoryStore`, a temp HOME and fakes.
pub struct Ctx<'a> {
    pub paths: &'a Paths,
    pub env: &'a dyn Env,
    /// The Keychain (the live item, cma's own items and backups).
    pub store: &'a dyn SecretStore,
    /// Claude Code's `.storage-write` lock for the live item's dir.
    pub locker: &'a dyn StorageLockAcquirer,
    pub profile: &'a dyn ProfileClient,
    /// The process list (running `claude` sessions, Claude Desktop).
    pub procs: &'a dyn crate::procs::ProcessLister,
    pub now_ms: fn() -> i64,
}

impl Ctx<'_> {
    pub fn live(&self) -> Result<LiveTarget> {
        LiveTarget::from_env(self.env)
    }

    pub fn now_ms(&self) -> i64 {
        (self.now_ms)()
    }

    pub fn now_secs(&self) -> i64 {
        self.now_ms() / 1000
    }

    /// Warnings about environment variables that make a CLI switch moot.
    pub fn env_warnings(&self) -> Vec<Warning> {
        OVERRIDE_ENV_VARS
            .iter()
            .filter(|k| self.env.var(k).is_some_and(|v| !v.is_empty()))
            .map(|k| {
                Warning::new(
                    "env_override",
                    format!("{k} is set in this shell; `claude` started from it ignores the Keychain login, so a CLI switch has no effect there"),
                )
            })
            .collect()
    }

    /// Warn if Claude Code's plaintext fallback file exists.
    pub fn plaintext_warning(&self) -> Option<Warning> {
        let p: PathBuf = self
            .paths
            .secure_storage_dir
            .join(PLAINTEXT_CREDENTIALS_FILE);
        std::fs::symlink_metadata(&p).is_ok().then(|| {
            Warning::new(
                "plaintext_credentials",
                format!(
                    "{} exists: Claude Code fell back to a plaintext credential file; cma never reads or writes it",
                    p.display()
                ),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Item shape
// ---------------------------------------------------------------------------

/// Top-level entries of an item, values kept as their exact source bytes.
pub struct RawItem(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for RawItem {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawItem;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut m: A,
            ) -> std::result::Result<RawItem, A::Error> {
                let mut v = Vec::new();
                while let Some((k, val)) = m.next_entry::<String, Box<RawValue>>()? {
                    v.push((k, val));
                }
                Ok(RawItem(v))
            }
        }
        d.deserialize_map(V)
    }
}

impl RawItem {
    /// Parse an item; anything but a JSON object is refused.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // Shape check first, without serde's "invalid type" message.
        let first = bytes.iter().find(|b| !b.is_ascii_whitespace());
        if first.is_some_and(|b| *b != b'{') {
            // Valid JSON of another type, or garbage: report which.
            return match serde_json::from_slice::<serde::de::IgnoredAny>(bytes) {
                Ok(_) => Err(Error::Invalid {
                    what: "credential item (not a JSON object)",
                    value: String::new(),
                }),
                Err(e) => Err(Error::json("credential item", &e)),
            };
        }
        let item: RawItem =
            serde_json::from_slice(bytes).map_err(|e| Error::json("credential item", &e))?;
        // Duplicate keys: serde_json's `Value` keeps the last, this type the
        // first, so the credential would be ambiguous. Fail closed.
        if item.0.iter().filter(|(k, _)| k == OAUTH_KEY).count() > 1 {
            return Err(Error::Invalid {
                what: "credential item (duplicate claudeAiOauth keys, so the login is ambiguous and cma will not use it; Claude Code never writes such an item: log in again in Claude Code with /login to rewrite it, then retry)",
                value: String::new(),
            });
        }
        Ok(item)
    }

    pub fn get(&self, key: &str) -> Option<&RawValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| &**v)
    }

    /// Top-level keys other than `claudeAiOauth`, with their raw bytes.
    pub fn others(&self) -> Vec<(&str, &str)> {
        self.0
            .iter()
            .filter(|(k, _)| k != OAUTH_KEY)
            .map(|(k, v)| (k.as_str(), v.get()))
            .collect()
    }

    pub fn keys(&self) -> Vec<&str> {
        self.0.iter().map(|(k, _)| k.as_str()).collect()
    }
}

impl Drop for RawItem {
    fn drop(&mut self) {
        // Best effort: the raw values hold token bytes.
        for (_, v) in self.0.drain(..) {
            let s: Box<str> = v.into();
            drop(Zeroizing::new(String::from(s)));
        }
    }
}

/// The `claudeAiOauth` object of an item (`None` when absent or not an
/// object).
/// Parsed through [`RawItem::parse`], so a non-object item or duplicate
/// `claudeAiOauth` keys are refused.
pub fn oauth_of(item: &[u8]) -> Result<Option<Value>> {
    let raw = RawItem::parse(item)?;
    match raw.get(OAUTH_KEY) {
        Some(v) => {
            let v: Value =
                serde_json::from_str(v.get()).map_err(|e| Error::json("credential item", &e))?;
            Ok(Some(v).filter(Value::is_object))
        }
        None => Ok(None),
    }
}

/// Canonical compact bytes of a credential (what fingerprints hash).
pub fn canonical_oauth(oauth: &Value) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(oauth).expect("serializable"))
}

/// Fingerprint of a credential object.
pub fn oauth_fingerprint(oauth: &Value) -> String {
    sha256_hex(&canonical_oauth(oauth))
}

/// An item that holds only `claudeAiOauth` (what cma stores and exports).
pub fn oauth_only_item(oauth: &Value) -> Secret {
    let canon = canonical_oauth(oauth);
    let mut out = Vec::with_capacity(canon.len() + 20);
    out.extend_from_slice(b"{\"");
    out.extend_from_slice(OAUTH_KEY.as_bytes());
    out.extend_from_slice(b"\":");
    out.extend_from_slice(&canon);
    out.push(b'}');
    Secret::new(out)
}

/// Replace only `claudeAiOauth` in `item` (absent ⇒ `{}`), keeping its
/// position and every other top-level key's exact bytes. The result is
/// compact JSON, as Claude Code writes it. Refuses a non-object item.
pub fn replace_oauth(item: Option<&[u8]>, oauth: &Value) -> Result<Secret> {
    let raw = match item {
        Some(b) => RawItem::parse(b)?,
        None => RawItem(Vec::new()),
    };
    let canon = canonical_oauth(oauth);
    let mut out = Vec::new();
    out.push(b'{');
    let mut wrote_oauth = false;
    let mut first = true;
    let mut push_entry = |out: &mut Vec<u8>, k: &str, v: &[u8]| {
        if !first {
            out.push(b',');
        }
        first = false;
        out.extend_from_slice(&serde_json::to_vec(k).expect("string"));
        out.push(b':');
        out.extend_from_slice(v);
    };
    for (k, v) in &raw.0 {
        if k == OAUTH_KEY {
            if !wrote_oauth {
                push_entry(&mut out, k, &canon);
                wrote_oauth = true;
            }
        } else {
            push_entry(&mut out, k, v.get().as_bytes());
        }
    }
    if !wrote_oauth {
        push_entry(&mut out, OAUTH_KEY, &canon);
    }
    out.push(b'}');
    Ok(Secret::new(out))
}

/// True for a credential Claude Code blanked after its grant died (empty
/// tokens or `expiresAt` 0). Such a credential is never an identity.
pub fn is_blanked(oauth: &Value) -> bool {
    let empty = |k: &str| {
        oauth
            .get(k)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    };
    let expires_zero = oauth.get("expiresAt").and_then(Value::as_i64) == Some(0);
    (empty("accessToken") && empty("refreshToken")) || expires_zero
}

/// `expiresAt` (ms) of a credential, if present.
pub fn expires_at_ms(oauth: &Value) -> Option<i64> {
    oauth.get("expiresAt").and_then(Value::as_i64)
}

/// The access token as a [`Secret`].
pub fn access_token(oauth: &Value) -> Option<Secret> {
    oauth
        .get("accessToken")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| Secret::new(s.as_bytes().to_vec()))
}

/// `subscriptionType` (plan) of a credential.
pub fn plan_of(oauth: &Value) -> String {
    oauth
        .get("subscriptionType")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Read cma's stored credential for `key` (`None` when absent).
pub fn stored_oauth(store: &dyn SecretStore, key: &str) -> Result<Option<Value>> {
    match store.get(OWN_SERVICE, key)? {
        Some(s) => oauth_of(s.expose()),
        None => Ok(None),
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Shared fakes for CLI-target tests.

    use serde_json::{Value, json};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    use super::*;
    use crate::identity::{Profile, ProfileClient};
    use crate::lock::tests::FakeLocker;
    use crate::paths::MapEnv;
    use crate::secret::MemoryStore;

    pub const USER: &str = "tester";
    pub const FAR_FUTURE_MS: i64 = 4_000_000_000_000;
    pub const NOW_MS: i64 = 1_800_000_000_000;

    pub fn now() -> i64 {
        NOW_MS
    }

    /// Profile stub: access token → profile; counts calls.
    #[derive(Default)]
    pub struct StubProfile {
        pub by_token: RefCell<HashMap<String, Profile>>,
        pub calls: Cell<u32>,
        pub fail: Cell<bool>,
    }

    impl StubProfile {
        pub fn add(&self, token: &str, acct: &str, org: &str, email: &str) {
            self.by_token.borrow_mut().insert(
                token.into(),
                Profile {
                    account_uuid: acct.into(),
                    org_uuid: org.into(),
                    email: email.into(),
                    display_name: String::new(),
                    org_name: format!("Org {org}"),
                },
            );
        }
    }

    impl ProfileClient for StubProfile {
        fn profile(&self, token: &Secret) -> Result<Profile> {
            self.calls.set(self.calls.get() + 1);
            if self.fail.get() {
                return Err(Error::ExternalTool {
                    program: "profile",
                    sub: "GET",
                    code: None,
                    class: crate::error::ToolFailure::Other,
                });
            }
            let t = String::from_utf8(token.expose().to_vec()).unwrap();
            self.by_token
                .borrow()
                .get(&t)
                .cloned()
                .ok_or_else(|| Error::NotFound("profile (401)".into()))
        }
    }

    pub fn oauth(token: &str) -> Value {
        json!({
            "accessToken": format!("at-{token}"),
            "refreshToken": format!("rt-{token}"),
            "expiresAt": FAR_FUTURE_MS,
            "refreshTokenExpiresAt": FAR_FUTURE_MS,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
        })
    }

    pub fn blanked() -> Value {
        json!({"accessToken": "", "refreshToken": "", "expiresAt": 0, "refreshTokenExpiresAt": FAR_FUTURE_MS})
    }

    /// A live item with an `mcpOAuth` key written the way Claude does.
    pub fn live_item(oauth: &Value) -> Vec<u8> {
        let mut v = br#"{"claudeAiOauth":"#.to_vec();
        v.extend_from_slice(&serde_json::to_vec(oauth).unwrap());
        v.extend_from_slice(
            br#","mcpOAuth":{"srv|1":{"accessToken":"mcp-x","expiresAt":1.50,"n":[1, 2]}}}"#,
        );
        v
    }

    /// Wraps a [`MemoryStore`]; while `armed`, `get` of one item fails the
    /// way a failed `security find-generic-password` does. Other calls and
    /// items pass through.
    pub struct FailGet<'a> {
        pub inner: &'a MemoryStore,
        pub service: String,
        pub account: String,
        pub armed: std::rc::Rc<Cell<bool>>,
    }

    impl<'a> FailGet<'a> {
        pub fn live(w: &'a World) -> Self {
            let l = w.live();
            FailGet {
                inner: &w.store,
                service: l.service,
                account: l.account,
                armed: Default::default(),
            }
        }
    }

    impl SecretStore for FailGet<'_> {
        fn get(&self, service: &str, account: &str) -> Result<Option<Secret>> {
            if self.armed.get() && service == self.service && account == self.account {
                return Err(Error::ExternalTool {
                    program: "security",
                    sub: "find-generic-password",
                    code: Some(36),
                    class: crate::error::ToolFailure::Other,
                });
            }
            self.inner.get(service, account)
        }
        fn set(&self, service: &str, account: &str, value: &Secret) -> Result<()> {
            self.inner.set(service, account, value)
        }
        fn delete(&self, service: &str, account: &str) -> Result<bool> {
            self.inner.delete(service, account)
        }
    }

    pub struct World {
        pub tmp: tempfile::TempDir,
        pub paths: Paths,
        pub env: MapEnv,
        pub store: MemoryStore,
        pub locker: FakeLocker,
        pub profile: StubProfile,
        pub procs: crate::procs::tests::FakeProcs,
    }

    impl World {
        pub fn new() -> Self {
            Self::with_env(&[])
        }

        pub fn with_env(extra: &[(&str, &str)]) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().join("home");
            std::fs::create_dir_all(home.join(".claude")).unwrap();
            let mut env = MapEnv::new([
                ("HOME", home.to_str().unwrap()),
                ("CMA_HOME", home.join("cma").to_str().unwrap()),
                ("CMA_ALLOW_HOME_OVERRIDE", "1"),
                ("USER", USER),
                ("PATH", "/usr/bin:/bin"),
            ]);
            for (k, v) in extra {
                env.0.insert((*k).into(), (*v).into());
            }
            let paths = Paths::from_env(&env).unwrap();
            paths.ensure_cma_home().unwrap();
            std::fs::write(
                &paths.claude_json,
                br#"{"numStartups": 7, "oauthAccount": {"accountUuid": "A", "organizationUuid": "oA", "emailAddress": "a@x"}, "projects": {"/p": {"k": 1}}}"#,
            )
            .unwrap();
            World {
                tmp,
                paths,
                env,
                store: MemoryStore::new(),
                locker: FakeLocker::default(),
                profile: StubProfile::default(),
                procs: crate::procs::tests::FakeProcs::default(),
            }
        }

        pub fn ctx(&self) -> Ctx<'_> {
            self.ctx_with(&self.store)
        }

        /// A context whose Keychain is `store` (e.g. a [`FailGet`] over
        /// `self.store`).
        pub fn ctx_with<'a>(&'a self, store: &'a dyn SecretStore) -> Ctx<'a> {
            Ctx {
                paths: &self.paths,
                env: &self.env,
                store,
                locker: &self.locker,
                profile: &self.profile,
                procs: &self.procs,
                now_ms: now,
            }
        }

        pub fn live(&self) -> LiveTarget {
            LiveTarget::from_env(&self.env).unwrap()
        }

        pub fn set_live(&self, bytes: &[u8]) {
            let l = self.live();
            self.store
                .set(&l.service, &l.account, &Secret::new(bytes.to_vec()))
                .unwrap();
        }

        pub fn live_bytes(&self) -> Option<Vec<u8>> {
            let l = self.live();
            self.store
                .get(&l.service, &l.account)
                .unwrap()
                .map(|s| s.expose().to_vec())
        }

        pub fn claude_json(&self) -> Value {
            serde_json::from_slice(&std::fs::read(&self.paths.claude_json).unwrap()).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::paths::MapEnv;
    use crate::registry::claude_oauth_fingerprint;

    #[test]
    fn service_rule_matches_values_observed_from_claude_code() {
        // Observed from Claude Code: `-e6eddae8` = sha256("$T/link/")[0:8];
        // the rule itself, independent of $T:
        let h = &sha256_hex(b"/tmp/x/link/")[..8];
        assert_eq!(
            service_for_dir("/tmp/x/link/").unwrap(),
            format!("Claude Code-credentials-{h}")
        );
        let env = MapEnv::new([("USER", "me")]);
        assert_eq!(live_service(&env).unwrap(), "Claude Code-credentials");
        assert_eq!(keychain_account(&env), "me");
        assert_eq!(
            keychain_account(&MapEnv::new([("USER", "bad user")])),
            "claude-code-user"
        );
        assert_eq!(keychain_account(&MapEnv::default()), "claude-code-user");
    }

    #[test]
    fn trailing_slash_and_no_slash_hash_differently() {
        let a = service_for_dir("/Users/me/x/").unwrap();
        let b = service_for_dir("/Users/me/x").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), "Claude Code-credentials-".len() + 8);
    }

    #[test]
    fn securestorage_dir_takes_precedence_and_empty_means_base() {
        let env = MapEnv::new([
            ("CLAUDE_CONFIG_DIR", "/cfg"),
            ("CLAUDE_SECURESTORAGE_CONFIG_DIR", "/sec"),
        ]);
        assert_eq!(
            live_service(&env).unwrap(),
            service_for_dir("/sec").unwrap()
        );
        let env = MapEnv::new([
            ("CLAUDE_CONFIG_DIR", "/cfg"),
            ("CLAUDE_SECURESTORAGE_CONFIG_DIR", ""),
        ]);
        assert_eq!(live_service(&env).unwrap(), LIVE_SERVICE_BASE);
        let env = MapEnv::new([("CLAUDE_CONFIG_DIR", "/cfg")]);
        assert_eq!(
            live_service(&env).unwrap(),
            service_for_dir("/cfg").unwrap()
        );
    }

    #[test]
    fn non_ascii_dir_refused() {
        assert!(matches!(
            service_for_dir("/Users/é/x"),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn replace_keeps_other_keys_byte_exact_and_position() {
        let a = oauth("A");
        let b = oauth("B");
        let item = live_item(&a);
        let out = replace_oauth(Some(&item), &b).unwrap();
        let before = RawItem::parse(&item).unwrap();
        let after = RawItem::parse(out.expose()).unwrap();
        assert_eq!(before.others(), after.others());
        assert!(String::from_utf8_lossy(out.expose()).contains(
            r#""mcpOAuth":{"srv|1":{"accessToken":"mcp-x","expiresAt":1.50,"n":[1, 2]}}"#
        ));
        assert_eq!(after.keys(), vec!["claudeAiOauth", "mcpOAuth"]);
        assert_eq!(
            claude_oauth_fingerprint(out.expose()).unwrap().unwrap(),
            oauth_fingerprint(&b)
        );
    }

    #[test]
    fn replace_on_absent_or_empty_item_and_refuses_non_object() {
        let b = oauth("B");
        let out = replace_oauth(None, &b).unwrap();
        assert_eq!(out.expose(), oauth_only_item(&b).expose());
        let out = replace_oauth(Some(b"{}"), &b).unwrap();
        assert_eq!(out.expose(), oauth_only_item(&b).expose());
        assert!(matches!(
            replace_oauth(Some(b"[1]"), &b),
            Err(Error::Invalid { .. })
        ));
        assert!(matches!(
            replace_oauth(Some(b"nope"), &b),
            Err(Error::Json { .. })
        ));
    }

    #[test]
    fn oauth_only_item_fingerprint_is_canonical() {
        let a = oauth("A");
        let item = oauth_only_item(&a);
        assert_eq!(
            claude_oauth_fingerprint(item.expose()).unwrap().unwrap(),
            oauth_fingerprint(&a)
        );
        assert_eq!(oauth_of(item.expose()).unwrap().unwrap(), a);
    }

    #[test]
    fn duplicate_claude_ai_oauth_keys_fail_closed() {
        let item = br#"{"claudeAiOauth":{"accessToken":"at-A"},"mcpOAuth":{},"claudeAiOauth":{"accessToken":"at-B"}}"#;
        for r in [
            RawItem::parse(item).map(|_| ()),
            oauth_of(item).map(|_| ()),
            replace_oauth(Some(item), &oauth("C")).map(|_| ()),
        ] {
            assert!(
                matches!(r, Err(Error::Invalid { what, .. })
                    if what.contains("duplicate") && what.contains("/login")),
                "{r:?}"
            );
        }
        // A duplicate of another key is Claude's business, not refused.
        assert!(oauth_of(br#"{"claudeAiOauth":{},"x":1,"x":2}"#).is_ok());
    }

    #[test]
    fn blanked_detection() {
        assert!(is_blanked(&blanked()));
        assert!(!is_blanked(&oauth("A")));
        let mut z = oauth("A");
        z["expiresAt"] = 0.into();
        assert!(is_blanked(&z));
    }

    #[test]
    fn env_and_plaintext_warnings() {
        let w = World::with_env(&[("CLAUDE_CODE_OAUTH_TOKEN", "x")]);
        let ctx = w.ctx();
        assert_eq!(ctx.env_warnings().len(), 1);
        assert!(ctx.plaintext_warning().is_none());
        std::fs::write(w.paths.secure_storage_dir.join(".credentials.json"), b"{}").unwrap();
        assert_eq!(
            ctx.plaintext_warning().unwrap().code,
            "plaintext_credentials"
        );
    }
}
