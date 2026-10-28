//! `registry.json`: accounts, active targets, settings and fingerprints.
//!
//! Unknown fields are preserved at every level so an older cma never drops
//! data written by a newer one; a newer `schema_version` is refused outright.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::fsutil;
use crate::secret::sha256_hex;

pub const SCHEMA_VERSION: u64 = 1;
pub const DEFAULT_REFRESH_GRACE_SECS: u64 = 300;
pub const DEFAULT_LIVE_INTERVAL_SECS: u64 = 60;

type Extra = Map<String, Value>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Registry {
    pub schema_version: u64,
    #[serde(default)]
    pub active: Active,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub desktop: Vec<DesktopLink>,
    /// sha256(canonical `claudeAiOauth` bytes) → account key.
    #[serde(default)]
    pub fingerprints: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            schema_version: SCHEMA_VERSION,
            active: Active::default(),
            settings: Settings::default(),
            accounts: Vec::new(),
            desktop: Vec::new(),
            fingerprints: BTreeMap::new(),
            extra: Extra::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Active {
    #[serde(default)]
    pub cli: Option<String>,
    #[serde(default)]
    pub desktop: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionFollow {
    #[default]
    Off,
    On,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    #[default]
    Cli,
    Desktop,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub session_follow: SessionFollow,
    pub live_usage: bool,
    pub live_interval_secs: u64,
    pub default_target: Target,
    pub refresh_grace_secs: u64,
    /// The one-time live-usage disclaimer ([`crate::usage::DISCLAIMER`])
    /// was shown.
    pub usage_disclaimer_shown: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            session_follow: SessionFollow::Off,
            live_usage: false,
            live_interval_secs: DEFAULT_LIVE_INTERVAL_SECS,
            default_target: Target::Cli,
            refresh_grace_secs: DEFAULT_REFRESH_GRACE_SECS,
            usage_disclaimer_shown: false,
            extra: Extra::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountKind {
    #[default]
    Oauth,
    Console,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Usage {
    /// Unix seconds of the last successful fetch (0: never).
    pub fetched_at: i64,
    /// Usage windows by raw key (see [`crate::usage::parse_usage`]); kept
    /// from the last success when a fetch fails.
    pub windows: Map<String, Value>,
    /// Why the last fetch or refresh failed; `None` after a success.
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Account {
    /// `<accountUuid>::<organizationUuid>`.
    pub key: String,
    pub kind: AccountKind,
    pub account_uuid: String,
    pub org_uuid: String,
    pub email: String,
    pub org_name: String,
    pub plan: String,
    pub alias: Option<String>,
    pub added_at: i64,
    pub last_active_at: i64,
    pub has_cli: bool,
    pub needs_login: bool,
    pub usage: Usage,
    /// Non-secret `oauthAccount` object written to `~/.claude.json` when
    /// this account becomes the live CLI account (captured at login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_account: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Account {
    pub fn key_for(account_uuid: &str, org_uuid: &str) -> String {
        format!("{account_uuid}::{org_uuid}")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DesktopLink {
    pub account_uuid: String,
    pub last_org_uuid: String,
    pub linked_at: i64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Deserialize)]
struct Peek {
    schema_version: Option<u64>,
}

impl Registry {
    /// Parse registry bytes, refusing a newer schema before anything else.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let peek: Peek = serde_json::from_slice(bytes).map_err(|e| Error::json("registry", &e))?;
        let found = peek.schema_version.unwrap_or(0);
        if found > SCHEMA_VERSION {
            return Err(Error::RegistryTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found == 0 {
            return Err(Error::Invalid {
                what: "registry schema_version",
                value: "missing".into(),
            });
        }
        serde_json::from_slice(bytes).map_err(|e| Error::json("registry", &e))
    }

    /// Load from disk; a missing file is an empty registry.
    pub fn load(path: &Path) -> Result<Self> {
        match fsutil::read_nofollow(path)? {
            Some(bytes) => Self::from_bytes(&bytes),
            None => Ok(Registry::default()),
        }
    }

    /// Atomically write with mode 0600. Refuses a registry newer than this
    /// build supports.
    pub fn save(&self, path: &Path) -> Result<()> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(Error::RegistryTooNew {
                found: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|e| Error::json("registry", &e))?;
        bytes.push(b'\n');
        fsutil::atomic_write_mode(path, &bytes, 0o600)
    }

    pub fn account(&self, key: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.key == key)
    }

    pub fn account_mut(&mut self, key: &str) -> Option<&mut Account> {
        self.accounts.iter_mut().find(|a| a.key == key)
    }

    /// Record that these canonical `claudeAiOauth` bytes belong to `key`.
    pub fn add_fingerprint(&mut self, fingerprint: String, key: &str) {
        self.fingerprints.insert(fingerprint, key.to_string());
    }

    /// Account key that owns a fingerprint, if any.
    pub fn account_for_fingerprint(&self, fingerprint: &str) -> Option<&str> {
        self.fingerprints.get(fingerprint).map(String::as_str)
    }
}

/// Fingerprint of a credential item: sha256 of the compact JSON of its
/// `claudeAiOauth` object, keys in stored order. Other top-level keys
/// (`mcpOAuth`, …) are ignored. `None` when the item has no such object.
pub fn claude_oauth_fingerprint(item: &[u8]) -> Result<Option<String>> {
    let value: Value =
        serde_json::from_slice(item).map_err(|e| Error::json("credential item", &e))?;
    let Some(oauth) = value.get("claudeAiOauth").filter(|v| v.is_object()) else {
        return Ok(None);
    };
    let canonical =
        Zeroizing::new(serde_json::to_vec(oauth).map_err(|e| Error::json("credential item", &e))?);
    Ok(Some(sha256_hex(&canonical)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let r = Registry::default();
        assert_eq!(r.settings.refresh_grace_secs, 300);
        assert_eq!(r.settings.session_follow, SessionFollow::Off);
        assert_eq!(r.settings.default_target, Target::Cli);
        let r = Registry::from_bytes(br#"{"schema_version":1}"#).unwrap();
        assert_eq!(r.settings.refresh_grace_secs, 300);
        assert_eq!(r.settings.live_interval_secs, 60);
        assert!(!r.settings.usage_disclaimer_shown);
    }

    #[test]
    fn unknown_keys_survive_round_trip() {
        let src = r#"{
          "schema_version": 1,
          "future_top": {"x": [1, 2]},
          "active": {"cli": "a::o", "desktop": null, "future_active": 1},
          "settings": {"session_follow": "on", "refresh_grace_secs": 120, "future_setting": "s"},
          "accounts": [{"key": "a::o", "kind": "oauth", "email": "a@x", "future_acct": true,
                        "usage": {"fetched_at": 5, "windows": {}, "error": null, "future_usage": 2}}],
          "desktop": [{"account_uuid": "a", "last_org_uuid": "o", "linked_at": 1, "future_desk": "d"}],
          "fingerprints": {"ff": "a::o"}
        }"#;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("registry.json");
        let r = Registry::from_bytes(src.as_bytes()).unwrap();
        r.save(&p).unwrap();
        let back: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(back["future_top"]["x"][1], 2);
        assert_eq!(back["active"]["future_active"], 1);
        assert_eq!(back["settings"]["future_setting"], "s");
        assert_eq!(back["settings"]["refresh_grace_secs"], 120);
        assert_eq!(back["accounts"][0]["future_acct"], true);
        assert_eq!(back["accounts"][0]["usage"]["future_usage"], 2);
        assert_eq!(back["desktop"][0]["future_desk"], "d");
        assert_eq!(Registry::load(&p).unwrap(), r);
        assert_eq!(fsutil::existing_mode(&p).unwrap(), Some(0o600));
    }

    #[test]
    fn newer_schema_rejected_on_load_and_save() {
        let err =
            Registry::from_bytes(br#"{"schema_version":2,"accounts":"whatever"}"#).unwrap_err();
        assert!(matches!(
            err,
            Error::RegistryTooNew {
                found: 2,
                supported: 1
            }
        ));
        let t = tempfile::tempdir().unwrap();
        let r = Registry {
            schema_version: 9,
            ..Registry::default()
        };
        assert!(matches!(
            r.save(&t.path().join("r.json")),
            Err(Error::RegistryTooNew { .. })
        ));
        assert!(!t.path().join("r.json").exists());
    }

    #[test]
    fn missing_file_is_empty_registry() {
        let t = tempfile::tempdir().unwrap();
        let r = Registry::load(&t.path().join("none.json")).unwrap();
        assert_eq!(r, Registry::default());
    }

    #[test]
    fn fingerprint_covers_only_claude_ai_oauth_in_stored_order() {
        let a = br#"{"claudeAiOauth":{"accessToken":"x","expiresAt":1},"mcpOAuth":{"s":1}}"#;
        let b = br#"{"mcpOAuth":{"s":2,"t":3},"claudeAiOauth":{"accessToken":"x","expiresAt":1}}"#;
        let fa = claude_oauth_fingerprint(a).unwrap().unwrap();
        assert_eq!(fa, claude_oauth_fingerprint(b).unwrap().unwrap());
        assert_eq!(fa, sha256_hex(br#"{"accessToken":"x","expiresAt":1}"#));
        // Key order as stored matters.
        let c = br#"{"claudeAiOauth":{"expiresAt":1,"accessToken":"x"}}"#;
        assert_ne!(fa, claude_oauth_fingerprint(c).unwrap().unwrap());
        assert!(claude_oauth_fingerprint(b"{}").unwrap().is_none());
        assert!(matches!(
            claude_oauth_fingerprint(b"not json"),
            Err(Error::Json { .. })
        ));
    }

    #[test]
    fn fingerprint_map() {
        let mut r = Registry::default();
        r.add_fingerprint("ff".into(), "a::o");
        assert_eq!(r.account_for_fingerprint("ff"), Some("a::o"));
        assert_eq!(r.account_for_fingerprint("gg"), None);
    }
}
