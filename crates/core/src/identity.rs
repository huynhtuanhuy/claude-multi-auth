//! Token-derived identity of a credential, failing closed.
//!
//! Sources, in order (the credential has no `profile`/`clientId`):
//!
//! 1. the fingerprint map: sha256 of the canonical `claudeAiOauth` bytes →
//!    account key, filled only by cma after it verified the identity;
//! 2. `GET /api/oauth/profile` with the credential's access token
//!    (`account.uuid`, `organization.uuid`), only while the token is
//!    unexpired: cma never refreshes a token to identify it;
//! 3. the `account`/`organization` of cma's own refresh response, when the
//!    caller has one.
//!
//! Every source that yields an answer must agree, otherwise the result is
//! [`Resolved::Unidentified`]. A blanked credential (Claude Code's mark of a
//! dead grant) is never an identity, and is never looked up by fingerprint:
//! blanked credentials of different accounts can have identical bytes. The
//! caller decides whether it is the signed-out active account
//! ([`crate::sync`]). `~/.claude.json` `oauthAccount` is not a
//! source at all: Desktop's Code tab and running sessions rewrite it.

use serde_json::Value;

use crate::cli_target::{access_token, expires_at_ms, is_blanked, oauth_fingerprint};
use crate::error::{Error, Result};
use crate::registry::{Account, Registry};
use crate::secret::Secret;

/// `/api/oauth/profile` fields cma uses. None of them is secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub account_uuid: String,
    pub org_uuid: String,
    pub email: String,
    pub display_name: String,
    pub org_name: String,
}

impl Profile {
    pub fn key(&self) -> String {
        Account::key_for(&self.account_uuid, &self.org_uuid)
    }

    /// The `oauthAccount` object Claude Code keeps in `~/.claude.json`,
    /// reduced to the fields the profile gives (Claude refetches the rest).
    pub fn oauth_account(&self) -> Value {
        serde_json::json!({
            "accountUuid": self.account_uuid,
            "organizationUuid": self.org_uuid,
            "emailAddress": self.email,
            "displayName": self.display_name,
            "organizationName": self.org_name,
        })
    }
}

/// Fetches the profile for an access token. Implementations must not log
/// the token or the response, and must time out (5 s).
pub trait ProfileClient {
    fn profile(&self, access_token: &Secret) -> Result<Profile>;
}

/// A client that never touches the network (identity then comes from the
/// fingerprint map only).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNetwork;

impl ProfileClient for NoNetwork {
    fn profile(&self, _: &Secret) -> Result<Profile> {
        Err(Error::Unsupported("network disabled".into()))
    }
}

fn str_at<'a>(v: &'a Value, obj: &str, key: &str) -> &'a str {
    v.get(obj)
        .and_then(|o| o.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Parse a `/api/oauth/profile` body. Both uuids are required.
pub fn parse_profile(body: &[u8]) -> Result<Profile> {
    let v: Value = serde_json::from_slice(body).map_err(|e| Error::json("profile", &e))?;
    let p = Profile {
        account_uuid: str_at(&v, "account", "uuid").to_string(),
        org_uuid: str_at(&v, "organization", "uuid").to_string(),
        email: str_at(&v, "account", "email").to_string(),
        display_name: str_at(&v, "account", "display_name").to_string(),
        org_name: str_at(&v, "organization", "name").to_string(),
    };
    let uuid_ok = |s: &str| {
        !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if !uuid_ok(&p.account_uuid) || !uuid_ok(&p.org_uuid) {
        return Err(Error::Invalid {
            what: "profile (account/organization uuid missing)",
            value: String::new(),
        });
    }
    Ok(p)
}

/// Which source produced an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Fingerprint,
    Profile,
    RefreshResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    Identified {
        key: String,
        source: Source,
        /// Set when the profile endpoint was asked.
        profile: Option<Profile>,
    },
    /// No trustworthy identity. Callers write nothing. `blanked`: the
    /// credential is signed out.
    Unidentified { reason: String, blanked: bool },
}

impl Resolved {
    pub fn key(&self) -> Option<&str> {
        match self {
            Resolved::Identified { key, .. } => Some(key),
            _ => None,
        }
    }

    /// The identified key, or an error that fails the caller closed.
    pub fn require(self) -> Result<(String, Option<Profile>)> {
        match self {
            Resolved::Identified { key, profile, .. } => Ok((key, profile)),
            Resolved::Unidentified {
                reason,
                blanked: true,
            } => Err(Error::NeedsLogin(reason)),
            Resolved::Unidentified { reason, .. } => Err(Error::Unidentified(reason)),
        }
    }
}

/// Resolve the identity of a `claudeAiOauth` object.
///
/// `refresh_identity`: (account uuid, org uuid) from cma's own refresh
/// response for exactly these bytes, if there was one.
pub fn resolve(
    registry: &Registry,
    client: &dyn ProfileClient,
    oauth: &Value,
    now_ms: i64,
    refresh_identity: Option<(&str, &str)>,
) -> Resolved {
    if is_blanked(oauth) {
        return Resolved::Unidentified {
            reason: "the credential is signed out (blanked by Claude Code)".into(),
            blanked: true,
        };
    }
    let fp = oauth_fingerprint(oauth);
    let known = registry.account_for_fingerprint(&fp).map(str::to_string);
    let mut found: Vec<(String, Source)> = Vec::new();
    let mut profile = None;
    let mut why = Vec::new();
    match known {
        Some(k) => found.push((k, Source::Fingerprint)),
        None => {
            let unexpired = expires_at_ms(oauth).is_some_and(|e| e > now_ms);
            match (unexpired, access_token(oauth)) {
                (true, Some(tok)) => match client.profile(&tok) {
                    Ok(p) => {
                        found.push((p.key(), Source::Profile));
                        profile = Some(p);
                    }
                    Err(e) => why.push(format!("profile lookup failed ({})", e.code())),
                },
                (false, _) => why.push(
                    "the access token is expired and cma never refreshes a token to identify it"
                        .to_string(),
                ),
                (true, None) => why.push("the credential has no access token".to_string()),
            }
        }
    }
    if let Some((a, o)) = refresh_identity {
        found.push((Account::key_for(a, o), Source::RefreshResponse));
    }
    match found.first() {
        None => Resolved::Unidentified {
            reason: if why.is_empty() {
                "no identity source resolved".into()
            } else {
                why.join("; ")
            },
            blanked: false,
        },
        Some((key, source)) if found.iter().all(|(k, _)| k == key) => Resolved::Identified {
            key: key.clone(),
            source: *source,
            profile,
        },
        Some(_) => Resolved::Unidentified {
            reason: "identity sources disagree".into(),
            blanked: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_target::testkit::*;

    #[test]
    fn fingerprint_wins_without_network() {
        let p = StubProfile::default();
        let mut r = Registry::default();
        let a = oauth("A");
        r.add_fingerprint(oauth_fingerprint(&a), "A::oA");
        let got = resolve(&r, &p, &a, NOW_MS, None);
        assert_eq!(got.key(), Some("A::oA"));
        assert_eq!(p.calls.get(), 0);
    }

    #[test]
    fn profile_resolves_unexpired_unknown_token() {
        let p = StubProfile::default();
        p.add("at-A", "A", "oA", "a@x");
        let got = resolve(&Registry::default(), &p, &oauth("A"), NOW_MS, None);
        match got {
            Resolved::Identified {
                key,
                source: Source::Profile,
                profile: Some(pr),
            } => {
                assert_eq!(key, "A::oA");
                assert_eq!(pr.email, "a@x");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn expired_token_is_never_sent_and_unidentified() {
        let p = StubProfile::default();
        p.add("at-A", "A", "oA", "a@x");
        let mut a = oauth("A");
        a["expiresAt"] = (NOW_MS - 1).into();
        let got = resolve(&Registry::default(), &p, &a, NOW_MS, None);
        assert!(matches!(got, Resolved::Unidentified { .. }));
        assert_eq!(p.calls.get(), 0);
    }

    #[test]
    fn disagreement_is_unidentified() {
        let p = StubProfile::default();
        p.add("at-A", "A", "oA", "a@x");
        let got = resolve(
            &Registry::default(),
            &p,
            &oauth("A"),
            NOW_MS,
            Some(("B", "oB")),
        );
        assert!(matches!(got, Resolved::Unidentified { .. }));
        let got = resolve(
            &Registry::default(),
            &p,
            &oauth("A"),
            NOW_MS,
            Some(("A", "oA")),
        );
        assert_eq!(got.key(), Some("A::oA"));
    }

    #[test]
    fn profile_failure_is_unidentified() {
        let p = StubProfile::default();
        p.fail.set(true);
        let got = resolve(&Registry::default(), &p, &oauth("A"), NOW_MS, None);
        assert!(matches!(got, Resolved::Unidentified { blanked: false, .. }));
        assert!(matches!(
            got.require(),
            Err(Error::Unidentified(m)) if m.contains("profile lookup failed")
        ));
    }

    #[test]
    fn blanked_credential_is_never_an_identity() {
        let p = StubProfile::default();
        // Even a profile that would answer for the empty token is not asked.
        p.add("", "A", "oA", "a@x");
        let b = blanked();
        let got = resolve(&Registry::default(), &p, &b, NOW_MS, None);
        assert!(matches!(got, Resolved::Unidentified { blanked: true, .. }));
        assert_eq!(p.calls.get(), 0);
        // Even a (never written) fingerprint entry or a refresh identity
        // does not make it one.
        let mut r = Registry::default();
        r.add_fingerprint(oauth_fingerprint(&b), "A::oA");
        let got = resolve(&r, &p, &b, NOW_MS, Some(("A", "oA")));
        assert!(matches!(got, Resolved::Unidentified { blanked: true, .. }));
        assert!(matches!(got.require(), Err(Error::NeedsLogin(_))));
    }

    #[test]
    fn parse_profile_requires_both_uuids() {
        let body = br#"{"account":{"uuid":"a-1","email":"e@x","display_name":"E"},"organization":{"uuid":"o-1","name":"Org"},"application":{}}"#;
        let p = parse_profile(body).unwrap();
        assert_eq!(p.key(), "a-1::o-1");
        assert_eq!(p.org_name, "Org");
        assert!(parse_profile(br#"{"account":{"uuid":"a"}}"#).is_err());
        assert!(
            parse_profile(br#"{"account":{"uuid":"a\"b"},"organization":{"uuid":"o"}}"#).is_err()
        );
    }
}
