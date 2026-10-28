//! Refresh a stored account's OAuth token.
//!
//! Refresh rotates the refresh token: the old one answers `invalid_grant`
//! from then on, while the newest keeps working (no family revocation), and
//! the refresh-token deadline is absolute per grant (rotation does not
//! extend it). So, under the account's [`AccountLock`] for the whole
//! read → POST → write span:
//!
//! 1. resolve what an interrupted refresh left behind
//!    ([`recover_interrupted`]);
//! 2. re-read the stored credential: signed out, or past
//!    `refreshTokenExpiresAt` ⇒ `needs_login` without a request; no longer
//!    expiring (another refresher just ran) ⇒ use it as it is;
//! 3. pre-refresh copy: copy the current credential into Keychain service
//!    `claude-multi-auth-backup`, account `<key>/pre-refresh`. It only
//!    restores a stored item that went missing or unreadable;
//! 4. POST the refresh request the way Claude Code sends it (`client_id`
//!    from the credential, else [`CLIENT_ID`]; `scope` = the credential's
//!    scopes; on `invalid_scope` once more without `scope`);
//! 5. on a 200, first write the rotated pair (with the response's account
//!    and organization uuids and the fingerprint it rotated from) to the
//!    post-refresh copy `<key>/post-refresh`: from here on the old refresh
//!    token is spent and this copy is the only valid grant. It is never
//!    used as the account's credential until its identity is verified;
//! 6. verify the identity (`account.uuid`/`organization.uuid`, else
//!    `/api/oauth/profile` with the new access token, retried once on a
//!    transient failure). Another account ⇒ store nothing, `needs_login`
//!    (the old refresh token is spent). Lookup unavailable ⇒ store nothing,
//!    keep the post-refresh copy for a later check (`refresh_pending`);
//! 7. store the new pair (one retry), keeping every other field, only over
//!    the credential this refresh started from; then delete both copies
//!    (a failed delete is only a warning). A failed store keeps the
//!    post-refresh copy, which the next run stores;
//! 8. `invalid_grant` ⇒ re-read: if the stored refresh token changed in the
//!    meantime (another writer stored a newer grant), retry once with it;
//!    otherwise `needs_login`.
//!
//! The caller decides *whether* an account may be refreshed at all (never
//! the live owner, never one active within the refresh grace): see
//! [`crate::usage`]. Refresh never writes the live Claude Code item and never
//! takes `.storage-write`.

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::backup::BACKUP_SERVICE;
use crate::cli_target::{
    OAUTH_KEY, OWN_SERVICE, Warning, expires_at_ms, is_blanked, oauth_fingerprint, oauth_of,
    oauth_only_item,
};
use crate::error::{Error, Result};
use crate::http::{HttpClient, Method, Request, fetch_profile, status_error};
use crate::lock::AccountLock;
use crate::paths::{Env, Paths};
use crate::registry::Account;
use crate::secret::{Secret, SecretStore};

pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
/// Claude Code 2.1.310's OAuth client id (public, not a secret). Stored
/// credentials carry no `clientId`, so this is what is sent.
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
/// Overrides [`CLIENT_ID`].
pub const CLIENT_ID_ENV: &str = "CMA_OAUTH_CLIENT_ID";
/// Refresh when the access token expires within this margin.
pub const REFRESH_MARGIN_MS: i64 = 60_000;
/// Profile lookups per identity check: one retry on a transient failure.
pub const PROFILE_ATTEMPTS: u64 = 2;
/// Most HTTP requests of the recovery of a post-refresh copy: a profile
/// lookup with its access token, then (refused or expired) a POST of its
/// refresh token plus its retry without `scope`, and the identity check of
/// that response.
pub const RECOVERY_MAX_REQUESTS: u64 = PROFILE_ATTEMPTS + 2 + PROFILE_ATTEMPTS;
/// Most HTTP requests of one refresh: two passes (the `invalid_grant`
/// retry) of a POST plus its retry without `scope`, then the identity check
/// of the response.
pub const ROTATION_MAX_REQUESTS: u64 = 2 * 2 + PROFILE_ATTEMPTS;
/// Most HTTP requests made while one account lock is held. A recovery that
/// used the network either stores a credential (and the caller then does
/// not refresh in the same hold) or fails, so the two never add up. The
/// account-lock wait is derived from it
/// ([`crate::lock::ACCOUNT_LOCK_TIMEOUT`]).
pub const REFRESH_MAX_REQUESTS: u64 = if RECOVERY_MAX_REQUESTS > ROTATION_MAX_REQUESTS {
    RECOVERY_MAX_REQUESTS
} else {
    ROTATION_MAX_REQUESTS
};
const WHAT: &str = "oauth/token";
/// Top-level key of the post-refresh copy's metadata (next to
/// `claudeAiOauth`).
const POST_META: &str = "cmaRefresh";

/// The client id to send when a credential has none.
pub fn client_id(env: &dyn Env) -> String {
    env.var(CLIENT_ID_ENV)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| CLIENT_ID.to_string())
}

/// Keychain account (in [`BACKUP_SERVICE`]) of the pre-refresh copy.
pub fn write_ahead_account(key: &str) -> String {
    format!("{key}/pre-refresh")
}

/// Keychain account (in [`BACKUP_SERVICE`]) of the post-refresh copy: the
/// rotated pair of a refresh that has not been stored yet.
pub fn post_refresh_account(key: &str) -> String {
    format!("{key}/post-refresh")
}

/// The access token expires within [`REFRESH_MARGIN_MS`] (or has no
/// expiry).
pub fn needs_refresh(oauth: &Value, now_ms: i64) -> bool {
    expires_at_ms(oauth).is_none_or(|e| e < now_ms + REFRESH_MARGIN_MS)
}

/// The access token is still valid now.
pub fn access_unexpired(oauth: &Value, now_ms: i64) -> bool {
    !is_blanked(oauth) && expires_at_ms(oauth).is_some_and(|e| e > now_ms)
}

/// Past the grant's absolute refresh deadline.
pub fn refresh_deadline_passed(oauth: &Value, now_ms: i64) -> bool {
    oauth
        .get("refreshTokenExpiresAt")
        .and_then(Value::as_i64)
        .is_some_and(|d| d > 0 && d <= now_ms)
}

fn str_field<'a>(oauth: &'a Value, k: &str) -> Option<&'a str> {
    oauth
        .get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// What network refresh and usage need. Everything is `Sync`, so accounts
/// can be processed in parallel.
pub struct NetCtx<'a> {
    pub paths: &'a Paths,
    /// The Keychain (cma's items, backups and the live item).
    pub store: &'a (dyn SecretStore + Sync),
    pub http: &'a dyn HttpClient,
    /// Sent when a credential has no `clientId` ([`client_id`]).
    pub client_id: String,
    pub now_ms: fn() -> i64,
}

impl NetCtx<'_> {
    pub fn now_ms(&self) -> i64 {
        (self.now_ms)()
    }

    fn io(&self) -> Io<'_> {
        Io {
            store: self.store,
            http: self.http,
            client_id: &self.client_id,
            now_ms: self.now_ms,
        }
    }
}

/// What recovery and the end of a rotation need (no `Sync` bound, so a
/// switch can use it with its own store).
struct Io<'a> {
    store: &'a dyn SecretStore,
    http: &'a dyn HttpClient,
    client_id: &'a str,
    now_ms: fn() -> i64,
}

impl Io<'_> {
    fn now_ms(&self) -> i64 {
        (self.now_ms)()
    }
}

/// An [`HttpClient`] that sends nothing: every request fails like a
/// transport error. Recovery run through it resolves only what needs no
/// network.
struct Offline;

impl HttpClient for Offline {
    fn send(&self, req: &Request<'_>) -> Result<crate::http::Response> {
        Err(crate::http::transport_error(req.what))
    }
}

/// Result of [`refresh_locked`]. `Debug` shows no token.
#[derive(Clone, PartialEq)]
pub enum Refreshed {
    /// The stored token did not need a refresh on re-read (e.g. another
    /// refresher just ran). Nothing was sent.
    StillValid { oauth: Value },
    /// Rotated and stored (by this call, or by the recovery of an
    /// interrupted one). `fingerprint` is the new credential's.
    Rotated { oauth: Value, fingerprint: String },
}

impl std::fmt::Debug for Refreshed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refreshed::StillValid { oauth } => f
                .debug_struct("StillValid")
                .field("fingerprint", &oauth_fingerprint(oauth))
                .finish(),
            Refreshed::Rotated { fingerprint, .. } => f
                .debug_struct("Rotated")
                .field("fingerprint", fingerprint)
                .finish(),
        }
    }
}

#[cfg(test)]
pub(crate) mod failpoint {
    //! Test-only hook right after the post-refresh copy was written: `true`
    //! simulates a crash (nothing after it runs, both copies stay).
    use std::cell::RefCell;

    thread_local! {
        pub static CRASH_AFTER_POST: RefCell<bool> = const { RefCell::new(false) };
    }

    pub fn set(on: bool) {
        CRASH_AFTER_POST.with(|c| *c.borrow_mut() = on);
    }

    pub fn crash() -> bool {
        CRASH_AFTER_POST.with(|c| *c.borrow())
    }
}

fn check_lock(lock: &AccountLock, key: &str) -> Result<()> {
    if lock.key() == key {
        Ok(())
    } else {
        Err(Error::Invalid {
            what: "account lock (held for another account)",
            value: lock.key().to_string(),
        })
    }
}

/// Set, and once more on failure.
fn set_retry(store: &dyn SecretStore, service: &str, account: &str, v: &Secret) -> Result<()> {
    store
        .set(service, account, v)
        .or_else(|_| store.set(service, account, v))
}

/// Delete a refresh copy; a failure is only a warning (a later run removes
/// it).
fn cleanup(io: &Io<'_>, account: &str, warnings: &mut Vec<Warning>) {
    if let Err(e) = io.store.delete(BACKUP_SERVICE, account) {
        warnings.push(Warning::new(
            "refresh_cleanup_failed",
            format!(
                "could not remove the refresh copy {account} ({}); a later run removes it",
                e.code()
            ),
        ));
    }
}

/// The stored credential, `None` when missing or unreadable. A failed
/// Keychain read is an error.
fn stored_lenient(io: &Io<'_>, key: &str) -> Result<Option<Value>> {
    Ok(io
        .store
        .get(OWN_SERVICE, key)?
        .and_then(|s| oauth_of(s.expose()).ok().flatten()))
}

/// What [`recover_interrupted`] did.
#[derive(Debug, Default)]
pub struct Recovery {
    pub warnings: Vec<Warning>,
    /// The post-refresh copy of an interrupted refresh was verified and
    /// stored: the fingerprint of the stored credential.
    pub promoted: Option<String>,
}

/// The post-refresh copy, parsed.
struct PostCopy {
    oauth: Value,
    account_uuid: Option<String>,
    org_uuid: Option<String>,
    /// Fingerprint of the credential the refresh started from.
    from: Option<String>,
}

pub(crate) fn post_refresh_item(
    new: &Value,
    account_uuid: Option<&str>,
    org_uuid: Option<&str>,
    from_fp: Option<&str>,
) -> Result<Secret> {
    let doc = serde_json::json!({
        OAUTH_KEY: new,
        POST_META: {
            "accountUuid": account_uuid,
            "organizationUuid": org_uuid,
            "from": from_fp,
        },
    });
    let bytes =
        Zeroizing::new(serde_json::to_vec(&doc).map_err(|e| Error::json("post-refresh copy", &e))?);
    Ok(Secret::new(bytes.to_vec()))
}

fn parse_post(item: &Secret) -> Result<PostCopy> {
    let oauth = oauth_of(item.expose())?.ok_or_else(|| Error::Invalid {
        what: "post-refresh copy (no claudeAiOauth)",
        value: String::new(),
    })?;
    let v: Value =
        serde_json::from_slice(item.expose()).map_err(|e| Error::json("post-refresh copy", &e))?;
    let meta = |k: &str| {
        v.get(POST_META)
            .and_then(|m| m.get(k))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    Ok(PostCopy {
        account_uuid: meta("accountUuid").filter(|u| uuid_ok(u)),
        org_uuid: meta("organizationUuid").filter(|u| uuid_ok(u)),
        from: meta("from"),
        oauth,
    })
}

/// Resolve what an interrupted refresh of `key` left behind. The caller
/// holds `lock` (for `key`).
///
/// A post-refresh copy (a rotated pair not stored yet):
/// - already stored ⇒ remove it;
/// - the stored credential is not the one it rotated from (a login or
///   import stored a newer grant) ⇒ remove it, keep the stored one;
/// - otherwise verify its identity: its saved uuids; else a profile lookup
///   with its access token; and when that token has expired or is refused,
///   by refreshing with its refresh token (the new pair is kept aside and
///   checked like any refresh response). This account ⇒ store it (it is
///   the only valid grant now); another account, or a refresh token that is
///   refused ⇒ remove it, [`Error::NeedsLogin`]; lookup unavailable ⇒ keep
///   it, [`Error::RefreshPending`] (checked again on the next run).
///
/// A pre-refresh copy: put back when the stored credential is missing or
/// unreadable; then removed.
///
/// After a recovery that stored a credential (`promoted`), the caller does
/// not refresh again while it holds this lock (see
/// [`REFRESH_MAX_REQUESTS`]).
pub fn recover_interrupted(ctx: &NetCtx<'_>, lock: &AccountLock, key: &str) -> Result<Recovery> {
    recover(&ctx.io(), lock, key)
}

/// [`recover_interrupted`] without network access, for a switch: a copy
/// that carries its identity is stored; one that needs a lookup or a
/// refresh is left alone and [`Error::RefreshPending`] is returned.
pub fn recover_offline(
    store: &dyn SecretStore,
    now_ms: fn() -> i64,
    lock: &AccountLock,
    key: &str,
) -> Result<Recovery> {
    let io = Io {
        store,
        http: &Offline,
        client_id: CLIENT_ID,
        now_ms,
    };
    recover(&io, lock, key)
}

fn recover(io: &Io<'_>, lock: &AccountLock, key: &str) -> Result<Recovery> {
    check_lock(lock, key)?;
    let mut rec = Recovery::default();
    let pa = post_refresh_account(key);
    let wa = write_ahead_account(key);
    if let Some(item) = io.store.get(BACKUP_SERVICE, &pa)? {
        let stored_fp = stored_lenient(io, key)?.map(|o| oauth_fingerprint(&o));
        match parse_post(&item) {
            Err(e) => {
                cleanup(io, &pa, &mut rec.warnings);
                rec.warnings.push(Warning::new(
                    "refresh_copy_unreadable",
                    format!(
                        "removed an unreadable post-refresh copy of {key} ({}); if the next refresh fails, log in again",
                        e.code()
                    ),
                ));
            }
            Ok(copy) => {
                drop(item);
                let new_fp = oauth_fingerprint(&copy.oauth);
                if stored_fp.as_deref() == Some(new_fp.as_str()) {
                    cleanup(io, &pa, &mut rec.warnings);
                    rec.warnings.push(Warning::new(
                        "refresh_cleanup",
                        format!("removed the leftover post-refresh copy of {key}"),
                    ));
                } else if stored_fp.is_some() && stored_fp != copy.from {
                    cleanup(io, &pa, &mut rec.warnings);
                    rec.warnings.push(Warning::new(
                        "refresh_superseded",
                        format!(
                            "{key} was stored again after an interrupted refresh; kept that login and dropped the refreshed token"
                        ),
                    ));
                } else {
                    return recover_copy(io, key, copy, new_fp, rec);
                }
            }
        }
    }
    recover_pre(io, key, &wa, &mut rec.warnings)?;
    Ok(rec)
}

const PENDING_HINT: &str = "the refreshed token of an interrupted refresh is kept aside and checked again on the next run (`cma usage`)";

/// Verify a post-refresh copy and store it (see [`recover_interrupted`]).
fn recover_copy(
    io: &Io<'_>,
    key: &str,
    copy: PostCopy,
    new_fp: String,
    mut rec: Recovery,
) -> Result<Recovery> {
    let pa = post_refresh_account(key);
    let wa = write_ahead_account(key);
    let identity_known = copy.account_uuid.is_some() && copy.org_uuid.is_some();
    let access = str_field(&copy.oauth, "accessToken")
        .filter(|_| access_unexpired(&copy.oauth, io.now_ms()));
    let verdict = if identity_known || access.is_some() {
        verify_identity(
            io.http,
            key,
            copy.account_uuid.as_deref(),
            copy.org_uuid.as_deref(),
            access,
        )
    } else {
        // Its access token expired: a profile lookup can only be refused.
        Err(Verify::TokenRefused(format!(
            "the access token of the refreshed token of {key} has expired"
        )))
    };
    match verdict {
        Ok(()) => {
            set_retry(io.store, OWN_SERVICE, key, &oauth_only_item(&copy.oauth))?;
            cleanup(io, &pa, &mut rec.warnings);
            cleanup(io, &wa, &mut rec.warnings);
            rec.promoted = Some(new_fp);
            rec.warnings.push(Warning::new(
                "refresh_recovered",
                format!(
                    "stored the refreshed token of {key} that an interrupted refresh had kept aside"
                ),
            ));
            Ok(rec)
        }
        Err(Verify::Unavailable(m)) => Err(Error::RefreshPending(format!("{m}; {PENDING_HINT}"))),
        Err(Verify::Rejected(m)) => {
            cleanup(io, &pa, &mut rec.warnings);
            // Put back a readable (spent) credential so the verdict can be
            // attributed to it.
            recover_pre(io, key, &wa, &mut rec.warnings)?;
            Err(Error::NeedsLogin(format!(
                "{m}; dropped the refreshed token of an interrupted refresh; log in again"
            )))
        }
        // The copy's refresh token is the valid grant: refreshing it proves
        // its identity the same way a refresh does.
        Err(Verify::TokenRefused(_)) => {
            match post_with_scope_fallback(io.http, &copy.oauth, io.client_id) {
                Ok(t) => {
                    let (r, mut w) = finish_rotation(
                        io,
                        key,
                        &copy.oauth,
                        copy.from.as_deref(),
                        &t,
                        rec.warnings,
                    )?;
                    let Refreshed::Rotated { fingerprint, .. } = r else {
                        unreachable!("finish_rotation only returns Rotated")
                    };
                    w.push(Warning::new(
                        "refresh_recovered",
                        format!(
                            "stored a new token of {key} obtained with the refreshed token an interrupted refresh had kept aside"
                        ),
                    ));
                    Ok(Recovery {
                        warnings: w,
                        promoted: Some(fingerprint),
                    })
                }
                Err(PostErr::InvalidGrant) | Err(PostErr::Unreadable(_)) => {
                    cleanup(io, &pa, &mut rec.warnings);
                    recover_pre(io, key, &wa, &mut rec.warnings)?;
                    Err(Error::NeedsLogin(format!(
                        "the refreshed token {key}'s interrupted refresh kept aside was refused; log in again"
                    )))
                }
                Err(PostErr::InvalidScope) => Err(Error::RefreshPending(format!(
                    "refreshing the kept token of {key} failed (oauth/token: HTTP 400); {PENDING_HINT}"
                ))),
                Err(PostErr::Other(e)) => Err(Error::RefreshPending(format!(
                    "refreshing the kept token of {key} failed ({}); {PENDING_HINT}",
                    crate::usage::error_text(&e)
                ))),
            }
        }
    }
}

/// A leftover pre-refresh copy: put it back if the stored credential is
/// missing or unreadable, then remove it.
fn recover_pre(io: &Io<'_>, key: &str, wa: &str, warnings: &mut Vec<Warning>) -> Result<()> {
    let Some(copy) = io.store.get(BACKUP_SERVICE, wa)? else {
        return Ok(());
    };
    let stored = io.store.get(OWN_SERVICE, key)?;
    let stored_ok = stored
        .as_ref()
        .is_some_and(|s| oauth_of(s.expose()).ok().flatten().is_some());
    let warning = if !stored_ok {
        // Only a parseable copy is put back.
        if oauth_of(copy.expose()).ok().flatten().is_none() {
            return Err(Error::StateUncertain(format!(
                "the credential of {key} is unreadable and so is its pre-refresh copy; log in again"
            )));
        }
        io.store.set(OWN_SERVICE, key, &copy)?;
        Warning::new(
            "refresh_restored",
            format!(
                "an interrupted token refresh left {key} without a readable credential; restored its pre-refresh copy (its refresh token may already be rotated: if the next refresh fails, log in again)"
            ),
        )
    } else if stored.as_ref().is_some_and(|s| s.expose() == copy.expose()) {
        Warning::new(
            "refresh_interrupted",
            format!(
                "an earlier token refresh of {key} was interrupted after its request; if the next refresh fails, log in again"
            ),
        )
    } else {
        // The new credential was stored; only the cleanup was missed.
        Warning::new(
            "refresh_cleanup",
            format!("removed the leftover pre-refresh copy of {key}"),
        )
    };
    cleanup(io, wa, warnings);
    warnings.push(warning);
    Ok(())
}

/// Tokens and identity of a successful refresh response.
struct Tokens {
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    expires_in: i64,
    refresh_expires_in: Option<i64>,
    account_uuid: Option<String>,
    org_uuid: Option<String>,
}

enum PostErr {
    InvalidGrant,
    InvalidScope,
    /// A 200 whose body could not be read: the old refresh token is spent.
    Unreadable(Error),
    Other(Error),
}

impl From<Error> for PostErr {
    fn from(e: Error) -> Self {
        PostErr::Other(e)
    }
}

fn uuid_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn parse_tokens(body: &[u8]) -> Result<Tokens> {
    let v: Value = serde_json::from_slice(body).map_err(|e| Error::json("token response", &e))?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let (Some(access), Some(refresh)) = (s("access_token"), s("refresh_token")) else {
        return Err(Error::Invalid {
            what: "token response (tokens missing)",
            value: String::new(),
        });
    };
    let expires_in = v
        .get("expires_in")
        .and_then(Value::as_i64)
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::Invalid {
            what: "token response (expires_in missing)",
            value: String::new(),
        })?;
    let id = |obj: &str| {
        v.get(obj)
            .and_then(|o| o.get("uuid"))
            .and_then(Value::as_str)
            .filter(|u| uuid_ok(u))
            .map(str::to_string)
    };
    Ok(Tokens {
        access: Zeroizing::new(access.to_string()),
        refresh: Zeroizing::new(refresh.to_string()),
        expires_in,
        refresh_expires_in: v
            .get("refresh_token_expires_in")
            .and_then(Value::as_i64)
            .filter(|n| *n > 0),
        account_uuid: id("account"),
        org_uuid: id("organization"),
    })
}

/// The OAuth `error` code of an error response, if it has one.
fn oauth_error(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    v.get("error").and_then(Value::as_str).map(str::to_string)
}

fn post(
    http: &dyn HttpClient,
    refresh_token: &str,
    client_id: &str,
    scope: Option<&str>,
) -> std::result::Result<Tokens, PostErr> {
    let mut body = Map::new();
    body.insert("grant_type".into(), "refresh_token".into());
    body.insert("refresh_token".into(), refresh_token.into());
    body.insert("client_id".into(), client_id.into());
    if let Some(s) = scope {
        body.insert("scope".into(), s.into());
    }
    let bytes = Secret::new(serde_json::to_vec(&Value::Object(body)).expect("serializable"));
    let resp = http.send(&Request {
        what: WHAT,
        method: Method::Post,
        url: TOKEN_URL,
        bearer: None,
        oauth_beta: false,
        json: Some(&bytes),
    })?;
    drop(bytes);
    match resp.status {
        200 => parse_tokens(resp.body.expose()).map_err(PostErr::Unreadable),
        400 | 401 => match oauth_error(resp.body.expose()).as_deref() {
            Some("invalid_grant") => Err(PostErr::InvalidGrant),
            Some("invalid_scope") => Err(PostErr::InvalidScope),
            _ => Err(PostErr::Other(status_error(WHAT, resp.status))),
        },
        s => Err(PostErr::Other(status_error(WHAT, s))),
    }
}

/// `scope` as Claude Code sends it: the credential's scopes, space-joined.
fn scope_of(oauth: &Value) -> Option<String> {
    match oauth.get("scopes") {
        Some(Value::Array(a)) => {
            let v: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            (!v.is_empty()).then(|| v.join(" "))
        }
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// POST with `scope`, and once more without it on `invalid_scope`.
fn post_with_scope_fallback(
    http: &dyn HttpClient,
    cur: &Value,
    default_client_id: &str,
) -> std::result::Result<Tokens, PostErr> {
    let rt = str_field(cur, "refreshToken").unwrap_or_default();
    let cid = str_field(cur, "clientId").unwrap_or(default_client_id);
    match scope_of(cur) {
        Some(scope) => match post(http, rt, cid, Some(&scope)) {
            Err(PostErr::InvalidScope) => post(http, rt, cid, None),
            r => r,
        },
        None => post(http, rt, cid, None),
    }
}

/// The new credential: `cur` with the new token pair and expiries; every
/// other field is kept in place.
fn rotated(cur: &Value, t: &Tokens, now_ms: i64) -> Value {
    let mut new = cur.clone();
    let o = new.as_object_mut().expect("credential is an object");
    o.insert("accessToken".into(), t.access.as_str().into());
    o.insert("refreshToken".into(), t.refresh.as_str().into());
    o.insert(
        "expiresAt".into(),
        (now_ms + t.expires_in.saturating_mul(1000)).into(),
    );
    if let Some(r) = t.refresh_expires_in {
        o.insert(
            "refreshTokenExpiresAt".into(),
            (now_ms + r.saturating_mul(1000)).into(),
        );
    }
    new
}

/// Why a rotated pair's identity was not verified.
enum Verify {
    /// It belongs to another account, or the lookup was refused: final.
    Rejected(String),
    /// The lookup failed transiently (transport, 429, 5xx) twice.
    Unavailable(String),
    /// The profile endpoint refused the access token (401/403).
    TokenRefused(String),
}

/// A failure worth one retry.
fn transient(e: &Error) -> bool {
    matches!(
        e,
        Error::ExternalTool { program: "http", code, .. }
            if code.is_none_or(|c| c == 429 || c >= 500)
    )
}

/// Verify that a rotated pair belongs to `key`: the response's own
/// identity, else the profile of its access token (one retry on a
/// transient failure).
fn verify_identity(
    http: &dyn HttpClient,
    key: &str,
    account_uuid: Option<&str>,
    org_uuid: Option<&str>,
    access: Option<&str>,
) -> std::result::Result<(), Verify> {
    let got = match (account_uuid, org_uuid) {
        (Some(a), Some(o)) => Account::key_for(a, o),
        _ => {
            let Some(access) = access else {
                return Err(Verify::Rejected(format!(
                    "the refreshed token of {key} has neither an identity nor an access token"
                )));
            };
            let tok = Secret::new(access.as_bytes().to_vec());
            let mut found = None;
            let mut last = String::new();
            for _ in 0..PROFILE_ATTEMPTS {
                match fetch_profile(http, &tok) {
                    Ok(p) => {
                        found = Some(p.key());
                        break;
                    }
                    Err(e) if transient(&e) => last = crate::usage::error_text(&e),
                    Err(
                        e @ Error::ExternalTool {
                            program: "http",
                            code: Some(401 | 403),
                            ..
                        },
                    ) => {
                        return Err(Verify::TokenRefused(format!(
                            "the profile lookup for the refreshed token of {key} was refused ({})",
                            crate::usage::error_text(&e)
                        )));
                    }
                    Err(e) => {
                        return Err(Verify::Rejected(format!(
                            "the refresh response of {key} has no identity and its profile lookup was refused ({})",
                            crate::usage::error_text(&e)
                        )));
                    }
                }
            }
            match found {
                Some(k) => k,
                None => {
                    return Err(Verify::Unavailable(format!(
                        "the refresh response of {key} has no identity and its profile lookup failed ({last})"
                    )));
                }
            }
        }
    };
    if got == key {
        Ok(())
    } else {
        Err(Verify::Rejected(format!(
            "the refreshed token of {key} belongs to {got}; nothing stored"
        )))
    }
}

fn read_stored(ctx: &NetCtx<'_>, key: &str) -> Result<Value> {
    let s = ctx
        .store
        .get(OWN_SERVICE, key)?
        .ok_or_else(|| Error::NotFound(format!("stored credential of {key}")))?;
    oauth_of(s.expose())?.ok_or_else(|| Error::Invalid {
        what: "stored credential (no claudeAiOauth)",
        value: key.into(),
    })
}

/// Refresh `key`'s stored token if it expires within the margin. The
/// caller holds `lock` (for `key`) and has decided that this account may be
/// refreshed. Warnings come from recovery and cleanup.
pub fn refresh_locked(
    ctx: &NetCtx<'_>,
    lock: &AccountLock,
    key: &str,
) -> Result<(Refreshed, Vec<Warning>)> {
    check_lock(lock, key)?;
    let Recovery {
        mut warnings,
        promoted,
    } = recover_interrupted(ctx, lock, key)?;
    let mut cur = read_stored(ctx, key)?;
    if let Some(fingerprint) = promoted {
        // Recovery stored a credential: no second refresh while this lock
        // is held (it is fresh unless the copy sat long; then the next run
        // refreshes it).
        return Ok((
            Refreshed::Rotated {
                oauth: cur,
                fingerprint,
            },
            warnings,
        ));
    }
    let io = ctx.io();
    let wa = write_ahead_account(key);
    for attempt in 0..2 {
        let now = ctx.now_ms();
        if is_blanked(&cur) {
            return Err(Error::NeedsLogin(format!(
                "the stored credential of {key} is signed out"
            )));
        }
        if !needs_refresh(&cur, now) {
            return Ok((Refreshed::StillValid { oauth: cur }, warnings));
        }
        if refresh_deadline_passed(&cur, now) {
            return Err(Error::NeedsLogin(format!(
                "the refresh token of {key} reached its deadline; log in again"
            )));
        }
        let cur_fp = oauth_fingerprint(&cur);
        // Pre-refresh copy before the old refresh token is spent.
        ctx.store.set(BACKUP_SERVICE, &wa, &oauth_only_item(&cur))?;
        match post_with_scope_fallback(ctx.http, &cur, &ctx.client_id) {
            Ok(t) => return finish_rotation(&io, key, &cur, Some(&cur_fp), &t, warnings),
            Err(PostErr::InvalidGrant) => {
                cleanup(&io, &wa, &mut warnings);
                let again = read_stored(ctx, key)?;
                let changed = str_field(&again, "refreshToken") != str_field(&cur, "refreshToken");
                if attempt == 0 && changed {
                    warnings.push(Warning::new(
                        "refresh_retried",
                        format!(
                            "the refresh token of {key} changed during its refresh; retried with the new one"
                        ),
                    ));
                    cur = again;
                    continue;
                }
                return Err(Error::NeedsLogin(format!(
                    "the refresh token of {key} was rejected (invalid_grant); log in again"
                )));
            }
            Err(PostErr::Unreadable(e)) => {
                cleanup(&io, &wa, &mut warnings);
                return Err(Error::NeedsLogin(format!(
                    "the token endpoint answered for {key} but its response could not be read ({}); the old refresh token is spent; log in again",
                    e.code()
                )));
            }
            Err(PostErr::InvalidScope) => {
                cleanup(&io, &wa, &mut warnings);
                return Err(status_error(WHAT, 400));
            }
            Err(PostErr::Other(e)) => {
                cleanup(&io, &wa, &mut warnings);
                return Err(e);
            }
        }
    }
    unreachable!("the loop returns on its second pass")
}

/// After a 200: keep the rotated pair aside, verify it, store it.
/// `cur` is what was refreshed; `from_fp` the stored credential it may
/// replace (`None`: only a missing or unreadable one).
fn finish_rotation(
    io: &Io<'_>,
    key: &str,
    cur: &Value,
    from_fp: Option<&str>,
    t: &Tokens,
    mut warnings: Vec<Warning>,
) -> Result<(Refreshed, Vec<Warning>)> {
    let wa = write_ahead_account(key);
    let pa = post_refresh_account(key);
    let new = rotated(cur, t, io.now_ms());
    // The old refresh token is spent: the rotated pair goes somewhere
    // durable before anything else can fail.
    let kept = match post_refresh_item(
        &new,
        t.account_uuid.as_deref(),
        t.org_uuid.as_deref(),
        from_fp,
    )
    .and_then(|item| set_retry(io.store, BACKUP_SERVICE, &pa, &item))
    {
        Ok(()) => true,
        Err(e) => {
            warnings.push(Warning::new(
                "refresh_copy_failed",
                format!(
                    "could not keep a post-refresh copy of {key} ({}); storing it directly",
                    e.code()
                ),
            ));
            false
        }
    };
    #[cfg(test)]
    if failpoint::crash() {
        return Err(Error::Interrupted);
    }
    match verify_identity(
        io.http,
        key,
        t.account_uuid.as_deref(),
        t.org_uuid.as_deref(),
        Some(t.access.as_str()),
    ) {
        Ok(()) => {}
        // A token issued a moment ago that the profile refuses is final.
        Err(Verify::Rejected(m)) | Err(Verify::TokenRefused(m)) => {
            cleanup(io, &pa, &mut warnings);
            cleanup(io, &wa, &mut warnings);
            return Err(Error::NeedsLogin(format!(
                "{m}; the old refresh token is spent; log in again"
            )));
        }
        Err(Verify::Unavailable(m)) if kept => {
            return Err(Error::RefreshPending(format!(
                "{m}; nothing stored, the refreshed token is kept aside and checked again on the next run (`cma usage`)"
            )));
        }
        Err(Verify::Unavailable(m)) => {
            // An older copy, if one was left, holds a spent token now.
            cleanup(io, &pa, &mut warnings);
            cleanup(io, &wa, &mut warnings);
            return Err(Error::NeedsLogin(format!(
                "{m}; nothing stored and the old refresh token is spent; log in again"
            )));
        }
    }
    // Only over the credential this refresh started from: a login or import
    // that stored a newer grant meanwhile wins (it is independent and
    // valid). A stored item that went missing or unreadable meanwhile gets
    // the verified pair.
    let now_fp = stored_lenient(io, key)?.map(|o| oauth_fingerprint(&o));
    if now_fp.as_deref().is_some_and(|fp| Some(fp) != from_fp) {
        cleanup(io, &pa, &mut warnings);
        cleanup(io, &wa, &mut warnings);
        return Err(Error::ConcurrentWrite(format!(
            "the stored credential of {key} was replaced during its refresh; kept the replacement"
        )));
    }
    if let Err(e) = set_retry(io.store, OWN_SERVICE, key, &oauth_only_item(&new)) {
        if kept {
            // The next run stores the post-refresh copy.
            return Err(e);
        }
        cleanup(io, &pa, &mut warnings);
        cleanup(io, &wa, &mut warnings);
        return Err(Error::NeedsLogin(format!(
            "storing the refreshed token of {key} failed ({}) and no copy of it could be kept; log in again",
            e.code()
        )));
    }
    cleanup(io, &pa, &mut warnings);
    cleanup(io, &wa, &mut warnings);
    let fingerprint = oauth_fingerprint(&new);
    Ok((
        Refreshed::Rotated {
            oauth: new,
            fingerprint,
        },
        warnings,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cli_target::stored_oauth;
    use crate::cli_target::testkit::*;
    use crate::http::tests::{FakeHttp, Seen, resp};
    use crate::paths::MapEnv;
    use crate::secret::MemoryStore;
    use serde_json::json;

    pub fn token_body(tag: &str, acct: &str, org: &str) -> String {
        json!({
            "access_token": format!("at-{tag}"),
            "refresh_token": format!("rt-{tag}"),
            "expires_in": 28800,
            "refresh_token_expires_in": 2_000_000,
            "scope": "user:inference user:profile",
            "token_type": "Bearer",
            "token_uuid": "tu-1",
            "account": {"uuid": acct, "email_address": "x@x"},
            "organization": {"uuid": org, "name": "Org"},
        })
        .to_string()
    }

    /// A credential of `tag` whose access token is expired.
    pub fn expired(tag: &str) -> Value {
        let mut o = oauth(tag);
        o["expiresAt"] = (NOW_MS - 1000).into();
        o
    }

    pub fn net<'a>(w: &'a World, store: &'a MemoryStore, http: &'a FakeHttp) -> NetCtx<'a> {
        NetCtx {
            paths: &w.paths,
            store,
            http,
            client_id: CLIENT_ID.into(),
            now_ms: now,
        }
    }

    pub fn put(store: &MemoryStore, key: &str, o: &Value) {
        store.set(OWN_SERVICE, key, &oauth_only_item(o)).unwrap();
    }

    /// Strict server: an unspent `rt-<tag>` rotates to `<tag>2` (for
    /// `acct`/`org`) and is spent from then on; a spent one answers
    /// `invalid_grant`, as the real endpoint does after a rotation.
    pub fn server_for(acct: &'static str, org: &'static str) -> FakeHttp {
        let spent = std::sync::Mutex::new(std::collections::HashSet::new());
        FakeHttp::new(move |s: &Seen| {
            let rt = s.json.as_ref().unwrap()["refresh_token"]
                .as_str()
                .unwrap()
                .to_string();
            if !spent.lock().unwrap().insert(rt.clone()) {
                return resp(400, r#"{"error":"invalid_grant"}"#);
            }
            let tag = rt.trim_start_matches("rt-");
            resp(200, &token_body(&format!("{tag}2"), acct, org))
        })
    }

    /// A store whose next `fail_own_sets` writes of a stored credential
    /// fail like `security` does.
    pub struct FlakyStore<'a> {
        pub inner: &'a MemoryStore,
        pub fail_own_sets: std::sync::atomic::AtomicUsize,
    }

    impl<'a> FlakyStore<'a> {
        pub fn new(inner: &'a MemoryStore, fails: usize) -> Self {
            FlakyStore {
                inner,
                fail_own_sets: fails.into(),
            }
        }
    }

    impl SecretStore for FlakyStore<'_> {
        fn get(&self, s: &str, a: &str) -> Result<Option<Secret>> {
            self.inner.get(s, a)
        }
        fn set(&self, s: &str, a: &str, v: &Secret) -> Result<()> {
            use std::sync::atomic::Ordering;
            if s == OWN_SERVICE
                && self
                    .fail_own_sets
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
            {
                return Err(Error::ExternalTool {
                    program: "security",
                    sub: "add-generic-password",
                    code: Some(1),
                    class: crate::error::ToolFailure::Other,
                });
            }
            self.inner.set(s, a, v)
        }
        fn delete(&self, s: &str, a: &str) -> Result<bool> {
            self.inner.delete(s, a)
        }
    }

    struct NoCrash;
    impl Drop for NoCrash {
        fn drop(&mut self) {
            failpoint::set(false);
        }
    }

    #[test]
    fn request_carries_scope_and_client_id_and_rotates() {
        let w = World::new();
        let http = server_for("A", "oA");
        let ctx = net(&w, &w.store, &http);
        let mut cur = expired("A");
        cur["extraField"] = json!({"keep": true});
        put(&w.store, "A::oA", &cur);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, warnings) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(warnings.is_empty());
        let reqs = http.requests("oauth/token");
        assert_eq!(reqs.len(), 1);
        let body = reqs[0].json.as_ref().unwrap();
        assert_eq!(reqs[0].url, TOKEN_URL);
        assert_eq!(reqs[0].method, Method::Post);
        assert!(reqs[0].bearer.is_none());
        assert_eq!(
            body,
            &json!({
                "grant_type": "refresh_token",
                "refresh_token": "rt-A",
                "client_id": CLIENT_ID,
                "scope": "user:inference user:profile",
            })
        );
        let Refreshed::Rotated {
            oauth: new,
            fingerprint,
        } = r
        else {
            panic!("{r:?}")
        };
        assert_eq!(new["accessToken"], "at-A2");
        assert_eq!(new["refreshToken"], "rt-A2");
        assert_eq!(new["expiresAt"], NOW_MS + 28_800_000);
        assert_eq!(new["refreshTokenExpiresAt"], NOW_MS + 2_000_000_000);
        assert_eq!(new["subscriptionType"], "max");
        assert_eq!(new["extraField"]["keep"], true);
        // Key order kept: the fingerprint matches what was stored.
        let stored = stored_oauth(&w.store, "A::oA").unwrap().unwrap();
        assert_eq!(stored, new);
        assert_eq!(fingerprint, oauth_fingerprint(&stored));
        let keys: Vec<&String> = stored.as_object().unwrap().keys().collect();
        assert_eq!(keys[0], "accessToken");
        // The write-ahead copy is gone.
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn stored_client_id_and_env_override_are_used() {
        let w = World::new();
        let http = server_for("A", "oA");
        let mut ctx = net(&w, &w.store, &http);
        ctx.client_id = client_id(&MapEnv::new([(CLIENT_ID_ENV, "env-client")]));
        assert_eq!(client_id(&MapEnv::default()), CLIENT_ID);
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        refresh_locked(&ctx, &lock, "A::oA").unwrap();
        let mut cur = expired("A3");
        cur["clientId"] = "stored-client".into();
        put(&w.store, "A::oA", &cur);
        refresh_locked(&ctx, &lock, "A::oA").unwrap();
        let reqs = http.requests("oauth/token");
        assert_eq!(reqs[0].json.as_ref().unwrap()["client_id"], "env-client");
        assert_eq!(reqs[1].json.as_ref().unwrap()["client_id"], "stored-client");
    }

    #[test]
    fn response_for_another_account_or_org_stores_nothing_and_needs_login() {
        for (acct, org) in [("B", "oA"), ("A", "oB")] {
            let w = World::new();
            let http = server_for(acct, org);
            let ctx = net(&w, &w.store, &http);
            let cur = expired("A");
            put(&w.store, "A::oA", &cur);
            let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
            // The old refresh token is spent: needs login at once.
            let e = refresh_locked(&ctx, &lock, "A::oA").unwrap_err();
            assert!(matches!(e, Error::NeedsLogin(_)), "{e:?}");
            assert!(e.to_string().contains("belongs to"), "{e}");
            assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), cur);
            assert_eq!(w.store.count(BACKUP_SERVICE), 0);
        }
    }

    #[test]
    fn response_without_identity_falls_back_to_profile() {
        let w = World::new();
        let http = FakeHttp::new(|s: &Seen| match s.what {
            "oauth/token" => resp(
                200,
                r#"{"access_token":"at-A2","refresh_token":"rt-A2","expires_in":28800}"#,
            ),
            "oauth/profile" if s.bearer.as_deref() == Some("at-A2") => resp(
                200,
                r#"{"account":{"uuid":"A"},"organization":{"uuid":"oA"}}"#,
            ),
            _ => resp(401, "{}"),
        });
        let ctx = net(&w, &w.store, &http);
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, _) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(matches!(r, Refreshed::Rotated { .. }));
        assert_eq!(http.count("oauth/profile"), 1);
        // No refresh_token_expires_in: the old deadline stays.
        let s = stored_oauth(&w.store, "A::oA").unwrap().unwrap();
        assert_eq!(s["refreshTokenExpiresAt"], FAR_FUTURE_MS);

        // Profile names someone else, or refuses the token: nothing
        // stored, needs login, no copy kept.
        for profile in [
            resp(
                200,
                r#"{"account":{"uuid":"B"},"organization":{"uuid":"oB"}}"#,
            ),
            resp(401, "{}"),
        ] {
            let http = FakeHttp::new(|_| resp(500, "{}"));
            http.script(resp(
                200,
                r#"{"access_token":"at-A9","refresh_token":"rt-A9","expires_in":28800}"#,
            ));
            http.script(profile);
            let ctx = net(&w, &w.store, &http);
            let before = expired("A5");
            put(&w.store, "A::oA", &before);
            assert!(matches!(
                refresh_locked(&ctx, &lock, "A::oA"),
                Err(Error::NeedsLogin(_))
            ));
            assert_eq!(http.count("oauth/profile"), 1, "no retry when refused");
            assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), before);
            assert_eq!(w.store.count(BACKUP_SERVICE), 0);
        }
    }

    const NO_IDENTITY: &str =
        r#"{"access_token":"at-A9","refresh_token":"rt-A9","expires_in":28800}"#;
    const PROFILE_A: &str = r#"{"account":{"uuid":"A"},"organization":{"uuid":"oA"}}"#;

    #[test]
    fn transient_profile_failure_is_retried_once() {
        let w = World::new();
        let http = FakeHttp::new(|_| resp(500, "{}"));
        http.script(resp(200, NO_IDENTITY));
        http.script(resp(503, "{}"));
        http.script(resp(200, PROFILE_A));
        let ctx = net(&w, &w.store, &http);
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, _) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(matches!(r, Refreshed::Rotated { .. }));
        assert_eq!(http.count("oauth/profile"), 2);
        assert_eq!(
            stored_oauth(&w.store, "A::oA").unwrap().unwrap()["refreshToken"],
            "rt-A9"
        );
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn failed_profile_lookup_keeps_the_rotated_pair_for_a_later_check() {
        let w = World::new();
        let http = FakeHttp::new(|_| resp(500, "{}"));
        http.script(resp(200, NO_IDENTITY));
        let ctx = net(&w, &w.store, &http);
        let before = expired("A");
        put(&w.store, "A::oA", &before);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        // Both lookups fail: nothing stored, not needs_login, pair kept.
        let e = refresh_locked(&ctx, &lock, "A::oA").unwrap_err();
        assert!(matches!(e, Error::RefreshPending(_)), "{e:?}");
        assert_eq!(e.code(), "refresh_pending");
        assert_eq!(http.count("oauth/profile"), 2);
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), before);
        assert!(
            w.store
                .get(BACKUP_SERVICE, &post_refresh_account("A::oA"))
                .unwrap()
                .is_some()
        );
        // Still unavailable on the next run: kept again, no POST with the
        // spent token.
        let e = refresh_locked(&ctx, &lock, "A::oA").unwrap_err();
        assert!(matches!(e, Error::RefreshPending(_)), "{e:?}");
        assert_eq!(http.count("oauth/token"), 1);

        // Later the lookup works: the kept pair is verified and stored.
        let http = FakeHttp::new(|s: &Seen| match s.what {
            "oauth/profile" if s.bearer.as_deref() == Some("at-A9") => resp(200, PROFILE_A),
            _ => resp(400, r#"{"error":"invalid_grant"}"#),
        });
        let ctx = net(&w, &w.store, &http);
        let (r, warnings) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        let Refreshed::Rotated { fingerprint, .. } = r else {
            panic!("{r:?}")
        };
        assert!(warnings.iter().any(|x| x.code == "refresh_recovered"));
        let s = stored_oauth(&w.store, "A::oA").unwrap().unwrap();
        assert_eq!(s["refreshToken"], "rt-A9");
        assert_eq!(fingerprint, oauth_fingerprint(&s));
        assert_eq!(http.count("oauth/token"), 0);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);

        // A kept pair whose access token the profile refuses is checked by
        // refreshing it; when its refresh token is refused too it is
        // dropped: needs login.
        let http = FakeHttp::new(|_| resp(500, "{}"));
        http.script(resp(200, NO_IDENTITY));
        let ctx = net(&w, &w.store, &http);
        put(&w.store, "A::oA", &expired("A5"));
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::RefreshPending(_))
        ));
        let http = FakeHttp::new(|s: &Seen| match s.what {
            "oauth/profile" => resp(401, "{}"),
            _ => resp(400, r#"{"error":"invalid_grant"}"#),
        });
        let ctx = net(&w, &w.store, &http);
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::NeedsLogin(_))
        ));
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
        let posts = http.requests("oauth/token");
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].json.as_ref().unwrap()["refresh_token"], "rt-A9");
    }

    /// Nine hours after [`NOW_MS`]: past an 8 h access token.
    fn nine_hours_later() -> i64 {
        NOW_MS + 9 * 3_600_000
    }

    #[test]
    fn kept_pair_whose_access_token_expired_is_verified_by_refreshing_it() {
        let w = World::new();
        let http = FakeHttp::new(|_| resp(500, "{}"));
        http.script(resp(200, NO_IDENTITY));
        let ctx = net(&w, &w.store, &http);
        let before = expired("A");
        put(&w.store, "A::oA", &before);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        // The lookup is unavailable: rt-A9 (access token valid for 8 h) is
        // kept aside.
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::RefreshPending(_))
        ));

        // Nine hours later its access token has expired. The profile would
        // refuse it, but its refresh token is the valid grant: it is
        // refreshed, and that response's identity decides.
        let http = FakeHttp::new(|s: &Seen| match s.what {
            "oauth/profile" if s.bearer.as_deref() == Some("at-A92") => resp(200, PROFILE_A),
            "oauth/profile" => resp(401, "{}"),
            _ => {
                let rt = s.json.as_ref().unwrap()["refresh_token"].as_str().unwrap();
                if rt == "rt-A9" {
                    resp(
                        200,
                        r#"{"access_token":"at-A92","refresh_token":"rt-A92","expires_in":28800}"#,
                    )
                } else {
                    resp(400, r#"{"error":"invalid_grant"}"#)
                }
            }
        });
        let ctx = NetCtx {
            now_ms: nine_hours_later,
            ..net(&w, &w.store, &http)
        };
        let (r, warnings) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        let Refreshed::Rotated { fingerprint, .. } = r else {
            panic!("{r:?}")
        };
        assert!(warnings.iter().any(|x| x.code == "refresh_recovered"));
        let s = stored_oauth(&w.store, "A::oA").unwrap().unwrap();
        assert_eq!(s["refreshToken"], "rt-A92");
        assert_eq!(s["expiresAt"], nine_hours_later() + 28_800_000);
        assert_eq!(fingerprint, oauth_fingerprint(&s));
        // The expired token was never sent to the profile endpoint.
        assert!(
            http.requests("oauth/profile")
                .iter()
                .all(|r| r.bearer.as_deref() == Some("at-A92"))
        );
        assert_eq!(http.count("oauth/token"), 1);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn kept_pair_refreshed_but_unverified_is_kept_again() {
        // The refresh of the kept pair succeeds but its identity cannot be
        // looked up: the newer pair replaces the kept one (the older one is
        // spent now) and stays aside.
        let w = World::new();
        let http = FakeHttp::new(|_| resp(500, "{}"));
        http.script(resp(200, NO_IDENTITY));
        let ctx = net(&w, &w.store, &http);
        let before = expired("A");
        put(&w.store, "A::oA", &before);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        assert!(refresh_locked(&ctx, &lock, "A::oA").is_err());
        let http = FakeHttp::new(|s: &Seen| match s.what {
            "oauth/profile" => resp(503, "{}"),
            _ => resp(
                200,
                r#"{"access_token":"at-A92","refresh_token":"rt-A92","expires_in":28800}"#,
            ),
        });
        let ctx = NetCtx {
            now_ms: nine_hours_later,
            ..net(&w, &w.store, &http)
        };
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::RefreshPending(_))
        ));
        let kept = w
            .store
            .get(BACKUP_SERVICE, &post_refresh_account("A::oA"))
            .unwrap()
            .unwrap();
        let copy = parse_post(&kept).unwrap();
        assert_eq!(copy.oauth["refreshToken"], "rt-A92");
        assert_eq!(copy.from, Some(oauth_fingerprint(&before)));
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), before);
    }

    #[test]
    fn unreadable_success_response_needs_login() {
        let w = World::new();
        let http = FakeHttp::new(|_| resp(200, r#"{"access_token":"at-x"}"#));
        let ctx = net(&w, &w.store, &http);
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::NeedsLogin(_))
        ));
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn store_failure_after_success_is_retried_once() {
        let w = World::new();
        let http = server_for("A", "oA");
        let store = FlakyStore::new(&w.store, 1);
        let ctx = NetCtx {
            store: &store,
            ..net(&w, &w.store, &http)
        };
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, _) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(matches!(r, Refreshed::Rotated { .. }));
        assert_eq!(
            stored_oauth(&w.store, "A::oA").unwrap().unwrap()["refreshToken"],
            "rt-A2"
        );
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn store_failure_after_success_is_recovered_by_the_next_run() {
        let w = World::new();
        let http = server_for("A", "oA");
        let store = FlakyStore::new(&w.store, 2);
        let ctx = NetCtx {
            store: &store,
            ..net(&w, &w.store, &http)
        };
        let before = expired("A");
        put(&w.store, "A::oA", &before);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let e = refresh_locked(&ctx, &lock, "A::oA").unwrap_err();
        assert!(
            matches!(
                e,
                Error::ExternalTool {
                    program: "security",
                    ..
                }
            ),
            "{e:?}"
        );
        // The stored token is spent; the rotated pair is kept aside.
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), before);
        assert!(
            w.store
                .get(BACKUP_SERVICE, &post_refresh_account("A::oA"))
                .unwrap()
                .is_some()
        );
        // Next run: recovered from the copy, without a POST of the spent
        // token (which the strict server would reject).
        let (r, warnings) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(matches!(r, Refreshed::Rotated { .. }), "{r:?}");
        assert!(warnings.iter().any(|x| x.code == "refresh_recovered"));
        assert_eq!(http.count("oauth/token"), 1);
        assert_eq!(
            stored_oauth(&w.store, "A::oA").unwrap().unwrap()["refreshToken"],
            "rt-A2"
        );
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn failed_cleanup_after_a_stored_rotation_is_only_a_warning() {
        struct NoDelete<'a>(&'a MemoryStore);
        impl SecretStore for NoDelete<'_> {
            fn get(&self, s: &str, a: &str) -> Result<Option<Secret>> {
                self.0.get(s, a)
            }
            fn set(&self, s: &str, a: &str, v: &Secret) -> Result<()> {
                self.0.set(s, a, v)
            }
            fn delete(&self, _: &str, _: &str) -> Result<bool> {
                Err(Error::ExternalTool {
                    program: "security",
                    sub: "delete-generic-password",
                    code: Some(1),
                    class: crate::error::ToolFailure::Other,
                })
            }
        }
        let w = World::new();
        let http = server_for("A", "oA");
        let store = NoDelete(&w.store);
        let ctx = NetCtx {
            store: &store,
            ..net(&w, &w.store, &http)
        };
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, warnings) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(matches!(r, Refreshed::Rotated { .. }));
        assert!(warnings.iter().any(|x| x.code == "refresh_cleanup_failed"));
        // The leftovers are recognised as such later: nothing is undone.
        let ctx = net(&w, &w.store, &http);
        let rec = recover_interrupted(&ctx, &lock, "A::oA").unwrap();
        assert_eq!(rec.promoted, None);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
        assert_eq!(
            stored_oauth(&w.store, "A::oA").unwrap().unwrap()["refreshToken"],
            "rt-A2"
        );
    }

    #[test]
    fn refreshed_debug_shows_no_token() {
        let o = oauth("A");
        let s = format!(
            "{:?} {:?}",
            Refreshed::StillValid { oauth: o.clone() },
            Refreshed::Rotated {
                oauth: o.clone(),
                fingerprint: "fp".into()
            }
        );
        assert!(!s.contains("at-A") && !s.contains("rt-A"), "{s}");
    }

    #[test]
    fn slowest_refresh_stays_within_the_request_budget() {
        // invalid_scope, invalid_grant after a concurrent rotation,
        // invalid_scope again, then a response whose identity needs a
        // profile lookup that fails once.
        let w = World::new();
        let store = std::sync::Arc::new(MemoryStore::new());
        let s2 = store.clone();
        let lookups = std::sync::atomic::AtomicUsize::new(0);
        let http = FakeHttp::new(move |s: &Seen| {
            if s.what == "oauth/profile" {
                let n = lookups.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return if n == 0 {
                    resp(503, "{}")
                } else {
                    resp(200, PROFILE_A)
                };
            }
            let j = s.json.as_ref().unwrap();
            if j.get("scope").is_some() {
                return resp(400, r#"{"error":"invalid_scope"}"#);
            }
            if j["refresh_token"] == "rt-A" {
                put(&s2, "A::oA", &expired("B7"));
                return resp(400, r#"{"error":"invalid_grant"}"#);
            }
            resp(200, NO_IDENTITY)
        });
        put(&store, "A::oA", &expired("A"));
        let ctx = net(&w, &store, &http);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, _) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(matches!(r, Refreshed::Rotated { .. }));
        let n = http.seen.lock().unwrap().len() as u64;
        assert_eq!(n, ROTATION_MAX_REQUESTS, "the path is the slowest one");
        assert!(n <= REFRESH_MAX_REQUESTS);
    }

    #[test]
    fn slowest_recovery_stays_within_the_request_budget_and_does_not_refresh_again() {
        // A kept copy without identity: profile 503, then 401; refreshing
        // its token answers invalid_scope, then a response without
        // identity whose lookup fails once.
        let w = World::new();
        let mut kept = oauth("K");
        kept["expiresAt"] = (NOW_MS + 3_600_000).into();
        let from = expired("A");
        put(&w.store, "A::oA", &from);
        w.store
            .set(
                BACKUP_SERVICE,
                &post_refresh_account("A::oA"),
                &post_refresh_item(&kept, None, None, Some(&oauth_fingerprint(&from))).unwrap(),
            )
            .unwrap();
        let http = FakeHttp::new(|s: &Seen| match s.what {
            "oauth/profile" if s.bearer.as_deref() == Some("at-A9") => resp(200, PROFILE_A),
            "oauth/profile" => resp(500, "{}"),
            _ if s.json.as_ref().unwrap().get("scope").is_some() => {
                resp(400, r#"{"error":"invalid_scope"}"#)
            }
            _ if s.json.as_ref().unwrap()["refresh_token"] == "rt-K" => resp(200, NO_IDENTITY),
            _ => resp(400, r#"{"error":"invalid_grant"}"#),
        });
        http.script(resp(503, "{}"));
        http.script(resp(401, "{}"));
        http.script(resp(400, r#"{"error":"invalid_scope"}"#));
        http.script(resp(200, NO_IDENTITY));
        http.script(resp(502, "{}"));
        let ctx = net(&w, &w.store, &http);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, warnings) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(matches!(r, Refreshed::Rotated { .. }), "{r:?}");
        assert!(warnings.iter().any(|x| x.code == "refresh_recovered"));
        let n = http.seen.lock().unwrap().len() as u64;
        assert_eq!(n, RECOVERY_MAX_REQUESTS, "the path is the slowest one");
        assert!(n <= REFRESH_MAX_REQUESTS);
        assert_eq!(
            stored_oauth(&w.store, "A::oA").unwrap().unwrap()["refreshToken"],
            "rt-A9"
        );
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn account_lock_wait_outlasts_the_slowest_refresh() {
        let slowest = crate::http::TIMEOUT * u32::try_from(REFRESH_MAX_REQUESTS).unwrap();
        assert!(crate::lock::ACCOUNT_LOCK_TIMEOUT > slowest);
    }

    #[test]
    fn past_refresh_deadline_or_signed_out_needs_login_without_a_post() {
        let w = World::new();
        let http = server_for("A", "oA");
        let ctx = net(&w, &w.store, &http);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let mut cur = expired("A");
        cur["refreshTokenExpiresAt"] = (NOW_MS - 1).into();
        put(&w.store, "A::oA", &cur);
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::NeedsLogin(_))
        ));
        put(&w.store, "A::oA", &blanked());
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::NeedsLogin(_))
        ));
        assert_eq!(http.count("oauth/token"), 0);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn unexpired_token_is_not_refreshed() {
        let w = World::new();
        let http = server_for("A", "oA");
        let ctx = net(&w, &w.store, &http);
        put(&w.store, "A::oA", &oauth("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, _) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert_eq!(r, Refreshed::StillValid { oauth: oauth("A") });
        assert_eq!(http.count("oauth/token"), 0);
    }

    #[test]
    fn crash_after_success_is_recovered_from_the_post_refresh_copy() {
        let _reset = NoCrash;
        for stored_after_crash in ["intact", "missing", "unreadable"] {
            let w = World::new();
            let http = server_for("A", "oA");
            let ctx = net(&w, &w.store, &http);
            let cur = expired("A");
            put(&w.store, "A::oA", &cur);
            let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
            failpoint::set(true);
            assert!(matches!(
                refresh_locked(&ctx, &lock, "A::oA"),
                Err(Error::Interrupted)
            ));
            failpoint::set(false);
            // Both copies are there; the stored token is spent.
            let pre = w
                .store
                .get(BACKUP_SERVICE, &write_ahead_account("A::oA"))
                .unwrap()
                .unwrap();
            assert_eq!(pre.expose(), oauth_only_item(&cur).expose());
            assert!(
                w.store
                    .get(BACKUP_SERVICE, &post_refresh_account("A::oA"))
                    .unwrap()
                    .is_some()
            );
            match stored_after_crash {
                "missing" => {
                    w.store.delete(OWN_SERVICE, "A::oA").unwrap();
                }
                "unreadable" => w
                    .store
                    .set(OWN_SERVICE, "A::oA", &Secret::new(b"{trunc".to_vec()))
                    .unwrap(),
                _ => {}
            }
            // The next refresh stores the rotated pair without a POST: the
            // strict server would reject the spent token.
            let (r, warnings) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
            assert!(
                warnings.iter().any(|x| x.code == "refresh_recovered"),
                "{stored_after_crash}"
            );
            let Refreshed::Rotated { fingerprint, .. } = r else {
                panic!("{r:?}")
            };
            let s = stored_oauth(&w.store, "A::oA").unwrap().unwrap();
            assert_eq!(s["refreshToken"], "rt-A2");
            assert_eq!(s["accessToken"], "at-A2");
            assert_eq!(fingerprint, oauth_fingerprint(&s));
            assert_eq!(http.count("oauth/token"), 1, "{stored_after_crash}");
            assert_eq!(w.store.count(BACKUP_SERVICE), 0);
        }
    }

    #[test]
    fn spent_refresh_token_is_rejected_by_the_strict_server() {
        let w = World::new();
        let http = server_for("A", "oA");
        let ctx = net(&w, &w.store, &http);
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        refresh_locked(&ctx, &lock, "A::oA").unwrap();
        // Putting the spent pair back (what restoring a pre-refresh copy
        // amounts to) ends in needs_login.
        put(&w.store, "A::oA", &expired("A"));
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::NeedsLogin(_))
        ));
    }

    #[test]
    fn pre_refresh_copy_restores_a_lost_item_only() {
        let w = World::new();
        let http = server_for("A", "oA");
        let ctx = net(&w, &w.store, &http);
        let cur = oauth("A");
        let wa = write_ahead_account("A::oA");
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        // Intact stored item: report and clean up.
        put(&w.store, "A::oA", &cur);
        w.store
            .set(BACKUP_SERVICE, &wa, &oauth_only_item(&cur))
            .unwrap();
        let rec = recover_interrupted(&ctx, &lock, "A::oA").unwrap();
        assert_eq!(rec.warnings[0].code, "refresh_interrupted");
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
        // Lost: put back.
        w.store
            .set(BACKUP_SERVICE, &wa, &oauth_only_item(&cur))
            .unwrap();
        w.store.delete(OWN_SERVICE, "A::oA").unwrap();
        let rec = recover_interrupted(&ctx, &lock, "A::oA").unwrap();
        assert_eq!(rec.warnings[0].code, "refresh_restored");
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), cur);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn post_refresh_copy_never_overrides_a_newer_login() {
        let w = World::new();
        let http = server_for("A", "oA");
        let ctx = net(&w, &w.store, &http);
        let from = expired("A");
        let kept = oauth("A2");
        w.store
            .set(
                BACKUP_SERVICE,
                &post_refresh_account("A::oA"),
                &post_refresh_item(
                    &kept,
                    Some("A"),
                    Some("oA"),
                    Some(&oauth_fingerprint(&from)),
                )
                .unwrap(),
            )
            .unwrap();
        // A login stored a newer grant after the interrupted refresh.
        put(&w.store, "A::oA", &oauth("L"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let rec = recover_interrupted(&ctx, &lock, "A::oA").unwrap();
        assert_eq!(rec.promoted, None);
        assert_eq!(rec.warnings[0].code, "refresh_superseded");
        assert_eq!(
            stored_oauth(&w.store, "A::oA").unwrap().unwrap(),
            oauth("L")
        );
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);

        // A copy that names another account is never stored.
        w.store
            .set(
                BACKUP_SERVICE,
                &post_refresh_account("A::oA"),
                &post_refresh_item(
                    &kept,
                    Some("B"),
                    Some("oB"),
                    Some(&oauth_fingerprint(&from)),
                )
                .unwrap(),
            )
            .unwrap();
        put(&w.store, "A::oA", &from);
        assert!(matches!(
            recover_interrupted(&ctx, &lock, "A::oA"),
            Err(Error::NeedsLogin(_))
        ));
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), from);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
        assert_eq!(http.seen.lock().unwrap().len(), 0);
    }

    #[test]
    fn two_concurrent_refreshers_send_exactly_one_post() {
        let w = World::new();
        let http = FakeHttp::new(|s: &Seen| {
            // Slow server so both refreshers overlap.
            std::thread::sleep(std::time::Duration::from_millis(150));
            let rt = s.json.as_ref().unwrap()["refresh_token"].as_str().unwrap();
            if rt == "rt-A" {
                resp(200, &token_body("A2", "A", "oA"))
            } else {
                resp(400, r#"{"error":"invalid_grant"}"#)
            }
        });
        put(&w.store, "A::oA", &expired("A"));
        let (paths, store, http) = (&w.paths, &w.store, &http);
        let results: Vec<Refreshed> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..2)
                .map(|_| {
                    sc.spawn(move || {
                        let ctx = NetCtx {
                            paths,
                            store,
                            http,
                            client_id: CLIENT_ID.into(),
                            now_ms: now,
                        };
                        let lock = AccountLock::acquire(paths, "A::oA").unwrap();
                        refresh_locked(&ctx, &lock, "A::oA").unwrap().0
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(http.count("oauth/token"), 1, "exactly one POST");
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Refreshed::StillValid { .. }))
                .count(),
            1,
            "the other re-read the rotated credential"
        );
        let s = stored_oauth(&w.store, "A::oA").unwrap().unwrap();
        assert_eq!(s["refreshToken"], "rt-A2");
    }

    #[test]
    fn invalid_grant_after_concurrent_rotation_retries_and_succeeds() {
        let w = World::new();
        let store = std::sync::Arc::new(MemoryStore::new());
        let s2 = store.clone();
        let http = FakeHttp::new(move |s: &Seen| {
            let rt = s.json.as_ref().unwrap()["refresh_token"].as_str().unwrap();
            if rt == "rt-A" {
                // Another writer stored a newer grant while this POST ran.
                put(&s2, "A::oA", &expired("B7"));
                resp(400, r#"{"error":"invalid_grant","error_description":"x"}"#)
            } else {
                resp(200, &token_body("B8", "A", "oA"))
            }
        });
        let ctx = net(&w, &store, &http);
        put(&store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        let (r, warnings) = refresh_locked(&ctx, &lock, "A::oA").unwrap();
        assert!(matches!(r, Refreshed::Rotated { .. }));
        assert_eq!(warnings[0].code, "refresh_retried");
        let reqs = http.requests("oauth/token");
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[1].json.as_ref().unwrap()["refresh_token"], "rt-B7");
        assert_eq!(
            stored_oauth(&*store, "A::oA").unwrap().unwrap()["refreshToken"],
            "rt-B8"
        );
        assert_eq!(store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn invalid_grant_with_unchanged_token_needs_login() {
        let w = World::new();
        let http = FakeHttp::new(|_| resp(400, r#"{"error":"invalid_grant"}"#));
        let ctx = net(&w, &w.store, &http);
        let cur = expired("A");
        put(&w.store, "A::oA", &cur);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::NeedsLogin(_))
        ));
        assert_eq!(http.count("oauth/token"), 1);
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), cur);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn invalid_scope_retries_without_scope() {
        let w = World::new();
        let http = FakeHttp::new(|s: &Seen| {
            if s.json.as_ref().unwrap().get("scope").is_some() {
                resp(400, r#"{"error":"invalid_scope"}"#)
            } else {
                resp(200, &token_body("A2", "A", "oA"))
            }
        });
        let ctx = net(&w, &w.store, &http);
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        refresh_locked(&ctx, &lock, "A::oA").unwrap();
        let reqs = http.requests("oauth/token");
        assert_eq!(reqs.len(), 2);
        assert!(reqs[1].json.as_ref().unwrap().get("scope").is_none());
    }

    #[test]
    fn replacement_during_post_is_kept() {
        let w = World::new();
        let store = std::sync::Arc::new(MemoryStore::new());
        let s2 = store.clone();
        let http = FakeHttp::new(move |_| {
            // A re-login stored a fresh grant while the POST ran.
            put(&s2, "A::oA", &oauth("L"));
            resp(200, &token_body("A2", "A", "oA"))
        });
        let ctx = net(&w, &store, &http);
        put(&store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::ConcurrentWrite(_))
        ));
        assert_eq!(stored_oauth(&*store, "A::oA").unwrap().unwrap(), oauth("L"));
        assert_eq!(store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn transport_failure_keeps_credential_and_removes_write_ahead() {
        let w = World::new();
        let http = FakeHttp::new(|_| Err(crate::http::transport_error("oauth/token")));
        let ctx = net(&w, &w.store, &http);
        let cur = expired("A");
        put(&w.store, "A::oA", &cur);
        let lock = AccountLock::acquire(&w.paths, "A::oA").unwrap();
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::ExternalTool { .. })
        ));
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), cur);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn lock_for_another_account_is_refused() {
        let w = World::new();
        let http = server_for("A", "oA");
        let ctx = net(&w, &w.store, &http);
        put(&w.store, "A::oA", &expired("A"));
        let lock = AccountLock::acquire(&w.paths, "B::oB").unwrap();
        assert!(matches!(
            refresh_locked(&ctx, &lock, "A::oA"),
            Err(Error::Invalid { .. })
        ));
        assert_eq!(http.count("oauth/token"), 0);
    }
}
