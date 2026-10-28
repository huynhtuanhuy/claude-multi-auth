//! Usage windows for every stored account, each fetched with its own token.
//!
//! `GET /api/oauth/usage` (non-public; opt-in, see [`DISCLAIMER`]). Which
//! token is used, per account:
//!
//! - the **live owner** (`active.cli`, or the account whose stored grant the
//!   live Claude Code item holds) ⇒ the live item's token; never refreshed
//!   by cma. Expired ⇒ cached values and [`Note::LiveExpired`];
//! - an account active within `refresh_grace_secs` (old sessions may still
//!   run on its token) ⇒ the stored token only while unexpired; never
//!   refreshed. Otherwise cached values and [`Note::WaitingForGrace`];
//! - any other OAuth account ⇒ the stored token, refreshed first
//!   ([`crate::refresh`]) when it expires within 60 s;
//! - Console accounts ⇒ [`Note::NotApplicable`].
//!
//! Accounts are processed up to [`MAX_PARALLEL`] at a time. Each one holds
//! only its own per-account lock, and only while it decides and refreshes;
//! no lock is held during the usage request. The cma lock is taken once at
//! the end, briefly, to write the results into the registry. Failures keep
//! the cached windows and set `usage.error`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Map, Value};

use crate::cli_target::{
    LiveTarget, OWN_SERVICE, Warning, access_token, oauth_fingerprint, oauth_of,
};
use crate::error::{Error, Result};
use crate::http::{HttpClient, Method, Request, status_error};
use crate::lock::{AccountLock, CmaLock};
use crate::refresh::{NetCtx, Refreshed, access_unexpired, recover_interrupted, refresh_locked};
use crate::registry::{AccountKind, Registry};
use crate::secret::Secret;

pub const USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
/// Accounts processed at the same time.
pub const MAX_PARALLEL: usize = 4;
const WHAT: &str = "oauth/usage";

/// Shown once before the first network use (then
/// `settings.usage_disclaimer_shown` is set).
pub const DISCLAIMER: &str = "Live usage sends each stored account's OAuth token to Anthropic endpoints that are not public API (/api/oauth/usage, and the token endpoint to refresh inactive accounts). They may change or stop working, and using them may conflict with Anthropic's terms; that risk is yours. Nothing is sent unless you ask for live usage.";

/// Whether [`DISCLAIMER`] still has to be shown.
pub fn disclaimer_due(reg: &Registry) -> bool {
    !reg.settings.usage_disclaimer_shown
}

/// Top-level keys that are never windows even when they have a
/// `utilization` field (`extra_usage` does).
const NOT_WINDOWS: [&str; 3] = ["extra_usage", "spend", "limits"];
/// Window fields kept (all non-secret).
const WINDOW_FIELDS: [&str; 6] = [
    "utilization",
    "resets_at",
    "limit_dollars",
    "used_dollars",
    "remaining_dollars",
    "locked_reason",
];

/// Display label of a known window key; unknown keys show raw.
pub fn label_for(key: &str) -> Option<&'static str> {
    Some(match key {
        "five_hour" => "5h",
        "seven_day" => "7d",
        "seven_day_opus" => "7d Opus",
        "seven_day_sonnet" => "7d Sonnet",
        "seven_day_cowork" => "7d Cowork",
        "seven_day_oauth_apps" => "7d OAuth apps",
        _ => return None,
    })
}

/// Lenient parse: every top-level object with a numeric `utilization`
/// (except [`NOT_WINDOWS`]) is a window, under its raw key; null windows
/// are skipped. `resets_at` is kept as the ISO-8601 string it is.
pub fn parse_usage(body: &[u8]) -> Result<Map<String, Value>> {
    let v: Value = serde_json::from_slice(body).map_err(|e| Error::json("usage", &e))?;
    let obj = v.as_object().ok_or_else(|| Error::Invalid {
        what: "usage response (not a JSON object)",
        value: String::new(),
    })?;
    let mut out = Map::new();
    for (k, w) in obj {
        if NOT_WINDOWS.contains(&k.as_str()) {
            continue;
        }
        let Some(w) = w.as_object() else { continue };
        if !w.get("utilization").is_some_and(Value::is_number) {
            continue;
        }
        let kept: Map<String, Value> = WINDOW_FIELDS
            .iter()
            .filter_map(|f| w.get(*f).map(|v| ((*f).to_string(), v.clone())))
            .collect();
        out.insert(k.clone(), Value::Object(kept));
    }
    Ok(out)
}

/// Fetch and parse the usage windows for one access token.
pub fn fetch_usage(http: &dyn HttpClient, access_token: &Secret) -> Result<Map<String, Value>> {
    let resp = http.send(&Request {
        what: WHAT,
        method: Method::Get,
        url: USAGE_URL,
        bearer: Some(access_token),
        oauth_beta: true,
        json: None,
    })?;
    if resp.status != 200 {
        return Err(status_error(WHAT, resp.status));
    }
    parse_usage(resp.body.expose())
}

/// Why an account shows cached values (or none) instead of fresh ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// Console (API billing) account: no usage windows.
    NotApplicable,
    /// The live owner's token is expired; Claude Code refreshes it when it
    /// next runs.
    LiveExpired,
    /// Active within the refresh grace and its token is expired: waiting
    /// for old sessions before refreshing.
    WaitingForGrace,
    /// The account must log in again.
    NeedsLogin,
}

impl Note {
    pub fn message(self) -> &'static str {
        match self {
            Note::NotApplicable => "n/a (API billing)",
            Note::LiveExpired => "refreshes when Claude Code next runs",
            Note::WaitingForGrace => "waiting for old sessions",
            Note::NeedsLogin => "needs login",
        }
    }
}

/// Where the token used came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    Live,
    Stored,
}

/// One account's result.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountUsage {
    pub key: String,
    /// Fresh windows when `fresh`, else the cached ones.
    pub windows: Map<String, Value>,
    /// Unix seconds of the windows (0: never fetched).
    pub fetched_at: i64,
    pub fresh: bool,
    pub source: Option<TokenSource>,
    /// The stored token was refreshed (rotated) in this run.
    pub refreshed: bool,
    pub note: Option<Note>,
    /// Why fetching or refreshing failed (no secret material).
    pub error: Option<String>,
    pub warnings: Vec<Warning>,
    /// Fingerprint of the new credential after a refresh.
    new_fingerprint: Option<String>,
    /// `needs_login` was decided for the stored credential with this
    /// fingerprint (empty: when no readable credential was stored).
    needs_login_for: Option<String>,
}

impl AccountUsage {
    fn cached(key: &str, reg: &Registry) -> Self {
        let (windows, fetched_at) = reg
            .account(key)
            .map(|a| (a.usage.windows.clone(), a.usage.fetched_at))
            .unwrap_or_default();
        AccountUsage {
            key: key.into(),
            windows,
            fetched_at,
            fresh: false,
            source: None,
            refreshed: false,
            note: None,
            error: None,
            warnings: Vec::new(),
            new_fingerprint: None,
            needs_login_for: None,
        }
    }

    pub fn needs_login(&self) -> bool {
        self.needs_login_for.is_some()
    }
}

/// Result of [`fetch_all`].
#[derive(Debug, Clone, PartialEq)]
pub struct UsageRun {
    /// In registry order.
    pub accounts: Vec<AccountUsage>,
    pub warnings: Vec<Warning>,
}

/// Short, secret-free description of a failure for `usage.error`.
pub fn error_text(e: &Error) -> String {
    match e {
        Error::ExternalTool {
            program: "http",
            sub,
            code: Some(c),
            ..
        } => format!("{sub}: HTTP {c}"),
        Error::ExternalTool {
            program: "http",
            sub,
            code: None,
            ..
        } => format!("{sub}: request failed"),
        e => format!("{}: {e}", e.code()),
    }
}

/// The live item's credential, read once per run.
struct Live {
    oauth: Option<Value>,
    fingerprint: Option<String>,
}

fn read_live(ctx: &NetCtx<'_>, live: &LiveTarget, warnings: &mut Vec<Warning>) -> Result<Live> {
    // A failed Keychain read is fatal: without it the live owner is
    // unknown, and refreshing it would cut off running sessions.
    let bytes = ctx.store.get(&live.service, &live.account)?;
    let oauth = match bytes {
        Some(b) => match oauth_of(b.expose()) {
            Ok(o) => o,
            Err(e) => {
                warnings.push(Warning::new(
                    "live_unreadable",
                    format!(
                        "the live Claude Code item could not be parsed ({}); only active.cli marks the live account",
                        e.code()
                    ),
                ));
                None
            }
        },
        None => None,
    };
    let fingerprint = oauth.as_ref().map(oauth_fingerprint);
    Ok(Live { oauth, fingerprint })
}

fn rt(o: &Value) -> Option<&str> {
    o.get("refreshToken")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Decide, refresh if allowed, and fetch for one account.
fn process(ctx: &NetCtx<'_>, live: &Live, key: &str) -> AccountUsage {
    let snapshot = Registry::load(&ctx.paths.registry_file()).unwrap_or_default();
    let mut out = AccountUsage::cached(key, &snapshot);
    // Console accounts have no windows; a Desktop-only account (no Claude
    // Code login stored) has no token cma could use.
    let desktop_only = snapshot.account(key).is_some_and(|a| !a.has_cli)
        && ctx
            .store
            .get(crate::cli_target::OWN_SERVICE, key)
            .ok()
            .flatten()
            .is_none();
    if desktop_only
        || snapshot
            .account(key)
            .is_some_and(|a| a.kind == AccountKind::Console)
    {
        out.note = Some(Note::NotApplicable);
        return out;
    }
    match decide_and_refresh(ctx, live, key, &mut out) {
        Ok(Some((token, source))) => {
            out.source = Some(source);
            match fetch_usage(ctx.http, &token) {
                Ok(w) => {
                    out.windows = w;
                    out.fetched_at = ctx.now_ms() / 1000;
                    out.fresh = true;
                }
                Err(e) => out.error = Some(error_text(&e)),
            }
        }
        Ok(None) => {}
        Err(e) => out.error = Some(error_text(&e)),
    }
    out
}

/// Under the account's lock: pick the token (refreshing when allowed).
/// `None`: no request (see `out.note`).
fn decide_and_refresh(
    ctx: &NetCtx<'_>,
    live: &Live,
    key: &str,
    out: &mut AccountUsage,
) -> Result<Option<(Secret, TokenSource)>> {
    let lock = AccountLock::acquire(ctx.paths, key)?;
    // Re-read under the lock: a switch that made this account live has
    // finished (it holds the lock until its registry write).
    let reg = Registry::load(&ctx.paths.registry_file())?;
    let acct = reg
        .account(key)
        .ok_or_else(|| Error::NotFound(format!("account {key}")))?;
    let rec = match recover_interrupted(ctx, &lock, key) {
        Ok(r) => r,
        Err(Error::NeedsLogin(m)) => {
            judge_needs_login(ctx, key, out, m)?;
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    out.warnings.extend(rec.warnings);
    if let Some(fp) = rec.promoted {
        // An interrupted refresh's rotated pair was verified and stored.
        out.refreshed = true;
        out.new_fingerprint = Some(fp);
    }
    let stored = ctx
        .store
        .get(OWN_SERVICE, key)?
        .map(|s| oauth_of(s.expose()))
        .transpose()?
        .flatten();
    let now = ctx.now_ms();
    let live_is_this = live
        .fingerprint
        .as_deref()
        .is_some_and(|fp| reg.account_for_fingerprint(fp) == Some(key))
        || matches!((&live.oauth, &stored), (Some(l), Some(s)) if rt(l).is_some() && rt(l) == rt(s));
    let owner = reg.active.cli.as_deref() == Some(key) || live_is_this;
    let unexpired_stored = stored
        .as_ref()
        .filter(|s| access_unexpired(s, now))
        .and_then(access_token);

    if owner {
        // Never refreshed here: Claude Code owns this grant's rotation.
        let tok = match (&live.oauth, live_is_this) {
            (Some(l), true) => Some(l)
                .filter(|l| access_unexpired(l, now))
                .and_then(access_token)
                .map(|t| (t, TokenSource::Live)),
            // active.cli names it but the live item is not its grant (an
            // outside change not synced yet): never use another account's
            // token, only its own stored one.
            _ => unexpired_stored.map(|t| (t, TokenSource::Stored)),
        };
        if tok.is_none() {
            out.note = Some(Note::LiveExpired);
        }
        return Ok(tok);
    }
    let grace = i64::try_from(reg.settings.refresh_grace_secs).unwrap_or(i64::MAX);
    if acct.last_active_at > 0 && now / 1000 - acct.last_active_at < grace {
        if unexpired_stored.is_none() {
            out.note = Some(Note::WaitingForGrace);
        }
        return Ok(unexpired_stored.map(|t| (t, TokenSource::Stored)));
    }
    if acct.needs_login && !out.refreshed {
        // Signed out already: no request with a dead refresh token.
        if unexpired_stored.is_none() {
            out.note = Some(Note::NeedsLogin);
            out.needs_login_for = Some(stored.as_ref().map(oauth_fingerprint).unwrap_or_default());
        }
        return Ok(unexpired_stored.map(|t| (t, TokenSource::Stored)));
    }
    if out.refreshed {
        // Recovery stored a credential: no second refresh while this lock
        // is held (the request budget of one hold assumes it).
        return Ok(unexpired_stored.map(|t| (t, TokenSource::Stored)));
    }
    if stored.is_none() {
        return Err(Error::NotFound(format!("stored credential of {key}")));
    }
    match refresh_locked(ctx, &lock, key) {
        Ok((r, w)) => {
            out.warnings.extend(w);
            let oauth = match r {
                Refreshed::StillValid { oauth } => oauth,
                Refreshed::Rotated { oauth, fingerprint } => {
                    out.refreshed = true;
                    out.new_fingerprint = Some(fingerprint);
                    oauth
                }
            };
            Ok(access_token(&oauth).map(|t| (t, TokenSource::Stored)))
        }
        Err(Error::NeedsLogin(m)) => {
            judge_needs_login(ctx, key, out, m)?;
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Record a `needs_login` verdict for the credential stored now. The
/// caller holds the account's lock, so this is the credential the verdict
/// was made on (a retry may have moved on from the one read first). With
/// no readable credential stored, the verdict is for "nothing stored".
fn judge_needs_login(
    ctx: &NetCtx<'_>,
    key: &str,
    out: &mut AccountUsage,
    message: String,
) -> Result<()> {
    out.note = Some(Note::NeedsLogin);
    out.needs_login_for = Some(
        ctx.store
            .get(OWN_SERVICE, key)?
            .and_then(|s| oauth_of(s.expose()).ok().flatten())
            .map(|o| oauth_fingerprint(&o))
            .unwrap_or_default(),
    );
    out.warnings.push(Warning::new("needs_login", message));
    Ok(())
}

/// Fetch usage for the stored accounts (`only`: these keys; `None`: all),
/// refreshing where allowed, and record the results in the registry. A
/// failed read of the live item aborts before any request.
///
/// Call it after [`crate::sync::begin`] (and with that session ended, so
/// the cma lock is free): sync records the live grant's fingerprint, which
/// is what lets the live owner's usage come from the live token. Called
/// while this thread holds the cma lock (a sync session still open), it
/// fails at once with [`Error::CmaLockHeld`] and sends nothing.
pub fn fetch_all(ctx: &NetCtx<'_>, live: &LiveTarget, only: Option<&[String]>) -> Result<UsageRun> {
    if crate::lock::cma_lock_held_here() {
        return Err(Error::CmaLockHeld(
            "fetching usage needs the cma lock free; end the sync session first".into(),
        ));
    }
    let mut warnings = Vec::new();
    let live = read_live(ctx, live, &mut warnings)?;
    let reg = Registry::load(&ctx.paths.registry_file())?;
    let keys: Vec<String> = reg
        .accounts
        .iter()
        .map(|a| a.key.clone())
        .filter(|k| only.is_none_or(|o| o.contains(k)))
        .collect();
    let results: Mutex<Vec<Option<AccountUsage>>> = Mutex::new(vec![None; keys.len()]);
    let next = AtomicUsize::new(0);
    let workers = keys.len().min(MAX_PARALLEL);
    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(key) = keys.get(i) else { break };
                    let r = process(ctx, &live, key);
                    results.lock().unwrap_or_else(|e| e.into_inner())[i] = Some(r);
                }
            });
        }
    });
    let accounts: Vec<AccountUsage> = results
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .flatten()
        .collect();
    record(ctx, &accounts)?;
    Ok(UsageRun { accounts, warnings })
}

/// Write the results into the registry under the cma lock (no per-account
/// lock is held here).
fn record(ctx: &NetCtx<'_>, accounts: &[AccountUsage]) -> Result<()> {
    let lock = CmaLock::acquire(&ctx.paths.lock_file())?;
    lock.check_for(ctx.paths)?;
    let mut reg = Registry::load(&ctx.paths.registry_file())?;
    let now = ctx.now_ms() / 1000;
    let mut changed = false;
    for r in accounts {
        // A `needs_login` verdict holds only for the credential it was
        // made on (a re-login meanwhile replaced it).
        let still_judged = match &r.needs_login_for {
            Some(fp) => match ctx
                .store
                .get(OWN_SERVICE, &r.key)?
                .and_then(|s| oauth_of(s.expose()).ok().flatten())
            {
                Some(o) => oauth_fingerprint(&o) == *fp,
                // Judged with nothing stored, and still nothing.
                None => fp.is_empty(),
            },
            None => false,
        };
        // An account removed meanwhile gets nothing (no dangling
        // fingerprint either).
        if reg.account(&r.key).is_none() {
            continue;
        }
        if let Some(fp) = &r.new_fingerprint {
            reg.add_fingerprint(fp.clone(), &r.key);
            changed = true;
        }
        let a = reg.account_mut(&r.key).expect("just checked");
        if r.fresh {
            a.usage.windows = r.windows.clone();
            a.usage.fetched_at = now;
            changed = true;
        }
        if r.refreshed {
            a.needs_login = false;
            changed = true;
        }
        if still_judged && !a.needs_login {
            a.needs_login = true;
            changed = true;
        }
        // The error of this run only: an older one does not outlive a run
        // that did not repeat it.
        let error = if r.fresh {
            None
        } else if let Some(e) = &r.error {
            Some(e.clone())
        } else if a.needs_login && r.note == Some(Note::NeedsLogin) {
            Some(Note::NeedsLogin.message().to_string())
        } else {
            None
        };
        if a.usage.error != error {
            a.usage.error = error;
            changed = true;
        }
    }
    if changed {
        reg.save(&ctx.paths.registry_file())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::BACKUP_SERVICE;
    use crate::cli_target::testkit::*;
    use crate::cli_target::{oauth_only_item, stored_oauth};
    use crate::http::tests::{FakeHttp, Seen, resp};
    use crate::refresh::tests::{FlakyStore, expired, net, put, token_body};
    use crate::secret::SecretStore;
    use crate::sync::tests::{add_account, set_active};
    use serde_json::json;

    const USAGE_BODY: &str = r#"{
        "five_hour": {"utilization": 12.5, "resets_at": "2026-10-27T12:00:00.000000+00:00", "limit_dollars": null, "used_dollars": null, "remaining_dollars": null, "locked_reason": null},
        "seven_day": {"utilization": 40, "resets_at": "2026-11-01T00:00:00.000000+00:00"},
        "seven_day_opus": null,
        "seven_day_oauth_apps": null,
        "iguana_necktie": {"utilization": 3, "resets_at": "2026-11-01T00:00:00Z", "used_dollars": 1},
        "amber_cistern": null,
        "extra_usage": {"is_enabled": true, "utilization": 5, "monthly_limit": 10},
        "spend": {"enabled": false, "percent": 0},
        "limits": [{"group": "g", "percent": 1}],
        "seven_day_breakdown": {"as_of": "x", "rows": []},
        "member_dashboard_available": true,
        "odd": {"utilization": "high"}
    }"#;

    #[test]
    fn parse_keeps_windows_skips_nulls_and_non_windows() {
        let w = parse_usage(USAGE_BODY.as_bytes()).unwrap();
        let keys: Vec<&String> = w.keys().collect();
        assert_eq!(keys, ["five_hour", "seven_day", "iguana_necktie"]);
        assert_eq!(w["five_hour"]["utilization"], 12.5);
        assert_eq!(
            w["five_hour"]["resets_at"],
            "2026-10-27T12:00:00.000000+00:00"
        );
        assert!(w["five_hour"]["locked_reason"].is_null());
        assert_eq!(w["iguana_necktie"]["used_dollars"], 1);
        assert_eq!(label_for("five_hour"), Some("5h"));
        assert_eq!(label_for("seven_day_oauth_apps"), Some("7d OAuth apps"));
        assert_eq!(label_for("iguana_necktie"), None);
        assert!(parse_usage(b"[1]").is_err());
        assert!(matches!(parse_usage(b"{x"), Err(Error::Json { .. })));
    }

    /// Usage: window `five_hour` = utilization 1 for any bearer; token
    /// endpoint rotates an unspent `rt-X…` to `X…2` for account `X::oX`; a
    /// spent refresh token answers `invalid_grant`.
    fn server() -> FakeHttp {
        let spent = Mutex::new(std::collections::HashSet::new());
        FakeHttp::new(move |s: &Seen| match s.what {
            "oauth/usage" => resp(200, r#"{"five_hour":{"utilization":1,"resets_at":"r"}}"#),
            "oauth/token" => {
                let rt = s.json.as_ref().unwrap()["refresh_token"].as_str().unwrap();
                if !spent.lock().unwrap().insert(rt.to_string()) {
                    return resp(400, r#"{"error":"invalid_grant"}"#);
                }
                let tag = rt.trim_start_matches("rt-").to_string();
                let acct = &tag[..1];
                resp(
                    200,
                    &token_body(&format!("{tag}2"), acct, &format!("o{acct}")),
                )
            }
            _ => resp(404, "{}"),
        })
    }

    fn reg(w: &World) -> Registry {
        Registry::load(&w.paths.registry_file()).unwrap()
    }

    fn set_last_active(w: &World, key: &str, secs: i64) {
        let mut r = reg(w);
        r.account_mut(key).unwrap().last_active_at = secs;
        r.save(&w.paths.registry_file()).unwrap();
    }

    fn by_key<'a>(run: &'a UsageRun, key: &str) -> &'a AccountUsage {
        run.accounts.iter().find(|a| a.key == key).unwrap()
    }

    fn bearers(http: &FakeHttp) -> Vec<String> {
        http.requests("oauth/usage")
            .into_iter()
            .map(|s| s.bearer.unwrap())
            .collect()
    }

    #[test]
    fn live_owner_is_never_refreshed_and_uses_the_live_token() {
        let w = World::new();
        add_account(&w, "A::oA", "a@x", &oauth("A"));
        set_active(&w, Some("A::oA"));
        // The live item holds a newer grant of A (Claude rotated it; sync
        // recorded its fingerprint).
        let live_a = oauth("Alive");
        w.set_live(&live_item(&live_a));
        let mut r = reg(&w);
        r.add_fingerprint(oauth_fingerprint(&live_a), "A::oA");
        r.save(&w.paths.registry_file()).unwrap();
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        let a = by_key(&run, "A::oA");
        assert!(a.fresh);
        assert_eq!(a.source, Some(TokenSource::Live));
        assert_eq!(bearers(&http), ["at-Alive"]);

        // Expired live token and expired stored token: still no refresh.
        let mut dead = live_a.clone();
        dead["expiresAt"] = (NOW_MS - 1).into();
        w.set_live(&live_item(&dead));
        put(&w.store, "A::oA", &expired("A"));
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        let a = by_key(&run, "A::oA");
        assert_eq!(a.note, Some(Note::LiveExpired));
        assert!(!a.fresh);
        assert_eq!(a.windows["five_hour"]["utilization"], 1, "cached kept");
        assert_eq!(http.count("oauth/token"), 0);
        assert_eq!(http.count("oauth/usage"), 0);
    }

    #[test]
    fn live_item_holding_a_stored_grant_marks_its_owner_even_if_not_active() {
        let w = World::new();
        let a = expired("A");
        add_account(&w, "A::oA", "a@x", &a);
        add_account(&w, "B::oB", "b@x", &oauth("B"));
        set_active(&w, Some("B::oB"));
        // An interrupted switch left A's stored grant in the live item.
        w.set_live(&live_item(&a));
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert_eq!(by_key(&run, "A::oA").note, Some(Note::LiveExpired));
        assert_eq!(http.count("oauth/token"), 0);
    }

    #[test]
    fn active_account_whose_live_item_is_foreign_never_uses_that_token() {
        let w = World::new();
        add_account(&w, "A::oA", "a@x", &oauth("A"));
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&oauth("X")));
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert_eq!(by_key(&run, "A::oA").source, Some(TokenSource::Stored));
        assert_eq!(bearers(&http), ["at-A"]);
    }

    #[test]
    fn within_grace_uses_unexpired_stored_token_but_never_refreshes() {
        let w = World::new();
        add_account(&w, "B::oB", "b@x", &oauth("B"));
        add_account(&w, "C::oC", "c@x", &expired("C"));
        for k in ["B::oB", "C::oC"] {
            set_last_active(&w, k, NOW_MS / 1000 - 100);
        }
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert!(by_key(&run, "B::oB").fresh);
        assert_eq!(by_key(&run, "C::oC").note, Some(Note::WaitingForGrace));
        assert_eq!(bearers(&http), ["at-B"]);
        assert_eq!(http.count("oauth/token"), 0);
        // Past the grace the expired one is refreshed.
        set_last_active(&w, "C::oC", NOW_MS / 1000 - 301);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert!(by_key(&run, "C::oC").refreshed);
        assert_eq!(http.count("oauth/token"), 1);
    }

    #[test]
    fn inactive_expired_account_refreshes_and_records_results() {
        let w = World::new();
        add_account(&w, "A::oA", "a@x", &oauth("A"));
        add_account(&w, "B::oB", "b@x", &expired("B"));
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&oauth("A")));
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        let b = by_key(&run, "B::oB");
        assert!(b.refreshed && b.fresh);
        assert_eq!(bearers(&http).len(), 2);
        assert!(bearers(&http).contains(&"at-B2".to_string()));
        let r = reg(&w);
        let new = stored_oauth(&w.store, "B::oB").unwrap().unwrap();
        assert_eq!(new["refreshToken"], "rt-B2");
        assert_eq!(
            r.account_for_fingerprint(&oauth_fingerprint(&new)),
            Some("B::oB")
        );
        let usage = &r.account("B::oB").unwrap().usage;
        assert_eq!(usage.fetched_at, NOW_MS / 1000);
        assert_eq!(usage.windows["five_hour"]["utilization"], 1);
        assert_eq!(usage.error, None);
        // The live item was never touched.
        assert_eq!(w.live_bytes().unwrap(), live_item(&oauth("A")));
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn console_is_not_applicable_and_failures_keep_cached_windows() {
        let w = World::new();
        add_account(&w, "A::oA", "a@x", &oauth("A"));
        add_account(&w, "K::oK", "k@x", &oauth("K"));
        let mut r = reg(&w);
        r.account_mut("K::oK").unwrap().kind = AccountKind::Console;
        let a = r.account_mut("A::oA").unwrap();
        a.usage
            .windows
            .insert("seven_day".into(), json!({"utilization": 9}));
        a.usage.fetched_at = 5;
        r.save(&w.paths.registry_file()).unwrap();
        let http = FakeHttp::new(|_| resp(503, "{}"));
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert_eq!(by_key(&run, "K::oK").note, Some(Note::NotApplicable));
        let a = by_key(&run, "A::oA");
        assert_eq!(a.error.as_deref(), Some("oauth/usage: HTTP 503"));
        assert_eq!(a.windows["seven_day"]["utilization"], 9);
        let r = reg(&w);
        let usage = &r.account("A::oA").unwrap().usage;
        assert_eq!(usage.windows["seven_day"]["utilization"], 9);
        assert_eq!(usage.fetched_at, 5);
        assert_eq!(usage.error.as_deref(), Some("oauth/usage: HTTP 503"));
        assert_eq!(http.count("oauth/usage"), 1, "console not requested");
    }

    #[test]
    fn refresh_deadline_marks_needs_login_and_stops_requests() {
        let w = World::new();
        let mut b = expired("B");
        b["refreshTokenExpiresAt"] = (NOW_MS - 1).into();
        add_account(&w, "B::oB", "b@x", &b);
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert!(by_key(&run, "B::oB").needs_login());
        assert!(reg(&w).account("B::oB").unwrap().needs_login);
        assert_eq!(http.count("oauth/token"), 0);
        // A flagged account is not tried again.
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert_eq!(by_key(&run, "B::oB").note, Some(Note::NeedsLogin));
        assert_eq!(http.count("oauth/token") + http.count("oauth/usage"), 0);
    }

    #[test]
    fn needs_login_is_not_recorded_over_a_newer_login() {
        let w = World::new();
        add_account(&w, "B::oB", "b@x", &expired("B"));
        let store = &w.store;
        let http = FakeHttp::new(|_| resp(400, r#"{"error":"invalid_grant"}"#));
        let ctx = net(&w, store, &http);
        // Simulate a re-login landing between the verdict and the record.
        let mut run = AccountUsage::cached("B::oB", &reg(&w));
        run.needs_login_for = Some(oauth_fingerprint(&expired("B")));
        put(store, "B::oB", &oauth("Bnew"));
        record(&ctx, &[run]).unwrap();
        assert!(!reg(&w).account("B::oB").unwrap().needs_login);
        // Without the re-login it is recorded.
        put(store, "B::oB", &expired("B"));
        fetch_all(&ctx, &w.live(), None).unwrap();
        assert!(reg(&w).account("B::oB").unwrap().needs_login);
    }

    #[test]
    fn live_read_failure_aborts_before_any_request() {
        let w = World::new();
        add_account(&w, "B::oB", "b@x", &expired("B"));
        // A Keychain read of the live item that fails like `security` does.
        struct SyncFail<'a>(&'a crate::secret::MemoryStore, LiveTarget);
        impl SecretStore for SyncFail<'_> {
            fn get(&self, s: &str, a: &str) -> Result<Option<Secret>> {
                if s == self.1.service && a == self.1.account {
                    return Err(Error::ExternalTool {
                        program: "security",
                        sub: "find-generic-password",
                        code: Some(36),
                        class: crate::error::ToolFailure::Other,
                    });
                }
                self.0.get(s, a)
            }
            fn set(&self, s: &str, a: &str, v: &Secret) -> Result<()> {
                self.0.set(s, a, v)
            }
            fn delete(&self, s: &str, a: &str) -> Result<bool> {
                self.0.delete(s, a)
            }
        }
        let store = SyncFail(&w.store, w.live());
        let http = server();
        let ctx = NetCtx {
            paths: &w.paths,
            store: &store,
            http: &http,
            client_id: crate::refresh::CLIENT_ID.into(),
            now_ms: now,
        };
        assert!(fetch_all(&ctx, &w.live(), None).is_err());
        assert_eq!(http.seen.lock().unwrap().len(), 0);
    }

    #[test]
    fn at_most_four_accounts_run_at_once_and_only_filters() {
        let w = World::new();
        let keys: Vec<String> = (0..7).map(|i| format!("U{i}::oU{i}")).collect();
        for k in &keys {
            add_account(&w, k, "u@x", &oauth(&k[..2]));
        }
        let cur = std::sync::Arc::new(AtomicUsize::new(0));
        let max = std::sync::Arc::new(AtomicUsize::new(0));
        let (c2, m2) = (cur.clone(), max.clone());
        let http = FakeHttp::new(move |_| {
            let n = c2.fetch_add(1, Ordering::SeqCst) + 1;
            m2.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(60));
            c2.fetch_sub(1, Ordering::SeqCst);
            resp(200, r#"{"five_hour":{"utilization":2}}"#)
        });
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert_eq!(run.accounts.len(), 7);
        assert!(run.accounts.iter().all(|a| a.fresh));
        let m = max.load(Ordering::SeqCst);
        assert!((2..=MAX_PARALLEL).contains(&m), "max parallel {m}");
        let order: Vec<&str> = run.accounts.iter().map(|a| a.key.as_str()).collect();
        assert_eq!(order, keys.iter().map(String::as_str).collect::<Vec<_>>());

        let only = vec![keys[2].clone()];
        let run = fetch_all(&ctx, &w.live(), Some(&only)).unwrap();
        assert_eq!(run.accounts.len(), 1);
        assert_eq!(run.accounts[0].key, keys[2]);
    }

    #[test]
    fn disclaimer_is_due_until_recorded() {
        let mut r = Registry::default();
        assert!(disclaimer_due(&r));
        r.settings.usage_disclaimer_shown = true;
        assert!(!disclaimer_due(&r));
        assert!(DISCLAIMER.contains("not public"));
    }

    #[test]
    fn stored_write_ahead_leftover_is_recovered_during_a_run() {
        let w = World::new();
        let b = oauth("B");
        add_account(&w, "B::oB", "b@x", &b);
        w.store
            .set(
                BACKUP_SERVICE,
                &crate::refresh::write_ahead_account("B::oB"),
                &oauth_only_item(&b),
            )
            .unwrap();
        w.store.delete(OWN_SERVICE, "B::oB").unwrap();
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        let r = by_key(&run, "B::oB");
        assert!(r.warnings.iter().any(|x| x.code == "refresh_restored"));
        assert!(r.fresh);
        assert_eq!(stored_oauth(&w.store, "B::oB").unwrap().unwrap(), b);
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn store_failure_after_a_refresh_is_recovered_by_the_next_run() {
        let w = World::new();
        add_account(&w, "B::oB", "b@x", &expired("B"));
        let http = server();
        let store = FlakyStore::new(&w.store, 2);
        let ctx = NetCtx {
            store: &store,
            ..net(&w, &w.store, &http)
        };
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        let b = by_key(&run, "B::oB");
        // Not needs_login: the rotated pair is kept aside.
        assert!(!b.needs_login() && !b.fresh);
        assert!(b.error.as_deref().unwrap().contains("security"), "{b:?}");
        assert!(!reg(&w).account("B::oB").unwrap().needs_login);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        let b = by_key(&run, "B::oB");
        assert!(b.refreshed && b.fresh, "{b:?}");
        assert!(b.warnings.iter().any(|x| x.code == "refresh_recovered"));
        assert_eq!(http.count("oauth/token"), 1, "the spent token is not sent");
        let new = stored_oauth(&w.store, "B::oB").unwrap().unwrap();
        assert_eq!(new["refreshToken"], "rt-B2");
        let r = reg(&w);
        assert_eq!(
            r.account_for_fingerprint(&oauth_fingerprint(&new)),
            Some("B::oB")
        );
        let a = r.account("B::oB").unwrap();
        assert!(!a.needs_login);
        assert_eq!(a.usage.error, None, "the earlier error is cleared");
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn failed_profile_lookup_is_not_needs_login_but_a_foreign_identity_is() {
        let w = World::new();
        add_account(&w, "B::oB", "b@x", &expired("B"));
        let http = FakeHttp::new(|s: &Seen| match s.what {
            "oauth/token" => resp(
                200,
                r#"{"access_token":"at-B2","refresh_token":"rt-B2","expires_in":28800}"#,
            ),
            _ => resp(503, "{}"),
        });
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        let b = by_key(&run, "B::oB");
        assert!(!b.needs_login());
        assert!(
            b.error.as_deref().unwrap().starts_with("refresh_pending"),
            "{b:?}"
        );
        assert_eq!(http.count("oauth/profile"), 2, "retried once");
        assert!(!reg(&w).account("B::oB").unwrap().needs_login);

        // The kept pair turns out to be another account's: needs login now.
        let http = FakeHttp::new(|s: &Seen| match s.what {
            "oauth/profile" => resp(
                200,
                r#"{"account":{"uuid":"C"},"organization":{"uuid":"oC"}}"#,
            ),
            _ => resp(400, r#"{"error":"invalid_grant"}"#),
        });
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert!(by_key(&run, "B::oB").needs_login());
        let a = reg(&w).account("B::oB").unwrap().clone();
        assert!(a.needs_login);
        assert_eq!(a.usage.error.as_deref(), Some(Note::NeedsLogin.message()));
        assert_eq!(http.count("oauth/token"), 0);
        assert_eq!(
            stored_oauth(&w.store, "B::oB").unwrap().unwrap(),
            expired("B")
        );
        assert_eq!(w.store.count(BACKUP_SERVICE), 0);
    }

    #[test]
    fn needs_login_is_attributed_to_the_credential_last_judged() {
        let w = World::new();
        add_account(&w, "B::oB", "b@x", &expired("B"));
        let store = std::sync::Arc::new(crate::secret::MemoryStore::new());
        put(&store, "B::oB", &expired("B"));
        let s2 = store.clone();
        let http = FakeHttp::new(move |s: &Seen| {
            let rt = s.json.as_ref().unwrap()["refresh_token"].as_str().unwrap();
            if rt == "rt-B" {
                // Another writer stored a newer grant, rejected as well.
                put(&s2, "B::oB", &expired("B7"));
            }
            resp(400, r#"{"error":"invalid_grant"}"#)
        });
        let ctx = net(&w, &store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert!(by_key(&run, "B::oB").needs_login());
        assert_eq!(http.count("oauth/token"), 2);
        assert!(reg(&w).account("B::oB").unwrap().needs_login);
    }

    #[test]
    fn fetch_all_inside_a_sync_session_fails_at_once() {
        let w = World::new();
        add_account(&w, "B::oB", "b@x", &expired("B"));
        let http = server();
        let net_ctx = net(&w, &w.store, &http);
        let ctx = w.ctx();
        let s = crate::sync::begin(&ctx).unwrap();
        let t = std::time::Instant::now();
        let e = fetch_all(&net_ctx, &w.live(), None).unwrap_err();
        assert_eq!(e.code(), "cma_lock_held");
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(http.seen.lock().unwrap().len(), 0);
        drop(s);
        assert!(fetch_all(&net_ctx, &w.live(), None).is_ok());
    }

    #[test]
    fn a_run_without_an_error_clears_an_older_one() {
        let w = World::new();
        add_account(&w, "C::oC", "c@x", &expired("C"));
        set_last_active(&w, "C::oC", NOW_MS / 1000 - 100);
        let mut r = reg(&w);
        r.account_mut("C::oC").unwrap().usage.error = Some("oauth/usage: HTTP 503".into());
        r.save(&w.paths.registry_file()).unwrap();
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert_eq!(by_key(&run, "C::oC").note, Some(Note::WaitingForGrace));
        assert_eq!(reg(&w).account("C::oC").unwrap().usage.error, None);
    }

    #[test]
    fn rejected_kept_pair_with_nothing_stored_records_needs_login() {
        let w = World::new();
        let b = expired("B");
        add_account(&w, "B::oB", "b@x", &b);
        // The stored item is gone and the kept pair names another account.
        w.store.delete(OWN_SERVICE, "B::oB").unwrap();
        w.store
            .set(
                BACKUP_SERVICE,
                &crate::refresh::post_refresh_account("B::oB"),
                &crate::refresh::post_refresh_item(
                    &oauth("C2"),
                    Some("C"),
                    Some("oC"),
                    Some(&oauth_fingerprint(&b)),
                )
                .unwrap(),
            )
            .unwrap();
        let http = server();
        let ctx = net(&w, &w.store, &http);
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        assert!(by_key(&run, "B::oB").needs_login());
        let a = reg(&w).account("B::oB").unwrap().clone();
        assert!(a.needs_login);
        // The next run says "needs login", not "not found".
        let run = fetch_all(&ctx, &w.live(), None).unwrap();
        let r = by_key(&run, "B::oB");
        assert_eq!(r.note, Some(Note::NeedsLogin));
        assert_eq!(r.error, None);
        assert_eq!(
            reg(&w).account("B::oB").unwrap().usage.error.as_deref(),
            Some(Note::NeedsLogin.message())
        );
        assert_eq!(http.seen.lock().unwrap().len(), 0);
    }
}
