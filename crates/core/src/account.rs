//! Stored accounts: add/replace a credential, remove, import the live one.

use serde_json::Value;

use crate::backup::{BACKUP_SERVICE, Backup};
use crate::cli_target::{
    OWN_SERVICE, Warning, is_blanked, oauth_fingerprint, oauth_of, oauth_only_item, plan_of,
};
use crate::error::{Error, Result};
use crate::identity::{Profile, resolve};
use crate::lock::AccountLock;
use crate::refresh::{post_refresh_account, write_ahead_account};
use crate::registry::{Account, AccountKind};
use crate::sync::{LiveState, Session};

/// Outcome of [`store_credential`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub key: String,
    /// An older grant of the same account was replaced. It is not revoked
    /// server-side (re-login does not revoke it).
    pub replaced: bool,
    pub backup_id: String,
}

/// What to record with a credential.
#[derive(Debug, Clone, Default)]
pub struct StoreOpts<'a> {
    pub kind: AccountKind,
    pub alias: Option<&'a str>,
    /// `oauthAccount` from Claude's `.claude.json`, used only when its uuids
    /// match the verified identity.
    pub oauth_account_hint: Option<&'a Value>,
}

pub(crate) fn hint_matches(hint: &Value, key: &str) -> bool {
    let s = |k: &str| hint.get(k).and_then(Value::as_str).unwrap_or_default();
    Account::key_for(s("accountUuid"), s("organizationUuid")) == key
}

/// Store `oauth` under the verified `key` (one grant per account: an
/// existing one is replaced, backed up first), add its fingerprint and
/// upsert the registry entry. `profile` fills a new entry's metadata.
/// Holds the account's lock (inside the session's cma lock), so it never
/// interleaves with a token refresh of that account.
pub fn store_credential(
    s: &mut Session<'_>,
    key: &str,
    profile: Option<&Profile>,
    oauth: &Value,
    opts: &StoreOpts<'_>,
) -> Result<Stored> {
    if is_blanked(oauth) {
        return Err(Error::NeedsLogin(
            "refusing to store a signed-out credential".into(),
        ));
    }
    let ctx = s.ctx;
    let _account = AccountLock::acquire(ctx.paths, key)?;
    let existed = ctx.store.get(OWN_SERVICE, key)?.is_some();
    let mut b = Backup::create(ctx.paths, ctx.store, ctx.locker, "store")?;
    b.write_keychain(OWN_SERVICE, key, &oauth_only_item(oauth))?;
    let now = ctx.now_secs();
    let reg = &mut s.registry;
    if reg.account(key).is_none() {
        let (a, o) = key.split_once("::").ok_or_else(|| Error::Invalid {
            what: "account key",
            value: key.into(),
        })?;
        reg.accounts.push(Account {
            key: key.into(),
            account_uuid: a.into(),
            org_uuid: o.into(),
            added_at: now,
            ..Default::default()
        });
    }
    let acct = reg.account_mut(key).expect("just ensured");
    acct.kind = opts.kind;
    acct.has_cli = true;
    acct.needs_login = false;
    acct.plan = plan_of(oauth);
    if let Some(p) = profile {
        acct.email = p.email.clone();
        acct.org_name = p.org_name.clone();
        if acct.oauth_account.is_none() {
            acct.oauth_account = Some(p.oauth_account());
        }
    }
    if let Some(h) = opts.oauth_account_hint.filter(|h| hint_matches(h, key)) {
        acct.oauth_account = Some(h.clone());
        if acct.email.is_empty()
            && let Some(e) = h.get("emailAddress").and_then(Value::as_str)
        {
            acct.email = e.into();
        }
    }
    if let Some(al) = opts.alias {
        acct.alias = Some(al.into());
    }
    reg.add_fingerprint(oauth_fingerprint(oauth), key);
    s.save()?;
    Ok(Stored {
        key: key.into(),
        replaced: existed,
        backup_id: b.id().to_string(),
    })
}

/// Remove a stored account: its secret (backed up), fingerprints, entry and
/// any copies a token refresh left behind. Holds the account's lock. The
/// active CLI account is refused unless `force`.
pub fn remove(s: &mut Session<'_>, key: &str, force: bool) -> Result<Vec<Warning>> {
    if s.registry.account(key).is_none() {
        return Err(Error::NotFound(format!("account {key}")));
    }
    let mut warnings = Vec::new();
    if s.registry.active.cli.as_deref() == Some(key) {
        if !force {
            return Err(Error::ConfirmationRequired(format!(
                "{key} is the active CLI account; pass --force to remove it (the live login stays as it is)"
            )));
        }
        warnings.push(Warning::new(
            "removed_active",
            "removed the active CLI account; its login stays live in Claude Code, which keeps using it until you `cma switch` to another account (`cma import-current` stores it again)",
        ));
        s.registry.active.cli = None;
    }
    let ctx = s.ctx;
    let _account = AccountLock::acquire(ctx.paths, key)?;
    let mut b = Backup::create(ctx.paths, ctx.store, ctx.locker, "remove")?;
    if ctx.store.get(OWN_SERVICE, key)?.is_some() {
        b.delete_keychain(OWN_SERVICE, key)?;
    }
    for copy in [write_ahead_account(key), post_refresh_account(key)] {
        ctx.store.delete(BACKUP_SERVICE, &copy)?;
    }
    s.registry.fingerprints.retain(|_, k| k != key);
    s.registry.accounts.retain(|a| a.key != key);
    s.save()?;
    warnings.push(Warning::new(
        "backup",
        format!("the removed credential is kept in backup {}", b.id()),
    ));
    Ok(warnings)
}

/// Snapshot the live CLI credential as a stored account, by its
/// token-derived identity (fail closed), and make it `active.cli`.
pub fn import_current(s: &mut Session<'_>, alias: Option<&str>) -> Result<Stored> {
    let ctx = s.ctx;
    let live = ctx.live()?;
    let bytes = ctx
        .store
        .get(&live.service, &live.account)?
        .ok_or_else(|| Error::NotFound("live Claude Code credential".into()))?;
    let oauth = oauth_of(bytes.expose())?.ok_or_else(|| {
        Error::Unsupported("the live item holds no Claude.ai credential (claudeAiOauth)".into())
    })?;
    drop(bytes);
    let (key, profile) = resolve(&s.registry, ctx.profile, &oauth, ctx.now_ms(), None).require()?;
    let hint = crate::fsutil::read_nofollow(&ctx.paths.claude_json)?
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("oauthAccount").cloned());
    let stored = store_credential(
        s,
        &key,
        profile.as_ref(),
        &oauth,
        &StoreOpts {
            kind: AccountKind::Oauth,
            alias,
            oauth_account_hint: hint.as_ref(),
        },
    )?;
    s.registry.active.cli = Some(key.clone());
    s.live = LiveState::Identified { key, managed: true };
    s.save()?;
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_target::stored_oauth;
    use crate::cli_target::testkit::*;
    use crate::registry::Registry;
    use crate::secret::SecretStore;
    use crate::sync::begin;
    use crate::sync::tests::{add_account, set_active};

    #[test]
    fn import_current_uses_token_identity_and_hint_only_if_matching() {
        let w = World::new();
        let a = oauth("A");
        w.profile.add("at-A", "A", "oA", "a@x");
        w.set_live(&live_item(&a));
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let st = import_current(&mut s, Some("work")).unwrap();
        assert_eq!(st.key, "A::oA");
        assert!(!st.replaced);
        drop(s);
        let r = Registry::load(&w.paths.registry_file()).unwrap();
        let acct = r.account("A::oA").unwrap();
        assert_eq!(acct.alias.as_deref(), Some("work"));
        assert_eq!(acct.email, "a@x");
        assert_eq!(acct.plan, "max");
        // World's ~/.claude.json oauthAccount is A/oA: matching hint kept.
        assert_eq!(acct.oauth_account.as_ref().unwrap()["emailAddress"], "a@x");
        assert_eq!(r.active.cli.as_deref(), Some("A::oA"));
        // Only claudeAiOauth is stored, never mcpOAuth.
        let item = w.store.get(OWN_SERVICE, "A::oA").unwrap().unwrap();
        assert_eq!(item.expose(), oauth_only_item(&a).expose());
    }

    #[test]
    fn import_current_fails_closed_when_unidentified() {
        let w = World::new();
        w.set_live(&live_item(&oauth("X")));
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        assert!(matches!(
            import_current(&mut s, None),
            Err(Error::Unidentified(_))
        ));
        assert_eq!(w.store.count(OWN_SERVICE), 0);
        w.set_live(&live_item(&blanked()));
        drop(s);
        let mut s = begin(&ctx).unwrap();
        assert!(import_current(&mut s, None).is_err());
        assert_eq!(w.store.count(OWN_SERVICE), 0);
    }

    #[test]
    fn remove_refuses_active_without_force_and_backs_up() {
        let w = World::new();
        let a = oauth("A");
        add_account(&w, "A::oA", "a@x", &a);
        add_account(&w, "B::oB", "b@x", &oauth("B"));
        set_active(&w, Some("A::oA"));
        w.set_live(&live_item(&a));
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        assert!(matches!(
            remove(&mut s, "A::oA", false),
            Err(Error::ConfirmationRequired(_))
        ));
        remove(&mut s, "B::oB", false).unwrap();
        assert!(stored_oauth(&w.store, "B::oB").unwrap().is_none());
        assert!(!s.registry.fingerprints.values().any(|k| k == "B::oB"));
        assert_eq!(w.store.count(crate::backup::BACKUP_SERVICE), 1);
        remove(&mut s, "A::oA", true).unwrap();
        assert_eq!(s.registry.active.cli, None);
        assert!(s.registry.accounts.is_empty());
        // The live item is untouched.
        assert_eq!(w.live_bytes().unwrap(), live_item(&a));
    }

    #[test]
    fn remove_deletes_refresh_copies_and_waits_for_the_account_lock() {
        use crate::backup::BACKUP_SERVICE;
        use crate::refresh::{post_refresh_account, write_ahead_account};
        let w = World::new();
        add_account(&w, "B::oB", "b@x", &oauth("B"));
        for copy in [write_ahead_account("B::oB"), post_refresh_account("B::oB")] {
            w.store
                .set(BACKUP_SERVICE, &copy, &oauth_only_item(&oauth("B2")))
                .unwrap();
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(None);
        std::thread::scope(|sc| {
            let (paths, released) = (&w.paths, &released);
            sc.spawn(move || {
                // A refresher holds B's lock for a while.
                let g = AccountLock::acquire(paths, "B::oB").unwrap();
                tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(200));
                *released.lock().unwrap() = Some(std::time::Instant::now());
                drop(g);
            });
            rx.recv().unwrap();
            let ctx = w.ctx();
            let mut s = begin(&ctx).unwrap();
            remove(&mut s, "B::oB", false).unwrap();
            let done = std::time::Instant::now();
            assert!(released.lock().unwrap().is_some_and(|r| r <= done));
        });
        assert!(stored_oauth(&w.store, "B::oB").unwrap().is_none());
        for copy in [write_ahead_account("B::oB"), post_refresh_account("B::oB")] {
            assert!(w.store.get(BACKUP_SERVICE, &copy).unwrap().is_none());
        }
    }

    #[test]
    fn storing_a_credential_waits_for_the_account_lock() {
        let w = World::new();
        let a = oauth("A");
        w.profile.add("at-A", "A", "oA", "a@x");
        w.set_live(&live_item(&a));
        let (tx, rx) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(None);
        std::thread::scope(|sc| {
            let (paths, released) = (&w.paths, &released);
            sc.spawn(move || {
                let g = AccountLock::acquire(paths, "A::oA").unwrap();
                tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(200));
                *released.lock().unwrap() = Some(std::time::Instant::now());
                drop(g);
            });
            rx.recv().unwrap();
            let ctx = w.ctx();
            let mut s = begin(&ctx).unwrap();
            import_current(&mut s, None).unwrap();
            let done = std::time::Instant::now();
            assert!(released.lock().unwrap().is_some_and(|r| r <= done));
        });
        assert_eq!(stored_oauth(&w.store, "A::oA").unwrap().unwrap(), a);
    }
}
