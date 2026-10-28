//! `cma usage [query]`: one live fetch for every stored account (or one).
//!
//! Order: `sync::begin` first (sync records the live grant's fingerprint,
//! which is what lets the live owner's usage use the live token), the
//! one-time disclaimer, then the session ends (the cma lock must be free:
//! `fetch_all` takes it itself) and `fetch_all` runs.

use cma_core::registry::Registry;
use cma_core::usage::{AccountUsage, DISCLAIMER, TokenSource, UsageRun, disclaimer_due, fetch_all};
use serde_json::{Value, json};

use super::{CmdResult, label, select_key, start};
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

pub fn run(deps: &Deps, out: &mut Out, query: Option<&str>) -> CmdResult {
    let (run, reg) = fetch(deps, out, query)?;
    let accounts: Vec<Value> = run.accounts.iter().map(|u| usage_json(&reg, u)).collect();
    let mut h = String::new();
    for u in &run.accounts {
        h.push_str(&usage_line(&reg, u));
        h.push('\n');
    }
    if run.accounts.is_empty() {
        h.push_str("no accounts stored");
    }
    Ok(Outcome::new(json!({"accounts": accounts}), h))
}

/// Sync, disclaimer, then fetch; returns the run and the registry after it.
pub fn fetch(
    deps: &Deps,
    out: &mut Out,
    query: Option<&str>,
) -> Result<(UsageRun, Registry), CliError> {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let only = {
        let mut s = start(&ctx, out)?;
        let only = query
            .map(|q| select_key(&s.registry, q).map(|k| vec![k]))
            .transpose()?;
        if disclaimer_due(&s.registry) {
            if out.json {
                out.warn("usage_disclaimer", DISCLAIMER);
            } else {
                eprintln!("note: {DISCLAIMER}");
            }
            s.registry.settings.usage_disclaimer_shown = true;
            s.save()?;
        }
        only
        // The session ends here: fetch_all takes the cma lock itself.
    };
    let live = ctx.live()?;
    let run = fetch_all(&deps.net(), &live, only.as_deref())?;
    let reg = Registry::load(&deps.paths.registry_file())?;
    out.warn_all(run.warnings.clone());
    for u in &run.accounts {
        let who = label(&reg, &u.key);
        out.warn_all(
            u.warnings.iter().map(|w| {
                cma_core::cli_target::Warning::new(w.code, format!("{who}: {}", w.message))
            }),
        );
    }
    Ok((run, reg))
}

pub fn usage_json(reg: &Registry, u: &AccountUsage) -> Value {
    json!({
        "key": u.key,
        "label": label(reg, &u.key),
        "windows": u.windows,
        "fetched_at": u.fetched_at,
        "fresh": u.fresh,
        "source": u.source.map(|s| match s {
            TokenSource::Live => "live",
            TokenSource::Stored => "stored",
        }),
        "refreshed": u.refreshed,
        "note": u.note.map(|n| n.message()),
        "error": u.error,
        "needs_login": u.needs_login() || reg.account(&u.key).is_some_and(|a| a.needs_login),
    })
}

pub fn usage_line(reg: &Registry, u: &AccountUsage) -> String {
    let mut s = format!("{}: ", label(reg, &u.key));
    let w = super::list::windows_text(&u.windows);
    s.push_str(if w.is_empty() { "-" } else { &w });
    if !u.fresh && u.fetched_at > 0 && !w.is_empty() {
        let now = cma_core::cli_target::system_now_ms() / 1000;
        s.push_str(&format!(
            " (cached, {} ago)",
            super::list::age(now - u.fetched_at)
        ));
    }
    if u.refreshed {
        s.push_str(" (token refreshed)");
    }
    if let Some(n) = u.note {
        s.push_str(&format!(" [{}]", n.message()));
    }
    if let Some(e) = &u.error {
        s.push_str(&format!(" [error: {e}]"));
    }
    if u.needs_login() || reg.account(&u.key).is_some_and(|a| a.needs_login) {
        let email = reg
            .account(&u.key)
            .map(|a| a.email.clone())
            .unwrap_or_default();
        if email.is_empty() {
            s.push_str(" — re-run `cma login`");
        } else {
            s.push_str(&format!(" — re-run `cma login --email {email}`"));
        }
    }
    s
}
