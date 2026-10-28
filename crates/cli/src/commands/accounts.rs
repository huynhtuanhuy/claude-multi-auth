//! `cma remove`, `cma alias set|clear`.

use cma_core::account::remove as core_remove;
use cma_core::cli_target::Warning;
use serde_json::json;

use cma_core::sync::Session;

use super::{CmdResult, interactive, label, select_key, start, with_consents};
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

pub fn remove(deps: &Deps, out: &mut Out, queries: &[String], all: bool, force: bool) -> CmdResult {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let tty = interactive(out);
    // The consent is asked with no lock held, then re-checked under it.
    let (mut s, keys, force) = with_consents(tty, |c| {
        let s = start(&ctx, out)?;
        let mut keys: Vec<String> = Vec::new();
        if all {
            keys = s.registry.accounts.iter().map(|a| a.key.clone()).collect();
        } else {
            for q in queries {
                let k = select_key(&s.registry, q)?;
                if !keys.contains(&k) {
                    keys.push(k);
                }
            }
        }
        if keys.is_empty() {
            return Err(CliError::new("not_found", "no accounts stored"));
        }
        // The active account needs consent before anything is removed.
        let mut force = force;
        if let Some(active) = s.registry.active.cli.clone()
            && keys.contains(&active)
            && !force
        {
            let who = label(&s.registry, &active);
            let msg = format!(
                "{who} is the active CLI account (the Claude Code login itself stays as it is)"
            );
            if tty && c.check(&format!("{msg}\nRemove it anyway?")) {
                force = true;
            } else {
                return Err(CliError::new(
                    "confirmation_required",
                    format!("{msg}; pass --force to remove it"),
                ));
            }
        }
        Ok((s, keys, force))
    })?;
    let mut removed = Vec::new();
    let mut failed = Vec::new();
    let mut first_err: Option<CliError> = None;
    for k in &keys {
        let who = label(&s.registry, k);
        match core_remove(&mut s, k, force) {
            Ok(w) => {
                out.warn_all(w);
                removed.push(json!({"key": k, "label": who}));
            }
            Err(e) => {
                let e = CliError::from(e);
                failed.push(json!({"key": k, "error": {"code": e.code, "message": e.message}}));
                out.warn_all([Warning::new(
                    "remove_failed",
                    format!("{who} was not removed: {}", e.message),
                )]);
                first_err.get_or_insert(e);
            }
        }
    }
    if removed.is_empty() {
        return Err(first_err.expect("a key failed"));
    }
    let h = removed
        .iter()
        .map(|r| format!("removed {}", r["label"].as_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\n");
    let partial = !failed.is_empty();
    let mut o = Outcome::new(json!({"removed": removed, "failed": failed}), h);
    o.partial = partial;
    Ok(o)
}

pub fn alias(deps: &Deps, out: &mut Out, query: &str, alias: Option<&str>) -> CmdResult {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let mut s = start(&ctx, out)?;
    let key = select_key(&s.registry, query)?;
    let alias = set_alias(&mut s, &key, alias)?;
    let who = label(&s.registry, &key);
    let h = match &alias {
        Some(al) => format!("alias {al} set: {who}"),
        None => format!("alias cleared: {who}"),
    };
    Ok(Outcome::new(json!({"key": key, "alias": alias}), h))
}

/// Validate and set (or clear) `key`'s alias, and save. Returns the alias
/// as stored (trimmed).
pub fn set_alias(
    s: &mut Session<'_>,
    key: &str,
    alias: Option<&str>,
) -> Result<Option<String>, CliError> {
    let alias = alias.map(str::trim);
    if let Some(al) = alias {
        if al.is_empty() {
            return Err(CliError::new("invalid", "an alias cannot be empty"));
        }
        if al.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CliError::new(
                "invalid",
                format!("alias {al:?} is a number, which `cma` reads as a row number"),
            ));
        }
        let l = al.to_lowercase();
        if let Some(other) = s.registry.accounts.iter().find(|a| {
            a.key != key
                && (a.alias.as_deref().is_some_and(|x| x.to_lowercase() == l)
                    || a.email.to_lowercase() == l)
        }) {
            return Err(CliError::new(
                "invalid",
                format!("alias {al:?} already names {}", super::label_of(other)),
            ));
        }
    }
    let a = s
        .registry
        .account_mut(key)
        .ok_or_else(|| CliError::new("not_found", format!("account {key}")))?;
    a.alias = alias.map(String::from);
    s.save()?;
    Ok(alias.map(String::from))
}
