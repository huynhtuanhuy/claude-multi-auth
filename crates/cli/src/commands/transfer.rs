//! `cma import-current`, `cma import`, `cma export`.

use std::path::Path;

use cma_core::account::import_current as core_import_current;
use cma_core::registry::AccountKind;
use cma_core::switch::Confirm;
use cma_core::transfer::{
    EXPORT_WARNING, ImportOpts, export as core_export, import as core_import,
};
use serde_json::json;

use super::{CmdResult, interactive, label, select_key, start, with_consents};
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

pub fn import_current(deps: &Deps, out: &mut Out, alias: Option<&str>) -> CmdResult {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let mut s = start(&ctx, out)?;
    let r = core_import_current(&mut s, alias)?;
    // Sync's "not stored by cma; `import-current` adds it" is moot now.
    out.drop_warnings("live_account_changed");
    let who = label(&s.registry, &r.key);
    let data = json!({"key": r.key, "replaced": r.replaced, "backup_id": r.backup_id});
    Ok(Outcome::new(
        data,
        format!("stored the current Claude Code login as {who} (now the active CLI account)"),
    ))
}

pub fn import(
    deps: &Deps,
    out: &mut Out,
    path: &Path,
    alias: Option<&str>,
    replace: bool,
) -> CmdResult {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let tty = interactive(out);
    let (mut s, r) = with_consents(tty, |c| {
        let mut s = start(&ctx, out)?;
        let ask_replace = |m: &str| c.check(&format!("{m}\nReplace?"));
        let replace = if replace || !tty {
            Confirm::NonInteractive { force: replace }
        } else {
            Confirm::Interactive(&ask_replace)
        };
        let r = core_import(&mut s, path, &ImportOpts { alias, replace })?;
        Ok((s, r))
    })?;
    out.warn_all(r.warnings.clone());
    // An identical credential is not written again, but `--alias` still
    // applies to it (core allows `--alias` with one file only).
    let mut alias_set = None;
    if let (Some(al), [key]) = (alias, r.unchanged.as_slice()) {
        alias_set = super::accounts::set_alias(&mut s, key, Some(al))?;
    }
    let stored: Vec<_> = r
        .stored
        .iter()
        .map(|x| json!({"key": x.key, "replaced": x.replaced, "backup_id": x.backup_id}))
        .collect();
    let mut h = String::new();
    for x in &r.stored {
        let verb = if x.replaced { "replaced" } else { "imported" };
        h.push_str(&format!("{verb}: {}\n", label(&s.registry, &x.key)));
    }
    for k in &r.unchanged {
        h.push_str(&format!(
            "unchanged (already stored): {}\n",
            label(&s.registry, k)
        ));
    }
    if let Some(al) = &alias_set {
        h.push_str(&format!("alias {al} set\n"));
    }
    Ok(Outcome::new(
        json!({"stored": stored, "unchanged": r.unchanged, "alias_set": alias_set}),
        h,
    ))
}

pub fn export(deps: &Deps, out: &mut Out, dir: &Path, queries: &[String], yes: bool) -> CmdResult {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let tty = interactive(out);
    let files = with_consents(tty, |c| {
        let s = start(&ctx, out)?;
        let keys: Vec<String> = if queries.is_empty() {
            let mut v = Vec::new();
            for a in &s.registry.accounts {
                if a.kind == AccountKind::Oauth {
                    v.push(a.key.clone());
                } else {
                    out.warn(
                        "export_skipped",
                        format!(
                            "{} is not a Claude.ai login and was not exported",
                            super::label_of(a)
                        ),
                    );
                }
            }
            v
        } else {
            let mut v = Vec::new();
            for q in queries {
                let k = select_key(&s.registry, q)?;
                if !v.contains(&k) {
                    v.push(k);
                }
            }
            v
        };
        if keys.is_empty() {
            return Err(CliError::new(
                "not_found",
                "no Claude.ai accounts to export",
            ));
        }
        let confirmed = yes || (tty && c.check(&format!("Note: {EXPORT_WARNING}.\nWrite them?")));
        core_export(&s, dir, &keys, confirmed).map_err(|e| {
            let e = CliError::from(e);
            if e.code == "confirmation_required" {
                CliError {
                    message: format!("{}; pass --yes", e.message),
                    ..e
                }
            } else {
                e
            }
        })
    })?;
    let mut h = String::new();
    for f in &files {
        h.push_str(&format!("wrote {}\n", f.display()));
    }
    h.push_str(
        "These files contain refresh tokens: keep them private and delete them after import.",
    );
    Ok(Outcome::new(json!({"files": files}), h))
}
