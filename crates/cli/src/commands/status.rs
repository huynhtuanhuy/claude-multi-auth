//! `cma status`: active account per target, environment warnings, running
//! `claude` sessions, and an unfinished operation journal. A failed sync
//! (e.g. a kept journal) is reported, not fatal, so status always shows
//! what is going on.

use cma_core::journal;
use cma_core::procs::running_cli_sessions;
use cma_core::registry::Registry;
use serde_json::json;

use super::{CmdResult, label, live_json, live_text};
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

pub fn run(deps: &Deps, out: &mut Out) -> CmdResult {
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let (reg, live, sync_error) = match cma_core::sync::begin(&ctx) {
        Ok(mut s) => {
            out.warn_all(std::mem::take(&mut s.warnings));
            (s.registry.clone(), Some(s.live.clone()), None)
        }
        Err(e) => {
            out.warn_all(ctx.env_warnings());
            out.warn_all(ctx.plaintext_warning());
            let e = CliError::from(e);
            (
                Registry::load(&deps.paths.registry_file()).unwrap_or_default(),
                None,
                Some(e),
            )
        }
    };
    let sessions = match running_cli_sessions(deps.procs.as_ref()) {
        Ok(p) => Some(p.len()),
        Err(e) => {
            out.warn(
                "process_list_failed",
                format!("could not list processes: {e}"),
            );
            None
        }
    };
    let pending = journal::read(&deps.paths).map_err(CliError::from)?;
    let both = journal::both_read(&deps.paths).map_err(CliError::from)?;
    let both_json = both.as_ref().map(
        |b| json!({"cli_from": b.cli_from, "cli_to": b.cli_to, "cli_backup_id": b.cli_backup_id}),
    );
    let pending_json = pending.as_ref().map(|j| {
        json!({"op": j.op, "target": j.target, "from": j.from, "to": j.to, "backup_id": j.backup_id})
    });

    let (desktop, desktop_text) = super::desktop::status_json(deps, &reg, out);
    let data = json!({
        "cli": {
            "active": reg.active.cli,
            "live": live.as_ref().map(live_json),
        },
        "desktop": desktop,
        "running_cli_sessions": sessions,
        "pending_journal": pending_json,
        "pending_both": both_json,
        "sync_error": sync_error.as_ref().map(|e| json!({"code": e.code, "message": e.message, "hint": e.hint})),
        "cma_home": deps.paths.cma_home,
        "accounts": reg.accounts.len(),
    });

    let mut h = String::new();
    let active = reg
        .active
        .cli
        .as_deref()
        .map(|k| label(&reg, k))
        .unwrap_or_else(|| "-".into());
    h.push_str(&format!("CLI active:      {active}\n"));
    if let Some(l) = &live {
        h.push_str(&format!("CLI live login:  {}\n", live_text(&reg, l)));
    }
    h.push_str(&format!("Desktop login:   {desktop_text}\n"));
    h.push_str(&format!(
        "Running claude:  {}\n",
        sessions.map_or_else(|| "unknown".to_string(), |n| n.to_string())
    ));
    h.push_str(&format!("Stored accounts: {}\n", reg.accounts.len()));
    if let Some(j) = &pending {
        h.push_str(&format!(
            "Unfinished operation: {} ({}) with backup {}; it could not be rolled back completely, and cma refuses further changes until its journal is resolved. `cma backups` shows what it touched; any other command retries the rollback, and `cma resolve-journal` accepts the current state.\n",
            j.op, j.target, j.backup_id
        ));
    }
    if let Some(e) = &sync_error {
        h.push_str(&format!("Sync failed [{}]: {}\n", e.code, e.message));
        if let Some(hint) = &e.hint {
            h.push_str(&format!("hint: {hint}\n"));
        }
    }
    if let Some(b) = &both {
        h.push_str(&format!(
            "Unfinished `switch --both` to {}: its Claude Desktop half did not finish and Claude Code could not be put back yet (backup {}). Any command retries; `cma resolve-journal` accepts Claude Code staying switched.\n",
            b.cli_to,
            b.cli_backup_id.as_deref().unwrap_or("-")
        ));
    }
    let mut o = Outcome::new(data, h);
    o.state_uncertain = pending.is_some() || both.is_some();
    Ok(o)
}
