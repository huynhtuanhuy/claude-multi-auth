//! `cma list [--live]`.

use cma_core::registry::{Account, AccountKind, Registry};
use cma_core::usage::label_for;
use serde_json::{Map, Value, json};

use super::{CmdResult, account_json, desktop_active, start};
use crate::deps::Deps;
use crate::output::{Out, Outcome};

pub fn run(deps: &Deps, out: &mut Out, live: bool) -> CmdResult {
    if live {
        if out.json {
            // No screen in JSON mode: one live fetch, then the list.
            super::usage::fetch(deps, out, None)?;
        } else {
            return crate::tui::run(deps, out);
        }
    }
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let s = start(&ctx, out)?;
    let reg = s.registry.clone();
    drop(s);
    Ok(outcome(&reg))
}

pub fn outcome(reg: &Registry) -> Outcome {
    let accounts: Vec<Value> = reg
        .accounts
        .iter()
        .enumerate()
        .map(|(i, a)| account_json(reg, i, a))
        .collect();
    let data = json!({
        "active": {"cli": reg.active.cli, "desktop": reg.active.desktop},
        "accounts": accounts,
    });
    Outcome::new(data, table(reg))
}

/// The account table.
pub fn table(reg: &Registry) -> String {
    if reg.accounts.is_empty() {
        return "no accounts stored; add one with `cma login` or `cma import-current`".into();
    }
    let now = now_secs();
    let rows: Vec<[String; 6]> = reg
        .accounts
        .iter()
        .enumerate()
        .map(|(i, a)| row(reg, i, a, now))
        .collect();
    let head = [
        "#".to_string(),
        "ACTIVE".into(),
        "ACCOUNT".into(),
        "ORG".into(),
        "PLAN".into(),
        "USAGE".into(),
    ];
    let mut widths = [0usize; 6];
    for r in std::iter::once(&head).chain(rows.iter()) {
        for (w, c) in widths.iter_mut().zip(r.iter()) {
            *w = (*w).max(c.chars().count());
        }
    }
    let mut s = String::new();
    for r in std::iter::once(&head).chain(rows.iter()) {
        let line: Vec<String> = r
            .iter()
            .zip(widths.iter())
            .enumerate()
            .map(|(i, (c, w))| {
                if i == r.len() - 1 {
                    c.clone()
                } else {
                    format!("{c:<w$}")
                }
            })
            .collect();
        s.push_str(line.join("  ").trim_end());
        s.push('\n');
    }
    s
}

fn row(reg: &Registry, i: usize, a: &Account, now: i64) -> [String; 6] {
    let mut marks = Vec::new();
    if reg.active.cli.as_deref() == Some(a.key.as_str()) {
        marks.push("CLI●");
    }
    if desktop_active(reg, a) {
        marks.push("Desktop●");
    }
    let mut who = super::label_of(a);
    if a.needs_login {
        who.push_str(" [needs login]");
    }
    let plan = match a.kind {
        AccountKind::Console => "console".to_string(),
        _ if a.plan.is_empty() => "-".into(),
        _ => a.plan.clone(),
    };
    [
        (i + 1).to_string(),
        marks.join(" "),
        who,
        if a.org_name.is_empty() {
            "-".into()
        } else {
            a.org_name.clone()
        },
        plan,
        usage_cell(a, now),
    ]
}

fn now_secs() -> i64 {
    cma_core::cli_target::system_now_ms() / 1000
}

/// "5h 42% · 7d 10% (3m ago)", or why there is nothing.
pub fn usage_cell(a: &Account, now: i64) -> String {
    if a.kind == AccountKind::Console {
        return "n/a (API billing)".into();
    }
    let mut s = windows_text(&a.usage.windows);
    if s.is_empty() {
        s = "-".into();
    } else if a.usage.fetched_at > 0 {
        s.push_str(&format!(" ({} ago)", age(now - a.usage.fetched_at)));
    }
    if let Some(e) = &a.usage.error {
        s.push_str(&format!(" [{e}]"));
    }
    s
}

/// Known windows first (5h, 7d, …), then any others, by raw key.
pub fn windows_text(w: &Map<String, Value>) -> String {
    let order = [
        "five_hour",
        "seven_day",
        "seven_day_opus",
        "seven_day_sonnet",
        "seven_day_cowork",
        "seven_day_oauth_apps",
    ];
    let mut keys: Vec<&String> = w.keys().collect();
    keys.sort_by_key(|k| {
        (
            order.iter().position(|o| o == k).unwrap_or(order.len()),
            (*k).clone(),
        )
    });
    keys.iter()
        .filter_map(|k| {
            let u = w.get(*k)?.get("utilization")?.as_f64()?;
            let name = label_for(k).map(str::to_string).unwrap_or((*k).clone());
            let reset = w
                .get(*k)
                .and_then(|x| x.get("resets_at"))
                .and_then(Value::as_str)
                .map(|r| format!(" ↻{}", short_time(r)))
                .unwrap_or_default();
            Some(format!("{name} {u:.0}%{reset}"))
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// `2026-10-27T14:00:00.123+00:00` → `10-27 14:00Z`-ish short form; the raw
/// string when it is not in that shape.
fn short_time(iso: &str) -> String {
    match (iso.get(5..10), iso.get(11..16)) {
        (Some(d), Some(t)) if iso.as_bytes().get(10) == Some(&b'T') => {
            let tz = if iso.ends_with('Z') || iso.contains("+00:00") {
                " UTC"
            } else {
                ""
            };
            format!("{d} {t}{tz}")
        }
        _ => iso.to_string(),
    }
}

pub fn age(secs: i64) -> String {
    let secs = secs.max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_render_known_first() {
        let w: Map<String, Value> = serde_json::from_value(json!({
            "zeta": {"utilization": 1.0},
            "seven_day": {"utilization": 10.4},
            "five_hour": {"utilization": 42.0, "resets_at": "2026-10-27T14:00:00+00:00"},
        }))
        .unwrap();
        assert_eq!(
            windows_text(&w),
            "5h 42% ↻10-27 14:00 UTC · 7d 10% · zeta 1%"
        );
    }
}
