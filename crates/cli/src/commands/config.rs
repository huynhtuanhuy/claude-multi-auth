//! `cma config get [key]` / `cma config set <key> <value>`.

use cma_core::registry::{DEFAULT_REFRESH_GRACE_SECS, Registry, Settings};
use serde_json::{Map, Value, json};

use super::{CmdResult, start};
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

/// Settings the user may change.
pub const KEYS: [&str; 5] = [
    "session_follow",
    "live_usage",
    "live_interval_secs",
    "default_target",
    "refresh_grace_secs",
];
/// Lowest background refresh interval for `list --live`.
pub const MIN_LIVE_INTERVAL_SECS: u64 = 10;

fn known(key: &str) -> Result<(), CliError> {
    if KEYS.contains(&key) {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid",
            format!("unknown setting {key:?}; settings: {}", KEYS.join(", ")),
        ))
    }
}

fn settings_map(s: &Settings) -> Map<String, Value> {
    let v = serde_json::to_value(s).unwrap_or_default();
    KEYS.iter()
        .filter_map(|k| v.get(*k).map(|x| ((*k).to_string(), x.clone())))
        .collect()
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub fn get(deps: &Deps, key: Option<&str>) -> CmdResult {
    let reg = Registry::load(&deps.paths.registry_file())?;
    let all = settings_map(&reg.settings);
    match key {
        Some(k) => {
            known(k)?;
            let v = all.get(k).cloned().unwrap_or(Value::Null);
            Ok(Outcome::new(json!({"key": k, "value": v}), text(&v)))
        }
        None => {
            let h = all
                .iter()
                .map(|(k, v)| format!("{k} = {}", text(v)))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(Outcome::new(json!({"settings": all}), h))
        }
    }
}

pub fn set(deps: &Deps, out: &mut Out, key: &str, raw: &str) -> CmdResult {
    known(key)?;
    let value: Value = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.into()));
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let mut s = start(&ctx, out)?;
    let mut v = serde_json::to_value(&s.registry.settings).map_err(|_| invalid(key, raw))?;
    v[key] = value;
    let new: Settings = serde_json::from_value(v).map_err(|_| invalid(key, raw))?;
    // Only the key being set is validated: a value set some other way
    // (hand edit, older cma) never blocks changing a different setting.
    if key == "live_interval_secs" && new.live_interval_secs < MIN_LIVE_INTERVAL_SECS {
        return Err(CliError::new(
            "invalid",
            format!("live_interval_secs must be at least {MIN_LIVE_INTERVAL_SECS}"),
        ));
    }
    if key == "refresh_grace_secs" && new.refresh_grace_secs < DEFAULT_REFRESH_GRACE_SECS {
        out.warn(
            "short_refresh_grace",
            format!(
                "refresh_grace_secs below {DEFAULT_REFRESH_GRACE_SECS} (the measured value): a session still running on an account just switched away from can lose its token when cma refreshes it"
            ),
        );
    }
    s.registry.settings = new;
    s.save()?;
    let shown = settings_map(&s.registry.settings)
        .get(key)
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Outcome::new(
        json!({"key": key, "value": shown}),
        format!("{key} = {}", text(&shown)),
    ))
}

fn invalid(key: &str, raw: &str) -> CliError {
    let expect = match key {
        "session_follow" => "off or on",
        "live_usage" => "true or false",
        "default_target" => "cli or desktop",
        _ => "a whole number of seconds",
    };
    CliError::new(
        "invalid",
        format!("invalid value {raw:?} for {key}: expected {expect}"),
    )
}
