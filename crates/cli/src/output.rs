//! Output layer: one JSON document on stdout in `--json` mode, otherwise
//! human text on stdout and warnings/errors on stderr. Exit codes:
//! 0 ok, 1 failed before any change, 2 state uncertain (rollback failed,
//! journal kept), 3 partial success.

use std::io::Write;

use cma_core::cli_target::Warning;
use serde_json::{Value, json};

pub const SCHEMA_VERSION: u64 = 1;

pub const EXIT_OK: u8 = 0;
pub const EXIT_FAILED: u8 = 1;
pub const EXIT_STATE_UNCERTAIN: u8 = 2;
pub const EXIT_PARTIAL: u8 = 3;

/// A failed command: a stable code, a secret-free message and an optional
/// hint saying what to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub code: String,
    pub message: String,
    pub hint: Option<String>,
    /// Facts the caller needs even though the command failed
    /// (`error.data`); `None` for most errors.
    pub data: Option<Box<Value>>,
}

impl CliError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        CliError {
            code: code.into(),
            message: message.into(),
            hint: hint_for(code),
            data: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn exit_code(&self) -> u8 {
        if self.code == "state_uncertain" {
            EXIT_STATE_UNCERTAIN
        } else {
            EXIT_FAILED
        }
    }
}

impl From<cma_core::Error> for CliError {
    fn from(e: cma_core::Error) -> Self {
        CliError::new(e.code(), e.to_string())
    }
}

/// What to do next, per error code (`None`: the message says it all).
pub fn hint_for(code: &str) -> Option<String> {
    let h = match code {
        "needs_login" => {
            "re-run `cma login` for this account (add --email to pick it in the browser)"
        }
        "refresh_pending" => {
            "an interrupted token refresh is waiting to be verified: run `cma usage` (it finishes the refresh when the network is back), then retry"
        }
        "cma_lock_held" => {
            "this process already holds the cma lock; run the command again on its own (internal ordering error)"
        }
        "locked" => {
            "another cma command (or a token refresh) is running; wait for it to finish and retry"
        }
        "unidentified" => {
            "cma could not tell which account this login belongs to (profile lookup failed or disagreed); check the network and retry, nothing was stored"
        }
        "state_uncertain" => {
            "an operation could not be rolled back completely; its journal and backup are kept and cma refuses further changes until the journal is resolved. Run `cma status` and `cma backups` to see what it touched; any other command retries the rollback, and `cma resolve-journal` accepts the current state (the backup stays, so `cma restore <id>` remains possible)"
        }
        "backup_missing" => {
            "the unfinished operation's backup is gone; run `cma status` to see the journal, then `cma resolve-journal` to accept the current state"
        }
        "restore_conflict" => {
            "these items changed since the operation, most likely because Claude Code refreshed the live login's token: restoring would replace that newer token with an older one. To change accounts, run `cma switch <account>` instead. `--force` restores anyway after confirming (`--force --yes` without a terminal); what it overwrites is kept in the restore's own backup, whose id it prints, and `cma restore <that id>` puts it back"
        }
        "internal" => {
            "this is a bug in cma; run `cma status` (an operation interrupted by it is rolled back by the next command)"
        }
        "desktop_unavailable" => {
            "Claude Desktop switching is not available in this version; use --cli"
        }
        "desktop_running" => {
            "quit Claude Desktop (cma never force-quits it) and run the command again; a helper that keeps running after Desktop quit shows in the list above"
        }
        "desktop_restore_refused" => {
            "switch back instead: `cma switch --desktop <account>` stores the current Claude Desktop login first and loses nothing"
        }
        "desktop_not_linked" => {
            "link the account once: `cma desktop link <account>` (or `cma desktop import-current` while Claude Desktop is signed in as it)"
        }
        "registry_too_new" => "upgrade cma",
        _ => return None,
    };
    Some(h.to_string())
}

/// A successful command's result.
pub struct Outcome {
    pub data: Value,
    /// Human rendering (stdout).
    pub human: String,
    /// Some targets were switched, others not (exit 3).
    pub partial: bool,
    /// The command succeeded, but uncertain state exists (e.g. a pending
    /// journal shown by `status`).
    pub state_uncertain: bool,
}

impl Outcome {
    pub fn new(data: Value, human: impl Into<String>) -> Self {
        Outcome {
            data,
            human: human.into(),
            partial: false,
            state_uncertain: false,
        }
    }
}

/// Collects warnings while a command runs.
pub struct Out {
    pub json: bool,
    pub warnings: Vec<Warning>,
}

impl Out {
    pub fn new(json: bool) -> Self {
        Out {
            json,
            warnings: Vec::new(),
        }
    }

    pub fn warn_all(&mut self, w: impl IntoIterator<Item = Warning>) {
        for x in w {
            if !self
                .warnings
                .iter()
                .any(|y| y.code == x.code && y.message == x.message)
            {
                self.warnings.push(x);
            }
        }
    }

    pub fn warn(&mut self, code: &'static str, message: impl Into<String>) {
        self.warn_all([Warning::new(code, message)]);
    }

    /// Drop the warnings with `code` (one this command's result makes moot).
    pub fn drop_warnings(&mut self, code: &str) {
        self.warnings.retain(|w| w.code != code);
    }

    /// Print the result and return the exit code.
    pub fn finish(self, r: Result<Outcome, CliError>) -> u8 {
        let exit = match &r {
            Ok(o) if o.partial => EXIT_PARTIAL,
            Ok(_) => EXIT_OK,
            Err(e) => e.exit_code(),
        };
        if self.json {
            let doc = document(&r, &self.warnings);
            let mut s = serde_json::to_string_pretty(&doc).expect("serializable");
            s.push('\n');
            let _ = std::io::stdout().lock().write_all(s.as_bytes());
        } else {
            let mut err = std::io::stderr().lock();
            for w in &self.warnings {
                let _ = writeln!(err, "warning: {}", w.message);
            }
            match &r {
                Ok(o) => {
                    drop(err);
                    if !o.human.is_empty() {
                        let mut out = std::io::stdout().lock();
                        let _ = out.write_all(o.human.as_bytes());
                        if !o.human.ends_with('\n') {
                            let _ = out.write_all(b"\n");
                        }
                    }
                }
                Err(e) => {
                    let _ = writeln!(err, "error [{}]: {}", e.code, e.message);
                    if let Some(h) = &e.hint {
                        let _ = writeln!(err, "hint: {h}");
                    }
                }
            }
        }
        exit
    }
}

/// The JSON document for a result.
pub fn document(r: &Result<Outcome, CliError>, warnings: &[Warning]) -> Value {
    let warnings: Vec<Value> = warnings
        .iter()
        .map(|w| json!({"code": w.code, "message": w.message}))
        .collect();
    match r {
        Ok(o) => json!({
            "schema_version": SCHEMA_VERSION,
            "ok": true,
            "data": o.data,
            "warnings": warnings,
            "error": null,
            "state_uncertain": o.state_uncertain,
        }),
        Err(e) => json!({
            "schema_version": SCHEMA_VERSION,
            "ok": false,
            "data": null,
            "warnings": warnings,
            "error": {"code": e.code, "message": e.message, "hint": e.hint, "data": e.data},
            "state_uncertain": e.code == "state_uncertain",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_the_contract() {
        let o = Out::new(true);
        assert_eq!(o.finish(Ok(Outcome::new(json!({}), ""))), EXIT_OK);
        let mut p = Outcome::new(json!({}), "");
        p.partial = true;
        assert_eq!(Out::new(true).finish(Ok(p)), EXIT_PARTIAL);
        assert_eq!(
            Out::new(true).finish(Err(CliError::new("not_found", "x"))),
            EXIT_FAILED
        );
        let e: CliError = cma_core::Error::StateUncertain("x".into()).into();
        assert_eq!(e.exit_code(), EXIT_STATE_UNCERTAIN);
    }

    #[test]
    fn needs_login_and_refresh_pending_have_distinct_hints() {
        let n: CliError = cma_core::Error::NeedsLogin("a".into()).into();
        assert_eq!(n.code, "needs_login");
        assert!(n.hint.unwrap().contains("cma login"));
        let r: CliError = cma_core::Error::RefreshPending("a".into()).into();
        assert_eq!(r.code, "refresh_pending");
        assert!(r.hint.unwrap().contains("cma usage"));
        let u: CliError = cma_core::Error::Unidentified("a".into()).into();
        assert_eq!(u.code, "unidentified");
        let c: CliError = cma_core::Error::CmaLockHeld("a".into()).into();
        assert_eq!(c.code, "cma_lock_held");
        assert!(c.hint.is_some());
    }

    #[test]
    fn document_shape() {
        let w = vec![Warning::new("x", "y")];
        let d = document(&Ok(Outcome::new(json!({"a": 1}), "")), &w);
        assert_eq!(d["schema_version"], 1);
        assert_eq!(d["ok"], true);
        assert_eq!(d["error"], Value::Null);
        assert_eq!(d["warnings"][0]["code"], "x");
        assert_eq!(d["state_uncertain"], false);
        let d = document(&Err(CliError::new("state_uncertain", "m")), &[]);
        assert_eq!(d["ok"], false);
        assert_eq!(d["data"], Value::Null);
        assert_eq!(d["error"]["code"], "state_uncertain");
        assert_eq!(d["state_uncertain"], true);
    }
}
