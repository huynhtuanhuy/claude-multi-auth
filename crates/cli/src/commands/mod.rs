//! Command implementations. Mutating commands go through
//! [`cma_core::sync::begin`] (cma lock → recover → sync) before their op;
//! `backups`, `restore`, `resolve-journal` and `clean` take the cma lock
//! without recovery, and
//! `status` reports a failed sync instead of failing, so a kept journal
//! never hides what happened.

mod accounts;
mod backups;
mod config;
mod desktop;
pub mod list;
mod login;
mod status;
mod switch;
mod transfer;
pub mod usage;

use std::cell::RefCell;
use std::io::IsTerminal;

use cma_core::cli_target::Ctx;
use cma_core::registry::{Account, Registry};
use cma_core::sync::{LiveState, Session, begin};
use cma_core::{lock, selector};
use serde_json::{Value, json};

use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};
use crate::{AliasCmd, Cli, Cmd, ConfigCmd, DesktopCmd};

pub type CmdResult = Result<Outcome, CliError>;

pub fn run(cli: &Cli, deps: &Deps, out: &mut Out) -> CmdResult {
    install_wait_notice(deps);
    // Fault injection for the `--json` panic path (test builds only).
    #[cfg(feature = "test-backends")]
    if deps.env.var("CMA_TEST_PANIC").is_some() {
        panic!("injected test panic");
    }
    match &cli.cmd {
        Cmd::List { live } => list::run(deps, out, *live),
        Cmd::Status => status::run(deps, out),
        Cmd::Login(a) => login::run(deps, out, a),
        Cmd::ImportCurrent { alias } => transfer::import_current(deps, out, alias.as_deref()),
        Cmd::Import {
            path,
            alias,
            replace,
        } => transfer::import(deps, out, path, alias.as_deref(), *replace),
        Cmd::Export { dir, queries, yes } => transfer::export(deps, out, dir, queries, *yes),
        Cmd::Switch(a) => switch::run(deps, out, a),
        Cmd::Remove {
            queries,
            all,
            force,
        } => accounts::remove(deps, out, queries, *all, *force),
        Cmd::Alias(AliasCmd::Set { query, alias }) => {
            accounts::alias(deps, out, query, Some(alias.as_str()))
        }
        Cmd::Alias(AliasCmd::Clear { query }) => accounts::alias(deps, out, query, None),
        Cmd::Usage { query } => usage::run(deps, out, query.as_deref()),
        Cmd::Desktop(DesktopCmd::Link {
            query,
            yes,
            replace_live,
        }) => desktop::link(deps, out, query, *yes, *replace_live),
        Cmd::Desktop(DesktopCmd::Unlink { query }) => desktop::unlink(deps, out, query.as_deref()),
        Cmd::Desktop(DesktopCmd::ImportCurrent { alias, yes }) => {
            desktop::import_current(deps, out, alias.as_deref(), *yes)
        }
        Cmd::Config(ConfigCmd::Get { key }) => config::get(deps, key.as_deref()),
        Cmd::Config(ConfigCmd::Set { key, value }) => config::set(deps, out, key, value),
        Cmd::Backups => backups::list(deps),
        Cmd::Restore {
            id,
            force,
            yes,
            replace_live,
        } => backups::restore(deps, out, id, *force, *yes, *replace_live),
        Cmd::ResolveJournal { yes } => backups::resolve_journal(deps, out, *yes),
        Cmd::Clean { keep } => backups::clean(deps, out, *keep),
    }
}

/// Say what a busy account lock waits for (another process refreshing that
/// account's token), instead of up to 40 s of silence. stderr only.
fn install_wait_notice(deps: &Deps) {
    let registry_file = deps.paths.registry_file();
    lock::set_account_wait_notifier(Some(Box::new(move |key: &str| {
        let label = Registry::load(&registry_file)
            .ok()
            .and_then(|r| r.account(key).map(label_of))
            .unwrap_or_else(|| key.to_string());
        eprintln!("waiting for a token refresh of {label} to finish (up to 40 s)…");
    })));
}

/// Start a session and move its warnings into `out`.
pub fn start<'c>(ctx: &'c Ctx<'c>, out: &mut Out) -> Result<Session<'c>, CliError> {
    let mut s = begin(ctx)?;
    out.warn_all(std::mem::take(&mut s.warnings));
    Ok(s)
}

/// Whether consent questions can be asked: human mode on a terminal, or
/// an embedding app that installed an asker ([`AskerGuard`]).
pub fn interactive(out: &Out) -> bool {
    asker_installed() || terminal(out)
}

/// Whether a terminal prompt (the picker) can be shown: human mode on a
/// terminal only, never through an embedding app's asker.
pub fn terminal(out: &Out) -> bool {
    !out.json
        && (fake_terminal_answers().is_some()
            || (std::io::stdin().is_terminal() && std::io::stderr().is_terminal()))
}

/// Test builds only: `CMA_TEST_TERMINAL_ANSWERS` (comma-separated `y`/`n`)
/// stands in for a terminal, answering the yes/no prompts in order (a
/// missing answer is no), so tests can see what human mode prints around a
/// prompt.
#[cfg(feature = "test-backends")]
fn fake_terminal_answers() -> Option<String> {
    std::env::var("CMA_TEST_TERMINAL_ANSWERS").ok()
}

#[cfg(not(feature = "test-backends"))]
fn fake_terminal_answers() -> Option<String> {
    None
}

/// Answers a consent question for an embedding app (a native dialog).
pub type Asker = Box<dyn Fn(&str) -> bool>;

thread_local! {
    static ASKER: RefCell<Option<Asker>> = const { RefCell::new(None) };
}

fn asker_installed() -> bool {
    ASKER.with(|a| a.borrow().is_some())
}

/// Installs an asker for this thread; dropping it (also on a panic)
/// removes it, so a pooled thread never answers a later command's
/// question with a stale asker.
pub struct AskerGuard(());

impl AskerGuard {
    pub fn install(asker: Asker) -> Self {
        ASKER.with(|a| *a.borrow_mut() = Some(asker));
        AskerGuard(())
    }
}

impl Drop for AskerGuard {
    fn drop(&mut self) {
        // `try_with`: the thread-local may already be gone at thread exit.
        let _ = ASKER.try_with(|a| a.borrow_mut().take());
    }
}

/// Most prompts one command shows before giving up on a condition that
/// keeps changing between them.
const MAX_PROMPTS: usize = 4;

/// Answers to prompts, given while no lock is held.
///
/// An operation runs with the cma lock (and possibly an account lock) held
/// and must never wait on the user there: other cma processes would time
/// out. So it runs with [`Consents::check`] as its prompt, which says yes
/// only to a question the user already agreed to and otherwise records the
/// question and says no. [`with_consents`] then releases the locks (the
/// operation returned), asks, and runs the operation again; the operation
/// re-checks its conditions under the lock, and a question that changed in
/// the meantime is asked again.
#[derive(Default)]
pub struct Consents {
    given: RefCell<Vec<String>>,
    asked: RefCell<Option<String>>,
}

impl Consents {
    pub fn check(&self, question: &str) -> bool {
        if self.given.borrow().iter().any(|q| q == question) {
            return true;
        }
        *self.asked.borrow_mut() = Some(question.to_string());
        false
    }
}

/// Run `op` and ask the questions it records only after it returned (and
/// released its locks); see [`Consents`]. Without a terminal (`tty` false)
/// `op` runs once and must not use [`Consents::check`]. A declined question
/// returns the operation's own `confirmation_required` error.
pub fn with_consents<T>(
    tty: bool,
    op: impl FnMut(&Consents) -> Result<T, CliError>,
) -> Result<T, CliError> {
    consent_loop(tty, &ask, op)
}

pub(crate) fn consent_loop<T>(
    tty: bool,
    ask: &dyn Fn(&str) -> bool,
    mut op: impl FnMut(&Consents) -> Result<T, CliError>,
) -> Result<T, CliError> {
    let c = Consents::default();
    for _ in 0..MAX_PROMPTS {
        match op(&c) {
            Err(e) if tty && e.code == "confirmation_required" => {
                let Some(q) = c.asked.borrow_mut().take() else {
                    return Err(e);
                };
                if !ask(&q) {
                    return Err(declined(e, &q));
                }
                c.given.borrow_mut().push(q);
            }
            r => return r,
        }
    }
    Err(CliError::new(
        "confirmation_required",
        "what needed confirmation kept changing between prompts; nothing was changed",
    )
    .with_hint("run the command again"))
}

/// The error for a declined question. On a terminal the explanation was
/// just printed above the prompt, so the error does not repeat it (an
/// embedding app's asker, and `--json`, keep the full message).
fn declined(e: CliError, question: &str) -> CliError {
    if asker_installed() {
        return e;
    }
    let shortened = question
        .rsplit_once('\n')
        .and_then(|(explanation, _)| e.message.split_once(explanation))
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.strip_prefix("; "))
        .map(str::to_string);
    match shortened {
        Some(message) => CliError { message, ..e },
        None => e,
    }
}

/// Ask a yes/no question: through the embedding app's asker when one is
/// installed, otherwise on stderr (default no; an error counts as no).
/// Only ever called with no lock held (see [`with_consents`]).
///
/// A question is an explanation and, on its last line, the question
/// proper. On a terminal the explanation is printed once as plain text and
/// only the last line is the prompt: the prompt redraws (and reports the
/// answer) by clearing just its own line, so a multi-line or wrapped
/// prompt would leave a copy of its explanation behind on every redraw.
pub fn ask(question: &str) -> bool {
    // Take the asker out while it runs, so a re-entrant call cannot alias
    // the RefCell; it is put back afterwards.
    if let Some(a) = ASKER.with(|a| a.borrow_mut().take()) {
        let yes = a(question);
        ASKER.with(|slot| *slot.borrow_mut() = Some(a));
        return yes;
    }
    let prompt = match question.rsplit_once('\n') {
        Some((explanation, prompt)) => {
            eprintln!("{explanation}");
            prompt
        }
        None => question,
    };
    if fake_terminal_answers().is_some() {
        return fake_terminal_confirm(prompt);
    }
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap_or(false)
}

thread_local! {
    static FAKE_ANSWERS_USED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The next `CMA_TEST_TERMINAL_ANSWERS` answer, echoed like the prompt
/// renders it.
fn fake_terminal_confirm(prompt: &str) -> bool {
    let answers = fake_terminal_answers().unwrap_or_default();
    let i = FAKE_ANSWERS_USED.with(|n| n.replace(n.get() + 1));
    let yes = answers.split(',').nth(i).map(str::trim) == Some("y");
    eprintln!("{prompt} [y/N] {}", if yes { "yes" } else { "no" });
    yes
}

/// Resolve a query to an account key.
pub fn select_key(reg: &Registry, query: &str) -> Result<String, CliError> {
    Ok(selector::select(&reg.accounts, query)?.key.clone())
}

/// `email` (or the key), plus the alias.
pub fn label_of(a: &Account) -> String {
    let base = if a.email.is_empty() {
        a.key.clone()
    } else {
        a.email.clone()
    };
    match &a.alias {
        Some(al) => format!("{al} ({base})"),
        None => base,
    }
}

/// A query that selects `key`: its alias, else its email, else the key.
pub fn query_for(reg: &Registry, key: &str) -> String {
    match reg.account(key) {
        Some(a) => a
            .alias
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if a.email.is_empty() {
                    key.to_string()
                } else {
                    a.email.clone()
                }
            }),
        None => key.to_string(),
    }
}

pub fn label(reg: &Registry, key: &str) -> String {
    reg.account(key)
        .map(label_of)
        .unwrap_or_else(|| key.to_string())
}

pub fn live_json(l: &LiveState) -> Value {
    match l {
        LiveState::Absent => json!({"state": "absent"}),
        LiveState::NoCredential => json!({"state": "no_credential"}),
        LiveState::Identified { key, managed } => {
            json!({"state": "identified", "key": key, "managed": managed})
        }
        LiveState::NeedsLogin { key } => json!({"state": "needs_login", "key": key}),
        LiveState::Unidentified { reason } => json!({"state": "unidentified", "reason": reason}),
    }
}

pub fn live_text(reg: &Registry, l: &LiveState) -> String {
    match l {
        LiveState::Absent => "no Claude Code login".into(),
        LiveState::NoCredential => "no Claude.ai credential in the Claude Code login".into(),
        LiveState::Identified { key, managed: true } => label(reg, key),
        LiveState::Identified {
            key,
            managed: false,
        } => {
            format!("{key} (not stored by cma; `cma import-current` keeps it)")
        }
        LiveState::NeedsLogin { key } => format!("{} (signed out: needs login)", label(reg, key)),
        LiveState::Unidentified { reason } => format!("unidentified ({reason})"),
    }
}

pub fn kind_str(a: &Account) -> Value {
    serde_json::to_value(a.kind).unwrap_or(Value::Null)
}

pub fn desktop_active(reg: &Registry, a: &Account) -> bool {
    reg.active.desktop.as_deref() == Some(a.account_uuid.as_str())
}

pub fn desktop_linked(reg: &Registry, a: &Account) -> bool {
    reg.desktop.iter().any(|l| l.account_uuid == a.account_uuid)
}

/// One account as JSON (`index` is the 1-based row number queries accept).
pub fn account_json(reg: &Registry, i: usize, a: &Account) -> Value {
    json!({
        "index": i + 1,
        "key": a.key,
        "alias": a.alias,
        "email": a.email,
        "org_name": a.org_name,
        "plan": a.plan,
        "kind": kind_str(a),
        "cli_active": reg.active.cli.as_deref() == Some(a.key.as_str()),
        "desktop_active": desktop_active(reg, a),
        "desktop_linked": desktop_linked(reg, a),
        "needs_login": a.needs_login,
        "added_at": a.added_at,
        "last_active_at": a.last_active_at,
        "usage": {
            "fetched_at": a.usage.fetched_at,
            "windows": a.usage.windows,
            "error": a.usage.error,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn needs(c: &Consents, q: &str) -> Result<(), CliError> {
        if c.check(q) {
            Ok(())
        } else {
            Err(CliError::new(
                "confirmation_required",
                format!("{q}; cancelled"),
            ))
        }
    }

    #[test]
    fn a_question_is_asked_between_runs_and_asked_again_when_it_changed() {
        let asked = RefCell::new(Vec::new());
        let ask = |q: &str| {
            asked.borrow_mut().push(q.to_string());
            true
        };
        let runs = Cell::new(0);
        let r = consent_loop(true, &ask, |c| {
            runs.set(runs.get() + 1);
            // The condition changes after the first answer (e.g. one more
            // `claude` session started while the user read the prompt).
            needs(
                c,
                if runs.get() == 1 {
                    "1 session"
                } else {
                    "2 sessions"
                },
            )
        });
        assert!(r.is_ok());
        assert_eq!(*asked.borrow(), ["1 session", "2 sessions"]);
        assert_eq!(runs.get(), 3);
    }

    #[test]
    fn a_declined_question_returns_the_operations_error() {
        let no = |_: &str| false;
        let runs = Cell::new(0);
        let e = consent_loop(true, &no, |c| {
            runs.set(runs.get() + 1);
            needs(c, "q")
        })
        .unwrap_err();
        assert_eq!(e.code, "confirmation_required");
        assert_eq!(e.message, "q; cancelled");
        assert_eq!(runs.get(), 1);
    }

    #[test]
    fn without_a_terminal_nothing_is_asked() {
        let ask = |_: &str| -> bool { panic!("asked without a terminal") };
        let e = consent_loop(false, &ask, |c| needs(c, "q")).unwrap_err();
        assert_eq!(e.code, "confirmation_required");
    }

    #[test]
    fn a_condition_that_keeps_changing_gives_up() {
        let yes = |_: &str| true;
        let n = Cell::new(0);
        let e = consent_loop(true, &yes, |c| {
            n.set(n.get() + 1);
            needs(c, &format!("q{}", n.get()))
        })
        .unwrap_err();
        assert_eq!(e.code, "confirmation_required");
        assert_eq!(n.get(), MAX_PROMPTS);
    }
}
