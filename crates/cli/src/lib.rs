//! `cma`: command-line interface of claude-multi-auth. The binary
//! (`main.rs`) only calls [`main`]; the library target exists so this
//! crate's integration tests can enable the `test-backends` feature.

mod commands;
mod deps;
pub mod embed;
mod output;
#[cfg(feature = "test-backends")]
mod testbackend;
mod tui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::output::{CliError, Out};

#[derive(Parser, Debug)]
#[command(
    name = "cma",
    version = cma_core::VERSION,
    about = "Switch Claude Code and Claude Desktop between multiple Claude accounts",
    after_help = "Every command accepts --json: one JSON document on stdout, never a prompt. Exit codes: 0 ok, 1 failed before any change, 2 state uncertain (rollback failed, journal kept; see `cma status`, then `cma resolve-journal`), 3 partial success."
)]
pub struct Cli {
    /// Print one JSON document (schema_version 1) and never prompt.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List stored accounts with cached usage.
    List {
        /// Live view: refreshes usage in the background; Enter switches.
        #[arg(long)]
        live: bool,
    },
    /// Active account per target, warnings, running sessions, pending journal.
    Status,
    /// Log in a new account in the browser without touching the active one.
    Login(LoginArgs),
    /// Store the current Claude Code login as an account.
    ImportCurrent {
        /// Alias to give the account.
        #[arg(long)]
        alias: Option<String>,
    },
    /// Import exported credential files (a file or a directory).
    Import {
        /// A credential file, or a directory of `*.credential.json` files.
        path: PathBuf,
        /// Alias to give the account (one file only); also set when the file is already stored unchanged.
        #[arg(long)]
        alias: Option<String>,
        /// Replace accounts that are already stored with a different login.
        #[arg(long)]
        replace: bool,
    },
    /// Export stored CLI credentials (they contain refresh tokens).
    Export {
        /// Directory to write into (must be private: mode 0700).
        dir: PathBuf,
        /// Accounts to export (default: every Claude.ai account).
        queries: Vec<String>,
        /// Confirm writing refresh tokens to files.
        #[arg(long)]
        yes: bool,
    },
    /// Switch the active account (no query: pick from a list).
    Switch(SwitchArgs),
    /// Remove stored accounts (their credentials stay in a backup).
    Remove {
        /// Accounts to remove: row number, alias, email or key prefix.
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        queries: Vec<String>,
        /// Remove every stored account.
        #[arg(long)]
        all: bool,
        /// Also remove the active CLI account.
        #[arg(long)]
        force: bool,
    },
    /// Set or clear an account's alias.
    #[command(subcommand)]
    Alias(AliasCmd),
    /// Fetch live usage now (one shot).
    Usage {
        /// Only this account (default: every account).
        query: Option<String>,
    },
    /// Claude Desktop target: link, unlink, import the current login.
    #[command(subcommand)]
    Desktop(DesktopCmd),
    /// Read or change settings.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// List backups.
    Backups,
    /// Restore what one operation wrote, from its backup.
    Restore {
        /// Backup id, as `cma backups` lists it.
        id: String,
        /// Restore even items that changed since the operation (asks first; it can replace a newer token).
        #[arg(long)]
        force: bool,
        /// With --force: confirm without a prompt (required with --json or without a terminal).
        #[arg(long, requires = "force")]
        yes: bool,
        /// With --force: move away a live Claude Desktop login cma does not store (it is kept only in a backup).
        #[arg(long, requires = "force")]
        replace_live: bool,
    },
    /// Accept the current state after an operation that could not be rolled back (exit 2): archive its journal, keep its backup.
    ResolveJournal {
        /// Confirm without a prompt (required with --json or without a terminal).
        #[arg(long)]
        yes: bool,
    },
    /// Delete old backups.
    Clean {
        /// Backups to keep (default 10).
        #[arg(long)]
        keep: Option<usize>,
    },
}

#[derive(Args, Debug, Default)]
pub struct LoginArgs {
    /// Email to pre-fill in the browser.
    #[arg(long)]
    pub email: Option<String>,
    /// Single sign-on login.
    #[arg(long)]
    pub sso: bool,
    /// Console (API billing) login.
    #[arg(long)]
    pub console: bool,
    /// Expected organization (uuid or name).
    #[arg(long)]
    pub org: Option<String>,
    /// Alias to give the account.
    #[arg(long)]
    pub alias: Option<String>,
    /// Read the options above from a private JSON file instead (mode 0600,
    /// owned by you, not a symlink): `{"email", "alias", "org", "sso",
    /// "console"}`. The menubar app uses it so no option ever passes
    /// through shell text.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["email", "sso", "console", "org", "alias"])]
    pub args_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SwitchArgs {
    /// Account: row number, alias, email or key prefix (none: pick from a list).
    pub query: Option<String>,
    /// Switch Claude Code (the default target unless `default_target` says otherwise).
    #[arg(long, conflicts_with_all = ["desktop", "both"])]
    pub cli: bool,
    /// Switch Claude Desktop.
    #[arg(long, conflicts_with_all = ["cli", "both"])]
    pub desktop: bool,
    /// Switch Claude Code, then Claude Desktop.
    #[arg(long, conflicts_with_all = ["cli", "desktop"])]
    pub both: bool,
    /// With --both: refuse up front unless every target can switch.
    #[arg(long, requires = "both")]
    pub strict: bool,
    /// Switch even though `claude` sessions are running.
    #[arg(long)]
    pub force: bool,
    /// Replace a live login cma does not store (it is kept only in the backup).
    #[arg(long)]
    pub replace_live: bool,
    /// Quit Claude Desktop without asking (it is started again afterwards).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Subcommand, Debug)]
pub enum AliasCmd {
    /// Give an account an alias.
    Set {
        /// Account: row number, alias, email or key prefix.
        query: String,
        /// The new alias (not a number).
        alias: String,
    },
    /// Remove an account's alias.
    Clear {
        /// Account: row number, alias, email or key prefix.
        query: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum DesktopCmd {
    /// Sign Claude Desktop in to an account and store that login (stores the current one first; needs a terminal or the app).
    Link {
        /// Account to sign in as: row number, alias, email or key prefix.
        query: String,
        /// Quit Claude Desktop without asking.
        #[arg(long)]
        yes: bool,
        /// Move away a live Desktop login cma does not store (it is kept only in the backup).
        #[arg(long)]
        replace_live: bool,
    },
    /// Forget the Claude Desktop login cma stores for an account (default: the active one); the live Desktop login stays.
    Unlink {
        /// Account: row number, alias, email or key prefix.
        query: Option<String>,
    },
    /// Link the account Claude Desktop is signed in to now (Desktop keeps running).
    ImportCurrent {
        /// Alias for a new Desktop-only account.
        #[arg(long)]
        alias: Option<String>,
        /// Save an account no stored account matches as Desktop-only without asking.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print one setting, or all of them.
    Get {
        /// Setting name (none: all settings).
        key: Option<String>,
    },
    /// Change one setting.
    Set {
        /// Setting name (see `cma config get`).
        key: String,
        /// New value.
        value: String,
    },
}

/// Parse arguments, run the command, print the result.
pub fn main() -> ExitCode {
    let json_flag = std::env::args().any(|a| a == "--json");
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) || !json_flag
            {
                let _ = e.print();
                return ExitCode::from(if e.use_stderr() { 1 } else { 0 });
            }
            let err = CliError::new("usage", e.kind().to_string())
                .with_hint("run `cma --help` for the command syntax");
            return ExitCode::from(Out::new(true).finish(Err(err)));
        }
    };
    let mut out = Out::new(cli.json);
    if cli.json {
        install_json_panic_hook();
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || match deps::Deps::from_env() {
            Ok(d) => commands::run(&cli, &d, &mut out),
            Err(e) => Err(e),
        },
    ));
    let r = r.unwrap_or_else(|_| {
        let at = PANIC_AT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| "unknown location".into());
        let paths = cma_core::paths::Paths::from_system().ok();
        Err(panic_error(&at, paths.as_ref()))
    });
    ExitCode::from(out.finish(r))
}

/// The error a caught panic becomes. An operation journal on disk means a
/// change may have begun and was not finished: reported like any uncertain
/// state (exit 2); otherwise `internal` (exit 1).
pub(crate) fn panic_error(at: &str, paths: Option<&cma_core::paths::Paths>) -> CliError {
    let journal = paths.is_some_and(|p| std::fs::symlink_metadata(p.journal_file()).is_ok());
    if journal {
        CliError::new(
            "state_uncertain",
            format!("cma hit an internal error (panic at {at}) while an operation journal exists"),
        )
        .with_hint("this is a bug in cma; run `cma status`: it rolls the interrupted operation back, or keeps its journal (then `cma resolve-journal`) if it cannot")
    } else {
        CliError::new(
            "internal",
            format!("cma hit an internal error (panic at {at})"),
        )
    }
}

/// Where the last panic happened (file:line only).
static PANIC_AT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// In `--json` mode a panic must still end in one JSON document on stdout
/// (code `internal`, exit 1; `state_uncertain`, exit 2, when an operation
/// journal exists): the hook only records the location and prints
/// one line to stderr, and `main` catches the unwind, so destructors (lock
/// release, journal left for recovery) run before the document is printed.
/// The panic payload is never printed: only the location.
fn install_json_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".into());
        eprintln!("cma: internal error (panic at {at})");
        *PANIC_AT.lock().unwrap_or_else(|e| e.into_inner()) = Some(at);
    }));
}
