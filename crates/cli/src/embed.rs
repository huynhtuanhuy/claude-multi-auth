//! In-process entry point for the menubar app: run one `cma` command and
//! get its JSON document back, with consent questions answered by the
//! app's own asker (a native dialog) instead of a terminal prompt.
//!
//! The command runs exactly as `cma <cmd> --json` would (same lock →
//! recover → sync path, same validation, same error codes and hints), with
//! one difference: a question the command would ask on a terminal is
//! passed to the asker. Questions are only ever asked after the command
//! released its locks (see `commands::with_consents`); the command then
//! runs again and re-checks under the lock.
//!
//! Must run on a plain thread (not an async runtime's): commands use
//! blocking I/O and blocking HTTP, and sessions are `!Send`.

use serde_json::Value;

use crate::commands::{self, AskerGuard};
use crate::deps::Deps;
use crate::output::{CliError, Out, document};
use crate::{Cli, Cmd};

/// A finished command: the `--json` document and the CLI exit code
/// (0 ok, 1 failed, 2 state uncertain, 3 partial).
#[derive(Debug, Clone)]
pub struct Finished {
    pub document: Value,
    pub exit_code: u8,
}

/// Run `cmd` against the real environment. `ask` answers consent
/// questions (return `true` only when the user agreed).
pub fn run(cmd: Cmd, ask: impl Fn(&str) -> bool + 'static) -> Finished {
    run_in(Box::new(cma_core::paths::SystemEnv), cmd, ask)
}

/// [`run`] with a fixed environment, for tests (the test backend is
/// selected through it).
#[cfg(feature = "test-backends")]
pub fn run_with_env(
    env: cma_core::paths::MapEnv,
    cmd: Cmd,
    ask: impl Fn(&str) -> bool + 'static,
) -> Finished {
    run_in(Box::new(env), cmd, ask)
}

fn run_in(
    env: Box<dyn cma_core::paths::Env>,
    cmd: Cmd,
    ask: impl Fn(&str) -> bool + 'static,
) -> Finished {
    let mut out = Out::new(true);
    if let Err(e) = embeddable(&cmd) {
        return finish(out, Err(e));
    }
    let cli = Cli { json: true, cmd };
    let _asker = AskerGuard::install(Box::new(ask));
    let deps = match Deps::with_env(env) {
        Ok(d) => d,
        Err(e) => return finish(out, Err(e)),
    };
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        commands::run(&cli, &deps, &mut out)
    }));
    // The panic payload is never reported, only that one happened.
    let r = r.unwrap_or_else(|_| Err(crate::panic_error("an app command", Some(&deps.paths))));
    finish(out, r)
}

fn finish(out: Out, r: Result<crate::output::Outcome, CliError>) -> Finished {
    let exit_code = match &r {
        Ok(o) if o.partial => crate::output::EXIT_PARTIAL,
        Ok(_) => crate::output::EXIT_OK,
        Err(e) => e.exit_code(),
    };
    Finished {
        document: document(&r, &out.warnings),
        exit_code,
    }
}

/// `login` never runs embedded: it runs `claude auth login`, which must
/// not run without a TTY (the app opens Terminal with
/// `cma login --args-file` instead). (`list --live` in JSON mode is a
/// one-shot fetch, not the terminal view, so it may run.)
fn embeddable(cmd: &Cmd) -> Result<(), CliError> {
    match cmd {
        Cmd::Login(_) => Err(CliError::new(
            "invalid",
            "login needs a terminal; the app opens one with `cma login --args-file`",
        )),
        _ => Ok(()),
    }
}
