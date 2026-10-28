//! Claude Desktop process control: is it running, quit it, launch it.
//!
//! Desktop counts as running while any process runs whose executable is
//! inside `Claude.app/Contents/`, or under `<Desktop dir>/claude-code*/`
//! (the `claude` binaries and VM helpers Desktop spawns). One exception:
//! `Claude.app/Contents/Helpers/chrome-native-host` is started by the web
//! browser for the Claude extension, not by Desktop, and is ignored.
//!
//! Quit asks politely (`osascript … to quit`) and waits for every Desktop
//! process to exit; it never force-kills. Launch is `open -b`. Only pid,
//! parent pid and the executable path are read, never command lines.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result, ToolFailure};
use crate::procs::{ProcInfo, ProcessLister};
use crate::secret::{CommandRunner, ProcessRunner};

/// Claude Desktop's bundle identifier.
pub const BUNDLE_ID: &str = "com.anthropic.claudefordesktop";
/// How long a quit waits for every Desktop process to exit.
pub const QUIT_TIMEOUT: Duration = Duration::from_secs(20);
/// Poll interval while waiting.
pub const POLL: Duration = Duration::from_millis(250);
/// Browser-started helper inside the bundle that does not count as Desktop.
pub const EXEMPT_HELPER: &str = "chrome-native-host";

/// Whether `comm` (an executable path as `ps -o comm` shows it) lies where
/// Desktop's processes run from. The browser-helper exemption needs the
/// process table: see [`desktop_processes`].
pub fn is_desktop_process(comm: &str, desktop_dir: &Path) -> bool {
    if comm.contains("/Claude.app/Contents/") {
        return true;
    }
    let dir = desktop_dir.to_string_lossy();
    let prefix = format!("{}/", dir.trim_end_matches('/'));
    comm.strip_prefix(&prefix)
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|top| top.starts_with("claude-code"))
}

fn is_exempt_helper(comm: &str) -> bool {
    comm.rsplit('/').next().unwrap_or(comm) == EXEMPT_HELPER
}

/// The Desktop processes in a process table. `chrome-native-host` is left
/// out only when its parent is not a Desktop process (the browser started
/// it); one Desktop started counts.
pub fn desktop_processes(procs: &[ProcInfo], desktop_dir: &Path) -> Vec<ProcInfo> {
    let parent_is_desktop = |p: &ProcInfo| {
        procs.iter().any(|q| {
            q.pid == p.ppid
                && q.pid != p.pid
                && is_desktop_process(&q.comm, desktop_dir)
                && !is_exempt_helper(&q.comm)
        })
    };
    let mut v: Vec<ProcInfo> = procs
        .iter()
        .filter(|p| is_desktop_process(&p.comm, desktop_dir))
        .filter(|p| !is_exempt_helper(&p.comm) || parent_is_desktop(p))
        .cloned()
        .collect();
    v.sort_by_key(|p| p.pid);
    v
}

/// `pid <n> <path>` lines for messages.
pub fn describe(procs: &[ProcInfo]) -> Vec<String> {
    procs
        .iter()
        .map(|p| format!("pid {} {}", p.pid, p.comm))
        .collect()
}

/// Whether the app itself (not only a helper it left behind) runs.
fn app_runs(procs: &[ProcInfo]) -> bool {
    procs
        .iter()
        .any(|p| p.comm.contains("/Claude.app/Contents/"))
}

/// Desktop control.
pub trait DesktopApp {
    /// Desktop processes running now.
    fn running(&self) -> Result<Vec<ProcInfo>>;
    /// Ask Desktop to quit (returns without waiting).
    fn quit(&self) -> Result<()>;
    /// Start Desktop.
    fn launch(&self) -> Result<()>;
    /// Wait between polls (tests make it free).
    fn pause(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// The real Desktop: `ps`, `osascript`, `open`.
pub struct SystemDesktopApp {
    pub desktop_dir: PathBuf,
}

fn run_tool(program: &'static str, path: &str, args: Vec<OsString>) -> Result<()> {
    let fail = |code, class| Error::ExternalTool {
        program,
        sub: "run",
        code,
        class,
    };
    let out = ProcessRunner
        .run(Path::new(path), &args, None)
        .map_err(|_| fail(None, ToolFailure::SpawnFailed))?;
    if out.code != Some(0) {
        return Err(fail(out.code, ToolFailure::Other));
    }
    Ok(())
}

impl DesktopApp for SystemDesktopApp {
    fn running(&self) -> Result<Vec<ProcInfo>> {
        Ok(desktop_processes(
            &crate::procs::PsLister.list()?,
            &self.desktop_dir,
        ))
    }

    fn quit(&self) -> Result<()> {
        run_tool(
            "osascript",
            "/usr/bin/osascript",
            vec![
                "-e".into(),
                format!("tell application id \"{BUNDLE_ID}\" to quit").into(),
            ],
        )
    }

    fn launch(&self) -> Result<()> {
        run_tool("open", "/usr/bin/open", vec!["-b".into(), BUNDLE_ID.into()])
    }
}

/// The error for Desktop processes that are (still) running.
pub fn running_error(what: &str, procs: &[ProcInfo]) -> Error {
    Error::DesktopRunning(format!("{what}: {}", describe(procs).join(", ")))
}

/// Quit Desktop if it runs and wait up to `timeout` for every Desktop
/// process to exit. Never force-kills: on timeout the error lists what is
/// still running. Returns whether Desktop was running.
pub fn quit_and_wait(app: &dyn DesktopApp, timeout: Duration) -> Result<bool> {
    let first = app.running()?;
    if first.is_empty() {
        return Ok(false);
    }
    if app_runs(&first) {
        // A failed osascript is not fatal by itself: the wait decides.
        let _ = app.quit();
    }
    let start = Instant::now();
    loop {
        let now = app.running()?;
        if now.is_empty() {
            return Ok(true);
        }
        if start.elapsed() >= timeout {
            return Err(running_error(
                &format!(
                    "Claude Desktop did not exit within {} s (cma never force-quits it)",
                    timeout.as_secs()
                ),
                &now,
            ));
        }
        app.pause(POLL);
    }
}

/// Re-checked before each write step of a Desktop op: Desktop (e.g. an
/// auto-update relaunch) appearing mid-op aborts it, and the op rolls back.
pub struct Guard<'a> {
    pub app: &'a dyn DesktopApp,
}

impl Guard<'_> {
    pub fn check(&self, step: &str) -> Result<()> {
        let now = self.app.running()?;
        if now.is_empty() {
            Ok(())
        } else {
            Err(running_error(
                &format!(
                    "Claude Desktop started during the operation (before {step}); rolled back"
                ),
                &now,
            ))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::procs::tests::p;
    use std::cell::{Cell, RefCell};

    const DD: &str = "/Users/me/Library/Application Support/Claude";

    /// Scripted Desktop: `running()` returns the next table from `script`
    /// (the last one repeats); quit/launch are recorded.
    #[derive(Default)]
    pub struct FakeApp {
        pub script: RefCell<Vec<Vec<ProcInfo>>>,
        pub calls: RefCell<Vec<String>>,
        pub polls: Cell<usize>,
        /// After quit, the table becomes empty.
        pub quit_stops: bool,
        pub stopped: Cell<bool>,
        /// After launch, the app runs.
        pub launched: Cell<bool>,
    }

    impl FakeApp {
        pub fn idle() -> Self {
            FakeApp::default()
        }

        pub fn running_app() -> Vec<ProcInfo> {
            vec![p(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude")]
        }

        /// Running until asked to quit.
        pub fn quits() -> Self {
            FakeApp {
                script: RefCell::new(vec![Self::running_app()]),
                quit_stops: true,
                ..Default::default()
            }
        }

        /// Not running for `n` polls, then running.
        pub fn starts_after(n: usize) -> Self {
            let mut s = vec![Vec::new(); n];
            s.push(Self::running_app());
            FakeApp {
                script: RefCell::new(s),
                ..Default::default()
            }
        }
    }

    impl DesktopApp for FakeApp {
        fn running(&self) -> Result<Vec<ProcInfo>> {
            self.polls.set(self.polls.get() + 1);
            if self.launched.get() && !self.stopped.get() {
                return Ok(Self::running_app());
            }
            if self.stopped.get() {
                return Ok(Vec::new());
            }
            let mut s = self.script.borrow_mut();
            Ok(if s.len() > 1 {
                s.remove(0)
            } else {
                s.first().cloned().unwrap_or_default()
            })
        }
        fn quit(&self) -> Result<()> {
            self.calls.borrow_mut().push("quit".into());
            if self.quit_stops {
                self.stopped.set(true);
            }
            Ok(())
        }
        fn launch(&self) -> Result<()> {
            self.calls.borrow_mut().push("launch".into());
            self.stopped.set(false);
            self.launched.set(true);
            Ok(())
        }
        fn pause(&self, _: Duration) {}
    }

    #[test]
    fn classifies_desktop_processes_and_exempts_the_browser_helper() {
        let dd = Path::new(DD);
        let procs = vec![
            p(1, 0, "/sbin/launchd"),
            p(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude"),
            p(
                11,
                10,
                "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)",
            ),
            // Started by Chrome for the browser extension.
            p(
                20,
                30,
                "/Applications/Claude.app/Contents/Helpers/chrome-native-host",
            ),
            p(
                30,
                1,
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            ),
            p(40, 10, &format!("{DD}/claude-code/2.1.310/claude")),
            // A VM helper that may outlive the app still counts.
            p(41, 1, &format!("{DD}/claude-code-vm/2.1.0/helper")),
            p(50, 1, &format!("{DD}/other/claude")),
            p(60, 1, "claude"),
            p(
                70,
                1,
                "/Users/me/Applications/Claude.app/Contents/MacOS/Claude",
            ),
        ];
        let pids: Vec<u32> = desktop_processes(&procs, dd)
            .iter()
            .map(|p| p.pid)
            .collect();
        assert_eq!(pids, vec![10, 11, 40, 41, 70]);
    }

    #[test]
    fn quit_waits_until_everything_exited() {
        let app = FakeApp::quits();
        assert!(quit_and_wait(&app, QUIT_TIMEOUT).unwrap());
        assert_eq!(*app.calls.borrow(), ["quit"]);
        // Not running: nothing to do.
        let idle = FakeApp::idle();
        assert!(!quit_and_wait(&idle, QUIT_TIMEOUT).unwrap());
        assert!(idle.calls.borrow().is_empty());
    }

    #[test]
    fn quit_times_out_with_the_list_and_never_kills() {
        let app = FakeApp {
            script: RefCell::new(vec![FakeApp::running_app()]),
            ..Default::default()
        };
        let e = quit_and_wait(&app, Duration::ZERO).unwrap_err();
        assert_eq!(e.code(), "desktop_running");
        assert!(e.to_string().contains("pid 10"), "{e}");
        assert_eq!(*app.calls.borrow(), ["quit"]);
    }

    #[test]
    fn a_leftover_helper_is_waited_for_but_no_quit_is_sent() {
        let helper = vec![p(41, 1, &format!("{DD}/claude-code-vm/x/helper"))];
        let app = FakeApp {
            script: RefCell::new(vec![helper.clone(), helper, Vec::new()]),
            ..Default::default()
        };
        assert!(quit_and_wait(&app, QUIT_TIMEOUT).unwrap());
        assert!(app.calls.borrow().is_empty());
    }

    #[test]
    fn guard_trips_when_desktop_appears() {
        let app = FakeApp::starts_after(1);
        let g = Guard { app: &app };
        g.check("one").unwrap();
        let e = g.check("two").unwrap_err();
        assert_eq!(e.code(), "desktop_running");
    }
}
