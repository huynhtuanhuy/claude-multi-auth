//! Detect running Claude Code CLI sessions (not Claude Desktop's).
//!
//! Only pid, parent pid and the executable name are read (`ps -o comm`):
//! never command lines, which can hold secrets of other processes.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;

use crate::error::{Error, Result, ToolFailure};
use crate::secret::{CommandRunner, ProcessRunner};

/// Warning shown before a CLI switch while sessions run (observed
/// with Claude Code 2.1.310).
pub const RUNNING_SESSIONS_WARNING: &str = "running sessions switch to the new account's token within ~30s, but their /status keeps showing the old account name until restarted";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    /// Executable name or path as `ps -o comm` shows it.
    pub comm: String,
}

/// Lists processes.
pub trait ProcessLister {
    fn list(&self) -> Result<Vec<ProcInfo>>;
}

/// `/bin/ps -axo pid=,ppid=,comm=`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PsLister;

impl ProcessLister for PsLister {
    fn list(&self) -> Result<Vec<ProcInfo>> {
        let args: Vec<OsString> = vec!["-axo".into(), "pid=,ppid=,comm=".into()];
        let fail = |code, class| Error::ExternalTool {
            program: "ps",
            sub: "-axo",
            code,
            class,
        };
        let out = ProcessRunner
            .run(Path::new("/bin/ps"), &args, None)
            .map_err(|_| fail(None, ToolFailure::SpawnFailed))?;
        if out.code != Some(0) {
            return Err(fail(out.code, ToolFailure::Other));
        }
        Ok(parse_ps(&String::from_utf8_lossy(out.stdout.expose())))
    }
}

/// Parse `pid ppid comm` lines; malformed lines are skipped.
pub fn parse_ps(text: &str) -> Vec<ProcInfo> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let (pid, rest) = l.split_once(char::is_whitespace)?;
            let rest = rest.trim_start();
            let (ppid, comm) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            Some(ProcInfo {
                pid: pid.parse().ok()?,
                ppid: ppid.parse().ok()?,
                comm: comm.trim().to_string(),
            })
        })
        .collect()
}

fn is_claude_exe(comm: &str) -> bool {
    let base = comm.rsplit('/').next().unwrap_or(comm);
    base == "claude" || base == "claude.exe"
}

fn is_desktop(comm: &str) -> bool {
    comm.contains("/Claude.app/") || comm.contains("Application Support/Claude/claude-code")
}

/// Pids of running Claude Code CLI sessions: executables named `claude`
/// that are not Desktop's bundled copy, not descendants of `Claude.app`,
/// and not `self_pid`.
pub fn cli_sessions(procs: &[ProcInfo], self_pid: u32) -> Vec<u32> {
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    let under_desktop = |p: &ProcInfo| {
        let mut cur = p.ppid;
        // Bounded walk: a cycle or a very deep tree stops it.
        for _ in 0..64 {
            match by_pid.get(&cur) {
                Some(q) if q.pid != q.ppid => {
                    if is_desktop(&q.comm) {
                        return true;
                    }
                    cur = q.ppid;
                }
                _ => return false,
            }
        }
        false
    };
    let mut v: Vec<u32> = procs
        .iter()
        .filter(|p| p.pid != self_pid)
        .filter(|p| is_claude_exe(&p.comm) && !is_desktop(&p.comm) && !under_desktop(p))
        .map(|p| p.pid)
        .collect();
    v.sort_unstable();
    v
}

/// What is known about a process and its start time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcStart {
    /// Definitely no such process (`kill(pid, 0)` says ESRCH, or `ps`
    /// succeeded and listed nothing).
    Gone,
    /// It runs and started at this time (`ps -o lstart=` in the C locale).
    Started(String),
    /// Could not tell (`ps` failed): callers treat it as running.
    Unknown,
}

/// `ps -o lstart= -p <pid>` with a cleared environment and the C locale, so
/// the text is the same whoever runs it. `ambient` is applied before the C
/// locale is forced (tests pass a foreign locale there to show it cannot
/// leak in).
fn ps_lstart(pid: u32, ambient: &[(&str, &str)]) -> ProcStart {
    let args: Vec<OsString> = vec![
        "-o".into(),
        "lstart=".into(),
        "-p".into(),
        pid.to_string().into(),
    ];
    let mut env: Vec<(OsString, OsString)> = ambient
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
    env.retain(|(k, _)| k != "LC_ALL" && k != "LANG");
    env.push(("PATH".into(), "/usr/bin:/bin".into()));
    env.push(("LC_ALL".into(), "C".into()));
    env.push(("LANG".into(), "C".into()));
    let Ok(out) = crate::secret::run_process(Path::new("/bin/ps"), &args, Some(&env), None) else {
        return ProcStart::Unknown;
    };
    let text = String::from_utf8_lossy(out.stdout.expose())
        .trim()
        .to_string();
    match out.code {
        Some(0) if text.is_empty() => ProcStart::Gone,
        Some(0) => ProcStart::Started(text),
        // `ps -p` exits 1 when the pid matches nothing: only with no
        // output at all is that a definite "gone".
        Some(1) if text.is_empty() => ProcStart::Gone,
        _ => ProcStart::Unknown,
    }
}

/// Probe process `pid`: ESRCH from `kill(pid, 0)` is definitely gone;
/// otherwise its start time from `ps`, or [`ProcStart::Unknown`].
pub fn probe_start(pid: u32) -> ProcStart {
    probe_start_with(pid, &[])
}

fn probe_start_with(pid: u32, ambient: &[(&str, &str)]) -> ProcStart {
    let Some(p) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return ProcStart::Unknown;
    };
    if let Err(e) = rustix::process::test_kill_process(p)
        && e == rustix::io::Errno::SRCH
    {
        return ProcStart::Gone;
    }
    ps_lstart(pid, ambient)
}

/// When process `pid` started, as [`probe_start`] reads it (`None` when it
/// could not be read).
pub fn process_start(pid: u32) -> Option<String> {
    match probe_start(pid) {
        ProcStart::Started(s) => Some(s),
        _ => None,
    }
}

/// Count running CLI sessions via `lister`.
pub fn running_cli_sessions(lister: &dyn ProcessLister) -> Result<Vec<u32>> {
    Ok(cli_sessions(&lister.list()?, std::process::id()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Fixed process table.
    #[derive(Default)]
    pub struct FakeProcs(pub Vec<ProcInfo>, pub bool);

    impl ProcessLister for FakeProcs {
        fn list(&self) -> Result<Vec<ProcInfo>> {
            if self.1 {
                return Err(Error::ExternalTool {
                    program: "ps",
                    sub: "-axo",
                    code: Some(1),
                    class: ToolFailure::Other,
                });
            }
            Ok(self.0.clone())
        }
    }

    pub fn p(pid: u32, ppid: u32, comm: &str) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            comm: comm.into(),
        }
    }

    #[test]
    fn parses_ps_output() {
        let t = "    1     0 /sbin/launchd\n24339 30640 claude\n  77 1 /Applications/Claude.app/Contents/MacOS/Claude\nbad line\n";
        let v = parse_ps(t);
        assert_eq!(v.len(), 3);
        assert_eq!(v[1], p(24339, 30640, "claude"));
        assert_eq!(v[2].comm, "/Applications/Claude.app/Contents/MacOS/Claude");
    }

    #[test]
    fn counts_terminal_sessions_and_excludes_desktop() {
        let procs = vec![
            p(1, 0, "/sbin/launchd"),
            p(10, 1, "-zsh"),
            p(11, 10, "claude"),
            p(12, 10, "/opt/bin/claude.exe"),
            p(20, 1, "/Applications/Claude.app/Contents/MacOS/Claude"),
            p(
                21,
                20,
                "/Applications/Claude.app/Contents/Frameworks/Claude Helper",
            ),
            p(22, 21, "claude"),
            p(
                30,
                1,
                "/Users/me/Library/Application Support/Claude/claude-code/2.1.310/claude",
            ),
            p(40, 10, "claudette"),
            p(99, 10, "claude"),
        ];
        assert_eq!(cli_sessions(&procs, 99), vec![11, 12]);
    }

    #[test]
    fn parent_cycle_terminates() {
        let procs = vec![p(5, 6, "x"), p(6, 5, "y"), p(7, 5, "claude")];
        assert_eq!(cli_sessions(&procs, 0), vec![7]);
    }

    #[test]
    fn start_time_ignores_the_callers_locale() {
        let me = std::process::id();
        let writer = probe_start_with(me, &[("LC_TIME", "de_DE.UTF-8"), ("LANG", "de_DE.UTF-8")]);
        let reader = probe_start_with(me, &[("LC_ALL", "ja_JP.UTF-8"), ("LC_TIME", "fr_FR.UTF-8")]);
        assert!(matches!(writer, ProcStart::Started(_)), "{writer:?}");
        assert_eq!(writer, reader);
        assert_eq!(
            process_start(me),
            match writer {
                ProcStart::Started(s) => Some(s),
                _ => None,
            }
        );
    }

    #[test]
    fn a_finished_process_is_definitely_gone() {
        let mut c = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = c.id();
        c.wait().unwrap();
        assert_eq!(probe_start(pid), ProcStart::Gone);
    }

    #[test]
    fn real_ps_runs() {
        // Read-only: lists pids and executable names only.
        let v = PsLister.list().unwrap();
        assert!(v.iter().any(|p| p.pid == std::process::id()));
    }
}
