//! Add account: `cma login` runs in Terminal (it needs a TTY and a
//! browser), never inside the app.
//!
//! Each login gets its own directory `<CMA_HOME>/run/<nonce>/` (0700, created
//! exclusively), holding `login.command`, a script whose content is fixed
//! (no option or path is ever written into it: every path is relative to
//! the script itself), a `cma` symlink to the cma binary, and the options
//! as JSON in `login-args.json` (0600), which cma reads with `--args-file`.
//! Terminal opens the script; the app polls for the `login-status` file the
//! script writes when cma exits, then notifies and deletes that directory.
//! A script that outlives the app's wait, or an app restart, therefore never
//! touches another login's files.

use std::collections::BTreeSet;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use cma_core::fsutil;
use cma_core::paths::Paths;
use cma_core::registry::Registry;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};

use crate::commands::{AppState, Invalid, LoginOptions, after_change, error_doc, ok_doc, text};

/// Environment variable naming the cma binary to use (debug builds only;
/// a release app always uses the `cma` next to its own executable).
pub const DEV_BIN_ENV: &str = "CMA_DEV_BIN";
/// How often the login result is checked, and for how long.
const POLL_EVERY: Duration = Duration::from_secs(2);
const POLL_FOR: Duration = Duration::from_secs(10 * 60);
/// Login directories older than this are removed at startup (the app
/// stopped waiting for them long ago).
pub const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

/// Script for the default cma home.
pub const SCRIPT: &str = r#"#!/bin/sh
# Written by Claude Multi Auth to add an account. Its content never
# changes: paths are relative to this file, and cma reads the login
# options from login-args.json (not from this script).
dir=$(cd "$(dirname "$0")" && pwd -P) || exit 1
"$dir/cma" login --args-file "$dir/login-args.json"
code=$?
rm -f "$dir/login-args.json"
printf '%s\n' "$code" > "$dir/login-status"
echo
if [ "$code" -eq 0 ]; then
  echo "Done. You can close this window."
else
  echo "cma login did not finish (exit $code). You can close this window."
fi
exit "$code"
"#;

/// Script for a cma home set with `CMA_HOME` (development only): the same,
/// with `CMA_HOME` derived from the script's own location.
pub const SCRIPT_HOME_OVERRIDE: &str = r#"#!/bin/sh
# Written by Claude Multi Auth to add an account. Its content never
# changes: paths are relative to this file, and cma reads the login
# options from login-args.json (not from this script).
dir=$(cd "$(dirname "$0")" && pwd -P) || exit 1
CMA_HOME=$(cd "$dir/../.." && pwd -P) || exit 1
export CMA_HOME
CMA_ALLOW_HOME_OVERRIDE=1
export CMA_ALLOW_HOME_OVERRIDE
"$dir/cma" login --args-file "$dir/login-args.json"
code=$?
rm -f "$dir/login-args.json"
printf '%s\n' "$code" > "$dir/login-status"
echo
if [ "$code" -eq 0 ]; then
  echo "Done. You can close this window."
else
  echo "cma login did not finish (exit $code). You can close this window."
fi
exit "$code"
"#;

/// Validated login options.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoginArgs {
    pub email: Option<String>,
    pub alias: Option<String>,
    pub org: Option<String>,
    pub sso: bool,
    pub console: bool,
}

impl LoginArgs {
    pub fn validate(o: &LoginOptions) -> Result<Self, Invalid> {
        Ok(LoginArgs {
            email: text("email", o.email.as_deref(), 254)?,
            alias: text("alias", o.alias.as_deref(), crate::commands::ALIAS_MAX)?,
            org: text("organization", o.org.as_deref(), 128)?,
            sso: o.sso,
            console: o.console,
        })
    }

    /// The `--args-file` JSON.
    pub fn json(&self) -> Value {
        json!({
            "email": self.email,
            "alias": self.alias,
            "org": self.org,
            "sso": self.sso,
            "console": self.console,
        })
    }
}

/// The files of one Terminal login.
#[derive(Debug, Clone)]
pub struct RunFiles {
    pub dir: PathBuf,
    pub script: PathBuf,
    pub args: PathBuf,
    pub status: PathBuf,
    pub bin: PathBuf,
}

/// `<CMA_HOME>/run`, the parent of every login's directory.
pub fn run_root(paths: &Paths) -> PathBuf {
    paths.cma_home.join("run")
}

impl RunFiles {
    pub fn in_dir(dir: PathBuf) -> Self {
        RunFiles {
            script: dir.join("login.command"),
            args: dir.join("login-args.json"),
            status: dir.join("login-status"),
            bin: dir.join("cma"),
            dir,
        }
    }

    /// Delete this login's directory (and only it).
    pub fn clear(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A name no other login of this machine uses: time, process, counter.
fn nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!(
        "{t:x}-{:x}-{:x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

fn private_dir(dir: &Path, exclusive: bool) -> Result<(), Value> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if !exclusive && e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_doc("could not create", dir, e)),
    }
    cma_core::paths::verify_private_dir(dir).map_err(|e| error_doc(e.code(), e.to_string(), None))
}

fn io_doc(what: &str, p: &Path, e: impl std::fmt::Display) -> Value {
    error_doc("io", format!("{what} {}: {e}", p.display()), None)
}

/// The cma binary: in debug builds `CMA_DEV_BIN` when set, otherwise the
/// `cma` next to this executable (inside the bundle).
pub fn cma_binary() -> Result<PathBuf, Value> {
    let dev = if cfg!(debug_assertions) {
        std::env::var_os(DEV_BIN_ENV).filter(|v| !v.is_empty())
    } else {
        None
    };
    let candidate = match dev {
        Some(p) => PathBuf::from(p),
        None => std::env::current_exe()
            .map_err(|e| error_doc("not_found", format!("own executable: {e}"), None))?
            .with_file_name("cma"),
    };
    match std::fs::metadata(&candidate) {
        Ok(m) if m.is_file() => Ok(candidate),
        _ => Err(error_doc(
            "not_found",
            format!("the cma binary was not found at {}", candidate.display()),
            Some(
                "debug builds: build it (`cargo build -p cma`) and start the app with CMA_DEV_BIN=<repo>/target/debug/cma",
            ),
        )),
    }
}

/// Write the script, the options file and the `cma` link for a login, in
/// a new directory of its own.
pub fn prepare(paths: &Paths, args: &LoginArgs, bin: &Path) -> Result<RunFiles, Value> {
    paths
        .ensure_cma_home()
        .map_err(|e| error_doc(e.code(), e.to_string(), None))?;
    let root = run_root(paths);
    private_dir(&root, false)?;
    let f = RunFiles::in_dir(root.join(nonce()));
    private_dir(&f.dir, true)?;
    let script = if paths.home_overridden {
        SCRIPT_HOME_OVERRIDE
    } else {
        SCRIPT
    };
    let body = serde_json::to_vec(&args.json()).expect("serializable");
    let write = || -> Result<(), Value> {
        fsutil::atomic_write_mode(&f.args, &body, 0o600)
            .map_err(|e| io_doc("could not write", &f.args, e))?;
        std::os::unix::fs::symlink(bin, &f.bin).map_err(|e| io_doc("could not link", &f.bin, e))?;
        fsutil::atomic_write_mode(&f.script, script.as_bytes(), 0o700)
            .map_err(|e| io_doc("could not write", &f.script, e))
    };
    if let Err(e) = write() {
        f.clear();
        return Err(e);
    }
    Ok(f)
}

/// Which accounts and stored logins exist now (to tell what a login added).
fn snapshot(paths: &Paths) -> (BTreeSet<String>, BTreeSet<String>) {
    match Registry::load(&paths.registry_file()) {
        Ok(r) => (
            r.accounts.iter().map(|a| a.key.clone()).collect(),
            r.fingerprints.keys().cloned().collect(),
        ),
        Err(_) => Default::default(),
    }
}

/// What a finished login did, from the registry before and after.
pub fn describe(before: &(BTreeSet<String>, BTreeSet<String>), after: &Registry) -> String {
    let label = |key: &str| {
        after
            .account(key)
            .map(|a| {
                let base = if a.email.is_empty() {
                    a.key.clone()
                } else {
                    a.email.clone()
                };
                match &a.alias {
                    Some(al) => format!("{al} ({base})"),
                    None => base,
                }
            })
            .unwrap_or_else(|| key.to_string())
    };
    if let Some(a) = after.accounts.iter().find(|a| !before.0.contains(&a.key)) {
        return format!("Added {}.", label(&a.key));
    }
    if let Some(key) = after
        .fingerprints
        .iter()
        .find(|(fp, _)| !before.1.contains(*fp))
        .map(|(_, k)| k.clone())
    {
        return format!("Logged in again: {}.", label(&key));
    }
    "The login finished.".to_string()
}

/// Read the exit code the script recorded, once it exists.
fn read_status(p: &Path) -> Option<i32> {
    let b = fsutil::read_nofollow(p).ok()??;
    std::str::from_utf8(&b[..b.len().min(16)])
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Start a Terminal login and watch for its result in the background.
pub fn start(app: &AppHandle, args: LoginArgs) -> Value {
    let state = app.state::<AppState>();
    if crate::commands::quitting(&state) {
        return crate::commands::quitting_doc();
    }
    if state.login_in_progress.swap(true, Ordering::SeqCst) {
        return error_doc(
            "login_in_progress",
            "a login is already running in Terminal",
            Some("finish or close it first (the app stops waiting after 10 minutes)"),
        );
    }
    let started = (|| {
        let paths = Paths::from_system().map_err(|e| error_doc(e.code(), e.to_string(), None))?;
        let bin = cma_binary()?;
        let before = snapshot(&paths);
        let files = prepare(&paths, &args, &bin)?;
        open_in_terminal(app, &files.script).inspect_err(|_| files.clear())?;
        Ok::<_, Value>((paths, files, before))
    })();
    let (paths, files, before) = match started {
        Ok(x) => x,
        Err(d) => {
            state.login_in_progress.store(false, Ordering::SeqCst);
            return d;
        }
    };
    state.bump();
    let app2 = app.clone();
    let script = files.script.clone();
    std::thread::spawn(move || watch(&app2, &paths, &files, &before));
    ok_doc(json!({"script": script}))
}

fn open_in_terminal(app: &AppHandle, script: &Path) -> Result<(), Value> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(script.to_string_lossy(), Some("Terminal"))
        .map_err(|e| {
            error_doc(
                "external_tool",
                format!("could not open Terminal: {e}"),
                None,
            )
        })
}

fn watch(
    app: &AppHandle,
    paths: &Paths,
    files: &RunFiles,
    before: &(BTreeSet<String>, BTreeSet<String>),
) {
    let until = Instant::now() + POLL_FOR;
    let mut code = None;
    while Instant::now() < until {
        std::thread::sleep(POLL_EVERY);
        if let Some(c) = read_status(&files.status) {
            code = Some(c);
            break;
        }
    }
    files.clear();
    app.state::<AppState>()
        .login_in_progress
        .store(false, Ordering::SeqCst);
    let (title, body) = match code {
        Some(0) => (
            "Account added",
            Registry::load(&paths.registry_file())
                .map(|r| describe(before, &r))
                .unwrap_or_else(|_| "The login finished.".into()),
        ),
        Some(c) => (
            "Login did not finish",
            format!("cma login exited with {c}; the Terminal window says why."),
        ),
        None => (
            "Stopped waiting for the login",
            "No result after 10 minutes. If the login finishes later, the account still appears in the list.".to_string(),
        ),
    };
    crate::notify(app, title, &body);
    after_change(app);
}

/// Remove login directories a previous run left behind, once they are
/// older than `max_age` (a younger one may belong to a login still running
/// in Terminal, so it is left alone), plus the single-login files an
/// earlier version wrote directly into `run/`.
pub fn clear_stale(paths: &Paths, max_age: Duration) {
    let root = run_root(paths);
    for name in ["login.command", "login-args.json", "login-status", "cma"] {
        let _ = std::fs::remove_file(root.join(name));
    }
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(m) = std::fs::symlink_metadata(e.path()) else {
            continue;
        };
        let old = m
            .modified()
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= max_age);
        if m.is_dir() && old {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cma_core::paths::MapEnv;
    use std::os::unix::fs::PermissionsExt;

    fn paths(tmp: &Path, overridden: bool) -> Paths {
        let home = tmp.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let mut vars = vec![("HOME", home.to_str().unwrap().to_string())];
        if overridden {
            vars.push((
                "CMA_HOME",
                tmp.join("cma home").to_str().unwrap().to_string(),
            ));
            vars.push(("CMA_ALLOW_HOME_OVERRIDE", "1".into()));
        }
        Paths::from_env(&MapEnv::new(vars)).unwrap()
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    const HOSTILE: &str = "\"; rm -rf ~ $(touch pwned) `touch pwned2` '";

    #[test]
    fn options_go_only_into_a_private_json_file() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path(), false);
        let args = LoginArgs {
            email: Some("a@x.test".into()),
            alias: Some(HOSTILE.into()),
            org: None,
            sso: true,
            console: false,
        };
        let bin = d.path().join("cma-bin");
        std::fs::write(&bin, b"").unwrap();
        let f = prepare(&p, &args, &bin).unwrap();
        // The script is the fixed text, byte for byte.
        assert_eq!(std::fs::read_to_string(&f.script).unwrap(), SCRIPT);
        assert_eq!(mode(&f.script), 0o700);
        assert_eq!(mode(&f.args), 0o600);
        assert_eq!(mode(&f.dir), 0o700);
        let v: Value = serde_json::from_slice(&std::fs::read(&f.args).unwrap()).unwrap();
        assert_eq!(v["alias"], HOSTILE);
        assert_eq!(v["sso"], true);
        assert_eq!(std::fs::read_link(&f.bin).unwrap(), bin);
        assert_eq!(mode(&run_root(&p)), 0o700);
        assert_eq!(f.dir.parent().unwrap(), run_root(&p));
        f.clear();
        assert!(!f.dir.exists());
        assert!(
            run_root(&p).exists(),
            "only this login's directory is removed"
        );
    }

    #[test]
    fn a_cma_home_override_uses_the_other_fixed_script() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path(), true);
        let bin = d.path().join("cma-bin");
        std::fs::write(&bin, b"").unwrap();
        let f = prepare(&p, &LoginArgs::default(), &bin).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f.script).unwrap(),
            SCRIPT_HOME_OVERRIDE
        );
    }

    /// Run the real script with a stand-in `cma` that records what it got:
    /// the options never reach the shell, and the script records the exit
    /// code and deletes the options file.
    #[test]
    fn the_script_passes_only_the_args_file_and_records_the_result() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path(), true);
        let bin = d.path().join("fake-cma");
        std::fs::write(
            &bin,
            "#!/bin/sh\nout=\"$(dirname \"$0\")/../../seen\"\nprintf '%s\\n' \"$@\" > \"$out\"\nprintf '%s\\n' \"$CMA_HOME\" >> \"$out\"\ncat \"$3\" >> \"$out\"\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let args = LoginArgs {
            alias: Some(HOSTILE.into()),
            ..LoginArgs::default()
        };
        let f = prepare(&p, &args, &bin).unwrap();
        let out = std::process::Command::new(&f.script)
            .current_dir(d.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let seen = std::fs::read_to_string(p.cma_home.join("seen")).unwrap();
        let lines: Vec<&str> = seen.lines().collect();
        let run = std::fs::canonicalize(&f.dir).unwrap();
        assert_eq!(lines[0], "login");
        assert_eq!(lines[1], "--args-file");
        assert_eq!(lines[2], run.join("login-args.json").to_str().unwrap());
        assert_eq!(
            lines[3],
            std::fs::canonicalize(&p.cma_home)
                .unwrap()
                .to_str()
                .unwrap()
        );
        let v: Value = serde_json::from_str(lines[4]).unwrap();
        assert_eq!(v["alias"], HOSTILE);
        assert!(!d.path().join("pwned").exists());
        assert!(!d.path().join("pwned2").exists());
        assert_eq!(read_status(&f.status), Some(0));
        assert!(!f.args.exists(), "options file deleted");
    }

    fn fake_cma(dir: &Path) -> PathBuf {
        let bin = dir.join("fake-cma");
        std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        bin
    }

    fn run_script(f: &RunFiles) {
        let out = std::process::Command::new(&f.script)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    /// An earlier login's script that finishes while a newer login runs
    /// (it outlived the app's wait, or the app restarted) touches only its
    /// own directory: the newer login's options stay and its result is
    /// not written by the old one.
    #[test]
    fn overlapping_logins_never_touch_each_others_files() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path(), true);
        let bin = fake_cma(d.path());
        let old = prepare(&p, &LoginArgs::default(), &bin).unwrap();
        let new = prepare(
            &p,
            &LoginArgs {
                alias: Some("new".into()),
                ..LoginArgs::default()
            },
            &bin,
        )
        .unwrap();
        assert_ne!(old.dir, new.dir);
        run_script(&old);
        assert_eq!(read_status(&old.status), Some(0));
        assert!(!old.args.exists());
        assert!(new.args.exists(), "the newer login's options are intact");
        assert_eq!(
            read_status(&new.status),
            None,
            "no result for the newer login"
        );
        // A restart in the middle of the newer login leaves it alone.
        clear_stale(&p, STALE_AFTER);
        assert!(new.args.exists() && new.script.exists());
        // The app finishing with the old login removes only its directory.
        old.clear();
        assert!(new.script.exists());
        run_script(&new);
        assert_eq!(read_status(&new.status), Some(0));
    }

    #[test]
    fn old_login_directories_and_earlier_files_are_removed_at_startup() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path(), true);
        let bin = fake_cma(d.path());
        let f = prepare(&p, &LoginArgs::default(), &bin).unwrap();
        let flat = run_root(&p).join("login-args.json");
        std::fs::write(&flat, b"{}").unwrap();
        clear_stale(&p, STALE_AFTER);
        assert!(f.dir.exists(), "young: kept");
        assert!(!flat.exists(), "earlier single-login file: removed");
        clear_stale(&p, Duration::ZERO);
        assert!(!f.dir.exists(), "old: removed");
        assert!(run_root(&p).exists());
    }

    #[test]
    fn input_limits() {
        let o = LoginOptions {
            email: Some(" a@x.test ".into()),
            alias: Some("x".repeat(65)),
            ..LoginOptions::default()
        };
        assert!(LoginArgs::validate(&o).is_err());
        let o = LoginOptions {
            email: Some(" a@x.test ".into()),
            alias: Some(HOSTILE.into()),
            ..LoginOptions::default()
        };
        let a = LoginArgs::validate(&o).unwrap();
        assert_eq!(a.email.as_deref(), Some("a@x.test"));
        assert_eq!(a.alias.as_deref(), Some(HOSTILE.trim()));
    }

    #[test]
    fn a_finished_login_is_described_from_the_registry() {
        use cma_core::registry::Account;
        let before = (
            BTreeSet::from(["A::oA".to_string()]),
            BTreeSet::from(["fpA".to_string()]),
        );
        let mut r = Registry::default();
        r.accounts.push(Account {
            key: "A::oA".into(),
            email: "a@x.test".into(),
            ..Account::default()
        });
        r.fingerprints.insert("fpA".into(), "A::oA".into());
        assert_eq!(describe(&before, &r), "The login finished.");
        r.fingerprints.insert("fpA2".into(), "A::oA".into());
        assert_eq!(describe(&before, &r), "Logged in again: a@x.test.");
        r.accounts.push(Account {
            key: "B::oB".into(),
            email: "b@x.test".into(),
            alias: Some("work".into()),
            ..Account::default()
        });
        assert_eq!(describe(&before, &r), "Added work (b@x.test).");
    }
}
