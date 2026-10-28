//! Test backend (feature `test-backends`, `CMA_SECRET_BACKEND=fake`): every
//! external effect is redirected into files under `CMA_FAKE_DIR`, so the
//! integration tests drive the real binary without the Keychain, the
//! network, `ps` or `claude`. Tests put dummy data only in these files.
//!
//! - `secrets.json`: `[{"service","account","value"}]`, the fake Keychain;
//! - `profiles.json`: access token → `/api/oauth/profile` body;
//! - `usage.json`: access token → `/api/oauth/usage` body;
//! - `token.json`: refresh token → token endpoint 200 body (else 400
//!   `invalid_grant`);
//! - `requests.log`: one line per request, the endpoint name only;
//! - `ps.txt`: `pid ppid comm` lines for the process list;
//! - `login.json`: the `claudeAiOauth` object the next fake `claude auth
//!   login` writes into its isolated item (absent: the login exits 1);
//! - `desktop.log`: one line per fake Claude Desktop `quit` / `launch`.
//!   Quit removes the Desktop processes from `ps.txt`, launch adds one;
//! - `desktop-signin.json`: `{"config": {..}, "files": {"rel": "text"}}`,
//!   what the next fake launch writes into the (temporary) Desktop dir, as
//!   if the user signed in there (then the file is removed).

#[cfg(not(debug_assertions))]
compile_error!("the test-backends feature is for debug test builds only");

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cma_core::cli_target::{keychain_account, service_for_dir};
use cma_core::http::{HttpClient, PROFILE_URL, Request, Response};
use cma_core::login::{ItemLister, LoginCommand, LoginExit, LoginSpawner};
use cma_core::paths::{Paths, SystemEnv};
use cma_core::procs::{ProcInfo, ProcessLister, parse_ps};
use cma_core::refresh::TOKEN_URL;
use cma_core::secret::{Secret, SecretStore};
use cma_core::usage::USAGE_URL;
use cma_core::{Error, Result};
use serde_json::{Value, json};

use crate::output::CliError;

/// Directory holding the fake backend's files.
pub const DIR_ENV: &str = "CMA_FAKE_DIR";

/// The fake backend refuses to run unless `HOME`, the Claude Code config
/// dir and its secure-storage dir all lie outside the real home directory
/// (from the password database, never from `HOME`): otherwise it would
/// rewrite the real `~/.claude.json` and take the real `.storage-write`
/// lock. A lookup failure refuses too.
pub fn check_isolated(paths: &Paths) -> std::result::Result<(), CliError> {
    let real = nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|u| u.dir)
        .ok_or_else(|| {
            CliError::new(
                "invalid",
                "CMA_SECRET_BACKEND=fake: could not look up the real home directory, so isolation cannot be checked",
            )
        })?;
    check_isolated_from(paths, &real)
}

pub fn check_isolated_from(paths: &Paths, real_home: &Path) -> std::result::Result<(), CliError> {
    let real = canonical(real_home);
    for (what, p) in [
        ("HOME", &paths.home),
        (
            "the Claude Code config dir (CLAUDE_CONFIG_DIR)",
            &paths.claude_config_dir,
        ),
        ("~/.claude.json", &paths.claude_json),
        (
            "the Claude Code secure-storage dir (CLAUDE_SECURESTORAGE_CONFIG_DIR)",
            &paths.secure_storage_dir,
        ),
    ] {
        if canonical(p).starts_with(&real) {
            return Err(CliError::new(
                "invalid",
                format!(
                    "CMA_SECRET_BACKEND=fake refuses to run: {what} is inside the real home directory; point HOME, CLAUDE_CONFIG_DIR and CLAUDE_SECURESTORAGE_CONFIG_DIR at a temporary directory"
                ),
            ));
        }
    }
    Ok(())
}

/// `p` with symlinks resolved as far as it exists (the rest appended), so
/// `/var/...` and `/private/var/...` compare equal.
fn canonical(p: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(c) = std::fs::canonicalize(&cur) {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return out;
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                cur = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// Serializes read-modify-write of `secrets.json` within this process
/// (usage fetches run on several threads).
static STORE_MUTEX: Mutex<()> = Mutex::new(());

fn io_err(path: &Path, e: std::io::Error) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        kind: e.kind(),
    }
}

fn read_json(path: &Path) -> Result<Option<Value>> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| Error::Json {
                what: "fake backend file",
                line: e.line(),
                column: e.column(),
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path, e)),
    }
}

/// The fake Keychain.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(dir: &Path) -> Self {
        FileStore {
            path: dir.join("secrets.json"),
        }
    }

    fn load(&self) -> Result<Vec<(String, String, String)>> {
        let Some(v) = read_json(&self.path)? else {
            return Ok(Vec::new());
        };
        let s = |x: &Value, k: &str| x.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .map(|x| (s(x, "service"), s(x, "account"), s(x, "value")))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn save(&self, items: &[(String, String, String)]) -> Result<()> {
        let v: Vec<Value> = items
            .iter()
            .map(|(s, a, v)| json!({"service": s, "account": a, "value": v}))
            .collect();
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&v).expect("serializable"))
            .map_err(|e| io_err(&tmp, e))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| io_err(&self.path, e))
    }
}

impl SecretStore for FileStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>> {
        let _g = STORE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self
            .load()?
            .into_iter()
            .find(|(s, a, _)| s == service && a == account)
            .map(|(_, _, v)| Secret::new(v.into_bytes())))
    }

    fn set(&self, service: &str, account: &str, value: &Secret) -> Result<()> {
        let _g = STORE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let mut items = self.load()?;
        items.retain(|(s, a, _)| !(s == service && a == account));
        items.push((
            service.into(),
            account.into(),
            String::from_utf8_lossy(value.expose()).into_owned(),
        ));
        self.save(&items)
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool> {
        let _g = STORE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let mut items = self.load()?;
        let n = items.len();
        items.retain(|(s, a, _)| !(s == service && a == account));
        let deleted = items.len() != n;
        if deleted {
            self.save(&items)?;
        }
        Ok(deleted)
    }
}

impl ItemLister for FileStore {
    fn list(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let _g = STORE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<(String, String)> = self
            .load()?
            .into_iter()
            .filter(|(s, _, _)| s.starts_with(prefix))
            .map(|(s, a, _)| (s, a))
            .collect();
        v.sort();
        Ok(v)
    }
}

/// Fake profile, usage and token endpoints.
pub struct FakeHttp {
    dir: PathBuf,
}

impl FakeHttp {
    pub fn new(dir: &Path) -> Self {
        FakeHttp { dir: dir.into() }
    }

    fn log(&self, what: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("requests.log"))
        {
            let _ = writeln!(f, "{what}");
        }
    }

    fn lookup(&self, file: &str, key: &str) -> Result<Option<Value>> {
        Ok(read_json(&self.dir.join(file))?.and_then(|v| v.get(key).cloned()))
    }
}

fn resp(status: u16, body: &Value) -> Result<Response> {
    Ok(Response {
        status,
        body: Secret::new(serde_json::to_vec(body).expect("serializable")),
    })
}

impl HttpClient for FakeHttp {
    fn send(&self, req: &Request<'_>) -> Result<Response> {
        self.log(req.what);
        let bearer = req
            .bearer
            .map(|b| String::from_utf8_lossy(b.expose()).into_owned())
            .unwrap_or_default();
        let found = if req.url == PROFILE_URL {
            self.lookup("profiles.json", &bearer)?
        } else if req.url == USAGE_URL {
            self.lookup("usage.json", &bearer)?
        } else if req.url == TOKEN_URL {
            let rt = req
                .json
                .and_then(|j| serde_json::from_slice::<Value>(j.expose()).ok())
                .and_then(|v| {
                    v.get("refresh_token")
                        .and_then(Value::as_str)
                        .map(String::from)
                })
                .unwrap_or_default();
            match self.lookup("token.json", &rt)? {
                Some(v) => Some(v),
                None => return resp(400, &json!({"error": "invalid_grant"})),
            }
        } else {
            None
        };
        match found {
            Some(v) => resp(200, &v),
            None => resp(401, &json!({"error": "unauthorized"})),
        }
    }
}

/// Fake process list from `ps.txt`.
pub struct FileProcs {
    path: PathBuf,
}

impl FileProcs {
    pub fn new(dir: &Path) -> Self {
        FileProcs {
            path: dir.join("ps.txt"),
        }
    }
}

impl ProcessLister for FileProcs {
    fn list(&self) -> Result<Vec<ProcInfo>> {
        match std::fs::read_to_string(&self.path) {
            Ok(t) => Ok(parse_ps(&t)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(io_err(&self.path, e)),
        }
    }
}

/// Fake Claude Desktop control over `ps.txt` and the temp Desktop dir.
pub struct FakeDesktop {
    dir: PathBuf,
    desktop_dir: PathBuf,
}

impl FakeDesktop {
    pub fn new(dir: &Path, desktop_dir: &Path) -> Self {
        FakeDesktop {
            dir: dir.into(),
            desktop_dir: desktop_dir.into(),
        }
    }

    fn log(&self, what: &str) -> Result<()> {
        let p = self.dir.join("desktop.log");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .map_err(|e| io_err(&p, e))?;
        writeln!(f, "{what}").map_err(|e| io_err(&p, e))
    }

    fn ps_lines(&self) -> Result<Vec<String>> {
        let p = self.dir.join("ps.txt");
        match std::fs::read_to_string(&p) {
            Ok(t) => Ok(t.lines().map(str::to_string).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(io_err(&p, e)),
        }
    }

    fn write_ps(&self, lines: &[String]) -> Result<()> {
        let p = self.dir.join("ps.txt");
        let mut t = lines.join("\n");
        t.push('\n');
        std::fs::write(&p, t).map_err(|e| io_err(&p, e))
    }
}

impl cma_core::desktop_app::DesktopApp for FakeDesktop {
    fn running(&self) -> Result<Vec<ProcInfo>> {
        Ok(cma_core::desktop_app::desktop_processes(
            &FileProcs::new(&self.dir).list()?,
            &self.desktop_dir,
        ))
    }

    fn quit(&self) -> Result<()> {
        self.log("quit")?;
        let keep: Vec<String> = self
            .ps_lines()?
            .into_iter()
            .filter(|l| {
                parse_ps(l).first().is_none_or(|p| {
                    !cma_core::desktop_app::is_desktop_process(&p.comm, &self.desktop_dir)
                })
            })
            .collect();
        self.write_ps(&keep)
    }

    fn launch(&self) -> Result<()> {
        self.log("launch")?;
        let signin = self.dir.join("desktop-signin.json");
        if let Some(v) = read_json(&signin)? {
            let cfg_path = self.desktop_dir.join("config.json");
            let mut cfg: Value = read_json(&cfg_path)?.unwrap_or_else(|| json!({}));
            if let (Some(o), Some(add)) = (cfg.as_object_mut(), v["config"].as_object()) {
                for (k, val) in add {
                    o.insert(k.clone(), val.clone());
                }
            }
            std::fs::write(
                &cfg_path,
                serde_json::to_vec_pretty(&cfg).unwrap_or_default(),
            )
            .map_err(|e| io_err(&cfg_path, e))?;
            if let Some(files) = v["files"].as_object() {
                for (rel, text) in files {
                    let p = self.desktop_dir.join(rel);
                    if let Some(parent) = p.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
                    }
                    std::fs::write(&p, text.as_str().unwrap_or_default())
                        .map_err(|e| io_err(&p, e))?;
                }
            }
            std::fs::remove_file(&signin).map_err(|e| io_err(&signin, e))?;
        }
        let mut lines = self.ps_lines()?;
        lines.push("9001 1 /Applications/Claude.app/Contents/MacOS/Claude".into());
        self.write_ps(&lines)
    }

    fn pause(&self, _: std::time::Duration) {}
}

/// Fake `claude auth login`: writes `login.json` into the isolated item.
pub struct FakeLogin {
    dir: PathBuf,
}

impl FakeLogin {
    pub fn new(dir: &Path) -> Self {
        FakeLogin { dir: dir.into() }
    }
}

impl LoginSpawner for FakeLogin {
    fn run(&self, cmd: &LoginCommand) -> Result<LoginExit> {
        let Some(cred) = read_json(&self.dir.join("login.json"))? else {
            return Ok(LoginExit {
                code: Some(1),
                interrupted: false,
            });
        };
        let cfg = cmd
            .env
            .iter()
            .find(|(k, _)| k == "CLAUDE_CONFIG_DIR")
            .map(|(_, v)| v.clone())
            .ok_or_else(|| Error::NotFound("CLAUDE_CONFIG_DIR in the login env".into()))?;
        let item = json!({ "claudeAiOauth": cred });
        FileStore::new(&self.dir).set(
            &service_for_dir(&cfg)?,
            &keychain_account(&SystemEnv),
            &Secret::new(serde_json::to_vec(&item).expect("serializable")),
        )?;
        Ok(LoginExit {
            code: Some(0),
            interrupted: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cma_core::paths::MapEnv;

    fn paths(vars: &[(&str, &str)]) -> Paths {
        Paths::from_env(&MapEnv::new(vars.iter().copied())).unwrap()
    }

    #[test]
    fn isolation_requires_every_claude_path_outside_the_real_home() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        let tmp = t.path().join("tmp");
        std::fs::create_dir_all(real.join(".claude")).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        let (r, h) = (real.to_str().unwrap(), tmp.to_str().unwrap());
        let inside = real.join(".claude");
        let inside = inside.to_str().unwrap();
        assert!(check_isolated_from(&paths(&[("HOME", h)]), &real).is_ok());
        let e = check_isolated_from(&paths(&[("HOME", r)]), &real).unwrap_err();
        assert!(e.message.contains("HOME"), "{}", e.message);
        let e = check_isolated_from(&paths(&[("HOME", h), ("CLAUDE_CONFIG_DIR", inside)]), &real)
            .unwrap_err();
        assert!(e.message.contains("CLAUDE_CONFIG_DIR"), "{}", e.message);
        let e = check_isolated_from(
            &paths(&[("HOME", h), ("CLAUDE_SECURESTORAGE_CONFIG_DIR", inside)]),
            &real,
        )
        .unwrap_err();
        assert!(
            e.message.contains("CLAUDE_SECURESTORAGE_CONFIG_DIR"),
            "{}",
            e.message
        );
        // A path that does not exist yet, reached through a symlink.
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let via = link.join("not-yet");
        assert!(check_isolated_from(&paths(&[("HOME", via.to_str().unwrap())]), &real).is_err());
    }
}
