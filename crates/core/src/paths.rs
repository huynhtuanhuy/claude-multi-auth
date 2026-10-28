//! Filesystem locations used by cma and by Claude.
//!
//! The environment is injected through [`Env`] so tests never mutate the
//! process environment (that is `unsafe` in edition 2024, which the workspace
//! forbids).

use std::collections::HashMap;
use std::fs::DirBuilder;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// Directory name of cma's home under `$HOME`.
pub const CMA_DIR_NAME: &str = ".claude-multi-auth";

/// Environment variable lookup.
pub trait Env {
    fn var(&self, key: &str) -> Option<String>;
}

/// The real process environment.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnv;

impl Env for SystemEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// A fixed environment, for tests.
#[derive(Debug, Default, Clone)]
pub struct MapEnv(pub HashMap<String, String>);

impl MapEnv {
    pub fn new<I, K, V>(vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        MapEnv(
            vars.into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

impl Env for MapEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The user's home directory (`$HOME`).
    pub home: PathBuf,
    /// cma's own state directory.
    pub cma_home: PathBuf,
    /// True when `CMA_HOME` was honoured (`CMA_ALLOW_HOME_OVERRIDE=1`).
    pub home_overridden: bool,
    /// Claude Code config dir: `CLAUDE_CONFIG_DIR` or `~/.claude`.
    pub claude_config_dir: PathBuf,
    /// The raw `CLAUDE_CONFIG_DIR` string when the user set one.
    pub claude_config_dir_env: Option<String>,
    /// `~/.claude.json`, or `<CLAUDE_CONFIG_DIR>/.claude.json`.
    pub claude_json: PathBuf,
    /// Directory holding Claude Code's `.storage-write` lock.
    pub secure_storage_dir: PathBuf,
    /// Claude Desktop's data directory.
    pub desktop_dir: PathBuf,
}

impl Paths {
    /// Resolve every path from the process environment.
    pub fn from_system() -> Result<Self> {
        Self::from_env(&SystemEnv)
    }

    pub fn from_env(env: &dyn Env) -> Result<Self> {
        let home = match env.var("HOME").filter(|h| !h.is_empty()) {
            Some(h) => PathBuf::from(h),
            None => dirs::home_dir().ok_or_else(|| Error::NotFound("home directory".into()))?,
        };
        let allow_override = env.var("CMA_ALLOW_HOME_OVERRIDE").as_deref() == Some("1");
        let (cma_home, home_overridden) = match env.var("CMA_HOME").filter(|h| !h.is_empty()) {
            Some(h) if allow_override => (PathBuf::from(h), true),
            _ => (home.join(CMA_DIR_NAME), false),
        };
        let default_cfg = home.join(".claude");
        let claude_config_dir_env = env.var("CLAUDE_CONFIG_DIR").filter(|c| !c.is_empty());
        let (claude_config_dir, claude_json) = match &claude_config_dir_env {
            Some(c) => (PathBuf::from(c), PathBuf::from(c).join(".claude.json")),
            None => (default_cfg.clone(), home.join(".claude.json")),
        };
        // Claude Code 2.1.310: CLAUDE_SECURESTORAGE_CONFIG_DIR if set (an empty
        // string means ~/.claude), otherwise the config dir. The binary also
        // NFC-normalizes the string; APFS lookups are normalization-insensitive,
        // so the lock directory is the same either way.
        let secure_storage_dir = match env.var("CLAUDE_SECURESTORAGE_CONFIG_DIR") {
            Some(s) if s.is_empty() => default_cfg,
            Some(s) => PathBuf::from(s),
            None => claude_config_dir.clone(),
        };
        let desktop_dir = home.join("Library/Application Support/Claude");
        Ok(Paths {
            home,
            cma_home,
            home_overridden,
            claude_config_dir,
            claude_config_dir_env,
            claude_json,
            secure_storage_dir,
            desktop_dir,
        })
    }

    pub fn registry_file(&self) -> PathBuf {
        self.cma_home.join("registry.json")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.cma_home.join(".lock")
    }

    pub fn journal_file(&self) -> PathBuf {
        self.cma_home.join("op.journal")
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.cma_home.join("backups")
    }

    /// Create cma's home (0700) if missing, then verify it is a real
    /// directory owned by the current user with mode 0700. Returns warnings.
    pub fn ensure_cma_home(&self) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        match std::fs::symlink_metadata(&self.cma_home) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(0o700)
                    .create(&self.cma_home)
                    .map_err(|e| Error::io(&self.cma_home, e))?;
            }
            Err(e) => return Err(Error::io(&self.cma_home, e)),
        }
        verify_private_dir(&self.cma_home)?;
        // Retried on every run until it succeeds once; the marker records
        // success so `tmutil` is not spawned each time.
        if !self.home_overridden && !self.tm_marker().exists() {
            if exclude_from_time_machine(&self.cma_home) {
                let _ = crate::fsutil::atomic_write_mode(&self.tm_marker(), b"", 0o600);
            } else {
                warnings.push(format!(
                    "could not exclude {} from Time Machine",
                    self.cma_home.display()
                ));
            }
        }
        Ok(warnings)
    }

    /// Marker written once the Time Machine exclusion succeeded.
    fn tm_marker(&self) -> PathBuf {
        self.cma_home.join(TM_EXCLUDED_MARKER)
    }
}

/// File in `CMA_HOME` recording a successful Time Machine exclusion.
pub const TM_EXCLUDED_MARKER: &str = ".tm-excluded";

/// Refuse a directory that is a symlink, not a directory, not owned by the
/// current user, or not mode 0700.
pub fn verify_private_dir(path: &Path) -> Result<()> {
    let unsafe_home = |reason: String| Error::UnsafeHome {
        path: path.to_path_buf(),
        reason,
    };
    let meta = std::fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    if meta.file_type().is_symlink() {
        return Err(unsafe_home("is a symlink".into()));
    }
    if !meta.is_dir() {
        return Err(unsafe_home("is not a directory".into()));
    }
    let uid = rustix::process::getuid().as_raw();
    if meta.uid() != uid {
        return Err(unsafe_home(format!(
            "owned by uid {}, not {}",
            meta.uid(),
            uid
        )));
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o700 {
        return Err(unsafe_home(format!("mode is {mode:o}, expected 700")));
    }
    Ok(())
}

fn exclude_from_time_machine(path: &Path) -> bool {
    Command::new("/usr/bin/tmutil")
        .arg("addexclusion")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn env_for(home: &Path, extra: &[(&str, &str)]) -> MapEnv {
        let mut m = MapEnv::new([("HOME", home.to_str().unwrap())]);
        for (k, v) in extra {
            m.0.insert((*k).into(), (*v).into());
        }
        m
    }

    #[test]
    fn cma_home_override_requires_allow_flag() {
        let t = tempfile::tempdir().unwrap();
        let p = Paths::from_env(&env_for(t.path(), &[("CMA_HOME", "/x/y")])).unwrap();
        assert_eq!(p.cma_home, t.path().join(CMA_DIR_NAME));
        assert!(!p.home_overridden);
        let p = Paths::from_env(&env_for(
            t.path(),
            &[("CMA_HOME", "/x/y"), ("CMA_ALLOW_HOME_OVERRIDE", "1")],
        ))
        .unwrap();
        assert_eq!(p.cma_home, PathBuf::from("/x/y"));
        assert!(p.home_overridden);
    }

    #[test]
    fn claude_paths_follow_config_dir() {
        let t = tempfile::tempdir().unwrap();
        let p = Paths::from_env(&env_for(t.path(), &[])).unwrap();
        assert_eq!(p.claude_config_dir, t.path().join(".claude"));
        assert_eq!(p.claude_json, t.path().join(".claude.json"));
        assert_eq!(p.secure_storage_dir, t.path().join(".claude"));
        assert_eq!(
            p.desktop_dir,
            t.path().join("Library/Application Support/Claude")
        );

        let p = Paths::from_env(&env_for(t.path(), &[("CLAUDE_CONFIG_DIR", "/cfg/x/")])).unwrap();
        assert_eq!(p.claude_config_dir_env.as_deref(), Some("/cfg/x/"));
        assert_eq!(p.claude_json, PathBuf::from("/cfg/x/.claude.json"));
        assert_eq!(p.secure_storage_dir, PathBuf::from("/cfg/x/"));
    }

    #[test]
    fn secure_storage_dir_rule() {
        let t = tempfile::tempdir().unwrap();
        let p = Paths::from_env(&env_for(
            t.path(),
            &[
                ("CLAUDE_CONFIG_DIR", "/cfg"),
                ("CLAUDE_SECURESTORAGE_CONFIG_DIR", "/sec"),
            ],
        ))
        .unwrap();
        assert_eq!(p.secure_storage_dir, PathBuf::from("/sec"));
        let p = Paths::from_env(&env_for(
            t.path(),
            &[
                ("CLAUDE_CONFIG_DIR", "/cfg"),
                ("CLAUDE_SECURESTORAGE_CONFIG_DIR", ""),
            ],
        ))
        .unwrap();
        assert_eq!(p.secure_storage_dir, t.path().join(".claude"));
    }

    fn overridden(t: &Path, home: &Path) -> Paths {
        Paths::from_env(&env_for(
            t,
            &[
                ("CMA_HOME", home.to_str().unwrap()),
                ("CMA_ALLOW_HOME_OVERRIDE", "1"),
            ],
        ))
        .unwrap()
    }

    #[test]
    fn ensure_creates_0700_and_accepts_it() {
        let t = tempfile::tempdir().unwrap();
        let p = overridden(t.path(), &t.path().join("cma"));
        p.ensure_cma_home().unwrap();
        let mode = std::fs::metadata(&p.cma_home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        p.ensure_cma_home().unwrap();
    }

    #[test]
    fn symlinked_cma_home_rejected() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        DirBuilder::new().mode(0o700).create(&real).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let p = overridden(t.path(), &link);
        match p.ensure_cma_home() {
            Err(Error::UnsafeHome { reason, .. }) => assert!(reason.contains("symlink")),
            other => panic!("expected UnsafeHome, got {other:?}"),
        }
    }

    #[test]
    fn open_mode_cma_home_rejected() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("open");
        DirBuilder::new().mode(0o755).create(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = overridden(t.path(), &dir);
        assert!(matches!(p.ensure_cma_home(), Err(Error::UnsafeHome { .. })));
    }

    #[test]
    fn file_as_cma_home_rejected() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("file");
        std::fs::write(&f, b"x").unwrap();
        let p = overridden(t.path(), &f);
        assert!(matches!(p.ensure_cma_home(), Err(Error::UnsafeHome { .. })));
    }
}
