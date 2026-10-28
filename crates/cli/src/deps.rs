//! What a command talks to: the Keychain, the network, the process list and
//! `claude auth login`. Real by default; the test backend
//! (`CMA_SECRET_BACKEND=fake`) exists only in builds with the
//! `test-backends` feature, and any other build refuses to start when the
//! variable is set, so a test can never fall through to the real Keychain.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cma_core::cli_target::{Ctx, system_now_ms};
use cma_core::desktop_app::{DesktopApp, SystemDesktopApp};
use cma_core::http::{HttpClient, HttpProfileClient, Request, ReqwestClient, Response};
use cma_core::lock::{ClaudeStorageLock, StorageGuard, StorageLockAcquirer};
use cma_core::login::{
    ClaudeLoginSpawner, ClaudeLoginSpawnerToStderr, DumpKeychainLister, ItemLister, LoginSpawner,
};
use cma_core::paths::{Env, Paths, SystemEnv};
use cma_core::procs::{ProcessLister, PsLister};
use cma_core::refresh::{NetCtx, client_id};
use cma_core::secret::{SecretStore, SecurityCliStore};

use crate::output::CliError;

/// Environment variable selecting a test backend.
pub const BACKEND_ENV: &str = "CMA_SECRET_BACKEND";

/// Everything a command needs.
pub struct Deps {
    pub env: Box<dyn Env>,
    pub paths: Paths,
    pub store: Box<dyn SecretStore + Sync>,
    pub lister: Box<dyn ItemLister>,
    pub locker: TimingLocker,
    pub http: Box<dyn HttpClient>,
    pub procs: Box<dyn ProcessLister>,
    /// Claude Desktop control (quit, launch, running).
    pub desktop: Box<dyn DesktopApp>,
    spawner: Box<dyn LoginSpawner>,
    spawner_json: Box<dyn LoginSpawner>,
}

impl Deps {
    pub fn from_env() -> Result<Self, CliError> {
        Self::with_env(Box::new(SystemEnv))
    }

    /// Like [`Deps::from_env`], with the environment given (the embedded
    /// entry point's tests pass a fixed one; the process environment cannot
    /// be changed safely).
    pub fn with_env(env: Box<dyn Env>) -> Result<Self, CliError> {
        let paths = Paths::from_env(env.as_ref())?;
        let locker = TimingLocker::new(Box::new(ClaudeStorageLock::for_paths(&paths)));
        let desktop_dir = paths.desktop_dir.clone();
        match env.var(BACKEND_ENV).as_deref() {
            None | Some("") => Ok(Deps {
                env,
                paths,
                store: Box::new(SecurityCliStore::new()),
                lister: Box::new(DumpKeychainLister),
                locker,
                http: Box::new(LazyHttp::default()),
                procs: Box::new(PsLister),
                desktop: Box::new(SystemDesktopApp { desktop_dir }),
                spawner: Box::new(ClaudeLoginSpawner),
                spawner_json: Box::new(ClaudeLoginSpawnerToStderr),
            }),
            Some(name) => test_backend(name, env, paths, locker),
        }
    }

    /// The login spawner; in `--json` mode the child's stdout goes to
    /// stderr so stdout carries only the JSON document.
    pub fn spawner(&self, json: bool) -> &dyn LoginSpawner {
        if json {
            self.spawner_json.as_ref()
        } else {
            self.spawner.as_ref()
        }
    }

    pub fn profile(&self) -> HttpProfileClient<'_> {
        HttpProfileClient(self.http.as_ref())
    }

    pub fn ctx<'a>(&'a self, profile: &'a HttpProfileClient<'a>) -> Ctx<'a> {
        Ctx {
            paths: &self.paths,
            env: self.env.as_ref(),
            store: self.store.as_ref(),
            locker: &self.locker,
            profile,
            procs: self.procs.as_ref(),
            now_ms: system_now_ms,
        }
    }

    pub fn net(&self) -> NetCtx<'_> {
        NetCtx {
            paths: &self.paths,
            store: self.store.as_ref(),
            http: self.http.as_ref(),
            client_id: client_id(self.env.as_ref()),
            now_ms: system_now_ms,
        }
    }
}

#[cfg(feature = "test-backends")]
fn test_backend(
    name: &str,
    env: Box<dyn Env>,
    paths: Paths,
    locker: TimingLocker,
) -> Result<Deps, CliError> {
    if name != "fake" {
        return Err(CliError::new(
            "invalid",
            format!("unknown {BACKEND_ENV} value {name:?} (only \"fake\")"),
        ));
    }
    // The fake backend only ever runs against a throwaway cma home.
    if !paths.home_overridden {
        return Err(CliError::new(
            "invalid",
            format!("{BACKEND_ENV}=fake needs CMA_HOME with CMA_ALLOW_HOME_OVERRIDE=1"),
        ));
    }
    // ... and never against the real Claude Code state: HOME and every
    // Claude Code directory must lie outside the user's real home, taken
    // from the password database (not from HOME).
    crate::testbackend::check_isolated(&paths)?;
    let dir = env
        .var(crate::testbackend::DIR_ENV)
        .filter(|d| !d.is_empty())
        .ok_or_else(|| {
            CliError::new(
                "invalid",
                format!("{BACKEND_ENV}=fake needs {}", crate::testbackend::DIR_ENV),
            )
        })?;
    let dir = std::path::PathBuf::from(dir);
    use crate::testbackend as tb;
    let desktop = Box::new(tb::FakeDesktop::new(&dir, &paths.desktop_dir));
    Ok(Deps {
        env,
        paths,
        store: Box::new(tb::FileStore::new(&dir)),
        lister: Box::new(tb::FileStore::new(&dir)),
        locker,
        http: Box::new(tb::FakeHttp::new(&dir)),
        procs: Box::new(tb::FileProcs::new(&dir)),
        desktop,
        spawner: Box::new(tb::FakeLogin::new(&dir)),
        spawner_json: Box::new(tb::FakeLogin::new(&dir)),
    })
}

#[cfg(not(feature = "test-backends"))]
fn test_backend(
    name: &str,
    _env: Box<dyn Env>,
    _paths: Paths,
    _locker: TimingLocker,
) -> Result<Deps, CliError> {
    Err(CliError::new(
        "invalid",
        format!(
            "{BACKEND_ENV}={name:?} is set, but this build has no test backends; unset it to use the real Keychain"
        ),
    ))
}

/// The real HTTP client, created on first use (most commands never touch
/// the network).
#[derive(Default)]
pub struct LazyHttp(Mutex<Option<Arc<ReqwestClient>>>);

impl HttpClient for LazyHttp {
    fn send(&self, req: &Request<'_>) -> cma_core::Result<Response> {
        let client = {
            let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
            match g.as_ref() {
                Some(c) => c.clone(),
                None => {
                    let c = Arc::new(ReqwestClient::new()?);
                    *g = Some(c.clone());
                    c
                }
            }
        };
        client.send(req)
    }
}

/// Wraps the `.storage-write` acquirer and records how long each hold
/// lasted, so a switch can report it (a Keychain prompt while the lock is
/// held would show as a long hold).
pub struct TimingLocker {
    inner: Box<dyn StorageLockAcquirer>,
    holds: Arc<Mutex<Vec<Duration>>>,
}

impl TimingLocker {
    pub fn new(inner: Box<dyn StorageLockAcquirer>) -> Self {
        TimingLocker {
            inner,
            holds: Arc::default(),
        }
    }

    /// The longest hold so far.
    pub fn max_hold(&self) -> Option<Duration> {
        self.holds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .max()
            .copied()
    }
}

impl StorageLockAcquirer for TimingLocker {
    fn acquire(&self) -> cma_core::Result<Box<dyn StorageGuard>> {
        let inner = self.inner.acquire()?;
        Ok(Box::new(TimedGuard {
            inner,
            since: Instant::now(),
            holds: self.holds.clone(),
        }))
    }
}

#[derive(Debug)]
struct TimedGuard {
    inner: Box<dyn StorageGuard>,
    since: Instant,
    holds: Arc<Mutex<Vec<Duration>>>,
}

impl StorageGuard for TimedGuard {
    fn is_compromised(&self) -> bool {
        self.inner.is_compromised()
    }
}

impl Drop for TimedGuard {
    fn drop(&mut self) {
        self.holds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(self.since.elapsed());
    }
}
