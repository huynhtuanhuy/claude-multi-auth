//! Minimal [`ProfileClient`] used by the developer harness: runs
//! `/usr/bin/curl` with its whole configuration (URL, headers, the bearer
//! token) on stdin via `--config -`, so the token never reaches argv.
//!
//! curl is isolated from the user's setup:
//! - argv is exactly `-q --config -`. `-q` must be first: it stops curl from
//!   reading `~/.curlrc` (`$CURL_HOME`, `$XDG_CONFIG_HOME`), whose
//!   `trace-ascii`, `location-trusted`, `proxy` or `libcurl` lines could
//!   otherwise write or send the bearer token somewhere;
//! - the environment is cleared and only [`CURL_ENV_PASSTHROUGH`] is passed
//!   (so `ALL_PROXY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `HOME`, … do not
//!   apply; HTTPS proxies keep working);
//! - the config pins HTTPS (`proto`, `proto-redir`), refuses redirects
//!   (`max-redirs = 0`) and times out after 5 s.
//!
//! Nothing is logged; stderr is only classified, and the response is only
//! parsed for the profile fields.

use std::ffi::OsString;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{Error, Result, ToolFailure};
use crate::identity::{Profile, ProfileClient, parse_profile};
use crate::paths::Env;
use crate::secret::{CmdOutput, Secret, run_process};

pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
pub const OAUTH_BETA: &str = "oauth-2025-04-20";
const CURL: &str = "/usr/bin/curl";
/// The complete curl argv. `-q` (ignore `.curlrc`) only works as the first
/// argument.
pub const CURL_ARGS: [&str; 3] = ["-q", "--config", "-"];
/// The only environment variables curl gets.
pub const CURL_ENV_PASSTHROUGH: [&str; 5] =
    ["PATH", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"];

/// Runs curl with a cleared environment plus exactly `env`. Injected so
/// tests can check argv and env without spawning.
pub trait CurlRunner {
    fn run(
        &self,
        program: &Path,
        args: &[OsString],
        env: &[(OsString, OsString)],
        stdin: &[u8],
    ) -> std::io::Result<CmdOutput>;
}

/// Spawns the real process with `env_clear()` and the given variables.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClearedEnvRunner;

impl CurlRunner for ClearedEnvRunner {
    fn run(
        &self,
        program: &Path,
        args: &[OsString],
        env: &[(OsString, OsString)],
        stdin: &[u8],
    ) -> std::io::Result<CmdOutput> {
        run_process(program, args, Some(env), Some(stdin))
    }
}

/// The passthrough subset of `env`.
pub fn curl_env(env: &dyn Env) -> Vec<(OsString, OsString)> {
    CURL_ENV_PASSTHROUGH
        .iter()
        .filter_map(|k| env.var(k).map(|v| (OsString::from(k), OsString::from(v))))
        .collect()
}

/// Run curl with [`CURL_ARGS`], `env` and `cfg` on stdin.
fn run_curl(
    runner: &dyn CurlRunner,
    env: &[(OsString, OsString)],
    cfg: &[u8],
) -> std::io::Result<CmdOutput> {
    let args: Vec<OsString> = CURL_ARGS.iter().map(OsString::from).collect();
    runner.run(Path::new(CURL), &args, env, cfg)
}

/// `curl`-backed profile client.
pub struct CurlProfileClient<R: CurlRunner = ClearedEnvRunner> {
    runner: R,
    env: Vec<(OsString, OsString)>,
    url: String,
}

impl CurlProfileClient<ClearedEnvRunner> {
    /// A client whose curl gets the [`CURL_ENV_PASSTHROUGH`] subset of `env`.
    pub fn new(env: &dyn Env) -> Self {
        Self::with_runner(ClearedEnvRunner, env)
    }
}

impl<R: CurlRunner> CurlProfileClient<R> {
    pub fn with_runner(runner: R, env: &dyn Env) -> Self {
        CurlProfileClient {
            runner,
            env: curl_env(env),
            url: PROFILE_URL.to_string(),
        }
    }
}

fn fail(code: Option<i32>, class: ToolFailure) -> Error {
    Error::ExternalTool {
        program: "curl",
        sub: "oauth/profile",
        code,
        class,
    }
}

/// The curl config sent on stdin.
fn config(url: &str, token: &[u8]) -> Result<Zeroizing<String>> {
    // Tokens are URL-safe ASCII; anything that could break out of the
    // quoted config value is refused.
    if token.is_empty()
        || !token
            .iter()
            .all(|b| b.is_ascii_graphic() && *b != b'"' && *b != b'\\')
    {
        return Err(Error::Invalid {
            what: "access token (unexpected characters)",
            value: String::new(),
        });
    }
    let tok = std::str::from_utf8(token).expect("ASCII");
    let mut c = Zeroizing::new(String::with_capacity(512 + tok.len()));
    for line in [
        format!("url = \"{url}\"\n"),
        "proto = \"=https\"\n".to_string(),
        "proto-redir = \"=https\"\n".to_string(),
        "max-redirs = 0\n".to_string(),
        "max-time = 5\n".to_string(),
        "silent\n".to_string(),
        format!("header = \"anthropic-beta: {OAUTH_BETA}\"\n"),
        format!(
            "header = \"User-Agent: claude-multi-auth/{}\"\n",
            crate::VERSION
        ),
        "write-out = \"\\n%{http_code}\"\n".to_string(),
    ] {
        c.push_str(&line);
    }
    c.push_str("header = \"Authorization: Bearer ");
    c.push_str(tok);
    c.push_str("\"\n");
    Ok(c)
}

impl<R: CurlRunner> ProfileClient for CurlProfileClient<R> {
    fn profile(&self, access_token: &Secret) -> Result<Profile> {
        let cfg = config(&self.url, access_token.expose())?;
        let out = run_curl(&self.runner, &self.env, cfg.as_bytes())
            .map_err(|_| fail(None, ToolFailure::SpawnFailed))?;
        drop(cfg);
        if out.code != Some(0) {
            return Err(fail(out.code, ToolFailure::Other));
        }
        let body = out.stdout.expose();
        let split = body
            .iter()
            .rposition(|b| *b == b'\n')
            .ok_or_else(|| fail(Some(0), ToolFailure::Other))?;
        let status = std::str::from_utf8(&body[split + 1..])
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(0);
        if status != 200 {
            return Err(fail(Some(status), ToolFailure::AuthFailed));
        }
        parse_profile(&body[..split])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::MapEnv;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Seen {
        program: String,
        args: Vec<OsString>,
        env: Vec<(OsString, OsString)>,
        stdin: Vec<u8>,
    }

    #[derive(Default)]
    struct FakeRunner(RefCell<Option<Seen>>);

    impl CurlRunner for FakeRunner {
        fn run(
            &self,
            program: &Path,
            args: &[OsString],
            env: &[(OsString, OsString)],
            stdin: &[u8],
        ) -> std::io::Result<CmdOutput> {
            *self.0.borrow_mut() = Some(Seen {
                program: program.display().to_string(),
                args: args.to_vec(),
                env: env.to_vec(),
                stdin: stdin.to_vec(),
            });
            Ok(CmdOutput {
                code: Some(0),
                stdout: Secret::new(
                    br#"{"account":{"uuid":"a-1","email":"e@x"},"organization":{"uuid":"o-1","name":"Org"}}
200"#
                        .to_vec(),
                ),
                stderr_class: ToolFailure::Other,
                stderr_hex_password: false,
            })
        }
    }

    #[test]
    fn config_carries_token_only_in_the_header_line() {
        let c = config(PROFILE_URL, b"sk-ant-oat01-abc_DEF-123").unwrap();
        assert!(c.ends_with("header = \"Authorization: Bearer sk-ant-oat01-abc_DEF-123\"\n"));
        assert!(c.contains("max-time = 5\n"));
        assert!(c.contains("proto = \"=https\"\n"));
        assert!(c.contains("proto-redir = \"=https\"\n"));
        assert!(c.contains("max-redirs = 0\n"));
        assert_eq!(c.matches("sk-ant").count(), 1);
    }

    #[test]
    fn config_refuses_breakout_characters() {
        for bad in [&b"a\"b"[..], b"a\nb", b"a\\b", b"", b"a b"] {
            assert!(config(PROFILE_URL, bad).is_err());
        }
    }

    #[test]
    fn curl_gets_q_first_and_only_the_passthrough_env() {
        let parent = MapEnv::new([
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/Users/me"),
            ("CURL_HOME", "/Users/me"),
            ("XDG_CONFIG_HOME", "/Users/me/.config"),
            ("ALL_PROXY", "socks5://evil:1"),
            ("HTTP_PROXY", "http://p:1"),
            ("HTTPS_PROXY", "http://corp:8080"),
            ("no_proxy", "localhost"),
            ("CURL_CA_BUNDLE", "/tmp/ca"),
            ("SSL_CERT_FILE", "/tmp/ca"),
            ("CLAUDE_CODE_OAUTH_TOKEN", "x"),
        ]);
        let client = CurlProfileClient::with_runner(FakeRunner::default(), &parent);
        let token = "sk-ant-oat01-dummy_TOKEN-1";
        let p = client
            .profile(&Secret::new(token.as_bytes().to_vec()))
            .unwrap();
        assert_eq!(p.key(), "a-1::o-1");
        let seen = client.runner.0.borrow_mut().take().unwrap();
        assert_eq!(seen.program, "/usr/bin/curl");
        assert_eq!(seen.args, vec!["-q", "--config", "-"]);
        assert_eq!(seen.args[0], "-q", "-q only works as the first argument");
        let mut env: Vec<(String, String)> = seen
            .env
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect();
        env.sort();
        assert_eq!(
            env,
            vec![
                ("HTTPS_PROXY".to_string(), "http://corp:8080".to_string()),
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("no_proxy".into(), "localhost".into()),
            ]
        );
        // The token is only on stdin.
        let stdin = String::from_utf8(seen.stdin).unwrap();
        assert!(stdin.contains(token));
        assert!(stdin.contains("max-redirs = 0\n"));
        assert!(stdin.contains("proto-redir = \"=https\"\n"));
        assert!(
            seen.args
                .iter()
                .chain(seen.env.iter().map(|(_, v)| v))
                .all(|a| !a.to_string_lossy().contains("dummy_TOKEN"))
        );
    }

    /// Reproduces the review's `.curlrc` trace scenario: a temp HOME whose
    /// `.curlrc` sets `trace-ascii`, a local plain-HTTP server on 127.0.0.1
    /// and a dummy bearer. Control: curl without `-q` honours the curlrc and
    /// writes the dummy token to the trace file. The production argv
    /// (`-q --config -`) with the same HOME writes no trace file. (The stdin
    /// config here is test-local: production pins `=https`, which a plain
    /// HTTP test server cannot serve.) Run with
    /// `cargo test -p cma-core -- --ignored curlrc`.
    #[test]
    #[ignore = "spawns /usr/bin/curl against a 127.0.0.1 test server"]
    fn curlrc_trace_is_ignored() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        const DUMMY: &str = "cma-dummy-not-a-real-token-0123456789";
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let trace = tmp.path().join("trace.txt");
        std::fs::write(
            home.join(".curlrc"),
            format!("trace-ascii = \"{}\"\n", trace.display()),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut conn in listener.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let _ = conn.read(&mut buf);
                let _ = conn.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });
        let cfg = format!(
            "url = \"http://127.0.0.1:{port}/api/oauth/profile\"\nmax-time = 5\nsilent\nheader = \"Authorization: Bearer {DUMMY}\"\n"
        );
        let env: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), home.clone().into_os_string()),
            ("CURL_HOME".into(), home.clone().into_os_string()),
            ("XDG_CONFIG_HOME".into(), home.clone().into_os_string()),
        ];

        // Control: without -q the curlrc is read and the token is traced.
        let ctl = ClearedEnvRunner
            .run(
                Path::new(CURL),
                &[OsString::from("--config"), OsString::from("-")],
                &env,
                cfg.as_bytes(),
            )
            .unwrap();
        assert_eq!(ctl.code, Some(0), "control request failed");
        let traced = std::fs::read_to_string(&trace).expect("control wrote no trace");
        assert!(
            traced.contains(DUMMY),
            "control trace lacks the dummy token"
        );
        std::fs::remove_file(&trace).unwrap();

        // Production argv: the same HOME, but the curlrc is ignored.
        let out = run_curl(&ClearedEnvRunner, &env, cfg.as_bytes()).unwrap();
        assert_eq!(out.code, Some(0), "request with -q failed");
        assert!(!trace.exists(), "-q run wrote a trace file");
        for e in std::fs::read_dir(tmp.path()).unwrap() {
            let p = e.unwrap().path();
            if p.is_file() {
                assert!(!std::fs::read_to_string(&p).unwrap().contains(DUMMY));
            }
        }
    }
}
