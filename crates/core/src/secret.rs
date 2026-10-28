//! Secrets and the Keychain store.
//!
//! [`Secret`] never prints its bytes. [`SecurityCliStore`] talks to
//! `/usr/bin/security` exactly like Claude Code 2.1.310: the
//! `add-generic-password` command goes to `security -i` on stdin (terminated
//! by `\n`) when the line fits in 4032 chars; larger items use the argv form
//! as an argument list. Every write is verified by
//! reading the item back.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result, ToolFailure};

/// Secret bytes, zeroized on drop. `Debug`/`Display` show only the length and
/// a short hash prefix.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Take ownership of the bytes without copying them.
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Full lowercase hex sha256 of the bytes.
    pub fn sha256_hex(&self) -> String {
        sha256_hex(&self.0)
    }
}

impl From<Vec<u8>> for Secret {
    fn from(v: Vec<u8>) -> Self {
        Secret::new(v)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Secret({}B, sha256:{})",
            self.0.len(),
            &self.sha256_hex()[..8]
        )
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Keychain-like generic password store keyed by (service, account).
pub trait SecretStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>>;
    fn set(&self, service: &str, account: &str, value: &Secret) -> Result<()>;
    /// Returns whether an item was deleted.
    fn delete(&self, service: &str, account: &str) -> Result<bool>;
}

/// In-memory store for tests.
#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<HashMap<(String, String), Secret>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored items for a service.
    pub fn count(&self, service: &str) -> usize {
        self.items
            .lock()
            .unwrap()
            .keys()
            .filter(|(s, _)| s == service)
            .count()
    }

    /// Every (service, account) pair whose service starts with `prefix`
    /// (stands in for a Keychain attribute listing in tests).
    pub fn names_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .items
            .lock()
            .unwrap()
            .keys()
            .filter(|(s, _)| s.starts_with(prefix))
            .cloned()
            .collect();
        v.sort();
        v
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>> {
        Ok(self
            .items
            .lock()
            .unwrap()
            .get(&(service.to_string(), account.to_string()))
            .cloned())
    }

    fn set(&self, service: &str, account: &str, value: &Secret) -> Result<()> {
        self.items
            .lock()
            .unwrap()
            .insert((service.to_string(), account.to_string()), value.clone());
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool> {
        Ok(self
            .items
            .lock()
            .unwrap()
            .remove(&(service.to_string(), account.to_string()))
            .is_some())
    }
}

/// Result of running an external command. `stdout` is moved straight into a
/// [`Secret`]; stderr is reduced to a classification by the runner.
pub struct CmdOutput {
    /// `None` when killed by a signal.
    pub code: Option<i32>,
    pub stdout: Secret,
    pub stderr_class: ToolFailure,
    /// stderr opened with `password: 0x`: `security find-generic-password -g`
    /// printed the item in hex form.
    pub stderr_hex_password: bool,
}

/// Runs a program with an argument list (never a shell) and optional stdin.
pub trait CommandRunner {
    fn run(
        &self,
        program: &Path,
        args: &[OsString],
        stdin: Option<&[u8]>,
    ) -> std::io::Result<CmdOutput>;
}

/// Runs real processes.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(
        &self,
        program: &Path,
        args: &[OsString],
        stdin: Option<&[u8]>,
    ) -> std::io::Result<CmdOutput> {
        run_process(program, args, None, stdin)
    }
}

/// Run a real process. `env`: `None` inherits the caller's environment;
/// `Some(vars)` clears it and passes exactly `vars`.
pub fn run_process(
    program: &Path,
    args: &[OsString],
    env: Option<&[(OsString, OsString)]>,
    stdin: Option<&[u8]>,
) -> std::io::Result<CmdOutput> {
    {
        let mut cmd = Command::new(program);
        cmd.args(args);
        if let Some(vars) = env {
            cmd.env_clear()
                .envs(vars.iter().map(|(k, v)| (k.as_os_str(), v.as_os_str())));
        }
        let mut child = cmd
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(input) = stdin {
            // Dropping the handle closes stdin so `security -i` sees EOF. A
            // failed write is not returned early: the child is still reaped
            // below, and the caller's read-back catches a write that did not
            // land.
            let mut pipe = child.stdin.take().expect("stdin piped");
            let _ = pipe.write_all(input);
        }
        // stderr on its own thread so neither pipe can fill and block.
        let mut err_pipe = child.stderr.take().expect("stderr piped");
        let err_reader = std::thread::spawn(move || {
            let mut buf = Zeroizing::new(Vec::new());
            let _ = err_pipe.read_to_end(&mut buf);
            buf
        });
        // Pre-sized so reading `-w` output does not reallocate (each
        // reallocation would leave an unzeroed copy in freed memory).
        let mut out = Zeroizing::new(Vec::with_capacity(STDOUT_CAPACITY));
        let read = child
            .stdout
            .take()
            .expect("stdout piped")
            .read_to_end(&mut out);
        let status = child.wait();
        let stderr = err_reader.join().unwrap_or_default();
        read?;
        let status = status?;
        Ok(CmdOutput {
            code: status.code(),
            stdout: Secret::new(std::mem::take(&mut *out)),
            stderr_class: classify_stderr(&stderr),
            stderr_hex_password: stderr.starts_with(b"password: 0x"),
        })
    }
}

/// Initial stdout buffer: larger than any Keychain item cma handles.
const STDOUT_CAPACITY: usize = 64 * 1024;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Reduce `security` stderr to a fixed classification.
pub fn classify_stderr(stderr: &[u8]) -> ToolFailure {
    // Lowercased in a zeroized copy (stderr may echo input).
    let mut s = Zeroizing::new(stderr.to_vec());
    s.make_ascii_lowercase();
    let has = |n: &str| contains(&s, n.as_bytes());
    if has("user canceled") || has("user cancelled") {
        ToolFailure::UserCanceled
    } else if has("interaction is not allowed") || has("interaction not allowed") {
        ToolFailure::InteractionNotAllowed
    } else if has("could not be found") {
        ToolFailure::NotFound
    } else if has("authoriz") || has("auth failed") || has("access") {
        ToolFailure::AuthFailed
    } else {
        ToolFailure::Other
    }
}

pub const SECURITY_PROGRAM: &str = "/usr/bin/security";
/// Claude Code's own limit for the `security -i` line (including the `\n`).
/// Measured: `security -i` accepts 4070 chars and rejects 4110.
pub const SECURITY_I_LIMIT: usize = 4032;
/// `security` exit code for "item not found".
pub const EXIT_ITEM_NOT_FOUND: i32 = 44;

/// How a write reached `security`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMethod {
    Stdin,
    Argv,
}

/// Service and account names are interpolated into a quoted `security -i`
/// line, so quotes, backslashes and control characters are refused. `/` is
/// allowed (backup accounts are `<id>/<n>`).
pub fn validate_name(what: &'static str, name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| !c.is_control() && c != '"' && c != '\\');
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid {
            what,
            // Names are not secret, but keep the echo short anyway.
            value: name.chars().filter(|c| !c.is_control()).take(24).collect(),
        })
    }
}

/// The exact stdin line Claude Code sends, including the trailing newline
/// (`security -i` silently ignores an unterminated last line and exits 0).
/// Lowercase hex of `value` in an exactly sized, zeroized buffer.
fn hex_zeroizing(value: &[u8]) -> Zeroizing<String> {
    let mut buf = vec![0u8; value.len() * 2];
    hex::encode_to_slice(value, &mut buf).expect("buffer is exactly 2x");
    Zeroizing::new(String::from_utf8(buf).expect("hex is ASCII"))
}

pub fn security_i_line(service: &str, account: &str, value: &[u8]) -> Zeroizing<String> {
    let hex = hex_zeroizing(value);
    let parts = [
        "add-generic-password -U -a \"",
        account,
        "\" -s \"",
        service,
        "\" -X \"",
        hex.as_str(),
        "\"\n",
    ];
    // Exact capacity: no reallocation, so no unzeroed partial copies.
    let mut line = Zeroizing::new(String::with_capacity(parts.iter().map(|p| p.len()).sum()));
    for p in parts {
        line.push_str(p);
    }
    line
}

/// Pick the write form for an item, by the length of its `security -i` line.
pub fn write_method(service: &str, account: &str, value: &[u8]) -> WriteMethod {
    if security_i_line(service, account, value).len() <= SECURITY_I_LIMIT {
        WriteMethod::Stdin
    } else {
        WriteMethod::Argv
    }
}

/// Keychain store backed by `/usr/bin/security`.
pub struct SecurityCliStore<R: CommandRunner = ProcessRunner> {
    runner: R,
    program: &'static Path,
}

impl SecurityCliStore<ProcessRunner> {
    pub fn new() -> Self {
        Self::with_runner(ProcessRunner)
    }
}

impl Default for SecurityCliStore<ProcessRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: CommandRunner> SecurityCliStore<R> {
    pub fn with_runner(runner: R) -> Self {
        SecurityCliStore {
            runner,
            program: Path::new(SECURITY_PROGRAM),
        }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    fn run(&self, sub: &'static str, args: &[OsString], stdin: Option<&[u8]>) -> Result<CmdOutput> {
        self.runner
            .run(self.program, args, stdin)
            .map_err(|_| Error::ExternalTool {
                program: "security",
                sub,
                code: None,
                class: ToolFailure::SpawnFailed,
            })
    }

    /// Write the item and return the form used. Verified by read-back.
    pub fn set_with_method(
        &self,
        service: &str,
        account: &str,
        value: &Secret,
    ) -> Result<WriteMethod> {
        validate_name("keychain service", service)?;
        validate_name("keychain account", account)?;
        let line = security_i_line(service, account, value.expose());
        let (method, sub, out) = if line.len() <= SECURITY_I_LIMIT {
            let args = [OsString::from("-i")];
            let out = self.run("-i", &args, Some(line.as_bytes()))?;
            (WriteMethod::Stdin, "-i", out)
        } else {
            drop(line);
            // Over the `security -i` line limit: argv form, as Claude Code does.
            // The hex is briefly visible in `ps` (documented in the README).
            let hex = hex_zeroizing(value.expose());
            let args: Vec<OsString> = vec![
                "add-generic-password".into(),
                "-U".into(),
                "-a".into(),
                account.into(),
                "-s".into(),
                service.into(),
                "-X".into(),
                hex.as_str().into(),
            ];
            let out = self.run("add-generic-password", &args, None);
            // Best-effort wipe of our copies of the hex argument.
            for a in args {
                Zeroizing::new(a.into_vec()).zeroize();
            }
            (WriteMethod::Argv, "add-generic-password", out?)
        };
        if out.code != Some(0) {
            return Err(Error::ExternalTool {
                program: "security",
                sub,
                code: out.code,
                class: failure_class(&out),
            });
        }
        // Mandatory read-back: `security -i` can exit 0 without writing.
        match self.get(service, account)? {
            Some(back) if back.sha256_hex() == value.sha256_hex() => Ok(method),
            _ => Err(Error::WriteNotVerified {
                service: service.to_string(),
                account: account.to_string(),
            }),
        }
    }
}

impl<R: CommandRunner> SecurityCliStore<R> {
    /// Whether `security` shows the item in its hex form.
    fn printed_as_hex(&self, service: &str, account: &str) -> Result<bool> {
        let args: Vec<OsString> = vec![
            "find-generic-password".into(),
            "-a".into(),
            account.into(),
            "-g".into(),
            "-s".into(),
            service.into(),
        ];
        let out = self.run("find-generic-password", &args, None)?;
        match out.code {
            Some(0) => Ok(out.stderr_hex_password),
            _ => Err(Error::ExternalTool {
                program: "security",
                sub: "find-generic-password",
                code: out.code,
                class: failure_class(&out),
            }),
        }
    }
}

fn printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// The bytes `-w` output would stand for if `security` printed it as hex:
/// non-empty, even length, lowercase hex digits only, and decoding to at
/// least one byte `security` would not print as is.
fn hex_printed_candidate(out: &[u8]) -> Option<Secret> {
    if out.is_empty()
        || !out.len().is_multiple_of(2)
        || !out.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut buf = vec![0u8; out.len() / 2];
    hex::decode_to_slice(out, &mut buf).ok()?;
    let decoded = Secret::new(buf);
    if decoded.expose().iter().all(|&b| printable(b)) {
        return None;
    }
    Some(decoded)
}

fn failure_class(out: &CmdOutput) -> ToolFailure {
    match out.code {
        None => ToolFailure::Signaled,
        Some(EXIT_ITEM_NOT_FOUND) => ToolFailure::NotFound,
        Some(_) => out.stderr_class,
    }
}

impl<R: CommandRunner> SecretStore for SecurityCliStore<R> {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>> {
        validate_name("keychain service", service)?;
        validate_name("keychain account", account)?;
        let args: Vec<OsString> = vec![
            "find-generic-password".into(),
            "-a".into(),
            account.into(),
            "-w".into(),
            "-s".into(),
            service.into(),
        ];
        let out = self.run("find-generic-password", &args, None)?;
        match out.code {
            Some(0) => {
                let mut bytes = out.stdout;
                // `-w` appends exactly one newline.
                if bytes.0.last() == Some(&b'\n') {
                    bytes.0.pop();
                }
                // `-w` prints an item holding any byte outside 0x20..=0x7e as
                // lowercase hex. Such output is ambiguous only with an item
                // that literally is that hex text; `-g` tells the two apart.
                if let Some(decoded) = hex_printed_candidate(bytes.expose())
                    && self.printed_as_hex(service, account)?
                {
                    return Ok(Some(decoded));
                }
                Ok(Some(bytes))
            }
            Some(EXIT_ITEM_NOT_FOUND) => Ok(None),
            _ => Err(Error::ExternalTool {
                program: "security",
                sub: "find-generic-password",
                code: out.code,
                class: failure_class(&out),
            }),
        }
    }

    fn set(&self, service: &str, account: &str, value: &Secret) -> Result<()> {
        self.set_with_method(service, account, value).map(|_| ())
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool> {
        validate_name("keychain service", service)?;
        validate_name("keychain account", account)?;
        let args: Vec<OsString> = vec![
            "delete-generic-password".into(),
            "-a".into(),
            account.into(),
            "-s".into(),
            service.into(),
        ];
        let out = self.run("delete-generic-password", &args, None)?;
        match out.code {
            Some(0) => Ok(true),
            Some(EXIT_ITEM_NOT_FOUND) => Ok(false),
            _ => Err(Error::ExternalTool {
                program: "security",
                sub: "delete-generic-password",
                code: out.code,
                class: failure_class(&out),
            }),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    /// One recorded call to the fake `security`.
    #[derive(Debug, Clone)]
    pub struct Call {
        pub program: String,
        pub args: Vec<String>,
        pub stdin: Option<Vec<u8>>,
    }

    /// A fake `security` backed by a map. Parses the `-i` line and the argv
    /// form, so tests check what was actually sent.
    #[derive(Default)]
    pub struct FakeSecurity {
        pub items: RefCell<HashMap<(String, String), Vec<u8>>>,
        pub calls: RefCell<Vec<Call>>,
        /// Accept writes but store nothing (models `security -i` without `\n`).
        pub drop_writes: bool,
        /// Store different bytes than were sent.
        pub corrupt_writes: bool,
        /// Exit code for every call, with this stderr class.
        pub fail_with: Option<(i32, ToolFailure)>,
        /// Echo this into stdout/stderr of failures (must never surface).
        pub noise: Vec<u8>,
        pub spawn_error: bool,
        /// Every call ends as if killed by a signal (no exit code).
        pub signaled: bool,
    }

    fn parse_i_line(line: &str) -> Option<(String, String, String)> {
        // add-generic-password -U -a "<a>" -s "<s>" -X "<hex>"\n
        let rest = line.strip_prefix("add-generic-password -U -a \"")?;
        let (a, rest) = rest.split_once("\" -s \"")?;
        let (s, rest) = rest.split_once("\" -X \"")?;
        let hex = rest.strip_suffix("\"\n")?;
        Some((a.into(), s.into(), hex.into()))
    }

    impl FakeSecurity {
        fn store(&self, a: String, s: String, hex: &str) {
            if self.drop_writes {
                return;
            }
            let mut v = hex::decode(hex).unwrap();
            if self.corrupt_writes {
                v.push(b'!');
            }
            self.items.borrow_mut().insert((s, a), v);
        }
    }

    impl CommandRunner for FakeSecurity {
        fn run(
            &self,
            program: &Path,
            args: &[OsString],
            stdin: Option<&[u8]>,
        ) -> std::io::Result<CmdOutput> {
            let args: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            self.calls.borrow_mut().push(Call {
                program: program.display().to_string(),
                args: args.clone(),
                stdin: stdin.map(<[u8]>::to_vec),
            });
            if self.spawn_error {
                return Err(std::io::Error::other(
                    String::from_utf8_lossy(&self.noise).into_owned(),
                ));
            }
            let ok = |stdout: Vec<u8>| CmdOutput {
                code: Some(0),
                stdout: Secret::new(stdout),
                stderr_class: ToolFailure::Other,
                stderr_hex_password: false,
            };
            if self.signaled {
                return Ok(CmdOutput {
                    code: None,
                    stdout: Secret::new(self.noise.clone()),
                    stderr_class: ToolFailure::Other,
                    stderr_hex_password: false,
                });
            }
            if let Some((code, class)) = self.fail_with {
                return Ok(CmdOutput {
                    code: Some(code),
                    stdout: Secret::new(self.noise.clone()),
                    stderr_class: class,
                    stderr_hex_password: false,
                });
            }
            let get = |flag: &str| {
                args.iter()
                    .position(|a| a == flag)
                    .map(|i| args[i + 1].clone())
                    .unwrap()
            };
            match args[0].as_str() {
                "-i" => {
                    let text = String::from_utf8(stdin.unwrap().to_vec()).unwrap();
                    // Real `security -i` ignores an unterminated line.
                    if let Some((a, s, hex)) = parse_i_line(&text) {
                        self.store(a, s, &hex);
                    }
                    Ok(ok(vec![]))
                }
                "add-generic-password" => {
                    self.store(get("-a"), get("-s"), &get("-X"));
                    Ok(ok(vec![]))
                }
                "find-generic-password" => match self.items.borrow().get(&(get("-s"), get("-a"))) {
                    // Like the real tool: `-w` prints hex when any byte is
                    // outside 0x20..=0x7e; `-g` goes hex for `"` and `\` too.
                    Some(v) if args.iter().any(|a| a == "-g") => Ok(CmdOutput {
                        code: Some(0),
                        stdout: Secret::new(vec![]),
                        stderr_class: ToolFailure::Other,
                        stderr_hex_password: v
                            .iter()
                            .any(|&b| !printable(b) || b == b'"' || b == b'\\'),
                    }),
                    Some(v) => {
                        let mut out = if v.iter().all(|&b| printable(b)) {
                            v.clone()
                        } else {
                            hex::encode(v).into_bytes()
                        };
                        out.push(b'\n');
                        Ok(ok(out))
                    }
                    None => Ok(CmdOutput {
                        code: Some(44),
                        stdout: Secret::new(vec![]),
                        stderr_class: ToolFailure::NotFound,
                        stderr_hex_password: false,
                    }),
                },
                "delete-generic-password" => {
                    if self
                        .items
                        .borrow_mut()
                        .remove(&(get("-s"), get("-a")))
                        .is_some()
                    {
                        Ok(ok(vec![]))
                    } else {
                        Ok(CmdOutput {
                            code: Some(44),
                            stdout: Secret::new(vec![]),
                            stderr_class: ToolFailure::NotFound,
                            stderr_hex_password: false,
                        })
                    }
                }
                other => panic!("unexpected subcommand {other}"),
            }
        }
    }

    const SVC: &str = "claude-multi-auth-test";
    const ACCT: &str = "tester";

    /// Payload whose `security -i` line is exactly `len` chars. `extra` adds
    /// one char via an odd-length service name (hex is always even).
    fn payload_for_line_len(len: usize) -> (String, Vec<u8>) {
        let base = security_i_line(SVC, ACCT, b"").len();
        let svc = if (len - base) % 2 == 1 {
            format!("{SVC}x")
        } else {
            SVC.to_string()
        };
        let base = security_i_line(&svc, ACCT, b"").len();
        let n = (len - base) / 2;
        let bytes = vec![b'a'; n];
        assert_eq!(security_i_line(&svc, ACCT, &bytes).len(), len);
        (svc, bytes)
    }

    #[test]
    fn line_matches_claude_code_format_and_ends_with_newline() {
        let line = security_i_line("Claude Code-credentials", "me", b"{}");
        assert_eq!(
            line.as_str(),
            "add-generic-password -U -a \"me\" -s \"Claude Code-credentials\" -X \"7b7d\"\n"
        );
    }

    #[test]
    fn stdin_at_4032_argv_at_4033() {
        for (len, want) in [
            (4031, WriteMethod::Stdin),
            (4032, WriteMethod::Stdin),
            (4033, WriteMethod::Argv),
            (4034, WriteMethod::Argv),
        ] {
            let (svc, bytes) = payload_for_line_len(len);
            let store = SecurityCliStore::with_runner(FakeSecurity::default());
            let m = store
                .set_with_method(&svc, ACCT, &Secret::new(bytes.clone()))
                .unwrap();
            assert_eq!(m, want, "line len {len}");
            assert_eq!(write_method(&svc, ACCT, &bytes), want);
            let calls = store.runner().calls.borrow();
            let w = &calls[0];
            assert_eq!(w.program, "/usr/bin/security");
            match want {
                WriteMethod::Stdin => {
                    assert_eq!(w.args, vec!["-i"]);
                    let stdin = w.stdin.as_ref().unwrap();
                    assert_eq!(stdin.len(), len);
                    assert_eq!(stdin.last(), Some(&b'\n'));
                }
                WriteMethod::Argv => {
                    assert!(w.stdin.is_none());
                    assert_eq!(
                        &w.args[..7],
                        &[
                            "add-generic-password",
                            "-U",
                            "-a",
                            ACCT,
                            "-s",
                            svc.as_str(),
                            "-X"
                        ]
                    );
                    assert_eq!(w.args[7], hex::encode(&bytes));
                    assert_eq!(w.args.len(), 8);
                }
            }
            // Read-back followed the write.
            assert_eq!(calls[1].args[0], "find-generic-password");
            drop(calls);
            assert_eq!(store.get(&svc, ACCT).unwrap().unwrap().expose(), &bytes[..]);
        }
    }

    #[test]
    fn dropped_write_is_not_verified() {
        let store = SecurityCliStore::with_runner(FakeSecurity {
            drop_writes: true,
            ..Default::default()
        });
        let err = store
            .set(SVC, ACCT, &Secret::new(b"{\"a\":1}".to_vec()))
            .unwrap_err();
        assert!(matches!(err, Error::WriteNotVerified { .. }));
    }

    #[test]
    fn mismatched_read_back_is_not_verified() {
        for big in [false, true] {
            let store = SecurityCliStore::with_runner(FakeSecurity {
                corrupt_writes: true,
                ..Default::default()
            });
            let v = vec![b'x'; if big { 3000 } else { 10 }];
            let err = store.set(SVC, ACCT, &Secret::new(v)).unwrap_err();
            assert!(matches!(err, Error::WriteNotVerified { .. }), "big={big}");
        }
    }

    /// Values `security -w` prints as hex, and printable values that look
    /// like hex, both read back as stored.
    fn hex_shaped_values() -> Vec<Vec<u8>> {
        let mut multi_line = b"{\n  \"a\": 1\n}\n".repeat(400);
        multi_line.truncate(5000);
        vec![
            b"{\n  \"a\": 1\n}".to_vec(),
            multi_line,
            "ti\u{1ebf}ng".as_bytes().to_vec(),
            b"a\tb".to_vec(),
            b"0a".to_vec(),
            b"414243".to_vec(),
            b"0a0d".to_vec(),
            b"a\"b\\c".to_vec(),
            b"abc".to_vec(),
        ]
    }

    #[test]
    fn values_printed_as_hex_round_trip() {
        for v in hex_shaped_values() {
            let store = SecurityCliStore::with_runner(FakeSecurity::default());
            store.set(SVC, ACCT, &Secret::new(v.clone())).unwrap();
            assert_eq!(store.get(SVC, ACCT).unwrap().unwrap().expose(), &v[..]);
        }
    }

    #[test]
    #[ignore = "writes the real login Keychain (test service only)"]
    fn real_keychain_round_trips_values_printed_as_hex() {
        let store = SecurityCliStore::new();
        for v in hex_shaped_values() {
            store.set(SVC, ACCT, &Secret::new(v.clone())).unwrap();
            assert_eq!(store.get(SVC, ACCT).unwrap().unwrap().expose(), &v[..]);
        }
        store.delete(SVC, ACCT).unwrap();
    }

    #[test]
    fn get_strips_exactly_one_newline_and_44_is_none() {
        let fake = FakeSecurity::default();
        fake.items
            .borrow_mut()
            .insert((SVC.into(), ACCT.into()), b"v\n".to_vec());
        let store = SecurityCliStore::with_runner(fake);
        assert_eq!(store.get(SVC, ACCT).unwrap().unwrap().expose(), b"v\n");
        assert!(store.get(SVC, "nobody").unwrap().is_none());
        let calls = store.runner().calls.borrow();
        assert_eq!(
            calls[0].args,
            vec!["find-generic-password", "-a", ACCT, "-w", "-s", SVC]
        );
    }

    #[test]
    fn binary_value_with_trailing_newline_round_trips_byte_exact() {
        for v in [
            b"\x00\xff\x01tok\n".to_vec(),
            b"line\n\n".to_vec(),
            vec![b'\n'],
            (0u8..=255).chain(*b"\n").collect::<Vec<u8>>(),
        ] {
            let store = SecurityCliStore::with_runner(FakeSecurity::default());
            store.set(SVC, ACCT, &Secret::new(v.clone())).unwrap();
            assert_eq!(store.get(SVC, ACCT).unwrap().unwrap().expose(), &v[..]);
        }
    }

    #[test]
    fn hex_buffer_and_line_have_exact_capacity() {
        let h = hex_zeroizing(b"\x00\xab");
        assert_eq!(h.as_str(), "00ab");
        let line = security_i_line(SVC, ACCT, &[7u8; 100]);
        assert_eq!(line.capacity(), line.len());
    }

    #[test]
    fn delete_reports_presence() {
        let store = SecurityCliStore::with_runner(FakeSecurity::default());
        store.set(SVC, ACCT, &Secret::new(b"1".to_vec())).unwrap();
        assert!(store.delete(SVC, ACCT).unwrap());
        assert!(!store.delete(SVC, ACCT).unwrap());
    }

    #[test]
    fn errors_carry_only_program_sub_code() {
        let store = SecurityCliStore::with_runner(FakeSecurity {
            fail_with: Some((51, ToolFailure::UserCanceled)),
            noise: b"SECRETSECRET".to_vec(),
            ..Default::default()
        });
        match store.get(SVC, ACCT).unwrap_err() {
            Error::ExternalTool {
                program,
                sub,
                code,
                class,
            } => {
                assert_eq!(
                    (program, sub, code, class),
                    (
                        "security",
                        "find-generic-password",
                        Some(51),
                        ToolFailure::UserCanceled
                    )
                );
            }
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn names_with_quotes_or_newlines_rejected() {
        let store = SecurityCliStore::with_runner(FakeSecurity::default());
        for bad in ["a\"b", "a\nb", "a\\b", ""] {
            assert!(matches!(
                store.set(bad, ACCT, &Secret::new(vec![1])),
                Err(Error::Invalid { .. })
            ));
            assert!(matches!(store.get(SVC, bad), Err(Error::Invalid { .. })));
        }
        validate_name("x", "20261026T101022Z-switch/0").unwrap();
        assert!(store.runner().calls.borrow().is_empty());
    }

    #[test]
    fn secret_debug_display_redacted() {
        let s = Secret::new(b"sk-ant-oat01-supersecretvalue".to_vec());
        let d = format!("{s:?}");
        assert!(d.starts_with("Secret(29B, sha256:"), "{d}");
        assert!(!d.contains("supersecret"));
        assert_eq!(format!("{s}"), d);
    }

    #[test]
    fn classify_stderr_fixed_classes() {
        assert_eq!(
            classify_stderr(b"security: SecKeychainItemCopyContent: User canceled the operation."),
            ToolFailure::UserCanceled
        );
        assert_eq!(
            classify_stderr(b"User interaction is not allowed."),
            ToolFailure::InteractionNotAllowed
        );
        assert_eq!(
            classify_stderr(b"The specified item could not be found in the keychain."),
            ToolFailure::NotFound
        );
        assert_eq!(classify_stderr(b"weird"), ToolFailure::Other);
        assert_eq!(classify_stderr(b""), ToolFailure::Other);
    }

    /// Real process: stdin write to a child that exits at once must not
    /// leave it unreaped or panic.
    #[test]
    fn process_runner_survives_child_closing_stdin() {
        let out = ProcessRunner
            .run(Path::new("/usr/bin/true"), &[], Some(&vec![b'x'; 1 << 20]))
            .unwrap();
        assert_eq!(out.code, Some(0));
        let out = ProcessRunner
            .run(Path::new("/bin/echo"), &[OsString::from("hi")], None)
            .unwrap();
        assert_eq!(out.stdout.expose(), b"hi\n");
    }

    /// Real Keychain, service `claude-multi-auth-test` only, dummy data.
    /// Run with `cargo test -p cma-core -- --ignored keychain`.
    mod real_keychain {
        use super::*;

        const TEST_SERVICE: &str = "claude-multi-auth-test";

        /// Deletes the test item even if the test panics.
        struct Cleanup<'a>(&'a SecurityCliStore, &'a str);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = self.0.delete(TEST_SERVICE, self.1);
            }
        }

        fn round_trip(account: &str, payload: Vec<u8>, want: WriteMethod) {
            let store = SecurityCliStore::new();
            let _cleanup = Cleanup(&store, account);
            let _ = store.delete(TEST_SERVICE, account);
            assert!(store.get(TEST_SERVICE, account).unwrap().is_none());
            let v = Secret::new(payload);
            assert_eq!(
                store.set_with_method(TEST_SERVICE, account, &v).unwrap(),
                want
            );
            let back = store.get(TEST_SERVICE, account).unwrap().unwrap();
            assert_eq!(back.sha256_hex(), v.sha256_hex());
            // Update in place (-U), verified again.
            let mut updated = v.expose().to_vec();
            updated.extend_from_slice(b" ");
            let u = Secret::new(updated);
            assert_eq!(
                store.set_with_method(TEST_SERVICE, account, &u).unwrap(),
                want
            );
            assert_eq!(
                store
                    .get(TEST_SERVICE, account)
                    .unwrap()
                    .unwrap()
                    .sha256_hex(),
                u.sha256_hex()
            );
            assert!(store.delete(TEST_SERVICE, account).unwrap());
            assert!(store.get(TEST_SERVICE, account).unwrap().is_none());
            assert!(!store.delete(TEST_SERVICE, account).unwrap());
        }

        #[test]
        #[ignore = "touches the real Keychain (service claude-multi-auth-test)"]
        fn keychain_small_item_via_stdin() {
            round_trip(
                "cma-core-test-small",
                br#"{"dummy":"small cma-core test payload"}"#.to_vec(),
                WriteMethod::Stdin,
            );
        }

        #[test]
        #[ignore = "touches the real Keychain (service claude-multi-auth-test)"]
        fn keychain_backup_style_account_with_slash() {
            round_trip(
                "20261026T101022Z-test/0",
                br#"{"dummy":"backup-style account"}"#.to_vec(),
                WriteMethod::Stdin,
            );
        }

        #[test]
        #[ignore = "touches the real Keychain (service claude-multi-auth-test)"]
        fn keychain_large_item_via_argv() {
            let mut p = br#"{"dummy":""#.to_vec();
            p.extend(std::iter::repeat_n(b'x', 2500));
            p.extend_from_slice(br#""}"#);
            round_trip("cma-core-test-large", p, WriteMethod::Argv);
        }
    }

    mod leak {
        use super::*;
        use crate::registry::{Registry, claude_oauth_fingerprint};
        use proptest::prelude::*;
        use regex::Regex;

        fn assert_clean(out: &str, secret: &str) {
            assert!(!out.contains(secret), "secret leaked: {out}");
            let long_hex = Regex::new(r"[0-9a-fA-F]{33,}").unwrap();
            assert!(!long_hex.is_match(out), "long hex run: {out}");
        }

        fn check(e: &Error, secret: &str) {
            assert_clean(&format!("{e:?}"), secret);
            assert_clean(&format!("{e}"), secret);
        }

        fn fake(secret: &str) -> FakeSecurity {
            FakeSecurity {
                noise: secret.as_bytes().to_vec(),
                ..Default::default()
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn no_secret_in_debug_or_display(secret in "[0-9a-f]{33,600}", code in (1i32..200).prop_filter("not 44", |c| *c != EXIT_ITEM_NOT_FOUND)) {
                let sec = Secret::new(secret.as_bytes().to_vec());
                assert_clean(&format!("{sec:?}"), &secret);
                assert_clean(&format!("{sec}"), &secret);
                // `security` failing with the secret on stdout/stderr.
                for class in [ToolFailure::Other, ToolFailure::UserCanceled, ToolFailure::AuthFailed, ToolFailure::InteractionNotAllowed] {
                    let store = SecurityCliStore::with_runner(FakeSecurity {
                        fail_with: Some((code, class)),
                        ..fake(&secret)
                    });
                    check(&store.get(SVC, ACCT).unwrap_err(), &secret);
                    check(&store.set(SVC, ACCT, &sec).unwrap_err(), &secret);
                    check(&store.delete(SVC, ACCT).unwrap_err(), &secret);
                }
                // Killed by a signal, with the secret on stdout.
                let store = SecurityCliStore::with_runner(FakeSecurity { signaled: true, ..fake(&secret) });
                for e in [store.get(SVC, ACCT).unwrap_err(), store.set(SVC, ACCT, &sec).unwrap_err(), store.delete(SVC, ACCT).unwrap_err()] {
                    prop_assert!(matches!(e, Error::ExternalTool { class: ToolFailure::Signaled, code: None, .. }), "{:?}", e);
                    check(&e, &secret);
                }
                // A hex-only name is refused and echoed only truncated.
                check(&store.get(&secret, ACCT).unwrap_err(), &secret);
                check(&store.set(SVC, &secret[..secret.len().min(300)], &sec).unwrap_err(), &secret);
                // Spawn failure whose io::Error message holds the secret.
                let store = SecurityCliStore::with_runner(FakeSecurity { spawn_error: true, ..fake(&secret) });
                check(&store.get(SVC, ACCT).unwrap_err(), &secret);
                check(&store.set(SVC, ACCT, &sec).unwrap_err(), &secret);
                // Read-back mismatch, stdin and argv paths.
                for big in [false, true] {
                    let mut v = secret.as_bytes().to_vec();
                    if big { v.extend(std::iter::repeat_n(b'0', 3000)); }
                    let store = SecurityCliStore::with_runner(FakeSecurity { corrupt_writes: true, ..fake(&secret) });
                    check(&store.set(SVC, ACCT, &Secret::new(v)).unwrap_err(), &secret);
                }
                // JSON parse errors over secret-bearing input.
                let bad = format!("{{\"schema_version\": \"{secret}\"}}");
                check(&Registry::from_bytes(bad.as_bytes()).unwrap_err(), &secret);
                let bad = format!("{{\"claudeAiOauth\": {{\"accessToken\": \"{secret}\" ");
                check(&claude_oauth_fingerprint(bad.as_bytes()).unwrap_err(), &secret);
                let bad = format!("{{\"a\": {secret}}}");
                check(&claude_oauth_fingerprint(bad.as_bytes()).unwrap_err(), &secret);
            }

            #[test]
            fn secret_debug_never_shows_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                let sec = Secret::new(bytes.clone());
                let d = format!("{sec:?}");
                let prefix = format!("Secret({}B, sha256:", bytes.len());
                let long_hex = Regex::new(r"[0-9a-f]{33,}").unwrap().is_match(&d);
                prop_assert!(d.starts_with(&prefix), "{}", d);
                prop_assert!(!long_hex, "{}", d);
                prop_assert_eq!(d.len(), format!("Secret({}B, sha256:12345678)", bytes.len()).len());
            }
        }
    }
}
