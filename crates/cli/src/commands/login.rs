//! `cma login`: isolated `claude auth login`, the active login untouched.
//!
//! `--args-file` takes the options from a private JSON file instead of the
//! command line; the menubar app writes one so an option (an alias such as
//! `"; rm -rf ~`) never passes through shell text.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use cma_core::login::{LoginOpts, login};
use serde::Deserialize;
use serde_json::json;

use super::CmdResult;
use crate::LoginArgs;
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

/// Largest accepted `--args-file`.
const ARGS_FILE_MAX: u64 = 16 * 1024;
/// Longest accepted text option in an `--args-file`.
const ARG_MAX_CHARS: usize = 256;

pub fn run(deps: &Deps, out: &mut Out, a: &LoginArgs) -> CmdResult {
    let opts = match &a.args_file {
        Some(p) => read_args_file(p)?,
        None => LoginOpts {
            email: a.email.clone(),
            sso: a.sso,
            console: a.console,
            org: a.org.clone(),
            alias: a.alias.clone(),
        },
    };
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let r = login(&ctx, deps.spawner(out.json), deps.lister.as_ref(), &opts)?;
    out.warn_all(r.warnings.clone());
    let data = json!({
        "key": r.key,
        "email": r.email,
        "org_name": r.org_name,
        "kind": serde_json::to_value(r.kind).unwrap_or_default(),
        "replaced": r.replaced,
    });
    let verb = if r.replaced {
        "logged in again"
    } else {
        "added"
    };
    let org = if r.org_name.is_empty() {
        String::new()
    } else {
        format!(" [{}]", r.org_name)
    };
    Ok(Outcome::new(data, format!("{verb}: {}{org}", r.email)))
}

/// The `--args-file` shape.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ArgsFile {
    email: Option<String>,
    alias: Option<String>,
    org: Option<String>,
    sso: bool,
    console: bool,
}

fn args_error(path: &Path, why: impl std::fmt::Display) -> CliError {
    CliError::new(
        "invalid",
        format!("login args file {}: {why}", path.display()),
    )
}

/// Read login options from a private JSON file: opened without following
/// a symlink, and refused unless it is a regular file owned by the current
/// user, readable by nobody else, and small.
pub fn read_args_file(path: &Path) -> Result<LoginOpts, CliError> {
    let nofollow = rustix::fs::OFlags::NOFOLLOW.bits() as i32;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(nofollow)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                args_error(path, "is a symlink")
            } else {
                args_error(path, e)
            }
        })?;
    let meta = f.metadata().map_err(|e| args_error(path, e))?;
    if !meta.is_file() {
        return Err(args_error(path, "is not a regular file"));
    }
    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(args_error(path, "is not owned by the current user"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(args_error(
            path,
            format!("mode is {:o}; it must be 600", meta.mode() & 0o777),
        ));
    }
    if meta.len() > ARGS_FILE_MAX {
        return Err(args_error(path, "is too large"));
    }
    let mut buf = Vec::new();
    f.by_ref()
        .take(ARGS_FILE_MAX + 1)
        .read_to_end(&mut buf)
        .map_err(|e| args_error(path, e))?;
    if buf.len() as u64 > ARGS_FILE_MAX {
        return Err(args_error(path, "is too large"));
    }
    let a: ArgsFile = serde_json::from_slice(&buf)
        .map_err(|e| args_error(path, format!("not valid login options ({e})")))?;
    let text = |name: &str, v: Option<String>| -> Result<Option<String>, CliError> {
        match v {
            Some(s) if s.chars().count() > ARG_MAX_CHARS => {
                Err(args_error(path, format!("{name} is too long")))
            }
            Some(s) if s.chars().any(char::is_control) => Err(args_error(
                path,
                format!("{name} contains a control character"),
            )),
            Some(s) if s.trim().is_empty() => Ok(None),
            other => Ok(other),
        }
    };
    Ok(LoginOpts {
        email: text("email", a.email)?,
        sso: a.sso,
        console: a.console,
        org: text("org", a.org)?,
        alias: text("alias", a.alias)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write(dir: &Path, body: &str, mode: u32) -> std::path::PathBuf {
        let p = dir.join("login-args.json");
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn options_are_read_literally() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            r#"{"email":"a@x.test","alias":"\"; rm -rf ~","org":"Org $(x)","sso":true}"#,
            0o600,
        );
        let o = read_args_file(&p).unwrap();
        assert_eq!(o.email.as_deref(), Some("a@x.test"));
        assert_eq!(o.alias.as_deref(), Some("\"; rm -rf ~"));
        assert_eq!(o.org.as_deref(), Some("Org $(x)"));
        assert!(o.sso);
        assert!(!o.console);
    }

    #[test]
    fn readable_by_others_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "{}", 0o644);
        let e = read_args_file(&p).unwrap_err();
        assert_eq!(e.code, "invalid");
        assert!(e.message.contains("must be 600"), "{}", e.message);
    }

    #[test]
    fn a_symlink_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let real = write(d.path(), "{}", 0o600);
        let link = d.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = read_args_file(&link).unwrap_err();
        assert!(e.message.contains("symlink"), "{}", e.message);
    }

    #[test]
    fn unknown_keys_wrong_types_and_control_characters_are_refused() {
        let d = tempfile::tempdir().unwrap();
        for body in [
            r#"{"email":"a@x.test","shell":"x"}"#,
            r#"{"sso":"yes"}"#,
            r#"{"alias":"a\nb"}"#,
            "not json",
        ] {
            let p = write(d.path(), body, 0o600);
            assert_eq!(read_args_file(&p).unwrap_err().code, "invalid", "{body}");
        }
        let long = format!(r#"{{"alias":"{}"}}"#, "a".repeat(ARG_MAX_CHARS + 1));
        let p = write(d.path(), &long, 0o600);
        assert!(read_args_file(&p).unwrap_err().message.contains("too long"));
    }
}
