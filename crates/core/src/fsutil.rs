//! Atomic file replacement and symlink-safe reads.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::error::{Error, Result};

fn nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}

fn map_open_err(path: &Path, e: std::io::Error) -> Error {
    // ELOOP: the final component is a symlink and O_NOFOLLOW refused it.
    if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
        Error::Symlink(path.to_path_buf())
    } else {
        Error::io(path, e)
    }
}

/// Read a file without following a symlink at its final component.
/// Missing file ⇒ `None`.
pub fn read_nofollow(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut f = match OpenOptions::new()
        .read(true)
        .custom_flags(nofollow())
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(map_open_err(path, e)),
    };
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| Error::io(path, e))?;
    Ok(Some(buf))
}

/// Mode of an existing regular file (symlinks refused), or `None` if missing.
pub fn existing_mode(path: &Path) -> Result<Option<u32>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(Error::Symlink(path.to_path_buf())),
        Ok(m) => Ok(Some(m.mode() & 0o7777)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Atomically replace `path` with `bytes`: temp file in the same directory,
/// fsync, rename, fsync the directory. An existing file keeps its mode; a new
/// one gets 0600. A symlink at `path` is refused.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mode = existing_mode(path)?.unwrap_or(0o600);
    atomic_write_mode(path, bytes, mode)
}

/// [`atomic_write`] with an explicit mode (cma's own private files).
pub fn atomic_write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    existing_mode(path)?;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".cma-tmp-")
        .tempfile_in(dir)
        .map_err(|e| Error::io(dir, e))?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io(tmp.path(), e))?;
    tmp.write_all(bytes).map_err(|e| Error::io(path, e))?;
    tmp.as_file().sync_all().map_err(|e| Error::io(path, e))?;
    tmp.persist(path).map_err(|e| Error::io(path, e.error))?;
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| Error::io(dir, e))?;
    Ok(())
}

/// Remove a file and fsync its directory, so the removal survives a power
/// loss. Returns whether the file existed.
pub fn remove_file_durable(path: &Path) -> Result<bool> {
    let existed = match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(e) => return Err(Error::io(path, e)),
    };
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| Error::io(dir, e))?;
    Ok(existed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_file_is_0600() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.json");
        atomic_write(&p, b"{}").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"{}");
        assert_eq!(existing_mode(&p).unwrap(), Some(0o600));
    }

    #[test]
    fn replace_preserves_mode() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.json");
        std::fs::write(&p, b"old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        atomic_write(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert_eq!(existing_mode(&p).unwrap(), Some(0o644));
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 1);
    }

    #[test]
    fn symlink_target_refused() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        std::fs::write(&real, b"x").unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(atomic_write(&link, b"y"), Err(Error::Symlink(_))));
        assert!(matches!(read_nofollow(&link), Err(Error::Symlink(_))));
        assert_eq!(std::fs::read(&real).unwrap(), b"x");
    }

    #[test]
    fn durable_remove_reports_presence() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("j");
        std::fs::write(&p, b"x").unwrap();
        assert!(remove_file_durable(&p).unwrap());
        assert!(!p.exists());
        assert!(!remove_file_durable(&p).unwrap());
    }

    #[test]
    fn read_missing_is_none() {
        let t = tempfile::tempdir().unwrap();
        assert!(read_nofollow(&t.path().join("nope")).unwrap().is_none());
    }
}
