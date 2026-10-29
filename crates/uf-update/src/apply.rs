//! Swapping the exe on disk. Windows lets a running exe be renamed but not
//! overwritten, so the current file moves aside to `<exe>.old` and the new one
//! takes its name; `.old` is removed on a later launch once nothing runs it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::Error;

fn with_suffix(exe: &Path, suffix: &str) -> PathBuf {
    let mut s = OsString::from(exe.as_os_str());
    s.push(suffix);
    s.into()
}

/// Where the replaced exe is parked.
pub fn old_path(exe: &Path) -> PathBuf {
    with_suffix(exe, ".old")
}

/// Whether an installed update waits for a restart: a parked exe is still
/// running (a stale, unused one is removed by the next [`swap`]).
pub fn restart_pending() -> bool {
    std::env::current_exe().is_ok_and(|exe| in_use(&old_path(&exe)))
}

/// Whether `path` exists and some process holds it open (a running image
/// refuses an exclusive open).
#[cfg(windows)]
fn in_use(path: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    path.exists()
        && fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .is_err()
}

#[cfg(not(windows))]
fn in_use(path: &Path) -> bool {
    path.exists()
}

/// Best-effort removal of leftovers from an earlier update.
pub fn cleanup() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = fs::remove_file(old_path(&exe));
        let _ = fs::remove_file(with_suffix(&exe, ".new"));
    }
}

/// Puts `new_exe` at `target`, keeping the previous file as `<target>.old`.
/// On failure `target` is left as it was.
pub fn swap(target: &Path, new_exe: &[u8]) -> Result<(), Error> {
    let old = old_path(target);
    let new = with_suffix(target, ".new");
    if old.exists() && fs::remove_file(&old).is_err() {
        // the previously replaced exe still runs
        return Err(Error::RestartPending);
    }
    fs::write(&new, new_exe).map_err(Error::Io)?;
    let undo = |e: io::Error| {
        let _ = fs::remove_file(&new);
        Error::Io(e)
    };
    fs::rename(target, &old).map_err(undo)?;
    if let Err(e) = fs::rename(&new, target) {
        let _ = fs::rename(&old, target);
        return Err(undo(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_replaces_and_parks_the_old_file() {
        let dir = std::env::temp_dir().join(format!("uf-update-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("unfilter.exe");
        fs::write(&exe, b"v1").unwrap();
        swap(&exe, b"v2").unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"v2");
        assert_eq!(fs::read(old_path(&exe)).unwrap(), b"v1");
        // a stale, removable .old does not block the next update
        swap(&exe, b"v3").unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"v3");
        assert_eq!(fs::read(old_path(&exe)).unwrap(), b"v2");
        assert!(!with_suffix(&exe, ".new").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failed_swap_leaves_target_alone() {
        let dir = std::env::temp_dir().join(format!("uf-update-miss-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("missing.exe");
        assert!(matches!(swap(&exe, b"v2"), Err(Error::Io(_))));
        assert!(!exe.exists() && !with_suffix(&exe, ".new").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
