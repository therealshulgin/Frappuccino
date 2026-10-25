//! Durable replacement of a file.
//!
//! The new content is written to a sibling `<name>.part`, flushed to storage
//! (`sync_all`), renamed over the destination, and then the directory entry is
//! flushed too. A reader therefore finds either the old file or the complete
//! new one, never a prefix, and a caller that deletes the only other copy of
//! the data after a success does not lose it to a power cut.
//!
//! On an error before the rename, the `.part` is removed (best effort) and the
//! destination is untouched. An error of the directory flush comes after the
//! rename, when the old content is already gone and the new one is complete
//! and flushed; what is left at the destination then is the caller's choice
//! ([`OnDirSyncError`]): a file whose source stays available elsewhere is
//! removed, so nothing is left behind; a file that is the only copy of its
//! data is kept. A `.part` left by a crash is for the owner of the directory
//! to sweep.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Suffix of the temporary sibling a durable write goes through.
pub const PART_SUFFIX: &str = ".part";

/// `<path>.part`, or `None` when `path` has no file name.
#[must_use]
pub fn part_path(path: &Path) -> Option<PathBuf> {
    let mut name = path.file_name()?.to_os_string();
    name.push(PART_SUFFIX);
    Some(path.with_file_name(name))
}

/// What [`write_durably`] leaves at the destination when the rename succeeded
/// but the flush of the directory entry failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnDirSyncError {
    /// Remove the renamed file, so nothing is left at the destination. For a
    /// file whose source stays available (an envelope beside the file it was
    /// sealed from, a download that can be fetched again).
    RemoveDestination,
    /// Keep the renamed file. For a file that replaced the only copy of its
    /// data: the old content is gone, so removing the new one would leave
    /// neither. The file is complete and flushed; only its directory entry
    /// may not survive a power cut, after which the old content (or no file,
    /// if there was none) is what storage holds.
    KeepDestination,
}

/// Replace `path` durably with whatever `write` puts into a fresh file.
///
/// # Errors
/// Any I/O error of the create, the write, the flush, the rename or the
/// directory flush; `InvalidInput` if `path` has no file name. After an error
/// of the directory flush, the destination holds the new content or nothing,
/// as `on_dir_sync_error` says.
pub fn write_durably(
    path: &Path,
    on_dir_sync_error: OnDirSyncError,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let part = part_path(path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let written = File::create(&part).and_then(|mut file| {
        write(&mut file)?;
        file.sync_all()
    });
    if let Err(error) = written.and_then(|()| std::fs::rename(&part, path)) {
        let _ = std::fs::remove_file(&part);
        return Err(error);
    }
    if let Err(error) = sync_parent_dir(path) {
        if on_dir_sync_error == OnDirSyncError::RemoveDestination {
            let _ = std::fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(())
}

/// Flush the directory entry of `path` to storage.
///
/// On Unix (the Android target) the parent directory is opened and synced.
/// Elsewhere this is a no-op: a directory cannot be opened as a `File` there,
/// and the platforms this crate ships on are Unix.
///
/// # Errors
/// The I/O error of opening or syncing the directory.
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("frap_durable_{}_{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn part_path_appends_the_suffix() {
        assert_eq!(
            part_path(Path::new("a/b/x.fqe")).unwrap(),
            PathBuf::from("a/b/x.fqe.part")
        );
        assert!(part_path(Path::new("")).is_none());
    }

    #[test]
    fn replaces_the_destination_and_leaves_no_part() {
        let dir = scratch_dir("ok");
        let dest = dir.join("x.fqe");
        std::fs::write(&dest, b"old").unwrap();
        write_durably(&dest, OnDirSyncError::RemoveDestination, |file| {
            file.write_all(b"new content")
        })
        .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new content");
        assert!(!part_path(&dest).unwrap().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failing_writer_leaves_the_destination_untouched() {
        let dir = scratch_dir("fail");
        let dest = dir.join("x.fqe");
        std::fs::write(&dest, b"old").unwrap();
        let error = write_durably(&dest, OnDirSyncError::KeepDestination, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("disk full"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "disk full");
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert!(!part_path(&dest).unwrap().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_directory_is_an_error_not_a_panic() {
        let dest = std::env::temp_dir()
            .join(format!("frap_durable_absent_{}", std::process::id()))
            .join("x.fqe");
        assert!(
            write_durably(&dest, OnDirSyncError::RemoveDestination, |file| file
                .write_all(b"x"))
            .is_err()
        );
        assert!(write_durably(Path::new(""), OnDirSyncError::KeepDestination, |_| Ok(())).is_err());
    }

    /// Make the directory flush fail AFTER a successful rename: a directory
    /// in mode 0o300 lets a non-root user create, rename and unlink in it, but
    /// not open it. Returns `false` when the process can open it anyway (root),
    /// in which case the failure cannot be provoked this way.
    #[cfg(unix)]
    fn deny_directory_open(dir: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o300)).unwrap();
        File::open(dir).is_err()
    }

    #[cfg(unix)]
    fn allow_directory_open(dir: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_directory_flush_keeps_or_removes_the_renamed_file_as_asked() {
        for (mode, kept) in [
            (OnDirSyncError::KeepDestination, true),
            (OnDirSyncError::RemoveDestination, false),
        ] {
            let dir = scratch_dir(&format!("dirsync_{kept}"));
            let dest = dir.join("state.bin");
            std::fs::write(&dest, b"old").unwrap();
            if !deny_directory_open(&dir) {
                allow_directory_open(&dir);
                eprintln!("skip: the directory still opens (running as root?)");
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
            let outcome = write_durably(&dest, mode, |file| file.write_all(b"new"));
            allow_directory_open(&dir);
            assert!(outcome.is_err(), "the directory flush must have failed");
            assert!(!part_path(&dest).unwrap().exists());
            if kept {
                // The old content is gone either way: the new one stays.
                assert_eq!(std::fs::read(&dest).unwrap(), b"new");
            } else {
                assert!(!dest.exists());
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
