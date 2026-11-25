//! Open an untrusted path as a regular file for reading (the CLI's config file, SEC-2).

use std::fs::File;
use std::path::Path;

use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
use rustix::io::Errno;

use crate::error::FsError;
use crate::root::FileStat;

/// Open `path` read-only and return the descriptor with its `fstat`.
///
/// The last path component is opened with `O_NOFOLLOW`: a symlink, dangling or not, is refused
/// with [`FsError::Symlink`] (a symlink in a parent directory is followed; a loop there is a
/// plain `ELOOP` I/O error).
/// `O_NONBLOCK` keeps a planted FIFO from blocking the open, `O_NOCTTY` keeps a terminal device
/// from becoming the controlling terminal; the descriptor is then `fstat`ed and anything but a
/// regular file (directory, FIFO, device, socket) is refused with [`FsError::NotRegular`].
/// Ownership and mode are not checked; the caller reads `FileStat::mode` and `uid` if it cares.
///
/// # Errors
/// A failed `open` or `fstat` (`ENOENT`, `EACCES`, `ELOOP`, ...), or [`FsError::NotRegular`].
pub fn open_regular_nofollow(path: &Path) -> Result<(File, FileStat), FsError> {
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        // ELOOP also comes from a loop in a parent directory; only a symlink as the last
        // component is a symlink refusal.
        if e == Errno::LOOP && std::fs::symlink_metadata(path).is_ok_and(|m| m.is_symlink()) {
            FsError::Symlink
        } else {
            FsError::io("open")(e)
        }
    })?;
    let st = fstat(&fd).map_err(FsError::io("fstat"))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(FsError::NotRegular);
    }
    Ok((File::from(fd), FileStat::from_stat(&st)))
}

/// True if `e` says the last path component is a symlink (not merely an `ELOOP` from a parent).
#[must_use]
pub fn is_symlink_refusal(e: &FsError) -> bool {
    matches!(e, FsError::Symlink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn opens_a_regular_file_and_reports_mode_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"abc").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let (mut f, st) = open_regular_nofollow(&p).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "abc");
        assert_eq!((st.size, st.mode), (3, 0o640));
    }

    #[test]
    fn refuses_symlinks_dangling_or_not() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"x").unwrap();
        let ok = dir.path().join("ok");
        let dangling = dir.path().join("dangling");
        symlink(&real, &ok).unwrap();
        symlink(dir.path().join("none"), &dangling).unwrap();
        for l in [ok, dangling] {
            let e = open_regular_nofollow(&l).unwrap_err();
            assert!(is_symlink_refusal(&e), "{e}");
        }
    }

    #[test]
    fn refuses_directory_fifo_and_device_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        for p in [dir.path(), fifo.as_path(), Path::new("/dev/null")] {
            assert!(matches!(open_regular_nofollow(p), Err(FsError::NotRegular)));
        }
    }

    #[test]
    fn missing_file_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let e = open_regular_nofollow(&dir.path().join("none")).unwrap_err();
        assert!(e.is_not_found());
    }
}
