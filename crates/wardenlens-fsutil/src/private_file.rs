//! Secure open of a SQLite file (ADR 0006 section 4). The `rusqlite` open stays in the callers.

use std::fs::File;
use std::path::Path;

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, Stat, fstat, openat, statat};
use rustix::io::Errno;

use crate::error::FsError;

/// Device and inode of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
}

impl FileIdentity {
    fn of(st: &Stat) -> Self {
        Self {
            dev: st.st_dev,
            ino: st.st_ino,
        }
    }
}

/// A checked, private, regular file opened without following symlinks.
///
/// Keep the descriptor open until [`PrivateFile::verify_path_unchanged`] has run: once it is
/// dropped the inode can be freed and the `(dev, ino)` pair reused by another file, which would
/// make the identity comparison meaningless.
#[derive(Debug)]
pub struct PrivateFile {
    file: File,
    identity: FileIdentity,
    created: bool,
}

impl PrivateFile {
    /// The descriptor we opened (read-only for an existing file).
    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Consume and return the descriptor.
    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }

    /// Device and inode recorded at open time.
    #[must_use]
    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// True if this call created the file.
    #[must_use]
    pub fn created(&self) -> bool {
        self.created
    }

    /// Post-open check: `lstat` the path again (after SQLite opened it) and compare device and
    /// inode with the descriptor checked at open time.
    ///
    /// # Errors
    /// [`FsError::IdentityMismatch`] if the path now names another file or a symlink.
    pub fn verify_path_unchanged(&self, path: &Path) -> Result<(), FsError> {
        if path_identity(path)? == self.identity {
            Ok(())
        } else {
            Err(FsError::IdentityMismatch)
        }
    }
}

/// Device and inode of `path` itself (`lstat`: a symlink reports its own identity, which then
/// never equals the identity of a checked regular file).
///
/// # Errors
/// A failed `lstat`.
pub fn path_identity(path: &Path) -> Result<FileIdentity, FsError> {
    let st = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(FsError::io("lstat"))?;
    Ok(FileIdentity::of(&st))
}

/// Open `path`, creating it with mode `0600` (`O_EXCL|O_NOFOLLOW`) if it is missing, then
/// `fstat` the descriptor: it must be a regular file, owned by the effective uid, with no group
/// or other permission bits and no setuid, setgid or sticky bit.
///
/// # Errors
/// Symlink (`ELOOP`), non-regular file, wrong owner, mode bits `& 0o7077`, or any I/O error.
pub fn open_private_file(path: &Path) -> Result<PrivateFile, FsError> {
    let (fd, created) = match open_existing(path) {
        Ok(fd) => (fd, false),
        Err(Errno::NOENT) => match create_new(path) {
            Ok(fd) => (fd, true),
            // Lost a creation race: the file exists now, so check it like any other.
            Err(Errno::EXIST) => (open_existing(path).map_err(FsError::io("open"))?, false),
            Err(e) => return Err(FsError::io("create")(e)),
        },
        Err(e) => return Err(FsError::io("open")(e)),
    };
    let st = fstat(&fd).map_err(FsError::io("fstat"))?;
    check_stat(&st)?;
    Ok(PrivateFile {
        file: File::from(fd),
        identity: FileIdentity::of(&st),
        created,
    })
}

fn open_existing(path: &Path) -> Result<rustix::fd::OwnedFd, Errno> {
    // O_NONBLOCK so that a planted FIFO cannot block the open; fstat then rejects it.
    openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

fn create_new(path: &Path) -> Result<rustix::fd::OwnedFd, Errno> {
    openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
}

fn check_stat(st: &Stat) -> Result<(), FsError> {
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(FsError::NotRegular);
    }
    let expected = rustix::process::geteuid().as_raw();
    if st.st_uid != expected {
        return Err(FsError::WrongOwner {
            found: st.st_uid,
            expected,
        });
    }
    if st.st_mode & 0o7077 != 0 {
        return Err(FsError::InsecureMode {
            mode: st.st_mode & 0o7777,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).map_or(0, |m| m.permissions().mode() & 0o777)
    }

    #[test]
    fn creates_missing_file_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("db");
        let f = open_private_file(&p).unwrap();
        assert!(f.created());
        assert_eq!(mode_of(&p), 0o600);
        f.verify_path_unchanged(&p).unwrap();
    }

    #[test]
    fn opens_existing_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("db");
        drop(open_private_file(&p).unwrap());
        let f = open_private_file(&p).unwrap();
        assert!(!f.created());
    }

    #[test]
    fn refuses_symlink_even_to_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        drop(open_private_file(&real).unwrap());
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let e = open_private_file(&link).unwrap_err();
        assert_eq!(e.errno(), Some(Errno::LOOP));
    }

    #[test]
    fn refuses_dangling_symlink_without_creating_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(open_private_file(&link).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn refuses_mode_0644() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("db");
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            open_private_file(&p),
            Err(FsError::InsecureMode { mode: 0o644 })
        ));
    }

    #[test]
    fn refuses_group_only_and_other_only_bits() {
        let dir = tempfile::tempdir().unwrap();
        for m in [0o640, 0o604, 0o660, 0o606] {
            let p = dir.path().join(format!("db{m:o}"));
            std::fs::write(&p, b"").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(m)).unwrap();
            assert!(
                matches!(open_private_file(&p), Err(FsError::InsecureMode { .. })),
                "{m:o}"
            );
        }
    }

    #[test]
    fn refuses_setuid_setgid_and_sticky_bits() {
        let dir = tempfile::tempdir().unwrap();
        for m in [0o4600, 0o2600, 0o1600] {
            let p = dir.path().join(format!("db{m:o}"));
            std::fs::write(&p, b"").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(m)).unwrap();
            assert!(
                matches!(open_private_file(&p), Err(FsError::InsecureMode { .. })),
                "{m:o}"
            );
        }
    }

    #[test]
    fn accepts_mode_0400() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("db");
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        open_private_file(&p).unwrap();
    }

    #[test]
    fn refuses_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            open_private_file(dir.path()),
            Err(FsError::NotRegular)
        ));
    }

    #[test]
    fn refuses_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fifo");
        rustix::fs::mknodat(CWD, &p, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        assert!(matches!(open_private_file(&p), Err(FsError::NotRegular)));
    }

    #[test]
    fn refuses_missing_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let e = open_private_file(&dir.path().join("nope").join("db")).unwrap_err();
        assert!(e.is_not_found());
    }

    #[test]
    fn detects_path_swapped_after_open() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("db");
        let f = open_private_file(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        drop(open_private_file(&p).unwrap());
        // A new file may reuse the inode number; a symlink swap is the reliable case.
        std::fs::remove_file(&p).unwrap();
        let other = dir.path().join("other");
        drop(open_private_file(&other).unwrap());
        symlink(&other, &p).unwrap();
        assert!(matches!(
            f.verify_path_unchanged(&p),
            Err(FsError::IdentityMismatch)
        ));
    }

    #[test]
    fn detects_path_removed_after_open() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("db");
        let f = open_private_file(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert!(f.verify_path_unchanged(&p).unwrap_err().is_not_found());
    }
}
