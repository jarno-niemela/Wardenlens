//! `RootDir`: a directory handle with kernel-enforced containment (ADR 0005 sections 3, 7, 8).

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags, Stat, StatVfsMountFlags, fstat,
    fstatvfs, fsync, mkdirat, openat, openat2, renameat_with, unlinkat,
};

use crate::error::FsError;

/// Kind of a file system object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileKind {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Anything else (FIFO, device, socket).
    Other,
}

/// The parts of `fstat` the callers use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileStat {
    /// Object kind.
    pub kind: FileKind,
    /// Size in bytes.
    pub size: u64,
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Owner uid.
    pub uid: u32,
    /// Permission bits (`mode & 0o7777`).
    pub mode: u32,
}

impl FileStat {
    fn from_stat(st: &Stat) -> Self {
        let kind = match FileType::from_raw_mode(st.st_mode) {
            FileType::RegularFile => FileKind::Regular,
            FileType::Directory => FileKind::Directory,
            FileType::Symlink => FileKind::Symlink,
            _ => FileKind::Other,
        };
        Self {
            kind,
            size: u64::try_from(st.st_size).unwrap_or(0),
            dev: st.st_dev,
            ino: st.st_ino,
            uid: st.st_uid,
            mode: st.st_mode & 0o7777,
        }
    }
}

/// The parts of `fstatvfs` the volume probe uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeStat {
    /// Fragment size in bytes.
    pub block_size: u64,
    /// Total blocks.
    pub blocks: u64,
    /// Blocks available to unprivileged users.
    pub blocks_available: u64,
    /// The volume is mounted read-only (`ST_RDONLY`).
    pub read_only: bool,
}

/// A regular file opened for reading, with the length from `fstat` of the same descriptor.
#[derive(Debug)]
pub struct ReadFile {
    /// The read-only descriptor.
    pub file: File,
    /// Its length in bytes.
    pub len: u64,
}

/// An owned directory descriptor. Children are opened with `openat2`
/// (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`); mutations take exactly one path component.
#[derive(Debug)]
pub struct RootDir {
    fd: OwnedFd,
}

/// Check one path component: non-empty, not `.` or `..`, no `/`, no NUL.
pub(crate) fn component(c: &str) -> Result<&str, FsError> {
    if c.is_empty() || c == "." || c == ".." || c.contains(['/', '\0']) {
        Err(FsError::InvalidComponent)
    } else {
        Ok(c)
    }
}

/// Join validated components with `/` (the result is relative and cannot contain `..`).
fn join<S: AsRef<str>>(comps: &[S]) -> Result<String, FsError> {
    if comps.is_empty() {
        return Err(FsError::InvalidComponent);
    }
    let mut out = String::new();
    for (i, c) in comps.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(component(c.as_ref())?);
    }
    Ok(out)
}

const BENEATH: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS);

impl RootDir {
    /// Open `path` as a directory handle (`O_DIRECTORY | O_NOFOLLOW`). Intermediate components
    /// of `path` are resolved normally (operator configuration), but the final component must
    /// not be a symlink (ADR 0005 section 8).
    ///
    /// Recommendation: mount the recordings volumes `nodev,nosuid,noexec`. A read open of a
    /// device node runs the driver's open routine before `fstat` can refuse it; the volume
    /// probe ticket is where this is enforced.
    ///
    /// # Errors
    /// A failed `open` (`ELOOP` for a symlinked root), or the path is not a directory.
    pub fn open(path: &Path) -> Result<Self, FsError> {
        let fd = openat(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(FsError::io("open root"))?;
        Ok(Self { fd })
    }

    /// Duplicate this handle.
    ///
    /// # Errors
    /// `dup` failure.
    pub fn try_clone(&self) -> Result<Self, FsError> {
        let fd = self.fd.try_clone().map_err(|e| FsError::Io {
            op: "dup",
            source: rustix::io::Errno::from_io_error(&e).unwrap_or(rustix::io::Errno::INVAL),
        })?;
        Ok(Self { fd })
    }

    /// Open the child directory named by `comps` (one or more components) beneath this one.
    ///
    /// # Errors
    /// [`FsError::InvalidComponent`] before any syscall, or the kernel's refusal (`ELOOP` for a
    /// symlink, `EXDEV` for an escape, `ENOENT`, ...), or `ENOTDIR`.
    pub fn open_dir<S: AsRef<str>>(&self, comps: &[S]) -> Result<Self, FsError> {
        let rel = join(comps)?;
        let fd = openat2(
            &self.fd,
            rel.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            BENEATH,
        )
        .map_err(FsError::io("open dir"))?;
        Ok(Self { fd })
    }

    /// Open the regular file named by `comps` for reading. Mount recordings volumes
    /// `nodev,nosuid,noexec`: a read open of a device node runs the driver's open routine
    /// before the `fstat` below refuses it. `O_NONBLOCK` keeps a planted FIFO
    /// from blocking; the descriptor is then `fstat`ed and anything but a regular file is
    /// refused.
    ///
    /// # Errors
    /// Invalid component, kernel refusal, or [`FsError::NotRegular`].
    pub fn open_read<S: AsRef<str>>(&self, comps: &[S]) -> Result<ReadFile, FsError> {
        let rel = join(comps)?;
        let fd = openat2(
            &self.fd,
            rel.as_str(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
            BENEATH,
        )
        .map_err(FsError::io("open file"))?;
        let st = FileStat::from_stat(&fstat(&fd).map_err(FsError::io("fstat"))?);
        if st.kind != FileKind::Regular {
            return Err(FsError::NotRegular);
        }
        Ok(ReadFile {
            file: File::from(fd),
            len: st.size,
        })
    }

    /// Create the directory `name` (mode `0700`) in this directory.
    ///
    /// # Errors
    /// Invalid component, or `mkdirat` failure (`EEXIST` included).
    pub fn mkdir(&self, name: &str) -> Result<(), FsError> {
        mkdirat(&self.fd, component(name)?, Mode::RWXU).map_err(FsError::io("mkdir"))
    }

    /// Remove the file `name` from this directory.
    ///
    /// # Errors
    /// Invalid component, or `unlinkat` failure.
    pub fn unlink(&self, name: &str) -> Result<(), FsError> {
        unlinkat(&self.fd, component(name)?, AtFlags::empty()).map_err(FsError::io("unlink"))
    }

    /// Rename `from` in this directory to `to` in `to_dir`, failing with `EEXIST` rather than
    /// replacing anything (`RENAME_NOREPLACE`).
    ///
    /// # Errors
    /// Invalid component, or `renameat2` failure.
    pub fn rename_noreplace(&self, from: &str, to_dir: &Self, to: &str) -> Result<(), FsError> {
        renameat_with(
            &self.fd,
            component(from)?,
            &to_dir.fd,
            component(to)?,
            RenameFlags::NOREPLACE,
        )
        .map_err(FsError::io("rename"))
    }

    /// `fsync` this directory (after creating, renaming or unlinking an entry in it).
    ///
    /// # Errors
    /// `fsync` failure.
    pub fn sync(&self) -> Result<(), FsError> {
        fsync(&self.fd).map_err(FsError::io("fsync dir"))
    }

    /// `fstat` this directory handle.
    ///
    /// # Errors
    /// `fstat` failure.
    pub fn stat(&self) -> Result<FileStat, FsError> {
        Ok(FileStat::from_stat(
            &fstat(&self.fd).map_err(FsError::io("fstat"))?,
        ))
    }

    /// `fstatvfs` this directory handle (volume probe, including the read-only flag).
    ///
    /// # Errors
    /// `fstatvfs` failure.
    pub fn statvfs(&self) -> Result<VolumeStat, FsError> {
        let v = fstatvfs(&self.fd).map_err(FsError::io("fstatvfs"))?;
        Ok(VolumeStat {
            block_size: v.f_frsize,
            blocks: v.f_blocks,
            blocks_available: v.f_bavail,
            read_only: v.f_flag.contains(StatVfsMountFlags::RDONLY),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    fn setup() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    #[test]
    fn rejects_bad_components_before_any_syscall() {
        let (_d, root) = setup();
        for bad in ["", ".", "..", "a/b", "/abs", "a\0b", "../x"] {
            assert!(
                matches!(root.mkdir(bad), Err(FsError::InvalidComponent)),
                "{bad:?}"
            );
            assert!(
                matches!(root.unlink(bad), Err(FsError::InvalidComponent)),
                "{bad:?}"
            );
            assert!(
                matches!(root.open_read(&[bad]), Err(FsError::InvalidComponent)),
                "{bad:?}"
            );
            assert!(
                matches!(root.open_dir(&[bad]), Err(FsError::InvalidComponent)),
                "{bad:?}"
            );
            assert!(matches!(
                root.rename_noreplace(bad, &root, "x"),
                Err(FsError::InvalidComponent)
            ));
            assert!(matches!(
                root.rename_noreplace("x", &root, bad),
                Err(FsError::InvalidComponent)
            ));
        }
        let none: [&str; 0] = [];
        assert!(matches!(
            root.open_read(&none),
            Err(FsError::InvalidComponent)
        ));
    }

    #[test]
    fn reads_nested_regular_file_with_length() {
        let (d, root) = setup();
        std::fs::create_dir_all(d.path().join("cam/day")).unwrap();
        std::fs::write(d.path().join("cam/day/f.mp4"), b"hello").unwrap();
        let mut r = root.open_read(&["cam", "day", "f.mp4"]).unwrap();
        assert_eq!(r.len, 5);
        let mut s = String::new();
        r.file.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn refuses_symlinked_file() {
        let (d, root) = setup();
        std::fs::write(d.path().join("real"), b"x").unwrap();
        symlink(d.path().join("real"), d.path().join("link")).unwrap();
        let e = root.open_read(&["link"]).unwrap_err();
        assert_eq!(e.errno(), Some(rustix::io::Errno::LOOP));
    }

    #[test]
    fn refuses_symlinked_intermediate_directory() {
        let (d, root) = setup();
        std::fs::create_dir(d.path().join("real")).unwrap();
        std::fs::write(d.path().join("real/f"), b"x").unwrap();
        symlink(d.path().join("real"), d.path().join("link")).unwrap();
        let loop_ = Some(rustix::io::Errno::LOOP);
        assert_eq!(root.open_read(&["link", "f"]).unwrap_err().errno(), loop_);
        assert_eq!(root.open_dir(&["link"]).unwrap_err().errno(), loop_);
    }

    #[test]
    fn refuses_symlink_escaping_the_root() {
        let (d, root) = setup();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"x").unwrap();
        symlink(outside.path(), d.path().join("out")).unwrap();
        let errno = root.open_read(&["out", "secret"]).unwrap_err().errno();
        assert!(
            errno == Some(rustix::io::Errno::LOOP) || errno == Some(rustix::io::Errno::XDEV),
            "{errno:?}"
        );
    }

    #[test]
    fn open_of_fifo_does_not_block_and_is_refused() {
        let (d, root) = setup();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            d.path().join("fifo"),
            FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(matches!(
            root.open_read(&["fifo"]),
            Err(FsError::NotRegular)
        ));
    }

    #[test]
    fn open_dir_refuses_a_regular_file() {
        let (d, root) = setup();
        std::fs::write(d.path().join("f"), b"x").unwrap();
        assert_eq!(
            root.open_dir(&["f"]).unwrap_err().errno(),
            Some(rustix::io::Errno::NOTDIR)
        );
    }

    #[test]
    fn open_root_refuses_a_regular_file() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f"), b"x").unwrap();
        assert!(RootDir::open(&d.path().join("f")).is_err());
    }

    #[test]
    fn rename_noreplace_refuses_existing_target() {
        let (d, root) = setup();
        std::fs::write(d.path().join("a"), b"a").unwrap();
        std::fs::write(d.path().join("b"), b"b").unwrap();
        let e = root.rename_noreplace("a", &root, "b").unwrap_err();
        assert_eq!(e.errno(), Some(rustix::io::Errno::EXIST));
        assert_eq!(std::fs::read(d.path().join("b")).unwrap(), b"b");
        assert!(d.path().join("a").exists());
        root.rename_noreplace("a", &root, "c").unwrap();
        assert!(!d.path().join("a").exists());
        assert_eq!(std::fs::read(d.path().join("c")).unwrap(), b"a");
    }

    #[test]
    fn mkdir_unlink_and_sync_work() {
        let (d, root) = setup();
        root.mkdir("sub").unwrap();
        assert!(d.path().join("sub").is_dir());
        assert_eq!(
            root.mkdir("sub").unwrap_err().errno(),
            Some(rustix::io::Errno::EXIST)
        );
        let sub = root.open_dir(&["sub"]).unwrap();
        std::fs::write(d.path().join("sub/f"), b"x").unwrap();
        sub.unlink("f").unwrap();
        sub.sync().unwrap();
        assert!(!d.path().join("sub/f").exists());
        assert!(sub.unlink("f").unwrap_err().is_not_found());
    }

    #[test]
    fn stat_and_statvfs_report_the_directory() {
        let (_d, root) = setup();
        let st = root.stat().unwrap();
        assert_eq!(st.kind, FileKind::Directory);
        let v = root.statvfs().unwrap();
        assert!(v.blocks > 0 && v.block_size > 0);
        assert!(v.blocks_available <= v.blocks);
    }
}
