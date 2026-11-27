//! `RootDir`: a directory handle with kernel-enforced containment (ADR 0005 sections 3, 7, 8).

use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags, Stat, StatVfsMountFlags, fstat,
    fstatvfs, fsync, mkdirat, openat, openat2, renameat_with, unlinkat,
};

use rustix::io::Errno;

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
    /// Bytes allocated on the volume (`st_blocks * 512`); less than `size` for a sparse file.
    pub allocated: u64,
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
    pub(crate) fn from_stat(st: &Stat) -> Self {
        let kind = match FileType::from_raw_mode(st.st_mode) {
            FileType::RegularFile => FileKind::Regular,
            FileType::Directory => FileKind::Directory,
            FileType::Symlink => FileKind::Symlink,
            _ => FileKind::Other,
        };
        Self {
            kind,
            size: u64::try_from(st.st_size).unwrap_or(0),
            allocated: u64::try_from(st.st_blocks).unwrap_or(0).saturating_mul(512),
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
    /// Free blocks, including those reserved for root (`f_bfree`).
    pub blocks_free: u64,
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
    /// Bytes allocated on the volume (`st_blocks * 512`): less than `len` for a sparse file, and
    /// more for a small one (whole blocks), which is what deleting the file frees.
    pub allocated: u64,
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DirEntry {
    /// The entry name (a single component; names that are not UTF-8 are skipped by [`RootDir::list`]).
    pub name: String,
    /// The kind reported by the directory entry (`Other` when the filesystem does not say).
    pub kind: FileKind,
}

/// The result of [`RootDir::list`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Listing {
    /// The entries with a usable name.
    pub entries: Vec<DirEntry>,
    /// Entries seen but not returned: names that are not UTF-8 or not a valid single component.
    /// They still count against the caller's bound.
    pub dropped: usize,
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
    /// Open `path` as a directory handle. The path is split structurally into a parent and a
    /// last segment: trailing `/` characters are stripped first, so `link`, `link/`, `link//`
    /// and `link/.` all name the same last segment as far as the check is concerned. The parent
    /// is opened normally (it is operator configuration, symlinks in it are followed), then the
    /// last segment is opened with `openat(parent, last, O_DIRECTORY | O_NOFOLLOW)`. A symlink
    /// in the last position is therefore refused whatever the spelling of the path (ADR 0005
    /// section 8).
    ///
    /// The path is refused with [`FsError::InvalidComponent`] if it is empty, consists only of
    /// slashes (the filesystem root `/` is refused: a recordings root is never `/`), or its last
    /// segment is `.`, `..`, or not valid UTF-8.
    ///
    /// Recommendation: mount the recordings volumes `nodev,nosuid,noexec`. A read open of a
    /// device node runs the driver's open routine before `fstat` can refuse it; the volume
    /// probe ticket is where this is enforced.
    ///
    /// # Errors
    /// [`FsError::InvalidComponent`] as above, or a failed `open` (for a symlink as last segment
    /// the kernel reports an errno such as `ENOTDIR` or `ELOOP`; callers must not depend on which),
    /// or the path is not a directory.
    pub fn open(path: &Path) -> Result<Self, FsError> {
        let mut bytes = path.as_os_str().as_bytes();
        while let Some(rest) = bytes.strip_suffix(b"/") {
            bytes = rest;
        }
        let (parent, last): (&[u8], &[u8]) = match bytes.iter().rposition(|&b| b == b'/') {
            // `split_at(i)` leaves the slash at the head of `tail`; `split_first` drops it.
            Some(i) => {
                let (head, tail) = bytes.split_at(i);
                (
                    if head.is_empty() { b"/" } else { head },
                    tail.split_first().map_or(&[][..], |(_, t)| t),
                )
            }
            None => (b".", bytes),
        };
        let last = std::str::from_utf8(last).map_err(|_| FsError::InvalidComponent)?;
        let last = component(last)?;
        let parent_fd = openat(
            rustix::fs::CWD,
            Path::new(OsStr::from_bytes(parent)),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(FsError::io("open root parent"))?;
        let fd = openat(
            &parent_fd,
            last,
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
            allocated: st.allocated,
        })
    }

    /// Create the regular file `name` (mode `0600`) in this directory with `O_CREAT | O_EXCL |
    /// O_NOFOLLOW`, for writing. An existing entry of any kind (a symlink included) is `EEXIST`.
    ///
    /// # Errors
    /// Invalid component, or the `openat` failure.
    pub fn create_new(&self, name: &str) -> Result<File, FsError> {
        let fd = openat(
            &self.fd,
            component(name)?,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NOCTTY
                | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(FsError::io("create file"))?;
        Ok(File::from(fd))
    }

    /// List this directory: at most `max` entries (`.` and `..` excluded). Names that are not
    /// UTF-8 or not a valid single component are not returned but are counted, both against
    /// `max` and in [`Listing::dropped`].
    ///
    /// # Errors
    /// The directory cannot be read, or it holds more than `max` entries ([`FsError::TooManyEntries`]).
    pub fn list(&self, max: usize) -> Result<Listing, FsError> {
        let mut dir = rustix::fs::Dir::read_from(&self.fd).map_err(FsError::io("read dir"))?;
        let mut out = Vec::new();
        let mut dropped: usize = 0;
        let mut seen: usize = 0;
        while let Some(entry) = dir.read() {
            let entry = entry.map_err(FsError::io("read dir"))?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            seen = seen.saturating_add(1);
            if seen > max {
                return Err(FsError::TooManyEntries);
            }
            let Some(name) = std::str::from_utf8(raw)
                .ok()
                .filter(|n| component(n).is_ok())
            else {
                dropped = dropped.saturating_add(1);
                continue;
            };
            let kind = match entry.file_type() {
                FileType::RegularFile => FileKind::Regular,
                FileType::Directory => FileKind::Directory,
                FileType::Symlink => FileKind::Symlink,
                _ => FileKind::Other,
            };
            out.push(DirEntry {
                name: name.to_owned(),
                kind,
            });
        }
        Ok(Listing {
            entries: out,
            dropped,
        })
    }

    /// Check that the entry named by `comps` is a regular file, without opening it for reading:
    /// an `O_PATH` descriptor needs no read permission, does not update `atime` and does not
    /// run a device's open routine. Symlinks anywhere are refused by the kernel.
    ///
    /// # Errors
    /// Invalid component, kernel refusal, or [`FsError::NotRegular`].
    pub(crate) fn ensure_regular<S: AsRef<str>>(&self, comps: &[S]) -> Result<(), FsError> {
        let rel = join(comps)?;
        let fd = openat2(
            &self.fd,
            rel.as_str(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            BENEATH,
        )
        .map_err(FsError::io("open path"))?;
        let st = FileStat::from_stat(&fstat(&fd).map_err(FsError::io("fstat"))?);
        if st.kind == FileKind::Regular {
            Ok(())
        } else {
            Err(FsError::NotRegular)
        }
    }

    /// Whether anything is named `name` in this directory (one component): a regular file, a directory,
    /// a FIFO, a device node or a symlink all count as "there". The entry is opened with
    /// `O_PATH`, so nothing is read, no device routine runs, no read permission is needed on the
    /// file, and `atime` does not change; `RESOLVE_NO_SYMLINKS` makes a symlink answer
    /// `ELOOP`, which is "there" too (the link itself exists; with one component it cannot be a
    /// parent).
    ///
    /// # Errors
    /// Invalid component, or a kernel refusal other than `ENOENT` and `ELOOP` (for example
    /// `EACCES` on this directory): the answer is unknown and the caller must not assume the name
    /// is free.
    pub fn exists(&self, name: &str) -> Result<bool, FsError> {
        match openat2(
            &self.fd,
            component(name)?,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            BENEATH,
        ) {
            Ok(_) | Err(Errno::LOOP) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(e) => Err(FsError::io("open path")(e)),
        }
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
            blocks_free: v.f_bfree,
            blocks_available: v.f_bavail,
            read_only: v.f_flag.contains(StatVfsMountFlags::RDONLY),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
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

    #[test]
    fn open_refuses_symlinked_root_in_every_spelling() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("real")).unwrap();
        symlink(d.path().join("real"), d.path().join("link")).unwrap();
        let link = d.path().join("link");
        for suffix in ["", "/", "//", "/.", "/.."] {
            let mut p = link.clone().into_os_string();
            p.push(suffix);
            assert!(RootDir::open(Path::new(&p)).is_err(), "{suffix:?}");
        }
    }

    #[test]
    fn open_accepts_real_directory_with_and_without_trailing_slash() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("real")).unwrap();
        let real = d.path().join("real");
        let ino = std::fs::metadata(&real).unwrap().ino();
        for suffix in ["", "/", "//"] {
            let mut p = real.clone().into_os_string();
            p.push(suffix);
            let root = RootDir::open(Path::new(&p)).unwrap();
            assert_eq!(root.stat().unwrap().ino, ino, "{suffix:?}");
        }
    }

    #[test]
    fn open_refuses_degenerate_paths() {
        for p in ["", "/", "//", ".", "..", "a/..", "a/."] {
            assert!(RootDir::open(Path::new(p)).is_err(), "{p:?}");
        }
        assert!(matches!(
            RootDir::open(Path::new("/")),
            Err(FsError::InvalidComponent)
        ));
    }

    #[test]
    fn open_resolves_a_bare_relative_name_against_cwd() {
        // Parent "." for a single segment: a missing name is a plain ENOENT, not a refusal.
        let e = RootDir::open(Path::new("definitely-missing-wardenlens-dir")).unwrap_err();
        assert!(e.is_not_found());
    }

    #[test]
    fn ensure_regular_needs_no_read_permission() {
        use std::os::unix::fs::PermissionsExt;
        let (d, root) = setup();
        std::fs::write(d.path().join("f"), b"x").unwrap();
        std::fs::set_permissions(d.path().join("f"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        root.ensure_regular(&["f"]).unwrap();
        std::fs::create_dir(d.path().join("dir")).unwrap();
        assert!(matches!(
            root.ensure_regular(&["dir"]),
            Err(FsError::NotRegular)
        ));
    }

    #[test]
    fn create_new_is_exclusive_private_and_refuses_symlinks() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let (d, root) = setup();
        let mut f = root.create_new("f.part").unwrap();
        f.write_all(b"x").unwrap();
        let mode = std::fs::metadata(d.path().join("f.part"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "never group or other access, whatever the umask"
        );
        assert_eq!(
            root.create_new("f.part").unwrap_err().errno(),
            Some(rustix::io::Errno::EXIST)
        );
        symlink(d.path().join("elsewhere"), d.path().join("dangling")).unwrap();
        assert_eq!(
            root.create_new("dangling").unwrap_err().errno(),
            Some(rustix::io::Errno::EXIST),
            "O_EXCL refuses a dangling symlink and does not create its target"
        );
        assert!(!d.path().join("elsewhere").exists());
        for bad in ["", ".", "..", "a/b"] {
            assert!(matches!(
                root.create_new(bad),
                Err(FsError::InvalidComponent)
            ));
        }
    }

    #[test]
    fn list_reports_names_and_kinds_and_enforces_the_bound() {
        let (d, root) = setup();
        std::fs::write(d.path().join("a"), b"x").unwrap();
        std::fs::create_dir(d.path().join("b")).unwrap();
        symlink(d.path().join("a"), d.path().join("c")).unwrap();
        let mut got = root.list(10).unwrap().entries;
        got.sort_by(|x, y| x.name.cmp(&y.name));
        let kinds: Vec<_> = got.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert_eq!(
            kinds,
            [
                ("a", FileKind::Regular),
                ("b", FileKind::Directory),
                ("c", FileKind::Symlink)
            ]
        );
        assert_eq!(
            root.list(2).unwrap_err().to_string(),
            FsError::TooManyEntries.to_string()
        );
        assert_eq!(root.list(3).unwrap().entries.len(), 3);
        // A name that is not UTF-8 is counted (against the bound and as dropped), not returned.
        std::fs::write(
            d.path().join(std::ffi::OsStr::from_bytes(b"\xff-odd")),
            b"x",
        )
        .unwrap();
        let l = root.list(4).unwrap();
        assert_eq!((l.entries.len(), l.dropped), (3, 1));
        assert!(
            root.list(3).is_err(),
            "the dropped name counts against the bound"
        );
    }
}
