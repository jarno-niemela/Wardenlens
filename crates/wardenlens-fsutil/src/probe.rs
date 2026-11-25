//! Shared pieces of the read-only identity probes of SQLite files (defect pattern P3): the parent
//! directory check, the sidecar check, a private scratch directory, a bounded copy and the
//! `immutable=1` URI. None of them opens SQLite or writes to the file under test.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{AtFlags, CWD, Mode, OFlags, statat};
use rustix::io::Errno;

use crate::error::FsError;
use crate::private_file::check_stat;

/// The parent directory must be owned by the effective user and not writable by group or others,
/// or another user could plant or swap files between our checks.
///
/// # Errors
/// [`FsError::ParentWrongOwner`], [`FsError::ParentWritable`] or a failed `stat`.
pub fn check_parent(parent: &Path) -> Result<(), FsError> {
    let meta = std::fs::metadata(parent).map_err(FsError::io_err("inspecting directory"))?;
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(FsError::ParentWrongOwner);
    }
    if meta.mode() & 0o022 != 0 {
        return Err(FsError::ParentWritable);
    }
    Ok(())
}

/// Checks a sidecar of a database file (`-wal`, `-shm`, `-journal`) without opening it: `lstat`,
/// then it must be a regular file owned by the effective user with no group or other permission
/// bits and no setuid, setgid or sticky bit, and **exactly one hard link**: SQLite truncates and
/// rewrites a `-shm` and a `-wal` in place, so a sidecar that is a second name of another file
/// would clobber that file. (The main database file is not subject to the link rule: it is the
/// file the index writes by design, and its identity is proven by its header.) Returns its
/// length, or `None` when it is absent.
///
/// # Errors
/// [`FsError::NotRegular`] (a symlink is not regular), [`FsError::WrongOwner`],
/// [`FsError::InsecureMode`], [`FsError::HardLinked`] or a failed `lstat`.
pub fn sidecar_len(path: &Path) -> Result<Option<u64>, FsError> {
    match statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            check_stat(&st)?;
            if st.st_nlink > 1 {
                return Err(FsError::HardLinked { links: st.st_nlink });
            }
            Ok(Some(u64::try_from(st.st_size).unwrap_or(u64::MAX)))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(FsError::io("lstat")(e)),
    }
}

/// Opens a discovered sidecar read-only with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY` (a symlink is
/// refused, a FIFO cannot block the open); the caller checks `is_file` on the descriptor.
///
/// # Errors
/// A failed `open`.
pub fn open_sidecar(path: &Path) -> Result<File, FsError> {
    let fd = rustix::fs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(FsError::io("open"))?;
    Ok(File::from(fd))
}

/// A private (`0700`) scratch directory created beside a database, removed with its contents on
/// drop.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    /// Creates `<parent>/.wardenlens-probe-<pid>-<nanos>-<n>`.
    ///
    /// # Errors
    /// A failed `mkdir`.
    pub fn new(parent: &Path) -> Result<Self, FsError> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = parent.join(format!(
            ".wardenlens-probe-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(FsError::io_err("creating scratch directory"))?;
        Ok(Self(dir))
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Removes the scratch directories (`.wardenlens-probe-<pid>-...`) that a process which has
    /// since died left in `parent` after a crash (SEC-2: they hold a copy of the database). A
    /// directory is removed only if it is a real directory (not a symlink) owned by the
    /// effective user, and the pid in its name is **not a live process** (`kill(pid, 0)` says
    /// no such process); the directories of live processes, including this one, are left alone.
    /// Best effort (ERR-4): a failure to remove one is skipped. Returns how many were removed.
    #[must_use]
    pub fn sweep_stale(parent: &Path) -> usize {
        let Ok(entries) = std::fs::read_dir(parent) else {
            return 0;
        };
        let me = rustix::process::geteuid().as_raw();
        let mut removed = 0usize;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = stale_candidate_pid(&name) else {
                continue;
            };
            if pid_is_alive(pid) {
                continue;
            }
            // `symlink_metadata`: a symlink named like a scratch directory is not followed and
            // not removed through.
            let ours = entry
                .path()
                .symlink_metadata()
                .is_ok_and(|m| m.is_dir() && m.uid() == me);
            if ours && std::fs::remove_dir_all(entry.path()).is_ok() {
                removed = removed.saturating_add(1);
            }
        }
        removed
    }
}

/// The pid of a `.wardenlens-probe-<pid>-<nanos>-<n>` name, or `None` for any other name.
fn stale_candidate_pid(name: &OsStr) -> Option<i32> {
    let rest = name.as_bytes().strip_prefix(b".wardenlens-probe-")?;
    let mut parts = rest.split(|b| *b == b'-');
    let (pid, nanos, n) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let digits = |b: &[u8]| !b.is_empty() && b.iter().all(u8::is_ascii_digit);
    if !(digits(pid) && digits(nanos) && digits(n)) {
        return None;
    }
    std::str::from_utf8(pid).ok()?.parse::<i32>().ok()
}

/// True unless `kill(pid, 0)` reports that no such process exists. A pid that is not a valid
/// process id is not alive.
fn pid_is_alive(pid: i32) -> bool {
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return false;
    };
    !matches!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    )
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // ERR-4: best effort; the directory is private and holds only copies.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Most bytes [`copy_bounded`] copies. The vault probe copies its file under this cap. The index
/// does **not** copy (it probes a `-wal` read-only on the real files), so its size is not capped by
/// it; the index uses the value only as the longest `-wal` it reads to prove it all zero.
pub const MAX_COPY_LEN: u64 = 256 * 1024 * 1024;

/// Copies `src` (at most [`MAX_COPY_LEN`] bytes) through the descriptor to a new `0600` file
/// `dst`. `Ok(false)` if the source is longer than the cap.
///
/// # Errors
/// A failed read, create or write.
pub fn copy_bounded(src: &File, dst: &Path) -> Result<bool, FsError> {
    use std::io::Write;
    let len = src
        .metadata()
        .map_err(FsError::io_err("inspecting file"))?
        .len();
    if len > MAX_COPY_LEN {
        return Ok(false);
    }
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
        .map_err(FsError::io_err("creating scratch copy"))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut off = 0u64;
    while off < len {
        let want = usize::try_from(len.saturating_sub(off)).map_or(buf.len(), |r| r.min(buf.len()));
        let Some(window) = buf.get_mut(..want) else {
            break;
        };
        let got = src
            .read_at(window, off)
            .map_err(FsError::io_err("reading file"))?;
        let Some(done) = buf.get(..got).filter(|d| !d.is_empty()) else {
            break;
        };
        out.write_all(done)
            .map_err(FsError::io_err("writing scratch copy"))?;
        off = off.saturating_add(u64::try_from(got).unwrap_or(u64::MAX));
    }
    out.sync_all()
        .map_err(FsError::io_err("writing scratch copy"))?;
    Ok(true)
}

/// The SQLite URI `file://<absolute path>?immutable=1`: a read-only open that never writes a
/// journal, `-wal` or `-shm` file and ignores any that exist. The path is percent-encoded byte
/// by byte; the empty authority keeps a leading `//` part of the path.
///
/// # Errors
/// A failed `absolute`.
pub fn immutable_uri(path: &Path) -> Result<OsString, FsError> {
    let abs = std::path::absolute(path).map_err(FsError::io_err("resolving path"))?;
    let mut uri = b"file://".to_vec();
    for &b in OsStr::as_bytes(abs.as_os_str()) {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            uri.push(b);
        } else {
            uri.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    uri.extend_from_slice(b"?immutable=1");
    Ok(OsString::from_vec(uri))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn private_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn check_parent_accepts_ours_and_refuses_group_or_other_write() {
        let d = private_dir();
        for (mode, ok) in [
            (0o700, true),
            (0o750, true),
            (0o755, true),
            (0o770, false),
            (0o775, false),
            (0o757, false),
            (0o777, false),
            (0o720, false),
            (0o702, false),
        ] {
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(check_parent(d.path()).is_ok(), ok, "{mode:o}");
            if !ok {
                assert!(matches!(
                    check_parent(d.path()),
                    Err(FsError::ParentWritable)
                ));
            }
        }
    }

    #[test]
    fn check_parent_missing_directory_is_not_found() {
        let d = private_dir();
        assert!(
            check_parent(&d.path().join("nope"))
                .unwrap_err()
                .is_not_found()
        );
    }

    #[test]
    fn sidecar_len_table() {
        let d = private_dir();
        let p = d.path().join("x-wal");
        assert_eq!(sidecar_len(&p).unwrap(), None);
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(sidecar_len(&p).unwrap(), Some(0));
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(sidecar_len(&p).unwrap(), Some(3));
        for mode in [0o666, 0o660, 0o640, 0o604, 0o4600, 0o2600, 0o1600] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(sidecar_len(&p), Err(FsError::InsecureMode { .. })),
                "{mode:o}"
            );
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(sidecar_len(&p).unwrap(), Some(3));
        // A second name makes it a hard-linked sidecar: refused, and the file is untouched.
        let twin = d.path().join("twin");
        std::fs::hard_link(&p, &twin).unwrap();
        assert!(matches!(
            sidecar_len(&p),
            Err(FsError::HardLinked { links: 2 })
        ));
        assert!(matches!(
            sidecar_len(&twin),
            Err(FsError::HardLinked { links: 2 })
        ));
        std::fs::remove_file(&twin).unwrap();
        assert_eq!(sidecar_len(&p).unwrap(), Some(3));
        // A symlink, a directory and a FIFO are not regular files.
        let link = d.path().join("link");
        symlink(&p, &link).unwrap();
        assert!(matches!(sidecar_len(&link), Err(FsError::NotRegular)));
        let dir = d.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        assert!(matches!(sidecar_len(&dir), Err(FsError::NotRegular)));
    }

    #[test]
    fn open_sidecar_refuses_a_symlink_and_does_not_block_on_a_fifo() {
        let d = private_dir();
        let real = d.path().join("real");
        std::fs::write(&real, b"x").unwrap();
        let link = d.path().join("link");
        symlink(&real, &link).unwrap();
        assert_eq!(open_sidecar(&link).unwrap_err().errno(), Some(Errno::LOOP));
        let fifo = d.path().join("fifo");
        rustix::fs::mknodat(
            CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(!open_sidecar(&fifo).unwrap().metadata().unwrap().is_file());
        assert!(open_sidecar(&real).unwrap().metadata().unwrap().is_file());
    }

    #[test]
    fn sweep_removes_only_stale_directories_of_ours() {
        let d = private_dir();
        let dead = i32::MAX - 1; // above any pid_max: no such process
        let stale = d.path().join(format!(".wardenlens-probe-{dead}-123-0"));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("copy.db"), b"x").unwrap();
        // The directory of a live process (this one) stays.
        let live = Scratch::new(d.path()).unwrap();
        // Names that merely look similar stay: wrong shape, not a directory, a symlink.
        let decoys = [
            format!(".wardenlens-probe-{dead}-123"),
            format!(".wardenlens-probe-{dead}-123-0-9"),
            ".wardenlens-probe-abc-123-0".to_string(),
            ".wardenlens-probe--1-123-0".to_string(),
            format!("wardenlens-probe-{dead}-123-0"),
        ];
        for n in &decoys {
            std::fs::create_dir(d.path().join(n)).unwrap();
        }
        let file = d.path().join(format!(".wardenlens-probe-{dead}-5-1"));
        std::fs::write(&file, b"keep").unwrap();
        let target = d.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("precious"), b"keep").unwrap();
        let link = d.path().join(format!(".wardenlens-probe-{dead}-6-2"));
        symlink(&target, &link).unwrap();

        assert_eq!(Scratch::sweep_stale(d.path()), 1);
        assert!(!stale.exists());
        assert!(live.path().exists());
        for n in &decoys {
            assert!(d.path().join(n).exists(), "{n}");
        }
        assert!(file.exists());
        assert!(link.symlink_metadata().is_ok());
        assert!(
            target.join("precious").exists(),
            "removed through a symlink"
        );
        // Idempotent, and a missing parent is not an error.
        assert_eq!(Scratch::sweep_stale(d.path()), 0);
        assert_eq!(Scratch::sweep_stale(&d.path().join("missing")), 0);
    }

    #[test]
    fn stale_candidate_pid_table() {
        let t = |s: &str| stale_candidate_pid(OsStr::new(s));
        assert_eq!(t(".wardenlens-probe-42-1-2"), Some(42));
        assert_eq!(t(".wardenlens-probe-42-1"), None);
        assert_eq!(t(".wardenlens-probe-42-1-2-3"), None);
        assert_eq!(t(".wardenlens-probe-x-1-2"), None);
        assert_eq!(t(".wardenlens-probe-99999999999-1-2"), None);
        assert_eq!(t(".wardenlens-probe-0-1-2"), Some(0));
        assert!(!pid_is_alive(0), "pid 0 is not a process id");
        assert!(pid_is_alive(i32::try_from(std::process::id()).unwrap()));
    }

    #[test]
    fn scratch_is_private_and_removed_on_drop() {
        let d = private_dir();
        let s = Scratch::new(d.path()).unwrap();
        let path = s.path().to_path_buf();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::write(path.join("f"), b"x").unwrap();
        let other = Scratch::new(d.path()).unwrap();
        assert_ne!(other.path(), path);
        drop(s);
        assert!(!path.exists());
        assert!(other.path().exists());
    }

    #[test]
    fn copy_bounded_copies_exactly_and_refuses_over_the_cap() {
        let d = private_dir();
        let src = d.path().join("src");
        let data: Vec<u8> = (0..200_000_u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        std::fs::write(&src, &data).unwrap();
        let dst = d.path().join("dst");
        assert!(copy_bounded(&File::open(&src).unwrap(), &dst).unwrap());
        assert_eq!(std::fs::read(&dst).unwrap(), data);
        assert_eq!(
            std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // An existing destination is never overwritten.
        assert!(copy_bounded(&File::open(&src).unwrap(), &dst).is_err());
        // One byte over the cap (a sparse file): refused without creating the destination.
        let big = d.path().join("big");
        let f = File::create(&big).unwrap();
        f.set_len(MAX_COPY_LEN + 1).unwrap();
        let dst2 = d.path().join("dst2");
        assert!(!copy_bounded(&File::open(&big).unwrap(), &dst2).unwrap());
        assert!(!dst2.exists());
        f.set_len(MAX_COPY_LEN).unwrap();
        // Exactly the cap is accepted (sparse, so cheap to write out).
        let dst3 = d.path().join("dst3");
        assert!(copy_bounded(&File::open(&big).unwrap(), &dst3).unwrap());
        assert_eq!(std::fs::metadata(&dst3).unwrap().len(), MAX_COPY_LEN);
    }

    #[test]
    fn immutable_uri_encodes_every_byte_outside_the_safe_set() {
        let uri = immutable_uri(Path::new("/a b/c?d#e%f/é.db")).unwrap();
        assert_eq!(
            uri.to_str().unwrap(),
            "file:///a%20b/c%3Fd%23e%25f/%C3%A9.db?immutable=1"
        );
        let plain = immutable_uri(Path::new("/x/y-z_1.db~")).unwrap();
        assert_eq!(plain.to_str().unwrap(), "file:///x/y-z_1.db~?immutable=1");
    }
}
