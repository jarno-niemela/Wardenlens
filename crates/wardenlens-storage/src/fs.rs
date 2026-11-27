//! The `Fs` trait: every file-system step of the move and the delete, one system call per
//! method, so a test can fail any of them (ADR 0005 section 7, "crash points").
//!
//! [`RealFs`] implements it with `wardenlens-fsutil` only: every path is opened with `openat2`
//! (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) below a root handle, and every directory operation
//! acts on a freshly opened parent descriptor with a single-component name. The archive handle
//! is always the one of the latest successful probe ([`ArchiveSlot`]).

use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rustix::io::Errno;
use wardenlens_core::storage::Tier;
use wardenlens_fsutil::{FsError, Listing, QuarantineOutcome, RootDir};

/// A file opened for reading (the M1 descriptor, an archive copy being verified, a file the
/// reconciliation adopts). `Seek` lets the `core::mp4box` walk skip `mdat` payloads.
pub trait SourceFile: Read + Seek + Send {
    /// `fsync` the file (it was opened read-only; `fsync` does not need write access).
    ///
    /// # Errors
    /// The `fsync` failure.
    fn sync(&mut self) -> io::Result<()>;
}

impl SourceFile for File {
    fn sync(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

/// A regular file opened by [`Fs::open_read`], with the length from `fstat` of the same descriptor.
pub struct Opened {
    /// The read-only descriptor.
    pub file: Box<dyn SourceFile>,
    /// Its length.
    pub len: u64,
    /// Bytes allocated on the volume (what deleting the file frees; not capped at `len`).
    pub allocated: u64,
}

/// Bytes read at a time when two files are compared.
const COMPARE_CHUNK: usize = 64 * 1024;

/// Whether two opened files hold the same bytes (compared in bounded chunks). `None` when either
/// could not be read to the end: no conclusion, so the caller deletes nothing on it (#195).
pub(crate) fn same_bytes(first: &mut Opened, second: &mut Opened) -> Option<bool> {
    if first.len != second.len {
        return Some(false);
    }
    first.file.seek(io::SeekFrom::Start(0)).ok()?;
    second.file.seek(io::SeekFrom::Start(0)).ok()?;
    let mut left_buf = vec![0u8; COMPARE_CHUNK];
    let mut right_buf = vec![0u8; COMPARE_CHUNK];
    let mut left = first.len;
    while left > 0 {
        let n = usize::try_from(left).map_or(COMPARE_CHUNK, |l| l.min(COMPARE_CHUNK));
        let (xs, ys) = (left_buf.get_mut(..n)?, right_buf.get_mut(..n)?);
        first.file.read_exact(xs).ok()?;
        second.file.read_exact(ys).ok()?;
        if xs != ys {
            return Some(false);
        }
        left = left.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Some(true)
}

/// The `.part` file being written.
pub trait PartFile: Send {
    /// Write all of `buf`.
    ///
    /// # Errors
    /// The write failure (`ENOSPC`, `EIO`, ...).
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    /// `fsync` the file.
    ///
    /// # Errors
    /// The `fsync` failure.
    fn sync(&mut self) -> io::Result<()>;
}

impl PartFile for File {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        Write::write_all(self, buf)
    }
    fn sync(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

/// File-system steps, addressed by tier and path components below that tier's root.
///
/// `dir`/`parent` may be empty (the root itself); `name`, `from` and `to` are single components.
pub trait Fs {
    /// Open the regular file `comps` for reading (`openat2`, `O_NONBLOCK`, then `fstat`).
    ///
    /// # Errors
    /// The kernel's refusal, [`FsError::NotRegular`], or an unavailable archive.
    fn open_read(&self, tier: Tier, comps: &[&str]) -> Result<Opened, FsError>;
    /// `mkdirat(parent, name)`.
    ///
    /// # Errors
    /// The failure (`EEXIST` included).
    fn mkdir(&self, tier: Tier, parent: &[&str], name: &str) -> Result<(), FsError>;
    /// `fsync` the directory `dir`.
    ///
    /// # Errors
    /// The failure.
    fn sync_dir(&self, tier: Tier, dir: &[&str]) -> Result<(), FsError>;
    /// `unlinkat(dir, name)`.
    ///
    /// # Errors
    /// The failure (`ENOENT` included).
    fn unlink(&self, tier: Tier, dir: &[&str], name: &str) -> Result<(), FsError>;
    /// Create `dir/name` with `O_CREAT | O_EXCL | O_NOFOLLOW`.
    ///
    /// # Errors
    /// The failure (`EEXIST` included).
    fn create_part(
        &self,
        tier: Tier,
        dir: &[&str],
        name: &str,
    ) -> Result<Box<dyn PartFile>, FsError>;
    /// `renameat2(dir/from, dir/to, RENAME_NOREPLACE)`.
    ///
    /// # Errors
    /// The failure (`EEXIST` included).
    fn rename_noreplace(
        &self,
        tier: Tier,
        dir: &[&str],
        from: &str,
        to: &str,
    ) -> Result<(), FsError>;
    /// Move `comps` into `<root>/_quarantine/` (`RENAME_NOREPLACE`, numeric suffixes, bound 1,000).
    ///
    /// # Errors
    /// The failure.
    fn quarantine(&self, tier: Tier, comps: &[&str]) -> Result<QuarantineOutcome, FsError>;
    /// List the directory `dir` (at most `max` entries; names that cannot be returned are counted
    /// in [`Listing::dropped`] and against `max`).
    ///
    /// # Errors
    /// The failure, or more than `max` entries.
    fn list_dir(&self, tier: Tier, dir: &[&str], max: usize) -> Result<Listing, FsError>;
}

/// The archive handle of the latest successful probe, shared by the probe (writer), the mover and
/// the [`SegmentFiles`](wardenlens_core::storage::SegmentFiles) implementation (readers). `None`
/// while the archive is unavailable: a failed probe keeps no handle.
#[derive(Debug, Default)]
pub(crate) struct ArchiveSlot {
    inner: Mutex<Option<Held>>,
}

#[derive(Debug, Clone)]
struct Held {
    root: Arc<RootDir>,
    dev: u64,
    ino: u64,
}

impl ArchiveSlot {
    /// The current handle, if the archive is available. An operation holds its `Arc` for its own
    /// duration, so a swap never changes the target in the middle of one.
    #[must_use]
    pub(crate) fn get(&self) -> Option<Arc<RootDir>> {
        self.lock().as_ref().map(|h| Arc::clone(&h.root))
    }

    /// Install `fresh` unless the slot already holds a handle with the same `(st_dev, st_ino)`
    /// (the old one is kept and `fresh` is closed); a changed pair swaps and closes the old one.
    pub(crate) fn install(&self, fresh: RootDir, dev: u64, ino: u64) {
        let mut g = self.lock();
        if g.as_ref().is_some_and(|h| h.dev == dev && h.ino == ino) {
            return;
        }
        *g = Some(Held {
            root: Arc::new(fresh),
            dev,
            ino,
        });
    }

    /// Drop the handle (the archive is unavailable).
    pub(crate) fn clear(&self) {
        *self.lock() = None;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Held>> {
        // The guarded value is replaced whole, so a poisoned lock holds a consistent value.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// [`Fs`] over `wardenlens-fsutil`.
#[derive(Debug, Clone)]
pub struct RealFs {
    hot: Arc<RootDir>,
    archive: Arc<ArchiveSlot>,
    quarantined: Arc<AtomicU64>,
}

impl RealFs {
    /// `quarantined` is bumped on every file this `Fs` moves into a quarantine: the one choke
    /// point every quarantine (move, delete, source, reconciliation) goes through, so the status
    /// count cannot miss a site.
    pub(crate) fn new(
        hot: Arc<RootDir>,
        archive: Arc<ArchiveSlot>,
        quarantined: Arc<AtomicU64>,
    ) -> Self {
        Self {
            hot,
            archive,
            quarantined,
        }
    }

    fn root(&self, tier: Tier) -> Result<Arc<RootDir>, FsError> {
        match tier {
            Tier::Archive => self.archive.get().ok_or(FsError::Io {
                op: "archive handle",
                source: Errno::NODEV,
            }),
            Tier::Hot => Ok(Arc::clone(&self.hot)),
            _ => Err(FsError::InvalidComponent),
        }
    }

    fn dir(&self, tier: Tier, comps: &[&str]) -> Result<RootDir, FsError> {
        let root = self.root(tier)?;
        if comps.is_empty() {
            root.try_clone()
        } else {
            root.open_dir(comps)
        }
    }
}

impl Fs for RealFs {
    fn open_read(&self, tier: Tier, comps: &[&str]) -> Result<Opened, FsError> {
        let r = self.root(tier)?.open_read(comps)?;
        Ok(Opened {
            file: Box::new(r.file),
            len: r.len,
            allocated: r.allocated,
        })
    }

    fn mkdir(&self, tier: Tier, parent: &[&str], name: &str) -> Result<(), FsError> {
        self.dir(tier, parent)?.mkdir(name)
    }

    fn sync_dir(&self, tier: Tier, dir: &[&str]) -> Result<(), FsError> {
        self.dir(tier, dir)?.sync()
    }

    fn unlink(&self, tier: Tier, dir: &[&str], name: &str) -> Result<(), FsError> {
        self.dir(tier, dir)?.unlink(name)
    }

    fn create_part(
        &self,
        tier: Tier,
        dir: &[&str],
        name: &str,
    ) -> Result<Box<dyn PartFile>, FsError> {
        Ok(Box::new(self.dir(tier, dir)?.create_new(name)?))
    }

    fn rename_noreplace(
        &self,
        tier: Tier,
        dir: &[&str],
        from: &str,
        to: &str,
    ) -> Result<(), FsError> {
        let d = self.dir(tier, dir)?;
        d.rename_noreplace(from, &d, to)
    }

    fn quarantine(&self, tier: Tier, comps: &[&str]) -> Result<QuarantineOutcome, FsError> {
        let outcome = wardenlens_fsutil::quarantine(&*self.root(tier)?, comps)?;
        // `Exhausted` left the file in place: nothing was quarantined.
        if matches!(outcome, QuarantineOutcome::Moved { .. }) {
            let _ = self
                .quarantined
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_add(1))
                });
        }
        Ok(outcome)
    }

    fn list_dir(&self, tier: Tier, dir: &[&str], max: usize) -> Result<Listing, FsError> {
        self.dir(tier, dir)?.list(max)
    }
}
