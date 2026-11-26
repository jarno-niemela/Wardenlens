//! The volume probe and the archive state (ADR 0005 sections 6 and 8).
//!
//! Every probe opens the archive root again with `O_DIRECTORY | O_NOFOLLOW` and runs all of its
//! checks on that new handle: a handle kept from start-up would keep pointing at the empty
//! directory that a later mount covers, and moves would land on the SSD.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use wardenlens_core::storage::{Tier, VolumeSpace};
use wardenlens_fsutil::{FsError, RootDir, VolumeStat};

use crate::error::ProbeError;
use crate::fs::ArchiveSlot;

/// The marker file the operator creates once on the mounted archive.
pub const ARCHIVE_MARKER: &str = ".wardenlens-archive";
/// The scratch file that clears a failure-based unavailability.
pub const PROBE_FILE: &str = ".wl-probe";
/// Consecutive archive-side move failures that make the archive unavailable.
pub const MAX_MOVE_FAILURES: u32 = 3;

/// Where the numbers of a volume come from. The real source is [`StatvfsUsage`]; tests use a
/// fake that measures two temporary directories against a pretend capacity.
pub trait VolumeUsage {
    /// Space of the volume that holds `root` (the handle of this probe).
    ///
    /// # Errors
    /// [`ProbeError::Unusable`] for zero capacity or overflow, or the failing call.
    fn space(&self, tier: Tier, root: &RootDir) -> Result<VolumeSpace, ProbeError>;
}

/// `fstatvfs` with checked arithmetic: `free = f_bavail * f_frsize`,
/// `capacity = (f_blocks - f_bfree + f_bavail) * f_frsize`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatvfsUsage;

impl VolumeUsage for StatvfsUsage {
    fn space(&self, _tier: Tier, root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        let v = root.statvfs().map_err(|e| ProbeError::Io(e.errno()))?;
        space_from_stat(&v)
    }
}

/// The floor arithmetic of section 6. A volume with `capacity == 0`, with `f_bfree > f_blocks`, or
/// whose arithmetic overflows is unusable: never a division, never a wrap.
///
/// # Errors
/// [`ProbeError::Unusable`].
pub fn space_from_stat(v: &VolumeStat) -> Result<VolumeSpace, ProbeError> {
    let used = v
        .blocks
        .checked_sub(v.blocks_free)
        .ok_or(ProbeError::Unusable)?;
    let cap_blocks = used
        .checked_add(v.blocks_available)
        .ok_or(ProbeError::Unusable)?;
    let capacity_bytes = cap_blocks
        .checked_mul(v.block_size)
        .ok_or(ProbeError::Unusable)?;
    let free_bytes = v
        .blocks_available
        .checked_mul(v.block_size)
        .ok_or(ProbeError::Unusable)?;
    if capacity_bytes == 0 {
        return Err(ProbeError::Unusable);
    }
    Ok(VolumeSpace {
        capacity_bytes,
        free_bytes,
    })
}

/// Why the archive is unavailable (section 8). Carries no path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnavailableCause {
    /// The root is missing, not a directory, a symlink, or cannot be opened.
    Missing,
    /// Same `st_dev` as the hot root: an unmounted disk, or a test setup without the switch.
    SameFilesystem,
    /// `ST_RDONLY`.
    ReadOnly,
    /// `.wardenlens-archive` is missing or not a regular file.
    NoMarker,
    /// Three consecutive archive-side move failures, not yet cleared by a `.wl-probe` round trip.
    MoveFailures,
    /// `capacity == 0` or the arithmetic overflowed.
    Unusable,
    /// The probe's own calls failed (`fstat`, `fstatvfs`).
    ProbeFailed,
}

/// The archive state of one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveProbe {
    /// Available, with its space.
    Available(VolumeSpace),
    /// Unavailable. A state, not an error.
    Unavailable(UnavailableCause),
}

impl ArchiveProbe {
    /// Whether moves may target the archive.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }
}

/// Result of one probe of both volumes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProbeResult {
    /// The hot volume.
    pub hot: Result<VolumeSpace, ProbeError>,
    /// The archive.
    pub archive: ArchiveProbe,
    /// A `.wl-probe` round trip succeeded: the caller resets its failure count.
    pub failures_cleared: bool,
}

/// Probes both volumes. Owns the hot handle (opened once) and publishes the archive handle of the
/// latest successful probe through the shared [`ArchiveSlot`].
#[derive(Debug)]
pub(crate) struct Probe {
    hot: Arc<RootDir>,
    archive_path: PathBuf,
    slot: Arc<ArchiveSlot>,
    allow_same_filesystem: bool,
}

impl Probe {
    pub(crate) fn new(
        hot: Arc<RootDir>,
        archive_path: &Path,
        slot: Arc<ArchiveSlot>,
        allow_same_filesystem: bool,
    ) -> Self {
        Self {
            hot,
            archive_path: archive_path.to_owned(),
            slot,
            allow_same_filesystem,
        }
    }

    /// Probe both volumes. `failures` is the current count of consecutive archive-side move
    /// failures. Re-run every tick and after every action.
    pub(crate) fn run(
        &self,
        usage: &impl VolumeUsage,
        failures: u32,
        may_clear: bool,
    ) -> ProbeResult {
        let hot = usage.space(Tier::Hot, &self.hot);
        let (archive, failures_cleared) = self.probe_archive(usage, failures, may_clear);
        ProbeResult {
            hot,
            archive,
            failures_cleared,
        }
    }

    fn probe_archive(
        &self,
        usage: &impl VolumeUsage,
        failures: u32,
        may_clear: bool,
    ) -> (ArchiveProbe, bool) {
        let unavailable = |cause| {
            // A failed probe leaves the state unavailable and keeps no handle.
            self.slot.clear();
            (ArchiveProbe::Unavailable(cause), false)
        };
        // 1. A fresh handle, on every probe; every other check runs on it.
        let Ok(fresh) = RootDir::open(&self.archive_path) else {
            return unavailable(UnavailableCause::Missing);
        };
        let (Ok(st), Ok(hot_st)) = (fresh.stat(), self.hot.stat()) else {
            return unavailable(UnavailableCause::ProbeFailed);
        };
        let Ok(vfs) = fresh.statvfs() else {
            return unavailable(UnavailableCause::ProbeFailed);
        };
        let facts = Facts {
            same_device: st.dev == hot_st.dev,
            allow_same_device: self.allow_same_filesystem,
            read_only: vfs.read_only,
            marker: fresh.open_read(&[ARCHIVE_MARKER]).is_ok(),
        };
        if let Some(cause) = facts.unavailable() {
            return unavailable(cause);
        }
        // 5. Three archive-side failures stay in force until a small file can be created, synced
        // and removed.
        let mut cleared = false;
        if failures >= MAX_MOVE_FAILURES {
            // Only the first probe of a tick may clear the failures: a state reached mid-tick
            // holds for the rest of that tick (ADR 0005 section 6 case 2, section 8 item 5).
            if !may_clear {
                return unavailable(UnavailableCause::MoveFailures);
            }
            if scratch_round_trip(&fresh).is_err() {
                return unavailable(UnavailableCause::MoveFailures);
            }
            cleared = true;
        }
        let space = match usage.space(Tier::Archive, &fresh) {
            Ok(s) => s,
            Err(ProbeError::Unusable) => return unavailable(UnavailableCause::Unusable),
            Err(_) => return unavailable(UnavailableCause::ProbeFailed),
        };
        self.slot.install(fresh, st.dev, st.ino);
        (ArchiveProbe::Available(space), cleared)
    }
}

/// What one probe learned from the fresh archive handle (section 8, checks 2 to 4).
#[derive(Debug, Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "four independent facts of one probe; the table test enumerates all 16 combinations"
)]
struct Facts {
    same_device: bool,
    allow_same_device: bool,
    read_only: bool,
    marker: bool,
}

impl Facts {
    /// The first check that fails, in the order of section 8.
    const fn unavailable(self) -> Option<UnavailableCause> {
        if self.same_device && !self.allow_same_device {
            Some(UnavailableCause::SameFilesystem)
        } else if self.read_only {
            Some(UnavailableCause::ReadOnly)
        } else if !self.marker {
            Some(UnavailableCause::NoMarker)
        } else {
            None
        }
    }
}

/// Create, fsync and remove `.wl-probe`; a stale one (left by a crash) is unlinked first.
fn scratch_round_trip(root: &RootDir) -> Result<(), FsError> {
    use std::io::Write;
    match root.unlink(PROBE_FILE) {
        Ok(()) => {}
        Err(e) if e.is_not_found() => {}
        Err(e) => return Err(e),
    }
    let mut f = root.create_new(PROBE_FILE)?;
    f.write_all(b"wardenlens")
        .and_then(|()| f.sync_all())
        .map_err(|e| FsError::Io {
            op: "probe write",
            source: rustix::io::Errno::from_io_error(&e).unwrap_or(rustix::io::Errno::IO),
        })?;
    drop(f);
    root.unlink(PROBE_FILE)?;
    root.sync()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_unavailable_fact_is_decided_in_the_order_of_section_8() {
        // (same_device, allow, read_only, marker) -> cause; TEST-9: the whole input space.
        for bits in 0_u8..16 {
            let f = Facts {
                same_device: bits & 1 != 0,
                allow_same_device: bits & 2 != 0,
                read_only: bits & 4 != 0,
                marker: bits & 8 != 0,
            };
            let want = if f.same_device && !f.allow_same_device {
                Some(UnavailableCause::SameFilesystem)
            } else if f.read_only {
                Some(UnavailableCause::ReadOnly)
            } else if !f.marker {
                Some(UnavailableCause::NoMarker)
            } else {
                None
            };
            assert_eq!(f.unavailable(), want, "{f:?}");
        }
    }

    fn stat(blocks: u64, free: u64, avail: u64, size: u64) -> VolumeStat {
        // `VolumeStat` is non-exhaustive: build it from a real one.
        let dir = std::env::temp_dir();
        let mut v = RootDir::open(&dir).unwrap().statvfs().unwrap();
        v.blocks = blocks;
        v.blocks_free = free;
        v.blocks_available = avail;
        v.block_size = size;
        v
    }

    #[test]
    fn floor_arithmetic_uses_available_space_and_is_checked() {
        // capacity = (blocks - bfree + bavail) * frsize; free = bavail * frsize.
        let s = space_from_stat(&stat(1000, 300, 200, 4096)).unwrap();
        assert_eq!(s.capacity_bytes, 900 * 4096);
        assert_eq!(s.free_bytes, 200 * 4096);
        for (v, why) in [
            (stat(0, 0, 0, 4096), "capacity 0"),
            (stat(10, 11, 0, 4096), "bfree > blocks"),
            (stat(10, 0, 0, 0), "zero block size"),
            (stat(u64::MAX, 0, 1, 2), "capacity overflows"),
        ] {
            assert_eq!(space_from_stat(&v), Err(ProbeError::Unusable), "{why}");
        }
    }
}
