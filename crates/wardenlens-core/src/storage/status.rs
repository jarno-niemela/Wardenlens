//! The storage status the API reports (ADR 0005 section 6, ticket #63): a plain snapshot of both
//! tiers, produced by the storage loop after every tick and read through the [`StorageStatus`]
//! port.
//!
//! The snapshot names tiers by [`Tier`] only. It carries no path, mount point, device id or error
//! text: the last error is a closed [`TickErrorKind`], the archive's unavailability a closed
//! [`ArchiveUnavailableCause`].

use crate::time::Timestamp;

use super::types::{MinFreePercent, VolumeSpace};

/// Percent of `capacity` that `free` is: `free * 100 / capacity`, rounded down, at most 100.
///
/// `capacity` is `(f_blocks - f_bfree + f_bavail) * f_frsize` and `free` is `f_bavail * f_frsize`
/// (ADR 0005 section 6). A zero capacity gives 0 (never a division by zero) and `free` above
/// `capacity` gives 100 (an inconsistent report is clamped, never a wrap).
#[must_use]
pub fn free_percent(free: u64, capacity: u64) -> u8 {
    let scaled = u128::from(free)
        .saturating_mul(100)
        .checked_div(u128::from(capacity))
        .unwrap_or(0);
    u8::try_from(scaled.min(100)).unwrap_or(100)
}

/// Space of one volume against its floor. Built only by [`VolumeStatus::new`], so the derived
/// fields always agree with the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeStatus {
    total_bytes: u64,
    free_bytes: u64,
    free_percent: u8,
    below_floor: bool,
}

impl VolumeStatus {
    /// The status of `space` against `min_free`. Never panics, whatever `space` holds.
    #[must_use]
    pub fn new(space: VolumeSpace, min_free: MinFreePercent) -> Self {
        let floor_bytes =
            u128::from(space.capacity_bytes).saturating_mul(u128::from(min_free.get())) / 100;
        Self {
            total_bytes: space.capacity_bytes,
            free_bytes: space.free_bytes,
            free_percent: free_percent(space.free_bytes, space.capacity_bytes),
            below_floor: u128::from(space.free_bytes) < floor_bytes,
        }
    }

    /// Capacity as the floor arithmetic sees it, in bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Space available to the service, in bytes.
    #[must_use]
    pub const fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    /// `free_bytes * 100 / total_bytes`, rounded down (see [`free_percent`]).
    #[must_use]
    pub const fn free_percent(&self) -> u8 {
        self.free_percent
    }

    /// Free space is under the floor, by the same byte rule the planner uses
    /// (`free < capacity * min_free / 100`, rounded down).
    #[must_use]
    pub const fn below_floor(&self) -> bool {
        self.below_floor
    }
}

/// One tier: its floor, its volume (when it could be measured) and its rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct TierStatus {
    /// The configured floor, in percent: known even while the volume is not measured. `None`
    /// only in the initial snapshot, before any tick or probe.
    pub min_free_percent: Option<u8>,
    /// `None` when the volume could not be measured (the archive is away, or the probe failed).
    pub volume: Option<VolumeStatus>,
    /// Segment rows on this tier.
    pub segments: u64,
    /// End time of the oldest segment, `None` for an empty tier.
    pub oldest: Option<Timestamp>,
    /// End time of the newest segment, `None` for an empty tier.
    pub newest: Option<Timestamp>,
}

impl TierStatus {
    /// A tier from its parts.
    #[must_use]
    pub const fn new(
        min_free: MinFreePercent,
        volume: Option<VolumeStatus>,
        segments: u64,
        oldest: Option<Timestamp>,
        newest: Option<Timestamp>,
    ) -> Self {
        Self {
            min_free_percent: Some(min_free.get()),
            volume,
            segments,
            oldest,
            newest,
        }
    }
}

/// Why the archive is unavailable (ADR 0005 section 8). A class, never a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveUnavailableCause {
    /// The root is missing, not a directory, a symlink, or cannot be opened.
    Missing,
    /// Same filesystem as the hot root (an unmounted disk).
    SameFilesystem,
    /// Mounted read-only.
    ReadOnly,
    /// The marker file is missing.
    NoMarker,
    /// Three consecutive archive-side move failures, not yet cleared.
    MoveFailures,
    /// Zero capacity or overflowing arithmetic.
    Unusable,
    /// The probe's own calls failed.
    ProbeFailed,
    /// A cause this version does not name.
    Other,
}

/// State of the archive after the last tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveCondition {
    /// Available and taking moves.
    Available,
    /// Available but unable to absorb the moves even after evicting everything (`archive_full`);
    /// it behaves like unavailable.
    Full,
    /// `archive_unavailable`, with the class of the cause.
    Unavailable(ArchiveUnavailableCause),
}

/// Why the last tick failed. A closed set: never error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TickErrorKind {
    /// The hot volume could not be probed or is unusable.
    HotVolume,
    /// The index could not be read.
    Index,
    /// The planner refused its input.
    Plan,
    /// A failure this version does not name.
    Other,
}

/// The storage loop's state after its latest tick.
///
/// Before the first tick (`last_tick` is `None`) nothing is measured yet: the tiers are empty and
/// unmeasured, and the archive condition is `unavailable (other)`, unless the start-up
/// reconciliation probed the archive first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StorageSnapshot {
    /// The hot tier.
    pub hot: TierStatus,
    /// The archive tier.
    pub archive: TierStatus,
    /// State of the archive.
    pub archive_condition: ArchiveCondition,
    /// An event counter: how many times, since start, a segment was left alone because nothing
    /// could be concluded about it. One segment can count again on a later tick.
    pub unverified_total: u64,
    /// An event counter: how many files, since start, were moved into a quarantine, whatever the
    /// reason (counted at the one place that quarantines). Files already there at start, and
    /// ones later evicted, are not counted or subtracted.
    pub quarantined_total: u64,
    /// When the latest tick ran (UTC Unix milliseconds); `None` before the first tick.
    pub last_tick: Option<Timestamp>,
    /// Why the latest tick failed; `None` when it succeeded.
    pub last_error: Option<TickErrorKind>,
    /// Ticks since start, per volume, that found it below its floor (saturating).
    pub floor_breaches_total: u64,
}

impl StorageSnapshot {
    /// The snapshot before the first tick: nothing measured, nothing counted.
    #[must_use]
    pub const fn initial() -> Self {
        let empty = TierStatus {
            min_free_percent: None,
            volume: None,
            segments: 0,
            oldest: None,
            newest: None,
        };
        Self {
            hot: empty,
            archive: empty,
            archive_condition: ArchiveCondition::Unavailable(ArchiveUnavailableCause::Other),
            unverified_total: 0,
            quarantined_total: 0,
            last_tick: None,
            last_error: None,
            floor_breaches_total: 0,
        }
    }
}

/// The snapshot could not be read. Carries no detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("storage status unavailable")]
pub struct StorageStatusError;

/// Read access to the latest storage snapshot (the API's view of the storage loop).
pub trait StorageStatus {
    /// The latest snapshot.
    ///
    /// # Errors
    /// [`StorageStatusError`] when it cannot be read.
    fn snapshot(&self) -> impl Future<Output = Result<StorageSnapshot, StorageStatusError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pct(p: u8) -> MinFreePercent {
        MinFreePercent::new(p).unwrap()
    }

    #[test]
    fn free_percent_edges() {
        assert_eq!(free_percent(0, 0), 0, "zero capacity");
        assert_eq!(free_percent(5, 0), 0, "zero capacity with free space");
        assert_eq!(free_percent(200, 100), 100, "free above capacity clamps");
        assert_eq!(free_percent(u64::MAX, 1), 100);
        assert_eq!(free_percent(u64::MAX, u64::MAX), 100);
        assert_eq!(free_percent(u64::MAX - 1, u64::MAX), 99, "rounds down");
        assert_eq!(free_percent(0, u64::MAX), 0);
        assert_eq!(free_percent(1, u64::MAX), 0);
        assert_eq!(free_percent(25, 100), 25);
        assert_eq!(free_percent(249, 1000), 24);
        assert_eq!(free_percent(250, 1000), 25);
    }

    #[test]
    fn below_floor_matches_the_byte_rule_at_the_boundary() {
        let at = |free| {
            VolumeStatus::new(
                VolumeSpace {
                    capacity_bytes: 1000,
                    free_bytes: free,
                },
                pct(25),
            )
        };
        assert!(at(249).below_floor());
        assert!(!at(250).below_floor());
        assert!(at(0).below_floor());
        assert_eq!(at(249).free_percent(), 24);
    }

    #[test]
    fn volume_status_never_panics_on_extremes() {
        for cap in [0, 1, 99, 100, u64::MAX - 1, u64::MAX] {
            for free in [0, 1, 99, 100, u64::MAX - 1, u64::MAX] {
                for p in [0, 1, 25, 90] {
                    let s = VolumeStatus::new(
                        VolumeSpace {
                            capacity_bytes: cap,
                            free_bytes: free,
                        },
                        pct(p),
                    );
                    assert!(s.free_percent() <= 100);
                    if p == 0 {
                        assert!(!s.below_floor(), "a zero floor is never breached");
                    }
                    if cap == 0 {
                        assert!(!s.below_floor());
                        assert_eq!(s.free_percent(), 0);
                    }
                }
            }
        }
    }
}
