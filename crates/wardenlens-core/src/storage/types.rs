//! Value types of the storage planner.

use std::fmt;

use crate::time::{DurationMs, Timestamp};

/// A storage tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tier {
    /// The fast SSD holding recent video.
    Hot,
    /// The slow HDD holding older video.
    Archive,
}

/// Identifier of a stored segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentId(u64);

impl SegmentId {
    /// Wraps a raw segment id.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw id.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// The minimum free space of a volume, in whole percent of its capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MinFreePercent(u8);

/// A [`MinFreePercent`] outside 0-90.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinFreePercentError {
    value: u8,
}

impl fmt::Display for MinFreePercentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "min free percent {} is outside the range 0 to {}",
            self.value,
            MinFreePercent::MAX
        )
    }
}

impl std::error::Error for MinFreePercentError {}

impl MinFreePercent {
    /// The largest accepted value.
    pub const MAX: u8 = 90;

    /// Validates a percentage.
    ///
    /// # Errors
    /// Returns [`MinFreePercentError`] when `value` is above 90.
    pub const fn new(value: u8) -> Result<Self, MinFreePercentError> {
        if value > Self::MAX {
            Err(MinFreePercentError { value })
        } else {
            Ok(Self(value))
        }
    }

    /// The percentage, 0 to 90.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for MinFreePercent {
    /// 25 percent.
    fn default() -> Self {
        Self(25)
    }
}

/// Planner policy (ADR 0005 section 6). The headroom is a fixed 1 percentage point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Floor of the hot volume.
    pub hot_min_free: MinFreePercent,
    /// Floor of the archive volume.
    pub archive_min_free: MinFreePercent,
    /// Hot segments that ended earlier than this are moved even without pressure.
    pub hot_max_age: DurationMs,
}

impl Default for Policy {
    /// 25 percent on both volumes and a hot max age of 12 hours.
    fn default() -> Self {
        Self {
            hot_min_free: MinFreePercent::default(),
            archive_min_free: MinFreePercent::default(),
            hot_max_age: DurationMs::from_secs(12 * 3600),
        }
    }
}

/// Space of one volume as probed by the adapter (ADR 0005 section 6: capacity is
/// used plus available space, free is the space available to the service).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeSpace {
    /// Space the service can ever occupy, in bytes.
    pub capacity_bytes: u64,
    /// Space available to the service, in bytes.
    pub free_bytes: u64,
}

impl VolumeSpace {
    /// A volume is usable when its capacity is non-zero and it is not freer than it is large.
    pub(crate) const fn is_usable(&self) -> bool {
        self.capacity_bytes > 0 && self.free_bytes <= self.capacity_bytes
    }
}

/// Whether the archive can take moves (ADR 0005 section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveState {
    /// Available, with its current space.
    Available(VolumeSpace),
    /// Unavailable for any reason of section 8; its rows are not touched.
    Unavailable,
}

/// A segment known to the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredSegment {
    /// Segment id.
    pub id: SegmentId,
    /// Tier the segment is on.
    pub tier: Tier,
    /// Size in bytes.
    pub bytes: u64,
    /// When the segment ended.
    pub ended_at: Timestamp,
}
