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
    /// Free space, in bytes, the planner keeps on the hot volume. It is a minimum for the hot
    /// floor (a floor below it, such as a 0 % floor, is raised to it, see [`hot_floor`]), so it
    /// engages whatever the percentage; capped at 90 % of the capacity and ignored while the
    /// volume cannot reach it. When the floor is unreachable the rolling buffer deletes the oldest hot
    /// video until at least this much is free (or no hot video remains). It stops foreign data
    /// growth from driving the hot volume to ENOSPC while the buffer would otherwise sit at its
    /// budget.
    pub emergency_reserve_bytes: u64,
}

/// Default emergency reserve: 2 GiB, about two minutes of headroom for the reference
/// five-camera site.
pub const DEFAULT_EMERGENCY_RESERVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

impl Default for Policy {
    /// 25 percent on both volumes, a hot max age of 12 hours and a 2 GiB emergency reserve.
    fn default() -> Self {
        Self {
            hot_min_free: MinFreePercent::default(),
            archive_min_free: MinFreePercent::default(),
            hot_max_age: DurationMs::from_secs(12 * 3600),
            emergency_reserve_bytes: DEFAULT_EMERGENCY_RESERVE_BYTES,
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

/// The emergency reserve the hot volume can be asked to keep: the policy's reserve capped at
/// [`MinFreePercent::MAX`] percent of the capacity (rounded down). A reserve larger than the
/// volume could never be met; uncapped it would make the floor unreachable on every tick. The
/// planner and the storage adapter share this so they cannot drift.
#[must_use]
pub fn effective_reserve_bytes(capacity_bytes: u64, reserve_bytes: u64) -> u64 {
    let cap = u128::from(capacity_bytes)
        .checked_mul(u128::from(MinFreePercent::MAX))
        .map_or(u128::MAX, |scaled| scaled / 100);
    reserve_bytes.min(u64::try_from(cap).unwrap_or(u64::MAX))
}

/// The hot floor in force for one probe, from [`hot_floor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotFloor {
    /// Free bytes below which the hot volume is under its floor.
    pub floor_bytes: u64,
    /// Free bytes the plan restores to when it is below (the floor plus 1 pp of headroom).
    pub target_bytes: u64,
    /// The emergency reserve would raise the floor but the volume cannot reach it (free space
    /// plus all hot video is below the reserve): the reserve is then not part of the floor, so it
    /// never makes the floor unreachable. Outside the rolling buffer nothing is deleted or moved
    /// for it; inside the rolling buffer (the percentage floor is also unreachable and the
    /// archive cannot help) the #44 drain toward the reserve still applies and the state is
    /// `RollingBuffer`. Either way the adapter alerts.
    pub reserve_unreachable: bool,
}

/// The one hot-floor rule, used by the planner, the status (`below_floor`, the breach counter)
/// and the quarantine eviction so they cannot disagree.
///
/// The floor is the percentage floor, raised to the effective reserve (see
/// [`effective_reserve_bytes`]) when the reserve is above it and the volume can reach it
/// (`free + hot video >= reserve`). The target keeps the usual 1 pp of headroom above the floor.
#[must_use]
pub fn hot_floor(
    capacity_bytes: u64,
    free_bytes: u64,
    hot_video_bytes: u64,
    policy: &Policy,
) -> HotFloor {
    let percent = |p: u8| {
        u128::from(capacity_bytes)
            .checked_mul(u128::from(p))
            .map_or(u64::MAX, |scaled| {
                u64::try_from(scaled / 100).unwrap_or(u64::MAX)
            })
    };
    let min_free = policy.hot_min_free.get();
    let (floor, target) = (percent(min_free), percent(min_free.saturating_add(1)));
    let reserve = effective_reserve_bytes(capacity_bytes, policy.emergency_reserve_bytes);
    if reserve <= floor {
        return HotFloor {
            floor_bytes: floor,
            target_bytes: target,
            reserve_unreachable: false,
        };
    }
    if free_bytes.saturating_add(hot_video_bytes) < reserve {
        return HotFloor {
            floor_bytes: floor,
            target_bytes: target,
            reserve_unreachable: true,
        };
    }
    HotFloor {
        floor_bytes: reserve,
        target_bytes: reserve.saturating_add(target.saturating_sub(floor)),
        reserve_unreachable: false,
    }
}
