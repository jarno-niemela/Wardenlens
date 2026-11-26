//! The snapshot the loop keeps for the API (ticket #63): built from the probe of the tick, the
//! tick's counts and the index, and nothing else. It carries no path, no camera and no error text.

use wardenlens_core::storage::{
    ArchiveCondition, ArchiveUnavailableCause, MinFreePercent, SegmentIndex, StoredSegment,
    TickErrorKind, Tier, TierStatus, TierTotals, VolumeSpace, VolumeStatus,
};

use crate::error::TickError;
use crate::index::SharedIndex;
use crate::probe::{ArchiveProbe, UnavailableCause};

pub(crate) const fn cause_class(cause: UnavailableCause) -> ArchiveUnavailableCause {
    match cause {
        UnavailableCause::Missing => ArchiveUnavailableCause::Missing,
        UnavailableCause::SameFilesystem => ArchiveUnavailableCause::SameFilesystem,
        UnavailableCause::ReadOnly => ArchiveUnavailableCause::ReadOnly,
        UnavailableCause::NoMarker => ArchiveUnavailableCause::NoMarker,
        UnavailableCause::MoveFailures => ArchiveUnavailableCause::MoveFailures,
        UnavailableCause::Unusable => ArchiveUnavailableCause::Unusable,
        UnavailableCause::ProbeFailed => ArchiveUnavailableCause::ProbeFailed,
    }
}

pub(crate) const fn error_kind(e: &TickError) -> TickErrorKind {
    match e {
        TickError::HotVolume(_) => TickErrorKind::HotVolume,
        TickError::Index => TickErrorKind::Index,
        TickError::Plan(_) => TickErrorKind::Plan,
    }
}

/// The archive's condition from the tick's last probe. A probe state this version does not know
/// is reported as unavailable (`other`): the safe reading, since moves treat it the same way.
pub(crate) const fn archive_condition(probe: &ArchiveProbe, full: bool) -> ArchiveCondition {
    match probe {
        ArchiveProbe::Available(_) if full => ArchiveCondition::Full,
        ArchiveProbe::Available(_) => ArchiveCondition::Available,
        ArchiveProbe::Unavailable(c) => ArchiveCondition::Unavailable(cause_class(*c)),
    }
}

/// How many volumes of this probe are under their floor, by the byte rule of the planner. The
/// archive counts only while it is available (an absent volume has no space to measure).
pub(crate) fn breaches(
    hot: Option<VolumeSpace>,
    hot_floor: MinFreePercent,
    archive: &ArchiveProbe,
    archive_floor: MinFreePercent,
) -> u64 {
    let hot = hot.is_some_and(|s| VolumeStatus::new(s, hot_floor).below_floor);
    let archive = match archive {
        ArchiveProbe::Available(s) => VolumeStatus::new(*s, archive_floor).below_floor,
        _ => false,
    };
    u64::from(hot).saturating_add(u64::from(archive))
}

/// A tier's status from its volume and the rows last read.
pub(crate) fn tier_status(
    space: Option<VolumeSpace>,
    floor: MinFreePercent,
    rows: &TierRows,
) -> TierStatus {
    TierStatus {
        volume: space.map(|s| VolumeStatus::new(s, floor)),
        segments: rows.segments,
        oldest: rows.oldest.map(|s| s.ended_at),
        newest: rows.newest.map(|s| s.ended_at),
    }
}

/// The rows of one tier as the index reports them.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TierRows {
    pub(crate) segments: u64,
    pub(crate) oldest: Option<StoredSegment>,
    pub(crate) newest: Option<StoredSegment>,
}

/// Counts, the oldest and the newest row of both tiers; `None` when any index call failed.
pub(crate) fn read_rows<I: SegmentIndex>(index: &SharedIndex<I>) -> Option<(TierRows, TierRows)> {
    let totals: TierTotals = index.totals().ok()?;
    let one = |tier: Tier, segments: u64| -> Option<TierRows> {
        Some(TierRows {
            segments,
            oldest: index.oldest(tier, None, 1).ok()?.into_iter().next(),
            newest: index.newest(tier).ok()?,
        })
    };
    Some((
        one(Tier::Hot, totals.hot.segments)?,
        one(Tier::Archive, totals.archive.segments)?,
    ))
}
