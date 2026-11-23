//! The pure tier planner (ADR 0005 section 6, amended by the ticket #44 override of case 4).

use std::collections::HashSet;
use std::fmt;

use super::types::{
    ArchiveState, Policy, SegmentId, StoredSegment, Tier, TimestampMs, VolumeSpace,
};

/// One step of a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Move the segment from the hot to the archive tier.
    MoveToArchive(SegmentId),
    /// Delete the segment.
    Delete(SegmentId),
}

/// Why the archive did (not) take part in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveStatus {
    /// The archive is available and absorbs what the plan moves.
    Available,
    /// The archive is unavailable; hot video is deleted to hold the floor.
    Unavailable,
    /// The archive is available but cannot absorb a wanted move even after
    /// evicting everything it holds.
    Full,
}

/// The planner output: ordered actions plus the state to report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// Archive deletions first, then moves, then hot deletions; oldest first within each.
    pub actions: Vec<Action>,
    /// State of the archive for health and metrics.
    pub archive: ArchiveStatus,
    /// The hot floor cannot be restored even by deleting all hot video (something
    /// else fills the volume). Reported as state, never as an error.
    pub unsatisfiable: bool,
    /// Hot video is deleted as fast as it arrives to stop it growing; raise an alert.
    pub rolling_buffer: bool,
}

/// Why no plan could be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanError {
    /// The hot volume has zero capacity or more free space than capacity.
    HotVolumeUnusable,
    /// Two segments share an id.
    DuplicateSegment(SegmentId),
    /// Byte arithmetic overflowed `u64`.
    Overflow,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HotVolumeUnusable => write!(f, "hot volume is unusable"),
            Self::DuplicateSegment(id) => write!(f, "duplicate segment id {}", id.as_u64()),
            Self::Overflow => write!(f, "byte arithmetic overflowed"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Everything the planner needs for one tick.
#[derive(Debug, Clone, Copy)]
pub struct PlanInput<'a> {
    /// Space of the hot volume.
    pub hot: VolumeSpace,
    /// State of the archive.
    pub archive: ArchiveState,
    /// All segments of both tiers.
    pub segments: &'a [StoredSegment],
    /// The current time.
    pub now: TimestampMs,
    /// Policy.
    pub policy: Policy,
    /// Bytes recorded since the previous plan; sizes the rolling buffer.
    pub ingested_bytes: u64,
}

/// Percent of `capacity` rounded down.
fn percent_of(capacity: u64, percent: u64) -> Result<u64, PlanError> {
    let scaled = u128::from(capacity)
        .checked_mul(u128::from(percent))
        .ok_or(PlanError::Overflow)?;
    u64::try_from(scaled / 100).map_err(|_| PlanError::Overflow)
}

/// Floor and target (floor plus 1 pp headroom) in bytes of free space.
fn floor_and_target(capacity: u64, floor_percent: u8) -> Result<(u64, u64), PlanError> {
    let floor = u64::from(floor_percent);
    Ok((
        percent_of(capacity, floor)?,
        percent_of(capacity, floor.saturating_add(1))?,
    ))
}

fn sum_bytes(segments: &[&StoredSegment]) -> Result<u64, PlanError> {
    segments
        .iter()
        .try_fold(0_u64, |acc, s| acc.checked_add(s.bytes))
        .ok_or(PlanError::Overflow)
}

/// Segments of one tier, oldest first by `ended_at`, ties by id.
fn tier_segments(segments: &[StoredSegment], tier: Tier) -> Vec<&StoredSegment> {
    let mut picked: Vec<&StoredSegment> = segments.iter().filter(|s| s.tier == tier).collect();
    picked.sort_by_key(|s| (s.ended_at, s.id));
    picked
}

/// Result of choosing which hot segments to move.
struct Moves {
    count: usize,
    bytes: u64,
    archive_full: bool,
}

/// Hot-side facts that drive move and delete choices.
struct HotNeed {
    /// Bytes that must leave the hot volume to reach the target (0 when not below the floor).
    needed: u64,
    /// The floor cannot be restored even by deleting all hot video.
    unsatisfiable: bool,
}

/// Plans one tick.
///
/// Order of actions: archive deletions, then `MoveToArchive` oldest first, then hot deletions.
/// Hot video is deleted only when the archive cannot take it, never when the floor cannot be
/// restored by deleting it; in that case moves are still planned and, without a usable archive,
/// a rolling buffer deletes hot video as fast as `ingested_bytes` arrives.
///
/// # Errors
/// [`PlanError`] for an unusable hot volume, duplicate segment ids or byte overflow.
pub fn plan(input: &PlanInput<'_>) -> Result<Plan, PlanError> {
    if !input.hot.is_usable() {
        return Err(PlanError::HotVolumeUnusable);
    }
    let mut seen = HashSet::new();
    if let Some(dup) = input.segments.iter().find(|s| !seen.insert(s.id)) {
        return Err(PlanError::DuplicateSegment(dup.id));
    }
    let archive = match input.archive {
        ArchiveState::Available(space) if space.is_usable() => Some(space),
        _ => None,
    };
    let hot = tier_segments(input.segments, Tier::Hot);
    let (hot_floor, hot_target) =
        floor_and_target(input.hot.capacity_bytes, input.policy.hot_min_free.get())?;
    let hot_total = sum_bytes(&hot)?;
    let below = input.hot.free_bytes < hot_floor;
    let need = HotNeed {
        needed: if below {
            hot_target.saturating_sub(input.hot.free_bytes)
        } else {
            0
        },
        unsatisfiable: below && input.hot.free_bytes.saturating_add(hot_total) < hot_target,
    };
    let mut actions = Vec::new();
    let moves = match archive {
        Some(space) => plan_archive_side(input, space, &hot, &need, &mut actions)?,
        None => Moves {
            count: 0,
            bytes: 0,
            archive_full: false,
        },
    };
    let rolling_buffer =
        plan_hot_deletes(input, &hot, &need, &moves, archive.is_some(), &mut actions);
    Ok(Plan {
        actions,
        archive: match archive {
            None => ArchiveStatus::Unavailable,
            Some(_) if moves.archive_full => ArchiveStatus::Full,
            Some(_) => ArchiveStatus::Available,
        },
        unsatisfiable: need.unsatisfiable,
        rolling_buffer,
    })
}

/// Pushes archive evictions then the moves; returns what was moved.
fn plan_archive_side(
    input: &PlanInput<'_>,
    space: VolumeSpace,
    hot: &[&StoredSegment],
    need: &HotNeed,
    actions: &mut Vec<Action>,
) -> Result<Moves, PlanError> {
    let archive_segments = tier_segments(input.segments, Tier::Archive);
    let archive_total = sum_bytes(&archive_segments)?;
    let (floor, target) =
        floor_and_target(space.capacity_bytes, input.policy.archive_min_free.get())?;
    let moves = choose_moves(input, space, hot, need, archive_total, floor)?;
    let breach = space.free_bytes < floor
        || space
            .free_bytes
            .checked_sub(moves.bytes)
            .is_none_or(|left| left < floor);
    if breach {
        let goal = moves.bytes.checked_add(target).ok_or(PlanError::Overflow)?;
        let mut free = space.free_bytes;
        for seg in &archive_segments {
            if free >= goal {
                break;
            }
            actions.push(Action::Delete(seg.id));
            free = free.saturating_add(seg.bytes);
        }
    }
    actions.extend(
        hot.iter()
            .take(moves.count)
            .map(|s| Action::MoveToArchive(s.id)),
    );
    Ok(moves)
}

/// Picks the oldest hot segments to move: those past `hot_max_age`, plus as many as the hot
/// floor needs (all of them when it is unreachable), as far as the archive can absorb them.
fn choose_moves(
    input: &PlanInput<'_>,
    space: VolumeSpace,
    hot: &[&StoredSegment],
    need: &HotNeed,
    archive_total: u64,
    archive_floor: u64,
) -> Result<Moves, PlanError> {
    let cutoff = input
        .now
        .as_millis()
        .saturating_sub(u64::try_from(input.policy.hot_max_age.as_millis()).unwrap_or(u64::MAX));
    // Most the archive can offer once everything it holds is evicted.
    let room = space.free_bytes.saturating_add(archive_total);
    let mut moves = Moves {
        count: 0,
        bytes: 0,
        archive_full: false,
    };
    for seg in hot {
        let aged = seg.ended_at.as_millis() < cutoff;
        let pressure = need.unsatisfiable || moves.bytes < need.needed;
        if !aged && !pressure {
            break;
        }
        let after = moves
            .bytes
            .checked_add(seg.bytes)
            .ok_or(PlanError::Overflow)?;
        if room < after.saturating_add(archive_floor) {
            moves.archive_full = true;
            break;
        }
        moves.bytes = after;
        moves.count = moves.count.saturating_add(1);
    }
    Ok(moves)
}

/// Pushes hot deletions when the archive cannot take the load; returns whether the
/// rolling buffer is in effect.
fn plan_hot_deletes(
    input: &PlanInput<'_>,
    hot: &[&StoredSegment],
    need: &HotNeed,
    moves: &Moves,
    archive_available: bool,
    actions: &mut Vec<Action>,
) -> bool {
    let archive_cannot_help = !archive_available || moves.archive_full;
    if !archive_cannot_help || moves.bytes >= need.needed {
        return false;
    }
    // Reachable: restore the floor plus headroom. Unreachable: only stop growth.
    let goal = if need.unsatisfiable {
        input.ingested_bytes
    } else {
        need.needed
    };
    let mut gone = moves.bytes;
    for seg in hot.iter().skip(moves.count) {
        if gone >= goal {
            break;
        }
        actions.push(Action::Delete(seg.id));
        gone = gone.saturating_add(seg.bytes);
    }
    need.unsatisfiable
}
