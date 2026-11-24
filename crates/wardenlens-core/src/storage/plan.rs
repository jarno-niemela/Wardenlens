//! The pure tier planner (ADR 0005 section 6, amended by the ticket #44 override of case 4).

use std::collections::HashSet;
use std::fmt;

use crate::time::Timestamp;

use super::types::{ArchiveState, Policy, SegmentId, StoredSegment, Tier, VolumeSpace};

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
    /// The archive is `Available` but its space report is unusable (zero capacity or more
    /// free space than capacity); it is treated like an unavailable archive and its rows
    /// are not touched.
    Unusable,
    /// The archive is available but cannot absorb a wanted move even after
    /// evicting everything it holds.
    Full,
    /// Foreign or quarantined data keeps the archive below its floor: even evicting every
    /// archived segment cannot restore it. Nothing is evicted (it would only lose
    /// recordings, ADR 0005 section 6 case 4) and no move that needs eviction is planned.
    BelowFloor,
}

/// State of the hot volume after the plan, for health and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HotState {
    /// The floor is reachable: free space plus all hot video is at least the floor, so the
    /// plan restores it or it was never breached.
    Ok,
    /// The floor cannot be restored even by removing all hot video (something else fills
    /// the volume), and this tick's plan deletes no hot video to stop growth: the archive
    /// absorbs the ingest, there is nothing ingested, or the moves already cover it.
    /// State, never an error.
    Unsatisfiable,
    /// As `Unsatisfiable`, and this tick's plan deletes hot video as fast as it arrives
    /// because the archive cannot absorb it. Raise an alert.
    RollingBuffer,
}

/// The planner output: ordered actions plus the state to report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// Archive deletions first, then moves, then hot deletions; oldest first within each.
    pub actions: Vec<Action>,
    /// State of the archive for health and metrics.
    pub archive: ArchiveStatus,
    /// State of the hot volume.
    pub hot: HotState,
    /// Foreign or quarantined data keeps the archive below its floor even when everything
    /// it holds is evicted. Kept separate because `ArchiveStatus::Full` takes precedence
    /// over `BelowFloor` in `archive`.
    pub archive_below_floor: bool,
}

/// Why no plan could be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanError {
    /// The hot volume has zero capacity or more free space than capacity.
    HotVolumeUnusable,
    /// Two segments share an id.
    DuplicateSegment(SegmentId),
    /// Byte arithmetic overflowed `u64`; names the quantity. The input is implausible
    /// (corrupt index or probe), so the adapter must alert on this error.
    Overflow(OverflowQuantity),
}

/// The quantity whose computation overflowed in [`PlanError::Overflow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OverflowQuantity {
    /// A floor or target computed from a capacity.
    FloorOrTarget,
    /// The summed size of the hot segments.
    HotTotal,
    /// The summed size of the archive segments.
    ArchiveTotal,
    /// Archive free space plus archive segment sizes.
    ArchiveRoom,
    /// The summed size of the hot segments chosen for moving.
    MoveBytes,
    /// Moved bytes plus the archive floor or target.
    EvictionGoal,
}

impl fmt::Display for OverflowQuantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FloorOrTarget => "floor or target",
            Self::HotTotal => "hot segment total",
            Self::ArchiveTotal => "archive segment total",
            Self::ArchiveRoom => "archive free space plus segments",
            Self::MoveBytes => "bytes to move",
            Self::EvictionGoal => "archive eviction goal",
        })
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HotVolumeUnusable => write!(f, "hot volume is unusable"),
            Self::DuplicateSegment(id) => write!(f, "duplicate segment id {}", id.as_u64()),
            Self::Overflow(q) => write!(f, "byte arithmetic overflowed computing {q}"),
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
    pub now: Timestamp,
    /// Policy.
    pub policy: Policy,
    /// Bytes recorded since the previous plan; sizes the rolling buffer.
    pub ingested_bytes: u64,
}

/// Percent of `capacity` rounded down.
fn percent_of(capacity: u64, percent: u64) -> Result<u64, PlanError> {
    let overflow = PlanError::Overflow(OverflowQuantity::FloorOrTarget);
    let scaled = u128::from(capacity)
        .checked_mul(u128::from(percent))
        .ok_or(overflow)?;
    u64::try_from(scaled / 100).map_err(|_| overflow)
}

/// Floor and target (floor plus 1 pp headroom) in bytes of free space.
fn floor_and_target(capacity: u64, floor_percent: u8) -> Result<(u64, u64), PlanError> {
    let floor = u64::from(floor_percent);
    Ok((
        percent_of(capacity, floor)?,
        percent_of(capacity, floor.saturating_add(1))?,
    ))
}

fn sum_bytes(segments: &[&StoredSegment], what: OverflowQuantity) -> Result<u64, PlanError> {
    segments
        .iter()
        .try_fold(0_u64, |acc, s| acc.checked_add(s.bytes))
        .ok_or(PlanError::Overflow(what))
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
    /// Bytes hot deletes must free: 0 when not below the floor; the target shortfall when the
    /// target is reachable by deleting all hot video, else the floor shortfall.
    delete_goal: u64,
    /// The floor cannot be restored even by deleting all hot video.
    unsatisfiable: bool,
}

/// Archive-side facts.
struct ArchiveFacts {
    floor: u64,
    /// Most free space the archive can offer once everything it holds is evicted.
    room: u64,
}

/// Plans one tick.
///
/// Order of actions: archive deletions, then `MoveToArchive` oldest first, then hot deletions.
/// Hot video is deleted only when the archive cannot take it, and never to restore a floor that
/// deleting it cannot reach (ADR 0005 section 6 case 4); then moves are still planned and,
/// without a usable archive, a rolling buffer deletes hot video as fast as `ingested_bytes`
/// arrives. The same holds for the archive: its video is evicted only when that can restore
/// its floor.
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
    let hot_total = sum_bytes(&hot, OverflowQuantity::HotTotal)?;
    let free = input.hot.free_bytes;
    let reachable = free
        .checked_add(hot_total)
        .ok_or(PlanError::Overflow(OverflowQuantity::HotTotal))?;
    let below = free < hot_floor;
    let unsatisfiable = reachable < hot_floor;
    let need = HotNeed {
        needed: if below {
            hot_target.saturating_sub(free)
        } else {
            0
        },
        delete_goal: match (below, unsatisfiable, reachable >= hot_target) {
            (false, _, _) => 0,
            (true, true, _) => input.ingested_bytes,
            (true, false, true) => hot_target.saturating_sub(free),
            (true, false, false) => hot_floor.saturating_sub(free),
        },
        unsatisfiable,
    };
    let mut actions = Vec::new();
    let mut below_floor = false;
    let moves = match archive {
        Some(space) => {
            let (moves, unreachable) = plan_archive_side(input, space, &hot, &need, &mut actions)?;
            below_floor = unreachable;
            moves
        }
        None => Moves {
            count: 0,
            bytes: 0,
            archive_full: false,
        },
    };
    let rolling_buffer = plan_hot_deletes(&hot, &need, &moves, archive.is_some(), &mut actions);
    let archive_status = match (input.archive, archive) {
        (ArchiveState::Available(_), None) => ArchiveStatus::Unusable,
        (_, None) => ArchiveStatus::Unavailable,
        (_, Some(_)) if moves.archive_full => ArchiveStatus::Full,
        (_, Some(_)) if below_floor => ArchiveStatus::BelowFloor,
        (_, Some(_)) => ArchiveStatus::Available,
    };
    Ok(Plan {
        actions,
        archive: archive_status,
        archive_below_floor: below_floor,
        hot: match (need.unsatisfiable, rolling_buffer) {
            (false, _) => HotState::Ok,
            (true, false) => HotState::Unsatisfiable,
            (true, true) => HotState::RollingBuffer,
        },
    })
}

/// Pushes archive evictions then the moves; returns what was moved and whether the archive
/// floor is unreachable even by evicting everything.
fn plan_archive_side(
    input: &PlanInput<'_>,
    space: VolumeSpace,
    hot: &[&StoredSegment],
    need: &HotNeed,
    actions: &mut Vec<Action>,
) -> Result<(Moves, bool), PlanError> {
    let archive_segments = tier_segments(input.segments, Tier::Archive);
    let archive_total = sum_bytes(&archive_segments, OverflowQuantity::ArchiveTotal)?;
    let (floor, target) =
        floor_and_target(space.capacity_bytes, input.policy.archive_min_free.get())?;
    let facts = ArchiveFacts {
        floor,
        room: space
            .free_bytes
            .checked_add(archive_total)
            .ok_or(PlanError::Overflow(OverflowQuantity::ArchiveRoom))?,
    };
    let moves = choose_moves(input, &facts, hot, need)?;
    let breach = space.free_bytes < floor
        || space
            .free_bytes
            .checked_sub(moves.bytes)
            .is_none_or(|left| left < floor);
    if breach {
        let eviction_goal = |extra: u64| {
            moves
                .bytes
                .checked_add(extra)
                .ok_or(PlanError::Overflow(OverflowQuantity::EvictionGoal))
        };
        let to_target = eviction_goal(target)?;
        let to_floor = eviction_goal(floor)?;
        let goal = if facts.room >= to_target {
            Some(to_target)
        } else if facts.room >= to_floor {
            Some(to_floor)
        } else {
            None
        };
        if let Some(goal) = goal {
            let mut free = space.free_bytes;
            for seg in &archive_segments {
                if free >= goal {
                    break;
                }
                actions.push(Action::Delete(seg.id));
                free = free.saturating_add(seg.bytes);
            }
        }
    }
    actions.extend(
        hot.iter()
            .take(moves.count)
            .map(|s| Action::MoveToArchive(s.id)),
    );
    Ok((moves, facts.room < floor))
}

/// Picks the oldest hot segments to move: those past `hot_max_age`, plus as many as the hot
/// target needs (all of them when it is unreachable), as far as the archive can absorb them
/// while keeping its floor.
fn choose_moves(
    input: &PlanInput<'_>,
    facts: &ArchiveFacts,
    hot: &[&StoredSegment],
    need: &HotNeed,
) -> Result<Moves, PlanError> {
    let mut moves = Moves {
        count: 0,
        bytes: 0,
        archive_full: false,
    };
    for seg in hot {
        let aged = input.now.saturating_duration_since(seg.ended_at) > input.policy.hot_max_age;
        if !aged && moves.bytes >= need.needed {
            break;
        }
        let after = moves
            .bytes
            .checked_add(seg.bytes)
            .ok_or(PlanError::Overflow(OverflowQuantity::MoveBytes))?;
        let needed_room = after
            .checked_add(facts.floor)
            .ok_or(PlanError::Overflow(OverflowQuantity::EvictionGoal))?;
        if facts.room < needed_room {
            moves.archive_full = true;
            break;
        }
        moves.bytes = after;
        moves.count = moves.count.saturating_add(1);
    }
    Ok(moves)
}

/// Pushes hot deletions when the archive cannot take the load; returns whether any hot
/// segment was deleted to stop an unreachable floor from growing (the rolling buffer).
///
/// Deletion goes to the target only when deleting all hot video can reach it; when only the
/// floor is reachable it stops there, since deleting further loses recordings for no gain.
fn plan_hot_deletes(
    hot: &[&StoredSegment],
    need: &HotNeed,
    moves: &Moves,
    archive_available: bool,
    actions: &mut Vec<Action>,
) -> bool {
    let archive_cannot_help = !archive_available || moves.archive_full;
    if !archive_cannot_help {
        return false;
    }
    let mut gone = moves.bytes;
    let mut deleted = false;
    for seg in hot.iter().skip(moves.count) {
        if gone >= need.delete_goal {
            break;
        }
        actions.push(Action::Delete(seg.id));
        deleted = true;
        gone = gone.saturating_add(seg.bytes);
    }
    deleted && need.unsatisfiable
}
