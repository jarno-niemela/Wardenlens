//! The pure tier planner (ADR 0005 section 6, amended by the ticket #44 override of case 4).

use std::collections::HashSet;
use std::fmt;

use crate::time::Timestamp;

use super::types::{
    ArchiveState, Policy, SegmentId, StoredSegment, Tier, VolumeSpace, effective_reserve_bytes,
    hot_floor,
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
    /// the volume), and this tick's plan deletes no hot video to hold the rolling budget: the
    /// archive absorbs the ingest, there is nothing ingested, the moves already cover it, or the
    /// hot video is already below the rolling budget and the emergency reserve is free. Or only
    /// the emergency reserve cannot be reached (`Plan::reserve_floor_unreachable`): the
    /// percentage floor is then still in force and, without an archive, can still delete hot
    /// video to restore it.
    /// State, never an error.
    Unsatisfiable,
    /// As `Unsatisfiable`, and this tick's plan deletes hot video to hold it at the rolling
    /// budget because the archive cannot absorb it. Raise an alert. The adapter must alert on
    /// `RollingBuffer`; on `Unsatisfiable` while the plan's `archive` is not `Available` (the
    /// buffer is then rolling but this tick happened to delete nothing); and on `Unsatisfiable`
    /// whenever `reserve_floor_unreachable` is set, whatever the archive state. When
    /// the emergency reserve cannot be met even after deleting all hot video, all of it is
    /// deleted and this is still the state: the adapter must alert.
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
    /// Hot-video byte level the rolling buffer holds: `Some` exactly when the hot floor is
    /// unreachable and the archive cannot take the load (the rolling-buffer case), else
    /// `None`. It equals the input level, except that when [`Policy::emergency_reserve_bytes`]
    /// forces deletes below it, it ratchets down to the hot video left. It recovers after
    /// such a ratchet, but only up to [`Plan::rolling_ceiling`], and never rises above it.
    /// A budget of 0 keeps no hot video.
    ///
    /// The adapter must store this value and `rolling_ceiling` and pass them back as
    /// [`PlanInput::rolling_budget`] and [`PlanInput::rolling_ceiling`] on the next tick, clear
    /// both when they are `None`, clear them when the volume or the configuration changes, and
    /// never feed back a budget larger than the previous plan's ceiling.
    pub rolling_budget: Option<u64>,
    /// Ceiling of the rolling budget, `Some` exactly when `rolling_budget` is: the level the
    /// budget may recover to. The adapter feeds it back as [`PlanInput::rolling_ceiling`].
    pub rolling_ceiling: Option<u64>,
    /// Foreign or quarantined data keeps the archive below its floor even when everything
    /// it holds is evicted. Kept separate because `ArchiveStatus::Full` takes precedence
    /// over `BelowFloor` in `archive`.
    pub archive_below_floor: bool,
    /// The emergency reserve would raise the hot floor above the percentage floor but the
    /// volume cannot reach it (free space plus all hot video is below the reserve). The reserve
    /// is then not part of the floor, so outside the rolling buffer nothing is deleted or
    /// moved for it (`hot` is `Unsatisfiable`); inside it the #44 drain toward the reserve still
    /// applies (`hot` is `RollingBuffer`). The adapter must alert on it whatever the
    /// archive state.
    pub reserve_floor_unreachable: bool,
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
    /// Bytes recorded since the previous plan. Used only to set the initial rolling-buffer
    /// budget when entering the buffer with no `rolling_budget`: the budget is then the hot
    /// video held before this tick's ingest. A seed of 0 keeps no hot video.
    pub ingested_bytes: u64,
    /// The `rolling_budget` of the previous [`Plan`], fed back by the adapter; `None` when
    /// the previous plan had none (or there was no previous plan). While `Some`, the rolling
    /// buffer deletes oldest hot segments until remaining hot video is at most this level
    /// (and the emergency reserve is free). Never feed back more than the previous plan
    /// returned; clear it when the volume or configuration changes.
    /// The target is an absolute level, so segment-size overshoot never accumulates.
    pub rolling_budget: Option<u64>,
    /// The `rolling_ceiling` of the previous [`Plan`], fed back by the adapter; `None` when the
    /// previous plan had none, in which case the ceiling is the budget in effect (the fed
    /// `rolling_budget`, else the seed): the budget then never rises. The budget recovers after
    /// a reserve-forced ratchet up to `min(ceiling, hot video + free space - emergency reserve)`
    /// (the free space plus the hot video is what a recorder with the reserve kept free could
    /// hold; deleting or moving video does not change that sum). A `rolling_budget` above the
    /// ceiling is lowered to it. Clear it with `rolling_budget`.
    pub rolling_ceiling: Option<u64>,
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

/// The reserve in force on this hot volume (see [`effective_reserve_bytes`]).
fn effective_reserve(input: &PlanInput<'_>) -> u64 {
    effective_reserve_bytes(
        input.hot.capacity_bytes,
        input.policy.emergency_reserve_bytes,
    )
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

/// The rolling budget the tick starts from and its ceiling (see [`PlanInput::rolling_ceiling`]).
///
/// The level is the fed budget, else the video held before this tick's ingest (the seed). The
/// ceiling is the fed ceiling, else that level; the level is lowered to the ceiling. Then the
/// level recovers up to `min(ceiling, reachable - reserve)`, never downwards.
fn rolling_levels(input: &PlanInput<'_>, hot_total: u64, reachable: u64) -> (u64, u64) {
    let level = input
        .rolling_budget
        .unwrap_or_else(|| hot_total.saturating_sub(input.ingested_bytes));
    let ceiling = input.rolling_ceiling.unwrap_or(level);
    let level = level.min(ceiling);
    let room = reachable.saturating_sub(effective_reserve(input));
    (level.max(ceiling.min(room)), ceiling)
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
    /// Bytes hot deletes must free: 0 when not below the floor or when the floor is unreachable
    /// (the rolling buffer sizes its deletes by the budget instead); the target shortfall when the
    /// target is reachable by deleting all hot video, else the floor shortfall.
    delete_goal: u64,
    /// The floor cannot be restored even by deleting all hot video.
    unsatisfiable: bool,
    /// Total size of the hot segments.
    hot_total: u64,
    /// Hot-video level the rolling buffer starts the tick holding, were it in effect: the fed
    /// (or seeded) level, recovered up to `min(ceiling, reachable - reserve)`.
    budget: u64,
    /// The level the budget may recover to; never below `budget`.
    ceiling: u64,
    /// Free space of the hot volume before the plan.
    free: u64,
    /// Free space the rolling buffer keeps ([`Policy::emergency_reserve_bytes`]).
    reserve: u64,
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
/// without a usable archive, a rolling buffer deletes the oldest hot video until it is at
/// most the rolling budget (see [`PlanInput::rolling_budget`]) and the emergency reserve is free.
/// The same holds for the archive: its video is evicted only when that can restore its floor.
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
    let hot_total = sum_bytes(&hot, OverflowQuantity::HotTotal)?;
    let free = input.hot.free_bytes;
    let reachable = free
        .checked_add(hot_total)
        .ok_or(PlanError::Overflow(OverflowQuantity::HotTotal))?;
    let floor = hot_floor(input.hot.capacity_bytes, free, hot_total, &input.policy);
    let (hot_floor, hot_target) = (floor.floor_bytes, floor.target_bytes);
    let below = free < hot_floor;
    let unsatisfiable = reachable < hot_floor;
    let (budget, ceiling) = rolling_levels(input, hot_total, reachable);
    let need = HotNeed {
        needed: if below {
            hot_target.saturating_sub(free)
        } else {
            0
        },
        delete_goal: match (below, unsatisfiable, reachable >= hot_target) {
            (false, _, _) | (true, true, _) => 0,
            (true, false, true) => hot_target.saturating_sub(free),
            (true, false, false) => hot_floor.saturating_sub(free),
        },
        unsatisfiable,
        hot_total,
        free,
        reserve: effective_reserve(input),
        budget,
        ceiling,
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
    let archive_cannot_help = archive.is_none() || moves.archive_full || below_floor;
    let rolling = plan_hot_deletes(&hot, &need, &moves, archive_cannot_help, &mut actions);
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
        reserve_floor_unreachable: floor.reserve_unreachable,
        hot: match (need.unsatisfiable, rolling.deleted) {
            (false, _) if floor.reserve_unreachable => HotState::Unsatisfiable,
            (false, _) => HotState::Ok,
            (true, false) => HotState::Unsatisfiable,
            (true, true) => HotState::RollingBuffer,
        },
        rolling_budget: rolling.budget,
        rolling_ceiling: rolling.budget.map(|_| need.ceiling),
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

/// Outcome of the hot-delete step.
struct HotDeletes {
    /// Hot video was deleted to hold an unreachable floor (the rolling buffer).
    deleted: bool,
    /// The rolling budget, set exactly in the rolling-buffer case.
    budget: Option<u64>,
}

/// Pushes hot deletions when the archive cannot take the load.
///
/// Deletion goes to the target only when deleting all hot video can reach it; when only the
/// floor is reachable it stops there, since deleting further loses recordings for no gain.
/// When the floor is unreachable (the rolling buffer) it deletes the oldest hot video until
/// what remains after the moves is at most the budget and the free space after the moves is at
/// least the emergency reserve, or no hot video is left. When the reserve forced deletes below
/// the budget, the reported budget is the video that remains (a ratchet down); otherwise it is
/// the budget unchanged. Ratcheting on every tick would drain the buffer whenever new segments
/// are smaller than the evicted ones.
fn plan_hot_deletes(
    hot: &[&StoredSegment],
    need: &HotNeed,
    moves: &Moves,
    archive_cannot_help: bool,
    actions: &mut Vec<Action>,
) -> HotDeletes {
    let none = HotDeletes {
        deleted: false,
        budget: None,
    };
    if !archive_cannot_help {
        return none;
    }
    let mut deleted = false;
    if need.unsatisfiable {
        let mut remaining = need.hot_total.saturating_sub(moves.bytes);
        let mut free = need.free.saturating_add(moves.bytes);
        let mut reserve_forced = false;
        for seg in hot.iter().skip(moves.count) {
            let over_budget = remaining > need.budget;
            if !over_budget && free >= need.reserve {
                break;
            }
            // Deleting at or below the budget happens only for the emergency reserve.
            reserve_forced |= !over_budget;
            actions.push(Action::Delete(seg.id));
            deleted = true;
            remaining = remaining.saturating_sub(seg.bytes);
            free = free.saturating_add(seg.bytes);
        }
        return HotDeletes {
            deleted,
            budget: Some(if reserve_forced {
                need.budget.min(remaining)
            } else {
                need.budget
            }),
        };
    }
    let mut gone = moves.bytes;
    for seg in hot.iter().skip(moves.count) {
        if gone >= need.delete_goal {
            break;
        }
        actions.push(Action::Delete(seg.id));
        gone = gone.saturating_add(seg.bytes);
    }
    none
}
