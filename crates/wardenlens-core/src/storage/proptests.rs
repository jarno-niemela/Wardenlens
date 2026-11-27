//! Property tests for the planner invariants.

use std::collections::HashSet;

use proptest::prelude::*;

use crate::time::{DurationMs, Timestamp};

use super::tests::simulate;
use super::{
    Action, ArchiveState, ArchiveStatus, HotState, MinFreePercent, PlanInput, Policy, SegmentId,
    StoredSegment, Tier, VolumeSpace, plan,
};

fn volume() -> impl Strategy<Value = VolumeSpace> {
    (1_u64..=1_000_000).prop_flat_map(|capacity| {
        (Just(capacity), 0..=capacity).prop_map(|(capacity_bytes, free_bytes)| VolumeSpace {
            capacity_bytes,
            free_bytes,
        })
    })
}

fn segments() -> impl Strategy<Value = Vec<StoredSegment>> {
    prop::collection::vec((any::<bool>(), 0_u64..50_000, 0_u64..2_000_000), 0..40).prop_map(|v| {
        v.into_iter()
            .enumerate()
            .map(|(i, (hot, bytes, ended))| StoredSegment {
                id: SegmentId::new(u64::try_from(i).unwrap_or(0)),
                tier: if hot { Tier::Hot } else { Tier::Archive },
                bytes,
                ended_at: Timestamp::from_unix_millis(i64::try_from(ended).unwrap()),
            })
            .collect()
    })
}

proptest! {
    #[test]
    fn plan_meets_floors_or_reports_state_and_never_repeats_a_segment(
        hot in volume(),
        archive in prop::option::of(volume()),
        segs in segments(),
        hot_pct in 0_u8..=90,
        arch_pct in 0_u8..=90,
        max_age_ms in 0_u64..2_000_000,
        ingested in 0_u64..100_000,
    ) {
        let policy = Policy {
            hot_min_free: MinFreePercent::new(hot_pct).unwrap(),
            archive_min_free: MinFreePercent::new(arch_pct).unwrap(),
            hot_max_age: DurationMs::from_millis(max_age_ms),
            emergency_reserve_bytes: 0,
        };
        let state = archive.map_or(ArchiveState::Unavailable, ArchiveState::Available);
        let input = PlanInput {
            hot, archive: state, segments: &segs,
            now: Timestamp::from_unix_millis(2_000_000), policy, ingested_bytes: ingested,
            rolling_budget: None,
            rolling_ceiling: None,
        };
        let p = plan(&input).unwrap();

        let mut seen = HashSet::new();
        for a in &p.actions {
            let id = match a { Action::MoveToArchive(id) | Action::Delete(id) => *id };
            prop_assert!(seen.insert(id), "segment in two actions");
        }
        let (hot_after, arch_after, _) = simulate(hot.free_bytes, archive.map(|a| a.free_bytes), &segs, &p);

        // Hot floor holds unless the plan reports the state; the state is measured
        // against the floor, computed independently.
        let hot_floor = hot.capacity_bytes * u64::from(hot_pct) / 100;
        let hot_total: u64 = segs.iter().filter(|s| s.tier == Tier::Hot).map(|s| s.bytes).sum();
        let unsat = hot.free_bytes + hot_total < hot_floor;
        prop_assert_eq!(p.hot != HotState::Ok, unsat);
        if !unsat {
            prop_assert!(hot_after >= hot_floor);
        }
        // Moves keep the archive at or above its floor.
        let moved = p.actions.iter().any(|a| matches!(a, Action::MoveToArchive(_)));
        let is_archive = |id: &SegmentId| segs.iter().any(|s| s.id == *id && s.tier == Tier::Archive);
        let arch_deleted = p.actions.iter().any(|a| matches!(a, Action::Delete(id) if is_archive(id)));
        if let (true, Some(a), Some(after)) = (moved || arch_deleted, archive, arch_after) {
            prop_assert!(after >= a.capacity_bytes * u64::from(arch_pct) / 100);
        }
        // With a usable, non-full archive no hot video is deleted.
        let hot_deleted = p.actions.iter().any(|a| matches!(a, Action::Delete(id) if !is_archive(id)));
        if matches!(p.archive, ArchiveStatus::Available | ArchiveStatus::BelowFloor) {
            prop_assert!(!hot_deleted);
        }
        // Per tier, planned segments are the oldest-first prefix, and all ids exist.
        for tier in [Tier::Hot, Tier::Archive] {
            let mut sorted: Vec<&StoredSegment> = segs.iter().filter(|s| s.tier == tier).collect();
            sorted.sort_by_key(|s| (s.ended_at, s.id));
            let picked: Vec<SegmentId> = p.actions.iter()
                .map(|a| match a { Action::MoveToArchive(id) | Action::Delete(id) => *id })
                .filter(|id| sorted.iter().any(|s| s.id == *id))
                .collect();
            let prefix: Vec<SegmentId> = sorted.iter().take(picked.len()).map(|s| s.id).collect();
            prop_assert_eq!(picked, prefix);
        }
        for a in &p.actions {
            let (Action::MoveToArchive(id) | Action::Delete(id)) = a;
            prop_assert!(segs.iter().any(|s| s.id == *id));
        }
        // Archive deletions precede moves, which precede hot deletions.
        let rank = |a: &Action, segs: &[StoredSegment]| match a {
            Action::MoveToArchive(_) => 1,
            Action::Delete(id) => {
                if segs.iter().any(|s| s.id == *id && s.tier == Tier::Archive) { 0 } else { 2 }
            }
        };
        let ranks: Vec<u8> = p.actions.iter().map(|a| rank(a, &segs)).collect();
        prop_assert!(ranks.windows(2).all(|w| w[0] <= w[1]));
        // Without an archive nothing archive-side is touched.
        if archive.is_none() {
            prop_assert!(ranks.iter().all(|r| *r == 2));
        }
    }

    #[test]
    fn rolling_buffer_holds_hot_video_at_the_budget_minimally(
        hot in volume(),
        segs in segments(),
        hot_pct in 0_u8..=90,
        ingested in 0_u64..100_000,
        fed in prop::option::of(0_u64..200_000),
        archive in prop::option::of(volume()),
    ) {
        let policy = Policy {
            hot_min_free: MinFreePercent::new(hot_pct).unwrap(),
            archive_min_free: MinFreePercent::default(),
            hot_max_age: DurationMs::from_millis(u64::MAX / 2),
            emergency_reserve_bytes: 0,
        };
        let state = archive.map_or(ArchiveState::Unavailable, ArchiveState::Available);
        let input = PlanInput {
            hot, archive: state, segments: &segs,
            now: Timestamp::from_unix_millis(2_000_000), policy, ingested_bytes: ingested,
            rolling_budget: fed,
            rolling_ceiling: None,
        };
        let p = plan(&input).unwrap();
        let hot_total: u64 = segs.iter().filter(|s| s.tier == Tier::Hot).map(|s| s.bytes).sum();
        let floor_unreachable = u128::from(hot.free_bytes) + u128::from(hot_total)
            < u128::from(hot.capacity_bytes) * u128::from(hot_pct) / 100;
        let cannot_help = !matches!(p.archive, ArchiveStatus::Available) || p.archive_below_floor;
        // The budget exists exactly in the rolling-buffer case.
        prop_assert_eq!(p.rolling_budget.is_some(), floor_unreachable && cannot_help);
        if p.hot == HotState::RollingBuffer {
            prop_assert!(p.rolling_budget.is_some());
        }
        if let Some(budget) = p.rolling_budget {
            let limit = fed.unwrap_or(hot_total.saturating_sub(ingested));
            let bytes_of = |id: &SegmentId| segs.iter().find(|s| s.id == *id).map_or(0, |s| s.bytes);
            let gone: u64 = p.actions.iter()
                .filter_map(|a| match a {
                    Action::MoveToArchive(id) => Some(bytes_of(id)),
                    Action::Delete(id) if segs.iter().any(|s| s.id == *id && s.tier == Tier::Hot) => Some(bytes_of(id)),
                    _ => None,
                })
                .sum();
            let remaining = hot_total - gone;
            // Reserve 0: nothing forces a ratchet, so the level is held.
            prop_assert_eq!(budget, limit);
            prop_assert!(remaining <= limit);
            let last = p.actions.iter().rev().find_map(|a| match a {
                Action::Delete(id) if segs.iter().any(|s| s.id == *id && s.tier == Tier::Hot) => Some(bytes_of(id)),
                _ => None,
            });
            if let Some(last) = last {
                prop_assert!(remaining + last > limit);
            }
        }
    }

    /// With a non-zero emergency reserve (ticket #108): without an archive, free space after the
    /// plan is at least the reserve or no hot video remains; the budget never exceeds its
    /// ceiling (which is the level in effect when none is fed); a ratchet below the level the
    /// tick started from happens only when the reserve forced the last delete.
    #[test]
    fn reserve_is_kept_the_budget_stays_under_its_ceiling_and_ratchets_only_when_forced(
        hot in volume(),
        segs in segments(),
        hot_pct in 0_u8..=90,
        reserve in prop_oneof![Just(0_u64), 0_u64..1_200_000, Just(u64::MAX)],
        ingested in 0_u64..100_000,
        fed in prop::option::of(0_u64..200_000),
        ceiling in prop::option::of(0_u64..200_000),
        with_archive in any::<bool>(),
        archive in volume(),
    ) {
        let policy = Policy {
            hot_min_free: MinFreePercent::new(hot_pct).unwrap(),
            archive_min_free: MinFreePercent::default(),
            hot_max_age: DurationMs::from_millis(u64::MAX / 2),
            emergency_reserve_bytes: reserve,
        };
        let state = if with_archive { ArchiveState::Available(archive) } else { ArchiveState::Unavailable };
        let input = PlanInput {
            hot, archive: state, segments: &segs,
            now: Timestamp::from_unix_millis(2_000_000), policy, ingested_bytes: ingested,
            rolling_budget: fed, rolling_ceiling: ceiling,
        };
        let p = plan(&input).unwrap();
        let hot_total: u64 = segs.iter().filter(|s| s.tier == Tier::Hot).map(|s| s.bytes).sum();
        let (hot_after, _, left) = simulate(hot.free_bytes, with_archive.then_some(archive.free_bytes), &segs, &p);
        let remaining: u64 = left.iter().filter(|s| s.tier == Tier::Hot).map(|s| s.bytes).sum();
        if !with_archive {
            prop_assert!(remaining == 0 || hot_after >= reserve,
                "free {} reserve {} left {} plan {:?}", hot_after, reserve, remaining, p);
        }
        prop_assert_eq!(p.rolling_ceiling.is_some(), p.rolling_budget.is_some());
        if let (Some(b), Some(c)) = (p.rolling_budget, p.rolling_ceiling) {
            let level = fed.unwrap_or(hot_total.saturating_sub(ingested));
            let expected_ceiling = ceiling.unwrap_or(level);
            prop_assert_eq!(c, expected_ceiling);
            prop_assert!(b <= c, "budget {} above its ceiling {}", b, c);
            if ceiling.is_none() {
                prop_assert!(b <= level, "budget rose without a ceiling");
            }
            let reachable = hot.free_bytes + hot_total;
            let start = level.min(c).max(c.min(reachable.saturating_sub(reserve)));
            if b < start {
                // A ratchet: the budget is what is left, and the last hot delete was needed
                // for the reserve (without it free space would have been under the reserve).
                prop_assert_eq!(b, remaining);
                let is_hot = |id: &SegmentId| segs.iter().any(|s| s.id == *id && s.tier == Tier::Hot);
                let last = p.actions.iter().rev().find_map(|a| match a {
                    Action::Delete(id) if is_hot(id) => segs.iter().find(|s| s.id == *id).map(|s| s.bytes),
                    _ => None,
                });
                let last = last.unwrap();
                prop_assert!(hot_after - last < reserve, "ratchet without the reserve forcing it");
            }
        }
    }
}
