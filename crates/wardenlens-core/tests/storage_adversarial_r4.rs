//! Adversarial tests, round 4, for the tiered storage planner (ticket #44): the absolute
//! rolling-buffer budget.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code; failures should panic"
)]

use proptest::prelude::*;
use wardenlens_core::storage::{
    Action, ArchiveState, ArchiveStatus, HotState, MinFreePercent, Plan, PlanError, PlanInput,
    Policy, SegmentId, StoredSegment, Tier, VolumeSpace, plan,
};
use wardenlens_core::time::{DurationMs, Timestamp};

const NOW: i64 = 1_000_000;

fn seg(id: u64, tier: Tier, bytes: u64, ended_ms: i64) -> StoredSegment {
    StoredSegment {
        id: SegmentId::new(id),
        tier,
        bytes,
        ended_at: Timestamp::from_unix_millis(ended_ms),
    }
}

fn vol(capacity_bytes: u64, free_bytes: u64) -> VolumeSpace {
    VolumeSpace {
        capacity_bytes,
        free_bytes,
    }
}

fn policy(hp: u8, ap: u8) -> Policy {
    Policy {
        hot_min_free: MinFreePercent::new(hp).unwrap(),
        archive_min_free: MinFreePercent::new(ap).unwrap(),
        hot_max_age: DurationMs::from_millis(u64::MAX),
        emergency_reserve_bytes: 0,
    }
}

fn policy_with_reserve(reserve: u64) -> Policy {
    Policy {
        emergency_reserve_bytes: reserve,
        ..policy(25, 25)
    }
}

fn run(
    hot: VolumeSpace,
    archive: ArchiveState,
    segments: &[StoredSegment],
    policy: Policy,
    ingested: u64,
    rolling_budget: Option<u64>,
) -> Result<Plan, PlanError> {
    plan(&PlanInput {
        hot,
        archive,
        segments,
        now: Timestamp::from_unix_millis(NOW),
        policy,
        ingested_bytes: ingested,
        rolling_budget,
    })
}

fn id_of(a: &Action) -> SegmentId {
    match a {
        Action::MoveToArchive(id) | Action::Delete(id) => *id,
        _ => unreachable!(),
    }
}

fn hot_video(segs: &[StoredSegment]) -> u64 {
    segs.iter()
        .filter(|s| s.tier == Tier::Hot)
        .map(|s| s.bytes)
        .sum()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Archive unavailable, floor unreachable, random per-tick segment sizes: with the budget
    /// fed back, hot video after every tick stays in (budget - largest segment, budget] and the
    /// budget never changes.
    #[test]
    fn rolling_buffer_holds_hot_video_in_band_for_any_size_mix(
        initial in prop::collection::vec(1_u64..5_000, 0..40),
        ticks in prop::collection::vec(prop::collection::vec(0_u64..8_000, 0..5), 1..60),
    ) {
        let cap = 10_000_000_u64; // floor 25 % = 2.5 MB, never reachable below
        let mut segs: Vec<StoredSegment> = initial.iter().enumerate()
            .map(|(i, b)| seg(u64::try_from(i).unwrap(), Tier::Hot, *b, i64::try_from(i).unwrap()))
            .collect();
        let mut next = u64::try_from(segs.len()).unwrap();
        let mut budget: Option<u64> = None;
        let mut largest = initial.iter().copied().max().unwrap_or(0);
        for (t, sizes) in ticks.iter().enumerate() {
            let mut ingested = 0;
            for b in sizes {
                segs.push(seg(next, Tier::Hot, *b, i64::try_from(next).unwrap()));
                next += 1;
                ingested += b;
                largest = largest.max(*b);
            }
            let before = hot_video(&segs);
            let free = 1_000_000_u64.saturating_sub(before).min(1_000_000);
            let p = run(vol(cap, free), ArchiveState::Unavailable, &segs, policy(25, 25), ingested, budget).unwrap();
            let b = budget.unwrap_or(before - ingested);
            let reported = p.rolling_budget.unwrap();
            prop_assert!(matches!(p.hot, HotState::RollingBuffer | HotState::Unsatisfiable), "tick {}", t);
            // Oldest first, deletes only.
            let gone: Vec<SegmentId> = p.actions.iter().map(|a| match a {
                Action::Delete(id) => *id, other => panic!("unexpected {other:?}"),
            }).collect();
            let oldest: Vec<SegmentId> = segs.iter().take(gone.len()).map(|s| s.id).collect();
            prop_assert_eq!(&gone, &oldest);
            segs.retain(|s| !gone.contains(&s.id));
            let after = hot_video(&segs);
            prop_assert!(after <= b, "tick {}: {} > budget {}", t, after, b);
            if !gone.is_empty() {
                prop_assert!(after + largest > b, "tick {}: overshoot {} vs budget {}", t, after, b);
            }
            // Reserve 0: the budget is held unchanged.
            prop_assert_eq!(reported, b, "tick {}", t);
            budget = p.rolling_budget;
        }
    }

    /// The budget is `Some` exactly when the hot floor is unreachable and the archive cannot
    /// help (unavailable, unusable or full), whatever was fed in.
    #[test]
    fn budget_is_some_exactly_in_the_rolling_case(
        hcap in 1_u64..20_000, hfree_frac in 0_u64..=100,
        acap in 0_u64..20_000, afree_frac in 0_u64..=120,
        avail in any::<bool>(),
        hot_sizes in prop::collection::vec(1_u64..3_000, 0..8),
        arc_sizes in prop::collection::vec(1_u64..3_000, 0..8),
        hp in 0_u8..=90, ap in 0_u8..=90,
        ingested in any::<u64>(),
        fed in prop::option::of(any::<u64>()),
    ) {
        let hfree = hcap * hfree_frac / 100;
        let afree = acap * afree_frac / 100;
        let mut segs = Vec::new();
        for (i, b) in hot_sizes.iter().enumerate() { segs.push(seg(u64::try_from(i).unwrap(), Tier::Hot, *b, i64::try_from(i).unwrap())); }
        for (i, b) in arc_sizes.iter().enumerate() { segs.push(seg(100 + u64::try_from(i).unwrap(), Tier::Archive, *b, i64::try_from(i).unwrap())); }
        let state = if avail { ArchiveState::Available(vol(acap, afree)) } else { ArchiveState::Unavailable };
        let p = run(vol(hcap, hfree), state, &segs, policy(hp, ap), ingested, fed).unwrap();
        let floor = u128::from(hcap) * u128::from(hp) / 100;
        let unsat = u128::from(hfree) + u128::from(hot_video(&segs)) < floor;
        let cannot_help = matches!(p.archive, ArchiveStatus::Unavailable | ArchiveStatus::Unusable | ArchiveStatus::Full) || p.archive_below_floor;
        prop_assert_eq!(p.rolling_budget.is_some(), unsat && cannot_help, "{:?}", p);
        if let Some(b) = p.rolling_budget {
            prop_assert!(b <= fed.unwrap_or_else(|| hot_video(&segs).saturating_sub(ingested)));
        }
        if p.hot == HotState::RollingBuffer { prop_assert!(p.rolling_budget.is_some()); }
    }
}

#[test]
fn extreme_budget_and_ingest_values_never_panic() {
    let segs = [
        seg(1, Tier::Hot, u64::MAX / 4, 1),
        seg(2, Tier::Hot, u64::MAX / 4, 2),
    ];
    for fed in [None, Some(0), Some(1), Some(u64::MAX)] {
        for ing in [0, 1, u64::MAX] {
            let p = run(
                vol(u64::MAX, 0),
                ArchiveState::Unavailable,
                &segs,
                policy(90, 90),
                ing,
                fed,
            )
            .unwrap();
            assert!(p.rolling_budget.is_some());
            assert!(p.actions.iter().map(id_of).all(|id| id.as_u64() <= 2));
        }
    }
    // Sum overflows: typed error, not a panic.
    let big = [seg(1, Tier::Hot, u64::MAX, 1), seg(2, Tier::Hot, 1, 2)];
    assert!(matches!(
        run(
            vol(10, 0),
            ArchiveState::Unavailable,
            &big,
            policy(25, 25),
            0,
            Some(5)
        ),
        Err(PlanError::Overflow(_))
    ));
}

/// A budget of 0 fed back deletes every hot segment, and a budget above hot video deletes none.
#[test]
fn budget_extremes_delete_all_or_nothing() {
    let segs = [seg(1, Tier::Hot, 10, 1), seg(2, Tier::Hot, 10, 2)];
    let p = run(
        vol(1000, 0),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25),
        5,
        Some(0),
    )
    .unwrap();
    assert_eq!(p.actions.len(), 2);
    assert_eq!(p.hot, HotState::RollingBuffer);
    let p = run(
        vol(1000, 0),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25),
        5,
        Some(1000),
    )
    .unwrap();
    assert_eq!(p.actions.len(), 0);
    assert_eq!(p.hot, HotState::Unsatisfiable);
    assert_eq!(p.rolling_budget, Some(1000));
}

/// Archive full with partial moves: moved segments are never also deleted, and
/// remaining hot video after moves and deletes is at most the budget.
#[test]
fn full_archive_moves_count_toward_the_budget_and_are_not_deleted() {
    // Hot: cap 1000, floor 250, free 0, video 60 -> unreachable.
    // Archive: cap 100, floor 25, free 50, empty: room 50, a move fits only while bytes + 25 <= 50.
    let segs = [
        seg(1, Tier::Hot, 20, 1),
        seg(2, Tier::Hot, 20, 2),
        seg(3, Tier::Hot, 20, 3),
    ];
    let p = run(
        vol(1000, 0),
        ArchiveState::Available(vol(100, 50)),
        &segs,
        policy(25, 25),
        20,
        None,
    )
    .unwrap();
    assert_eq!(p.archive, ArchiveStatus::Full);
    assert_eq!(p.rolling_budget, Some(40));
    // One 20 B move fits (20 + 25 <= 50); remaining 40 <= budget, so no delete.
    assert_eq!(p.actions, vec![Action::MoveToArchive(SegmentId::new(1))]);
    assert_eq!(p.hot, HotState::Unsatisfiable);
}

/// Budget clears once the floor becomes reachable again and re-seeds on re-entry.
#[test]
fn budget_clears_when_floor_reachable_and_reseeds_on_reentry() {
    let segs = [seg(1, Tier::Hot, 10, 1), seg(2, Tier::Hot, 10, 2)];
    let p = run(
        vol(1000, 0),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25),
        10,
        None,
    )
    .unwrap();
    assert_eq!(p.rolling_budget, Some(10));
    // Foreign data removed: floor reachable -> cleared even with a fed budget.
    let p = run(
        vol(1000, 600),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25),
        10,
        Some(10),
    )
    .unwrap();
    assert_eq!(p.rolling_budget, None);
    assert_eq!(p.hot, HotState::Ok);
    // Archive available with room: cleared even though unreachable.
    let p = run(
        vol(1000, 0),
        ArchiveState::Available(vol(1000, 1000)),
        &segs,
        policy(25, 25),
        10,
        Some(10),
    )
    .unwrap();
    assert_eq!(p.rolling_budget, None);
    assert_eq!(p.hot, HotState::Unsatisfiable);
    assert!(
        p.actions
            .iter()
            .all(|a| matches!(a, Action::MoveToArchive(_)))
    );
    // Unusable archive behaves as unavailable.
    let p = run(
        vol(1000, 0),
        ArchiveState::Available(vol(100, 200)),
        &segs,
        policy(25, 25),
        10,
        None,
    )
    .unwrap();
    assert_eq!(p.archive, ArchiveStatus::Unusable);
    assert_eq!(p.rolling_budget, Some(10));
    assert_eq!(p.actions, vec![Action::Delete(SegmentId::new(1))]);
}

/// Ticket #44 override: "Never let the recorder run / to ENOSPC." Foreign data has filled the
/// hot volume to zero free bytes while the archive is unavailable; the recorder cannot write,
/// so nothing is ingested. Hot video is at the budget, so the planner deletes nothing and the
/// volume stays at ENOSPC on every later tick, although 60 B of deletable hot video exist.
#[test]
fn rolling_buffer_frees_space_when_hot_volume_is_at_enospc() {
    let segs = [
        seg(1, Tier::Hot, 20, 1),
        seg(2, Tier::Hot, 20, 2),
        seg(3, Tier::Hot, 20, 3),
    ];
    // Steady state: the budget was fed back as 60, then foreign data grew to fill the disk.
    for fed in [Some(60), None] {
        let p = run(
            vol(1000, 0),
            ArchiveState::Unavailable,
            &segs,
            policy_with_reserve(20),
            0,
            fed,
        )
        .unwrap();
        assert!(
            p.actions.iter().map(id_of).count() > 0,
            "fed {fed:?}: free 0 B, deletable hot video 60 B, plan deletes nothing: {p:?}"
        );
    }
}

/// Same defect over time: foreign data grows 5 B per tick while video is held flat at the
/// budget, so free space reaches 0 and stays there; the recorder then cannot write at all.
#[test]
fn rolling_buffer_does_not_hold_hot_volume_at_zero_free_while_video_is_deletable() {
    let mut segs: Vec<StoredSegment> = (0..10)
        .map(|i| seg(i, Tier::Hot, 10, i64::try_from(i).unwrap()))
        .collect();
    let mut next = 10_u64;
    let mut free = 50_u64; // cap 1000, floor 250: unreachable (50 + 100 < 250)
    let mut budget = None;
    for tick in 0..40 {
        free = free.saturating_sub(5); // foreign growth
        let ingested = if free >= 10 { 10 } else { 0 }; // ENOSPC: nothing can be written
        if ingested > 0 {
            segs.push(seg(next, Tier::Hot, 10, i64::try_from(next).unwrap()));
            next += 1;
        }
        free -= ingested;
        let p = run(
            vol(1000, free),
            ArchiveState::Unavailable,
            &segs,
            policy_with_reserve(20),
            ingested,
            budget,
        )
        .unwrap();
        budget = p.rolling_budget;
        let gone: Vec<SegmentId> = p.actions.iter().map(id_of).collect();
        let freed: u64 = segs
            .iter()
            .filter(|s| gone.contains(&s.id))
            .map(|s| s.bytes)
            .sum();
        segs.retain(|s| !gone.contains(&s.id));
        free += freed;
        assert!(
            free > 0 || hot_video(&segs) == 0,
            "tick {tick}: hot volume at 0 B free with {} B of hot video kept",
            hot_video(&segs)
        );
    }
}
