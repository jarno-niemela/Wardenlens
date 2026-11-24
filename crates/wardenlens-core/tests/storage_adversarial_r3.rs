//! Adversarial tests, round 3, for the tiered storage planner (ticket #44).
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; failures should panic"
)]

use std::collections::HashMap;

use proptest::prelude::*;
use wardenlens_core::storage::{
    Action, ArchiveState, ArchiveStatus, HotState, MinFreePercent, Plan, PlanError, PlanInput,
    Policy, SegmentId, StoredSegment, Tier, VolumeSpace, plan,
};
use wardenlens_core::time::{DurationMs, Timestamp};

const NOW: i64 = 1_000;

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

fn policy(hp: u8, ap: u8, age_ms: u64) -> Policy {
    Policy {
        hot_min_free: MinFreePercent::new(hp).unwrap(),
        archive_min_free: MinFreePercent::new(ap).unwrap(),
        hot_max_age: DurationMs::from_millis(age_ms),
        emergency_reserve_bytes: 0,
    }
}

fn run(
    hot: VolumeSpace,
    archive: ArchiveState,
    segments: &[StoredSegment],
    policy: Policy,
    ingested: u64,
) -> Result<Plan, PlanError> {
    run_with(hot, archive, segments, policy, ingested, None)
}

fn run_with(
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

fn pct(c: u64, p: u8) -> u128 {
    u128::from(c) * u128::from(p) / 100
}

type Split<'a> = (
    Vec<&'a StoredSegment>,
    Vec<&'a StoredSegment>,
    Vec<&'a StoredSegment>,
);

fn split<'a>(segs: &'a [StoredSegment], p: &Plan) -> Split<'a> {
    let by_id: HashMap<SegmentId, &StoredSegment> = segs.iter().map(|s| (s.id, s)).collect();
    let (mut ad, mut mv, mut hd) = (vec![], vec![], vec![]);
    for a in &p.actions {
        let s = by_id[&id_of(a)];
        match (a, s.tier) {
            (Action::Delete(_), Tier::Archive) => ad.push(s),
            (Action::MoveToArchive(_), Tier::Hot) => mv.push(s),
            (Action::Delete(_), Tier::Hot) => hd.push(s),
            _ => panic!("bad action {a:?}"),
        }
    }
    (ad, mv, hd)
}

fn sum(v: &[&StoredSegment]) -> u128 {
    v.iter().map(|s| u128::from(s.bytes)).sum()
}

// --- Targeted attacks on the round-3 change ---------------------------------

/// Floor reachable, target not, archive unavailable: stop as soon as the floor holds,
/// even when that takes several small deletes.
#[test]
fn floor_goal_stops_after_the_first_delete_that_restores_the_floor() {
    // cap 1000, floor 250, target 260; free 230, hot video 25 -> reachable 255.
    let segs = [
        seg(1, Tier::Hot, 10, 1),
        seg(2, Tier::Hot, 10, 2),
        seg(3, Tier::Hot, 5, 3),
    ];
    let p = run(
        vol(1_000, 230),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25, u64::MAX),
        0,
    )
    .unwrap();
    assert_eq!(
        p.actions,
        vec![
            Action::Delete(SegmentId::new(1)),
            Action::Delete(SegmentId::new(2))
        ]
    );
    assert_eq!(p.hot, HotState::Ok);
}

/// Reachable exactly equal to the target uses the target goal.
#[test]
fn reachable_exactly_at_target_deletes_to_the_target() {
    // floor 250, target 260; free 240 + 20 = 260.
    let segs = [seg(1, Tier::Hot, 10, 1), seg(2, Tier::Hot, 10, 2)];
    let p = run(
        vol(1_000, 240),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25, u64::MAX),
        0,
    )
    .unwrap();
    assert_eq!(p.actions.len(), 2);
    assert_eq!(p.hot, HotState::Ok);
}

/// Reachable exactly equal to the floor: Ok, and every hot segment goes.
#[test]
fn reachable_exactly_at_floor_is_ok_and_deletes_all() {
    let segs = [seg(1, Tier::Hot, 10, 1), seg(2, Tier::Hot, 10, 2)];
    let p = run(
        vol(1_000, 230),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25, u64::MAX),
        0,
    )
    .unwrap();
    assert_eq!(p.actions.len(), 2);
    assert_eq!(p.hot, HotState::Ok);
}

/// Partially full archive, floor reachable but target not: moves count towards the floor
/// goal and hot deletes stop at the floor.
#[test]
fn full_archive_partial_moves_then_floor_goal_deletes() {
    // Hot: cap 1000, floor 250, target 260, free 200, video 55 -> reachable 255.
    // Archive: cap 1000 floor 250, free 270, nothing to evict: room for 20 B of moves.
    let segs = [
        seg(1, Tier::Hot, 20, 1),
        seg(2, Tier::Hot, 25, 2),
        seg(3, Tier::Hot, 10, 3),
    ];
    let p = run(
        vol(1_000, 200),
        ArchiveState::Available(vol(1_000, 270)),
        &segs,
        policy(25, 25, u64::MAX),
        0,
    )
    .unwrap();
    assert_eq!(p.archive, ArchiveStatus::Full);
    assert_eq!(
        p.actions,
        vec![
            Action::MoveToArchive(SegmentId::new(1)),
            Action::Delete(SegmentId::new(2)),
            Action::Delete(SegmentId::new(3)),
        ]
    );
    // 200 + 20 + 25 = 245 < 250: the third delete is needed for the floor.
    assert_eq!(p.hot, HotState::Ok);
}

/// Unsatisfiable with an available, non-full archive never deletes hot video and moves
/// all of it (case-4 override).
#[test]
fn unsatisfiable_with_room_moves_everything_and_deletes_nothing() {
    let segs = [
        seg(1, Tier::Hot, 10, 1),
        seg(2, Tier::Hot, 10, 900),
        seg(3, Tier::Archive, 10, 0),
    ];
    let p = run(
        vol(1_000, 0),
        ArchiveState::Available(vol(1_000, 900)),
        &segs,
        policy(25, 25, u64::MAX),
        1_000,
    )
    .unwrap();
    assert_eq!(p.hot, HotState::Unsatisfiable);
    assert_eq!(p.archive, ArchiveStatus::Available);
    assert_eq!(
        p.actions,
        vec![
            Action::MoveToArchive(SegmentId::new(1)),
            Action::MoveToArchive(SegmentId::new(2))
        ]
    );
}

/// Zero-byte hot segments must not be deleted when no bytes are needed.
#[test]
fn zero_byte_segments_are_not_deleted_without_a_need() {
    let segs = [seg(1, Tier::Hot, 0, 1), seg(2, Tier::Hot, 0, 2)];
    for ingested in [0, 5] {
        let p = run(
            vol(1_000, 900),
            ArchiveState::Unavailable,
            &segs,
            policy(25, 25, u64::MAX),
            ingested,
        )
        .unwrap();
        assert!(p.actions.is_empty(), "{:?}", p.actions);
    }
}

/// Huge archive at 90 % with a huge move: the plan must not error out when the move simply
/// does not fit (overflow of `after + floor` means the archive cannot take it).
#[test]
fn huge_values_never_panic() {
    let segs = [
        seg(1, Tier::Hot, u64::MAX / 2, 1),
        seg(2, Tier::Archive, u64::MAX / 2, 0),
    ];
    for hp in [0, 1, 89, 90] {
        for ap in [0, 1, 89, 90] {
            for free in [0, u64::MAX / 3, u64::MAX] {
                for st in [
                    ArchiveState::Unavailable,
                    ArchiveState::Available(vol(u64::MAX, free)),
                    ArchiveState::Available(vol(u64::MAX, 0)),
                ] {
                    let _ = run(vol(u64::MAX, free), st, &segs, policy(hp, ap, 0), u64::MAX);
                }
            }
        }
    }
}

// --- Property: tight minimality with the round-3 goal ------------------------

fn volume(max: u64) -> impl Strategy<Value = VolumeSpace> {
    (1_u64..=max).prop_flat_map(|c| (Just(c), 0..=c).prop_map(|(c, f)| vol(c, f)))
}

fn segments(max_bytes: u64) -> impl Strategy<Value = Vec<StoredSegment>> {
    prop::collection::vec((any::<bool>(), 0_u64..max_bytes, 0_i64..1_000), 0..25).prop_map(|v| {
        v.into_iter()
            .enumerate()
            .map(|(i, (h, b, e))| {
                seg(
                    u64::try_from(i).unwrap(),
                    if h { Tier::Hot } else { Tier::Archive },
                    b,
                    e,
                )
            })
            .collect()
    })
}

fn check(
    hot: VolumeSpace,
    archive: Option<VolumeSpace>,
    segs: &[StoredSegment],
    hp: u8,
    ap: u8,
    age: u64,
    ingested: u64,
) -> Result<(), TestCaseError> {
    let st = archive.map_or(ArchiveState::Unavailable, ArchiveState::Available);
    let p = match run(hot, st, segs, policy(hp, ap, age), ingested) {
        Ok(p) => p,
        Err(PlanError::Overflow(_)) => return Ok(()),
        Err(e) => return Err(TestCaseError::fail(format!("unexpected error {e:?}"))),
    };
    let (_ad, mv, hd) = split(segs, &p);
    let hot_total: u128 = segs
        .iter()
        .filter(|s| s.tier == Tier::Hot)
        .map(|s| u128::from(s.bytes))
        .sum();
    let hfree = u128::from(hot.free_bytes);
    let hfloor = pct(hot.capacity_bytes, hp);
    let htarget = pct(hot.capacity_bytes, hp + 1);
    let reachable = hfree + hot_total;
    let moved = sum(&mv);
    let hdel = sum(&hd);
    let below = hfree < hfloor;

    // Hot deletions only below the floor and only when the archive cannot help.
    if !hd.is_empty() {
        prop_assert!(below, "hot deletes above the floor: {:?}", p);
        prop_assert!(
            matches!(
                p.archive,
                ArchiveStatus::Full | ArchiveStatus::Unavailable | ArchiveStatus::Unusable
            ),
            "hot deletes with archive {:?}",
            p.archive
        );
    }
    // Tight minimality: goal is the target shortfall if reachable, else the floor shortfall,
    // else the ingest.
    if let Some(last) = hd.last() {
        let goal = if reachable >= htarget {
            htarget - hfree
        } else if reachable >= hfloor {
            hfloor - hfree
        } else {
            u128::from(ingested)
        };
        let before_last = moved + hdel - u128::from(last.bytes);
        prop_assert!(
            before_last < goal,
            "over-deleted hot: before_last {} goal {} plan {:?}",
            before_last,
            goal,
            p
        );
        // And the goal is met (or all hot video is gone).
        prop_assert!(moved + hdel >= goal.min(hot_total));
    }
    // Non-aged moves stop once the target need is met.
    let now = Timestamp::from_unix_millis(NOW);
    let need = if below { htarget - hfree } else { 0 };
    let mut acc = 0_u128;
    for m in &mv {
        let aged = now.saturating_duration_since(m.ended_at) > DurationMs::from_millis(age);
        if !aged {
            prop_assert!(acc < need, "move beyond need: {:?}", p);
        }
        acc += u128::from(m.bytes);
    }
    // Status coherence.
    let unsat = reachable < hfloor;
    match p.hot {
        HotState::Ok => prop_assert!(!unsat),
        HotState::Unsatisfiable => prop_assert!(unsat && hd.is_empty()),
        HotState::RollingBuffer => prop_assert!(unsat && !hd.is_empty()),
        _ => {}
    }
    if p.archive_below_floor {
        let a = archive.unwrap();
        let atotal: u128 = segs
            .iter()
            .filter(|s| s.tier == Tier::Archive)
            .map(|s| u128::from(s.bytes))
            .sum();
        prop_assert!(u128::from(a.free_bytes) + atotal < pct(a.capacity_bytes, ap));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]
    #[test]
    fn hot_deletes_are_tightly_minimal_small(
        hot in volume(5_000),
        archive in prop::option::of(volume(5_000)),
        segs in segments(300),
        hp in 0_u8..=90,
        ap in 0_u8..=90,
        age in 0_u64..1_200,
        ingested in 0_u64..2_000,
    ) {
        check(hot, archive, &segs, hp, ap, age, ingested)?;
    }

    #[test]
    fn hot_deletes_are_tightly_minimal_huge(
        hot in volume(u64::MAX),
        archive in prop::option::of(volume(u64::MAX)),
        segs in segments(u64::MAX / 4),
        hp in 0_u8..=90,
        ap in 0_u8..=90,
        age in 0_u64..1_200,
        ingested in any::<u64>(),
    ) {
        check(hot, archive, &segs, hp, ap, age, ingested)?;
    }
}

/// The ADR 0005 section 10 camera mix (segment sizes in MB, 5 per minute, two 30 s ticks per
/// minute), archive unavailable and the hot floor unreachable. `ingested_bytes` is exactly the
/// bytes of the segments that arrived since the previous plan. Required test (b) says hot
/// video stays flat; deleting whole oldest segments "until >= ingest" overshoots every tick
/// and the surplus is never credited back, so hot video drains.
#[test]
fn rolling_buffer_with_mixed_segment_sizes_does_not_drain_hot_video() {
    const MB: u64 = 1_000_000;
    let sizes = [22 * MB, 22 * MB, 32 * MB, MB, 65 * MB];
    let cap = 1_000_000 * MB; // 1 TB, floor 25 % = 250 GB
    let mut segs: Vec<StoredSegment> = Vec::new();
    let mut next = 0_u64;
    // 10 minutes of history: 50 segments, 1,420 MB.
    for _ in 0..10 {
        for b in sizes {
            segs.push(seg(next, Tier::Hot, b, i64::try_from(next).unwrap()));
            next += 1;
        }
    }
    let initial: u64 = segs.iter().map(|s| s.bytes).sum();
    let foreign_free = 100_000 * MB; // free + video is far below the floor
    let mut cursor = 0_usize;
    let mut budget = None;
    for tick in 0..100 {
        let n = if tick % 2 == 0 { 3 } else { 2 };
        let mut ingested = 0;
        for _ in 0..n {
            let b = sizes[cursor % sizes.len()];
            cursor += 1;
            segs.push(seg(next, Tier::Hot, b, i64::try_from(next).unwrap()));
            next += 1;
            ingested += b;
        }
        let video: u64 = segs.iter().map(|s| s.bytes).sum();
        let free = (foreign_free + initial).saturating_sub(video);
        let p = run_with(
            vol(cap, free),
            ArchiveState::Unavailable,
            &segs,
            policy(25, 25, u64::MAX),
            ingested,
            budget,
        )
        .unwrap();
        budget = p.rolling_budget;
        assert_eq!(p.hot, HotState::RollingBuffer, "tick {tick}");
        let gone: Vec<SegmentId> = p.actions.iter().map(id_of).collect();
        segs.retain(|s| !gone.contains(&s.id));
    }
    let after: u64 = segs.iter().map(|s| s.bytes).sum();
    // Allow one largest segment of slack.
    assert!(
        after + 65 * MB >= initial,
        "hot video drained from {} MB to {} MB over 100 ticks",
        initial / MB,
        after / MB
    );
}

/// Rolling buffer, archive unavailable, floor unreachable: four of five cameras go quiet, so
/// each tick ingests one small 1 MB segment while the oldest hot segments are 22 MB. Each
/// tick deletes a whole 22 MB segment for 1 MB of ingest and never credits the surplus, so
/// hot video bytes drain instead of staying flat (ticket #44 override, required test (b)).
#[test]
fn rolling_buffer_does_not_drain_hot_video_when_new_segments_are_smaller() {
    const MB: u64 = 1_000_000;
    let cap = 1_000_000 * MB;
    let mut segs: Vec<StoredSegment> = (0..100)
        .map(|i| seg(i, Tier::Hot, 22 * MB, i64::try_from(i).unwrap()))
        .collect();
    let initial: u64 = segs.iter().map(|s| s.bytes).sum();
    let mut budget = None;
    for (next, tick) in (100_u64..).zip(0..100) {
        segs.push(seg(next, Tier::Hot, MB, i64::try_from(next).unwrap()));
        let video: u64 = segs.iter().map(|s| s.bytes).sum();
        let free = (100_000 * MB + initial).saturating_sub(video);
        let p = run_with(
            vol(cap, free),
            ArchiveState::Unavailable,
            &segs,
            policy(25, 25, u64::MAX),
            MB,
            budget,
        )
        .unwrap();
        budget = p.rolling_budget;
        // Slack below the budget means a tick may delete nothing; the buffer still rolls.
        assert!(
            matches!(p.hot, HotState::RollingBuffer | HotState::Unsatisfiable),
            "tick {tick}"
        );
        assert!(p.rolling_budget.is_some(), "tick {tick}");
        let gone: Vec<SegmentId> = p.actions.iter().map(id_of).collect();
        segs.retain(|s| !gone.contains(&s.id));
    }
    let after: u64 = segs.iter().map(|s| s.bytes).sum();
    assert!(
        after + 22 * MB >= initial,
        "hot video drained from {} MB to {} MB over 100 ticks",
        initial / MB,
        after / MB
    );
}

/// Uniform 10 B segments, 1.5 segments recorded per tick (60 s segments, 30 s ticks as in
/// ADR 0005), `ingested_bytes` = bytes written in the tick (15). Each tick deletes two
/// segments (20 B) for 15 B of ingest: hot video drains by 5 B per tick, forever.
#[test]
fn rolling_buffer_does_not_drain_when_ingest_is_not_segment_aligned() {
    let cap = 100_000;
    let mut segs: Vec<StoredSegment> = (0..100)
        .map(|i| seg(i, Tier::Hot, 10, i64::try_from(i).unwrap()))
        .collect();
    let initial: u64 = segs.iter().map(|s| s.bytes).sum();
    let mut next = 100_u64;
    let mut budget = None;
    for tick in 0..100_u64 {
        let n = if tick % 2 == 0 { 1 } else { 2 };
        for _ in 0..n {
            segs.push(seg(next, Tier::Hot, 10, i64::try_from(next).unwrap()));
            next += 1;
        }
        let p = run_with(
            vol(cap, 0),
            ArchiveState::Unavailable,
            &segs,
            policy(25, 25, u64::MAX),
            15,
            budget,
        )
        .unwrap();
        budget = p.rolling_budget;
        assert_eq!(p.hot, HotState::RollingBuffer, "tick {tick}");
        let gone: Vec<SegmentId> = p.actions.iter().map(id_of).collect();
        segs.retain(|s| !gone.contains(&s.id));
    }
    let after: u64 = segs.iter().map(|s| s.bytes).sum();
    assert!(
        after + 20 >= initial,
        "hot video drained from {initial} B to {after} B over 100 ticks"
    );
}
