//! Adversarial tests, round 2, for the tiered storage planner (ticket #44).
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
    }
}

fn run(
    hot: VolumeSpace,
    archive: ArchiveState,
    segments: &[StoredSegment],
    policy: Policy,
    now: i64,
    ingested: u64,
) -> Result<Plan, PlanError> {
    plan(&PlanInput {
        hot,
        archive,
        segments,
        now: Timestamp::from_unix_millis(now),
        policy,
        ingested_bytes: ingested,
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

/// Splits a plan into (archive deletes, moves, hot deletes) as segment lists.
fn split<'a>(
    segs: &'a [StoredSegment],
    p: &Plan,
) -> (
    Vec<&'a StoredSegment>,
    Vec<&'a StoredSegment>,
    Vec<&'a StoredSegment>,
) {
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

// --- Targeted unit attacks ---------------------------------------------------

/// Aged segments alone (no hot pressure) that the archive cannot take must
/// never cause hot deletions ("`hot_max_age` never deletes anything").
#[test]
fn blocked_aged_move_without_pressure_deletes_nothing_from_hot() {
    let segs = [seg(1, Tier::Hot, 900, 0)];
    let p = run(
        vol(10_000, 9_000),
        ArchiveState::Available(vol(1_000, 800)),
        &segs,
        policy(25, 25, 10),
        1_000,
        500,
    )
    .unwrap();
    assert!(p.actions.is_empty(), "{:?}", p.actions);
    assert_eq!(p.archive, ArchiveStatus::Full);
    assert_eq!(p.hot, HotState::Ok);
}

/// Archive below its floor (reachable) with no hot work: evicts oldest to the
/// target, no further.
#[test]
fn archive_eviction_stops_exactly_at_target() {
    // cap 1000, floor 250, target 260, free 200. Need 60.
    let segs = [
        seg(1, Tier::Archive, 30, 1),
        seg(2, Tier::Archive, 30, 2),
        seg(3, Tier::Archive, 30, 3),
        seg(4, Tier::Archive, 30, 4),
    ];
    let p = run(
        vol(1_000, 900),
        ArchiveState::Available(vol(1_000, 200)),
        &segs,
        policy(25, 25, u64::MAX),
        1_000,
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
    assert_eq!(p.archive, ArchiveStatus::Available);
}

/// Rolling buffer: deletes exactly enough to cover the ingest, oldest first.
#[test]
fn rolling_buffer_deletes_just_enough_for_the_ingest() {
    // Hot cap 1000, floor 250, free 0, 100 B video -> unsatisfiable.
    let segs = [
        seg(1, Tier::Hot, 40, 1),
        seg(2, Tier::Hot, 40, 2),
        seg(3, Tier::Hot, 20, 3),
    ];
    let p = run(
        vol(1_000, 0),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25, u64::MAX),
        1_000,
        41,
    )
    .unwrap();
    assert_eq!(p.hot, HotState::RollingBuffer);
    assert_eq!(
        p.actions,
        vec![
            Action::Delete(SegmentId::new(1)),
            Action::Delete(SegmentId::new(2))
        ]
    );
}

/// Zero ingest under the rolling buffer deletes nothing (no video for nothing).
#[test]
fn rolling_buffer_with_zero_ingest_deletes_nothing() {
    let segs = [seg(1, Tier::Hot, 40, 1)];
    let p = run(
        vol(1_000, 0),
        ArchiveState::Unavailable,
        &segs,
        policy(25, 25, u64::MAX),
        1_000,
        0,
    )
    .unwrap();
    assert_eq!(p.actions, vec![]);
    assert_eq!(p.hot, HotState::Unsatisfiable);
}

/// Archive is `BelowFloor` (foreign data) and hot is pressed: the move is
/// blocked, Full wins, the archive is untouched and hot is deleted to target.
#[test]
fn below_floor_archive_with_hot_pressure_reports_full_and_spares_archive() {
    let segs = [
        seg(1, Tier::Archive, 5, 0),
        seg(2, Tier::Hot, 100, 1),
        seg(3, Tier::Hot, 100, 2),
        seg(4, Tier::Hot, 100, 3),
    ];
    // hot cap 1000 floor 250 target 260 free 200 -> need 60.
    let p = run(
        vol(1_000, 200),
        ArchiveState::Available(vol(1_000, 100)),
        &segs,
        policy(25, 25, u64::MAX),
        1_000,
        0,
    )
    .unwrap();
    assert_eq!(p.archive, ArchiveStatus::Full);
    assert_eq!(p.actions, vec![Action::Delete(SegmentId::new(2))]);
    assert_eq!(p.hot, HotState::Ok);
}

/// No hot work, archive `BelowFloor`: status `BelowFloor`, nothing deleted.
#[test]
fn below_floor_without_hot_work_reports_below_floor() {
    let segs = [seg(1, Tier::Archive, 5, 0), seg(2, Tier::Hot, 100, 1)];
    let p = run(
        vol(1_000, 900),
        ArchiveState::Available(vol(1_000, 100)),
        &segs,
        policy(25, 25, u64::MAX),
        1_000,
        0,
    )
    .unwrap();
    assert_eq!(p.actions, vec![]);
    assert_eq!(p.archive, ArchiveStatus::BelowFloor);
}

/// A huge archive (room = `u64::MAX`) and a hot segment whose move plus the
/// archive floor overflows u64: the planner must not treat the saturated sum
/// as fitting. Either a typed error or a non-move plan, never a panic.
#[test]
fn saturated_room_check_never_panics_or_plans_an_impossible_move() {
    let big = u64::MAX / 10 * 8;
    let segs = [seg(1, Tier::Hot, big, 0), seg(2, Tier::Archive, 10, 0)];
    let r = run(
        vol(u64::MAX, 0),
        ArchiveState::Available(vol(u64::MAX, u64::MAX - 10)),
        &segs,
        policy(25, 25, u64::MAX),
        1_000,
        0,
    );
    if let Ok(p) = r {
        assert!(
            !p.actions
                .contains(&Action::MoveToArchive(SegmentId::new(1))),
            "{p:?}"
        );
    }
}

/// Floor 0 and 90 on both volumes at capacity 1 byte: no panic, sensible.
#[test]
fn tiny_volumes_at_extreme_percentages_do_not_panic() {
    for hp in [0_u8, 1, 50, 89, 90] {
        for ap in [0_u8, 1, 50, 89, 90] {
            for (hc, hf) in [(1_u64, 0_u64), (1, 1), (3, 0), (100, 0)] {
                let segs = [seg(1, Tier::Hot, 1, 0), seg(2, Tier::Archive, 1, 0)];
                let p = run(
                    vol(hc, hf),
                    ArchiveState::Available(vol(hc, hf)),
                    &segs,
                    policy(hp, ap, 0),
                    i64::MAX,
                    u64::MAX,
                )
                .unwrap();
                assert!(p.actions.len() <= 2);
            }
        }
    }
}

// --- Property: minimality and status coherence -------------------------------

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

#[expect(
    clippy::too_many_lines,
    reason = "test helper checking every invariant in one place"
)]
fn check(
    hot: VolumeSpace,
    archive: Option<VolumeSpace>,
    segs: &[StoredSegment],
    hp: u8,
    ap: u8,
    age: u64,
    ingested: u64,
) -> Result<(), TestCaseError> {
    let pol = policy(hp, ap, age);
    let st = archive.map_or(ArchiveState::Unavailable, ArchiveState::Available);
    let p = match run(hot, st, segs, pol, 1_000, ingested) {
        Ok(p) => p,
        Err(PlanError::Overflow(_)) => return Ok(()),
        Err(e) => return Err(TestCaseError::fail(format!("unexpected error {e:?}"))),
    };
    let (ad, mv, hd) = split(segs, &p);
    let mut hot_sorted: Vec<_> = segs.iter().filter(|s| s.tier == Tier::Hot).collect();
    hot_sorted.sort_by_key(|s| (s.ended_at, s.id));
    let hot_total = sum(&hot_sorted);
    let hfree = u128::from(hot.free_bytes);
    let hfloor = pct(hot.capacity_bytes, hp);
    let htarget = pct(hot.capacity_bytes, hp + 1);
    let moved = sum(&mv);
    let hdel = sum(&hd);
    let unsat = hfree + hot_total < hfloor;

    // Hot deletion minimality: without the last hot delete, the goal was unmet.
    if let Some(last) = hd.last() {
        let before_last = moved + hdel - u128::from(last.bytes);
        let goal = if unsat {
            u128::from(ingested)
        } else {
            htarget.saturating_sub(hfree)
        };
        prop_assert!(
            before_last < goal,
            "over-deleted hot: before_last {} goal {} plan {:?}",
            before_last,
            goal,
            p
        );
    }
    // RollingBuffer: hot video does not grow (deleted+moved covers ingest or all).
    if p.hot == HotState::RollingBuffer {
        prop_assert!(moved + hdel >= u128::from(ingested).min(hot_total));
    }
    // Aged segments that were not moved imply a non-Available archive status.
    let now = Timestamp::from_unix_millis(1_000);
    let aged_unmoved = hot_sorted.iter().any(|s| {
        now.saturating_duration_since(s.ended_at) > DurationMs::from_millis(age)
            && !mv.iter().any(|m| m.id == s.id)
    });
    if archive.is_some_and(|a| a.free_bytes <= a.capacity_bytes) && aged_unmoved {
        prop_assert!(
            p.archive == ArchiveStatus::Full,
            "aged segment unmoved but status {:?}",
            p.archive
        );
    }
    if let Some(a) = archive.filter(|a| a.free_bytes <= a.capacity_bytes) {
        let afree = u128::from(a.free_bytes);
        let afloor = pct(a.capacity_bytes, ap);
        let atarget = pct(a.capacity_bytes, ap + 1);
        let atotal: u128 = segs
            .iter()
            .filter(|s| s.tier == Tier::Archive)
            .map(|s| u128::from(s.bytes))
            .sum();
        let room = afree + atotal;
        let adel = sum(&ad);
        // Archive deletion minimality.
        if let Some(last) = ad.last() {
            let goal = if room >= moved + atarget {
                moved + atarget
            } else {
                moved + afloor
            };
            prop_assert!(
                afree + adel - u128::from(last.bytes) < goal,
                "over-evicted archive: {:?}",
                p
            );
        }
        // Post-plan archive: at or above floor whenever anything touched it,
        // and at target when the target was reachable and eviction happened.
        let after = afree + adel - moved;
        if !ad.is_empty() || !mv.is_empty() {
            prop_assert!(after >= afloor);
        }
        if !ad.is_empty() && room >= moved + atarget {
            prop_assert!(after >= atarget);
        }
        // Status coherence.
        if p.archive == ArchiveStatus::BelowFloor {
            prop_assert!(room < afloor && ad.is_empty());
        }
        if room < afloor {
            prop_assert!(ad.is_empty() && mv.is_empty());
            prop_assert!(matches!(
                p.archive,
                ArchiveStatus::BelowFloor | ArchiveStatus::Full
            ));
        }
        if p.archive == ArchiveStatus::Available && !unsat && hfree < hfloor {
            prop_assert!(hfree + moved >= htarget.min(hfree + hot_total));
            prop_assert!(hd.is_empty());
        }
    }
    // Hot floor restored whenever reachable.
    if unsat {
        prop_assert!(p.hot != HotState::Ok);
    } else {
        prop_assert!(hfree + moved + hdel >= hfloor);
        prop_assert_eq!(p.hot, HotState::Ok);
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]
    #[test]
    fn plans_are_minimal_and_statuses_coherent_small(
        hot in volume(50_000),
        archive in prop::option::of(volume(50_000)),
        segs in segments(6_000),
        hp in 0_u8..=90,
        ap in 0_u8..=90,
        age in 0_u64..1_200,
        ingested in 0_u64..20_000,
    ) {
        check(hot, archive, &segs, hp, ap, age, ingested)?;
    }

    #[test]
    fn plans_are_minimal_and_statuses_coherent_huge(
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
