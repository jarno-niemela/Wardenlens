//! Unit tests: ADR 0005 worked example, the case 4 override and the edges.

use crate::time::{DurationMs, Timestamp};

use super::{
    Action, ArchiveState, ArchiveStatus, HotState, MinFreePercent, OverflowQuantity, Plan,
    PlanError, PlanInput, Policy, SegmentId, StoredSegment, Tier, VolumeSpace, plan,
};

/// Applies a plan to a simulated state: `(hot free, archive free, segments)`.
pub(super) fn simulate(
    hot_free: u64,
    archive_free: Option<u64>,
    segments: &[StoredSegment],
    plan: &Plan,
) -> (u64, Option<u64>, Vec<StoredSegment>) {
    let mut hot = hot_free;
    let mut arch = archive_free;
    let mut left = segments.to_vec();
    for action in &plan.actions {
        let (id, moving) = match action {
            Action::MoveToArchive(id) => (*id, true),
            Action::Delete(id) => (*id, false),
        };
        let pos = left.iter().position(|s| s.id == id).unwrap();
        let mut seg = left.remove(pos);
        match (seg.tier, moving) {
            (Tier::Hot, true) => {
                hot += seg.bytes;
                arch = Some(arch.unwrap() - seg.bytes);
                seg.tier = Tier::Archive;
                left.push(seg);
            }
            (Tier::Hot, false) => hot += seg.bytes,
            (Tier::Archive, false) => arch = Some(arch.unwrap() + seg.bytes),
            (Tier::Archive, true) => panic!("moved an archive segment"),
        }
    }
    (hot, arch, left)
}

fn seg(id: u64, tier: Tier, bytes: u64, ended_ms: u64) -> StoredSegment {
    StoredSegment {
        id: SegmentId::new(id),
        tier,
        bytes,
        ended_at: Timestamp::from_unix_millis(i64::try_from(ended_ms).unwrap()),
    }
}

fn input(
    hot: VolumeSpace,
    archive: ArchiveState,
    segments: &[StoredSegment],
    ingested_bytes: u64,
) -> PlanInput<'_> {
    PlanInput {
        hot,
        archive,
        segments,
        now: Timestamp::from_unix_millis(1_000_000),
        policy: Policy {
            hot_max_age: DurationMs::from_millis(u64::MAX),
            emergency_reserve_bytes: 0,
            ..Policy::default()
        },
        ingested_bytes,
        rolling_budget: None,
        rolling_ceiling: None,
    }
}

fn ids(plan: &Plan) -> Vec<Action> {
    plan.actions.clone()
}

#[test]
fn min_free_percent_accepts_zero_to_ninety_and_rejects_more() {
    assert_eq!(MinFreePercent::new(0).unwrap().get(), 0);
    assert_eq!(MinFreePercent::new(90).unwrap().get(), 90);
    assert!(MinFreePercent::new(91).is_err());
    assert!(MinFreePercent::new(255).is_err());
    assert_eq!(MinFreePercent::default().get(), 25);
}

/// ADR 0005 section 10, "A floor-driven tick", to the byte.
#[test]
fn reproduces_the_worked_example_of_adr_0005_section_10() {
    const SEG: u64 = 28_480_000;
    let hot = VolumeSpace {
        capacity_bytes: 932_269_510_656,
        free_bytes: 232_907_377_664,
    };
    let archive = VolumeSpace {
        capacity_bytes: 1_998_964_121_600,
        free_bytes: 499_796_030_400,
    };
    let mut segments = Vec::new();
    // 333 hot segments totalling exactly the 9,482,695,106 B to move.
    for i in 0..333_u64 {
        let bytes = if i == 332 { 27_335_106 } else { SEG };
        segments.push(seg(10_000 + i, Tier::Hot, bytes, 1_000 + i));
    }
    // 1,033 archive segments totalling exactly the 29,417,336,322 B to evict (plus one spare).
    for i in 0..1_033_u64 {
        let bytes = if i == 1_032 { 25_976_322 } else { SEG };
        segments.push(seg(i, Tier::Archive, bytes, i));
    }
    segments.push(seg(5_000, Tier::Archive, SEG, 5_000));
    let p = plan(&input(hot, ArchiveState::Available(archive), &segments, 0)).unwrap();
    let deletes = p
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Delete(_)))
        .count();
    let moves = p
        .actions
        .iter()
        .filter(|a| matches!(a, Action::MoveToArchive(_)))
        .count();
    assert_eq!((deletes, moves), (1_033, 333));
    assert!(
        p.actions[..1_033]
            .iter()
            .all(|a| matches!(a, Action::Delete(_)))
    );
    assert_eq!(p.actions[0], Action::Delete(SegmentId::new(0)));
    assert_eq!(
        p.actions[1_033],
        Action::MoveToArchive(SegmentId::new(10_000))
    );
    assert_eq!(p.archive, ArchiveStatus::Available);
    assert_eq!(p.hot, HotState::Ok);
    let (hot_free, arch_free, _) =
        simulate(hot.free_bytes, Some(archive.free_bytes), &segments, &p);
    assert_eq!(hot_free, 242_390_072_770);
    assert_eq!(arch_free, Some(519_730_671_616));
}

#[test]
fn plans_nothing_when_both_volumes_are_above_their_floor() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 300,
    };
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 300,
    };
    let segments = [seg(1, Tier::Hot, 10, 1), seg(2, Tier::Archive, 10, 1)];
    let p = plan(&input(hot, ArchiveState::Available(arch), &segments, 0)).unwrap();
    assert_eq!(ids(&p), Vec::<Action>::new());
}

#[test]
fn moves_the_oldest_hot_segments_first_regardless_of_input_order() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 240,
    };
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    // target 260: need 20 bytes, so the two oldest 10-byte segments.
    let segments = [
        seg(3, Tier::Hot, 10, 30),
        seg(1, Tier::Hot, 10, 10),
        seg(2, Tier::Hot, 10, 20),
    ];
    let p = plan(&input(hot, ArchiveState::Available(arch), &segments, 0)).unwrap();
    assert_eq!(
        ids(&p),
        vec![
            Action::MoveToArchive(SegmentId::new(1)),
            Action::MoveToArchive(SegmentId::new(2))
        ]
    );
}

#[test]
fn ties_on_ended_at_are_broken_by_id() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 249,
    };
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let segments = [seg(9, Tier::Hot, 20, 5), seg(4, Tier::Hot, 20, 5)];
    let p = plan(&input(hot, ArchiveState::Available(arch), &segments, 0)).unwrap();
    assert_eq!(ids(&p), vec![Action::MoveToArchive(SegmentId::new(4))]);
}

#[test]
fn moves_segments_older_than_hot_max_age_without_pressure() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let mut i = input(hot, ArchiveState::Available(arch), &[], 0);
    let segments = [
        seg(1, Tier::Hot, 10, 100),
        seg(2, Tier::Hot, 10, 50_000),
        seg(3, Tier::Hot, 10, 900_000),
    ];
    i.segments = &segments;
    i.now = Timestamp::from_unix_millis(100_000);
    i.policy.hot_max_age = DurationMs::from_millis(60_000);
    // cutoff 40,000: only segment 1 ended before it.
    let p = plan(&i).unwrap();
    assert_eq!(ids(&p), vec![Action::MoveToArchive(SegmentId::new(1))]);
}

#[test]
fn max_age_larger_than_now_moves_nothing() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let segments = [seg(1, Tier::Hot, 10, 0)];
    let mut i = input(hot, ArchiveState::Available(arch), &segments, 0);
    i.now = Timestamp::from_unix_millis(5);
    i.policy.hot_max_age = DurationMs::from_secs(3600);
    assert_eq!(ids(&plan(&i).unwrap()), Vec::<Action>::new());
}

#[test]
fn evicts_archive_before_a_move_that_would_breach_its_floor() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 240,
    };
    // archive floor 250, target 260; moving 20 leaves 250 + 15... start 255.
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 255,
    };
    let segments = [
        seg(1, Tier::Hot, 20, 10),
        seg(7, Tier::Archive, 10, 2),
        seg(6, Tier::Archive, 10, 1),
        seg(8, Tier::Archive, 10, 3),
    ];
    let p = plan(&input(hot, ArchiveState::Available(arch), &segments, 0)).unwrap();
    // goal = 20 + 260 = 280: free 255 -> delete 6, 7, 8 would be 285; 6,7 gives 275 < 280.
    assert_eq!(
        ids(&p),
        vec![
            Action::Delete(SegmentId::new(6)),
            Action::Delete(SegmentId::new(7)),
            Action::Delete(SegmentId::new(8)),
            Action::MoveToArchive(SegmentId::new(1)),
        ]
    );
    let (_, arch_free, _) = simulate(240, Some(255), &segments, &p);
    assert!(arch_free.unwrap() >= 250);
}

#[test]
fn evicts_archive_alone_when_it_is_below_its_floor() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 240,
    };
    let segments = [seg(1, Tier::Archive, 15, 1), seg(2, Tier::Archive, 15, 2)];
    let p = plan(&input(hot, ArchiveState::Available(arch), &segments, 0)).unwrap();
    assert_eq!(
        ids(&p),
        vec![
            Action::Delete(SegmentId::new(1)),
            Action::Delete(SegmentId::new(2))
        ]
    );
}

#[test]
fn archive_unavailable_deletes_oldest_hot_to_the_target_and_leaves_archive_rows() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 240,
    };
    let segments = [
        seg(1, Tier::Hot, 15, 1),
        seg(2, Tier::Hot, 15, 2),
        seg(3, Tier::Hot, 15, 3),
        seg(9, Tier::Archive, 15, 0),
    ];
    let p = plan(&input(hot, ArchiveState::Unavailable, &segments, 0)).unwrap();
    assert_eq!(
        ids(&p),
        vec![
            Action::Delete(SegmentId::new(1)),
            Action::Delete(SegmentId::new(2))
        ]
    );
    assert_eq!(p.archive, ArchiveStatus::Unavailable);
    assert_eq!(p.hot, HotState::Ok);
}

#[test]
fn archive_unavailable_and_hot_above_floor_plans_nothing_even_for_aged_segments() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let segments = [seg(1, Tier::Hot, 15, 0)];
    let mut i = input(hot, ArchiveState::Unavailable, &segments, 0);
    i.now = Timestamp::from_unix_millis(10_000_000_000);
    i.policy.hot_max_age = DurationMs::from_secs(1);
    assert_eq!(ids(&plan(&i).unwrap()), Vec::<Action>::new());
}

#[test]
fn unusable_archive_is_reported_as_unusable_and_treated_as_unavailable() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 240,
    };
    let arch = VolumeSpace {
        capacity_bytes: 0,
        free_bytes: 0,
    };
    let segments = [seg(1, Tier::Hot, 30, 1)];
    let p = plan(&input(hot, ArchiveState::Available(arch), &segments, 0)).unwrap();
    assert_eq!(p.archive, ArchiveStatus::Unusable);
    assert_eq!(ids(&p), vec![Action::Delete(SegmentId::new(1))]);
}

#[test]
fn archive_that_cannot_absorb_a_segment_is_full_and_hot_is_deleted_instead() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 240,
    };
    // The archive can offer at most 100 above its 250 floor... only 300 free + 0 segments.
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 260,
    };
    let segments = [seg(1, Tier::Hot, 30, 1)];
    // room 260 < 30 + 250: cannot move.
    let p = plan(&input(hot, ArchiveState::Available(arch), &segments, 0)).unwrap();
    assert_eq!(ids(&p), vec![Action::Delete(SegmentId::new(1))]);
    assert_eq!(p.archive, ArchiveStatus::Full);
}

/// Case 4 (a): other data fills hot past the reachable floor, archive available.
#[test]
fn unreachable_floor_with_archive_available_still_plans_every_move() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 100,
    };
    let arch = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    // Even all 3 x 20 bytes of video leave 160 < target 260.
    let segments = [
        seg(1, Tier::Hot, 20, 1),
        seg(2, Tier::Hot, 20, 2),
        seg(3, Tier::Hot, 20, 3),
    ];
    let p = plan(&input(hot, ArchiveState::Available(arch), &segments, 20)).unwrap();
    assert_eq!(p.hot, HotState::Unsatisfiable);
    assert_eq!(p.archive, ArchiveStatus::Available);
    assert_eq!(
        ids(&p),
        vec![
            Action::MoveToArchive(SegmentId::new(1)),
            Action::MoveToArchive(SegmentId::new(2)),
            Action::MoveToArchive(SegmentId::new(3)),
        ]
    );
}

/// Case 4 (b): same, archive unavailable; hot video stays flat over N ticks.
#[test]
fn unreachable_floor_without_archive_keeps_hot_video_flat_and_alerts() {
    const SEG: u64 = 20;
    let capacity = 1000;
    let mut segments: Vec<StoredSegment> = (0..3).map(|i| seg(i, Tier::Hot, SEG, i)).collect();
    let mut hot_free = 100_u64;
    let mut budget = None;
    let initial_video: u64 = segments.iter().map(|s| s.bytes).sum();
    for tick in 0..50_u64 {
        // New video arrives and consumes space.
        segments.push(seg(100 + tick, Tier::Hot, SEG, 100 + tick));
        hot_free -= SEG;
        let space = VolumeSpace {
            capacity_bytes: capacity,
            free_bytes: hot_free,
        };
        let mut pin = input(space, ArchiveState::Unavailable, &segments, SEG);
        pin.rolling_budget = budget;
        let p = plan(&pin).unwrap();
        assert_eq!(p.hot, HotState::RollingBuffer, "tick {tick}");
        assert_eq!(p.rolling_budget, Some(initial_video), "tick {tick}");
        budget = p.rolling_budget;
        let (free, _, left) = simulate(hot_free, None, &segments, &p);
        hot_free = free;
        segments = left;
        let video: u64 = segments.iter().map(|s| s.bytes).sum();
        assert_eq!(video, initial_video, "tick {tick}");
        assert_eq!(hot_free, 100, "tick {tick}");
    }
}

/// Floor 250 unreachable (free 200, hot video 30) but the archive is usable and has room only
/// for the floor-reaching moves: moves still aim for the target and hot stays `Ok`.
#[test]
fn usable_archive_with_only_the_floor_reachable_moves_to_the_target() {
    // Hot: floor 250, target 260, free 200, video 55: reachable 255 (floor yes, target no).
    // Archive: ample room.
    let segments = [
        seg(1, Tier::Hot, 20, 1),
        seg(2, Tier::Hot, 25, 2),
        seg(3, Tier::Hot, 10, 3),
    ];
    let p = plan(&input(
        vol(1000, 200),
        ArchiveState::Available(vol(1000, 900)),
        &segments,
        0,
    ))
    .unwrap();
    // Target shortfall is 60 B: all three (55 B) move, since the target is unreachable.
    assert_eq!(
        ids(&p),
        vec![
            Action::MoveToArchive(SegmentId::new(1)),
            Action::MoveToArchive(SegmentId::new(2)),
            Action::MoveToArchive(SegmentId::new(3)),
        ]
    );
    assert_eq!(p.hot, HotState::Ok);
    assert_eq!(p.archive, ArchiveStatus::Available);
    assert_eq!(p.rolling_budget, None);
}

#[test]
fn rolling_budget_is_seeded_from_hot_video_before_the_ingest_then_honoured() {
    let hot = vol(1000, 0);
    let segments = [
        seg(1, Tier::Hot, 20, 1),
        seg(2, Tier::Hot, 20, 2),
        seg(3, Tier::Hot, 20, 3),
    ];
    // Seed: 60 - 25 = 35; remaining must be <= 35, so two segments go.
    let p = plan(&input(hot, ArchiveState::Unavailable, &segments, 25)).unwrap();
    assert_eq!(p.rolling_budget, Some(35));
    assert_eq!(
        ids(&p),
        vec![
            Action::Delete(SegmentId::new(1)),
            Action::Delete(SegmentId::new(2))
        ]
    );
    // A fed-back budget wins over the ingest.
    let mut pin = input(hot, ArchiveState::Unavailable, &segments, 25);
    pin.rolling_budget = Some(40);
    let p = plan(&pin).unwrap();
    assert_eq!(p.rolling_budget, Some(40));
    assert_eq!(ids(&p), vec![Action::Delete(SegmentId::new(1))]);
    // Outside the rolling-buffer case the budget is cleared.
    let mut pin = input(vol(1000, 900), ArchiveState::Unavailable, &segments, 25);
    pin.rolling_budget = Some(40);
    assert_eq!(plan(&pin).unwrap().rolling_budget, None);
}

#[test]
fn rolling_buffer_never_deletes_more_than_exists() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 0,
    };
    let segments = [seg(1, Tier::Hot, 20, 1)];
    let p = plan(&input(hot, ArchiveState::Unavailable, &segments, 1_000_000)).unwrap();
    assert_eq!(ids(&p), vec![Action::Delete(SegmentId::new(1))]);
}

#[test]
fn rejects_an_unusable_hot_volume() {
    for hot in [
        VolumeSpace {
            capacity_bytes: 0,
            free_bytes: 0,
        },
        VolumeSpace {
            capacity_bytes: 10,
            free_bytes: 11,
        },
    ] {
        assert_eq!(
            plan(&input(hot, ArchiveState::Unavailable, &[], 0)),
            Err(PlanError::HotVolumeUnusable)
        );
    }
}

#[test]
fn rejects_duplicate_segment_ids() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let segments = [seg(1, Tier::Hot, 1, 1), seg(1, Tier::Archive, 1, 1)];
    assert_eq!(
        plan(&input(hot, ArchiveState::Unavailable, &segments, 0)),
        Err(PlanError::DuplicateSegment(SegmentId::new(1)))
    );
}

#[test]
fn reports_overflow_instead_of_wrapping_on_huge_segment_sizes() {
    let hot = VolumeSpace {
        capacity_bytes: 1000,
        free_bytes: 900,
    };
    let segments = [seg(1, Tier::Hot, u64::MAX, 1), seg(2, Tier::Hot, 1, 2)];
    assert_eq!(
        plan(&input(hot, ArchiveState::Unavailable, &segments, 0)),
        Err(PlanError::Overflow(OverflowQuantity::HotTotal))
    );
}

#[test]
fn handles_the_largest_capacity_without_overflow() {
    let hot = VolumeSpace {
        capacity_bytes: u64::MAX,
        free_bytes: 0,
    };
    let segments = [seg(1, Tier::Hot, u64::MAX, 1)];
    let p = plan(&input(hot, ArchiveState::Unavailable, &segments, 0)).unwrap();
    assert_eq!(ids(&p), vec![Action::Delete(SegmentId::new(1))]);
}

#[test]
fn zero_percent_floor_is_never_breached_at_zero_free() {
    let mut i = input(
        VolumeSpace {
            capacity_bytes: 1000,
            free_bytes: 0,
        },
        ArchiveState::Unavailable,
        &[],
        0,
    );
    i.policy.hot_min_free = MinFreePercent::new(0).unwrap();
    assert_eq!(ids(&plan(&i).unwrap()), Vec::<Action>::new());
}

fn vol(capacity_bytes: u64, free_bytes: u64) -> VolumeSpace {
    VolumeSpace {
        capacity_bytes,
        free_bytes,
    }
}

fn has_delete_of(p: &Plan, tier: Tier, segments: &[StoredSegment]) -> bool {
    p.actions.iter().any(|a| match a {
        Action::Delete(id) => segments.iter().any(|s| s.id == *id && s.tier == tier),
        _ => false,
    })
}

/// Reviewer scenario: floor 250, free 100, only 100 B of video; unreachable.
#[test]
fn archive_floor_unreachable_deletes_nothing_and_reports_below_floor() {
    let segments = [seg(1, Tier::Archive, 50, 1), seg(2, Tier::Archive, 50, 2)];
    let p = plan(&input(
        vol(1000, 900),
        ArchiveState::Available(vol(1000, 100)),
        &segments,
        0,
    ))
    .unwrap();
    assert_eq!(ids(&p), Vec::<Action>::new());
    assert_eq!(p.archive, ArchiveStatus::BelowFloor);
}

/// Auditor scenario: 800 B of foreign data, ten 10 B segments; 100 + 200... only 300 reachable.
#[test]
fn archive_filled_by_foreign_data_is_not_wiped() {
    let segments: Vec<StoredSegment> = (0..10).map(|i| seg(i, Tier::Archive, 10, i)).collect();
    let p = plan(&input(
        vol(1000, 100),
        ArchiveState::Available(vol(1000, 100)),
        &segments,
        0,
    ))
    .unwrap();
    assert!(!has_delete_of(&p, Tier::Archive, &segments));
    assert_eq!(p.archive, ArchiveStatus::BelowFloor);
}

/// Floor reachable, target not: evict only up to the floor.
#[test]
fn archive_floor_reachable_but_target_not_evicts_up_to_the_floor() {
    // floor 250, target 260; free 200 + 5 x 10 = 250 reachable, 260 not.
    let segments: Vec<StoredSegment> = (0..5).map(|i| seg(i, Tier::Archive, 10, i)).collect();
    let p = plan(&input(
        vol(1000, 900),
        ArchiveState::Available(vol(1000, 200)),
        &segments,
        0,
    ))
    .unwrap();
    assert_eq!(p.actions.len(), 5);
    let (_, arch, _) = simulate(900, Some(200), &segments, &p);
    assert_eq!(arch, Some(250));
    assert_eq!(p.archive, ArchiveStatus::Available);
}

/// Hot move needs eviction to a reachable floor but not the target.
#[test]
fn move_needing_eviction_to_floor_only_still_happens() {
    // archive free 240, 20 B segment: goal floor 250 + 20 = 270 = 240 + 30 reachable; target 280 not.
    let segments = [
        seg(1, Tier::Hot, 20, 1),
        seg(2, Tier::Archive, 15, 1),
        seg(3, Tier::Archive, 15, 2),
    ];
    let p = plan(&input(
        vol(1000, 240),
        ArchiveState::Available(vol(1000, 240)),
        &segments,
        0,
    ))
    .unwrap();
    let (hot_free, arch, _) = simulate(240, Some(240), &segments, &p);
    assert_eq!(hot_free, 260);
    assert_eq!(arch, Some(250));
}

/// No move that needs eviction is planned when the archive floor is unreachable.
#[test]
fn unreachable_archive_floor_plans_no_move_and_deletes_hot_instead() {
    let segments = [seg(1, Tier::Hot, 30, 1), seg(2, Tier::Archive, 10, 1)];
    let p = plan(&input(
        vol(1000, 240),
        ArchiveState::Available(vol(1000, 10)),
        &segments,
        0,
    ))
    .unwrap();
    assert_eq!(ids(&p), vec![Action::Delete(SegmentId::new(1))]);
    assert_eq!(p.archive, ArchiveStatus::Full);
    assert_eq!(p.hot, HotState::Ok);
}

/// Floor 250 reachable (free 200 + 55 video) but target 260 not: not unsatisfiable.
#[test]
fn hot_floor_reachable_but_target_not_without_archive_stops_at_the_floor() {
    let segments = [seg(1, Tier::Hot, 50, 1), seg(2, Tier::Hot, 5, 2)];
    for state in [
        ArchiveState::Unavailable,
        ArchiveState::Available(vol(1000, 10)),
    ] {
        let p = plan(&input(vol(1000, 200), state, &segments, 999)).unwrap();
        assert_eq!(p.hot, HotState::Ok);
        assert_eq!(ids(&p), vec![Action::Delete(SegmentId::new(1))]);
    }
}

#[test]
fn full_archive_covering_the_ingest_reports_unsatisfiable_not_rolling_buffer() {
    // Floor 250, free 0, hot video 100: unreachable. The archive takes 40 B and is then full.
    let segments = [seg(1, Tier::Hot, 40, 1), seg(2, Tier::Hot, 60, 2)];
    let p = plan(&input(
        vol(1000, 0),
        ArchiveState::Available(vol(1000, 290)),
        &segments,
        40,
    ))
    .unwrap();
    assert_eq!(p.archive, ArchiveStatus::Full);
    assert_eq!(ids(&p), vec![Action::MoveToArchive(SegmentId::new(1))]);
    assert_eq!(p.hot, HotState::Unsatisfiable);
}

#[test]
fn full_takes_precedence_over_below_floor_but_the_flag_survives() {
    let segments = [seg(1, Tier::Hot, 40, 1)];
    let p = plan(&input(
        vol(1000, 0),
        ArchiveState::Available(vol(1000, 100)),
        &segments,
        0,
    ))
    .unwrap();
    assert_eq!(p.archive, ArchiveStatus::Full);
    assert!(p.archive_below_floor);
}

#[test]
fn move_size_plus_floor_overflow_is_reported() {
    let segments = [seg(1, Tier::Hot, u64::MAX, 1)];
    assert_eq!(
        plan(&input(
            vol(1000, 0),
            ArchiveState::Available(vol(1000, 900)),
            &segments,
            0
        )),
        Err(PlanError::Overflow(OverflowQuantity::EvictionGoal))
    );
}

#[test]
fn overflow_names_the_quantity() {
    let segments = [
        seg(1, Tier::Archive, u64::MAX, 1),
        seg(2, Tier::Archive, 1, 2),
    ];
    assert_eq!(
        plan(&input(
            vol(1000, 900),
            ArchiveState::Available(vol(1000, 900)),
            &segments,
            0
        )),
        Err(PlanError::Overflow(OverflowQuantity::ArchiveTotal))
    );
}

fn reserve_input(
    free: u64,
    archive: ArchiveState,
    segments: &[StoredSegment],
    reserve: u64,
    budget: Option<u64>,
) -> PlanInput<'_> {
    let mut pin = input(vol(1000, free), archive, segments, 0);
    pin.policy.emergency_reserve_bytes = reserve;
    pin.rolling_budget = budget;
    pin
}

fn hot_bytes(segments: &[StoredSegment]) -> u64 {
    segments.iter().map(|s| s.bytes).sum()
}

fn apply_deletes(segments: &mut Vec<StoredSegment>, free: &mut u64, p: &Plan) {
    for a in &p.actions {
        if let Action::Delete(id) = a {
            if let Some(s) = segments.iter().find(|s| s.id == *id) {
                *free += s.bytes;
            }
            segments.retain(|s| s.id != *id);
        }
    }
}

#[test]
fn empty_hot_tick_keeps_the_budget_when_the_archive_is_full() {
    // Hot floor 250 unreachable (free 0, no video); archive room 10 is below its floor 25.
    let p = plan(&input(
        vol(1000, 0),
        ArchiveState::Available(vol(100, 10)),
        &[],
        0,
    ))
    .unwrap();
    assert_eq!(p.actions.len(), 0);
    assert_eq!(p.rolling_budget, Some(0));
    assert_eq!(p.hot, HotState::Unsatisfiable);
}

#[test]
fn emergency_reserve_deletes_oldest_video_even_at_the_budget() {
    let segments: Vec<StoredSegment> = (0..5).map(|i| seg(i, Tier::Hot, 10, i)).collect();
    // Video 50 is at the budget 50, free 5 is below the reserve 30: delete until free >= 30.
    let p = plan(&reserve_input(
        5,
        ArchiveState::Unavailable,
        &segments,
        30,
        Some(50),
    ))
    .unwrap();
    assert_eq!(
        ids(&p),
        vec![
            Action::Delete(SegmentId::new(0)),
            Action::Delete(SegmentId::new(1)),
            Action::Delete(SegmentId::new(2)),
        ]
    );
    assert_eq!(p.hot, HotState::RollingBuffer);
    assert_eq!(p.rolling_budget, Some(20));
}

#[test]
fn unmeetable_reserve_deletes_all_hot_video_and_reports_the_buffer() {
    let segments: Vec<StoredSegment> = (0..3).map(|i| seg(i, Tier::Hot, 10, i)).collect();
    let p = plan(&reserve_input(
        0,
        ArchiveState::Unavailable,
        &segments,
        500,
        Some(30),
    ))
    .unwrap();
    assert_eq!(p.actions.len(), 3);
    assert_eq!(p.hot, HotState::RollingBuffer);
    assert_eq!(p.rolling_budget, Some(0));
}

#[test]
fn foreign_growth_never_leaves_hot_below_the_reserve_while_video_remains() {
    const RESERVE: u64 = 30;
    let mut segments: Vec<StoredSegment> = (0..10).map(|i| seg(i, Tier::Hot, 10, i)).collect();
    let mut free = 100_u64; // floor 250 stays unreachable
    let mut budget = None;
    for tick in 0..60_u64 {
        free = free.saturating_sub(7); // foreign growth
        if free >= 10 {
            segments.push(seg(100 + tick, Tier::Hot, 10, 100 + tick));
            free -= 10;
        }
        let p = plan(&reserve_input(
            free,
            ArchiveState::Unavailable,
            &segments,
            RESERVE,
            budget,
        ))
        .unwrap();
        budget = p.rolling_budget;
        apply_deletes(&mut segments, &mut free, &p);
        assert!(
            free >= RESERVE || segments.is_empty(),
            "tick {tick}: free {free} with {} B of video",
            hot_bytes(&segments)
        );
    }
}

#[test]
fn rolling_budget_never_rises_across_ticks() {
    let mut segments: Vec<StoredSegment> = (0..6).map(|i| seg(i, Tier::Hot, 10, i)).collect();
    let mut free = 100_u64;
    let mut budget: Option<u64> = None;
    let mut prev = u64::MAX;
    for tick in 0..80_u64 {
        // Foreign data shrinks free space on some ticks; video arrives on most.
        free = free.saturating_sub(tick % 5);
        if tick % 7 != 0 && free >= 10 {
            segments.push(seg(100 + tick, Tier::Hot, 10, 100 + tick));
            free -= 10;
        }
        let mut pin = reserve_input(free, ArchiveState::Unavailable, &segments, 20, budget);
        pin.ingested_bytes = 10;
        let p = plan(&pin).unwrap();
        let b = p.rolling_budget.unwrap();
        assert!(b <= prev, "tick {tick}: budget rose from {prev} to {b}");
        prev = b;
        budget = p.rolling_budget;
        apply_deletes(&mut segments, &mut free, &p);
    }
}

fn ceiling_input(
    free: u64,
    segments: &[StoredSegment],
    reserve: u64,
    budget: Option<u64>,
    ceiling: Option<u64>,
) -> PlanInput<'_> {
    let mut pin = reserve_input(free, ArchiveState::Unavailable, segments, reserve, budget);
    // A hot floor of 250 B that stays unreachable in these cases.
    pin.rolling_ceiling = ceiling;
    pin
}

#[test]
fn budget_recovers_to_the_ceiling_once_the_foreign_burst_is_gone() {
    // A burst ratcheted the budget to 0; now free 100 and no video: 100 - reserve 30 = 70
    // can be held, the ceiling 50 limits it.
    let p = plan(&ceiling_input(100, &[], 30, Some(0), Some(50))).unwrap();
    assert_eq!(p.rolling_budget, Some(50));
    assert_eq!(p.rolling_ceiling, Some(50));
    assert_eq!(p.hot, HotState::Unsatisfiable);
    assert_eq!(p.actions.len(), 0);
}

#[test]
fn budget_recovery_is_limited_by_video_plus_free_minus_reserve() {
    // 60 free, no video, reserve 30: only 30 B can be held.
    let p = plan(&ceiling_input(60, &[], 30, Some(0), Some(50))).unwrap();
    assert_eq!(p.rolling_budget, Some(30));
    assert_eq!(p.rolling_ceiling, Some(50));
    // Video counts toward it: 20 B of video and 40 free is the same 60 B.
    let segs = [seg(0, Tier::Hot, 20, 0)];
    let p = plan(&ceiling_input(40, &segs, 30, Some(0), Some(50))).unwrap();
    assert_eq!(p.rolling_budget, Some(30));
    assert!(p.actions.is_empty(), "20 B of video is under the budget 30");
}

#[test]
fn recovery_never_lowers_the_budget_and_never_exceeds_the_ceiling() {
    // Nothing to recover to (reachable - reserve = 0): the fed level stays, and the reserve
    // then deletes and ratchets as before.
    let segs: Vec<StoredSegment> = (0..3).map(|i| seg(i, Tier::Hot, 10, i)).collect();
    let p = plan(&ceiling_input(0, &segs, 500, Some(20), Some(50))).unwrap();
    assert_eq!(p.rolling_budget, Some(0));
    assert_eq!(p.rolling_ceiling, Some(50));
    // A fed budget above the ceiling is lowered to it.
    let segs: Vec<StoredSegment> = (0..8).map(|i| seg(i, Tier::Hot, 10, i)).collect();
    let p = plan(&ceiling_input(100, &segs, 0, Some(80), Some(50))).unwrap();
    assert_eq!(p.rolling_budget, Some(50));
    assert_eq!(p.actions.len(), 3, "80 B of video held to 50 B");
}

#[test]
fn without_a_ceiling_the_fed_budget_is_the_ceiling() {
    let p = plan(&ceiling_input(100, &[], 30, Some(10), None)).unwrap();
    assert_eq!(p.rolling_budget, Some(10));
    assert_eq!(p.rolling_ceiling, Some(10));
}

#[test]
fn a_ratchet_then_recovery_returns_the_buffer_after_a_foreign_burst() {
    const CEILING: u64 = 100;
    // Floor 250 of 1000 is unreachable throughout. Reserve 40.
    let mut segments: Vec<StoredSegment> = (0..10).map(|i| seg(i, Tier::Hot, 10, i)).collect();
    let mut budget = None;
    let mut ceiling = None;
    let mut seen_low = false;
    for tick in 0..40_u64 {
        // Ticks 5..15: foreign data takes 60 B; afterwards it is gone again.
        let foreign = if (5..15).contains(&tick) { 60 } else { 0 };
        let video = hot_bytes(&segments);
        let reachable = 1000 - 900 - foreign; // total space not held by steady foreign data
        let mut free = reachable - video.min(reachable);
        let mut pin = reserve_input(free, ArchiveState::Unavailable, &segments, 40, budget);
        pin.rolling_ceiling = ceiling;
        pin.ingested_bytes = if tick == 0 { 0 } else { 10 };
        let p = plan(&pin).unwrap();
        budget = p.rolling_budget;
        ceiling = p.rolling_ceiling;
        apply_deletes(&mut segments, &mut free, &p);
        segments.push(seg(100 + tick, Tier::Hot, 10, 100 + tick));
        seen_low |= hot_bytes(&segments) < CEILING / 2;
    }
    assert!(seen_low, "the burst must have squeezed the buffer");
    let end = hot_bytes(&segments);
    assert!(
        end >= 50,
        "the buffer stayed drained after the burst: {end} B"
    );
    assert_eq!(ceiling, Some(CEILING));
}

#[test]
fn the_reserve_is_capped_at_ninety_percent_of_the_capacity() {
    use super::effective_reserve_bytes as eff;
    assert_eq!(eff(1000, 0), 0);
    assert_eq!(eff(1000, 899), 899);
    assert_eq!(eff(1000, 900), 900);
    assert_eq!(eff(1000, 901), 900);
    assert_eq!(eff(1000, u64::MAX), 900);
    assert_eq!(eff(1, 5), 0);
    assert_eq!(eff(0, 5), 0);
    assert_eq!(
        eff(u64::MAX, u64::MAX),
        u64::MAX / 100 * 90 + u64::MAX % 100 * 90 / 100
    );
}

#[test]
fn a_reserve_floor_above_the_percentage_floor_that_is_unreachable_is_flagged() {
    let segs = [seg(0, Tier::Hot, 10, 0)];
    // Percentage floor 250; reserve 500 raises it. free 100 + video 10 < 500: unreachable.
    let p = plan(&reserve_input(
        100,
        ArchiveState::Unavailable,
        &segs,
        500,
        None,
    ))
    .unwrap();
    assert!(p.reserve_floor_unreachable, "{p:?}");
    // Reserve below the percentage floor: the floor is the percentage and the flag stays off
    // even though it is unreachable.
    let p = plan(&reserve_input(
        100,
        ArchiveState::Unavailable,
        &segs,
        100,
        None,
    ))
    .unwrap();
    assert_eq!(p.hot, HotState::Unsatisfiable);
    assert!(!p.reserve_floor_unreachable, "{p:?}");
    // Reachable: off.
    let p = plan(&reserve_input(
        600,
        ArchiveState::Unavailable,
        &segs,
        500,
        None,
    ))
    .unwrap();
    assert!(!p.reserve_floor_unreachable, "{p:?}");
}
