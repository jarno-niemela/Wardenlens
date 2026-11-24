//! Unit tests: ADR 0005 worked example, the case 4 override and the edges.

use crate::time::{DurationMs, Timestamp};

use super::{
    Action, ArchiveState, ArchiveStatus, MinFreePercent, Plan, PlanError, PlanInput, Policy,
    SegmentId, StoredSegment, Tier, VolumeSpace, plan,
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
            ..Policy::default()
        },
        ingested_bytes,
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
    assert!(!p.unsatisfiable && !p.rolling_buffer);
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
    assert!(!p.unsatisfiable && !p.rolling_buffer);
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
fn unusable_archive_counts_as_unavailable() {
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
    assert_eq!(p.archive, ArchiveStatus::Unavailable);
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
    assert!(p.unsatisfiable);
    assert!(!p.rolling_buffer);
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
    let initial_video: u64 = segments.iter().map(|s| s.bytes).sum();
    for tick in 0..50_u64 {
        // New video arrives and consumes space.
        segments.push(seg(100 + tick, Tier::Hot, SEG, 100 + tick));
        hot_free -= SEG;
        let space = VolumeSpace {
            capacity_bytes: capacity,
            free_bytes: hot_free,
        };
        let p = plan(&input(space, ArchiveState::Unavailable, &segments, SEG)).unwrap();
        assert!(p.unsatisfiable && p.rolling_buffer, "tick {tick}");
        let (free, _, left) = simulate(hot_free, None, &segments, &p);
        hot_free = free;
        segments = left;
        let video: u64 = segments.iter().map(|s| s.bytes).sum();
        assert_eq!(video, initial_video, "tick {tick}");
        assert_eq!(hot_free, 100, "tick {tick}");
    }
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
        Err(PlanError::Overflow)
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
