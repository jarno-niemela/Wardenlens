//! Adversarial tests for the tiered storage planner (ticket #44).
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code on small bounded values; failures should panic"
)]

use std::collections::HashSet;

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

fn no_age_policy() -> Policy {
    Policy {
        hot_max_age: DurationMs::from_millis(u64::MAX),
        ..Policy::default()
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
        rolling_budget: None,
    })
}

fn id_of(a: &Action) -> SegmentId {
    match a {
        Action::MoveToArchive(id) | Action::Delete(id) => *id,
        _ => unreachable!(),
    }
}

/// Simulates the plan. Returns (hot free, archive free, archive video deleted).
fn simulate(hot_free: u64, arch_free: u64, segs: &[StoredSegment], p: &Plan) -> (u64, u64, u64) {
    let mut hot = hot_free;
    let mut arch = arch_free;
    let mut arch_deleted = 0;
    let mut tier: std::collections::HashMap<SegmentId, (Tier, u64)> =
        segs.iter().map(|s| (s.id, (s.tier, s.bytes))).collect();
    for a in &p.actions {
        let (t, b) = tier[&id_of(a)];
        match (a, t) {
            (Action::MoveToArchive(id), Tier::Hot) => {
                hot += b;
                arch = arch.checked_sub(b).expect("impossible move planned");
                tier.insert(*id, (Tier::Archive, b));
            }
            (Action::Delete(_), Tier::Hot) => hot += b,
            (Action::Delete(_), Tier::Archive) => {
                arch += b;
                arch_deleted += b;
            }
            _ => panic!("bad action {a:?}"),
        }
    }
    (hot, arch, arch_deleted)
}

// --- Case-4 principle applied to the archive -------------------------------

/// Non-video data fills the archive so its floor cannot be restored even by
/// deleting every archived segment. ADR 0005 section 6 case 4: "deleting video
/// that cannot restore the floor only loses recordings". The planner must not
/// wipe the archive for nothing.
#[test]
fn does_not_wipe_the_archive_when_its_floor_is_unreachable() {
    let hot = vol(1000, 900); // hot is fine
    // floor 250, free 10, archive video only 30 bytes: max reachable 40 < 250.
    let archive = vol(1000, 10);
    let segments = [
        seg(1, Tier::Archive, 10, 1),
        seg(2, Tier::Archive, 10, 2),
        seg(3, Tier::Archive, 10, 3),
    ];
    let p = run(
        hot,
        ArchiveState::Available(archive),
        &segments,
        no_age_policy(),
        1_000,
        0,
    )
    .unwrap();
    assert!(
        p.actions.is_empty(),
        "deleted archive video that cannot restore the floor: {:?}",
        p.actions
    );
}

/// Same, while the hot tier is below its floor: hot video cannot move to an
/// archive that can never hold it, and the archive must not be wiped either.
#[test]
fn does_not_wipe_the_archive_when_unreachable_and_hot_is_pressed() {
    let hot = vol(1000, 200); // below floor 250, reachable with hot deletes
    let archive = vol(1000, 10);
    let segments = [
        seg(1, Tier::Archive, 10, 1),
        seg(2, Tier::Archive, 10, 2),
        seg(10, Tier::Hot, 30, 10),
        seg(11, Tier::Hot, 30, 11),
        seg(12, Tier::Hot, 30, 12),
    ];
    let p = run(
        hot,
        ArchiveState::Available(archive),
        &segments,
        no_age_policy(),
        1_000,
        0,
    )
    .unwrap();
    let archive_deletes: Vec<_> = p
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Delete(id) if id.as_u64() < 10))
        .collect();
    assert!(
        archive_deletes.is_empty(),
        "archive video deleted with no benefit: {:?}",
        p.actions
    );
    assert_eq!(p.archive, ArchiveStatus::Full);
    let (hot_after, _, _) = simulate(200, 10, &segments, &p);
    assert!(hot_after >= 260);
}

// --- Plain edge cases (should pass) ----------------------------------------

#[test]
fn segment_exactly_at_max_age_is_not_moved_one_past_is() {
    let hot = vol(1000, 900);
    let archive = vol(1000, 900);
    let policy = Policy {
        hot_max_age: DurationMs::from_millis(100),
        ..Policy::default()
    };
    let segments = [seg(1, Tier::Hot, 10, 899), seg(2, Tier::Hot, 10, 900)];
    let p = run(
        hot,
        ArchiveState::Available(archive),
        &segments,
        policy,
        1_000,
        0,
    )
    .unwrap();
    assert_eq!(p.actions, vec![Action::MoveToArchive(SegmentId::new(1))]);
}

#[test]
fn extreme_timestamps_and_max_age_do_not_panic() {
    let hot = vol(1000, 900);
    let archive = vol(1000, 900);
    for (now, ended, age) in [
        (i64::MAX, i64::MIN, 0_u64),
        (i64::MIN, i64::MAX, 0),
        (i64::MAX, i64::MIN, u64::MAX),
        (0, i64::MIN, u64::MAX - 1),
    ] {
        let policy = Policy {
            hot_max_age: DurationMs::from_millis(age),
            ..Policy::default()
        };
        let segments = [seg(1, Tier::Hot, 10, ended)];
        let _ = run(
            hot,
            ArchiveState::Available(archive),
            &segments,
            policy,
            now,
            u64::MAX,
        )
        .unwrap();
    }
}

#[test]
fn u64_max_everything_returns_without_panic() {
    let hot = vol(u64::MAX, 0);
    let archive = vol(u64::MAX, u64::MAX);
    let segments = [
        seg(1, Tier::Hot, u64::MAX / 2, 1),
        seg(2, Tier::Archive, u64::MAX / 2, 0),
    ];
    for pct in [0_u8, 1, 50, 89, 90] {
        let policy = Policy {
            hot_min_free: MinFreePercent::new(pct).unwrap(),
            archive_min_free: MinFreePercent::new(pct).unwrap(),
            hot_max_age: DurationMs::from_millis(0),
            emergency_reserve_bytes: 0,
        };
        for st in [ArchiveState::Available(archive), ArchiveState::Unavailable] {
            let r = run(hot, st, &segments, policy, 10, u64::MAX);
            if let Ok(p) = r {
                let (h, _, _) = simulate(0, u64::MAX, &segments, &p);
                let _ = h;
            }
        }
    }
}

#[test]
fn archive_with_free_above_capacity_is_unavailable_and_untouched() {
    let hot = vol(1000, 100);
    let segments = [seg(1, Tier::Archive, 10, 1), seg(2, Tier::Hot, 200, 2)];
    let p = run(
        hot,
        ArchiveState::Available(vol(100, 101)),
        &segments,
        no_age_policy(),
        1_000,
        0,
    )
    .unwrap();
    assert_eq!(p.archive, ArchiveStatus::Unusable);
    assert_eq!(p.actions, vec![Action::Delete(SegmentId::new(2))]);
}

#[test]
fn duplicate_ids_across_tiers_are_rejected() {
    let segments = [seg(7, Tier::Hot, 1, 1), seg(7, Tier::Archive, 1, 1)];
    let r = run(
        vol(1000, 900),
        ArchiveState::Unavailable,
        &segments,
        no_age_policy(),
        1,
        0,
    );
    assert_eq!(r, Err(PlanError::DuplicateSegment(SegmentId::new(7))));
}

#[test]
fn hot_exactly_at_floor_plans_nothing() {
    let segments = [seg(1, Tier::Hot, 10, 1)];
    let p = run(
        vol(1000, 250),
        ArchiveState::Unavailable,
        &segments,
        no_age_policy(),
        1,
        0,
    )
    .unwrap();
    assert_eq!(p.actions, Vec::<Action>::new());
}

#[test]
fn big_old_segment_that_never_fits_does_not_block_reporting_full() {
    // archive can take at most 750 bytes above floor; first hot segment is 800.
    let hot = vol(10_000, 2_000); // floor 2500, target 2600, need 600
    let archive = vol(1000, 1000);
    let segments = [seg(1, Tier::Hot, 800, 1), seg(2, Tier::Hot, 100, 2)];
    let p = run(
        hot,
        ArchiveState::Available(archive),
        &segments,
        no_age_policy(),
        10,
        0,
    )
    .unwrap();
    assert_eq!(p.archive, ArchiveStatus::Full);
    let (h, a, _) = simulate(2_000, 1_000, &segments, &p);
    assert!(h >= 2_600);
    assert!(a >= 250);
}

// --- Stronger property oracle ----------------------------------------------

fn volume() -> impl Strategy<Value = VolumeSpace> {
    (1_u64..=100_000).prop_flat_map(|c| (Just(c), 0..=c).prop_map(|(c, f)| vol(c, f)))
}

fn segments() -> impl Strategy<Value = Vec<StoredSegment>> {
    prop::collection::vec((any::<bool>(), 0_u64..8_000, 0_i64..1_000), 0..30).prop_map(|v| {
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]
    #[test]
    fn planner_oracle(
        hot in volume(),
        archive in prop::option::of(volume()),
        segs in segments(),
        hp in 0_u8..=90,
        ap in 0_u8..=90,
        age in 0_u64..1_200,
        ingested in 0_u64..10_000,
    ) {
        let policy = Policy {
            hot_min_free: MinFreePercent::new(hp).unwrap(),
            archive_min_free: MinFreePercent::new(ap).unwrap(),
            emergency_reserve_bytes: 0,
            hot_max_age: DurationMs::from_millis(age),
        };
        let st = archive.map_or(ArchiveState::Unavailable, ArchiveState::Available);
        let p = run(hot, st, &segs, policy, 1_000, ingested).unwrap();

        // Every id exists, no repeats.
        let mut seen = HashSet::new();
        for a in &p.actions {
            prop_assert!(seen.insert(id_of(a)));
            prop_assert!(segs.iter().any(|s| s.id == id_of(a)));
        }

        // Moves and hot deletes form a contiguous oldest-first prefix of hot.
        let mut hot_sorted: Vec<_> = segs.iter().filter(|s| s.tier == Tier::Hot).collect();
        hot_sorted.sort_by_key(|s| (s.ended_at, s.id));
        let hot_actions: Vec<SegmentId> = p.actions.iter().map(id_of)
            .filter(|id| hot_sorted.iter().any(|s| s.id == *id)).collect();
        let prefix: Vec<SegmentId> = hot_sorted.iter().take(hot_actions.len()).map(|s| s.id).collect();
        prop_assert_eq!(&hot_actions, &prefix);

        // Archive deletions also oldest-first prefix.
        let mut arch_sorted: Vec<_> = segs.iter().filter(|s| s.tier == Tier::Archive).collect();
        arch_sorted.sort_by_key(|s| (s.ended_at, s.id));
        let arch_actions: Vec<SegmentId> = p.actions.iter().map(id_of)
            .filter(|id| arch_sorted.iter().any(|s| s.id == *id)).collect();
        let aprefix: Vec<SegmentId> = arch_sorted.iter().take(arch_actions.len()).map(|s| s.id).collect();
        prop_assert_eq!(&arch_actions, &aprefix);

        let hot_floor = hot.capacity_bytes * u64::from(hp) / 100;
        let hot_target = hot.capacity_bytes * (u64::from(hp) + 1) / 100;
        let hot_total: u64 = hot_sorted.iter().map(|s| s.bytes).sum();
        let (h_after, a_after, arch_deleted) =
            simulate(hot.free_bytes, archive.map_or(0, |a| a.free_bytes), &segs, &p);

        // Reachable hot floor: the plan restores the target.
        if hot.free_bytes < hot_floor && hot.free_bytes + hot_total >= hot_target {
            prop_assert!(p.hot == HotState::Ok);
            prop_assert!(h_after >= hot_target, "hot {} < target {}", h_after, hot_target);
        }
        // Hot deletes only when the archive cannot help.
        let hot_deletes = p.actions.iter().any(|a| matches!(a, Action::Delete(id)
            if hot_sorted.iter().any(|s| s.id == *id)));
        if hot_deletes {
            prop_assert!(p.archive != ArchiveStatus::Available);
        }
        // Hot above floor and not aged: nothing deleted from hot.
        if hot.free_bytes >= hot_floor {
            prop_assert!(!hot_deletes);
        }
        if let Some(a) = archive {
            let afloor = a.capacity_bytes * u64::from(ap) / 100;
            // Archive deletions must buy something: either they restore the
            // archive floor or they make room for planned moves.
            let arch_total: u64 = arch_sorted.iter().map(|s| s.bytes).sum();
            let reachable = a.free_bytes + arch_total >= afloor;
            if arch_deleted > 0 && reachable {
                prop_assert!(a_after >= afloor,
                    "archive video deleted ({}) yet archive left below floor {} < {}",
                    arch_deleted, a_after, afloor);
            }
            // Archive at or above floor stays there if it was.
            if a.free_bytes >= afloor {
                prop_assert!(a_after >= afloor);
            }
        }
    }
}

proptest! {
    /// ADR 0005 section 6 case 4 principle on the archive: when even deleting
    /// every archived segment cannot restore the archive floor, no archive
    /// video is deleted (it would only lose recordings).
    #[test]
    fn unreachable_archive_floor_deletes_no_archive_video(
        hot in volume(),
        cap in 1_000_u64..100_000,
        segs in segments(),
        ap in 1_u8..=90,
    ) {
        let arch_total: u64 = segs.iter().filter(|s| s.tier == Tier::Archive).map(|s| s.bytes).sum();
        let afloor = cap * u64::from(ap) / 100;
        prop_assume!(arch_total < afloor);
        let free = (afloor - arch_total).saturating_sub(1);
        let policy = Policy {
            archive_min_free: MinFreePercent::new(ap).unwrap(),
            ..no_age_policy()
        };
        let p = run(hot, ArchiveState::Available(vol(cap, free)), &segs, policy, 1_000, 0).unwrap();
        let arch_deletes = p.actions.iter().filter(|a| matches!(a, Action::Delete(id)
            if segs.iter().any(|s| s.id == *id && s.tier == Tier::Archive))).count();
        prop_assert_eq!(arch_deletes, 0, "plan {:?}", p.actions);
    }
}
