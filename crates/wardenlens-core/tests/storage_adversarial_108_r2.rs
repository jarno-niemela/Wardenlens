//! Adversarial tests for ticket #108 round 2 (PR #192): the 90 % cap on the reserve-raised hot
//! floor, `Plan::reserve_floor_unreachable`, and the proof that an ingest cap cannot change a
//! plan.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code; failures should panic"
)]

use proptest::prelude::*;
use wardenlens_core::storage::{
    Action, ArchiveState, ArchiveStatus, HotState, MinFreePercent, Plan, PlanInput, Policy,
    SegmentId, StoredSegment, Tier, VolumeSpace, plan,
};
use wardenlens_core::time::{DurationMs, Timestamp};

const NOW: i64 = 1_000_000;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

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

fn default_policy() -> Policy {
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
    ingested: u64,
    budget: Option<u64>,
    ceiling: Option<u64>,
) -> Plan {
    plan(&PlanInput {
        hot,
        archive,
        segments,
        now: Timestamp::from_unix_millis(NOW),
        policy,
        ingested_bytes: ingested,
        rolling_budget: budget,
        rolling_ceiling: ceiling,
    })
    .unwrap()
}

fn deleted(p: &Plan) -> Vec<SegmentId> {
    p.actions
        .iter()
        .filter_map(|a| match a {
            Action::Delete(id) => Some(*id),
            _ => None,
        })
        .collect()
}

/// Simulates `ticks` ticks of a recorder writing one `seg_bytes` segment per tick onto a hot
/// volume of `capacity` holding `foreign` bytes of non-video data, archive unavailable.
/// Returns the hot video held after the last tick.
fn simulate_hot_only(capacity: u64, foreign: u64, seg_bytes: u64, policy: Policy) -> u64 {
    let mut segs: Vec<StoredSegment> = Vec::new();
    let (mut budget, mut ceiling) = (None, None);
    for tick in 0..60_u64 {
        let held: u64 = segs.iter().map(|s| s.bytes).sum();
        if capacity - foreign - held >= seg_bytes {
            segs.push(seg(
                tick,
                Tier::Hot,
                seg_bytes,
                i64::try_from(tick).unwrap(),
            ));
        }
        let held: u64 = segs.iter().map(|s| s.bytes).sum();
        let p = run(
            vol(capacity, capacity - foreign - held),
            ArchiveState::Unavailable,
            &segs,
            policy,
            seg_bytes,
            budget,
            ceiling,
        );
        budget = p.rolling_budget;
        ceiling = p.rolling_ceiling;
        let gone = deleted(&p);
        segs.retain(|s| !gone.contains(&s.id));
    }
    segs.iter().map(|s| s.bytes).sum()
}

/// Invariant: a 1 GiB hot volume with the default policy and 150 MiB (about 15 %) of non-video
/// data (the index, logs, `lost+found`, the OS) keeps more than one tick of video. The percentage
/// floor (25 %) is reachable, and the reserve (capped at 90 % of the capacity) is not part of the
/// floor while the volume cannot reach it, so the rolling buffer never chases it.
#[test]
fn small_hot_volume_with_some_foreign_data_keeps_more_than_one_tick_of_video() {
    let held = simulate_hot_only(GIB, 150 * MIB, 10 * MIB, default_policy());
    assert!(
        held > 10 * MIB,
        "only {} MiB of video kept on a 1 GiB volume with 150 MiB of other data",
        held / MIB
    );
}

/// Invariant on a volume larger than the reserve (no cap involved): 4 GiB, default policy,
/// 2.1 GiB of other data. The plain 25 % floor (1 GiB) is reachable with ~0.9 GiB of video; the
/// 2 GiB reserve is not, so it is ignored and video is kept as without a reserve.
#[test]
fn four_gib_hot_volume_with_reachable_percentage_floor_keeps_video() {
    let foreign = 2 * GIB + 100 * MIB;
    let with_reserve = simulate_hot_only(4 * GIB, foreign, 10 * MIB, default_policy());
    let without = simulate_hot_only(
        4 * GIB,
        foreign,
        10 * MIB,
        Policy {
            emergency_reserve_bytes: 0,
            ..default_policy()
        },
    );
    assert!(
        without > 500 * MIB,
        "sanity: the percentage floor alone keeps video ({} MiB)",
        without / MIB
    );
    assert!(
        with_reserve > 10 * MIB,
        "{} MiB kept with the reserve vs {} MiB without",
        with_reserve / MIB,
        without / MIB
    );
}

/// Control: the round-2 cap fixes the no-foreign-data case (the ADR's 1 GiB example).
#[test]
fn small_hot_volume_with_nothing_else_keeps_about_ninety_mib() {
    let held = simulate_hot_only(GIB, 0, 10 * MIB, default_policy());
    assert!((80 * MIB..=100 * MIB).contains(&held), "{} MiB", held / MIB);
}

/// Control: the exact cliff edge. Reachable == the capped reserve keeps the floor satisfiable;
/// one byte less flips into the rolling buffer.
#[test]
fn the_capped_reserve_floor_is_unreachable_exactly_one_byte_below_it() {
    let capacity = 1000 * MIB;
    let eff = capacity / 100 * 90;
    let segs = [seg(1, Tier::Hot, 10 * MIB, 1)];
    let at = run(
        vol(capacity, eff - 10 * MIB),
        ArchiveState::Unavailable,
        &segs,
        default_policy(),
        0,
        None,
        None,
    );
    assert_ne!(at.hot, HotState::RollingBuffer, "{at:?}");
    assert!(!at.reserve_floor_unreachable, "{at:?}");
    let below = run(
        vol(capacity, eff - 10 * MIB - 1),
        ArchiveState::Unavailable,
        &segs,
        default_policy(),
        0,
        None,
        None,
    );
    assert!(below.reserve_floor_unreachable, "{below:?}");
}

/// The alert flag is set when the archive is `Available` and takes everything, so the
/// adapter alerts even though the archive status alone would not.
#[test]
fn reserve_floor_unreachable_is_set_while_the_archive_absorbs_all_hot_video() {
    let segs = [
        seg(1, Tier::Hot, 10 * MIB, 1),
        seg(2, Tier::Hot, 10 * MIB, 2),
    ];
    let p = run(
        vol(GIB, 800 * MIB),
        ArchiveState::Available(vol(100 * GIB, 100 * GIB)),
        &segs,
        default_policy(),
        0,
        None,
        None,
    );
    assert_eq!(p.archive, ArchiveStatus::Available, "{p:?}");
    assert_eq!(p.hot, HotState::Unsatisfiable, "{p:?}");
    assert!(p.reserve_floor_unreachable, "{p:?}");
    assert!(deleted(&p).is_empty(), "the archive takes it: {p:?}");
}

/// The flag is not set when the plain percentage floor is the unreachable one (it is a
/// reserve-specific alert), nor when the reserve floor is merely breached but reachable.
#[test]
fn reserve_floor_unreachable_is_off_for_percentage_floor_and_reachable_reserve() {
    let segs = [seg(1, Tier::Hot, 10 * MIB, 1)];
    let big = 100 * GIB;
    // Percentage floor 25 GiB dominates the 2 GiB reserve; unreachable.
    let p = run(
        vol(big, GIB),
        ArchiveState::Unavailable,
        &segs,
        default_policy(),
        0,
        None,
        None,
    );
    assert_eq!(p.hot, HotState::RollingBuffer);
    assert!(!p.reserve_floor_unreachable, "{p:?}");
    // 0 % floor, reserve 2 GiB dominates; breached but reachable.
    let pol = Policy {
        hot_min_free: MinFreePercent::new(0).unwrap(),
        ..default_policy()
    };
    let segs = [seg(1, Tier::Hot, 3 * GIB, 1)];
    let p = run(
        vol(big, GIB),
        ArchiveState::Unavailable,
        &segs,
        pol,
        0,
        None,
        None,
    );
    assert_eq!(p.hot, HotState::Ok);
    assert!(!p.reserve_floor_unreachable, "{p:?}");
}

fn segments() -> impl Strategy<Value = Vec<StoredSegment>> {
    prop::collection::vec((1_u64..50_000, -1000_i64..1000, any::<bool>()), 0..12).prop_map(|v| {
        v.into_iter()
            .enumerate()
            .map(|(i, (b, t, h))| {
                seg(
                    u64::try_from(i).unwrap(),
                    if h { Tier::Hot } else { Tier::Archive },
                    b,
                    t,
                )
            })
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The round-2 removal proof of `plausible_ingest`: capping the ingest at the used space
    /// (`capacity - free`) never changes a plan. The adapter's ingest is at most the hot total
    /// (`hot_total.saturating_sub(after)`), so the generator keeps that bound.
    #[test]
    fn capping_ingest_at_the_used_space_never_changes_a_plan(
        capacity in 1_u64..400_000,
        free_frac in 0_u64..=100,
        segs in segments(),
        hot_pct in 0_u8..=90,
        reserve in prop_oneof![Just(0_u64), 0_u64..500_000, Just(u64::MAX)],
        ingest_frac in 0_u64..=100,
        fed in prop::option::of(0_u64..300_000),
        ceiling in prop::option::of(0_u64..300_000),
        with_archive in any::<bool>(),
    ) {
        let free = capacity / 100 * free_frac;
        let hot_total: u64 = segs.iter().filter(|s| s.tier == Tier::Hot).map(|s| s.bytes).sum();
        let ingested = hot_total / 100 * ingest_frac;
        let used = capacity.saturating_sub(free);
        let capped = ingested.min(used);
        let pol = Policy {
            hot_min_free: MinFreePercent::new(hot_pct).unwrap(),
            emergency_reserve_bytes: reserve,
            ..default_policy()
        };
        let archive = if with_archive {
            ArchiveState::Available(vol(300_000, 150_000))
        } else {
            ArchiveState::Unavailable
        };
        let a = run(vol(capacity, free), archive, &segs, pol, ingested, fed, ceiling);
        let b = run(vol(capacity, free), archive, &segs, pol, capped, fed, ceiling);
        prop_assert_eq!(a, b);
    }
}
