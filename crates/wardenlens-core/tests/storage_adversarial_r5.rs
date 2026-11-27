//! Adversarial tests, round 5, for the tiered storage planner (ticket #44): the emergency
//! free-space reserve and the reserve-forced budget ratchet.
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

fn policy(hp: u8, reserve: u64) -> Policy {
    Policy {
        hot_min_free: MinFreePercent::new(hp).unwrap(),
        archive_min_free: MinFreePercent::new(25).unwrap(),
        hot_max_age: DurationMs::from_millis(u64::MAX),
        emergency_reserve_bytes: reserve,
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
        rolling_ceiling: None,
    })
}

fn bytes_of(segs: &[StoredSegment], id: SegmentId) -> u64 {
    segs.iter().find(|s| s.id == id).map_or(0, |s| s.bytes)
}

/// Bytes leaving the hot volume (moves + hot deletes) and the hot deletes, in order.
fn hot_outflow(segs: &[StoredSegment], p: &Plan) -> (u64, Vec<SegmentId>) {
    let mut out = 0;
    let mut dels = Vec::new();
    for a in &p.actions {
        let id = match a {
            Action::MoveToArchive(id) | Action::Delete(id) => *id,
            _ => unreachable!(),
        };
        if segs.iter().any(|s| s.id == id && s.tier == Tier::Hot) {
            out += bytes_of(segs, id);
            if matches!(a, Action::Delete(_)) {
                dels.push(id);
            }
        }
    }
    (out, dels)
}

fn arb_archive() -> impl Strategy<Value = ArchiveState> {
    prop_oneof![
        Just(ArchiveState::Unavailable),
        (1_u64..20_000, 0_u64..20_000).prop_map(|(c, f)| ArchiveState::Available(vol(c, f.min(c)))),
        Just(ArchiveState::Available(vol(0, 0))),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Whenever the hot floor is unreachable, after simulated execution either no hot video is
    /// left or the hot volume has at least the emergency reserve free. Budget never rises, and
    /// a ratchet happens only when the reserve really forced a delete at or below the budget.
    #[test]
    fn unreachable_floor_never_leaves_free_below_reserve_with_video_left(
        hot_sizes in prop::collection::vec(0_u64..3_000, 0..20),
        arch_sizes in prop::collection::vec(0_u64..3_000, 0..10),
        cap in 1_u64..50_000,
        free_frac in 0_u64..=100,
        hp in 0_u8..=90,
        reserve in prop_oneof![Just(0_u64), 0_u64..20_000, Just(u64::MAX)],
        archive in arb_archive(),
        fed in prop::option::of(0_u64..60_000),
        ingested in 0_u64..10_000,
    ) {
        let free = cap * free_frac / 100;
        let mut segs = Vec::new();
        for (i, b) in hot_sizes.iter().enumerate() {
            let i = u64::try_from(i).unwrap();
            segs.push(seg(i, Tier::Hot, *b, i64::try_from(i).unwrap()));
        }
        for (i, b) in arch_sizes.iter().enumerate() {
            let i = 1000 + u64::try_from(i).unwrap();
            segs.push(seg(i, Tier::Archive, *b, i64::try_from(i).unwrap()));
        }
        let p = run(vol(cap, free), archive, &segs, policy(hp, reserve), ingested, fed).unwrap();
        let hot_total: u64 = hot_sizes.iter().sum();
        let floor = cap * u64::from(hp) / 100;
        let (out, dels) = hot_outflow(&segs, &p);
        let left = hot_total - out;
        let free_after = free + out;
        if free + hot_total < floor {
            prop_assert!(left == 0 || free_after >= reserve,
                "left {} free_after {} reserve {} plan {:?}", left, free_after, reserve, p);
            // A Unsatisfiable report with deletable video and free below the reserve must not
            // happen (the adapter would see no deletes and no RollingBuffer).
        }
        if let Some(b) = p.rolling_budget {
            let limit = fed.unwrap_or(hot_total.saturating_sub(ingested));
            prop_assert!(b <= limit, "budget rose {} > {}", b, limit);
            if b < limit {
                // Ratchet: must equal what is left, and the reserve must have been binding:
                // without the last delete free would have been below the reserve.
                prop_assert_eq!(b, left);
                let last = *dels.last().unwrap();
                prop_assert!(free_after - bytes_of(&segs, last) < reserve);
            }
            // Deletes stop as soon as both conditions hold.
            if let Some(last) = dels.last() {
                let lb = bytes_of(&segs, *last);
                prop_assert!(left + lb > b.max(left) || free_after - lb < reserve,
                    "over-deleted: left {} budget {} free_after {} reserve {}", left, b, free_after, reserve);
            }
        }
        if p.hot == HotState::RollingBuffer {
            prop_assert!(!dels.is_empty());
            prop_assert!(p.rolling_budget.is_some());
        }
    }

    /// No-drain with a reserve that is comfortably met at the budget: constant foreign data,
    /// random ingest sizes; the budget never changes and hot video never falls more than one
    /// segment below it.
    #[test]
    fn satisfiable_reserve_never_drains_the_buffer(
        initial in prop::collection::vec(1_u64..5_000, 1..40),
        ticks in prop::collection::vec(prop::collection::vec(1_u64..5_000, 0..4), 1..60),
    ) {
        let cap = 10_000_000_u64; // floor 2.5 MB
        let foreign = 9_000_000_u64; // floor unreachable: free + video <= 1 MB
        let reserve = 500_000_u64;
        let mut segs: Vec<StoredSegment> = initial.iter().enumerate()
            .map(|(i, b)| seg(u64::try_from(i).unwrap(), Tier::Hot, *b, i64::try_from(i).unwrap()))
            .collect();
        let mut next = u64::try_from(segs.len()).unwrap();
        let mut budget = None;
        let mut largest = initial.iter().copied().max().unwrap_or(0);
        let mut first = None;
        for sizes in &ticks {
            let mut ingested = 0;
            for b in sizes {
                segs.push(seg(next, Tier::Hot, *b, i64::try_from(next).unwrap()));
                next += 1;
                ingested += b;
                largest = largest.max(*b);
            }
            let video: u64 = segs.iter().map(|s| s.bytes).sum();
            let free = cap - foreign - video;
            let p = run(vol(cap, free), ArchiveState::Unavailable, &segs, policy(25, reserve), ingested, budget).unwrap();
            let b = p.rolling_budget.unwrap();
            let f = *first.get_or_insert(b);
            prop_assert_eq!(b, f, "budget changed");
            let (_, dels) = hot_outflow(&segs, &p);
            segs.retain(|s| !dels.contains(&s.id));
            let after: u64 = segs.iter().map(|s| s.bytes).sum();
            prop_assert!(after <= b && after + largest > b || after == 0);
            budget = p.rolling_budget;
        }
    }

    /// Foreign growth with a Full archive that takes some moves: free never stays below the
    /// reserve while hot video is left.
    #[test]
    fn full_archive_with_foreign_growth_keeps_reserve(
        growth in prop::collection::vec(0_u64..400, 1..60),
        arch_free in 0_u64..2_000,
    ) {
        let cap = 10_000_u64; // floor 2500
        let reserve = 600_u64;
        let mut segs: Vec<StoredSegment> = (0..10).map(|i| seg(i, Tier::Hot, 100, i64::try_from(i).unwrap())).collect();
        let mut foreign = 7_500_u64;
        let mut budget = None;
        let mut arch_free = arch_free;
        for (next, g) in (100_u64..).zip(growth) {
            foreign = (foreign + g).min(cap);
            segs.push(seg(next, Tier::Hot, 100, i64::try_from(next).unwrap()));
            let video: u64 = segs.iter().filter(|s| s.tier == Tier::Hot).map(|s| s.bytes).sum();
            let free = cap.saturating_sub(foreign + video);
            // Index lags reality if foreign+video > cap; clamp like statvfs would.
            let p = run(vol(cap, free), ArchiveState::Available(vol(4_000, arch_free)), &segs,
                policy(25, reserve), 100, budget).unwrap();
            budget = p.rolling_budget;
            let (out, _) = hot_outflow(&segs, &p);
            for a in &p.actions {
                match a {
                    Action::Delete(id) => segs.retain(|s| s.id != *id),
                    Action::MoveToArchive(id) => {
                        let s = segs.iter_mut().find(|s| s.id == *id).unwrap();
                        s.tier = Tier::Archive;
                        arch_free -= s.bytes;
                    }
                    _ => unreachable!(),
                }
            }
            let left: u64 = segs.iter().filter(|s| s.tier == Tier::Hot).map(|s| s.bytes).sum();
            prop_assert!(left == 0 || free + out >= reserve, "free {} out {} left {} {:?}", free, out, left, p);
        }
    }
}

/// Ticket override: "Never let the recorder run / to ENOSPC." A hot floor of 0 % is a valid
/// configuration (0-90). The reserve is a minimum for the floor, so with the archive unavailable
/// and foreign data plus video filling the volume to 0 free bytes the planner deletes hot video
/// until the reserve is free (ticket #108; it once planned nothing).
#[test]
fn zero_percent_floor_at_enospc_with_deletable_video_frees_space() {
    let segs: Vec<StoredSegment> = (0..10)
        .map(|i| seg(i, Tier::Hot, 100, i64::try_from(i).unwrap()))
        .collect();
    let p = run(
        vol(10_000, 0),
        ArchiveState::Unavailable,
        &segs,
        policy(0, 500),
        100,
        None,
    )
    .unwrap();
    let (out, _) = hot_outflow(&segs, &p);
    assert!(
        out >= 500,
        "free stays 0 (ENOSPC) with 1000 B of deletable video: {p:?}"
    );
}

/// Same with the archive available and empty: the video moves (it once did not).
#[test]
fn zero_percent_floor_at_enospc_with_archive_space_moves_video() {
    let segs: Vec<StoredSegment> = (0..10)
        .map(|i| seg(i, Tier::Hot, 100, i64::try_from(i).unwrap()))
        .collect();
    let p = run(
        vol(10_000, 0),
        ArchiveState::Available(vol(100_000, 100_000)),
        &segs,
        policy(0, 500),
        100,
        None,
    )
    .unwrap();
    let (out, _) = hot_outflow(&segs, &p);
    assert!(
        out > 0,
        "hot at ENOSPC, archive empty, nothing moved: {p:?}"
    );
}

/// Reserve of `u64::MAX` on an unreachable floor: every hot segment is deleted, budget 0,
/// `RollingBuffer`, no panic; a `Full` archive's moves are not also deleted.
#[test]
fn max_reserve_with_partial_moves_deletes_rest_once() {
    let segs: Vec<StoredSegment> = (0..6)
        .map(|i| seg(i, Tier::Hot, 100, i64::try_from(i).unwrap()))
        .collect();
    // Archive cap 1000, floor 250, free 500 -> room for 2 moves (200 + 250 <= 500, 300+250 > 500).
    let p = run(
        vol(100_000, 0),
        ArchiveState::Available(vol(1000, 500)),
        &segs,
        policy(25, u64::MAX),
        0,
        Some(10_000),
    )
    .unwrap();
    let moved: Vec<_> = p
        .actions
        .iter()
        .filter(|a| matches!(a, Action::MoveToArchive(_)))
        .collect();
    let deleted: Vec<_> = p
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Delete(_)))
        .collect();
    assert_eq!(moved.len(), 2);
    assert_eq!(deleted.len(), 4);
    assert_eq!(p.hot, HotState::RollingBuffer);
    assert_eq!(p.archive, ArchiveStatus::Full);
    assert_eq!(p.rolling_budget, Some(0));
}
