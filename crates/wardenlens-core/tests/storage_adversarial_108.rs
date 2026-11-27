//! Adversarial tests for ticket #108 (PR #192): the emergency reserve as a minimum hot floor,
//! rolling-budget recovery up to a ceiling, and their behaviour across many ticks.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code; failures should panic"
)]

use proptest::prelude::*;
use wardenlens_core::storage::{
    Action, ArchiveState, HotState, MinFreePercent, Plan, PlanInput, Policy, SegmentId,
    StoredSegment, Tier, VolumeSpace, effective_reserve_bytes, plan,
};
use wardenlens_core::time::{DurationMs, Timestamp};

const NOW: i64 = 1_000_000;
const MIB: u64 = 1024 * 1024;

fn seg(id: u64, bytes: u64, ended_ms: i64) -> StoredSegment {
    StoredSegment {
        id: SegmentId::new(id),
        tier: Tier::Hot,
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

#[derive(Clone, Copy)]
struct Fed {
    budget: Option<u64>,
    ceiling: Option<u64>,
}

fn run(
    hot: VolumeSpace,
    archive: ArchiveState,
    segments: &[StoredSegment],
    policy: Policy,
    ingested: u64,
    fed: Fed,
) -> Plan {
    plan(&PlanInput {
        hot,
        archive,
        segments,
        now: Timestamp::from_unix_millis(NOW),
        policy,
        ingested_bytes: ingested,
        rolling_budget: fed.budget,
        rolling_ceiling: fed.ceiling,
    })
    .unwrap()
}

fn hot_deleted(p: &Plan) -> Vec<SegmentId> {
    p.actions
        .iter()
        .filter_map(|a| match a {
            Action::Delete(id) => Some(*id),
            _ => None,
        })
        .collect()
}

/// A hot volume smaller than the (default, 2 GiB) emergency reserve, well above its 25 %
/// percentage floor, archive unavailable. Before #108 nothing was deleted (the floor holds);
/// the reserve-as-floor now makes the floor unreachable by construction, so every hot segment
/// is deleted on every tick although the reserve can never be met and nothing fills the volume.
#[test]
fn small_hot_volume_with_default_reserve_does_not_delete_all_video_when_well_above_its_floor() {
    let capacity = 1024 * MIB;
    let segs: Vec<StoredSegment> = (0..10)
        .map(|i| seg(i, 10 * MIB, i64::try_from(i).unwrap()))
        .collect();
    // 100 MiB of video, 924 MiB free: far above the 256 MiB floor, nothing foreign.
    let p = run(
        vol(capacity, capacity - 100 * MIB),
        ArchiveState::Unavailable,
        &segs,
        Policy {
            hot_max_age: DurationMs::from_millis(u64::MAX),
            ..Policy::default()
        },
        10 * MIB,
        Fed {
            budget: None,
            ceiling: None,
        },
    );
    let deleted = hot_deleted(&p);
    assert!(
        deleted.len() < segs.len(),
        "all {} hot segments deleted on a volume that is 90 % free: {p:?}",
        deleted.len()
    );
}

/// Same over ticks: the recorder writes one 10 MiB segment per tick; retention collapses to the
/// segment just written.
#[test]
fn small_hot_volume_keeps_more_than_one_tick_of_video_across_ticks() {
    let capacity = 1024 * MIB;
    let pol = Policy {
        hot_max_age: DurationMs::from_millis(u64::MAX),
        ..Policy::default()
    };
    let mut segs: Vec<StoredSegment> = Vec::new();
    let mut fed = Fed {
        budget: None,
        ceiling: None,
    };
    for tick in 0..50_u64 {
        segs.push(seg(tick, 10 * MIB, i64::try_from(tick).unwrap()));
        let hot: u64 = segs.iter().map(|s| s.bytes).sum();
        let p = run(
            vol(capacity, capacity - hot),
            ArchiveState::Unavailable,
            &segs,
            pol,
            10 * MIB,
            fed,
        );
        fed = Fed {
            budget: p.rolling_budget,
            ceiling: p.rolling_ceiling,
        };
        let gone = hot_deleted(&p);
        segs.retain(|s| !gone.contains(&s.id));
    }
    let held: u64 = segs.iter().map(|s| s.bytes).sum();
    // The 25 % floor allows ~758 MiB; even a reserve clamped to the 90 % maximum floor allows
    // ~92 MiB. Anything at or under one segment is total loss of retention.
    assert!(
        held > 10 * MIB,
        "only {} MiB of video kept on a 1 GiB volume with nothing else on it",
        held / MIB
    );
}

/// The reserve as a floor engages and frees space (the AC) but only to reserve + 1 pp: no more.
#[test]
fn zero_percent_floor_reserve_deletes_minimally() {
    let segs: Vec<StoredSegment> = (0..10)
        .map(|i| seg(i, 100, i64::try_from(i).unwrap()))
        .collect();
    // capacity 10_000, reserve 2_000, 1 pp = 100; video 1_000, free 500 (foreign 8_500).
    let p = run(
        vol(10_000, 500),
        ArchiveState::Unavailable,
        &segs,
        policy(0, 2_000),
        0,
        Fed {
            budget: None,
            ceiling: None,
        },
    );
    assert_ne!(p.hot, HotState::Ok, "{p:?}");
    // reachable 1_500 < reserve 2_000: everything goes (documented). Now a reachable reserve:
    let p = run(
        vol(10_000, 1_500),
        ArchiveState::Unavailable,
        &segs,
        policy(0, 2_000),
        0,
        Fed {
            budget: None,
            ceiling: None,
        },
    );
    assert_eq!(p.hot, HotState::Ok);
    // need 2_100 - 1_500 = 600 -> 6 segments, not more.
    assert_eq!(hot_deleted(&p).len(), 6, "{p:?}");
}

/// `HotState` is measured against max(percentage floor, reserve), independently computed.
#[test]
fn hot_state_is_measured_against_the_larger_of_floor_and_reserve() {
    for (cap, free, video, pct, reserve) in [
        (1000_u64, 100_u64, 50_u64, 0_u8, 151_u64),
        (1000, 100, 50, 0, 150),
        (1000, 100, 50, 10, 149),
        (1000, 0, 0, 0, 1),
        (1000, 0, 0, 0, 0),
        (1, 1, 0, 90, 2),
        (u64::MAX, u64::MAX, 0, 90, u64::MAX),
    ] {
        let segs: Vec<StoredSegment> = if video > 0 {
            vec![seg(1, video, 0)]
        } else {
            vec![]
        };
        let p = run(
            vol(cap, free),
            ArchiveState::Unavailable,
            &segs,
            policy(pct, reserve),
            0,
            Fed {
                budget: None,
                ceiling: None,
            },
        );
        let floor = u64::try_from(u128::from(cap) * u128::from(pct) / 100).unwrap();
        // The oracle uses the reserve capped at 90 % of capacity (ticket #108 ruling).
        let unsat = free + video < floor.max(effective_reserve_bytes(cap, reserve));
        assert_eq!(
            p.hot != HotState::Ok,
            unsat,
            "{cap} {free} {video} {pct} {reserve}: {p:?}"
        );
    }
}

/// Recovery: once a burst of foreign data is gone, the budget returns to its ceiling and then
/// stays put (no flapping) while the foreign data is steady.
#[test]
fn budget_is_stable_once_foreign_data_is_steady_after_a_burst() {
    const CAP: u64 = 10_000;
    const BASE_FOREIGN: u64 = 8_000; // floor 2_500 unreachable: reachable <= 2_000
    const RESERVE: u64 = 300;
    let pol = policy(25, RESERVE);
    let mut segs: Vec<StoredSegment> = (0..10)
        .map(|i| seg(i, 100, i64::try_from(i).unwrap()))
        .collect();
    let mut fed = Fed {
        budget: None,
        ceiling: None,
    };
    let mut next = 100_u64;
    let mut budgets = Vec::new();
    for tick in 0..80_u64 {
        let foreign = if (5..20).contains(&tick) {
            BASE_FOREIGN + 1_200
        } else {
            BASE_FOREIGN
        };
        let mut hot: u64 = segs.iter().map(|s| s.bytes).sum();
        let foreign = foreign.min(CAP - hot);
        let mut ingested = 0;
        if tick > 0 && CAP - foreign - hot >= 50 {
            segs.push(seg(next, 50, i64::try_from(next).unwrap()));
            next += 1;
            hot += 50;
            ingested = 50;
        }
        let free = CAP - foreign - hot;
        let p = run(
            vol(CAP, free),
            ArchiveState::Unavailable,
            &segs,
            pol,
            ingested,
            fed,
        );
        fed = Fed {
            budget: p.rolling_budget,
            ceiling: p.rolling_ceiling,
        };
        let gone = hot_deleted(&p);
        segs.retain(|s| !gone.contains(&s.id));
        let after_hot: u64 = segs.iter().map(|s| s.bytes).sum();
        let after_free = CAP - foreign - after_hot;
        assert!(
            after_hot == 0 || after_free >= RESERVE,
            "tick {tick}: free {after_free}"
        );
        assert!(fed.budget.unwrap() <= fed.ceiling.unwrap(), "tick {tick}");
        budgets.push(fed.budget.unwrap());
    }
    let ceiling = fed.ceiling.unwrap();
    assert_eq!(ceiling, 1_000, "the seed is the entry video");
    // Steady for the last 40 ticks: the budget is the ceiling and constant.
    assert!(budgets[40..].iter().all(|b| *b == ceiling), "{budgets:?}");
    let held: u64 = segs.iter().map(|s| s.bytes).sum();
    assert!(held + 50 >= ceiling, "buffer drained: {held}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// No drain, many ticks: foreign data fluctuates at random above a baseline that keeps the
    /// floor unreachable; after it returns to the baseline the buffer refills to its ceiling
    /// (bounded by what fits next to the reserve). Every tick: budget <= ceiling, the ceiling never
    /// changes while the buffer lasts, the reserve is free or no hot video is left, and each
    /// delete was needed (the plan deletes no segment once the budget and reserve are both met).
    #[test]
    fn rolling_buffer_never_drains_and_deletes_minimally_across_ticks(
        bursts in prop::collection::vec(0_u64..2_000, 1..30),
        seg_bytes in 10_u64..200,
        reserve in 0_u64..800,
        initial in 1_u64..20,
        settle in 40_usize..60,
    ) {
        const CAP: u64 = 10_000;
        const BASE: u64 = 8_000;
        let pol = policy(25, reserve);
        let mut segs: Vec<StoredSegment> = (0..initial).map(|i| seg(i, seg_bytes, i64::try_from(i).unwrap())).collect();
        let mut next = 1_000_u64;
        let mut fed = Fed { budget: None, ceiling: None };
        let mut first_ceiling = None;
        let foreign_seq: Vec<u64> = bursts.iter().map(|b| BASE + b).chain(std::iter::repeat_n(BASE, settle)).collect();
        for (tick, foreign) in foreign_seq.iter().copied().enumerate() {
            let mut hot: u64 = segs.iter().map(|s| s.bytes).sum();
            let foreign = foreign.min(CAP - hot); // foreign cannot exceed what is free
            let mut ingested = 0;
            if tick > 0 && CAP - foreign - hot >= seg_bytes {
                segs.push(seg(next, seg_bytes, i64::try_from(next).unwrap()));
                next += 1;
                hot += seg_bytes;
                ingested = seg_bytes;
            }
            let free = CAP - foreign - hot;
            let p = run(vol(CAP, free), ArchiveState::Unavailable, &segs, pol, ingested, fed);
            let deleted = hot_deleted(&p);
            // Minimality: before the last delete, budget or reserve was still unmet.
            if let (Some(b), Some(last)) = (p.rolling_budget, deleted.last()) {
                let last_bytes = segs.iter().find(|s| s.id == *last).unwrap().bytes;
                let gone: u64 = segs.iter().filter(|s| deleted.contains(&s.id)).map(|s| s.bytes).sum();
                let before_hot = hot - gone + last_bytes;
                let before_free = free + gone - last_bytes;
                // budget as the tick started (b may have ratcheted below it)
                let start = fed.budget.unwrap_or(hot - ingested);
                let start = start.min(fed.ceiling.unwrap_or(start));
                let room = (free + hot).saturating_sub(reserve);
                let start = start.max(fed.ceiling.unwrap_or(start).min(room));
                prop_assert!(before_hot > start || before_free < reserve,
                    "tick {}: needless delete (hot {} budget {} free {} reserve {}) b {}", tick, before_hot, start, before_free, reserve, b);
            }
            segs.retain(|s| !deleted.contains(&s.id));
            let after_hot: u64 = segs.iter().map(|s| s.bytes).sum();
            let after_free = CAP - foreign - after_hot;
            prop_assert!(after_hot == 0 || after_free >= reserve, "tick {}: free {} reserve {}", tick, after_free, reserve);
            prop_assert_eq!(p.rolling_budget.is_some(), p.rolling_ceiling.is_some());
            if let (Some(b), Some(c)) = (p.rolling_budget, p.rolling_ceiling) {
                prop_assert!(b <= c);
                match first_ceiling {
                    None => first_ceiling = Some(c),
                    Some(fc) => prop_assert_eq!(fc, c, "ceiling changed while the buffer lasts"),
                }
            }
            fed = Fed { budget: p.rolling_budget, ceiling: p.rolling_ceiling };
        }
        // Settled at the baseline: the buffer holds min(ceiling, 2_000 - reserve) less at most
        // one segment of granularity.
        if let Some(c) = fed.ceiling {
            let want = c.min((CAP - BASE).saturating_sub(reserve));
            let held: u64 = segs.iter().map(|s| s.bytes).sum();
            prop_assert!(held + seg_bytes >= want, "drained: held {} want {} (ceiling {}, reserve {})", held, want, c, reserve);
            prop_assert!(held <= want.max(c.min(held)), "over the ceiling");
        }
    }
}
