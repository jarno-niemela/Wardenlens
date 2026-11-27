//! Adversarial tests for ticket #108 round 4 (PR #192): the reachability switch of the reserve
//! over many ticks, swept across the amount of foreign data on the hot volume.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code; failures should panic"
)]

use wardenlens_core::storage::{
    Action, ArchiveState, Plan, PlanInput, Policy, SegmentId, StoredSegment, Tier, VolumeSpace,
    plan,
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

/// Monotonicity: more non-video data on the hot volume never lets it keep more video. With the
/// reachability switch it does: on a 1 GiB volume (default policy, capped reserve ~921.6 MiB,
/// archive away) 95 MiB of foreign data keeps under one 10 MiB segment (the reserve is reachable
/// only by deleting almost all video), while 110 MiB keeps hundreds of MiB (the reserve is ignored
/// and the 25 % floor applies). The same cliff sits at `free + video == reserve` on any volume.
#[test]
#[ignore = "#194: reachability cliff"]
fn more_foreign_data_never_lets_the_hot_volume_keep_more_video() {
    let mut prev: Option<(u64, u64)> = None;
    for foreign_mib in [0_u64, 50, 90, 95, 100, 105, 110, 150, 300, 600] {
        let held = simulate_hot_only(GIB, foreign_mib * MIB, 10 * MIB, default_policy());
        if let Some((pf, ph)) = prev {
            assert!(
                held <= ph,
                "{foreign_mib} MiB foreign keeps {} MiB of video, {pf} MiB foreign kept only {} MiB",
                held / MIB,
                ph / MIB
            );
        }
        prev = Some((foreign_mib, held));
    }
}

/// The round-2 invariant ("a 1 GiB hot volume with some foreign data keeps more than one tick of
/// video") at 95 MiB of foreign data instead of 150 MiB.
#[test]
#[ignore = "#194: reachability cliff"]
fn small_hot_volume_with_95_mib_of_foreign_data_keeps_more_than_one_tick_of_video() {
    let held = simulate_hot_only(GIB, 95 * MIB, 10 * MIB, default_policy());
    assert!(
        held > 10 * MIB,
        "only {} MiB of video kept on a 1 GiB volume with 95 MiB of other data",
        held / MIB
    );
}
