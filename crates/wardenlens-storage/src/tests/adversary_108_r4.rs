//! Adversarial tests for ticket #108 round 4 (PR #192): the round-4 adapter fixes (eviction
//! figures, status on a failed row read, the truncated-index alert suppression) each pinned by a
//! test that fails when the fix is reverted.

use wardenlens_core::storage::{MinFreePercent, Tier};

use super::support::{Env, now, pattern};
use crate::{ARCHIVE_MARKER, Storage};

const CAP: u64 = 100_000;

fn quarantine_file(env: &Env, n: u32, bytes: usize) {
    let q = env
        .hot
        .join(format!("_quarantine/cam-1/2023-11-12/{n:06}-000.mp4"));
    std::fs::create_dir_all(q.parent().unwrap()).unwrap();
    std::fs::write(&q, pattern(bytes)).unwrap();
}

fn set_foreign(env: &Env, bytes: usize) {
    std::fs::write(env.hot.join("foreign"), vec![0_u8; bytes]).unwrap();
}

fn hot_loop(
    env: &Env,
    pct: u8,
    reserve: u64,
) -> crate::StorageLoop<super::support::TestIndex, crate::RealFs, super::support::FakeUsage> {
    let mut cfg = env.cfg();
    cfg.policy.hot_min_free = MinFreePercent::new(pct).unwrap();
    cfg.policy.emergency_reserve_bytes = reserve;
    Storage::open(cfg, env.index.clone(), env.usage.clone())
        .unwrap()
        .0
}

/// Round-4 fix "`evict::select` passes video only to `hot_floor`": the reserve (310 000) is reachable
/// only if the quarantine is counted (free 200 000 + video 40 000 < 310 000 <= + quarantine
/// 81 920). The hot floor is then the 25 % floor (250 000, target 260 000): about 15 of the 20
/// quarantined 4 KiB files restore it, and free + video stays below the reserve afterwards.
/// Counting the quarantine toward the reserve raised the goal to the reserve target (320 000) and
/// evicted all twenty (evidence lost for a reserve the volume cannot reach). The selection sizes
/// files by their allocated blocks, so the test only asserts that some quarantine survives.
#[test]
fn quarantine_eviction_stops_at_the_percentage_target_when_only_the_quarantine_reaches_the_reserve()
{
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..4 {
        env.add("cam-1", n, 10_000, Tier::Hot);
    }
    for n in 0..20 {
        quarantine_file(&env, n, 4_096);
    }
    set_foreign(&env, 678_080);
    let mut lp = hot_loop(&env, 25, 310_000);
    let r = lp.tick(now()).unwrap();
    assert!(r.quarantine_evicted > 0, "{r:?}");
    assert_eq!((r.moved, r.deleted), (0, 0), "{r:?}");
    assert!(
        !Env::quarantined(&env.hot).is_empty(),
        "the whole quarantine was evicted for an unreachable reserve: {r:?}"
    );
    assert!(r.hot_alert, "the unreachable reserve alerts: {r:?}");
}

/// Round-4 fix "on a `read_rows` failure the status uses 0 hot bytes": free 20 000 + video 40 000
/// reaches the 50 000 reserve, so with good rows the volume is below its floor. When the index
/// totals cannot be read, the status (like the breach counter) counts 0 hot bytes: the reserve
/// is out of the floor (0 %) and the volume is not below it. Keeping the older read said "below".
#[test]
fn status_after_a_failed_totals_read_uses_zero_hot_bytes_not_the_previous_read() {
    let env = Env::new();
    env.set_cap("hot", CAP);
    for n in 0..4 {
        env.add("cam-1", n, 10_000, Tier::Hot);
    }
    let mut lp = hot_loop(&env, 0, 50_000);
    lp.tick(now()).unwrap();
    assert!(!lp.snapshot().hot.volume.unwrap().below_floor());
    // Foreign data arrives; then the totals read fails for the next tick.
    set_foreign(&env, 40_000);
    {
        // `oldest` too, so the failed tick plans and moves nothing.
        let mut f = env.index.faults.lock().unwrap();
        f.totals = true;
        f.oldest = true;
    }
    let _ = lp.tick(now());
    let snap = lp.snapshot();
    assert!(
        !snap.hot.volume.unwrap().below_floor(),
        "status used stale hot bytes: {snap:?}"
    );
    assert_eq!(snap.floor_breaches_total, 0, "{snap:?}");
}

/// The status and the breach counter of one tick judge the same probe by the same rule. With
/// `oldest` failing (but `totals` readable) the breach counter sees the 40 000 bytes of video and
/// counts a reserve breach, while the status uses 0 hot bytes and says "not below".
#[test]
fn status_and_breach_counter_agree_when_only_the_row_listing_fails() {
    let env = Env::new();
    env.set_cap("hot", CAP);
    for n in 0..4 {
        env.add("cam-1", n, 10_000, Tier::Hot);
    }
    let mut lp = hot_loop(&env, 0, 50_000);
    lp.tick(now()).unwrap();
    set_foreign(&env, 40_000);
    env.index.faults.lock().unwrap().oldest = true;
    let _ = lp.tick(now());
    let snap = lp.snapshot();
    assert_eq!(
        snap.hot.volume.unwrap().below_floor(),
        snap.floor_breaches_total == 1,
        "status and breach counter disagree on the same tick: {snap:?}"
    );
}

/// Round-4 fix "the `reserve_floor_unreachable` alert is suppressed when the hot index is
/// truncated": 10 hot rows of 4 000 bytes (40 000) plus 20 000 free reach the 50 000 reserve, but
/// a 3-row prefix (12 000) does not. The flag from the prefix is wrong; no alert with the archive
/// available.
#[test]
fn a_truncated_hot_prefix_does_not_raise_a_false_reserve_alert() {
    let env = Env::new();
    env.set_cap("hot", CAP);
    for n in 0..10 {
        env.add("cam-1", n, 4_000, Tier::Hot);
    }
    set_foreign(&env, 40_000);
    let mut lp = hot_loop(&env, 0, 50_000);
    lp.set_max_segments(3);
    let r = lp.tick(now()).unwrap();
    assert!(r.segments_truncated, "{r:?}");
    assert!(!r.hot_alert, "{r:?}");
}

/// The other side of the suppression: the reserve is unreachable by the true totals too (free
/// 5 000 + video 40 000 < 50 000), which the loop can read (`totals`), yet a truncated hot prefix
/// suppresses the alert with the archive available.
#[test]
fn a_truncated_hot_prefix_still_alerts_when_the_true_totals_cannot_reach_the_reserve() {
    let env = Env::new();
    env.set_cap("hot", CAP);
    for n in 0..10 {
        env.add("cam-1", n, 4_000, Tier::Hot);
    }
    set_foreign(&env, 55_000);
    let mut lp = hot_loop(&env, 0, 50_000);
    lp.set_max_segments(3);
    let r = lp.tick(now()).unwrap();
    assert!(r.segments_truncated, "{r:?}");
    assert!(
        r.hot_alert,
        "a real unreachable reserve is not alerted: {r:?}"
    );
}

/// Outside the rolling buffer nothing is deleted or moved for an unreachable reserve, through the
/// whole loop and over many ticks with a recorder adding video: the percentage floor (25 %) is
/// reachable, the reserve (60 000) is not (free + video stays at 50 000), the archive is away.
#[test]
fn an_unreachable_reserve_never_deletes_through_the_loop_over_many_ticks() {
    let env = Env::new();
    env.set_cap("hot", CAP);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    set_foreign(&env, 50_000);
    let mut lp = hot_loop(&env, 25, 60_000);
    let mut deleted = 0;
    // Ten ticks of 2 000 bytes each: video 20 000, free 30 000 >= 25 000 floor throughout.
    for n in 0..10 {
        env.add("cam-1", n, 2_000, Tier::Hot);
        let r = lp.tick(now()).unwrap();
        deleted += r.deleted;
        assert!(r.hot_alert, "tick {n}: {r:?}");
        assert_ne!(
            r.hot,
            Some(wardenlens_core::storage::HotState::RollingBuffer),
            "tick {n}: {r:?}"
        );
    }
    assert_eq!(deleted, 0);
}
