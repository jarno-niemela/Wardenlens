//! Adversary for ticket #59, round 3: the degraded hold, the own-floor evictions that are now
//! executed directly, the reserve-as-floor rule and the pass back-off.

use wardenlens_core::storage::Tier;
use wardenlens_core::time::Timestamp;

use super::support::{Env, T0, du};
use crate::{ARCHIVE_MARKER, Storage};

fn late() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 48 * 3_600_000)
}

/// Archive below its own floor by more than its visible (capped) prefix: the `archive_only` plan
/// evicts the stand-in for the unseen rows too. The stand-in's id is `max loaded id + 1`, which
/// can be a real row that was not loaded. Round 3 executes the own-floor plan's deletes as is
/// (no `by_id` filter), so the stand-in id must still never be executed.
fn standin_setup(
    env: &Env,
) -> (
    Vec<wardenlens_core::storage::SegmentId>,
    wardenlens_core::storage::SegmentId,
) {
    env.set_cap("arch", 1_000_000);
    // Archive: 3 tiny oldest rows (the visible prefix), 7 big newer ones (unseen).
    for n in 0..3 {
        env.add("cam-2", n, 1_000, Tier::Archive);
    }
    for n in 3..10 {
        env.add("cam-2", n, 120_000, Tier::Archive);
    }
    // Hot: 3 rows loaded (ids 11..13); the stand-in will be id 14.
    let hot: Vec<_> = (20..23)
        .map(|n| env.add("cam-1", n, 1_000, Tier::Hot))
        .collect();
    // The newest recording, a real hot row with the stand-in's id, beyond the loaded prefix.
    let newest = env.add("cam-1", 23, 1_000, Tier::Hot);
    (hot, newest)
}

#[test]
fn the_unseen_archive_stand_in_is_never_executed_without_a_hold() {
    let env = Env::new();
    let (_, newest) = standin_setup(&env);
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    let r = lp.tick(late()).unwrap();
    assert_eq!(env.tier_of(newest), Some(Tier::Hot), "{r:?}");
    assert!(env.hot_file("cam-1", 23).exists(), "{r:?}");
}

#[test]
fn the_unseen_archive_stand_in_is_never_executed_while_the_archive_returned_hold_is_set() {
    let env = Env::new();
    let (_, newest) = standin_setup(&env);
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    // The archive is seen returning on the first probe: the hold is set for this tick.
    lp.set_initial_archive_state(false);
    let r = lp.tick(late()).unwrap();
    assert!(r.archive_returned || r.returned.is_some(), "{r:?}");
    assert_eq!(
        env.tier_of(newest),
        Some(Tier::Hot),
        "the newest hot recording (id = stand-in id) was deleted by the held own-floor plan: {r:?}"
    );
    assert!(env.hot_file("cam-1", 23).exists(), "{r:?}");
}

/// Hot free bytes now.
fn hot_free(env: &Env) -> u64 {
    1_000_000_u64.saturating_sub(du(&env.hot))
}

/// A hold whose pass never finishes (walk cap of 1), with a recorder writing every tick: after
/// the first held tick the hot floor holds on every tick (never ENOSPC), for many ticks, through
/// several back-off periods, and no move runs.
fn held_forever(reserve: u64, ticks: i64) -> (Vec<u64>, u32, u32) {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..10 {
        env.add("cam-1", n, 60_000, Tier::Hot);
    }
    for n in 0..3 {
        env.add("cam-2", n, 1_000, Tier::Archive);
    }
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    let mut cfg = env.cfg().with_walk_max_entries(1);
    cfg.policy.emergency_reserve_bytes = reserve;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_initial_archive_state(false);
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    let mut frees = Vec::new();
    let (mut moved, mut deleted) = (0, 0);
    for t in 0..ticks {
        env.add("cam-1", 100 + t, 40_000, Tier::Hot);
        let r = lp.tick(late()).unwrap();
        assert!(r.archive_returned, "tick {t}: {r:?}");
        moved += r.moved;
        deleted += r.deleted;
        frees.push(hot_free(&env));
    }
    (frees, moved, deleted)
}

#[test]
fn an_unfinished_hold_keeps_the_hot_floor_on_every_tick_over_many_back_off_periods() {
    let (frees, moved, _) = held_forever(0, 80);
    assert_eq!(moved, 0);
    for (t, f) in frees.iter().enumerate().skip(1) {
        assert!(
            *f >= 250_000,
            "tick {t}: hot free {f} below the 25% floor: {frees:?}"
        );
    }
}

/// Minimality: with the reserve below the floor the held plan deletes no more than the floor's
/// target needs (26%) plus one segment, on every tick.
#[test]
fn an_unfinished_hold_with_a_small_reserve_deletes_only_to_the_floor_target() {
    let (frees, _, _) = held_forever(100_000, 60);
    for (t, f) in frees.iter().enumerate().skip(1) {
        assert!(
            *f <= 260_000 + 60_000,
            "tick {t}: hot free {f} over-deleted: {frees:?}"
        );
    }
}

/// Reserve above the floor (35% of the hot capacity): it is kept on every held tick after the
/// first, and the deletes stop near it (rounded-up whole percent plus the one-percent target
/// step, plus one segment).
#[test]
fn an_unfinished_hold_keeps_a_reserve_above_the_floor_without_draining_the_hot_tier() {
    let (frees, _, _) = held_forever(350_000, 60);
    for (t, f) in frees.iter().enumerate().skip(1) {
        assert!(
            *f >= 350_000,
            "tick {t}: hot free {f} below the reserve: {frees:?}"
        );
        assert!(
            *f < 360_000 + 60_000,
            "tick {t}: hot free {f} over-deleted: {frees:?}"
        );
    }
}

/// Once the pass finishes, the hold ends, the reserve-as-floor rule is gone (plain policy: the
/// hot side is relieved by moves, not deletes) and the hot tier is not drained further.
#[test]
fn after_the_fault_clears_the_hold_ends_and_moves_replace_the_held_deletes() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..10 {
        env.add("cam-1", n, 60_000, Tier::Hot);
    }
    for n in 0..3 {
        env.add("cam-2", n, 1_000, Tier::Archive);
    }
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    let mut cfg = env.cfg();
    cfg.policy.emergency_reserve_bytes = 350_000;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_initial_archive_state(false);
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    env.index.faults.lock().unwrap().list = true;
    for t in 0..25 {
        env.add("cam-1", 100 + t, 40_000, Tier::Hot);
        lp.tick(late()).unwrap();
    }
    assert!(lp.returned_pass_unfinished());
    env.index.faults.lock().unwrap().list = false;
    let mut ended = None;
    for t in 25..60 {
        env.add("cam-1", 100 + t, 40_000, Tier::Hot);
        let r = lp.tick(late()).unwrap();
        if !r.archive_returned && ended.is_none() {
            ended = Some(t);
        }
        if let Some(e) = ended
            && t > e
        {
            assert_eq!(
                r.deleted, 0,
                "tick {t}: hot video deleted after the hold ended: {r:?}"
            );
        }
    }
    let e = ended.expect("the hold ends once the fault has cleared");
    assert!(e <= 25 + 17, "the hold ended at tick {e}");
    assert!(!lp.returned_pass_unfinished());
}
