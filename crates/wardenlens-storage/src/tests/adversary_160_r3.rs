//! Adversary for ticket #160, round 3: the bounded memory of failed cap deletes, its liveness,
//! the degrade path over many ticks.

use wardenlens_core::storage::{SegmentIndex, Tier};

use super::fault::{Fault, Op};
use super::matrix::build;
use super::support::{Env, now};
use crate::{ARCHIVE_MARKER, Storage};

fn rows(env: &Env) -> (u64, u64) {
    let t = env.index.bytes_by_tier().unwrap();
    (t.hot.segments, t.archive.segments)
}

fn pin(path: &std::path::Path) {
    std::fs::remove_file(path).unwrap();
    std::fs::create_dir(path).unwrap();
    std::fs::write(path.join("x"), b"x").unwrap();
}

/// More undeletable oldest rows than the memory holds (4 x the action bound): the memory churns,
/// every forgotten row is retried and fails again, and the cap spends its whole bound on them.
/// The deletable rows behind them must still be evicted.
#[test]
fn more_pinned_rows_than_the_memory_holds_do_not_disable_the_row_cap() {
    let env = Env::new();
    // max_actions 1: memory of 4. Five pinned oldest archive rows, then deletable rows.
    for n in 0..5 {
        env.add("cam-2", n, 1000, Tier::Archive);
        pin(&env.arch_file("cam-2", n));
    }
    for n in 5..10 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = 1;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(10);
    let mut last = String::new();
    for t in 0..40 {
        env.add("cam-1", 100 + t, 1000, Tier::Hot);
        last = format!("{:?}", lp.tick(now()).unwrap());
    }
    let (h, a) = rows(&env);
    // Cap 10 plus at most the 5 rows that can never go.
    assert!(
        h + a <= 15,
        "rows {} (hot {h}, archive {a}) after 40 ticks with ingest 1/tick, cap 10, 5 pinned: {last}",
        h + a
    );
}

/// Same with the default action bound (64, memory 256): 400 undeletable oldest rows (a few hours
/// of one camera whose files cannot be unlinked) stop the cap for good.
#[test]
fn a_camera_day_of_pinned_rows_does_not_disable_the_row_cap_at_the_default_bound() {
    let env = Env::new();
    for n in 0..400 {
        env.row("cam-2", n, 1000, Tier::Archive);
        // A directory where the file should be: unlink fails with EISDIR.
        let p = env.arch_file("cam-2", n);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("x"), b"x").unwrap();
    }
    for n in 400..410 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(410);
    let mut evicted = 0;
    for t in 0..30 {
        env.add("cam-1", 1000 + t, 1000, Tier::Hot);
        evicted += lp.tick(now()).unwrap().rows_evicted_over_cap;
    }
    let (h, a) = rows(&env);
    assert!(
        h + a <= 410,
        "rows {} (hot {h}, archive {a}), cap 410 with 400 pinned; evicted {evicted} in 30 ticks",
        h + a
    );
}

/// A failure that has gone (one transient EIO): the remembered row is the oldest and should be
/// "retried again once in a while" (the rustdoc of `remember_cap_failure`). Without further
/// failures it is never retried: it outlives every newer row the cap evicts.
#[test]
fn a_transiently_failed_cap_row_is_retried_once_the_fault_has_gone() {
    let env = Env::new();
    let first = env.add("cam-2", 0, 1000, Tier::Archive);
    for n in 1..5 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let fault = Fault {
        errno: rustix::io::Errno::IO,
        ..Fault::once(Op::Unlink(Tier::Archive), 1)
    };
    let (mut lp, _) = build(&env, Some(fault));
    lp.set_max_rows(4);
    let r = lp.tick(now()).unwrap();
    assert!(r.cap_delete_failed, "{r:?}");
    for t in 0..50 {
        env.add("cam-2", 100 + t, 1000, Tier::Archive);
        lp.tick(now()).unwrap();
    }
    assert_eq!(
        env.tier_of(first),
        None,
        "the oldest row, whose one delete failed transiently, survives 50 ticks of cap evictions \
         of newer rows"
    );
}

/// The archive goes away in the middle of the cap's archive pass: every following archive row is
/// skipped (`ArchiveUnavailable`), not a failed delete. Those healthy rows must not be remembered
/// as stuck: once the archive is back the cap evicts oldest first again.
#[test]
fn rows_skipped_because_the_archive_went_away_are_not_remembered_as_stuck() {
    let env = Env::new();
    let ids: Vec<_> = (0..8)
        .map(|n| env.add("cam-2", n, 1000, Tier::Archive))
        .collect();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(2);
    let marker = env.arch.join(ARCHIVE_MARKER);
    let m2 = marker.clone();
    env.index.faults.lock().unwrap().get_hook = Some(Box::new(move || {
        std::fs::remove_file(&m2).unwrap();
    }));
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.rows_evicted_over_cap, 1, "{r:?}");
    assert_eq!(env.tier_of(ids[0]), None);
    let flagged_while_offline = r.cap_delete_failed;
    std::fs::write(&marker, b"").unwrap();
    // Archive back.
    let r2 = lp.tick(now()).unwrap();
    let r3 = lp.tick(now()).unwrap();
    // 7 rows, cap 2: the oldest five go, so ids[1] (the oldest left) must go.
    assert_eq!(
        env.tier_of(ids[1]),
        None,
        "healthy oldest row kept while newer ones went; remembered {} (flag while offline: \
         {flagged_while_offline}): {r2:?} {r3:?}",
        lp.cap_failed_len()
    );
    assert!(!r3.cap_delete_failed, "no row is stuck: {r3:?}");
}

/// Degrade path over many ticks, alternating: totals readable on even ticks, failing on odd
/// ones. The hot free space never drops below the reserve, and no archive row is touched on a
/// degraded tick.
#[test]
fn alternating_degraded_ticks_keep_the_reserve_and_never_touch_the_archive_when_degraded() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..10 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    for n in 20..27 {
        env.add("cam-1", n, 95_000, Tier::Hot);
    }
    let mut cfg = env.cfg();
    cfg.policy.emergency_reserve_bytes = 100_000;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    for t in 0..30_i64 {
        let degraded = t % 2 == 1;
        env.add("cam-1", 100 + t, 40_000, Tier::Hot);
        env.index.faults.lock().unwrap().totals = false;
        let (_, a0) = rows(&env);
        env.index.faults.lock().unwrap().totals = degraded;
        let r = lp.tick(now()).unwrap();
        env.index.faults.lock().unwrap().totals = false;
        let (_, a) = rows(&env);
        if degraded {
            assert_eq!(r.moved, 0, "tick {t}: {r:?}");
            assert!(a <= a0, "tick {t}: {r:?}");
            assert_eq!(a, a0, "tick {t}: degraded tick touched archive rows: {r:?}");
        }
        let free = 1_000_000 - super::support::du(&env.hot);
        assert!(free >= 100_000, "tick {t}: hot free {free}: {r:?}");
    }
}

/// Archive offline, hot rows pinned, action bound 1 (memory 4). Returns the lowest hot free space
/// once foreign data puts the hot volume in the rolling buffer.
fn pinned_hot_rolling(pinned: i64) -> (u64, String) {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    for n in 0..8 {
        env.add("cam-1", n, 10_000, Tier::Hot);
    }
    for n in 0..pinned {
        pin(&env.hot_file("cam-1", n));
    }
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = 1;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(8);
    lp.set_max_segments(8);
    let mut n = 100;
    for _ in 0..10 {
        env.add("cam-1", n, 10_000, Tier::Hot);
        n += 1;
        lp.tick(now()).unwrap();
    }
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 750_000]).unwrap();
    let mut lowest = u64::MAX;
    let mut last = String::new();
    for _ in 0..20 {
        env.add("cam-1", n, 10_000, Tier::Hot);
        n += 1;
        last = format!("{:?}", lp.tick(now()).unwrap());
        lowest = lowest.min(1_000_000_u64.saturating_sub(super::support::du(&env.hot)));
    }
    let (h, _) = rows(&env);
    (lowest, format!("hot rows {h}: {last}"))
}

/// Five pinned hot rows, one more than the memory holds: the hot cap stalls, the hot tier grows
/// past the per-tier load cap, the plan is made from a truncated prefix and deletes nothing.
/// The hot volume must not fill up.
#[test]
fn more_pinned_hot_rows_than_the_memory_holds_never_lead_to_a_full_hot_volume() {
    let (lowest, last) = pinned_hot_rolling(5);
    assert!(lowest >= 50_000, "lowest hot free {lowest}, {last}");
}

/// Baseline: four pinned hot rows (exactly what the memory holds), same load.
#[test]
fn baseline_as_many_pinned_hot_rows_as_the_memory_holds_keep_hot_free_space() {
    let (lowest, last) = pinned_hot_rolling(4);
    assert!(lowest >= 50_000, "lowest hot free {lowest}, {last}");
}

/// Baseline: nothing pinned, same load.
#[test]
fn baseline_unpinned_hot_rows_keep_hot_free_space_with_an_action_bound_of_one() {
    let (lowest, last) = pinned_hot_rolling(0);
    assert!(lowest >= 50_000, "lowest hot free {lowest}, {last}");
}
