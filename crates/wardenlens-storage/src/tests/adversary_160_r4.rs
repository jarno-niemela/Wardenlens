//! Adversary for ticket #160, round 4: the per-tier paging cursor, its reset, and the fall-through
//! from a "blocked" archive pass to hot rows (the only copy of recent video).

use wardenlens_core::storage::{SegmentId, SegmentIndex, Tier};

use super::fault::{Fault, Op};
use super::matrix::build;
use super::support::{Env, now};
use crate::Storage;

fn rows(env: &Env) -> (u64, u64) {
    let t = env.index.bytes_by_tier().unwrap();
    (t.hot.segments, t.archive.segments)
}

fn pin(path: &std::path::Path) {
    std::fs::remove_file(path).unwrap();
    std::fs::create_dir(path).unwrap();
    std::fs::write(path.join("x"), b"x").unwrap();
}

/// `stuck` pinned oldest archive rows, then `free` deletable archive rows, 5 hot rows; cap at
/// the starting total, one hot row ingested per tick for `ticks` ticks. Returns the hot rows the
/// cap deleted and the archive rows left.
fn stuck_archive_sim(bound: usize, stuck: i64, free: i64, ticks: i64) -> (Vec<SegmentId>, u64) {
    let env = Env::new();
    for n in 0..stuck {
        env.add("cam-2", n, 1000, Tier::Archive);
        pin(&env.arch_file("cam-2", n));
    }
    for n in stuck..stuck + free {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let mut hot: Vec<_> = (0..5)
        .map(|n| env.add("cam-1", 1000 + n, 1000, Tier::Hot))
        .collect();
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = bound;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    let (h, a) = rows(&env);
    lp.set_max_rows(usize::try_from(h + a).unwrap());
    for t in 0..ticks {
        hot.push(env.add("cam-1", 1100 + t, 1000, Tier::Hot));
        lp.tick(now()).unwrap();
    }
    let lost = hot
        .into_iter()
        .filter(|id| env.tier_of(*id).is_none())
        .collect();
    (lost, rows(&env).1)
}

/// Baseline: nothing pinned, the cap takes only archive rows.
#[test]
fn baseline_without_stuck_rows_the_cap_never_deletes_hot_video() {
    let (lost, archive_left) = stuck_archive_sim(2, 0, 40, 20);
    assert!(
        lost.is_empty(),
        "hot rows lost {lost:?}; archive left {archive_left}"
    );
}

/// As many stuck oldest archive rows as the cap's bound, many deletable archive rows behind
/// them. The archive is available and can always supply the excess (one row a tick), yet a pass
/// that spends its bound on the stuck rows counts as "blocked" and the excess is taken from the
/// hot tier: the only copy of recent video goes while older deletable archive video is kept.
/// The cursor reset on each clean tick sends the next pass back to the stuck rows, so this
/// recurs for good.
#[test]
fn stuck_archive_rows_never_make_the_cap_delete_hot_video_while_deletable_archive_rows_remain() {
    let (lost, archive_left) = stuck_archive_sim(2, 2, 40, 20);
    assert!(
        lost.is_empty(),
        "{} hot rows deleted by the row cap over 20 ticks while {archive_left} archive rows \
         (of which {} deletable) were kept: {lost:?}",
        lost.len(),
        archive_left - 2
    );
}

/// Same at the default bound (64): one camera whose 64 oldest archive files cannot be unlinked
/// (a directory planted over each; in the field, a permissions mistake on one camera folder).
#[test]
fn a_block_of_stuck_archive_rows_at_the_default_bound_never_costs_hot_video() {
    let (lost, archive_left) = stuck_archive_sim(64, 64, 100, 20);
    assert!(
        lost.is_empty(),
        "{} hot rows deleted by the row cap over 20 ticks while {archive_left} archive rows \
         (of which {} deletable) were kept",
        lost.len(),
        archive_left - 64
    );
}

/// Every archive row is undeletable for one tick (a directory over each file stands in for a
/// burst of archive unlink errors, e.g. a USB/NAS hiccup), then the fault is gone. The cap is
/// retention, not safety: the excess can wait a tick. It must not delete hot video because the
/// archive was briefly unwritable.
#[test]
fn a_one_tick_archive_unlink_burst_does_not_make_the_cap_delete_hot_video() {
    let env = Env::new();
    for n in 0..10 {
        env.add("cam-2", n, 1000, Tier::Archive);
        pin(&env.arch_file("cam-2", n));
    }
    let hot: Vec<_> = (0..5)
        .map(|n| env.add("cam-1", 1000 + n, 1000, Tier::Hot))
        .collect();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(12);
    let r = lp.tick(now()).unwrap();
    let lost: Vec<_> = hot
        .iter()
        .filter(|id| env.tier_of(**id).is_none())
        .collect();
    assert!(
        lost.is_empty(),
        "hot rows {lost:?} deleted because archive unlinks failed for one tick: {r:?}"
    );
    for n in 0..10 {
        let p = env.arch_file("cam-2", n);
        std::fs::remove_dir_all(&p).unwrap();
        std::fs::write(&p, super::support::pattern(1000)).unwrap();
    }
    // And the archive catches up once the fault is gone.
    let r = lp.tick(now()).unwrap();
    let (h, a) = rows(&env);
    assert_eq!(h + a, 12, "{r:?}");
}

/// Liveness: interleaved stuck rows (one of every three archive rows), ingest every tick, many
/// ticks. The total converges to the cap plus at most the stuck rows, and the cap never deletes
/// more than the excess in a tick.
#[test]
fn interleaved_stuck_rows_converge_and_the_cap_never_deletes_more_than_the_excess() {
    let env = Env::new();
    let mut stuck = 0;
    for n in 0..30 {
        env.add("cam-2", n, 1000, Tier::Archive);
        if n % 3 == 0 {
            pin(&env.arch_file("cam-2", n));
            stuck += 1;
        }
    }
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = 2;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(20);
    for t in 0..60 {
        env.add("cam-1", 1000 + t, 1000, Tier::Hot);
        let (h0, a0) = rows(&env);
        let before = h0 + a0;
        let r = lp.tick(now()).unwrap();
        let excess = before.saturating_sub(20);
        assert!(
            u64::from(r.rows_evicted_over_cap) <= excess,
            "tick {t}: evicted {} with excess {excess}: {r:?}",
            r.rows_evicted_over_cap
        );
    }
    let (h, a) = rows(&env);
    assert!(
        h + a <= 20 + stuck,
        "rows {} after 60 ticks: hot {h} archive {a}",
        h + a
    );
}

/// A transient failure on the oldest row with a cap that is never quite caught up and a fault
/// on another row every tick (so the cursor is never reset by a clean tick): the oldest row is
/// still retried when the cursor wraps.
#[test]
fn a_transient_failure_is_retried_after_the_wrap_even_when_no_tick_is_clean() {
    let env = Env::new();
    let first = env.add("cam-2", 0, 1000, Tier::Archive);
    for n in 1..4 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    // A permanently stuck newer row keeps every pass that reaches it failing.
    env.add("cam-2", 50, 1000, Tier::Archive);
    pin(&env.arch_file("cam-2", 50));
    let fault = Fault {
        errno: rustix::io::Errno::IO,
        ..Fault::once(Op::Unlink(Tier::Archive), 1)
    };
    let (mut lp, _) = build(&env, Some(fault));
    lp.set_max_rows(4);
    for t in 0..40 {
        env.add("cam-2", 100 + t, 1000, Tier::Archive);
        lp.tick(now()).unwrap();
    }
    assert_eq!(
        env.tier_of(first),
        None,
        "transiently failed oldest row survives 40 ticks"
    );
}

/// The archive holds the cap's worth of rows and none can be deleted (in the field: archive
/// folders restored or copied with the wrong owner, so unlink gets EACCES, or a failing archive
/// disk returning EIO; a read-only mount probes as unavailable and is not this case). Every new hot
/// segment then takes the total over the cap and is deleted by the cap on the next tick: the
/// recorder keeps no new video at all, though nothing is short of space.
#[test]
fn an_undeletable_archive_at_the_cap_does_not_make_the_cap_delete_every_new_recording() {
    let env = Env::new();
    for n in 0..10 {
        env.add("cam-2", n, 1000, Tier::Archive);
        pin(&env.arch_file("cam-2", n));
    }
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = 4;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(10);
    let mut recorded = Vec::new();
    let mut last = String::new();
    for t in 0..10 {
        recorded.push(env.add("cam-1", 1000 + t, 1000, Tier::Hot));
        last = format!("{:?}", lp.tick(now()).unwrap());
    }
    let kept = recorded
        .iter()
        .filter(|id| env.tier_of(**id).is_some())
        .count();
    assert!(
        kept > 0,
        "all {} new recordings deleted by the row cap within a tick of being written: {last}",
        recorded.len()
    );
}
