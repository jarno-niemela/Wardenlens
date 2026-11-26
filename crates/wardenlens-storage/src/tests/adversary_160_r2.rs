//! Adversary for ticket #160, round 2: the cap after the plan, the degrade path, the dropped
//! moves and multi-tick behaviour.

use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::Timestamp;

use super::support::{Env, T0, now};
use crate::{ARCHIVE_MARKER, ArchiveProbe, Storage};

fn rows(env: &Env) -> (u64, u64) {
    let t = env.index.bytes_by_tier().unwrap();
    (t.hot.segments, t.archive.segments)
}

fn late() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 48 * 3_600_000)
}

/// A directory planted where the oldest archive segment's file should be: `unlink` gives
/// `EISDIR`, so that one row can never be deleted. The cap must still hold the other rows.
#[test]
fn one_undeletable_oldest_row_does_not_disable_the_row_cap_for_good() {
    let env = Env::new();
    for n in 0..6 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let pinned = env.arch_file("cam-2", 0);
    std::fs::remove_file(&pinned).unwrap();
    std::fs::create_dir(&pinned).unwrap();
    std::fs::write(pinned.join("x"), b"x").unwrap();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(6);
    let mut last = String::new();
    for t in 0..20 {
        env.add("cam-1", 100 + t, 1000, Tier::Hot);
        last = format!("{:?}", lp.tick(now()).unwrap());
    }
    let (h, a) = rows(&env);
    assert!(
        h + a <= 7,
        "rows {} (hot {h}, archive {a}) over a cap of 6 after 20 ticks, one pinned row: {last}",
        h + a
    );
}

/// Same with the archive offline: a hot row pinned by a planted directory stops the hot-only
/// cap for good.
#[test]
fn one_undeletable_oldest_hot_row_does_not_disable_the_hot_row_cap_for_good() {
    let env = Env::new();
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    for n in 0..4 {
        env.add("cam-1", n, 1000, Tier::Hot);
    }
    let pinned = env.hot_file("cam-1", 0);
    std::fs::remove_file(&pinned).unwrap();
    std::fs::create_dir(&pinned).unwrap();
    std::fs::write(pinned.join("x"), b"x").unwrap();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(4);
    let mut last = String::new();
    for t in 0..20 {
        env.add("cam-1", 100 + t, 1000, Tier::Hot);
        last = format!("{:?}", lp.tick(now()).unwrap());
    }
    let (h, _) = rows(&env);
    assert!(
        h <= 5,
        "hot rows {h} over a cap of 4 after 20 ticks: {last}"
    );
}

/// Degrade path: hot below its floor but the floor reachable (state `Ok`), free space below
/// the emergency reserve; the archive is cut to its prefix and its totals cannot be read. The
/// round claims the reserve's hot deletes still run.
#[test]
fn a_degraded_tick_still_honours_the_emergency_reserve() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..10 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    // 10 x 95 kB: free 50 kB, floor 250 kB reachable by deleting video; reserve 100 kB.
    for n in 20..30 {
        env.add("cam-1", n, 95_000, Tier::Hot);
    }
    let mut cfg = env.cfg();
    cfg.policy.emergency_reserve_bytes = 100_000;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    env.index.faults.lock().unwrap().totals = true;
    let r = lp.tick(now()).unwrap();
    let free = 1_000_000 - super::support::du(&env.hot);
    assert!(
        free >= 100_000,
        "hot free {free} below the 100000 emergency reserve after a degraded tick: {r:?}"
    );
}

/// Several degraded ticks with ingest: the hot volume must never run out of space.
#[test]
fn persistent_degraded_ticks_never_fill_the_hot_volume() {
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
    env.index.faults.lock().unwrap().totals = true;
    let mut lowest = u64::MAX;
    let mut last = String::new();
    for t in 0..6 {
        env.add("cam-1", 100 + t, 50_000, Tier::Hot);
        last = format!("{:?}", lp.tick(now()).unwrap());
        lowest = lowest.min(1_000_000_u64.saturating_sub(super::support::du(&env.hot)));
    }
    assert!(lowest >= 100_000, "lowest hot free {lowest}: {last}");
}

/// The moves dropped for an evicted stand-in resume once the visible evictions made room, and
/// the archive floor holds on every tick.
#[test]
fn moves_dropped_for_the_stand_in_resume_and_the_archive_floor_holds() {
    let env = Env::new();
    env.set_cap("arch", 1_000_000);
    for n in 0..10 {
        env.add("cam-2", n, 80_000, Tier::Archive);
    }
    let hot: Vec<_> = (20..23)
        .map(|n| env.add("cam-1", n, 200_000, Tier::Hot))
        .collect();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    let mut moved = 0;
    for t in 0..15 {
        let r = lp.tick(late()).unwrap();
        moved += r.moved;
        if let ArchiveProbe::Available(s) = r.archive {
            assert!(
                s.free_bytes >= 250_000,
                "tick {t}: archive below floor: {r:?}"
            );
        }
    }
    assert_eq!(moved, 3);
    for id in hot {
        assert_eq!(env.tier_of(id), Some(Tier::Archive));
    }
}

/// Archive offline, ingest every tick, the hot tier at the cap: each tick only the hot excess
/// goes (exactly), archive rows are never touched, and the plan's deletes count first.
#[test]
fn offline_archive_multi_tick_cap_is_exact_and_never_touches_archive_rows() {
    let env = Env::new();
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    for n in 0..5 {
        env.row("cam-2", n, 1000, Tier::Archive);
    }
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(8);
    let mut n = 100;
    for t in 0..40_i64 {
        for _ in 0..(t % 4) {
            env.add("cam-1", n, 1000 + usize::try_from(t).unwrap(), Tier::Hot);
            n += 1;
        }
        let (h0, _) = rows(&env);
        let r = lp.tick(now()).unwrap();
        let (h, a) = rows(&env);
        assert_eq!(a, 5, "tick {t}: {r:?}");
        assert_eq!(h, h0.min(8), "tick {t}: {r:?}");
    }
}

/// Archive offline and the hot volume in the rolling buffer (foreign data): the cap and the
/// rolling deletes together delete one row per tick (the ingest), never both for the same need.
#[test]
fn rolling_buffer_and_offline_cap_together_stay_minimal_over_ticks() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 800_000]).unwrap();
    for n in 0..5 {
        env.add("cam-1", n, 10_000, Tier::Hot);
    }
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(5);
    for (t, n) in (0..40).zip(100..) {
        env.add("cam-1", n, 10_000, Tier::Hot);
        let r = lp.tick(now()).unwrap();
        let (h, _) = rows(&env);
        assert_eq!(h, 5, "tick {t}: {r:?}");
        assert_eq!(r.deleted, 1, "tick {t}: exactly the ingest goes: {r:?}");
    }
}

/// Archive offline; the hot tier is held at the cap until foreign data makes its floor
/// unreachable (the rolling buffer). Returns the lowest hot free space seen in that phase.
fn pinned_then_rolling(pin: bool) -> (u64, String) {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    for n in 0..4 {
        env.add("cam-1", n, 10_000, Tier::Hot);
    }
    if pin {
        let pinned = env.hot_file("cam-1", 0);
        std::fs::remove_file(&pinned).unwrap();
        std::fs::create_dir(&pinned).unwrap();
        std::fs::write(pinned.join("x"), vec![0_u8; 10_000]).unwrap();
    }
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(4);
    lp.set_max_segments(4);
    let mut n = 100;
    for _ in 0..10 {
        env.add("cam-1", n, 10_000, Tier::Hot);
        n += 1;
        lp.tick(now()).unwrap();
    }
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 800_000]).unwrap();
    let mut lowest = u64::MAX;
    let mut last = String::new();
    for _ in 0..12 {
        env.add("cam-1", n, 10_000, Tier::Hot);
        n += 1;
        last = format!("{:?}", lp.tick(now()).unwrap());
        lowest = lowest.min(1_000_000_u64.saturating_sub(super::support::du(&env.hot)));
    }
    (lowest, last)
}

#[test]
fn baseline_the_rolling_buffer_holds_hot_free_space_at_the_cap() {
    let (lowest, last) = pinned_then_rolling(false);
    assert!(lowest >= 100_000, "lowest hot free {lowest}: {last}");
}

/// One pinned hot row: the cap stalls, the hot tier grows past the per-tier load cap, the plan
/// is then made from a truncated hot prefix and the rolling deletes are refused for good: the
/// hot volume fills up.
#[test]
fn one_pinned_hot_row_never_leads_to_a_full_hot_volume() {
    let (lowest, last) = pinned_then_rolling(true);
    assert!(lowest >= 50_000, "lowest hot free {lowest}: {last}");
}

/// A symlink planted over the own tier's camera directory (to a directory that really holds the
/// file) is not "no file can exist": the row must not be dropped while the file stays reachable.
#[test]
fn a_symlinked_own_tier_directory_is_not_treated_as_gone() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 100, Tier::Hot);
    let rel = Env::rel("cam-1", 0);
    let first = rel.split('/').next().unwrap();
    let target = env.tmp.path().join("elsewhere");
    std::fs::rename(env.hot.join(first), &target).unwrap();
    std::os::unix::fs::symlink(&target, env.hot.join(first)).unwrap();
    let (lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    let out = lp.delete_now(id, true);
    assert_eq!(env.tier_of(id), Some(Tier::Hot), "{out:?}");
    assert!(env.hot_file("cam-1", 0).exists());
}
