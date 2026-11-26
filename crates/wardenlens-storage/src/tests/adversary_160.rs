//! Adversary for ticket #160: the segment row cap, the truncated-archive stand-in, ENOTDIR and
//! the failed totals read.

use wardenlens_core::storage::{SegmentId, SegmentIndex, Tier};
use wardenlens_core::time::Timestamp;

use super::support::{Env, T0, TestIndex, now, pattern};
use crate::{ARCHIVE_MARKER, ArchiveProbe, Observer, Storage, StorageConfig};

fn total_rows(env: &Env) -> u64 {
    let t = env.index.bytes_by_tier().unwrap();
    t.hot.segments + t.archive.segments
}

fn arch_free(r: &crate::TickReport) -> u64 {
    match r.archive {
        ArchiveProbe::Available(s) => s.free_bytes,
        _ => u64::MAX,
    }
}

/// Hot 1 MB: 800 kB foreign, 3 x 50 kB video (free 50 kB, floor 250 kB unreachable): the
/// rolling buffer, with a 100 kB emergency reserve that demands one hot delete. The archive
/// (60 kB, 10 x 1 kB rows) cannot take a 50 kB segment above its floor: full.
fn reserve_world() -> (Env, Vec<SegmentId>, StorageConfig) {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 60_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 800_000]).unwrap();
    for n in 0..10 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let hot = (20..23)
        .map(|n| env.add("cam-1", n, 50_000, Tier::Hot))
        .collect();
    let mut cfg = env.cfg();
    cfg.policy.emergency_reserve_bytes = 100_000;
    cfg.max_actions_per_tick = 4;
    (env, hot, cfg)
}

#[test]
fn baseline_the_emergency_reserve_deletes_a_hot_segment() {
    let (env, hot, cfg) = reserve_world();
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    let r = lp.tick(now()).unwrap();
    assert_eq!(env.tier_of(hot[0]), None, "{r:?}");
}

#[test]
fn row_cap_eviction_never_starves_the_emergency_reserve_hot_deletes() {
    // 13 rows, cap 5: 8 above it, 4 actions per tick. The cap spends every action on archive
    // rows (freeing nothing on hot) and the hot volume stays below its emergency reserve.
    let (env, hot, cfg) = reserve_world();
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(5);
    let r = lp.tick(now()).unwrap();
    assert_eq!(
        env.tier_of(hot[0]),
        None,
        "the reserve's hot delete was starved by the row cap: {r:?}"
    );
}

#[test]
fn an_offline_archive_never_makes_the_row_cap_delete_hot_video_with_room_to_spare() {
    // Archive merely offline (marker gone) holding 5 old rows; 5 newer hot segments; both volumes
    // huge. Cap 8: 2 above it. Per-tier truncation is still far away (each tier is below the
    // per-tier load cap), so nothing forces deleting the newest video while older video is kept.
    let env = Env::new();
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    for n in 0..5 {
        env.row("cam-2", n, 1000, Tier::Archive);
    }
    let hot: Vec<_> = (20..25)
        .map(|n| env.add("cam-1", n, 1000, Tier::Hot))
        .collect();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(8);
    let r = lp.tick(now()).unwrap();
    for id in hot {
        assert_eq!(
            env.tier_of(id),
            Some(Tier::Hot),
            "hot row {id:?} deleted while the archive was only offline and older archive \
             rows were kept: {r:?}"
        );
    }
}

#[test]
fn the_row_cap_falls_through_to_hot_rows_within_the_same_tick() {
    // Archive available with 2 rows, hot 6 rows, cap 4: 4 above it, 64 actions. ADR: "while the
    // rows exceed it ... hot rows only when the archive ... holds no rows, within
    // max_actions_per_tick".
    let env = Env::new();
    for n in 0..2 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    for n in 20..26 {
        env.add("cam-1", n, 1000, Tier::Hot);
    }
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(4);
    let r = lp.tick(now()).unwrap();
    assert_eq!(total_rows(&env), 4, "{r:?}");
}

#[test]
fn row_cap_is_exact_over_many_ticks_with_ingest() {
    // Steady ingest at the cap, archive available, nothing below a floor: after every tick the
    // rows are exactly the cap (never above for long, never below).
    let env = Env::new();
    for n in 0..6 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_rows(6);
    let mut next = 100;
    for tick in 0..50 {
        for _ in 0..(tick % 3) {
            env.add(
                "cam-1",
                next,
                1000 + usize::try_from(tick).unwrap(),
                Tier::Hot,
            );
            next += 1;
        }
        let before = total_rows(&env);
        let r = lp.tick(now()).unwrap();
        assert_eq!(total_rows(&env), 6, "tick {tick}: {r:?}");
        assert_eq!(
            u64::from(r.rows_evicted_over_cap),
            before - 6,
            "tick {tick}: only the excess goes: {r:?}"
        );
    }
}

#[test]
fn the_stand_in_eviction_never_lets_moves_push_the_archive_below_its_floor() {
    // Archive 1 MB, 10 x 80 kB (free 200 kB, floor 250 kB). Three aged 200 kB hot segments.
    // With the archive cut to a 3-row prefix the plan evicts the 3 visible rows plus the stand-in
    // (never executed) and moves all three: 600 kB into 440 kB free.
    let env = Env::new();
    env.set_cap("arch", 1_000_000);
    for n in 0..10 {
        env.add("cam-2", n, 80_000, Tier::Archive);
    }
    for n in 20..23 {
        env.add("cam-1", n, 200_000, Tier::Hot);
    }
    let late = Timestamp::from_unix_millis(T0 + 48 * 3_600_000);
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    let r = lp.tick(late).unwrap();
    assert!(r.segments_truncated, "{r:?}");
    assert!(
        arch_free(&r) >= 250_000,
        "archive free {} below its 250000 floor after the tick: {r:?}",
        arch_free(&r)
    );
}

#[test]
fn a_failed_totals_read_on_a_truncated_archive_does_not_block_the_reserve_hot_delete() {
    let (env, hot, cfg) = reserve_world();
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    // The archive (10 rows) is cut to 3; hot (3 rows) is whole.
    lp.set_max_segments(3);
    env.index.faults.lock().unwrap().totals = true;
    let r = lp.tick(now());
    assert_eq!(
        env.tier_of(hot[0]),
        None,
        "the hot emergency delete was blocked by a totals read: {r:?}"
    );
}

struct FlipTotals(TestIndex);
impl Observer for FlipTotals {
    fn quarantine_eviction(&self, _tier: Tier, _files: usize) {
        self.0.faults.lock().unwrap().totals = true;
    }
}

#[test]
fn a_skipped_row_cap_after_a_failed_totals_read_is_reported() {
    // The quarantine step reads the totals fine; the row cap's own read then fails. The comment
    // in `enforce_row_cap` claims the error was already counted.
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..7 {
        env.add("cam-1", n, 100_000, Tier::Hot);
    }
    for n in 0..3 {
        env.add("cam-2", n + 100, 1000, Tier::Archive);
    }
    let d = env.hot.join("_quarantine/cam-1/2023-11-12");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("000000-000.mp4"), pattern(99_000)).unwrap();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_observer(Box::new(FlipTotals(env.index.clone())));
    lp.set_max_rows(8);
    let r = lp.tick(now());
    env.index.faults.lock().unwrap().totals = false;
    let r = r.unwrap();
    assert!(
        r.rows_evicted_over_cap > 0 || r.index_errors > 0,
        "the row cap was skipped silently: {r:?}"
    );
}

#[test]
fn a_regular_file_planted_over_the_own_tier_directory_does_not_pin_the_row() {
    // The ENOTDIR fix covers the twin; the row's own tier has the same planted-object case.
    for tier in [Tier::Hot, Tier::Archive] {
        let env = Env::new();
        let id = env.row("cam-1", 0, 100, tier);
        let rel = Env::rel("cam-1", 0);
        let first = rel.split('/').next().unwrap();
        let root = if tier == Tier::Hot {
            &env.hot
        } else {
            &env.arch
        };
        std::fs::write(root.join(first), b"planted").unwrap();
        let (lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
        let out = lp.delete_now(id, true);
        assert_eq!(
            env.tier_of(id),
            None,
            "{tier:?}: {out:?} pinned by a planted file"
        );
    }
}

#[test]
fn a_hold_tick_evicts_no_more_archive_rows_than_the_excess() {
    // Archive returns (pending pass): the cap still deletes only the excess.
    let env = Env::new();
    let marker = env.arch.join(ARCHIVE_MARKER);
    std::fs::remove_file(&marker).unwrap();
    for n in 0..6 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_initial_archive_state(false);
    lp.set_max_rows(4);
    std::fs::write(&marker, b"").unwrap();
    let r = lp.tick(now()).unwrap();
    assert!(r.archive_returned, "{r:?}");
    assert_eq!(total_rows(&env), 4, "{r:?}");
    assert_eq!(r.rows_evicted_over_cap, 2, "{r:?}");
}

/// Hot 100 kB (floor 25 kB), archive huge holding 20 old rows. Every tick 3 x 10 kB hot
/// segments arrive and 4 actions per tick are allowed: the moves keep up (3 per tick) unless
/// something else takes the actions. Returns the lowest hot free space seen after a tick.
fn ingest_sim(max_rows: Option<usize>, ticks: usize) -> (u64, String) {
    let env = Env::new();
    env.set_cap("hot", 100_000);
    for n in 0..20 {
        env.add("cam-2", n, 1000, Tier::Archive);
    }
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = 4;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    if let Some(m) = max_rows {
        lp.set_max_rows(m);
    }
    let mut lowest = u64::MAX;
    let mut last = String::new();
    let mut n = 1000;
    for _ in 0..ticks {
        for _ in 0..3 {
            env.add("cam-1", n, 10_000, Tier::Hot);
            n += 1;
        }
        let r = lp.tick(now()).unwrap();
        lowest = lowest.min(100_000_u64.saturating_sub(super::support::du(&env.hot)));
        last = format!("{r:?}");
    }
    (lowest, last)
}

#[test]
fn baseline_moves_keep_the_hot_floor_under_steady_ingest() {
    let (lowest, last) = ingest_sim(None, 30);
    assert!(lowest >= 25_000, "lowest hot free {lowest}: {last}");
}

#[test]
fn the_row_cap_at_steady_ingest_never_starves_the_moves_into_a_full_hot_volume() {
    // At the cap (20 rows), every new hot row makes one archive row go: 3 cap deletes plus 3
    // moves per tick need 6 actions of 4. Before the cap the same site kept its hot floor.
    let (lowest, last) = ingest_sim(Some(20), 30);
    assert!(
        lowest >= 25_000,
        "lowest hot free {lowest} (floor 25000): {last}"
    );
}
