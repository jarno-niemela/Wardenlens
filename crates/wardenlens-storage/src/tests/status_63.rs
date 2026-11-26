//! The snapshot the loop keeps for the API (ticket #63), against the real index and two
//! temporary directories with pretend capacities.

use wardenlens_core::storage::{
    ArchiveCondition, ArchiveUnavailableCause, StorageSnapshot, TickErrorKind, Tier,
};
use wardenlens_core::time::Timestamp;

use super::matrix::build;
use super::support::{Env, T0, now};
use crate::{ARCHIVE_MARKER, UnavailableCause};

const SEG: usize = 100_000;

fn ts(n: i64) -> Timestamp {
    // The row of `Env::add(.., n, ..)` ends at start + 1 s.
    Timestamp::from_unix_millis(T0 + n * 60_000 + 1000)
}

#[test]
fn before_the_first_tick_nothing_is_measured_or_counted() {
    let env = Env::new();
    let (lp, _) = build(&env, None);
    assert_eq!(lp.snapshot(), StorageSnapshot::initial());
    assert_eq!(lp.snapshot().last_tick, None);
}

#[test]
fn a_healthy_tick_reports_both_tiers_the_rows_and_the_tick_time() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 2_000_000);
    env.add("cam-1", 0, SEG, Tier::Hot);
    env.add("cam-1", 1, SEG, Tier::Hot);
    env.add("cam-2", 5, SEG, Tier::Archive);
    let (mut lp, _) = build(&env, None);
    lp.tick(now()).unwrap();
    let s = lp.snapshot();
    assert_eq!(s.last_tick, Some(now()));
    assert_eq!(s.last_error, None);
    assert_eq!(s.archive_condition, ArchiveCondition::Available);
    assert_eq!(s.floor_breaches_total, 0);
    let hot = s.hot.volume.unwrap();
    assert_eq!(hot.total_bytes, 1_000_000);
    assert_eq!(hot.free_bytes, 1_000_000 - 2 * SEG as u64);
    assert_eq!(hot.free_percent, 80);
    assert_eq!(hot.min_free_percent, 25);
    assert!(!hot.below_floor);
    assert_eq!(s.hot.segments, 2);
    assert_eq!(s.hot.oldest, Some(ts(0)));
    assert_eq!(s.hot.newest, Some(ts(1)));
    let arch = s.archive.volume.unwrap();
    assert_eq!(arch.total_bytes, 2_000_000);
    assert_eq!(arch.free_percent, 95);
    assert_eq!(s.archive.segments, 1);
    assert_eq!(s.archive.oldest, Some(ts(5)));
    assert_eq!(s.archive.newest, Some(ts(5)));
}

#[test]
fn an_empty_tier_has_no_times() {
    let env = Env::new();
    let (mut lp, _) = build(&env, None);
    lp.tick(now()).unwrap();
    let s = lp.snapshot();
    assert_eq!(
        (s.hot.segments, s.hot.oldest, s.hot.newest),
        (0, None, None)
    );
    assert_eq!(s.archive.segments, 0);
}

#[test]
fn an_unavailable_archive_reports_its_cause_class_and_counts_the_hot_breach_once_per_tick() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    for n in 0..9 {
        env.add("cam-1", n, SEG, Tier::Hot);
    }
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    assert!(r.deleted >= 1);
    let s = lp.snapshot();
    assert_eq!(
        s.archive_condition,
        ArchiveCondition::Unavailable(ArchiveUnavailableCause::NoMarker)
    );
    assert!(s.archive.volume.is_none(), "an absent archive has no space");
    assert_eq!(
        s.floor_breaches_total, 1,
        "one breach for the tick, not one per probe after each action"
    );
    // The floor was restored, so the next tick finds nothing below it: the count stands.
    lp.tick(now()).unwrap();
    assert_eq!(lp.snapshot().floor_breaches_total, 1);
    assert!(!lp.snapshot().hot.volume.unwrap().below_floor);
}

#[test]
fn every_unavailable_cause_has_a_class() {
    for (c, want) in [
        (UnavailableCause::Missing, ArchiveUnavailableCause::Missing),
        (
            UnavailableCause::SameFilesystem,
            ArchiveUnavailableCause::SameFilesystem,
        ),
        (
            UnavailableCause::ReadOnly,
            ArchiveUnavailableCause::ReadOnly,
        ),
        (
            UnavailableCause::NoMarker,
            ArchiveUnavailableCause::NoMarker,
        ),
        (
            UnavailableCause::MoveFailures,
            ArchiveUnavailableCause::MoveFailures,
        ),
        (
            UnavailableCause::Unusable,
            ArchiveUnavailableCause::Unusable,
        ),
        (
            UnavailableCause::ProbeFailed,
            ArchiveUnavailableCause::ProbeFailed,
        ),
    ] {
        assert_eq!(crate::status::cause_class(c), want);
    }
}

#[test]
fn a_full_archive_is_reported_as_full() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 150_000);
    for n in 0..9 {
        env.add("cam-1", n, SEG, Tier::Hot);
    }
    let (mut lp, _) = build(&env, None);
    assert!(lp.tick(now()).unwrap().archive_full);
    assert_eq!(lp.snapshot().archive_condition, ArchiveCondition::Full);
}

#[test]
fn an_archive_below_its_floor_counts_too() {
    let env = Env::new();
    env.set_cap("arch", 400_000);
    for n in 0..3 {
        env.add("cam-2", n, SEG, Tier::Archive);
    }
    // 100k free of 400k: 25%, at the floor. One more segment puts it under.
    env.add("cam-2", 3, SEG, Tier::Archive);
    let (mut lp, _) = build(&env, None);
    lp.tick(now()).unwrap();
    assert_eq!(lp.snapshot().floor_breaches_total, 1);
}

#[test]
fn a_failed_tick_reports_its_kind_and_keeps_counting() {
    let env = Env::new();
    env.add("cam-1", 0, SEG, Tier::Hot);
    let (mut lp, _) = build(&env, None);
    lp.tick(now()).unwrap();
    // Hot probe fails.
    env.usage.io_error.lock().unwrap().push(Tier::Hot);
    let at = Timestamp::from_unix_millis(T0 + 7);
    assert!(lp.tick(at).is_err());
    let s = lp.snapshot();
    assert_eq!(s.last_error, Some(TickErrorKind::HotVolume));
    assert_eq!(s.last_tick, Some(at));
    assert!(
        s.hot.volume.is_none(),
        "an unmeasured volume is not invented"
    );
    assert_eq!(s.hot.segments, 1, "the rows are still read");
    // Recovery clears the error.
    env.usage.io_error.lock().unwrap().clear();
    lp.tick(now()).unwrap();
    assert_eq!(lp.snapshot().last_error, None);
}

#[test]
fn an_unreadable_index_keeps_the_last_rows_and_reports_index() {
    let env = Env::new();
    env.add("cam-1", 0, SEG, Tier::Hot);
    let (mut lp, _) = build(&env, None);
    lp.tick(now()).unwrap();
    env.index.faults.lock().unwrap().totals = true;
    let _ = lp.tick(now());
    let s = lp.snapshot();
    assert_eq!(s.last_error, Some(TickErrorKind::Index));
    assert_eq!(s.hot.segments, 1, "the rows of the last good read");
}

#[test]
fn each_volume_under_its_floor_counts_and_the_counter_saturates() {
    for (start, want) in [(0, 2), (u64::MAX - 1, u64::MAX), (u64::MAX, u64::MAX)] {
        let env = Env::new();
        env.set_cap("hot", 10);
        env.set_cap("arch", 10);
        // 1 byte free of 10 on both: under a floor of 2 bytes.
        env.add("cam-1", 0, 9, Tier::Hot);
        env.add("cam-2", 0, 9, Tier::Archive);
        let (mut lp, _) = build(&env, None);
        lp.set_breaches_for_test(start);
        let _ = lp.tick(now());
        assert_eq!(lp.snapshot().floor_breaches_total, want, "start {start}");
    }
}

#[test]
fn the_debug_output_names_no_path() {
    let env = Env::new();
    env.add("cam-1", 0, SEG, Tier::Hot);
    let (mut lp, _) = build(&env, None);
    lp.tick(now()).unwrap();
    let dbg = format!("{:?}", lp.snapshot());
    let root = env.tmp.path().to_string_lossy().into_owned();
    assert!(!dbg.contains(&root), "{dbg}");
    assert!(!dbg.contains("cam-1"), "{dbg}");
}
