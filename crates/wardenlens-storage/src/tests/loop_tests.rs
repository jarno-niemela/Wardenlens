//! The probe, the archive state and `StorageLoop::tick`.

use std::sync::{Arc, Mutex};

use wardenlens_core::storage::{SegmentFiles, SegmentId, SegmentIndex, SegmentOpenError, Tier};
use wardenlens_core::time::Timestamp;

use super::fault::{Fault, Op, count};
use super::matrix::build;
use super::support::{Env, T0, now, pattern};
use crate::{
    ARCHIVE_MARKER, ArchiveProbe, Observer, PROBE_FILE, Storage, TickError, UnavailableCause,
};

const SEG: usize = 100_000;

fn late() -> Timestamp {
    // Past `hot_max_age` for every segment: all hot segments are due to move.
    Timestamp::from_unix_millis(T0 + 100 * 3_600_000)
}

fn cause(p: ArchiveProbe) -> Option<UnavailableCause> {
    match p {
        ArchiveProbe::Unavailable(c) => Some(c),
        _ => None,
    }
}

#[test]
fn archive_state_is_unavailable_for_each_cause_and_never_an_error() {
    // Missing root.
    let env = Env::new();
    std::fs::remove_dir_all(&env.arch).unwrap();
    let (mut lp, _) = build(&env, None);
    assert_eq!(
        cause(lp.tick(now()).unwrap().archive),
        Some(UnavailableCause::Missing)
    );
    // A symlink as the root is refused (O_NOFOLLOW on the last segment).
    let env = Env::new();
    let real = env.tmp.path().join("real");
    std::fs::rename(&env.arch, &real).unwrap();
    std::os::unix::fs::symlink(&real, &env.arch).unwrap();
    let (mut lp, _) = build(&env, None);
    assert_eq!(
        cause(lp.tick(now()).unwrap().archive),
        Some(UnavailableCause::Missing)
    );
    // A regular file as the root.
    let env = Env::new();
    std::fs::remove_dir_all(&env.arch).unwrap();
    std::fs::write(&env.arch, b"x").unwrap();
    let (mut lp, _) = build(&env, None);
    assert_eq!(
        cause(lp.tick(now()).unwrap().archive),
        Some(UnavailableCause::Missing)
    );
    // Same st_dev as the hot root (the switch is off): the unmounted-disk case.
    let env = Env::new();
    let mut cfg = env.cfg();
    cfg.allow_same_filesystem = false;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    assert_eq!(
        cause(lp.tick(now()).unwrap().archive),
        Some(UnavailableCause::SameFilesystem)
    );
    // Marker missing, and a marker that is not a regular file.
    let env = Env::new();
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    let (mut lp, _) = build(&env, None);
    assert_eq!(
        cause(lp.tick(now()).unwrap().archive),
        Some(UnavailableCause::NoMarker)
    );
    std::fs::create_dir(env.arch.join(ARCHIVE_MARKER)).unwrap();
    assert_eq!(
        cause(lp.tick(now()).unwrap().archive),
        Some(UnavailableCause::NoMarker)
    );
    // Unusable archive (capacity 0): unavailable, not an error; unusable hot: the tick fails.
    let env = Env::new();
    env.set_cap("arch", 0);
    let (mut lp, _) = build(&env, None);
    assert_eq!(
        cause(lp.tick(now()).unwrap().archive),
        Some(UnavailableCause::Unusable)
    );
    let env = Env::new();
    env.set_cap("hot", 0);
    let (mut lp, _) = build(&env, None);
    assert!(matches!(lp.tick(now()), Err(TickError::HotVolume(_))));
}

#[test]
fn a_missing_hot_root_refuses_to_start() {
    let env = Env::new();
    let mut cfg = env.cfg();
    cfg.hot_root = env.tmp.path().join("nope");
    assert!(matches!(
        Storage::open(cfg, env.index.clone(), env.usage.clone()),
        Err(crate::StorageError::HotRoot(_))
    ));
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = 0;
    assert!(matches!(
        Storage::open(cfg, env.index.clone(), env.usage.clone()),
        Err(crate::StorageError::NoActions)
    ));
}

#[test]
fn start_unmounted_then_mount_while_running_keeps_every_archive_row_and_moves_land_on_the_new_archive()
 {
    let env = Env::new();
    // The "unmounted" archive: a directory on the hot filesystem, no marker (a plain mount point).
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    let archived: Vec<SegmentId> = (0..5)
        .map(|n| env.row("cam-2", n, SEG, Tier::Archive))
        .collect();
    let hot: Vec<SegmentId> = (0..3)
        .map(|n| env.add("cam-1", n, SEG, Tier::Hot))
        .collect();
    let (files, mut lp) = {
        let (l, f) =
            Storage::open_with(env.cfg(), env.index.clone(), env.usage.clone(), |r| r).unwrap();
        (f, l)
    };
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive.is_available());
    assert_eq!(r.moved, 0, "nothing lands on the covered directory");
    assert!(
        std::fs::read_dir(&env.arch).unwrap().next().is_none(),
        "the covered directory is empty"
    );
    for id in &archived {
        assert_eq!(
            env.tier_of(*id),
            Some(Tier::Archive),
            "every archive row is kept"
        );
    }
    assert_eq!(
        files.open_segment(archived[0]).unwrap_err(),
        SegmentOpenError::ArchiveUnavailable
    );
    // The disk is mounted while the service runs: a new directory (another inode) with the marker,
    // covering the old one.
    let covered = env.tmp.path().join("covered");
    std::fs::rename(&env.arch, &covered).unwrap();
    std::fs::create_dir(&env.arch).unwrap();
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    let r = lp.tick(late()).unwrap();
    assert!(r.archive.is_available());
    assert!(
        r.archive_returned,
        "the 'archive returned' pass is due on this tick"
    );
    assert_eq!(
        r.moved, 0,
        "no moves in the returning tick: the pass of #59 runs first"
    );
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive_returned);
    assert_eq!(r.moved, 3);
    for id in &hot {
        assert_eq!(env.tier_of(*id), Some(Tier::Archive));
    }
    for id in &archived {
        assert_eq!(
            env.tier_of(*id),
            Some(Tier::Archive),
            "archive rows still kept"
        );
    }
    assert!(
        env.arch_file("cam-1", 0).exists(),
        "moves land on the new archive"
    );
    assert!(
        !covered.join("cam-1").exists(),
        "not on the covered directory"
    );
    // A second tick is no longer a return.
    assert!(!lp.tick(late()).unwrap().archive_returned);
}

#[test]
fn the_probe_swaps_the_handle_when_the_directory_identity_changes_and_files_follow_it() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 64, Tier::Archive);
    let (l, files) =
        Storage::open_with(env.cfg(), env.index.clone(), env.usage.clone(), |r| r).unwrap();
    let mut lp = l;
    lp.tick(now()).unwrap();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut files.open_segment(id).unwrap().into_handle(), &mut buf)
        .unwrap();
    assert_eq!(buf, pattern(64));
    // Replace the archive with another directory holding different bytes at the same path.
    let old = env.tmp.path().join("old");
    std::fs::rename(&env.arch, &old).unwrap();
    std::fs::create_dir(&env.arch).unwrap();
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    let p = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, vec![9_u8; 64]).unwrap();
    lp.tick(now()).unwrap();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut files.open_segment(id).unwrap().into_handle(), &mut buf)
        .unwrap();
    assert_eq!(
        buf,
        vec![9_u8; 64],
        "the handle of the latest probe, not the one from before"
    );
}

#[test]
fn three_archive_side_failures_make_the_archive_unavailable_until_a_probe_file_round_trips() {
    let env = Env::new();
    let ids: Vec<_> = (0..6)
        .map(|n| env.add("cam-1", n, SEG, Tier::Hot))
        .collect();
    // `.wl-probe` cannot be created, fsynced and removed while a directory sits there.
    std::fs::create_dir(env.arch.join(PROBE_FILE)).unwrap();
    let fault = Fault {
        sticky: true,
        ..Fault::once(Op::Mkdir(Tier::Archive), 1)
    };
    let (mut lp, state) = build(&env, Some(fault));
    let r = lp.tick(late()).unwrap();
    assert_eq!(r.archive_failures, 3);
    assert_eq!(cause(r.archive), Some(UnavailableCause::MoveFailures));
    assert_eq!(
        r.replans, 1,
        "the plan was recomputed for the unavailable archive"
    );
    assert_eq!(
        count(&state, Op::Open(Tier::Hot)),
        3,
        "the other three were not attempted"
    );
    for id in &ids {
        assert_eq!(
            env.tier_of(*id),
            Some(Tier::Hot),
            "the hot copies stay authoritative"
        );
    }
    // Next tick: still unavailable while the probe file cannot be removed.
    state.lock().unwrap().fault = None;
    let r = lp.tick(late()).unwrap();
    assert_eq!(cause(r.archive), Some(UnavailableCause::MoveFailures));
    assert_eq!(r.moved, 0);
    // Cleared by the next probe that can create, fsync and remove a small file.
    std::fs::remove_dir(env.arch.join(PROBE_FILE)).unwrap();
    let r = lp.tick(late()).unwrap();
    assert!(r.archive.is_available());
    assert!(r.archive_returned);
    assert_eq!(r.moved, 0, "the returning tick plans no moves");
    assert_eq!(lp.move_failures(), 0);
    assert_eq!(lp.tick(late()).unwrap().moved, 6);
}

#[test]
fn a_stale_probe_file_is_unlinked_by_the_next_ticks_first_probe() {
    let env = Env::new();
    for n in 0..3 {
        env.add("cam-1", n, SEG, Tier::Hot);
    }
    std::fs::write(env.arch.join(PROBE_FILE), b"left by a crash").unwrap();
    let fault = Fault {
        sticky: true,
        ..Fault::once(Op::Mkdir(Tier::Archive), 1)
    };
    let (mut lp, state) = build(&env, Some(fault));
    // Three failures: the state holds for the rest of the tick, whatever the probe file is.
    let r = lp.tick(late()).unwrap();
    assert_eq!(r.archive_failures, 3);
    assert_eq!(cause(r.archive), Some(UnavailableCause::MoveFailures));
    assert_eq!(lp.move_failures(), 3);
    // The next tick's first probe unlinks the stale file, round-trips a new one and clears.
    state.lock().unwrap().fault = None;
    let r = lp.tick(late()).unwrap();
    assert!(r.archive.is_available());
    assert!(r.archive_returned);
    assert!(!env.arch.join(PROBE_FILE).exists());
    assert_eq!(lp.move_failures(), 0);
}

#[test]
fn three_failures_hold_for_the_rest_of_the_tick_and_the_floor_wins() {
    // A working scratch file: the old code cleared the count at the next re-probe and kept
    // writing to a failing archive while the hot volume stayed below its floor.
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 100_000]).unwrap();
    // 20 x 40 kB: used 900 kB, free 100 kB; the plan wants four moves (160 kB to the target).
    let ids: Vec<_> = (0..20)
        .map(|n| env.add("cam-1", n, 40_000, Tier::Hot))
        .collect();
    let fault = Fault {
        sticky: true,
        ..Fault::once(Op::Write, 1)
    };
    let (mut lp, state) = build(&env, Some(fault));
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.archive_failures, 3, "{r:?}");
    assert_eq!(
        cause(r.archive),
        Some(UnavailableCause::MoveFailures),
        "{r:?}"
    );
    assert!(r.deleted >= 1, "floor wins over video: {r:?}");
    assert!(r.replans >= 1);
    assert_eq!(
        count(&state, Op::CreatePart),
        3,
        "no fourth write to the failing archive"
    );
    let free = 1_000_000 - super::support::du(&env.hot);
    assert!(free >= 250_000, "the hot floor holds: {free}");
    assert_eq!(env.tier_of(ids[0]), None, "oldest first");
    // The next tick's first probe clears the state.
    state.lock().unwrap().fault = None;
    let r = lp.tick(now()).unwrap();
    assert!(r.archive.is_available());
    assert_eq!(lp.move_failures(), 0);
}

#[test]
fn a_failed_segment_is_never_retried_within_a_tick_and_the_rest_of_the_plan_runs() {
    let env = Env::new();
    let ids: Vec<_> = (0..5)
        .map(|n| env.add("cam-1", n, SEG, Tier::Hot))
        .collect();
    // Segment 1 cannot be verified (its H/R is a directory).
    std::fs::remove_file(env.hot_file("cam-1", 1)).unwrap();
    std::fs::create_dir(env.hot_file("cam-1", 1)).unwrap();
    let (mut lp, state) = build(&env, None);
    let r = lp.tick(late()).unwrap();
    assert_eq!(r.moved, 4);
    assert_eq!(r.unverified, 1);
    assert_eq!(
        count(&state, Op::Open(Tier::Hot)),
        5,
        "one open per segment, no retry"
    );
    assert_eq!(env.tier_of(ids[1]), Some(Tier::Hot));
    // The next tick tries it again (and again does not conclude anything).
    let r = lp.tick(late()).unwrap();
    assert_eq!((r.moved, r.unverified), (0, 1));
}

#[test]
fn one_tick_is_bounded_to_n_actions() {
    let env = Env::new();
    for n in 0..10 {
        env.add("cam-1", n, 1000, Tier::Hot);
    }
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = 3;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    let r = lp.tick(late()).unwrap();
    assert_eq!(r.moved, 3);
    assert!(r.truncated);
    assert_eq!(lp.tick(late()).unwrap().moved, 3);
    let (mut again, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    let r = again.tick(late()).unwrap();
    assert_eq!(r.moved, 4, "the remaining four");
    assert!(!r.truncated);
}

#[test]
fn the_archive_is_re_probed_after_every_action() {
    let env = Env::new();
    for n in 0..4 {
        env.add("cam-1", n, 1000, Tier::Hot);
    }
    let (mut lp, _) = build(&env, None);
    // The archive disappears mid-tick: the first move succeeds, and the hook below removes the
    // marker after it. The probe after that action sees it and the tick replans.
    let marker = env.arch.join(ARCHIVE_MARKER);
    let m2 = marker.clone();
    env.index.faults.lock().unwrap().get_hook = Some(Box::new(move || {
        let _ = std::fs::remove_file(m2);
    }));
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive.is_available(), "{r:?}");
    assert!(r.replans >= 1);
    assert!(r.moved < 4, "the rest did not land on a vanished archive");
    assert!(!marker.exists());
}

#[test]
fn floor_wins_when_the_archive_is_unavailable_and_archive_rows_are_untouched() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    let rows: Vec<_> = (0..3)
        .map(|n| env.row("cam-2", n, SEG, Tier::Archive))
        .collect();
    let hot: Vec<_> = (0..9)
        .map(|n| env.add("cam-1", n, SEG, Tier::Hot))
        .collect();
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    assert!(!r.archive.is_available());
    assert!(
        r.deleted >= 1,
        "the oldest hot video is deleted to hold the floor: {r:?}"
    );
    assert_eq!(env.tier_of(hot[0]), None, "oldest first");
    let free = 1_000_000 - super::support::du(&env.hot);
    assert!(free >= 250_000, "the floor holds again: {free}");
    for id in rows {
        assert_eq!(env.tier_of(id), Some(Tier::Archive));
    }
}

#[test]
fn an_archive_that_cannot_absorb_the_moves_reports_archive_full_and_behaves_like_unavailable() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 150_000); // 25% floor leaves 112k: a 100k move after eviction does not fit with a second.
    for n in 0..9 {
        env.add("cam-1", n, SEG, Tier::Hot);
    }
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    assert!(r.archive_full, "{r:?}");
    assert!(
        r.deleted >= 1,
        "hot video is deleted to hold the floor: {r:?}"
    );
}

#[test]
fn hot_floor_is_restored_by_moving_oldest_first() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 10_000_000);
    let ids: Vec<_> = (0..9)
        .map(|n| env.add("cam-1", n, SEG, Tier::Hot))
        .collect();
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    // 900k used of 1M: free 100k; floor 250k, target (floor + 1 pp) 260k: two segments move.
    assert_eq!(r.moved, 2);
    assert_eq!(env.tier_of(ids[0]), Some(Tier::Archive), "oldest first");
    assert_eq!(env.tier_of(ids[1]), Some(Tier::Archive));
    assert_eq!(env.tier_of(ids[2]), Some(Tier::Hot));
    assert!(1_000_000 - super::support::du(&env.hot) >= 250_000);
}

#[test]
fn index_errors_skip_the_segment_and_raise_a_health_error_after_three_ticks() {
    let env = Env::new();
    env.add("cam-1", 0, 1000, Tier::Hot);
    env.index.faults.lock().unwrap().get = true;
    let (mut lp, _) = build(&env, None);
    let mut last = None;
    for i in 1..=3 {
        let r = lp.tick(late()).unwrap();
        assert_eq!(r.index_errors, 1, "tick {i}");
        assert_eq!(
            r.archive_failures, 0,
            "an index error is not the archive's fault"
        );
        assert!(r.archive.is_available());
        assert_eq!(r.index_health_error, i == 3, "tick {i}");
        last = Some(r);
    }
    assert!(last.is_some());
    // A good tick clears the counter.
    env.index.faults.lock().unwrap().get = false;
    assert!(!lp.tick(late()).unwrap().index_health_error);
    // Reading the whole index failing is a tick error, and counts as an index tick too.
    env.index.faults.lock().unwrap().oldest = true;
    assert!(matches!(lp.tick(late()), Err(TickError::Index)));
}

struct Spy(Arc<Mutex<Vec<(Tier, usize)>>>);
impl Observer for Spy {
    fn quarantine_eviction(&self, tier: Tier, files: usize) {
        self.0.lock().unwrap().push((tier, files));
    }
}

#[test]
fn quarantined_files_are_evicted_first_oldest_first_after_an_alert() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..7 {
        env.add("cam-1", n, SEG, Tier::Hot);
    }
    let q = |day: &str, name: &str, bytes: usize| {
        let d = env.hot.join("_quarantine/cam-1").join(day);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(name), pattern(bytes)).unwrap();
    };
    q("2023-11-12", "000000-000.mp4", 33_000);
    q("2023-11-13", "000000-000.mp4.1", 33_000);
    q("2023-11-14", "000000-000.mp4", 33_000);
    q("2023-11-12", "notes.txt", 10); // not ours: never touched
    // used = 700k + 99k + 10 -> free 200_990 < 250k.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (mut lp, _) = build(&env, None);
    lp.set_observer(Box::new(Spy(Arc::clone(&seen))));
    let r = lp.tick(now()).unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(Tier::Hot, 2)],
        "alerted once, for the two files about to go"
    );
    assert_eq!(
        r.quarantine_evicted, 2,
        "until floor plus headroom: 260k free"
    );
    assert!(
        !env.hot
            .join("_quarantine/cam-1/2023-11-12/000000-000.mp4")
            .exists()
    );
    assert!(
        !env.hot
            .join("_quarantine/cam-1/2023-11-13/000000-000.mp4.1")
            .exists()
    );
    assert!(
        env.hot
            .join("_quarantine/cam-1/2023-11-14/000000-000.mp4")
            .exists()
    );
    assert!(
        env.hot
            .join("_quarantine/cam-1/2023-11-12/notes.txt")
            .exists()
    );
    assert_eq!(
        r.moved + r.deleted,
        0,
        "no video was touched: the quarantine was enough"
    );
}

#[test]
fn quarantine_is_left_alone_when_its_volume_is_above_the_floor() {
    let env = Env::new();
    let d = env.hot.join("_quarantine/cam-1/2023-11-12");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("000000-000.mp4"), b"evidence").unwrap();
    let (mut lp, _) = build(&env, None);
    assert_eq!(lp.tick(now()).unwrap().quarantine_evicted, 0);
    assert!(d.join("000000-000.mp4").exists());
}

#[test]
fn a_quarantine_walk_failure_never_stops_the_tick() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..9 {
        env.add("cam-1", n, SEG, Tier::Hot);
    }
    let fault = Fault {
        sticky: true,
        ..Fault::once(Op::List(Tier::Hot), 1)
    };
    let (mut lp, _) = build(&env, Some(fault));
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.quarantine_evicted, 0);
    assert_eq!(r.moved, 2, "the plan still ran");
}

#[test]
fn rolling_budget_is_fed_back_and_cleared_when_the_archive_returns() {
    // Foreign data fills the hot volume so that deleting all video cannot restore the floor, and
    // the archive is unavailable: the planner enters its rolling buffer and the loop keeps the
    // budget for the next tick (PlanInput::rolling_budget).
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 900_000]).unwrap();
    for n in 0..2 {
        env.add("cam-1", n, 40_000, Tier::Hot);
    }
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    assert!(!r.archive.is_available());
    assert!(lp.rolling_budget().is_some(), "{r:?}");
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    lp.tick(now()).unwrap();
    assert_eq!(
        lp.rolling_budget(),
        None,
        "cleared when the archive can take the load"
    );
}

#[test]
fn archive_probe_marks_available_on_a_healthy_archive() {
    let env = Env::new();
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    assert!(matches!(r.archive, ArchiveProbe::Available(s) if s.capacity_bytes == 1 << 40));
    assert!(!r.archive_full);
}

#[test]
fn files_port_returns_typed_errors_and_the_tier_actually_opened() {
    use std::io::Read;
    let env = Env::new();
    let (l, files) =
        Storage::open_with(env.cfg(), env.index.clone(), env.usage.clone(), |r| r).unwrap();
    let mut lp = l;
    lp.tick(now()).unwrap();
    let hot = env.add("cam-1", 0, 300, Tier::Hot);
    let arch = env.add("cam-1", 1, 200, Tier::Archive);
    // Not found: no row; a row whose file is missing on its tier (after the one re-read).
    assert_eq!(
        files.open_segment(SegmentId::new(999)).unwrap_err(),
        SegmentOpenError::NotFound
    );
    let gone = env.row("cam-1", 2, 10, Tier::Hot);
    env.index.faults.lock().unwrap().gets = 0;
    assert_eq!(
        files.open_segment(gone).unwrap_err(),
        SegmentOpenError::NotFound
    );
    assert_eq!(
        env.index.faults.lock().unwrap().gets,
        2,
        "re-read exactly once, never a loop"
    );
    // Opened: length from the handle, tier the file came from.
    let o = files.open_segment(hot).unwrap();
    assert_eq!((o.len(), o.tier()), (300, Tier::Hot));
    let mut buf = Vec::new();
    o.into_handle().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, pattern(300));
    let o = files.open_segment(arch).unwrap();
    assert_eq!((o.len(), o.tier()), (200, Tier::Archive));
    // A download in progress keeps reading through the unlink.
    let mut h = files.open_segment(hot).unwrap().into_handle();
    std::fs::remove_file(env.hot_file("cam-1", 0)).unwrap();
    let mut buf = Vec::new();
    h.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, pattern(300));
    // Non-regular files and symlinks are an I/O error, never followed.
    let dir_row = env.row("cam-1", 3, 10, Tier::Hot);
    std::fs::create_dir_all(env.hot_file("cam-1", 3)).unwrap();
    assert!(matches!(
        files.open_segment(dir_row).unwrap_err(),
        SegmentOpenError::Io { .. }
    ));
    let link_row = env.row("cam-1", 4, 10, Tier::Hot);
    std::fs::create_dir_all(env.hot_file("cam-1", 4).parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(env.arch_file("cam-1", 1), env.hot_file("cam-1", 4)).unwrap();
    assert!(matches!(
        files.open_segment(link_row).unwrap_err(),
        SegmentOpenError::Io { .. }
    ));
    // An index failure is an I/O error.
    env.index.faults.lock().unwrap().get = true;
    assert!(matches!(
        files.open_segment(hot).unwrap_err(),
        SegmentOpenError::Io { .. }
    ));
}

#[test]
fn files_port_follows_a_move_that_finishes_between_the_row_read_and_the_open() {
    use std::io::Read;
    let env = Env::new();
    let (l, files) =
        Storage::open_with(env.cfg(), env.index.clone(), env.usage.clone(), |r| r).unwrap();
    let mut lp = l;
    lp.tick(now()).unwrap();
    let id = env.add("cam-1", 0, 300, Tier::Hot);
    // After the first `get` returned (row says hot), the move completes: the file is on the
    // archive, the row says archive, the hot file is gone.
    let (hot, arch) = (env.hot_file("cam-1", 0), env.arch_file("cam-1", 0));
    let idx = Arc::clone(&env.index.inner);
    env.index.faults.lock().unwrap().get_hook = Some(Box::new(move || {
        std::fs::create_dir_all(arch.parent().unwrap()).unwrap();
        std::fs::rename(&hot, &arch).unwrap();
        wardenlens_core::storage::SegmentIndex::set_tier(
            &mut *idx.lock().unwrap(),
            id,
            Tier::Archive,
        )
        .unwrap();
    }));
    let o = files.open_segment(id).unwrap();
    assert_eq!(
        o.tier(),
        Tier::Archive,
        "the reported tier is where it was opened"
    );
    let mut buf = Vec::new();
    o.into_handle().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, pattern(300));
}

#[test]
fn mp4box_walk_over_a_stored_segment_is_bounded_and_typed() {
    use crate::ReadSeekSource;
    use wardenlens_core::mp4box::{MAX_PAYLOAD_LEN, Mp4BoxError, summarize};
    let env = Env::new();
    let (l, files) =
        Storage::open_with(env.cfg(), env.index.clone(), env.usage.clone(), |r| r).unwrap();
    let mut lp = l;
    lp.tick(now()).unwrap();
    // A planted file with a moov box above the 1 MiB cap, inside a file big enough to hold it:
    // refused from the header, with the specific variant.
    let p = env.hot_file("cam-1", 0);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let ftyp = [
        0, 0, 0, 16, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm', 0, 0, 0, 0,
    ];
    let declared = u32::try_from(MAX_PAYLOAD_LEN + 1024).unwrap();
    let mut bytes = ftyp.to_vec();
    bytes.extend_from_slice(&declared.to_be_bytes());
    bytes.extend_from_slice(b"moov");
    let total = ftyp.len() + usize::try_from(declared).unwrap() + 64;
    bytes.resize(total, 0);
    std::fs::write(&p, &bytes).unwrap();
    let id = env.row("cam-1", 0, bytes.len(), Tier::Hot);
    let h = files.open_segment(id).unwrap().into_handle();
    let mut src = ReadSeekSource::new(h).unwrap();
    assert!(
        matches!(
            summarize(&mut src),
            Err(Mp4BoxError::PayloadTooLarge { .. })
        ),
        "the 1 MiB cap on moov"
    );
    // Garbage is a typed error, not a panic.
    std::fs::write(&p, b"\0\0\0\x04junk").unwrap();
    let h = files.open_segment(id).unwrap().into_handle();
    let mut src = ReadSeekSource::new(h).unwrap();
    assert!(matches!(
        summarize(&mut src),
        Err(Mp4BoxError::ExceedsParent { .. } | Mp4BoxError::InvalidSize(_))
    ));
}

#[test]
fn every_tick_error_and_probe_failure_is_typed() {
    // The hot probe fails with an I/O error: the tick fails, typed.
    let env = Env::new();
    env.usage.io_error.lock().unwrap().push(Tier::Hot);
    let (mut lp, _) = build(&env, None);
    assert!(matches!(
        lp.tick(now()),
        Err(TickError::HotVolume(crate::ProbeError::Io(Some(_))))
    ));
    // The archive probe fails with an I/O error: unavailable, not an error.
    let env = Env::new();
    env.usage.io_error.lock().unwrap().push(Tier::Archive);
    let (mut lp, _) = build(&env, None);
    assert_eq!(
        cause(lp.tick(now()).unwrap().archive),
        Some(UnavailableCause::ProbeFailed)
    );
    // More free space than capacity: the planner refuses its input.
    let env = Env::new();
    *env.usage.hot_overfull.lock().unwrap() = true;
    let (mut lp, _) = build(&env, None);
    assert!(matches!(
        lp.tick(now()),
        Err(TickError::Plan(
            wardenlens_core::storage::PlanError::HotVolumeUnusable
        ))
    ));
}

#[test]
fn segments_are_paged_in_order_and_capped() {
    let env = Env::new();
    for n in 0..4 {
        env.add("cam-1", n, 10, Tier::Hot);
        env.add("cam-2", n, 10, Tier::Archive);
    }
    let (lp, _) = build(&env, None);
    // Pages of 3 (including the exact multiple of the page size at 6 rows and 8 rows total).
    let (all, cut) = lp.load_for_test(3, 100).unwrap();
    assert!(!cut);
    assert_eq!(all.len(), 8);
    let mut ids: Vec<_> = all.iter().map(|s| s.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(
        ids.len(),
        8,
        "no row twice, none missed across the page boundaries"
    );
    let hot: Vec<_> = all
        .iter()
        .filter(|s| s.tier == Tier::Hot)
        .map(|s| s.ended_at)
        .collect();
    assert!(hot.windows(2).all(|w| w[0] <= w[1]), "oldest first");
    for page in [1, 2, 4, 8, 9] {
        assert_eq!(
            lp.load_for_test(page, 100).unwrap().0.len(),
            8,
            "page {page}"
        );
    }
    // The cap is per tier (4 each): exactly 4 is fine, 3 keeps the oldest three and says so.
    let (rows, cut) = lp.load_for_test(3, 4).unwrap();
    assert_eq!((rows.len(), cut), (8, false));
    let (rows, cut) = lp.load_for_test(3, 3).unwrap();
    assert_eq!((rows.len(), cut), (6, true));
    let hot_all: Vec<_> = all
        .iter()
        .filter(|s| s.tier == Tier::Hot)
        .map(|s| s.id)
        .collect();
    let hot_cut: Vec<_> = rows
        .iter()
        .filter(|s| s.tier == Tier::Hot)
        .map(|s| s.id)
        .collect();
    assert_eq!(hot_cut, hot_all[..3], "the oldest-first prefix");
}

#[test]
fn quarantine_that_cannot_restore_the_floor_is_not_deleted() {
    // Foreign data fills the hot volume: deleting the evidence would lose it for nothing (P2).
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 900_000]).unwrap();
    let d = env.hot.join("_quarantine/cam-1/2023-11-12");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("000000-000.mp4"), pattern(10_000)).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (mut lp, _) = build(&env, None);
    lp.set_observer(Box::new(Spy(Arc::clone(&seen))));
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.quarantine_evicted, 0);
    assert!(
        seen.lock().unwrap().is_empty(),
        "no alert for a deletion that does not happen"
    );
    assert!(d.join("000000-000.mp4").exists());
}

#[test]
fn quarantine_eviction_deletes_the_shortest_oldest_first_prefix_that_reaches_the_goal() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    // Floor 250_000, target 260_000. Free = 249_999 (foreign 600_001 + 10 files of 15_000...).
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 600_001]).unwrap();
    let d = env.hot.join("_quarantine/cam-1/2023-11-12");
    std::fs::create_dir_all(&d).unwrap();
    for i in 0..10 {
        std::fs::write(d.join(format!("00000{i}-000.mp4")), pattern(15_000)).unwrap();
    }
    // used = 600_001 + 150_000 = 750_001: free 249_999, one byte under the floor.
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    // 10_001 bytes to the target: one 15_000-byte file is enough, and it is the oldest.
    assert_eq!(r.quarantine_evicted, 1);
    assert!(!d.join("000000-000.mp4").exists());
    assert!(d.join("000001-000.mp4").exists());
}

#[test]
fn hostile_names_under_quarantine_are_never_deleted_or_panicked_on() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 700_000]).unwrap();
    // used 770k: free 230k is under the floor, and the hostile files (70k) would reach it
    // if they were counted as ours.
    // Well-formed shapes with hostile components: multibyte characters in every position.
    let hostile = [
        "_quarantine/cam-1/2023-11-12/\u{e9}00000-000.mp4",
        "_quarantine/cam-1/2023-11-12/000000-000.mp4.\u{e9}",
        "_quarantine/cam-1/2023-1\u{e9}-12/000000-000.mp4",
        "_quarantine/Cam-1/2023-11-12/000000-000.mp4",
        "_quarantine/c\u{e9}m/2023-11-12/000000-000.mp4",
        "_quarantine/cam-1/2023-11-12/000000-000.mp4.part",
        "_quarantine/cam-1/2023-11-12/000000-000.mp4.1.2",
    ];
    for h in hostile {
        let p = env.hot.join(h);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, pattern(10_000)).unwrap();
    }
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.quarantine_evicted, 0);
    for h in hostile {
        assert!(env.hot.join(h).exists(), "{h}");
    }
}

fn count_files(root: &std::path::Path) -> usize {
    fn walk(d: &std::path::Path, n: &mut usize) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, n);
            } else if p.extension().is_some_and(|x| x == "mp4") {
                *n += 1;
            }
        }
    }
    let mut n = 0;
    walk(root, &mut n);
    n
}

#[test]
fn multi_tick_simulation_holds_both_floors_and_keeps_rows_and_files_in_step() {
    // A recorder adds mixed-size segments every tick and foreign data grows now and then; the
    // loop moves and evicts. After every tick both floors hold, and rows and files agree.
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 2_000_000);
    let mut cfg = env.cfg();
    cfg.policy.hot_max_age = wardenlens_core::time::DurationMs::from_secs(20 * 60);
    cfg.max_actions_per_tick = 16;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    let sizes = [20_000_usize, 40_000, 60_000, 30_000];
    let mut foreign = 0_usize;
    let mut n = 0_i64;
    for tick in 0..100_i64 {
        for k in 0..2 {
            env.add(
                "cam-1",
                n,
                sizes[usize::try_from(n).unwrap() % sizes.len()],
                Tier::Hot,
            );
            n += 1;
            let _ = k;
        }
        if tick % 10 == 0 && foreign < 60_000 {
            foreign += 20_000;
            std::fs::write(env.hot.join("foreign"), vec![0_u8; foreign]).unwrap();
        }
        let at = Timestamp::from_unix_millis(T0 + (tick + 1) * 120_000 + 2_000);
        let r = lp.tick(at).unwrap();
        assert!(
            r.moved + r.deleted + r.rolled_forward <= 16,
            "bounded: {r:?}"
        );
        let (hot_used, arch_used) = (super::support::du(&env.hot), super::support::du(&env.arch));
        assert!(
            hot_used <= 750_000,
            "tick {tick}: hot floor: used {hot_used}"
        );
        assert!(
            arch_used <= 1_500_000,
            "tick {tick}: archive floor: used {arch_used}"
        );
        assert!(
            r.archive.is_available() && !r.archive_full,
            "tick {tick}: {r:?}"
        );
        let totals = env.index.bytes_by_tier().unwrap();
        assert_eq!(
            count_files(&env.hot),
            usize::try_from(totals.hot.segments).unwrap(),
            "tick {tick}"
        );
        assert_eq!(
            count_files(&env.arch),
            usize::try_from(totals.archive.segments).unwrap(),
            "tick {tick}"
        );
        assert_eq!(du_mp4(&env.hot), totals.hot.bytes, "tick {tick}");
        assert_eq!(du_mp4(&env.arch), totals.archive.bytes, "tick {tick}");
    }
    assert!(
        env.index.bytes_by_tier().unwrap().archive.segments > 0,
        "the archive was used"
    );
}

fn du_mp4(root: &std::path::Path) -> u64 {
    fn walk(d: &std::path::Path, n: &mut u64) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, n);
            } else if p.extension().is_some_and(|x| x == "mp4") {
                *n += e.metadata().unwrap().len();
            }
        }
    }
    let mut n = 0;
    walk(root, &mut n);
    n
}

// ---- archive returned ---------------------------------------------------------------------

#[test]
fn archive_returned_is_set_when_the_archive_went_away_mid_tick_and_is_back_next_tick() {
    let env = Env::new();
    for n in 0..4 {
        env.add("cam-1", n, 1000, Tier::Hot);
    }
    let (mut lp, _) = build(&env, None);
    let marker = env.arch.join(ARCHIVE_MARKER);
    let m2 = marker.clone();
    env.index.faults.lock().unwrap().get_hook = Some(Box::new(move || {
        let _ = std::fs::remove_file(m2);
    }));
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive.is_available() && !r.archive_returned, "{r:?}");
    // The first probe of the next tick sees it available, but the loop knows it was away.
    std::fs::write(&marker, b"").unwrap();
    let r = lp.tick(late()).unwrap();
    assert!(r.archive_returned, "{r:?}");
    assert_eq!(r.moved, 0, "no moves in the returning tick");
    assert!(lp.tick(late()).unwrap().moved >= 1);
}

#[test]
fn archive_appearing_mid_tick_plans_no_moves_for_the_rest_of_that_tick() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    let ids: Vec<_> = (0..9)
        .map(|n| env.add("cam-1", n, SEG, Tier::Hot))
        .collect();
    let (mut lp, _) = build(&env, None);
    // The first delete (floor wins, archive unavailable) is followed by the archive appearing.
    let marker = env.arch.join(ARCHIVE_MARKER);
    env.index.faults.lock().unwrap().get_hook = Some(Box::new(move || {
        std::fs::write(marker, b"").unwrap();
    }));
    let r = lp.tick(now()).unwrap();
    assert!(r.archive.is_available());
    assert!(r.archive_returned, "{r:?}");
    assert_eq!(r.moved, 0, "{r:?}");
    assert!(r.replans >= 1);
    assert_eq!(env.tier_of(ids[8]), Some(Tier::Hot));
    assert!(
        std::fs::read_dir(&env.arch)
            .unwrap()
            .all(|e| e.unwrap().file_name() == ARCHIVE_MARKER)
    );
}

#[test]
fn a_healthy_archive_at_the_first_probe_is_not_a_return() {
    let env = Env::new();
    env.add("cam-1", 0, 1000, Tier::Hot);
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive_returned);
    assert_eq!(r.moved, 1);
}

// ---- degrade, order and bounds ------------------------------------------------------------

#[test]
fn above_the_segment_cap_the_plan_uses_the_oldest_prefix_and_the_floor_still_holds() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    let ids: Vec<_> = (0..9)
        .map(|n| env.add("cam-1", n, SEG, Tier::Hot))
        .collect();
    let (mut lp, _) = build(&env, None);
    lp.set_max_segments(8); // cap + 1 rows in the hot tier
    let r = lp.tick(now()).unwrap();
    assert!(r.segments_truncated, "a health warning: {r:?}");
    assert_eq!(r.moved, 2, "moves still run");
    assert!(
        1_000_000 - super::support::du(&env.hot) >= 250_000,
        "the hot floor holds"
    );
    assert_eq!(env.tier_of(ids[0]), Some(Tier::Archive), "oldest first");
    // Archive unavailable: the floor-wins deletes still run above the cap.
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    for n in 0..9 {
        env.add("cam-1", n, SEG, Tier::Hot);
    }
    let (mut lp, _) = build(&env, None);
    lp.set_max_segments(8);
    let r = lp.tick(now()).unwrap();
    assert!(r.segments_truncated && r.deleted >= 1, "{r:?}");
    assert!(1_000_000 - super::support::du(&env.hot) >= 250_000);
}

#[test]
fn unknown_directory_entry_kinds_fall_back_to_open_and_fstat() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 600_001]).unwrap();
    let d = env.hot.join("_quarantine/cam-1/2023-11-12");
    std::fs::create_dir_all(&d).unwrap();
    for i in 0..10 {
        std::fs::write(d.join(format!("00000{i}-000.mp4")), pattern(15_000)).unwrap();
    }
    // A FIFO with a quarantine-shaped name is never opened blocking and never deleted.
    rustix::fs::mknodat(
        rustix::fs::CWD,
        d.join("000099-000.mp4"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let (mut lp, state) = build(&env, None);
    state.lock().unwrap().unknown_kinds = true;
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.quarantine_evicted, 1, "{r:?}");
    assert!(!d.join("000000-000.mp4").exists());
    assert!(std::fs::symlink_metadata(d.join("000099-000.mp4")).is_ok());
}

#[test]
fn failed_quarantine_evictions_count_toward_the_action_bound() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 500_000]).unwrap();
    let d = env.hot.join("_quarantine/cam-1/2023-11-12");
    std::fs::create_dir_all(&d).unwrap();
    for i in 0..10 {
        std::fs::write(d.join(format!("00000{i}-000.mp4")), pattern(40_000)).unwrap();
    }
    let mut cfg = env.cfg();
    cfg.max_actions_per_tick = 2;
    let state: super::fault::Shared = Arc::new(Mutex::new(super::fault::State {
        fault: Some(Fault {
            sticky: true,
            ..Fault::once(Op::Unlink(Tier::Hot), 1)
        }),
        ..super::fault::State::default()
    }));
    let s2 = Arc::clone(&state);
    let (mut lp, _) = Storage::open_with(cfg, env.index.clone(), env.usage.clone(), move |r| {
        super::fault::FaultFs::new(r, s2)
    })
    .unwrap();
    let r = lp.tick(now()).unwrap();
    assert_eq!(count(&state, Op::Unlink(Tier::Hot)), 2, "{r:?}");
    assert!(r.truncated);
    assert_eq!(r.quarantine_evicted, 0);
}

#[test]
fn index_health_counts_only_index_errors() {
    // Planner and probe errors are not the index's fault.
    let env = Env::new();
    *env.usage.hot_overfull.lock().unwrap() = true;
    let (mut lp, _) = build(&env, None);
    for _ in 0..4 {
        assert!(matches!(lp.tick(now()), Err(TickError::Plan(_))));
    }
    assert!(!lp.index_health_error());
    // A failed index read is, and the error path reports it through the accessor.
    let env = Env::new();
    env.index.faults.lock().unwrap().oldest = true;
    let (mut lp, _) = build(&env, None);
    for _ in 0..3 {
        assert!(matches!(lp.tick(now()), Err(TickError::Index)));
    }
    assert!(lp.index_health_error());
}

#[test]
fn a_quarantine_that_is_needed_is_deleted_before_video_when_the_total_reaches_the_floor() {
    // Order, not a gate: the quarantine alone (50 kB) cannot reach the floor, quarantine plus
    // video can. The quarantine goes first, then the plan deletes only what is still needed.
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    let ids: Vec<_> = (0..9)
        .map(|n| env.add("cam-1", n + 100, SEG, Tier::Hot))
        .collect();
    let d = env.hot.join("_quarantine/cam-1/2023-11-12");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("000000-000.mp4"), pattern(50_000)).unwrap();
    let (mut lp, _) = build(&env, None);
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.quarantine_evicted, 1, "{r:?}");
    assert!(!d.join("000000-000.mp4").exists());
    let gone = ids.iter().filter(|id| env.tier_of(**id).is_none()).count();
    assert_eq!(gone, 2, "two segments finish the job: {r:?}");
}
