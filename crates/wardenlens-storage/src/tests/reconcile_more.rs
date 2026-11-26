//! The reconciliation beyond the per-cell tables: the required scenarios, the crash table, the
//! "archive returned" pass, the walk bounds, the adoption parser and every error path.

use std::collections::BTreeMap;
use std::path::Path;

use wardenlens_core::mp4box::{MAX_FILE_LEN, MAX_PAYLOAD_LEN};
use wardenlens_core::storage::Tier;
use wardenlens_core::time::Timestamp;

use super::fault::{Fault, Op};
use super::matrix::build;
use super::support::{Env, T0, good, mp4, now, pattern, put};
use crate::{ARCHIVE_MARKER, ReconcileReport};

fn late() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 100 * 3_600_000)
}

/// Every file below `root` (relative path to bytes), the quarantine included.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, d: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(base, &p, out);
            } else if ft.is_symlink() {
                out.insert(rel, b"<symlink>".to_vec());
            } else if ft.is_file() {
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn unmount(env: &Env) {
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
}

fn startup(env: &Env) -> crate::Reconciled {
    let (mut lp, _) = build(env, None);
    lp.reconcile_startup().unwrap()
}

// ---- the required scenarios ----------------------------------------------------------------------

#[test]
fn archive_unmounted_keeps_every_archive_row_and_touches_no_archive_file() {
    let env = Env::new();
    // The stale mount point: an empty directory on the hot filesystem, no marker.
    unmount(&env);
    let arch_ids: Vec<_> = (0..20)
        .map(|n| env.row("cam-2", n, 5000, Tier::Archive))
        .collect();
    let hot_ids: Vec<_> = (0..3)
        .map(|n| env.add("cam-1", n, 5000, Tier::Hot))
        .collect();
    // Whatever sits in the unobservable archive stays exactly as it is, `.part` and invalid
    // files included.
    put(
        &env.arch,
        "cam-2/2023-11-14/221320-000.mp4.part",
        b"interrupted move",
    );
    put(
        &env.arch,
        "cam-9/2023-11-14/221320-000.mp4",
        b"not even a segment",
    );
    let before = snapshot(&env.arch);
    // A hot `.part` is deleted at start-up whatever the archive does.
    put(
        &env.hot,
        "cam-1/2023-11-14/221320-000.mp4.part",
        b"cut by the crash",
    );
    let out = startup(&env);
    assert!(out.report.archive_unavailable && out.report.archive_unverified);
    assert_eq!(out.report.part_deleted, 1, "{:?}", out.report);
    assert_eq!(
        out.report.unverified, 20,
        "one per archive row: {:?}",
        out.report
    );
    assert_eq!(out.report.missing, 0);
    assert_eq!(out.report.quarantined, 0);
    assert_eq!(out.report.size_mismatch, 0);
    for id in &arch_ids {
        assert_eq!(
            env.tier_of(*id),
            Some(Tier::Archive),
            "every archive row is kept"
        );
    }
    for id in &hot_ids {
        assert_eq!(env.tier_of(*id), Some(Tier::Hot));
    }
    assert_eq!(snapshot(&env.arch), before, "no archive file is touched");
    assert!(
        !env.hot
            .join("cam-1/2023-11-14/221320-000.mp4.part")
            .exists()
    );
}

#[test]
fn archive_mounted_while_running_keeps_every_archive_row_and_resolves_them_in_the_returned_pass() {
    let env = Env::new();
    unmount(&env);
    let arch_ids: Vec<_> = (0..6)
        .map(|n| env.row("cam-2", n, 5000, Tier::Archive))
        .collect();
    let hot_ids: Vec<_> = (0..3)
        .map(|n| env.add("cam-1", n, 5000, Tier::Hot))
        .collect();
    let (mut lp, _) = build(&env, None);
    let out = lp.reconcile_startup().unwrap();
    assert!(out.report.archive_unavailable);
    for id in &arch_ids {
        assert_eq!(env.tier_of(*id), Some(Tier::Archive));
    }
    // Still unmounted at the first tick: nothing changes.
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive.is_available() && r.returned.is_none(), "{r:?}");
    // The disk is mounted while the service runs: it holds the segments and a stale `.part`.
    let covered = env.tmp.path().join("covered");
    std::fs::rename(&env.arch, &covered).unwrap();
    std::fs::create_dir(&env.arch).unwrap();
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    for n in 0..6 {
        put(&env.arch, &Env::rel("cam-2", n), &pattern(5000));
    }
    put(
        &env.arch,
        "cam-2/2023-11-14/221320-000.mp4.part",
        b"interrupted move",
    );
    let r = lp.tick(late()).unwrap();
    assert!(r.archive_returned, "{r:?}");
    assert_eq!(r.moved, 0, "no move on the returning tick");
    let pass = r.returned.expect("the pass ran on the returning tick");
    assert_eq!(pass.part_deleted, 1, "the archive `.part` rule: {pass:?}");
    assert_eq!(pass.missing, 0);
    assert_eq!(pass.quarantined, 0);
    assert_eq!(pass.unverified, 0);
    for id in &arch_ids {
        assert_eq!(
            env.tier_of(*id),
            Some(Tier::Archive),
            "every archive row is kept"
        );
    }
    // The hold is gone once the pass has run: the next tick moves, onto the new archive.
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive_returned && r.returned.is_none(), "{r:?}");
    assert_eq!(r.moved, 3);
    for id in &hot_ids {
        assert_eq!(env.tier_of(*id), Some(Tier::Archive));
    }
    assert!(env.arch_file("cam-1", 0).exists());
    assert!(
        !covered.join("cam-1").exists(),
        "never on the covered directory"
    );
}

#[test]
fn the_returned_pass_touches_no_hot_file_no_hot_part_and_no_row_of_a_key_without_a_row() {
    let env = Env::new();
    unmount(&env);
    // The recorder is mid-segment (a hot `.part`), mid-rename (a hot `.mp4` with no row yet),
    // and has finished segments with rows.
    let part = put(
        &env.hot,
        "cam-1/2023-11-14/221400-000.mp4.part",
        b"being written now",
    );
    let renamed = put(&env.hot, &Env::rel("cam-1", 5), &good());
    let id0 = env.add("cam-1", 0, 5000, Tier::Hot);
    let id1 = env.add("cam-1", 1, 5000, Tier::Hot);
    // A hot orphan whose bytes are not a segment: a start-up pass would quarantine it; the
    // returned pass never even looks.
    let junk = put(&env.hot, &Env::rel("cam-1", 6), b"junk");
    // The archive holds its own consistent segment, and the rest of the disk.
    let aid = env.row("cam-2", 0, 5000, Tier::Archive);
    let (mut lp, _) = build(&env, None);
    // The service has been running with the archive away (the start-up pass is another test).
    lp.set_initial_archive_state(false);
    let hot_before = snapshot(&env.hot);
    let rows_before = (env.rows_of("cam-1"), env.rows_of("cam-2"));
    let covered = env.tmp.path().join("covered");
    std::fs::rename(&env.arch, &covered).unwrap();
    std::fs::create_dir(&env.arch).unwrap();
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    put(&env.arch, &Env::rel("cam-2", 0), &pattern(5000));
    let arch_before = snapshot(&env.arch);
    let r = lp.tick(now()).unwrap();
    let pass = r.returned.expect("the pass ran");
    assert_eq!(
        pass.adopted + pass.quarantined + pass.part_deleted,
        0,
        "{pass:?}"
    );
    assert_eq!(
        snapshot(&env.hot),
        hot_before,
        "no hot file or hot `.part` is touched"
    );
    assert_eq!(
        snapshot(&env.arch),
        arch_before,
        "no archive file is touched"
    );
    assert_eq!(
        (env.rows_of("cam-1"), env.rows_of("cam-2")),
        rows_before,
        "no row changed"
    );
    assert!(part.exists() && renamed.exists() && junk.exists());
    assert!(
        env.find("cam-1", 5).is_none(),
        "a hot-only key is never adopted"
    );
    assert!(env.find("cam-1", 6).is_none());
    assert_eq!(env.tier_of(id0), Some(Tier::Hot));
    assert_eq!(env.tier_of(id1), Some(Tier::Hot));
    assert_eq!(env.tier_of(aid), Some(Tier::Archive));
}

#[test]
fn the_returned_pass_adopts_an_archive_orphan_and_never_touches_the_hot_twin() {
    let env = Env::new();
    unmount(&env);
    // The recorder's rename-to-insert window for key 3, and an old orphan of the same key on the
    // archive: the pass adopts A and leaves H (the start-up cell would delete or quarantine H).
    let h = put(&env.hot, &Env::rel("cam-1", 3), &good());
    let (mut lp, _) = build(&env, None);
    lp.set_initial_archive_state(false);
    let covered = env.tmp.path().join("covered");
    std::fs::rename(&env.arch, &covered).unwrap();
    std::fs::create_dir(&env.arch).unwrap();
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    put(&env.arch, &Env::rel("cam-1", 3), &good());
    put(&env.arch, &Env::rel("cam-1", 4), b"not a segment");
    let hot_before = snapshot(&env.hot);
    let r = lp.tick(now()).unwrap();
    let pass = r.returned.expect("the pass ran");
    assert_eq!(pass.adopted, 1, "{pass:?}");
    assert_eq!(pass.quarantined, 1, "the invalid archive file: {pass:?}");
    assert_eq!(env.find("cam-1", 3).unwrap().tier, Tier::Archive);
    assert!(env.find("cam-1", 4).is_none());
    assert!(h.exists());
    assert_eq!(snapshot(&env.hot), hot_before);
    assert_eq!(Env::quarantined(&env.arch).len(), 1);
}

#[test]
fn the_returned_pass_scope_is_archive_files_archive_rows_and_hot_rows_with_a_missing_hot_file() {
    let env = Env::new();
    unmount(&env);
    // (a) a hot row whose hot file is missing: evaluated, (hot, none, none) drops it.
    env.row("cam-1", 0, 5000, Tier::Hot);
    // (b) a hot row with a wrong-size hot file and no archive file: not evaluated at all.
    env.row("cam-1", 1, 5000, Tier::Hot);
    let wrong = put(&env.hot, &Env::rel("cam-1", 1), &pattern(9));
    // (c) a hot row with a valid hot file: not evaluated.
    let c = env.add("cam-1", 2, 5000, Tier::Hot);
    // (d) an archive row whose hot file still exists (crash after M8): H goes.
    env.row("cam-1", 3, 5000, Tier::Archive);
    let twin = put(&env.hot, &Env::rel("cam-1", 3), &pattern(5000));
    let (mut lp, _) = build(&env, None);
    // Not the start-up pass: only the loop's own state, as if the archive had been away.
    lp.set_initial_archive_state(false);
    let covered = env.tmp.path().join("covered");
    std::fs::rename(&env.arch, &covered).unwrap();
    std::fs::create_dir(&env.arch).unwrap();
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    put(&env.arch, &Env::rel("cam-1", 3), &pattern(5000));
    let r = lp.tick(now()).unwrap();
    let pass = r.returned.expect("the pass ran");
    assert_eq!(pass.missing, 1, "{pass:?}");
    assert_eq!(pass.duplicates_deleted, 1, "{pass:?}");
    assert_eq!(pass.quarantined, 0, "{pass:?}");
    assert!(env.find("cam-1", 0).is_none(), "(a) dropped");
    assert!(wrong.exists(), "(b) the wrong-size hot file is left alone");
    assert_eq!(env.find("cam-1", 1).unwrap().tier, Tier::Hot);
    assert_eq!(env.tier_of(c), Some(Tier::Hot));
    assert!(
        !twin.exists(),
        "(d) the hot twin of an archive row is deleted"
    );
    assert_eq!(env.find("cam-1", 3).unwrap().tier, Tier::Archive);
}

// ---- `.part` rules --------------------------------------------------------------------------------

#[test]
fn part_files_follow_the_rules_of_each_pass() {
    let hp = "cam-1/2023-11-14/221320-000.mp4.part";
    let ap = "cam-2/2023-11-14/221320-000.mp4.part";
    // Start-up, archive available: both are deleted.
    let env = Env::new();
    put(&env.hot, hp, b"h");
    put(&env.arch, ap, b"a");
    let out = startup(&env);
    assert_eq!(out.report.part_deleted, 2);
    assert!(!env.hot.join(hp).exists() && !env.arch.join(ap).exists());
    // Start-up, archive unavailable: the hot one only.
    let env = Env::new();
    unmount(&env);
    put(&env.hot, hp, b"h");
    put(&env.arch, ap, b"a");
    let out = startup(&env);
    assert_eq!(out.report.part_deleted, 1);
    assert!(!env.hot.join(hp).exists());
    assert!(
        env.arch.join(ap).exists(),
        "only when the archive is available"
    );
    // Returned pass: the archive one only.
    let env = Env::new();
    unmount(&env);
    let (mut lp, _) = build(&env, None);
    lp.reconcile_startup().unwrap();
    put(&env.hot, hp, b"h");
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    put(&env.arch, ap, b"a");
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.returned.expect("ran").part_deleted, 1);
    assert!(
        env.hot.join(hp).exists(),
        "a hot `.part` may be being written right now"
    );
    assert!(!env.arch.join(ap).exists());
}

#[test]
fn a_part_that_is_not_a_regular_file_or_not_canonical_is_left() {
    let env = Env::new();
    // A directory and a symlink named like a `.part`, and a pattern-matching non-canonical one.
    std::fs::create_dir_all(env.hot.join("cam-1/2023-11-14/221320-000.mp4.part")).unwrap();
    let outside = env.tmp.path().join("outside");
    std::fs::write(&outside, b"keep me").unwrap();
    std::os::unix::fs::symlink(
        &outside,
        env.hot.join("cam-1/2023-11-14/221321-000.mp4.part"),
    )
    .unwrap();
    put(
        &env.hot,
        "cam-1/2023-11-14/996099-000.mp4.part",
        b"not canonical",
    );
    let before = snapshot(&env.hot);
    let out = startup(&env);
    assert_eq!(out.report.part_deleted, 0);
    assert_eq!(out.report.unknown_left, 3, "{:?}", out.report);
    assert_eq!(snapshot(&env.hot), before);
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep me");
}

// ---- names, walk and bounds -------------------------------------------------------------------------

#[test]
fn a_pattern_matching_but_non_canonical_name_is_unknown_left_never_adopted_or_deleted() {
    let env = Env::new();
    let names = [
        "996099-000.mp4",   // minute 60 and second 99
        "240000-000.mp4",   // hour 24
        "236000-000.mp4",   // minute 60
        "235960-000.mp4",   // second 60
        "000000-000.MP4",   // case
        "00000-0000.mp4",   // wrong widths
        "000000-000.mp4.1", // a quarantine suffix outside the quarantine
        "000000-000.mp4x",
        "note.txt",
    ];
    for n in names {
        put(&env.hot, &format!("cam-1/2023-11-14/{n}"), &good());
    }
    // The one canonical neighbour (hour 23, minute 59, second 59) is adopted.
    put(&env.hot, "cam-1/2023-11-14/235959-999.mp4", &good());
    let before = snapshot(&env.hot);
    let out = startup(&env);
    assert_eq!(out.report.unknown_left, 9, "{:?}", out.report);
    assert_eq!(out.report.adopted, 1);
    assert_eq!(out.report.quarantined + out.report.part_deleted, 0);
    assert_eq!(env.rows_of("cam-1").len(), 1);
    assert_eq!(snapshot(&env.hot), before, "every name is left in place");
}

#[test]
fn directories_that_are_not_ours_symlinks_and_depth_are_never_followed() {
    let env = Env::new();
    // A planted tree outside both roots that must never be touched.
    let outside = env.tmp.path().join("outside");
    put(&outside, "cam-8/2023-11-14/221320-000.mp4", &good());
    put(&outside, "2023-11-14/221320-000.mp4", &good());
    let out_before = snapshot(&outside);
    // A symlinked camera directory, a symlinked day directory, a symlinked segment.
    std::os::unix::fs::symlink(outside.join("cam-8"), env.hot.join("cam-8")).unwrap();
    std::fs::create_dir_all(env.hot.join("cam-1")).unwrap();
    std::os::unix::fs::symlink(&outside, env.hot.join("cam-1/2023-11-14")).unwrap();
    put(&env.hot, "cam-2/2023-11-14/221320-001.mp4.keep", b"x");
    std::os::unix::fs::symlink(
        outside.join("cam-8/2023-11-14/221320-000.mp4"),
        env.hot.join("cam-2/2023-11-14/221320-000.mp4"),
    )
    .unwrap();
    // A directory below a day directory (depth 4) holding a perfectly good segment: not entered.
    put(&env.hot, "cam-2/2023-11-14/deeper/221321-000.mp4", &good());
    // Things that are not a camera or a day.
    put(&env.hot, "Not_A_Camera/2023-11-14/221320-000.mp4", &good());
    put(&env.hot, "cam-3/not-a-day/221320-000.mp4", &good());
    put(&env.hot, "cam-3/2023-02-30/221320-000.mp4", &good());
    put(&env.hot, "loose.mp4", &good());
    let before = snapshot(&env.hot);
    let out = startup(&env);
    assert_eq!(out.report.adopted, 0, "{:?}", out.report);
    assert_eq!(out.report.quarantined, 0);
    assert_eq!(out.report.part_deleted, 0);
    assert!(out.report.unknown_left >= 8, "{:?}", out.report);
    assert_eq!(snapshot(&env.hot), before, "nothing in the root changed");
    assert_eq!(
        snapshot(&outside),
        out_before,
        "nothing outside was touched"
    );
    assert!(env.rows_of("cam-2").is_empty() && env.rows_of("cam-8").is_empty());
}

#[test]
fn a_fifo_or_directory_at_a_segment_name_neither_blocks_nor_is_touched() {
    let env = Env::new();
    let dir = env.hot.join("cam-1/2023-11-14");
    std::fs::create_dir_all(&dir).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        dir.join("221320-000.mp4"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    std::fs::create_dir(dir.join("221321-000.mp4")).unwrap();
    // A row of a key whose hot name is a FIFO is not concluded either way.
    let id = env.row("cam-1", 0, 5000, Tier::Hot);
    let out = startup(&env);
    assert_eq!(out.report.unknown_left, 2, "{:?}", out.report);
    // Both keys are skipped (the FIFO's has the row, the directory's has none).
    assert_eq!(out.report.unverified, 2);
    assert_eq!(out.report.missing, 0);
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    assert!(dir.join("221320-000.mp4").exists() && dir.join("221321-000.mp4").is_dir());
}

/// Entries the walk lists: everything below a root, the `_quarantine` directory itself counted but
/// not entered, and nothing below a day directory (the fixture has no such directory).
fn entries(root: &Path) -> usize {
    let mut n = 0;
    for e in std::fs::read_dir(root).unwrap().flatten() {
        n += 1;
        if e.file_name() == "_quarantine" {
            continue;
        }
        if e.file_type().unwrap().is_dir() {
            n += entries(&e.path());
        }
    }
    n
}

fn cap_fixture() -> (Env, wardenlens_core::storage::SegmentId) {
    let env = Env::new();
    for cam in ["cam-1", "cam-2"] {
        for n in [0, 1, 2, 1000] {
            env.add(cam, n, 5000, Tier::Hot);
        }
    }
    env.add("cam-1", 3, 5000, Tier::Archive);
    // A row in the last directory that walks, whose file is missing: `missing` if seen.
    let last = env.row("cam-2", 1001, 5000, Tier::Hot);
    (env, last)
}

#[test]
fn the_entry_cap_is_exact_and_stops_the_walk_without_concluding_from_the_unseen() {
    let (env, last) = cap_fixture();
    let total = entries(&env.hot) + entries(&env.arch);
    for (cap, capped) in [
        (total + 1, false),
        (total, false),
        (total - 1, true),
        (1, true),
        (0, true),
    ] {
        let (env, last) = cap_fixture();
        let (mut lp, _) = {
            let cfg = env.cfg().with_walk_max_entries(cap);
            let state = std::sync::Arc::new(std::sync::Mutex::new(super::fault::State::default()));
            let s2 = std::sync::Arc::clone(&state);
            let (l, _f) =
                crate::Storage::open_with(cfg, env.index.clone(), env.usage.clone(), move |r| {
                    super::fault::FaultFs::new(r, s2)
                })
                .unwrap();
            (l, state)
        };
        let snap = (snapshot(&env.hot), snapshot(&env.arch));
        let out = lp.reconcile_startup().expect("the service starts anyway");
        let r = out.report;
        assert_eq!(r.walk_cap_exceeded, capped, "cap {cap} of {total}: {r:?}");
        assert_eq!(r.health_error(), capped);
        assert_eq!((r.hot_unverified, r.archive_unverified), (capped, capped));
        if capped {
            assert!(r.unverified > 0, "{r:?}");
            assert_eq!(env.tier_of(last), Some(Tier::Hot), "the unseen row is kept");
            assert_eq!(r.missing, 0);
        } else {
            assert_eq!(env.tier_of(last), None, "{r:?}");
            assert_eq!(r.missing, 1);
        }
        assert_eq!(
            (snapshot(&env.hot), snapshot(&env.arch)),
            snap,
            "files untouched in every case (cap {cap})"
        );
    }
    drop((env, last));
}

#[test]
fn the_walk_holds_one_camera_day_directory_of_rows_at_a_time() {
    let env = Env::new();
    for cam in ["cam-1", "cam-2"] {
        for n in [0, 1, 1000] {
            env.add(cam, n, 5000, Tier::Hot);
        }
    }
    env.index.faults.lock().unwrap().list_ranges.clear();
    let out = startup(&env);
    assert_eq!(out.report, ReconcileReport::default());
    let ranges = env.index.faults.lock().unwrap().list_ranges.clone();
    assert_eq!(ranges.len(), 4, "one listing per (camera, day): {ranges:?}");
    for (from, to) in ranges {
        assert_eq!(to - from, 86_400_000, "a window is exactly one day");
        assert_eq!(from.rem_euclid(86_400_000), 0, "aligned to a UTC day");
    }
}

#[test]
fn hostile_components_in_well_formed_names_never_panic_and_are_left() {
    let env = Env::new();
    let names = [
        "cam-1/2023-11-14/aé1234-042.mp4",
        "cam-1/2023-11-14/00é000-042.mp4",
        "cam-1/2023-11-14/000000-04é.mp4",
        "cam-1/2023-11-14/000000-042.mp4é",
        "cam-1/2023-11-1é/000000-042.mp4",
        "cam-1/2023-11-14/\u{202e}000000-042.mp4",
        "caé-1/2023-11-14/000000-042.mp4",
        "cam-1/２０２３-11-14/000000-042.mp4",
        "cam-1/2023-11-14/０００００００-042.mp4",
    ];
    for n in names {
        put(&env.hot, n, &good());
    }
    let long = format!("cam-1/2023-11-14/{}.mp4", "9".repeat(240));
    put(&env.hot, &long, &good());
    let before = snapshot(&env.hot);
    let out = startup(&env);
    assert_eq!(
        out.report.adopted + out.report.quarantined,
        0,
        "{:?}",
        out.report
    );
    assert!(out.report.unknown_left >= 8, "{:?}", out.report);
    assert_eq!(snapshot(&env.hot), before);
}

// ---- the adoption parser (untrusted input) ---------------------------------------------------------

fn hostile() -> Vec<(&'static str, Vec<u8>)> {
    let g = good();
    let box_size = |off: usize, size: u32| {
        let mut v = g.clone();
        v[off..off + 4].copy_from_slice(&size.to_be_bytes());
        v
    };
    // `good()` starts with ftyp (21 bytes), then moov.
    let ftyp_len = 8 + 12;
    let moov_len = u32::from_be_bytes(g[ftyp_len..ftyp_len + 4].try_into().unwrap()) as usize;
    let mut trailing = g.clone();
    trailing.extend_from_slice(&[0, 0, 0]);
    let mut largesize = g.clone();
    largesize[ftyp_len..ftyp_len + 4].copy_from_slice(&1_u32.to_be_bytes());
    let mut huge_moov = vec![];
    {
        // A `moov` whose payload is one byte over the 1 MiB read cap.
        let payload = vec![0_u8; usize::try_from(MAX_PAYLOAD_LEN).unwrap() + 1];
        let size = u32::try_from(payload.len() + 8).unwrap();
        huge_moov.extend_from_slice(&g[..ftyp_len]);
        huge_moov.extend_from_slice(&size.to_be_bytes());
        huge_moov.extend_from_slice(b"moov");
        huge_moov.extend_from_slice(&payload);
        huge_moov.extend_from_slice(&g[ftyp_len + moov_len..]);
    }
    // A `trun` that declares 0xFFFFFFFF samples in a tiny payload.
    let mut many = g.clone();
    let pos = many
        .windows(4)
        .position(|w| w == b"trun")
        .expect("the fixture has a trun");
    many[pos + 8..pos + 12].copy_from_slice(&u32::MAX.to_be_bytes());
    // One sample of 601 s.
    let long = mp4(&[&[90_000 * 601]]);
    vec![
        ("empty file", vec![]),
        ("garbage", pattern(300)),
        ("size field 0", box_size(ftyp_len, 0)),
        ("size field 4", box_size(ftyp_len, 4)),
        ("size field 7", box_size(ftyp_len, 7)),
        ("largesize", largesize),
        ("moov larger than the file", box_size(ftyp_len, u32::MAX)),
        ("trailing partial box", trailing),
        ("truncated mid mdat", g[..g.len() - 5].to_vec()),
        ("moov over 1 MiB", huge_moov),
        ("sample count beyond the payload", many),
        ("601 s of media", long),
        ("no fragment", g[..ftyp_len + moov_len].to_vec()),
        (
            "no moov",
            [g[..ftyp_len].to_vec(), g[ftyp_len + moov_len..].to_vec()].concat(),
        ),
        ("only a ftyp", g[..ftyp_len].to_vec()),
        ("moof without mdat", g[..g.len() - 48].to_vec()),
    ]
}

#[test]
fn every_hostile_file_without_a_row_is_quarantined_never_adopted_never_deleted() {
    for (what, bytes) in hostile() {
        for tier in [Tier::Hot, Tier::Archive] {
            let env = Env::new();
            let root = if tier == Tier::Hot {
                &env.hot
            } else {
                &env.arch
            };
            let rel = Env::rel("cam-1", 0);
            put(root, &rel, &bytes);
            let out = startup(&env);
            assert_eq!(
                out.report.quarantined, 1,
                "{what} ({tier:?}): {:?}",
                out.report
            );
            assert_eq!(out.report.adopted, 0, "{what}");
            assert!(env.rows_of("cam-1").is_empty(), "{what}: no row");
            assert!(!root.join(&rel).exists(), "{what}: moved away");
            assert_eq!(
                Env::quarantined(root),
                vec![bytes.clone()],
                "{what}: kept byte for byte"
            );
        }
    }
}

#[test]
fn a_file_over_one_gib_is_quarantined_not_walked() {
    let env = Env::new();
    let rel = Env::rel("cam-1", 0);
    let p = put(&env.hot, &rel, &good());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&p)
        .unwrap()
        .set_len(MAX_FILE_LEN + 1)
        .unwrap();
    let out = startup(&env);
    assert_eq!(
        (out.report.quarantined, out.report.adopted),
        (1, 0),
        "{:?}",
        out.report
    );
    assert!(!p.exists());
}

#[test]
fn every_prefix_of_a_good_file_is_refused_without_a_panic() {
    let g = mp4(&[&[3000, 3000], &[3000]]);
    // The one prefix that is a file again: it ends exactly after the first complete
    // `moof` + `mdat` pair (the property fMP4 is chosen for). Computed from the builder.
    let first_fragment = mp4(&[&[3000, 3000]]).len();
    for cut in 0..g.len() {
        let env = Env::new();
        let rel = Env::rel("cam-1", 0);
        put(&env.hot, &rel, &g[..cut]);
        let out = startup(&env);
        if cut == first_fragment {
            assert_eq!(out.report.adopted, 1, "prefix {cut}");
            assert_eq!(env.find("cam-1", 0).unwrap().record.frame_count, 2);
        } else {
            assert_eq!(out.report.adopted, 0, "prefix {cut}");
            assert_eq!(out.report.quarantined, 1, "prefix {cut}");
        }
    }
    // The whole file is adopted: two fragments, three samples.
    let env = Env::new();
    put(&env.hot, &Env::rel("cam-1", 0), &g);
    assert_eq!(startup(&env).report.adopted, 1);
    assert_eq!(env.find("cam-1", 0).unwrap().record.frame_count, 3);
}

#[test]
fn durations_are_ticks_rounded_up_to_ms_with_a_minimum_of_one_and_the_column_bound() {
    // (fragments of sample durations in ticks, expected duration_ms)
    let cases: [(&[&[u32]], u64); 8] = [
        (&[&[1]], 1),                     // min 1
        (&[&[89]], 1),                    // 0.99 ms rounds up
        (&[&[90]], 1),                    // exactly 1 ms
        (&[&[91]], 2),                    // just over
        (&[&[90_000]], 1000),             // exactly one second
        (&[&[90_001]], 1001),             // one tick over rounds up
        (&[&[3000, 3000], &[3000]], 100), // summed across fragments
        (&[&[54_000_000]], 600_000),      // the column's maximum, exactly
    ];
    for (frags, ms) in cases {
        let env = Env::new();
        put(&env.hot, &Env::rel("cam-1", 0), &mp4(frags));
        assert_eq!(startup(&env).report.adopted, 1, "{frags:?}");
        assert_eq!(
            env.find("cam-1", 0).unwrap().record.duration_ms,
            ms,
            "{frags:?}"
        );
    }
    // One tick above the column's `CHECK` (600,001 ms): not adoptable, quarantined.
    let env = Env::new();
    put(&env.hot, &Env::rel("cam-1", 0), &mp4(&[&[54_000_001]]));
    let out = startup(&env);
    assert_eq!((out.report.adopted, out.report.quarantined), (0, 1));
}

#[test]
fn an_adoption_insert_failure_is_retried_a_bounded_number_of_times_then_quarantines() {
    for (failures, adopted, inserts) in [(0, 1, 1), (1, 1, 2), (2, 1, 3), (3, 0, 3), (50, 0, 3)] {
        let env = Env::new();
        let p = put(&env.hot, &Env::rel("cam-1", 0), &good());
        env.index.faults.lock().unwrap().insert_failures = failures;
        let out = startup(&env);
        let r = out.report;
        assert_eq!(r.adopted, adopted, "{failures} failures: {r:?}");
        assert_eq!(
            env.index.faults.lock().unwrap().inserts,
            inserts,
            "bounded, never an unbounded loop"
        );
        if adopted == 0 {
            assert_eq!(r.quarantined, 1, "{r:?}");
            assert_eq!(r.index_errors, 1);
            assert!(r.health_error());
            assert!(!p.exists());
            assert_eq!(Env::quarantined(&env.hot), vec![good()]);
        } else {
            assert!(p.exists());
        }
    }
}

// ---- error paths: one test per way a step can fail ---------------------------------------------------

fn faulty(env: &Env, fault: Fault) -> super::matrix::Loop {
    build(env, Some(fault)).0
}

#[test]
fn a_directory_that_cannot_be_listed_is_unverified_and_nothing_in_it_is_touched() {
    let env = Env::new();
    put(&env.hot, "cam-1/2023-11-14/221320-000.mp4.part", b"p");
    put(&env.hot, &Env::rel("cam-1", 1), &good());
    let id = env.row("cam-1", 2, 5000, Tier::Hot);
    let before = snapshot(&env.hot);
    // List 1 is the root, 2 the camera, 3 the day directory.
    let mut lp = faulty(&env, Fault::once(Op::List(Tier::Hot), 3));
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(out.report.unverified, 1, "{:?}", out.report);
    assert!(out.report.hot_unverified);
    assert_eq!(
        out.report.part_deleted + out.report.adopted + out.report.missing,
        0
    );
    assert_eq!(snapshot(&env.hot), before);
    assert_eq!(
        env.tier_of(id),
        Some(Tier::Hot),
        "a row of that directory is kept"
    );
}

#[test]
fn an_open_error_other_than_enoent_leaves_the_key_unverified() {
    // Hot open fails on a (archive, valid) row: no conclusion, nothing changes.
    for (row, tier_of_file, op) in [
        (Tier::Archive, Tier::Archive, Op::Open(Tier::Hot)),
        (Tier::Hot, Tier::Hot, Op::Open(Tier::Archive)),
        (Tier::Hot, Tier::Hot, Op::Open(Tier::Hot)),
    ] {
        let env = Env::new();
        let id = env.add("cam-1", 0, 5000, tier_of_file);
        assert_eq!(row, tier_of_file);
        let before = (snapshot(&env.hot), snapshot(&env.arch));
        let mut lp = faulty(&env, Fault::once(op, 1));
        let out = lp.reconcile_startup().unwrap();
        assert_eq!(out.report.unverified, 1, "{op:?}: {:?}", out.report);
        assert_eq!(
            out.report.missing + out.report.quarantined + out.report.rolled_back,
            0
        );
        assert_eq!(env.tier_of(id), Some(row));
        assert_eq!((snapshot(&env.hot), snapshot(&env.arch)), before, "{op:?}");
    }
}

#[test]
fn a_regular_file_planted_in_place_of_a_directory_is_not_enoent() {
    // `cam-1` on the archive is a regular file: opening below it is ENOTDIR, not ENOENT, so the
    // archive copy of the row is unknown and the row is neither dropped nor changed.
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    std::fs::write(env.arch.join("cam-1"), b"x").unwrap();
    let out = startup(&env);
    assert_eq!(out.report.unverified, 1, "{:?}", out.report);
    assert_eq!(out.report.unknown_left, 1, "the planted file is not ours");
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
}

#[test]
fn a_failed_quarantine_keeps_the_file_and_the_row() {
    let env = Env::new();
    let id = env.row("cam-1", 0, 5000, Tier::Hot);
    let h = put(&env.hot, &Env::rel("cam-1", 0), &pattern(9));
    let mut lp = faulty(&env, Fault::once(Op::Quarantine(Tier::Hot), 1));
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(out.report.quarantined, 0);
    assert_eq!(out.report.unverified, 1, "{:?}", out.report);
    assert!(h.exists(), "never deleted");
    assert_eq!(
        env.tier_of(id),
        Some(Tier::Hot),
        "the row is dropped only after the quarantine"
    );
}

#[test]
fn an_exhausted_quarantine_bound_leaves_the_file_in_place_and_counts_it_unverified() {
    let env = Env::new();
    let rel = Env::rel("cam-1", 0);
    let name = rel.rsplit('/').next().unwrap().to_owned();
    let h = put(&env.hot, &rel, b"corrupt");
    let q = "_quarantine/cam-1/2023-11-14";
    put(&env.hot, &format!("{q}/{name}"), b"q0");
    for i in 1..=1000 {
        put(&env.hot, &format!("{q}/{name}.{i}"), b"q");
    }
    let out = startup(&env);
    assert_eq!(out.report.quarantined, 0, "{:?}", out.report);
    assert_eq!(out.report.unverified, 1);
    assert_eq!(
        std::fs::read(&h).unwrap(),
        b"corrupt",
        "nothing is overwritten or deleted"
    );
}

#[test]
fn a_failed_index_write_leaves_files_and_row_as_found() {
    // set_tier fails on a roll forward: both files stay, the row stays hot.
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    put(&env.arch, &Env::rel("cam-1", 0), &pattern(5000));
    env.index.faults.lock().unwrap().set_tier = true;
    let out = startup(&env);
    assert_eq!(
        (out.report.index_errors, out.report.unverified),
        (1, 1),
        "{:?}",
        out.report
    );
    assert_eq!(out.report.rolled_forward + out.report.duplicates_deleted, 0);
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    assert!(env.hot_file("cam-1", 0).exists() && env.arch_file("cam-1", 0).exists());
    // delete fails on a missing row: the row stays.
    let env = Env::new();
    let id = env.row("cam-1", 0, 5000, Tier::Hot);
    env.index.faults.lock().unwrap().delete = true;
    let out = startup(&env);
    assert_eq!(
        (out.report.index_errors, out.report.missing),
        (1, 0),
        "{:?}",
        out.report
    );
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    // delete fails after a quarantine: the file is in quarantine, the row stays (a later pass
    // sees (hot, none, none) and drops it).
    let env = Env::new();
    let id = env.row("cam-1", 0, 5000, Tier::Hot);
    put(&env.hot, &Env::rel("cam-1", 0), &pattern(9));
    env.index.faults.lock().unwrap().delete = true;
    let out = startup(&env);
    assert_eq!(out.report.quarantined, 1);
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
}

#[test]
fn a_row_listing_failure_leaves_the_directory_unverified() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let orphan = put(&env.hot, &Env::rel("cam-1", 1), &good());
    env.index.faults.lock().unwrap().list = true;
    let out = startup(&env);
    assert_eq!(
        (out.report.index_errors, out.report.unverified),
        (1, 1),
        "{:?}",
        out.report
    );
    assert!(out.report.health_error());
    env.index.faults.lock().unwrap().list = false;
    assert!(orphan.exists());
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    assert!(env.find("cam-1", 1).is_none());
}

#[test]
fn a_failed_row_read_in_the_row_only_phase_changes_nothing() {
    for (get, oldest) in [(true, false), (false, true)] {
        let env = Env::new();
        let id = env.row("cam-1", 0, 5000, Tier::Hot);
        {
            let mut f = env.index.faults.lock().unwrap();
            f.get = get;
            f.oldest = oldest;
        }
        let out = startup(&env);
        assert!(out.report.index_errors >= 1, "{:?}", out.report);
        assert_eq!(out.report.missing, 0);
        env.index.faults.lock().unwrap().get = false;
        assert_eq!(env.tier_of(id), Some(Tier::Hot));
    }
}

#[test]
fn a_failed_fsync_before_an_index_write_stops_the_cell() {
    // (hot, valid, valid): the archive file's fsync fails, so the row is not pointed at it and
    // the hot copy is not deleted.
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    put(&env.arch, &Env::rel("cam-1", 0), &pattern(5000));
    let mut lp = faulty(&env, Fault::once(Op::SyncSource, 1));
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(out.report.unverified, 1, "{:?}", out.report);
    assert_eq!(out.report.rolled_forward + out.report.duplicates_deleted, 0);
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    assert!(env.hot_file("cam-1", 0).exists());
    // The directory's fsync failing stops an adoption too: no row, the file stays (not
    // quarantined: it is valid).
    let env = Env::new();
    let p = put(&env.hot, &Env::rel("cam-1", 0), &good());
    let mut lp = faulty(&env, Fault::once(Op::SyncDir(Tier::Hot), 1));
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(
        (out.report.adopted, out.report.unverified),
        (0, 1),
        "{:?}",
        out.report
    );
    assert!(p.exists() && Env::quarantined(&env.hot).is_empty());
    assert!(env.find("cam-1", 0).is_none());
}

#[test]
fn a_read_error_while_parsing_is_no_conclusion_and_never_quarantines() {
    let env = Env::new();
    let p = put(&env.hot, &Env::rel("cam-1", 0), &good());
    let fault = Fault {
        sticky: true,
        ..Fault::once(Op::Read, 1)
    };
    let mut lp = faulty(&env, fault);
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(out.report.unverified, 1, "{:?}", out.report);
    assert_eq!(out.report.quarantined + out.report.adopted, 0);
    assert!(p.exists());
}

// ---- crash table: every row of section 7's table, built by the real mover ------------------------------

#[test]
fn every_crash_row_of_the_move_table_recovers_to_one_file_on_the_rows_tier() {
    struct Row {
        what: &'static str,
        fault: Option<Fault>,
        index_set_tier: bool,
        // The row's tier before recovery, and what recovery reports.
        before: Tier,
        part_deleted: u32,
        rolled_forward: u32,
        duplicates: u32,
        after: Tier,
    }
    let a = Tier::Archive;
    let dead = |op, nth| {
        Some(Fault {
            dead: true,
            ..Fault::once(op, nth)
        })
    };
    let rows = [
        Row {
            what: "before M3",
            fault: dead(Op::Mkdir(a), 1),
            index_set_tier: false,
            before: Tier::Hot,
            part_deleted: 0,
            rolled_forward: 0,
            duplicates: 0,
            after: Tier::Hot,
        },
        Row {
            what: "during M3/M4, before M5",
            fault: dead(Op::Write, 1),
            index_set_tier: false,
            before: Tier::Hot,
            part_deleted: 1,
            rolled_forward: 0,
            duplicates: 0,
            after: Tier::Hot,
        },
        Row {
            what: "after M5, before M6",
            fault: dead(Op::Rename, 1),
            index_set_tier: false,
            before: Tier::Hot,
            part_deleted: 1,
            rolled_forward: 0,
            duplicates: 0,
            after: Tier::Hot,
        },
        Row {
            what: "after M6, before M7",
            fault: dead(Op::SyncDir(a), 3),
            index_set_tier: false,
            before: Tier::Hot,
            part_deleted: 0,
            rolled_forward: 1,
            duplicates: 1,
            after: a,
        },
        Row {
            what: "after M7, before M8",
            fault: None,
            index_set_tier: true,
            before: Tier::Hot,
            part_deleted: 0,
            rolled_forward: 1,
            duplicates: 1,
            after: a,
        },
        Row {
            what: "after M8, before M9",
            fault: dead(Op::Unlink(Tier::Hot), 1),
            index_set_tier: false,
            before: a,
            part_deleted: 0,
            rolled_forward: 0,
            duplicates: 1,
            after: a,
        },
        Row {
            what: "after M9",
            fault: None,
            index_set_tier: false,
            before: a,
            part_deleted: 0,
            rolled_forward: 0,
            duplicates: 0,
            after: a,
        },
    ];
    for row in rows {
        let env = Env::new();
        let id = env.add("cam-1", 0, 5000, Tier::Hot);
        env.index.faults.lock().unwrap().set_tier = row.index_set_tier;
        let (lp, _) = build(&env, row.fault);
        let _ = lp.move_now(id, true);
        env.index.faults.lock().unwrap().set_tier = false;
        assert_eq!(
            env.tier_of(id),
            Some(row.before),
            "{}: the crash state",
            row.what
        );
        // A new process: reconcile.
        let out = startup(&env);
        let r = out.report;
        assert_eq!(
            (r.part_deleted, r.rolled_forward, r.duplicates_deleted),
            (row.part_deleted, row.rolled_forward, row.duplicates),
            "{}: {r:?}",
            row.what
        );
        assert_eq!(
            (r.quarantined, r.size_mismatch, r.missing, r.unverified),
            (0, 0, 0, 0),
            "{}",
            row.what
        );
        // The post-condition: the row names the tier that holds its one file; no `.part`.
        assert_eq!(env.tier_of(id), Some(row.after), "{}", row.what);
        let (h, ar) = (
            env.hot_file("cam-1", 0).exists(),
            env.arch_file("cam-1", 0).exists(),
        );
        assert_eq!(
            (h, ar),
            (row.after == Tier::Hot, row.after == a),
            "{}: exactly one file",
            row.what
        );
        let part = env.arch_file("cam-1", 0).with_extension("mp4.part");
        assert!(!part.exists(), "{}", row.what);
        assert_eq!(
            std::fs::read(if h {
                env.hot_file("cam-1", 0)
            } else {
                env.arch_file("cam-1", 0)
            })
            .unwrap(),
            pattern(5000),
            "{}",
            row.what
        );
        // And it is a fixed point: a second pass finds nothing to do.
        assert_eq!(
            startup(&env).report,
            ReconcileReport::default(),
            "{}",
            row.what
        );
        assert_eq!(
            env.find("cam-1", 0).map(|r| r.id),
            Some(id),
            "{}: the id is kept",
            row.what
        );
    }
}

// ---- ids, reports, seeds, wiring -----------------------------------------------------------------------

#[test]
fn ids_are_never_reassigned_while_a_row_exists_and_a_dropped_id_is_not_reused() {
    let env = Env::new();
    let keep_hot = env.add("cam-1", 0, 5000, Tier::Hot);
    let keep_arch = env.add("cam-1", 1, 5000, Tier::Archive);
    let dropped = env.row("cam-1", 2, 5000, Tier::Hot);
    let flipped = env.add("cam-1", 3, 5000, Tier::Hot);
    put(&env.arch, &Env::rel("cam-1", 3), &pattern(5000));
    std::fs::remove_file(env.hot_file("cam-1", 3)).unwrap();
    put(&env.hot, &Env::rel("cam-1", 4), &good());
    let out = startup(&env);
    assert_eq!(
        (
            out.report.missing,
            out.report.rolled_forward,
            out.report.adopted
        ),
        (1, 1, 1)
    );
    assert_eq!(env.tier_of(keep_hot), Some(Tier::Hot));
    assert_eq!(env.tier_of(keep_arch), Some(Tier::Archive));
    assert_eq!(env.tier_of(flipped), Some(Tier::Archive));
    assert_eq!(env.tier_of(dropped), None);
    let adopted = env.find("cam-1", 4).unwrap().id;
    assert!(
        adopted.as_u64() > dropped.as_u64() && adopted.as_u64() > flipped.as_u64(),
        "AUTOINCREMENT: a new id is never an old one"
    );
}

#[test]
fn reports_carry_counts_and_flags_only_never_a_name() {
    let env = Env::new();
    put(&env.hot, &Env::rel("cam-1", 0), &pattern(9));
    put(&env.hot, "secret-cam/2023-11-14/note.txt", b"x");
    let out = startup(&env);
    let text = format!("{out:?}");
    for needle in ["cam-1", "secret", "2023", "221320", ".mp4", "/"] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }
}

#[test]
fn the_newest_key_per_camera_covers_files_orphans_and_the_quarantine() {
    let env = Env::new();
    put(&env.hot, &Env::rel("cam-1", 2), &good());
    put(&env.arch, &Env::rel("cam-1", 4), &pattern(9));
    // Already in the quarantine from an earlier run: newer than everything else.
    let q = Env::rel("cam-1", 9);
    put(&env.hot, &format!("_quarantine/{q}.2"), b"old evidence");
    put(&env.hot, &Env::rel("cam-2", 1), &good());
    let out = startup(&env);
    let cam1: wardenlens_core::camera::CameraId = "cam-1".parse().unwrap();
    let cam2: wardenlens_core::camera::CameraId = "cam-2".parse().unwrap();
    assert_eq!(out.newest.get(&cam1).unwrap().as_i64(), T0 + 9 * 60_000);
    assert_eq!(out.newest.get(&cam2).unwrap().as_i64(), T0 + 60_000);
    assert!(out.newest.get(&"cam-3".parse().unwrap()).is_none());
}

#[test]
fn the_pass_runs_once_per_return_and_the_hold_ends_with_it() {
    let env = Env::new();
    unmount(&env);
    env.add("cam-1", 0, 5000, Tier::Hot);
    let (mut lp, _) = build(&env, None);
    lp.reconcile_startup().unwrap();
    assert!(lp.tick(late()).unwrap().returned.is_none());
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    let r = lp.tick(late()).unwrap();
    assert!(r.archive_returned && r.returned.is_some() && r.moved == 0);
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive_returned && r.returned.is_none());
    assert_eq!(r.moved, 1);
    // Away and back again: a second return, a second pass.
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
    assert!(lp.tick(late()).unwrap().returned.is_none());
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    assert!(lp.tick(late()).unwrap().returned.is_some());
}

#[test]
fn a_healthy_archive_at_start_up_is_not_a_return_and_the_pass_does_not_run() {
    let env = Env::new();
    env.add("cam-1", 0, 5000, Tier::Hot);
    let (mut lp, _) = build(&env, None);
    let out = lp.reconcile_startup().unwrap();
    assert!(!out.report.archive_unavailable);
    let r = lp.tick(late()).unwrap();
    assert!(!r.archive_returned && r.returned.is_none());
    assert_eq!(r.moved, 1);
}

#[test]
fn a_failed_fsync_keeps_the_hot_twin_of_an_archive_row() {
    // (archive, valid, valid): H is deleted only after A is durable.
    let env = Env::new();
    env.add("cam-1", 0, 5000, Tier::Archive);
    put(&env.hot, &Env::rel("cam-1", 0), &pattern(5000));
    let mut lp = faulty(&env, Fault::once(Op::SyncSource, 1));
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(
        (out.report.duplicates_deleted, out.report.unverified),
        (0, 1),
        "{:?}",
        out.report
    );
    assert!(env.hot_file("cam-1", 0).exists());
}

#[test]
fn an_unusable_hot_volume_is_an_error_not_a_pass() {
    let env = Env::new();
    env.set_cap("hot", 0);
    let (mut lp, _) = build(&env, None);
    assert!(matches!(
        lp.reconcile_startup(),
        Err(crate::TickError::HotVolume(_))
    ));
}

#[test]
fn an_archive_root_that_cannot_be_listed_marks_the_archive_unverified() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Archive);
    let before = snapshot(&env.arch);
    let mut lp = faulty(&env, Fault::once(Op::List(Tier::Archive), 1));
    let out = lp.reconcile_startup().unwrap();
    assert!(
        out.report.archive_unverified && !out.report.hot_unverified,
        "{:?}",
        out.report
    );
    assert_eq!(out.report.unverified, 1);
    assert_eq!(env.tier_of(id), Some(Tier::Archive));
    assert_eq!(snapshot(&env.arch), before);
}

#[test]
fn the_returned_pass_never_follows_a_symlink_or_touches_anything_outside_the_archive() {
    let env = Env::new();
    unmount(&env);
    let outside = env.tmp.path().join("outside");
    put(&outside, "2023-11-14/221320-000.mp4", &good());
    put(&outside, "2023-11-14/221320-001.mp4.part", b"keep");
    let outside_before = snapshot(&outside);
    let (mut lp, _) = build(&env, None);
    lp.set_initial_archive_state(false);
    let covered = env.tmp.path().join("covered");
    std::fs::rename(&env.arch, &covered).unwrap();
    std::fs::create_dir(&env.arch).unwrap();
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    // A symlinked camera directory, a symlinked day directory and a symlinked segment.
    std::os::unix::fs::symlink(&outside, env.arch.join("cam-8")).unwrap();
    std::fs::create_dir_all(env.arch.join("cam-9")).unwrap();
    std::os::unix::fs::symlink(
        outside.join("2023-11-14"),
        env.arch.join("cam-9/2023-11-14"),
    )
    .unwrap();
    put(&env.arch, "cam-7/2023-11-14/221320-002.mp4.keep", b"x");
    std::os::unix::fs::symlink(
        outside.join("2023-11-14/221320-000.mp4"),
        env.arch.join("cam-7/2023-11-14/221320-000.mp4"),
    )
    .unwrap();
    let arch_before = snapshot(&env.arch);
    let r = lp.tick(now()).unwrap();
    let pass = r.returned.expect("the pass ran");
    assert_eq!(
        pass.adopted + pass.quarantined + pass.part_deleted,
        0,
        "{pass:?}"
    );
    assert!(pass.unknown_left >= 3, "{pass:?}");
    assert_eq!(snapshot(&outside), outside_before);
    assert_eq!(snapshot(&env.arch), arch_before);
    assert!(env.rows_of("cam-7").is_empty() && env.rows_of("cam-8").is_empty());
}

// ---- paging, the row bound, gating counts, the hold (fix round 2) ---------------------------------

/// More rows in one `(camera, day)` than one `list` page (`MAX_LIST_LIMIT`, 1,000), and a row of
/// the previous day that overlaps the day's start, so `list` returns it too.
fn crowded_day(env: &Env, tier: Tier, rows: i64) -> Vec<wardenlens_core::storage::SegmentId> {
    let mut ids = Vec::new();
    for n in 0..rows {
        ids.push(env.add("cam-1", -rows + n, 100, tier));
    }
    let day_start = T0 - T0.rem_euclid(86_400_000);
    let first = day_start - 500;
    let cam: wardenlens_core::camera::CameraId = "cam-1".parse().unwrap();
    let rec = wardenlens_core::recording::SegmentRecord::new(
        cam.clone(),
        wardenlens_core::time::UnixMs::new(first).unwrap(),
        1000,
        100,
        5,
    );
    let root = if tier == Tier::Hot {
        &env.hot
    } else {
        &env.arch
    };
    put(
        root,
        &wardenlens_core::recording::RelPath::new(&cam, rec.started_at_ms).to_string(),
        &pattern(100),
    );
    let mut idx = env.index.clone();
    ids.push(wardenlens_core::storage::SegmentIndex::insert(&mut idx, &rec, tier).unwrap());
    ids
}

#[test]
fn more_than_one_page_of_hot_rows_in_a_day_is_paged_through_at_start_up() {
    let env = Env::new();
    let ids = crowded_day(&env, Tier::Hot, 1001);
    let rows_before = env.rows_of("cam-1");
    let before = snapshot(&env.hot);
    let out = startup(&env);
    assert_eq!(out.report, ReconcileReport::default());
    assert_eq!(snapshot(&env.hot), before);
    assert_eq!(env.rows_of("cam-1"), rows_before);
    assert_eq!(rows_before.len(), ids.len());
}

#[test]
fn more_than_one_page_of_archive_rows_in_a_day_is_paged_through_in_the_returned_pass() {
    let env = Env::new();
    unmount(&env);
    let (mut lp, _) = build(&env, None);
    lp.set_initial_archive_state(false);
    let covered = env.tmp.path().join("covered");
    std::fs::rename(&env.arch, &covered).unwrap();
    std::fs::create_dir(&env.arch).unwrap();
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    crowded_day(&env, Tier::Archive, 1001);
    let rows_before = env.rows_of("cam-1");
    let before = snapshot(&env.arch);
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.returned.expect("ran"), ReconcileReport::default());
    assert_eq!(snapshot(&env.arch), before);
    assert_eq!(env.rows_of("cam-1"), rows_before);
}

#[test]
fn the_per_day_row_bound_is_exact_and_exceeding_it_changes_nothing() {
    // Six rows in one day: bound 7 and 6 hold them all, 5 and 0 do not.
    for (bound, capped) in [(7, false), (6, false), (5, true), (0, true)] {
        let env = Env::new();
        for n in 0..5 {
            env.add("cam-1", n, 100, Tier::Hot);
        }
        // A row without a file (`missing` when seen) and an orphan file (adopted when seen).
        let gone = env.row("cam-1", 5, 100, Tier::Hot);
        let orphan = put(&env.hot, &Env::rel("cam-1", 7), &good());
        let cfg = env.cfg().with_walk_max_dir_rows(bound);
        let (mut lp, _) = crate::Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
        let before = snapshot(&env.hot);
        let r = lp.reconcile_startup().unwrap().report;
        assert_eq!(r.walk_cap_exceeded, capped, "bound {bound}: {r:?}");
        assert_eq!(r.health_error(), capped);
        if capped {
            assert_eq!(env.tier_of(gone), Some(Tier::Hot), "bound {bound}");
            assert_eq!(snapshot(&env.hot), before, "bound {bound}: files untouched");
            assert_eq!(r.adopted + r.missing, 0, "bound {bound}");
            assert!(orphan.exists());
            assert!(env.find("cam-1", 7).is_none());
            assert!(r.unverified > 0);
        } else {
            assert_eq!(env.tier_of(gone), None, "bound {bound}");
            assert_eq!((r.missing, r.adopted), (1, 1), "bound {bound}");
        }
    }
}

#[test]
fn a_hot_row_out_of_the_returned_passs_scope_adds_nothing_to_its_counts() {
    let env = Env::new();
    unmount(&env);
    // A hot row with a wrong-size hot file, one whose hot name is a FIFO, one with a symlink.
    env.row("cam-1", 0, 5000, Tier::Hot);
    put(&env.hot, &Env::rel("cam-1", 0), &pattern(9));
    env.row("cam-1", 1, 5000, Tier::Hot);
    rustix::fs::mknodat(
        rustix::fs::CWD,
        env.hot.join(Env::rel("cam-1", 1)),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    env.row("cam-1", 2, 5000, Tier::Hot);
    std::os::unix::fs::symlink("/nonexistent", env.hot.join(Env::rel("cam-1", 2))).unwrap();
    let (mut lp, _) = build(&env, None);
    lp.set_initial_archive_state(false);
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.returned.expect("ran"), ReconcileReport::default());
}

#[test]
fn the_row_only_phase_reads_no_row_that_a_directory_already_handled() {
    let env = Env::new();
    for n in 0..5 {
        env.add("cam-1", n, 100, Tier::Hot);
    }
    env.row("cam-2", 0, 100, Tier::Hot);
    env.index.faults.lock().unwrap().gets = 0;
    let out = startup(&env);
    assert_eq!(out.report.missing, 1);
    assert_eq!(
        env.index.faults.lock().unwrap().gets,
        1,
        "only the row of the directory that does not exist is read"
    );
}

#[test]
fn a_returned_pass_that_hit_the_cap_or_an_index_error_keeps_the_hold_and_runs_again() {
    for index_error in [false, true] {
        let env = Env::new();
        unmount(&env);
        env.add("cam-1", 0, 100, Tier::Hot);
        let cap = if index_error { 1000 } else { 1 };
        let cfg = env.cfg().with_walk_max_entries(cap);
        let (mut lp, _) = crate::Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
        lp.set_initial_archive_state(false);
        std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
        put(&env.arch, &Env::rel("cam-2", 0), &good());
        if index_error {
            env.index.faults.lock().unwrap().list = true;
        }
        let mut last_moved = 0;
        for tick in 1..=3 {
            let r = lp.tick(late()).unwrap();
            let pass = r
                .returned
                .expect("the pass reruns while it could not finish");
            assert!(pass.health_error() || pass.walk_cap_exceeded, "{pass:?}");
            assert!(r.archive_returned, "tick {tick}: the hold stays");
            last_moved += r.moved;
            assert_eq!(
                lp.index_health_error(),
                index_error && tick == 3,
                "tick {tick}: the pass's index errors feed the health counter"
            );
        }
        assert_eq!(last_moved, 0, "no move while the hold stays");
        if index_error {
            // The index recovers: the pass completes and the hold ends.
            env.index.faults.lock().unwrap().list = false;
            let r = lp.tick(late()).unwrap();
            assert_eq!(r.returned.expect("ran").index_errors, 0);
            assert!(!lp.index_health_error());
            assert!(lp.tick(late()).unwrap().moved >= 1);
        }
    }
}
