//! Fault injection at every crash point of the section 7 table (TEST-9: the whole table, in two
//! modes), and the required named tests.

use std::sync::{Arc, Mutex};

use wardenlens_core::storage::Tier;

use super::fault::{Fault, FaultFs, Op, Shared, State, count};
use super::support::{Env, pattern};
use super::support::{FakeUsage, TestIndex};
use crate::{COPY_CHUNK, Outcome, Stage, Storage, StorageLoop};

pub(super) type Loop = StorageLoop<TestIndex, FaultFs, FakeUsage>;

pub(super) fn build(env: &Env, fault: Option<Fault>) -> (Loop, Shared) {
    let state: Shared = Arc::new(Mutex::new(State {
        fault,
        ..State::default()
    }));
    let s2 = Arc::clone(&state);
    let (l, _files) =
        Storage::open_with(env.cfg(), env.index.clone(), env.usage.clone(), move |r| {
            FaultFs::new(r, s2)
        })
        .unwrap();
    (l, state)
}

const BYTES: usize = COPY_CHUNK * 2 + 5;

struct Point {
    name: &'static str,
    fault: Fault,
    outcome: Outcome,
}

fn points() -> Vec<Point> {
    let p = |name, op, nth, outcome| Point {
        name,
        fault: Fault::once(op, nth),
        outcome,
    };
    let af = Outcome::ArchiveFailure;
    let a = Tier::Archive;
    vec![
        p(
            "M1 open of H/R fails",
            Op::Open(Tier::Hot),
            1,
            Outcome::Unverified,
        ),
        p("M2 mkdir camera dir", Op::Mkdir(a), 1, af(Stage::M2)),
        p("M2 mkdir day dir", Op::Mkdir(a), 2, af(Stage::M2)),
        p(
            "M2 fsync parent of camera dir",
            Op::SyncDir(a),
            1,
            af(Stage::M2),
        ),
        p(
            "M2 fsync parent of day dir",
            Op::SyncDir(a),
            2,
            af(Stage::M2),
        ),
        p("M3 unlink stale part", Op::Unlink(a), 1, af(Stage::M3)),
        p("M3 create part", Op::CreatePart, 1, af(Stage::M3)),
        p("M4 write chunk 1", Op::Write, 1, af(Stage::M4Write)),
        p("M4 write chunk 2", Op::Write, 2, af(Stage::M4Write)),
        p("M4 write chunk 3", Op::Write, 3, af(Stage::M4Write)),
        p("M4 read chunk 1", Op::Read, 1, Outcome::SourceQuarantined),
        p("M4 read chunk 3", Op::Read, 3, Outcome::SourceQuarantined),
        p("M5 fsync part", Op::SyncPart, 1, af(Stage::M5)),
        p("M6 rename", Op::Rename, 1, af(Stage::M6)),
        p("M7 fsync archive dir", Op::SyncDir(a), 3, af(Stage::M7)),
        p(
            "M9 unlink hot",
            Op::Unlink(Tier::Hot),
            1,
            Outcome::MovedHotLeft,
        ),
        p(
            "M9 fsync hot dir",
            Op::SyncDir(Tier::Hot),
            1,
            Outcome::Moved,
        ),
    ]
}

/// "At every crash point at least one complete copy exists and the row points at a tier where a
/// complete copy exists" (section 7).
fn assert_hot_authoritative(env: &Env, id: wardenlens_core::storage::SegmentId, what: &str) {
    let want = pattern(BYTES);
    let hot = std::fs::read(env.hot_file("cam-1", 0)).ok();
    let arch = std::fs::read(env.arch_file("cam-1", 0)).ok();
    if let Some(a) = &arch {
        assert_eq!(a, &want, "{what}: A/R is present only when complete");
    }
    if let Some(h) = &hot {
        assert_eq!(h, &want, "{what}: the hot file is never touched");
    }
    match env.tier_of(id) {
        Some(Tier::Hot) => assert!(hot.is_some(), "{what}: row says hot, hot file must exist"),
        Some(Tier::Archive) => assert!(arch.is_some(), "{what}: row says archive, A/R must exist"),
        None => assert!(
            Env::quarantined(&env.hot).contains(&want),
            "{what}: a dropped row keeps its file in quarantine"
        ),
        _ => unreachable!(),
    }
}

#[test]
fn hot_copy_stays_authoritative_on_every_failure() {
    for dead in [false, true] {
        for pt in points() {
            let what = format!("{} (dead={dead})", pt.name);
            let env = Env::new();
            let id = env.add("cam-1", 0, BYTES, Tier::Hot);
            let fault = Fault { dead, ..pt.fault };
            let (lp, state) = build(&env, Some(fault));
            let out = lp.move_now(id, true);
            assert!(state.lock().unwrap().fired, "{what}: the fault fired");
            if !dead {
                assert_eq!(out, pt.outcome, "{what}");
            }
            assert_hot_authoritative(&env, id, &what);
            // The next tick finishes the move whenever the row still says hot.
            if env.tier_of(id) == Some(Tier::Hot) {
                let (again, _) = build(&env, None);
                assert_eq!(again.move_now(id, true), Outcome::Moved, "{what}: recovers");
                assert_eq!(env.tier_of(id), Some(Tier::Archive), "{what}");
                assert_eq!(
                    std::fs::read(env.arch_file("cam-1", 0)).unwrap(),
                    pattern(BYTES)
                );
                assert!(
                    !env.hot_file("cam-1", 0).exists(),
                    "{what}: hot unlinked last"
                );
                assert!(
                    !env.arch_file("cam-1", 0)
                        .with_extension("mp4.part")
                        .exists(),
                    "{what}: no stale part"
                );
            }
        }
    }
}

#[test]
fn index_failure_at_m8_keeps_the_hot_copy_and_a_complete_archive_copy() {
    let env = Env::new();
    let id = env.add("cam-1", 0, BYTES, Tier::Hot);
    env.index.faults.lock().unwrap().set_tier = true;
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::IndexError);
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    assert_hot_authoritative(&env, id, "M8");
    assert!(
        env.arch_file("cam-1", 0).exists(),
        "M7 made it durable first"
    );
    // The index recovers: the stale complete A/R is rolled forward (EEXIST at M6).
    env.index.faults.lock().unwrap().set_tier = false;
    assert_eq!(lp.move_now(id, true), Outcome::Moved);
    assert_eq!(env.tier_of(id), Some(Tier::Archive));
}

#[test]
fn m4_read_failure_leaves_archive_available_and_deletes_no_hot_video() {
    let env = Env::new();
    let ids: Vec<_> = (0..4)
        .map(|n| env.add("cam-1", n, 4096, Tier::Hot))
        .collect();
    let fault = Fault {
        sticky: true,
        ..Fault::once(Op::Read, 1)
    };
    let (mut lp, state) = build(&env, Some(fault));
    for id in &ids {
        assert_eq!(lp.move_now(*id, true), Outcome::SourceQuarantined);
    }
    assert!(state.lock().unwrap().fired);
    // Three read failures in a row are not the archive's fault.
    assert_eq!(lp.move_failures(), 0);
    let r = lp.tick(super::support::now()).unwrap();
    assert!(r.archive.is_available(), "the archive stays available");
    // No hot video was deleted: every file is in quarantine, byte for byte.
    let q = Env::quarantined(&env.hot);
    assert_eq!(q.len(), 4);
    assert!(q.iter().all(|c| *c == pattern(4096)));
    // Nothing was left on the archive.
    assert!(
        !env.arch
            .join("cam-1")
            .join("2023-11-14")
            .join("22132000-000.mp4.part")
            .exists()
    );
}

#[test]
fn stale_complete_archive_copy_at_m6_is_rolled_forward() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    // An earlier attempt left a complete A/R (and its directories) behind.
    let a = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    std::fs::write(&a, pattern(5000)).unwrap();
    let (lp, state) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::Moved);
    assert_eq!(env.tier_of(id), Some(Tier::Archive));
    assert_eq!(
        std::fs::read(&a).unwrap(),
        pattern(5000),
        "the stale copy was kept, not replaced"
    );
    assert!(!env.hot_file("cam-1", 0).exists());
    assert!(
        !a.with_extension("mp4.part").exists(),
        "the .part is deleted"
    );
    // Rolled forward means the stale copy was fsynced before the row changed.
    assert_eq!(count(&state, Op::SyncSource), 1);
}

#[test]
fn stale_wrong_size_archive_copy_at_m6_is_quarantined_and_m6_retried_once() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let a = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    std::fs::write(&a, b"partial").unwrap();
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::Moved);
    assert_eq!(std::fs::read(&a).unwrap(), pattern(5000));
    assert_eq!(
        Env::quarantined(&env.arch),
        vec![b"partial".to_vec()],
        "never deleted"
    );
    // The retry is bounded: when it fails too, that is an M6 failure and the hot copy stays.
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let a = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    std::fs::write(&a, b"partial").unwrap();
    let (lp, state) = build(&env, Some(Fault::once(Op::Rename, 2)));
    assert_eq!(lp.move_now(id, true), Outcome::ArchiveFailure(Stage::M6));
    assert_eq!(count(&state, Op::Rename), 2, "retried exactly once");
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    assert!(env.hot_file("cam-1", 0).exists());
}

#[test]
fn eexist_at_m6_with_an_unquarantinable_stale_copy_is_an_m6_failure() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let a = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    std::fs::write(&a, b"partial").unwrap();
    let (lp, _) = build(&env, Some(Fault::once(Op::Quarantine(Tier::Archive), 1)));
    assert_eq!(lp.move_now(id, true), Outcome::ArchiveFailure(Stage::M6));
    assert_eq!(
        std::fs::read(&a).unwrap(),
        b"partial",
        "nothing was overwritten"
    );
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    assert_eq!(
        std::fs::read(env.hot_file("cam-1", 0)).unwrap(),
        pattern(5000)
    );
}

#[test]
fn a_stale_part_is_unlinked_before_the_new_one_is_created() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let a = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    let part = a.with_extension("mp4.part");
    std::fs::write(
        &part,
        b"stale half copy that is longer than the real one ......",
    )
    .unwrap();
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::Moved);
    assert_eq!(std::fs::read(&a).unwrap(), pattern(5000));
    assert!(!part.exists());
}

#[test]
fn a_planted_symlink_as_part_is_never_followed() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let a = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    let victim = env.tmp.path().join("victim");
    std::fs::write(&victim, b"precious").unwrap();
    std::os::unix::fs::symlink(&victim, a.with_extension("mp4.part")).unwrap();
    let (lp, _) = build(&env, None);
    // The stale entry is unlinked (the link, not its target) and O_EXCL|O_NOFOLLOW creates anew.
    assert_eq!(lp.move_now(id, true), Outcome::Moved);
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
}

#[test]
fn a_symlinked_archive_directory_is_refused_and_counts_as_an_archive_failure() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let outside = env.tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, env.arch.join("cam-1")).unwrap();
    let (lp, _) = build(&env, None);
    let out = lp.move_now(id, true);
    assert!(out.blames_archive(), "{out:?}");
    assert_eq!(
        std::fs::read_dir(&outside).unwrap().count(),
        0,
        "nothing escaped the root"
    );
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
}

#[test]
fn a_hot_file_that_ends_early_is_a_source_problem_not_the_archives() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let fault = Fault {
        eof: true,
        ..Fault::once(Op::Read, 1)
    };
    let (lp, _) = build(&env, Some(fault));
    assert_eq!(lp.move_now(id, true), Outcome::SourceQuarantined);
    assert_eq!(lp.move_failures(), 0);
    assert_eq!(env.tier_of(id), None);
    assert_eq!(Env::quarantined(&env.hot), vec![pattern(5000)]);
    assert!(!env.arch_file("cam-1", 0).exists());
}

#[test]
fn eexist_at_m6_with_an_exhausted_quarantine_bound_is_unverified_and_not_counted() {
    // Amendment: an EEXIST at M6 never counts toward the three failures; when the 1,000 bound is
    // used up the stale file stays in place and the segment is `unverified`.
    let env = Env::new();
    let id = env.add("cam-1", 0, 5000, Tier::Hot);
    let a = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    std::fs::write(&a, b"partial").unwrap();
    let rel = Env::rel("cam-1", 0);
    let q = env.arch.join("_quarantine").join(&rel);
    std::fs::create_dir_all(q.parent().unwrap()).unwrap();
    let name = q.file_name().unwrap().to_str().unwrap().to_owned();
    std::fs::write(&q, b"q").unwrap();
    for i in 1..=1000 {
        std::fs::write(q.parent().unwrap().join(format!("{name}.{i}")), b"q").unwrap();
    }
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::Unverified);
    assert_eq!(std::fs::read(&a).unwrap(), b"partial", "left in place");
    assert!(
        !a.with_extension("mp4.part").exists(),
        "the .part is dropped"
    );
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
}
