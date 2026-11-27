//! M1 for a missing or wrong-size hot file (the section 9 cells for row = hot), non-regular hot
//! files, durability before the only copy, and delete.

use rustix::io::Errno;
use wardenlens_core::storage::Tier;

use super::fault::{Fault, Op};
use super::matrix::build;
use super::support::{Env, pattern};
use crate::{Dropped, Outcome, Skip};

#[derive(Clone, Copy, Debug)]
enum H {
    Missing,
    Wrong,
}
#[derive(Clone, Copy, Debug)]
enum A {
    None,
    Valid,
    Invalid,
    Err,
}

fn setup(h: H, a: A) -> (Env, wardenlens_core::storage::SegmentId) {
    let env = Env::new();
    let id = env.row("cam-1", 0, 5000, Tier::Hot);
    let hp = env.hot_file("cam-1", 0);
    let ap = env.arch_file("cam-1", 0);
    if matches!(h, H::Wrong) {
        std::fs::create_dir_all(hp.parent().unwrap()).unwrap();
        std::fs::write(&hp, pattern(100)).unwrap();
    }
    match a {
        A::None => {}
        A::Valid | A::Invalid => {
            std::fs::create_dir_all(ap.parent().unwrap()).unwrap();
            std::fs::write(&ap, pattern(if matches!(a, A::Valid) { 5000 } else { 7 })).unwrap();
        }
        // `cam-1` is a regular file: opening below it is ENOTDIR, an error that is not ENOENT.
        A::Err => std::fs::write(env.arch.join("cam-1"), b"x").unwrap(),
    }
    (env, id)
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "one row of the section 9 table"
)]
struct Cell {
    h: H,
    a: A,
    out: Outcome,
    row: Option<Tier>,
    hot_kept: bool,
    hot_q: bool,
    arch_kept: bool,
    arch_q: bool,
}

#[test]
fn section_9_cells_for_a_bad_hot_file_every_combination() {
    use Dropped::{Missing as DM, SizeMismatch as DS};
    let c = |h, a, out, row, hot_kept, hot_q, arch_kept, arch_q| Cell {
        h,
        a,
        out,
        row,
        hot_kept,
        hot_q,
        arch_kept,
        arch_q,
    };
    let (arch, hot, none) = (Some(Tier::Archive), Some(Tier::Hot), None);
    let table = [
        c(
            H::Missing,
            A::None,
            Outcome::RowDropped(DM),
            none,
            false,
            false,
            false,
            false,
        ),
        c(
            H::Missing,
            A::Valid,
            Outcome::RolledForward,
            arch,
            false,
            false,
            true,
            false,
        ),
        c(
            H::Missing,
            A::Invalid,
            Outcome::RowDropped(DM),
            none,
            false,
            false,
            false,
            true,
        ),
        c(
            H::Missing,
            A::Err,
            Outcome::Unverified,
            hot,
            false,
            false,
            false,
            false,
        ),
        c(
            H::Wrong,
            A::None,
            Outcome::RowDropped(DS),
            none,
            false,
            true,
            false,
            false,
        ),
        c(
            H::Wrong,
            A::Valid,
            Outcome::RolledForward,
            arch,
            false,
            true,
            true,
            false,
        ),
        c(
            H::Wrong,
            A::Invalid,
            Outcome::RowDropped(DS),
            none,
            false,
            true,
            false,
            true,
        ),
        c(
            H::Wrong,
            A::Err,
            Outcome::Unverified,
            hot,
            true,
            false,
            false,
            false,
        ),
    ];
    for Cell {
        h,
        a,
        out,
        row,
        hot_kept,
        hot_q,
        arch_kept,
        arch_q,
    } in table
    {
        let what = format!("{h:?}/{a:?}");
        let (env, id) = setup(h, a);
        let (lp, _) = build(&env, None);
        assert_eq!(lp.move_now(id, true), out, "{what}");
        assert_eq!(env.tier_of(id), row, "{what}: row");
        assert_eq!(
            env.hot_file("cam-1", 0).exists(),
            hot_kept,
            "{what}: hot file"
        );
        assert_eq!(
            !Env::quarantined(&env.hot).is_empty(),
            hot_q,
            "{what}: hot quarantine"
        );
        if !matches!(a, A::Err) {
            assert_eq!(
                env.arch_file("cam-1", 0).exists(),
                arch_kept,
                "{what}: archive file"
            );
        }
        assert_eq!(
            !Env::quarantined(&env.arch).is_empty(),
            arch_q,
            "{what}: archive quarantine"
        );
        // An invalid file is never deleted: its bytes survive somewhere.
        if matches!(a, A::Invalid) {
            assert_eq!(Env::quarantined(&env.arch), vec![pattern(7)], "{what}");
        }
        if matches!(h, H::Wrong) && !hot_kept {
            assert_eq!(Env::quarantined(&env.hot), vec![pattern(100)], "{what}");
        }
    }
}

#[test]
fn a_bad_hot_file_with_the_archive_unavailable_concludes_nothing_from_the_archive() {
    // Missing: keep the row, unverified.
    let (env, id) = setup(H::Missing, A::None);
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, false), Outcome::Unverified);
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    // Wrong size: H quarantined (it is invalid), row kept, archive not touched.
    let (env, id) = setup(H::Wrong, A::Valid);
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, false), Outcome::Unverified);
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    assert_eq!(Env::quarantined(&env.hot), vec![pattern(100)]);
    assert_eq!(
        std::fs::read(env.arch_file("cam-1", 0)).unwrap(),
        pattern(5000)
    );
    // A good hot file is left alone.
    let env = Env::new();
    let id = env.add("cam-1", 0, 100, Tier::Hot);
    let (lp, _) = build(&env, None);
    assert_eq!(
        lp.move_now(id, false),
        Outcome::Skipped(Skip::ArchiveUnavailable)
    );
    assert!(env.hot_file("cam-1", 0).exists());
}

#[test]
fn non_enoent_errors_on_h_make_the_segment_unverified_and_never_drop_the_row() {
    for errno in [Errno::IO, Errno::ACCESS, Errno::LOOP, Errno::NOTDIR] {
        let env = Env::new();
        let id = env.add("cam-1", 0, 100, Tier::Hot);
        let fault = Fault {
            errno,
            ..Fault::once(Op::Open(Tier::Hot), 1)
        };
        let (lp, _) = build(&env, Some(fault));
        assert_eq!(lp.move_now(id, true), Outcome::Unverified, "{errno:?}");
        assert_eq!(env.tier_of(id), Some(Tier::Hot));
        assert!(env.hot_file("cam-1", 0).exists());
        assert!(!env.arch_file("cam-1", 0).exists());
    }
}

#[test]
fn a_non_regular_hot_file_is_unverified_and_the_archive_is_not_evaluated() {
    // A directory, a FIFO (opened with O_NONBLOCK: never blocks) and a symlink to a valid file.
    for kind in ["dir", "fifo", "symlink"] {
        let env = Env::new();
        let id = env.row("cam-1", 0, 100, Tier::Hot);
        let hp = env.hot_file("cam-1", 0);
        std::fs::create_dir_all(hp.parent().unwrap()).unwrap();
        match kind {
            "dir" => std::fs::create_dir(&hp).unwrap(),
            "fifo" => {
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &hp,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .unwrap();
            }
            _ => {
                let real = env.tmp.path().join("real");
                std::fs::write(&real, pattern(100)).unwrap();
                std::os::unix::fs::symlink(&real, &hp).unwrap();
            }
        }
        // A valid archive copy that a "missing" cell would promote must stay untouched.
        let ap = env.arch_file("cam-1", 0);
        std::fs::create_dir_all(ap.parent().unwrap()).unwrap();
        std::fs::write(&ap, pattern(100)).unwrap();
        let (lp, _) = build(&env, None);
        assert_eq!(lp.move_now(id, true), Outcome::Unverified, "{kind}");
        assert_eq!(env.tier_of(id), Some(Tier::Hot), "{kind}");
        assert!(
            std::fs::symlink_metadata(&hp).is_ok(),
            "{kind}: left in place"
        );
        assert!(Env::quarantined(&env.hot).is_empty(), "{kind}");
    }
}

#[test]
fn a_non_regular_archive_copy_is_unverified_for_a_missing_hot_file() {
    let env = Env::new();
    let id = env.row("cam-1", 0, 100, Tier::Hot);
    std::fs::create_dir_all(env.arch_file("cam-1", 0)).unwrap();
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::Unverified);
    assert_eq!(env.tier_of(id), Some(Tier::Hot), "never drops the row");
}

#[test]
fn the_archive_copy_is_fsynced_before_it_becomes_the_only_copy() {
    // (Missing, Valid): a failing fsync of the file, or of its directory, keeps the row hot.
    for op in [Op::SyncSource, Op::SyncDir(Tier::Archive)] {
        let (env, id) = setup(H::Missing, A::Valid);
        let (lp, _) = build(&env, Some(Fault::once(op, 1)));
        assert_eq!(lp.move_now(id, true), Outcome::Unverified, "{op:?}");
        assert_eq!(env.tier_of(id), Some(Tier::Hot), "{op:?}");
    }
    // And the index error after a good fsync skips the segment, with the file kept.
    let (env, id) = setup(H::Missing, A::Valid);
    env.index.faults.lock().unwrap().set_tier = true;
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::IndexError);
    assert!(env.arch_file("cam-1", 0).exists());
}

#[test]
fn an_index_error_while_dropping_a_row_skips_the_segment() {
    let (env, id) = setup(H::Missing, A::None);
    env.index.faults.lock().unwrap().delete = true;
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::IndexError);
    assert_eq!(env.tier_of(id), Some(Tier::Hot));
    env.index.faults.lock().unwrap().delete = false;
    env.index.faults.lock().unwrap().get = true;
    assert_eq!(
        lp.move_now(id, true),
        Outcome::IndexError,
        "reading the row"
    );
}

#[test]
fn an_exhausted_quarantine_bound_leaves_the_file_in_place_as_unverified() {
    let (env, id) = setup(H::Wrong, A::None);
    let rel = Env::rel("cam-1", 0);
    let qdir = env
        .hot
        .join("_quarantine")
        .join(std::path::Path::new(&rel).parent().unwrap());
    std::fs::create_dir_all(&qdir).unwrap();
    let name = std::path::Path::new(&rel)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    std::fs::write(qdir.join(&name), b"q").unwrap();
    for i in 1..=1000 {
        std::fs::write(qdir.join(format!("{name}.{i}")), b"q").unwrap();
    }
    let (lp, _) = build(&env, None);
    assert_eq!(lp.move_now(id, true), Outcome::Unverified);
    assert_eq!(env.tier_of(id), Some(Tier::Hot), "row kept");
    assert_eq!(
        std::fs::read(env.hot_file("cam-1", 0)).unwrap(),
        pattern(100),
        "left in place"
    );
    assert_eq!(
        std::fs::read(qdir.join(&name)).unwrap(),
        b"q",
        "nothing overwritten"
    );
}

#[test]
fn stale_plan_entries_are_skipped_without_blame() {
    let env = Env::new();
    let (lp, _) = build(&env, None);
    assert_eq!(
        lp.move_now(wardenlens_core::storage::SegmentId::new(99), true),
        Outcome::Skipped(Skip::NoRow)
    );
    let id = env.add("cam-1", 0, 10, Tier::Archive);
    assert_eq!(lp.move_now(id, true), Outcome::Skipped(Skip::WrongTier));
}

// ---- delete -------------------------------------------------------------------------------

#[test]
fn delete_unlinks_fsyncs_each_directory_and_removes_the_row_last() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 100, Tier::Hot);
    // A twin on the archive (a crash between M6 and M8 left one).
    let ap = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(ap.parent().unwrap()).unwrap();
    std::fs::write(&ap, pattern(100)).unwrap();
    let (lp, state) = build(&env, None);
    assert_eq!(lp.delete_now(id, true), Outcome::Deleted);
    assert_eq!(env.tier_of(id), None);
    assert!(!env.hot_file("cam-1", 0).exists());
    assert!(!ap.exists());
    let log = state.lock().unwrap().log.clone();
    assert_eq!(
        log,
        vec![
            Op::Open(Tier::Archive), // the twin is looked at before anything is unlinked
            Op::Open(Tier::Hot),     // the row's own file, to compare the bytes (#195)
            Op::Read,
            Op::Read,
            Op::Unlink(Tier::Hot),
            Op::SyncDir(Tier::Hot),
            Op::Unlink(Tier::Archive),
            Op::SyncDir(Tier::Archive)
        ]
    );
}

#[test]
fn delete_never_removes_the_row_before_the_unlink_and_the_directory_fsync() {
    // Each failing step keeps the row.
    for (op, name) in [
        (Op::Unlink(Tier::Hot), "unlink hot"),
        (Op::SyncDir(Tier::Hot), "fsync hot dir"),
        (Op::Unlink(Tier::Archive), "unlink archive"),
        (Op::SyncDir(Tier::Archive), "fsync archive dir"),
    ] {
        let env = Env::new();
        let id = env.add("cam-1", 0, 100, Tier::Archive);
        let (lp, _) = build(&env, Some(Fault::once(op, 1)));
        assert_eq!(lp.delete_now(id, true), Outcome::DeleteFailed, "{name}");
        assert_eq!(env.tier_of(id), Some(Tier::Archive), "{name}: row kept");
    }
    // The other order: the row delete fails after both files are gone and synced.
    let env = Env::new();
    let id = env.add("cam-1", 0, 100, Tier::Hot);
    env.index.faults.lock().unwrap().delete = true;
    let (lp, state) = build(&env, None);
    assert_eq!(lp.delete_now(id, true), Outcome::IndexError);
    assert_eq!(
        state.lock().unwrap().log.len(),
        5,
        "all file steps came first"
    );
    assert_eq!(
        env.tier_of(id),
        Some(Tier::Hot),
        "a row without a file is the table's cell"
    );
}

#[test]
fn delete_tolerates_a_missing_file_or_a_file_over_its_directory_but_no_other_errno() {
    let env = Env::new();
    let id = env.row("cam-1", 0, 100, Tier::Hot);
    let (lp, _) = build(&env, None);
    assert_eq!(
        lp.delete_now(id, true),
        Outcome::Deleted,
        "ENOENT is tolerated"
    );
    // ENOTDIR (a file where the directory should be): no segment file can exist there, so it is
    // tolerated like ENOENT (ticket #160, round 2) and never pins the row. The planted object
    // is left alone. Any other errno is still a failure (the fault tests above).
    let env = Env::new();
    let id = env.row("cam-1", 0, 100, Tier::Hot);
    std::fs::write(env.hot.join("cam-1"), b"x").unwrap();
    let (lp, _) = build(&env, None);
    assert_eq!(lp.delete_now(id, true), Outcome::Deleted);
    assert_eq!(env.tier_of(id), None);
    assert_eq!(std::fs::read(env.hot.join("cam-1")).unwrap(), b"x");
}

#[test]
fn delete_leaves_the_archive_alone_while_it_is_unavailable() {
    let env = Env::new();
    let hot = env.add("cam-1", 0, 100, Tier::Hot);
    let arch = env.add("cam-1", 1, 100, Tier::Archive);
    // A twin of the hot row on the archive stays too: nothing is concluded or touched there.
    let twin = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(twin.parent().unwrap()).unwrap();
    std::fs::write(&twin, pattern(100)).unwrap();
    let (lp, _) = build(&env, None);
    assert_eq!(lp.delete_now(hot, false), Outcome::Deleted);
    assert!(twin.exists());
    assert_eq!(
        lp.delete_now(arch, false),
        Outcome::Skipped(Skip::ArchiveUnavailable)
    );
    assert_eq!(
        env.tier_of(arch),
        Some(Tier::Archive),
        "archive rows are kept"
    );
    assert!(env.arch_file("cam-1", 1).exists());
}

/// A twin that cannot be compared with the row's own file is not deleted: `DeleteFailed`, both
/// files and the row stay (#195).
#[test]
fn delete_with_a_twin_that_cannot_be_compared_deletes_nothing() {
    for eof in [false, true] {
        let env = Env::new();
        let id = env.add("cam-1", 0, 100, Tier::Hot);
        let ap = env.arch_file("cam-1", 0);
        std::fs::create_dir_all(ap.parent().unwrap()).unwrap();
        std::fs::write(&ap, pattern(100)).unwrap();
        let fault = Fault {
            sticky: true,
            eof,
            ..Fault::once(Op::Read, 1)
        };
        let (lp, _) = build(&env, Some(fault));
        assert_eq!(lp.delete_now(id, true), Outcome::DeleteFailed, "eof {eof}");
        assert_eq!(env.tier_of(id), Some(Tier::Hot));
        assert!(env.hot_file("cam-1", 0).exists() && ap.exists());
    }
}
