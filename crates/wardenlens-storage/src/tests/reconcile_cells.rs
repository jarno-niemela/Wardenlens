//! One test per cell of the section 9 decision tables (27 with the archive available, 9
//! without), each on temporary directories with the real index, asserting the files, the row
//! (and its id) and the whole report.

use wardenlens_core::storage::Tier;

use super::matrix::build;
use super::support::{Env, good, mp4, pattern, put};
use crate::ReconcileReport;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum F {
    /// No file.
    No,
    /// A valid segment (the row's size, or a file the adoption parser accepts).
    Ok,
    /// A regular file that is neither.
    Bad,
}

/// What must have happened to a file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum End {
    /// Still where it was, with its bytes.
    Stays,
    /// Deleted (and not in quarantine).
    Gone,
    /// In `_quarantine` with its bytes.
    Quar,
}
use End::{Gone, Quar, Stays};

struct Expect {
    /// The row afterwards: its tier, or none.
    row: Option<Tier>,
    h: End,
    a: End,
    report: ReconcileReport,
}

fn rep(f: impl FnOnce(&mut ReconcileReport)) -> ReconcileReport {
    let mut r = ReconcileReport::default();
    f(&mut r);
    r
}

fn bad() -> Vec<u8> {
    pattern(7)
}

fn bytes_of(f: F) -> Option<Vec<u8>> {
    match f {
        F::No => None,
        F::Ok => Some(good()),
        F::Bad => Some(bad()),
    }
}

/// Build the state, run the start-up pass, check every file, the row, its id and the report.
fn run_cell(archive_up: bool, row: Option<Tier>, h: F, a: F, want: &Expect) {
    let env = Env::new();
    if !archive_up {
        std::fs::remove_file(env.arch.join(crate::ARCHIVE_MARKER)).unwrap();
    }
    let id = row.map(|t| env.row("cam-1", 0, good().len(), t));
    let rel = Env::rel("cam-1", 0);
    let (hb, ab) = (bytes_of(h), bytes_of(a));
    if let Some(b) = &hb {
        put(&env.hot, &rel, b);
    }
    if let Some(b) = &ab {
        put(&env.arch, &rel, b);
    }
    let (mut lp, _) = build(&env, None);
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(out.report, want.report, "report");
    assert!(!out.report.health_error());
    // A fixed point (several passes, TEST-8): a second pass over the result finds nothing more to
    // change. With the archive unobservable only the `unverified` rows are counted again.
    let (mut again, _) = build(&env, None);
    let second = again.reconcile_startup().unwrap().report;
    assert_eq!(
        (
            second.adopted,
            second.quarantined,
            second.rolled_forward,
            second.rolled_back,
            second.missing,
            second.duplicates_deleted,
            second.part_deleted
        ),
        (0, 0, 0, 0, 0, 0, 0),
        "a second pass changes nothing: {second:?}"
    );
    if archive_up {
        assert_eq!(second, ReconcileReport::default());
    }
    // An invalid file is never deleted.
    assert!(
        (h != F::Bad || want.h != Gone) && (a != F::Bad || want.a != Gone),
        "the table itself must never delete an invalid file"
    );
    for (root, orig, end, what) in [
        (&env.hot, &hb, want.h, "hot"),
        (&env.arch, &ab, want.a, "archive"),
    ] {
        let path = root.join(&rel);
        let q = Env::quarantined(root);
        match (end, orig) {
            (Stays, Some(b)) => {
                assert_eq!(&std::fs::read(&path).unwrap(), b, "{what} stays");
                assert!(q.is_empty(), "{what}: nothing quarantined");
            }
            (Gone, Some(_)) => {
                assert!(!path.exists(), "{what} deleted");
                assert!(q.is_empty(), "{what}: deleted, not quarantined");
            }
            (Quar, Some(b)) => {
                assert!(!path.exists(), "{what} moved away");
                assert_eq!(q, vec![b.clone()], "{what} quarantined with its bytes");
            }
            (_, None) => {
                assert!(!path.exists(), "{what}: nothing appears");
                assert_eq!(q.len(), 0);
            }
        }
    }
    match (want.row, id) {
        (Some(t), Some(id)) => {
            let r = env.find("cam-1", 0).expect("the row is kept");
            assert_eq!(r.id, id, "an id is never reassigned while a row exists");
            assert_eq!(r.tier, t);
        }
        (None, Some(_)) => assert!(env.find("cam-1", 0).is_none(), "the row is dropped"),
        (Some(t), None) => {
            let r = env.find("cam-1", 0).expect("the file is adopted");
            assert_eq!(r.tier, t);
            // Read from the box walk: 9,000 ticks at 90 kHz is 100 ms, three samples, the file's
            // own size.
            assert_eq!(
                (r.record.duration_ms, r.record.frame_count, r.record.bytes),
                (100, 3, good().len() as u64)
            );
        }
        (None, None) => assert!(env.find("cam-1", 0).is_none(), "no row appears"),
    }
}

macro_rules! cell {
    ($name:ident, $row:expr, $h:expr, $a:expr, $want:expr) => {
        #[test]
        fn $name() {
            run_cell(true, $row, $h, $a, &$want);
        }
    };
}
macro_rules! cell_unavailable {
    ($name:ident, $row:expr, $h:expr, $want:expr) => {
        #[test]
        fn $name() {
            run_cell(false, $row, $h, F::No, &$want);
        }
    };
}

const HOT: Option<Tier> = Some(Tier::Hot);
const ARC: Option<Tier> = Some(Tier::Archive);
const NONE: Option<Tier> = None;

fn e(row: Option<Tier>, h: End, a: End, report: ReconcileReport) -> Expect {
    Expect { row, h, a, report }
}

// ---- archive available: row none ----------------------------------------------------------------

cell!(
    none_none_none,
    NONE,
    F::No,
    F::No,
    e(NONE, Stays, Stays, rep(|_| {}))
);
cell!(
    none_none_valid_adopt_a_as_archive,
    NONE,
    F::No,
    F::Ok,
    e(ARC, Stays, Stays, rep(|r| r.adopted = 1))
);
cell!(
    none_none_invalid_quarantine_a,
    NONE,
    F::No,
    F::Bad,
    e(NONE, Stays, Quar, rep(|r| r.quarantined = 1))
);
cell!(
    none_valid_none_adopt_h_as_hot,
    NONE,
    F::Ok,
    F::No,
    e(HOT, Stays, Stays, rep(|r| r.adopted = 1))
);
cell!(
    none_valid_valid_adopt_a_and_delete_h_when_sizes_are_equal,
    NONE,
    F::Ok,
    F::Ok,
    e(
        ARC,
        Gone,
        Stays,
        rep(|r| {
            r.adopted = 1;
            r.duplicates_deleted = 1;
        })
    )
);
cell!(
    none_valid_invalid_adopt_h_quarantine_a,
    NONE,
    F::Ok,
    F::Bad,
    e(
        HOT,
        Stays,
        Quar,
        rep(|r| {
            r.adopted = 1;
            r.quarantined = 1;
        })
    )
);
cell!(
    none_invalid_none_quarantine_h,
    NONE,
    F::Bad,
    F::No,
    e(NONE, Quar, Stays, rep(|r| r.quarantined = 1))
);
cell!(
    none_invalid_valid_adopt_a_quarantine_h,
    NONE,
    F::Bad,
    F::Ok,
    e(
        ARC,
        Quar,
        Stays,
        rep(|r| {
            r.adopted = 1;
            r.quarantined = 1;
        })
    )
);
cell!(
    none_invalid_invalid_quarantine_both,
    NONE,
    F::Bad,
    F::Bad,
    e(NONE, Quar, Quar, rep(|r| r.quarantined = 2))
);

// ---- archive available: row hot ------------------------------------------------------------------

cell!(
    hot_none_none_delete_the_row_count_missing,
    HOT,
    F::No,
    F::No,
    e(NONE, Stays, Stays, rep(|r| r.missing = 1))
);
cell!(
    hot_none_valid_set_archive_the_file_is_the_truth,
    HOT,
    F::No,
    F::Ok,
    e(ARC, Stays, Stays, rep(|r| r.rolled_forward = 1))
);
cell!(
    hot_none_invalid_quarantine_a_delete_the_row,
    HOT,
    F::No,
    F::Bad,
    e(
        NONE,
        Stays,
        Quar,
        rep(|r| {
            r.quarantined = 1;
            r.size_mismatch = 1;
        })
    )
);
cell!(
    hot_valid_none_consistent,
    HOT,
    F::Ok,
    F::No,
    e(HOT, Stays, Stays, rep(|_| {}))
);
cell!(
    hot_valid_valid_roll_forward_delete_h,
    HOT,
    F::Ok,
    F::Ok,
    e(
        ARC,
        Gone,
        Stays,
        rep(|r| {
            r.rolled_forward = 1;
            r.duplicates_deleted = 1;
        })
    )
);
cell!(
    hot_valid_invalid_quarantine_a_keep_h,
    HOT,
    F::Ok,
    F::Bad,
    e(
        HOT,
        Stays,
        Quar,
        rep(|r| {
            r.quarantined = 1;
            r.size_mismatch = 1;
        })
    )
);
cell!(
    hot_invalid_none_quarantine_h_delete_the_row,
    HOT,
    F::Bad,
    F::No,
    e(
        NONE,
        Quar,
        Stays,
        rep(|r| {
            r.quarantined = 1;
            r.size_mismatch = 1;
        })
    )
);
cell!(
    hot_invalid_valid_set_archive_quarantine_h,
    HOT,
    F::Bad,
    F::Ok,
    e(
        ARC,
        Quar,
        Stays,
        rep(|r| {
            r.rolled_forward = 1;
            r.quarantined = 1;
            r.size_mismatch = 1;
        })
    )
);
cell!(
    hot_invalid_invalid_quarantine_both_delete_the_row,
    HOT,
    F::Bad,
    F::Bad,
    e(
        NONE,
        Quar,
        Quar,
        rep(|r| {
            r.quarantined = 2;
            r.size_mismatch = 2;
        })
    )
);

// ---- archive available: row archive --------------------------------------------------------------

cell!(
    archive_none_none_delete_the_row_count_missing,
    ARC,
    F::No,
    F::No,
    e(NONE, Stays, Stays, rep(|r| r.missing = 1))
);
cell!(
    archive_none_valid_consistent,
    ARC,
    F::No,
    F::Ok,
    e(ARC, Stays, Stays, rep(|_| {}))
);
cell!(
    archive_none_invalid_quarantine_a_delete_the_row,
    ARC,
    F::No,
    F::Bad,
    e(
        NONE,
        Stays,
        Quar,
        rep(|r| {
            r.quarantined = 1;
            r.size_mismatch = 1;
        })
    )
);
cell!(
    archive_valid_none_set_hot_the_file_is_the_truth,
    ARC,
    F::Ok,
    F::No,
    e(HOT, Stays, Stays, rep(|r| r.rolled_back = 1))
);
cell!(
    archive_valid_valid_delete_h,
    ARC,
    F::Ok,
    F::Ok,
    e(ARC, Gone, Stays, rep(|r| r.duplicates_deleted = 1))
);
cell!(
    archive_valid_invalid_roll_back_quarantine_a,
    ARC,
    F::Ok,
    F::Bad,
    e(
        HOT,
        Stays,
        Quar,
        rep(|r| {
            r.rolled_back = 1;
            r.quarantined = 1;
            r.size_mismatch = 1;
        })
    )
);
cell!(
    archive_invalid_none_quarantine_h_delete_the_row,
    ARC,
    F::Bad,
    F::No,
    e(
        NONE,
        Quar,
        Stays,
        rep(|r| {
            r.quarantined = 1;
            r.size_mismatch = 1;
        })
    )
);
cell!(
    archive_invalid_valid_quarantine_h_keep_the_row,
    ARC,
    F::Bad,
    F::Ok,
    e(
        ARC,
        Quar,
        Stays,
        rep(|r| {
            r.quarantined = 1;
            r.size_mismatch = 1;
        })
    )
);
cell!(
    archive_invalid_invalid_quarantine_both_delete_the_row,
    ARC,
    F::Bad,
    F::Bad,
    e(
        NONE,
        Quar,
        Quar,
        rep(|r| {
            r.quarantined = 2;
            r.size_mismatch = 2;
        })
    )
);

// ---- archive unavailable (A is unknown, nothing is concluded from it) ---------------------------

fn unavailable(f: impl FnOnce(&mut ReconcileReport)) -> ReconcileReport {
    rep(|r| {
        r.archive_unavailable = true;
        r.archive_unverified = true;
        f(r);
    })
}

cell_unavailable!(
    unavailable_none_none,
    NONE,
    F::No,
    e(NONE, Stays, Stays, unavailable(|_| {}))
);
cell_unavailable!(
    unavailable_none_valid_adopt_h_as_hot,
    NONE,
    F::Ok,
    e(HOT, Stays, Stays, unavailable(|r| r.adopted = 1))
);
cell_unavailable!(
    unavailable_none_invalid_quarantine_h,
    NONE,
    F::Bad,
    e(NONE, Quar, Stays, unavailable(|r| r.quarantined = 1))
);
cell_unavailable!(
    unavailable_hot_none_keep_the_row_unverified,
    HOT,
    F::No,
    e(HOT, Stays, Stays, unavailable(|r| r.unverified = 1))
);
cell_unavailable!(
    unavailable_hot_valid_consistent,
    HOT,
    F::Ok,
    e(HOT, Stays, Stays, unavailable(|_| {}))
);
cell_unavailable!(
    unavailable_hot_invalid_quarantine_h_keep_the_row_unverified,
    HOT,
    F::Bad,
    e(
        HOT,
        Quar,
        Stays,
        unavailable(|r| {
            r.quarantined = 1;
            r.unverified = 1;
            r.size_mismatch = 1;
        })
    )
);
cell_unavailable!(
    unavailable_archive_none_keep_the_row_unverified,
    ARC,
    F::No,
    e(ARC, Stays, Stays, unavailable(|r| r.unverified = 1))
);
cell_unavailable!(
    unavailable_archive_valid_keep_the_row_and_h,
    ARC,
    F::Ok,
    e(ARC, Stays, Stays, unavailable(|_| {}))
);
cell_unavailable!(
    unavailable_archive_invalid_quarantine_h_keep_the_row_unverified,
    ARC,
    F::Bad,
    e(
        ARC,
        Quar,
        Stays,
        unavailable(|r| {
            r.quarantined = 1;
            r.unverified = 1;
            r.size_mismatch = 1;
        })
    )
);

// ---- the equal-size exception of (none, valid, valid) --------------------------------------------

#[test]
fn none_valid_valid_with_different_sizes_adopts_a_and_quarantines_h() {
    let env = Env::new();
    let rel = Env::rel("cam-1", 0);
    let h = mp4(&[&[3000, 3000, 3000], &[3000]]);
    let a = good();
    assert_ne!(h.len(), a.len());
    put(&env.hot, &rel, &h);
    put(&env.arch, &rel, &a);
    let (mut lp, _) = build(&env, None);
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(
        out.report,
        rep(|r| {
            r.adopted = 1;
            r.quarantined = 1;
        })
    );
    assert_eq!(env.find("cam-1", 0).unwrap().tier, Tier::Archive);
    assert_eq!(std::fs::read(env.arch.join(&rel)).unwrap(), a);
    assert!(!env.hot.join(&rel).exists());
    assert_eq!(
        Env::quarantined(&env.hot),
        vec![h],
        "H is kept, not deleted"
    );
}

/// (none, valid, valid) is the one cell with a size test: equal sizes are the same segment copied
/// (a duplicate), a longer or shorter H is not.
#[test]
fn none_valid_valid_one_byte_apart_is_not_a_duplicate() {
    let env = Env::new();
    let rel = Env::rel("cam-1", 0);
    let mut h = good();
    h.push(0); // a trailing partial box: invalid, not a second valid file
    let a = good();
    put(&env.hot, &rel, &h);
    put(&env.arch, &rel, &a);
    let (mut lp, _) = build(&env, None);
    let out = lp.reconcile_startup().unwrap();
    // H does not parse (trailing byte), so this is the (none, invalid, valid) cell: H is
    // quarantined, never deleted.
    assert_eq!(out.report.quarantined, 1);
    assert_eq!(out.report.duplicates_deleted, 0);
    assert_eq!(Env::quarantined(&env.hot), vec![h]);
}

// ---- a foreign file at a key (#195, ADR 0005 section 9, "twins") ----------------------------------

/// A well-formed segment of the same length as [`good`] with other payload bytes: another
/// recording that landed on the same name (the recorder bumped its key onto it).
fn same_size_other_content() -> Vec<u8> {
    let mut v = good();
    let n = v.len();
    v[n - 1] ^= 0xFF; // last byte of the mdat payload
    v
}

/// The twin rule, one case per cell that used to delete H on the strength of its size: the hot
/// copy is deleted only when it is byte-identical to the archive copy. Otherwise it is
/// quarantined (never deleted), the row and A stay, and the report carries `foreign_twins`.
#[test]
fn a_hot_file_that_is_not_a_copy_of_the_archive_file_is_quarantined_never_deleted() {
    // (row tier, expected row tier afterwards, expected report)
    let cases: [(Option<Tier>, Tier, ReconcileReport); 3] = [
        (
            Some(Tier::Archive),
            Tier::Archive,
            rep(|r| {
                r.foreign_twins = 1;
                r.quarantined = 1;
            }),
        ),
        (
            Some(Tier::Hot),
            Tier::Archive,
            rep(|r| {
                r.foreign_twins = 1;
                r.quarantined = 1;
                r.rolled_forward = 1;
            }),
        ),
        (
            None,
            Tier::Archive,
            rep(|r| {
                r.foreign_twins = 1;
                r.quarantined = 1;
                r.adopted = 1;
            }),
        ),
    ];
    for (row, after, want) in cases {
        let env = Env::new();
        let rel = Env::rel("cam-1", 0);
        let id = row.map(|t| env.row("cam-1", 0, good().len(), t));
        let foreign = same_size_other_content();
        assert_eq!(foreign.len(), good().len());
        put(&env.hot, &rel, &foreign);
        put(&env.arch, &rel, &good());
        let (mut lp, _) = build(&env, None);
        let out = lp.reconcile_startup().unwrap();
        assert_eq!(out.report, want, "{row:?}");
        assert!(out.report.health_error(), "{row:?}: an alert");
        assert!(!env.hot.join(&rel).exists(), "{row:?}");
        assert_eq!(Env::quarantined(&env.hot), vec![foreign], "{row:?}: kept");
        assert_eq!(std::fs::read(env.arch.join(&rel)).unwrap(), good());
        let r = env.find("cam-1", 0).expect("the row is kept");
        assert_eq!(r.tier, after);
        if let Some(id) = id {
            assert_eq!(r.id, id);
        }
    }
}

/// A true copy is still deleted, in all three cells.
#[test]
fn an_identical_hot_copy_is_still_deleted() {
    for row in [Some(Tier::Archive), Some(Tier::Hot), None] {
        let env = Env::new();
        let rel = Env::rel("cam-1", 0);
        if let Some(t) = row {
            env.row("cam-1", 0, good().len(), t);
        }
        put(&env.hot, &rel, &good());
        put(&env.arch, &rel, &good());
        let (mut lp, _) = build(&env, None);
        let out = lp.reconcile_startup().unwrap();
        assert_eq!(out.report.duplicates_deleted, 1, "{row:?}");
        assert_eq!(out.report.foreign_twins, 0);
        assert!(!out.report.health_error());
        assert!(!env.hot.join(&rel).exists());
        assert_eq!(Env::quarantined(&env.hot).len(), 0);
    }
}

/// Where the two copies differ matters not: first byte, middle, last.
#[test]
fn a_difference_anywhere_in_the_file_is_found() {
    let len = good().len();
    for at in [0, len / 2, len - 1] {
        let env = Env::new();
        let rel = Env::rel("cam-1", 0);
        env.row("cam-1", 0, len, Tier::Archive);
        let mut h = good();
        h[at] ^= 1;
        // A flipped header byte may make H invalid (then the old invalid rule applies); only the
        // payload flip keeps it valid by size, which is the case under test.
        put(&env.hot, &rel, &h);
        put(&env.arch, &rel, &good());
        let (mut lp, _) = build(&env, None);
        let out = lp.reconcile_startup().unwrap();
        assert_eq!(out.report.duplicates_deleted, 0, "at {at}");
        assert_eq!(
            Env::quarantined(&env.hot),
            vec![h],
            "at {at}: never deleted"
        );
    }
}
