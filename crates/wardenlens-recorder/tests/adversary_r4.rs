//! Adversary round 4 (ticket #57): every insert error reaches quarantine only through a
//! confirmed answer from the index.

mod common;

use common::rig::*;
use common::*;
use rusqlite::ErrorCode;
use wardenlens_core::recording::RelPath;
use wardenlens_index::IndexError;

fn quarantined(root: &std::path::Path) -> Vec<String> {
    tree(root)
        .into_iter()
        .filter(|n| n.starts_with("_quarantine"))
        .collect()
}

fn permanent() -> Vec<fn() -> IndexError> {
    vec![
        || IndexError::Duplicate,
        || IndexError::Constraint { op: "insert" },
        || IndexError::Damaged,
        || IndexError::Sqlite {
            op: "insert",
            code: Some(ErrorCode::DatabaseCorrupt),
        },
        || IndexError::Sqlite {
            op: "insert",
            code: None,
        },
    ]
}

/// Every hot row in the index has its file at its key with the row's size.
fn every_row_has_its_file(d: &Done) {
    for row in &d.rows {
        let p = d
            .root
            .join(RelPath::new(&row.record.camera, row.record.started_at_ms).to_string());
        let len = std::fs::metadata(&p).map(|m| m.len()).ok();
        assert_eq!(
            len,
            Some(row.record.bytes),
            "{}: tree {:?}",
            p.display(),
            tree(&d.root)
        );
    }
}

/// First attempt, un-bumped key, permanent error, read-back refused: the answer is unknown, so
/// the file stays where it is, unindexed.
#[test]
fn a_permanent_first_attempt_error_with_an_unreadable_index_keeps_the_file() {
    for make in permanent() {
        let mut r = Rig::new();
        r.start();
        r.feed(Slice::P);
        {
            let mut s = r.index.lock().unwrap();
            s.insert_errors = vec![make()].into();
            s.list_errors = 1;
        }
        let d = r.finish();
        assert_eq!(
            (
                d.end.segments_indexed,
                d.end.segments_unindexed,
                d.end.segments_quarantined
            ),
            (0, 1, 0),
            "{:?}",
            make()
        );
        assert!(quarantined(&d.root).is_empty(), "{:?}", tree(&d.root));
        assert_eq!(tree(&d.root).len(), 1);
    }
}

/// First attempt, permanent error, no row (confirmed): quarantined, exactly one insert attempt
/// (a permanent error is never retried).
#[test]
fn a_permanent_first_attempt_error_with_no_row_quarantines_without_a_retry() {
    for make in permanent() {
        let mut r = Rig::new();
        r.start();
        r.feed(Slice::P);
        r.index.lock().unwrap().insert_errors = vec![make()].into();
        let script = r.index.clone();
        let d = r.finish();
        assert_eq!(script.lock().unwrap().attempts, 1, "{:?}", make());
        assert_eq!(d.end.segments_quarantined, 1, "{:?}", make());
        assert_eq!(quarantined(&d.root).len(), 1);
        assert_eq!(d.rows.len(), 0);
    }
}

/// Transient errors first, then the row commits and a permanent error is reported: the read-back
/// matches and the segment is indexed in place.
#[test]
fn a_commit_then_permanent_error_after_retries_counts_as_indexed() {
    for make in permanent() {
        let mut r = Rig::new();
        r.start();
        r.feed(Slice::P);
        {
            let mut s = r.index.lock().unwrap();
            s.insert_errors = vec![
                IndexError::Busy { op: "insert" },
                IndexError::Busy { op: "insert" },
            ]
            .into();
            s.commit_then_error = vec![make()].into();
        }
        let d = r.finish();
        assert_eq!(
            (d.end.segments_indexed, d.end.segments_quarantined),
            (1, 0),
            "{:?}",
            make()
        );
        every_row_has_its_file(&d);
    }
}

/// Bumped key, the row committed and then a permanent error: indexed, nothing moved.
#[test]
fn a_bumped_key_committed_then_a_permanent_error_counts_as_indexed() {
    for make in permanent() {
        let mut r = Rig::new();
        r.start();
        r.feed(Slice::P);
        let planted = r.root.join(RelPath::new(&cam(), ms(T0 + 100)).to_string());
        std::fs::write(&planted, b"foreign").unwrap();
        r.index.lock().unwrap().commit_then_error = vec![make()].into();
        let d = r.finish();
        assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
        assert_eq!(
            (d.end.segments_indexed, d.end.segments_quarantined),
            (1, 0),
            "{:?}",
            make()
        );
        assert_eq!(d.rows.len(), 1);
        assert_eq!(d.rows[0].record.started_at_ms, ms(T0 + 101));
        every_row_has_its_file(&d);
    }
}

/// The retries run out, the row was committed by the last attempt: indexed.
#[test]
fn retries_exhausted_after_the_last_attempt_committed_counts_as_indexed() {
    let config = fast().with_insert_retries(1, std::time::Duration::ZERO);
    let mut r = Rig::build(config, None, |_, _| {});
    r.start();
    r.feed(Slice::P);
    {
        let mut s = r.index.lock().unwrap();
        s.insert_errors = vec![IndexError::Busy { op: "insert" }].into();
        s.commit_then_error = vec![IndexError::Busy { op: "insert" }].into();
    }
    let d = r.finish();
    assert_eq!(
        (
            d.end.segments_indexed,
            d.end.segments_unindexed,
            d.end.segments_quarantined
        ),
        (1, 0, 0),
        "{:?}",
        d.end
    );
    every_row_has_its_file(&d);
}

type Step = Box<dyn Fn(&mut IndexScript)>;

/// Over several segments with a mix of failures, the counters add up to the segments closed,
/// no indexed row ever loses its file, and no unindexed file is reused as another key.
#[test]
fn a_run_of_mixed_insert_failures_keeps_every_row_and_file_consistent() {
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    let mut script: Vec<Step> = vec![
        Box::new(|s| s.commit_then_error = vec![IndexError::Duplicate].into()),
        Box::new(|s| {
            s.insert_errors = vec![IndexError::Constraint { op: "insert" }].into();
            s.list_errors = 1;
        }),
        Box::new(|s| s.insert_errors = vec![IndexError::Damaged].into()),
        Box::new(|s| {
            s.insert_errors = vec![IndexError::Busy { op: "insert" }].into();
            s.commit_then_error = vec![IndexError::Damaged].into();
        }),
        Box::new(|_| {}),
    ];
    for step in script.drain(..) {
        step(&mut r.index.lock().unwrap());
        // A discontinuity on a delta frame closes the segment; the next keyframe opens another.
        let s = r.spec(Slice::P).with_loss();
        r.push(&s);
        r.gop(2);
    }
    let d = r.finish();
    let h = d.end;
    assert_eq!(
        h.segments_indexed + h.segments_unindexed + h.segments_quarantined,
        6,
        "{h:?}"
    );
    assert_eq!(h.segments_quarantined, 1, "{h:?} {:?}", tree(&d.root));
    assert_eq!(h.segments_unindexed, 1, "{h:?}");
    every_row_has_its_file(&d);
    let keys: std::collections::BTreeSet<i64> = d
        .rows
        .iter()
        .map(|r| r.record.started_at_ms.as_i64())
        .collect();
    assert_eq!(keys.len(), d.rows.len());
    // The rows plus the unindexed file plus the quarantined file: one file each.
    let in_place = tree(&d.root)
        .into_iter()
        .filter(|n| !n.starts_with("_quarantine"))
        .count();
    assert_eq!(in_place, d.rows.len() + 1, "{:?}", tree(&d.root));
}
