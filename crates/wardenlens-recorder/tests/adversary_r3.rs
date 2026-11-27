//! Adversary round 3 (ticket #57): every path from an insert error to quarantine, and the
//! tri-state read-back (`Match`, `NoRow`, `Differs`, `Unknown`).

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

/// The first insert commits the row and then reports a PERMANENT error (no transient error came
/// first). The row is in the index and matches the file; quarantining the file would leave an
/// indexed row pointing at a moved file. The recorder must ask the index before judging.
#[test]
fn a_permanent_error_after_the_row_was_committed_on_the_first_attempt_does_not_quarantine() {
    for make in permanent() {
        let mut r = Rig::new();
        r.index.lock().unwrap().commit_then_error = vec![make()].into();
        r.start();
        r.feed(Slice::P);
        let d = r.finish();
        assert_eq!(d.rows.len(), 1, "the row was committed");
        let row = &d.rows[0].record;
        let path = d
            .root
            .join(RelPath::new(&row.camera, row.started_at_ms).to_string());
        assert!(
            path.exists(),
            "{:?}: the indexed segment's file was quarantined: tree {:?}, health {:?}",
            make(),
            tree(&d.root),
            d.end
        );
        assert_eq!(d.end.segments_quarantined, 0, "{:?}", make());
    }
}

/// Retries run out after another segment's row took the key: the read-back says `Differs`.
/// The exhausted path must neither count it indexed nor quarantine it.
#[test]
fn retries_exhausted_with_a_differing_row_leaves_the_file_unindexed_in_place() {
    let config = fast().with_insert_retries(0, std::time::Duration::ZERO);
    let mut r = Rig::build(config, None, |_, _| {});
    r.index.lock().unwrap().other_row_then_error = vec![IndexError::Busy { op: "insert" }].into();
    r.start();
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!(
        (
            d.end.segments_indexed,
            d.end.segments_unindexed,
            d.end.segments_quarantined
        ),
        (0, 1, 0),
        "{:?}",
        d.end
    );
    assert_eq!(quarantined(&d.root).len(), 0, "{:?}", tree(&d.root));
}

/// Retries run out, no row exists (confirmed): the file stays, unindexed (reconciliation adopts
/// it), never quarantined.
#[test]
fn retries_exhausted_with_no_row_never_quarantines() {
    let config = fast().with_insert_retries(2, std::time::Duration::ZERO);
    let mut r = Rig::build(config, None, |_, _| {});
    r.index.lock().unwrap().insert_errors =
        (0..3).map(|_| IndexError::Busy { op: "insert" }).collect();
    r.start();
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!(d.end.segments_unindexed, 1);
    assert_eq!(d.end.segments_quarantined, 0);
    assert_eq!(d.end.segments_indexed, 0);
    assert_eq!(quarantined(&d.root).len(), 0);
}

/// A unknown read-back after many transient failures and then a permanent one: never quarantine.
#[test]
fn several_transient_errors_then_a_permanent_one_with_an_unreadable_index_keeps_the_file() {
    for make in permanent() {
        let mut r = Rig::new();
        r.start();
        r.feed(Slice::P);
        {
            let mut s = r.index.lock().unwrap();
            s.insert_errors = vec![
                IndexError::Busy { op: "insert" },
                IndexError::Busy { op: "insert" },
                make(),
            ]
            .into();
            s.list_errors = 1;
        }
        let d = r.finish();
        assert_eq!(d.end.segments_quarantined, 0, "{:?}", make());
        assert_eq!(d.end.segments_unindexed, 1, "{:?}", make());
        assert_eq!(quarantined(&d.root).len(), 0);
    }
}

/// The rename bump probes the index (#195): a key a row holds is skipped, and so is a key the
/// index cannot answer for. The file lands one key further, is indexed there, and the held
/// key's row and the planted file are untouched. (Before #195 the file was finished under the
/// held key and left unindexed.)
#[test]
fn a_bumped_key_with_an_unreadable_index_is_skipped_as_if_held() {
    let (r, planted) = bumped_rig();
    r.index.lock().unwrap().list_errors = 1;
    let d = r.finish();
    assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
    assert_eq!(quarantined(&d.root).len(), 0, "{:?}", tree(&d.root));
    assert_eq!(
        (
            d.end.segments_indexed,
            d.end.segments_unindexed,
            d.end.segments_quarantined
        ),
        (1, 0, 0)
    );
    let held = d.root.join(RelPath::new(&cam(), ms(T0 + 101)).to_string());
    assert!(!held.exists(), "{:?}", tree(&d.root));
    let next = d.root.join(RelPath::new(&cam(), ms(T0 + 102)).to_string());
    assert!(next.exists(), "{:?}", tree(&d.root));
    // The archive row is untouched.
    assert_eq!(d.rows.len(), 2);
    assert_eq!(d.rows[0].record.bytes, 4_096);
    assert_eq!(d.rows[1].record.started_at_ms, ms(T0 + 102));
}

/// Bumped past a held key, after transient insert failures: the segment is indexed under the
/// free key, nothing is quarantined, and no `.mp4` sits at the held key.
#[test]
fn a_bumped_key_held_by_another_row_is_skipped_also_after_transient_errors() {
    let (r, _planted) = bumped_rig();
    r.index.lock().unwrap().insert_errors = vec![
        IndexError::Busy { op: "insert" },
        IndexError::Busy { op: "insert" },
    ]
    .into();
    let d = r.finish();
    assert_eq!(quarantined(&d.root).len(), 0, "{:?}", tree(&d.root));
    assert_eq!((d.end.segments_indexed, d.end.segments_unindexed), (1, 0));
    assert_eq!(d.rows[1].record.started_at_ms, ms(T0 + 102));
}

/// Bumped key, the row really committed then a transient error: the read-back matches, the
/// segment counts as indexed, nothing is quarantined.
#[test]
fn a_bumped_key_whose_own_row_was_committed_counts_as_indexed() {
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    let planted = r.root.join(RelPath::new(&cam(), ms(T0 + 100)).to_string());
    std::fs::write(&planted, b"foreign").unwrap();
    r.index.lock().unwrap().commit_then_error = vec![IndexError::Busy { op: "insert" }].into();
    let d = r.finish();
    assert_eq!(
        (d.end.segments_indexed, d.end.segments_quarantined),
        (1, 0),
        "{:?}",
        d.end
    );
    assert_eq!(d.rows.len(), 1);
    assert_eq!(d.rows[0].record.started_at_ms, ms(T0 + 101));
    let f = d.root.join(RelPath::new(&cam(), ms(T0 + 101)).to_string());
    assert_eq!(std::fs::metadata(f).unwrap().len(), d.rows[0].record.bytes);
}

/// Bumped key, no row, a permanent (non-key) error: a confirmed `NoRow` quarantines, and the
/// planted foreign file at the original name is never touched.
#[test]
fn a_bumped_key_with_a_confirmed_missing_row_and_a_permanent_error_quarantines_only_its_own_file() {
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    let planted = r.root.join(RelPath::new(&cam(), ms(T0 + 100)).to_string());
    std::fs::write(&planted, b"foreign").unwrap();
    r.index.lock().unwrap().insert_errors = vec![IndexError::Constraint { op: "insert" }].into();
    let d = r.finish();
    assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
    assert_eq!(d.end.segments_quarantined, 1, "{:?}", d.end);
    let q = quarantined(&d.root);
    assert_eq!(q.len(), 1, "{:?}", tree(&d.root));
    assert!(q[0].contains("221320-101"), "{q:?}");
}

/// Two segments in a row, the first hits Differs + quarantine; the second must still be indexed
/// under a fresh key and the first segment's key never reused.
#[test]
fn after_a_quarantine_the_next_segment_is_indexed_under_a_new_key() {
    let mut r = Rig::new();
    r.index.lock().unwrap().other_row_then_error = vec![IndexError::Busy { op: "insert" }].into();
    r.start();
    r.feed(Slice::P);
    // A discontinuity on a delta frame closes the first segment.
    let s = r.spec(Slice::P).with_loss();
    r.push(&s);
    assert_eq!(r.health().segments_quarantined, 1);
    r.gop(2);
    let d = r.finish();
    assert_eq!(d.end.segments_quarantined, 1, "{:?}", d.end);
    assert_eq!(d.end.segments_indexed, 1, "{:?}", d.end);
    let keys: Vec<i64> = d
        .rows
        .iter()
        .map(|r| r.record.started_at_ms.as_i64())
        .collect();
    let mut dedup = keys.clone();
    dedup.dedup();
    assert_eq!(keys, dedup);
    // Every indexed hot row has its file in place.
    for row in &d.rows {
        if row.record.bytes == 0 {
            continue;
        }
        let p = d
            .root
            .join(RelPath::new(&row.record.camera, row.record.started_at_ms).to_string());
        if row.record.started_at_ms.as_i64() == T0 + 100 {
            continue; // the "other" row of the first segment
        }
        assert_eq!(std::fs::metadata(p).unwrap().len(), row.record.bytes);
    }
}
