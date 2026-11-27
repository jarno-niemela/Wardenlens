//! A read-only index volume (#195, ADR 0005 section 3): `SQLITE_READONLY` and `SQLITE_CANTOPEN`
//! are permanent for the run, but they say nothing about the file. The file is kept, the recorder
//! holds with its own reason and probes now and then, and no segment is quarantined.

mod common;

use common::rig::*;
use common::*;
use rusqlite::ErrorCode;
use wardenlens_index::IndexError;
use wardenlens_recorder::{HoldReason, RecorderState};

fn read_only() -> IndexError {
    IndexError::Sqlite {
        op: "insert",
        code: Some(ErrorCode::ReadOnly),
    }
}

fn cannot_open() -> IndexError {
    IndexError::Sqlite {
        op: "insert",
        code: Some(ErrorCode::CannotOpen),
    }
}

fn read_only_fs() -> IndexError {
    IndexError::Io {
        op: "insert",
        kind: std::io::ErrorKind::ReadOnlyFilesystem,
    }
}

const FAULTS: [fn() -> IndexError; 3] = [read_only, cannot_open, read_only_fs];

fn mp4_files(root: &std::path::Path) -> usize {
    tree(root)
        .iter()
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("mp4"))
        })
        .count()
}

fn quarantined(root: &std::path::Path) -> usize {
    tree(root)
        .iter()
        .filter(|n| n.starts_with("_quarantine"))
        .count()
}

/// One segment is closed by a discontinuity on a delta frame; the next keyframe is a new start.
fn close_segment(r: &mut Rig) {
    let s = r.spec(Slice::P).with_loss();
    r.push(&s);
}

#[test]
fn a_read_only_index_keeps_the_file_holds_the_recorder_and_never_quarantines() {
    for make in FAULTS {
        let mut r = Rig::new();
        r.index.lock().unwrap().insert_forever = Some(make);
        r.start();
        r.feed(Slice::P);
        close_segment(&mut r);
        let h = r.health();
        assert_eq!(
            (
                h.segments_indexed,
                h.segments_unindexed,
                h.segments_quarantined
            ),
            (0, 1, 0),
            "{:?}",
            make()
        );
        assert_eq!(r.state(), RecorderState::Held(HoldReason::IndexReadOnly));
        // Not retried: a permanent condition costs one attempt.
        assert_eq!(r.index.lock().unwrap().attempts, 1);
        let d = r.finish();
        assert_eq!(mp4_files(&d.root), 1, "the finished file stays in place");
        assert_eq!(quarantined(&d.root), 0);
        assert_eq!(part_files(&d.root).len(), 0);
    }
}

/// While held, keyframes do not start segments except one probe after every 32 skipped keyframes; a probe the
/// index refuses keeps the hold, and no file is ever quarantined.
#[test]
fn while_held_only_a_probe_segment_is_tried_and_the_files_all_stay() {
    let mut r = Rig::new();
    r.index.lock().unwrap().insert_forever = Some(read_only);
    r.start();
    r.feed(Slice::P);
    close_segment(&mut r);
    let creates_after_first = r.store.lock().unwrap().creates;
    // 32 keyframes are skipped: nothing is created.
    for _ in 0..32 {
        r.gop(2);
        close_segment(&mut r);
    }
    assert_eq!(r.store.lock().unwrap().creates, creates_after_first);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::IndexReadOnly));
    // The 33rd keyframe after the hold is the probe: a segment is created and refused again.
    r.gop(2);
    close_segment(&mut r);
    assert_eq!(r.store.lock().unwrap().creates, creates_after_first + 1);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::IndexReadOnly));
    let d = r.finish();
    assert_eq!(mp4_files(&d.root), 2);
    assert_eq!(quarantined(&d.root), 0);
    assert_eq!(d.end.segments_quarantined, 0);
    assert_eq!(d.end.segments_unindexed, 2);
}

/// The volume is writable again: the next probe is indexed and the hold ends.
#[test]
fn a_probe_the_index_accepts_ends_the_hold() {
    let mut r = Rig::new();
    r.index.lock().unwrap().insert_forever = Some(read_only);
    r.start();
    r.feed(Slice::P);
    close_segment(&mut r);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::IndexReadOnly));
    r.index.lock().unwrap().insert_forever = None;
    for _ in 0..32 {
        r.gop(2);
        close_segment(&mut r);
    }
    r.gop(2);
    assert_eq!(
        r.state(),
        RecorderState::Held(HoldReason::IndexReadOnly),
        "until the probe closes"
    );
    close_segment(&mut r);
    assert_eq!(r.state(), RecorderState::Waiting);
    // Normal recording again: the next keyframe starts a segment at once.
    r.gop(2);
    assert_eq!(r.state(), RecorderState::Recording);
    let d = r.finish();
    assert_eq!(d.end.segments_indexed, 2, "{:?}", d.end);
    assert_eq!(d.end.segments_unindexed, 1);
    assert_eq!(d.end.segments_quarantined, 0);
}

/// Other permanent errors still judge the file: the read-only class is not a catch-all.
#[test]
fn another_permanent_error_still_quarantines() {
    let mut r = Rig::new();
    r.index.lock().unwrap().insert_errors = vec![IndexError::Constraint { op: "insert" }].into();
    r.start();
    r.feed(Slice::P);
    close_segment(&mut r);
    let h = r.health();
    assert_eq!((h.segments_quarantined, h.segments_unindexed), (1, 0));
    assert_ne!(r.state(), RecorderState::Held(HoldReason::IndexReadOnly));
}
