//! The close sequence's failure paths (index retry and quarantine, a full volume, write errors)
//! and the size limits (hard maximum, fragment cap), against real files and a real index.

#![expect(
    clippy::unwrap_used,
    reason = "test code on small synthetic values; a panic is a failure; one table per invariant"
)]

mod common;

use common::rig::*;
use common::*;
use rusqlite::ErrorCode;
use wardenlens_core::mp4box::{SliceSource, summarize};
use wardenlens_core::recording::{RelPath, SegmentConfig, SegmentRecord};
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_index::IndexError;
use wardenlens_recorder::{ChannelSource, HoldReason, Recorder, RecorderState, StoreError};

fn io_error() -> StoreError {
    StoreError::Io {
        op: "write",
        kind: std::io::ErrorKind::Other,
    }
}

/// One 2-frame segment with these insert errors queued, then a graceful stop.
fn one_segment(
    errors: Vec<IndexError>,
    config: wardenlens_recorder::RecorderConfig,
) -> (Done, u32) {
    let mut r = Rig::build(config, None, |_, _| {});
    r.index.lock().unwrap().insert_errors = errors.into();
    r.start();
    r.feed(Slice::P);
    let script = r.index.clone();
    let d = r.finish();
    let attempts = script.lock().unwrap().attempts;
    (d, attempts)
}

fn transient() -> Vec<fn() -> IndexError> {
    vec![
        || IndexError::Busy { op: "insert" },
        || IndexError::Sqlite {
            op: "insert",
            code: Some(ErrorCode::SystemIoFailure),
        },
        || IndexError::Sqlite {
            op: "insert",
            code: Some(ErrorCode::DiskFull),
        },
        || IndexError::Sqlite {
            op: "insert",
            code: Some(ErrorCode::OutOfMemory),
        },
    ]
}

fn permanent() -> Vec<fn() -> IndexError> {
    vec![
        || IndexError::Duplicate,
        || IndexError::Constraint { op: "insert" },
        || IndexError::InvalidRecord { field: "bytes" },
        || IndexError::Damaged,
        // `SQLITE_READONLY` is not here since #195: it holds the recorder and keeps the file
        // (tests/readonly_index.rs).
        || IndexError::Sqlite {
            op: "insert",
            code: None,
        },
    ]
}

#[test]
fn a_transient_insert_error_is_retried_and_the_segment_is_indexed() {
    for make in transient() {
        let (d, attempts) = one_segment(vec![make(), make(), make()], fast());
        assert_eq!(attempts, 4);
        assert_eq!(d.end.segments_indexed, 1);
        assert_eq!(d.rows.len(), 1);
    }
}

#[test]
fn a_transient_error_that_never_ends_stops_at_the_bound_and_keeps_the_file() {
    for make in transient() {
        for retries in [0u32, 1, 5] {
            let config = fast().with_insert_retries(retries, std::time::Duration::ZERO);
            let (d, attempts) = one_segment((0..20).map(|_| make()).collect(), config);
            assert_eq!(attempts, retries + 1, "bound {retries}");
            assert_eq!(d.end.segments_unindexed, 1);
            assert_eq!(d.end.segments_quarantined, 0);
            assert_eq!(d.rows.len(), 0);
            // The finished file stays for the reconciliation pass of the next start.
            let names = tree(&d.root);
            assert_eq!(names.len(), 1, "{names:?}");
            assert!(names[0].contains(".mp4") && !names[0].contains("_quarantine"));
        }
    }
}

#[test]
fn a_permanent_insert_error_quarantines_the_file_without_a_retry() {
    for make in permanent() {
        let (d, attempts) = one_segment(vec![make()], fast());
        assert_eq!(attempts, 1);
        assert_eq!(d.end.segments_quarantined, 1);
        assert_eq!(d.end.segments_indexed, 0);
        let names = tree(&d.root);
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(
            names[0].starts_with(&format!("_quarantine/cam1/{DAY}/")),
            "{names:?}"
        );
        assert!(names[0].contains(".mp4"));
    }
}

#[test]
fn a_full_volume_when_a_segment_starts_holds_and_retries_once_space_is_back() {
    let mut r = Rig::new();
    r.store.lock().unwrap().create_error = Some(StoreError::NoSpace);
    r.start();
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    assert_eq!(tree(&r.root).len(), 0);
    r.store.lock().unwrap().available = Some(0);
    for _ in 0..5 {
        r.feed(Slice::Idr);
    }
    // No space: the store is not asked to create again.
    assert_eq!(r.store.lock().unwrap().creates, 1);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    r.store.lock().unwrap().available = Some(1 << 30);
    r.feed(Slice::Idr);
    assert_eq!(r.store.lock().unwrap().creates, 2);
    assert_eq!(r.state(), RecorderState::Recording);
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!(d.frames(), [2]);
    assert_eq!(d.end.segments_aborted, 1);
}

#[test]
fn a_full_volume_mid_segment_aborts_it_removes_the_part_and_resumes_later() {
    let mut r = Rig::new();
    r.start();
    for _ in 1..20 {
        r.feed(Slice::P);
    }
    {
        let mut s = r.store.lock().unwrap();
        s.appends_until_error = Some(0);
        s.append_error = Some(StoreError::NoSpace);
        s.available = Some(0);
    }
    r.feed(Slice::Idr); // the fragment flush fails
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    assert_eq!(part_files(&r.root).len(), 0);
    assert_eq!(r.store.lock().unwrap().aborts, 1);
    for _ in 0..30 {
        r.feed(Slice::P);
    }
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    r.store.lock().unwrap().available = Some(1 << 30);
    r.feed(Slice::Idr);
    r.feed(Slice::P);
    assert_eq!(r.state(), RecorderState::Recording);
    let d = r.finish();
    assert_eq!(d.frames(), [2], "only the complete segment is indexed");
    assert_eq!(d.end.segments_aborted, 1);
    assert_eq!(tree(&d.root).len(), 1);
}

#[test]
fn a_full_volume_while_closing_loses_the_segment_and_leaves_no_file() {
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    r.store.lock().unwrap().commit_error = Some(StoreError::NoSpace);
    let d = r.finish();
    assert_eq!(d.rows.len(), 0);
    assert_eq!(tree(&d.root).len(), 0);
    assert_eq!(d.end.state, RecorderState::Held(HoldReason::StorageFull));
    assert_eq!(d.end.segments_aborted, 1);
}

#[test]
fn another_write_error_aborts_the_segment_and_retries_at_the_next_keyframe() {
    let mut r = Rig::new();
    r.start();
    for _ in 1..20 {
        r.feed(Slice::P);
    }
    {
        let mut s = r.store.lock().unwrap();
        s.appends_until_error = Some(0);
        s.append_error = Some(io_error());
        s.available = Some(0); // irrelevant: not a full volume
    }
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::WriteFailed));
    assert_eq!(part_files(&r.root).len(), 0);
    r.feed(Slice::P);
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Recording);
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!(d.frames(), [2]);
}

#[test]
fn a_failed_close_for_another_reason_is_a_write_failure() {
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    r.store.lock().unwrap().commit_error = Some(io_error());
    let d = r.finish();
    assert_eq!(d.end.state, RecorderState::Held(HoldReason::WriteFailed));
    assert_eq!(tree(&d.root).len(), 0);
}

#[test]
fn a_lost_race_for_the_name_takes_the_next_key() {
    let mut r = Rig::new();
    r.store.lock().unwrap().create_error = Some(StoreError::NameTaken);
    r.start();
    r.feed(Slice::P);
    r.feed(Slice::Idr);
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!(d.frames(), [4]);
    assert_eq!(d.rows[0].record.started_at_ms.as_i64(), T0 + 101);
}

// ---- size limits ----

#[test]
fn the_hard_maximum_closes_the_segment_on_the_frame_and_waits_for_a_keyframe() {
    // Target 10 s, hard maximum 20 s.
    let config = fast().with_segment(SegmentConfig::new(10, 1 << 30).unwrap());
    let mut r = Rig::build(config, None, |_, _| {});
    r.start();
    for _ in 1..250 {
        r.feed(Slice::P);
    }
    r.feed(Slice::Idr);
    for _ in 0..4 {
        r.feed(Slice::P);
    }
    let d = r.finish();
    assert_eq!(d.frames(), [200, 5]);
    assert_eq!(d.durations(), [20_000, 500]);
    assert_eq!(d.end.frames_dropped, 50);
}

#[test]
fn a_gop_over_the_fragment_cap_is_split_into_fragments_and_stays_valid() {
    let mut r = Rig::new();
    r.start();
    for _ in 0..20 {
        let s = r.spec(Slice::P).with_size(1 << 20);
        r.push(&s);
    }
    let d = r.finish();
    let file = d.file(0);
    let moofs = file.windows(4).filter(|w| *w == b"moof").count();
    assert_eq!(moofs, 2, "one GOP over 16 MiB is cut once");
    let sum = summarize(&mut SliceSource(&file)).unwrap();
    assert_eq!(sum.frame_count, 21);
    assert_eq!(d.rows[0].record.frame_count, 21);
    assert_eq!(d.rows[0].record.bytes, u64::try_from(file.len()).unwrap());
    assert_eq!(d.rows[0].record.duration_ms, sum.duration_ms);
}

// ---- the channel source ----

#[test]
fn the_channel_source_ends_the_recording_when_the_sender_is_dropped() {
    let dir = private_tempdir();
    let (store, _) = TestStore::new(&hot_root(dir.path()));
    let (index, _) = TestIndex::open(dir.path());
    let (recorder, health) = Recorder::new(cam(), fast(), store, index, None).unwrap();
    let mut feeder = Feeder::new();
    let frames = stream(&mut feeder, 30, 10, 20);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let producer = std::thread::spawn(move || {
        for f in frames {
            tx.blocking_send(f).unwrap();
        }
    });
    let end = recorder.run(ChannelSource::new(rx));
    producer.join().unwrap();
    assert_eq!(end.segments_indexed, 1);
    assert_eq!(health.borrow().segments_indexed, 1);
    assert_eq!(health.borrow().state, RecorderState::Waiting);
}

// ---- round 2: insert that commits and then fails, durability, back-off, index probe ----

#[test]
fn a_transient_error_after_the_row_was_committed_does_not_quarantine_the_segment() {
    // SQLite's checkpoint inside COMMIT can fail after the row is durable: the retry then meets
    // its own row as a duplicate.
    for make in transient() {
        let mut r = Rig::new();
        r.index.lock().unwrap().commit_then_error = vec![make()].into();
        r.start();
        r.feed(Slice::P);
        let d = r.finish();
        assert_eq!(d.end.segments_indexed, 1, "{:?}", d.end);
        assert_eq!(d.end.segments_quarantined, 0);
        assert_eq!(d.rows.len(), 1);
        assert_eq!(tree(&d.root).len(), 1);
        assert!(!tree(&d.root)[0].contains("_quarantine"));
    }
}

#[test]
fn the_committed_row_is_found_even_when_the_retries_run_out() {
    let config = fast().with_insert_retries(0, std::time::Duration::ZERO);
    let mut r = Rig::build(config, None, |_, _| {});
    r.index.lock().unwrap().commit_then_error = vec![IndexError::Busy { op: "insert" }].into();
    r.start();
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!((d.end.segments_indexed, d.end.segments_unindexed), (1, 0));
}

#[test]
fn a_duplicate_after_a_transient_error_without_a_matching_row_still_quarantines() {
    // Busy, then Duplicate, and no row exists: nothing indexes this file.
    let mut r = Rig::new();
    r.index.lock().unwrap().insert_errors =
        vec![IndexError::Busy { op: "insert" }, IndexError::Duplicate].into();
    r.start();
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!((d.end.segments_indexed, d.end.segments_quarantined), (0, 1));
}

#[test]
fn a_directory_that_cannot_be_synced_keeps_the_file_and_skips_the_insert() {
    let mut r = Rig::new();
    r.store.lock().unwrap().not_durable = true;
    r.start();
    r.feed(Slice::P);
    let attempts = r.index.clone();
    let d = r.finish();
    assert_eq!(attempts.lock().unwrap().attempts, 0);
    assert_eq!((d.end.segments_indexed, d.end.segments_unindexed), (0, 1));
    assert_eq!(d.end.segments_aborted, 0);
    assert_eq!(d.rows.len(), 0);
    let names = tree(&d.root);
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(names[0].contains(".mp4") && !names[0].contains(".part"));
}

#[test]
fn a_file_planted_at_the_final_name_mid_segment_is_skipped_and_the_segment_is_kept() {
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    let planted = r
        .root
        .join(wardenlens_core::recording::RelPath::new(&cam(), ms(T0 + 100)).to_string());
    std::fs::write(&planted, b"foreign").unwrap();
    let d = r.finish();
    assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
    assert_eq!(d.rows.len(), 1);
    assert_eq!(d.rows[0].record.started_at_ms.as_i64(), T0 + 101);
    assert_eq!(tree(&d.root).len(), 2);
}

#[test]
fn a_volume_that_cannot_be_freed_is_retried_with_a_growing_back_off_not_in_a_loop() {
    // Creating works and statvfs shows room (a quota, or a volume refilled by someone else),
    // but every write fails with ENOSPC. The recorder must not create and delete a segment at
    // every keyframe.
    let mut r = Rig::new();
    {
        let mut s = r.store.lock().unwrap();
        s.appends_until_error = Some(0);
        s.appends_always_full = true;
        s.available = Some(1 << 40);
    }
    r.start();
    for k in 1..400u32 {
        // A keyframe every 10 frames, 1 s apart.
        for _ in 0..9 {
            r.feed(Slice::P);
        }
        r.feed(Slice::Idr);
        assert!(part_files(&r.root).len() <= 1, "{k}");
    }
    let creates = r.store.lock().unwrap().creates;
    let aborts = r.store.lock().unwrap().aborts;
    // Back-off 1, 2, 4, 8, 16, 32 keyframes, then every 33rd: about 17 attempts in 400.
    assert!(creates <= 20, "{creates} creates in 400 keyframes");
    assert!(creates >= 8, "{creates}: it must keep trying");
    assert_eq!(creates, aborts);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    // Space that is real: it recovers.
    {
        let mut s = r.store.lock().unwrap();
        s.appends_until_error = None;
    }
    for _ in 0..40 {
        for _ in 0..9 {
            r.feed(Slice::P);
        }
        r.feed(Slice::Idr);
    }
    assert_eq!(r.state(), RecorderState::Recording);
    let d = r.finish();
    assert_eq!(d.rows.len(), 1);
}

#[test]
fn the_aborted_segments_size_must_be_free_again_before_a_retry() {
    // The abort freed the segment's own bytes, so seeing them free proves nothing.
    let config = fast().with_resume_free_bytes(1_000);
    let mut r = Rig::build(config, None, |_, _| {});
    r.start();
    for _ in 1..20 {
        r.feed(Slice::P);
    }
    {
        let mut s = r.store.lock().unwrap();
        s.appends_until_error = Some(0);
        s.append_error = Some(StoreError::NoSpace);
    }
    r.feed(Slice::Idr); // the flush of 20 frames fails
    r.feed(Slice::P);
    r.feed(Slice::Idr); // consumed by the back-off
    // Written so far: the init segment and nothing else (the first fragment failed), so the
    // need is the margin plus the init segment's length (a few hundred bytes).
    r.store.lock().unwrap().available = Some(1_000);
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    r.store.lock().unwrap().available = Some(1_000_000);
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Recording);
}

#[test]
fn an_index_that_cannot_answer_holds_with_its_own_reason_and_recovers() {
    let mut r = Rig::new();
    r.index.lock().unwrap().list_errors = 1;
    r.start();
    assert_eq!(r.state(), RecorderState::Held(HoldReason::IndexUnavailable));
    assert_eq!(tree(&r.root).len(), 0);
    r.feed(Slice::P);
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Recording);
    let d = r.finish();
    assert_eq!(d.rows.len(), 1);
}

#[test]
fn the_seed_error_keeps_its_source() {
    let dir = private_tempdir();
    let (store, _) = TestStore::new(&hot_root(dir.path()));
    let (index, script) = TestIndex::open(dir.path());
    script.lock().unwrap().seed_error = Some(IndexError::Busy { op: "x" });
    let e = Recorder::new(cam(), fast(), store, index, None)
        .err()
        .unwrap();
    let source = std::error::Error::source(&e).unwrap();
    assert!(source.to_string().contains("busy"));
}

#[test]
fn a_row_at_the_key_that_is_another_segment_is_not_this_one_and_quarantines() {
    // Busy after another row took the key, then Duplicate: the read-back sees a row that
    // differs (size), so this file is not indexed and is quarantined.
    let mut r = Rig::new();
    r.index.lock().unwrap().other_row_then_error = vec![IndexError::Busy { op: "insert" }].into();
    r.start();
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!((d.end.segments_indexed, d.end.segments_quarantined), (0, 1));
}

#[test]
fn an_unreadable_index_never_quarantines_a_file_after_a_duplicate() {
    // Busy, Duplicate, and the read-back is refused: the answer is unknown, not "no row".
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    {
        let mut s = r.index.lock().unwrap();
        s.insert_errors = vec![IndexError::Busy { op: "insert" }, IndexError::Duplicate].into();
        s.list_errors = 1;
    }
    let d = r.finish();
    assert_eq!(
        (d.end.segments_quarantined, d.end.segments_unindexed),
        (0, 1)
    );
    assert_eq!(tree(&d.root).len(), 1);
    assert!(!tree(&d.root)[0].contains("_quarantine"));
}

/// The rename bump never lands on a key an index row holds (#195): the segment is finished under
/// the next free key and indexed there; the held key's row and the planted file are untouched.
#[test]
fn a_segment_bumped_past_a_key_another_row_holds_is_indexed_under_a_free_key() {
    let (r, planted) = bumped_rig();
    let d = r.finish();
    assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
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
    assert_eq!(d.rows.len(), 2);
    assert_eq!(d.rows[0].record.started_at_ms, ms(T0 + 101));
    assert_eq!(d.rows[0].record.bytes, 4_096);
    assert_eq!(d.rows[1].record.started_at_ms, ms(T0 + 102));
    let own = d.root.join(RelPath::new(&cam(), ms(T0 + 102)).to_string());
    assert_eq!(
        std::fs::metadata(own).unwrap().len(),
        d.rows[1].record.bytes
    );
}

/// Every key the bump passes is checked, however many rows hold consecutive keys, up to the
/// rename bound; past it the finished recording is kept in quarantine (never deleted), counted
/// quarantined, and no file is left under a held key.
#[test]
fn a_run_of_held_keys_is_skipped_and_too_long_a_run_aborts_without_a_file_at_any_of_them() {
    for (held, indexed, quarantined) in [(3_i64, 1_u64, 0_u64), (6, 1, 0), (7, 0, 1)] {
        let mut r = Rig::build(fast(), None, |_, index| {
            for n in 1..=held {
                let rec = SegmentRecord::new(cam(), ms(T0 + 100 + n), 1_000, 4_096, 10);
                index.insert(&rec, Tier::Archive).unwrap();
            }
        });
        r.start();
        r.feed(Slice::P);
        let planted = r.root.join(RelPath::new(&cam(), ms(T0 + 100)).to_string());
        std::fs::write(&planted, b"foreign").unwrap();
        let d = r.finish();
        assert_eq!(
            (
                d.end.segments_indexed,
                d.end.segments_quarantined,
                d.end.segments_aborted
            ),
            (indexed, quarantined, 0),
            "{held} held keys: {:?}",
            d.end
        );
        for n in 1..=held {
            let k = d
                .root
                .join(RelPath::new(&cam(), ms(T0 + 100 + n)).to_string());
            assert!(!k.exists(), "{held}: {:?}", tree(&d.root));
        }
        // No `.part` is left in the day directory; the sealed one is in quarantine, whole.
        let parts = part_files(&d.root);
        assert_eq!(
            parts.len(),
            usize::try_from(quarantined).unwrap(),
            "{parts:?}"
        );
        assert!(parts.iter().all(|p| p.starts_with("_quarantine/")));
        for p in &parts {
            let bytes = std::fs::read(d.root.join(p)).unwrap();
            summarize(&mut SliceSource(&bytes)).unwrap();
        }
        assert_eq!(
            d.rows.len(),
            usize::try_from(held + i64::try_from(indexed).unwrap()).unwrap()
        );
    }
}
