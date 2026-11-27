//! Ticket #57 acceptance: about three minutes of synthetic frames (fake source, fake clock,
//! temporary directory, temporary database) give three indexed segments whose durations and
//! byte counts match the files.

#![expect(
    clippy::unwrap_used,
    clippy::similar_names,
    reason = "test code on small synthetic values; a panic is a failure"
)]

mod common;

use std::os::unix::fs::PermissionsExt;

use common::*;
use wardenlens_core::mp4box::{SliceSource, summarize};
use wardenlens_core::recording::RelPath;
use wardenlens_core::storage::Tier;
use wardenlens_recorder::{Recorder, RecorderConfig, RecorderState};

/// 10 frames per second, a keyframe every 2 s, 180 s.
fn run_three_minutes(dir: &std::path::Path) -> (TestIndex, std::path::PathBuf) {
    let root = hot_root(dir);
    let (store, _) = TestStore::new(&root);
    let (index, _) = TestIndex::open(dir);
    let (recorder, health) =
        Recorder::new(cam(), RecorderConfig::default(), store, index, None).unwrap();
    let mut feeder = Feeder::new();
    let frames = stream(&mut feeder, 180, 10, 20);
    let end = recorder.run(frames.into_iter());
    assert_eq!(end.segments_indexed, 3);
    assert_eq!(*health.borrow(), end);
    // Reopen the database to read what a restart would see.
    let (index, _) = TestIndex::open(dir);
    (index, root)
}

#[test]
fn three_minutes_give_three_indexed_segments_that_match_their_files() {
    let dir = private_tempdir();
    let (index, root) = run_three_minutes(dir.path());
    let rows = rows(&index);
    assert_eq!(rows.len(), 3);
    let mut tiles = 0u64;
    for row in &rows {
        assert_eq!(row.tier, Tier::Hot);
        let rec = &row.record;
        let rel = RelPath::new(&rec.camera, rec.started_at_ms).to_string();
        let path = root.join(&rel);
        let bytes = std::fs::read(&path).unwrap();
        // Bytes: the row equals the file.
        assert_eq!(rec.bytes, u64::try_from(bytes.len()).unwrap());
        // Duration and frame count: the row equals what the file's own boxes say.
        let sum = summarize(&mut SliceSource(&bytes)).unwrap();
        assert_eq!(rec.duration_ms, sum.duration_ms);
        assert_eq!(rec.frame_count, sum.frame_count);
        // The patched header durations equal the sample table (90 kHz ticks).
        let (mvhd, mehd) = header_durations(&bytes);
        assert_eq!(mvhd, mehd);
        assert_eq!(mvhd.div_ceil(90), rec.duration_ms);
        tiles += rec.frame_count;
    }
    // 180 s at 10 fps, cut at the first keyframe at or after 60 s: 600 + 600 + 600 frames.
    assert_eq!(tiles, 1800);
    let counts: Vec<u64> = rows.iter().map(|r| r.record.frame_count).collect();
    assert_eq!(counts, [600, 600, 600]);
    // Each is a minute of media time (the last sample reuses the previous step).
    assert!(rows.iter().all(|r| r.record.duration_ms == 60_000));
    // Start times are the arrival of each segment's first frame.
    let starts: Vec<i64> = rows
        .iter()
        .map(|r| r.record.started_at_ms.as_i64())
        .collect();
    assert_eq!(starts, [T0 + 100, T0 + 60_100, T0 + 120_100]);
}

#[test]
fn the_layout_permissions_and_leftovers_follow_adr_0005() {
    let dir = private_tempdir();
    let (index, root) = run_three_minutes(dir.path());
    let names = tree(&root);
    assert_eq!(names.len(), 3, "no .part and nothing else: {names:?}");
    for row in rows(&index) {
        let rel = RelPath::new(&row.record.camera, row.record.started_at_ms).to_string();
        assert!(names.contains(&rel), "{rel} in {names:?}");
        assert!(rel.starts_with(&format!("cam1/{DAY}/")));
        let file_mode = std::fs::metadata(root.join(&rel))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o7777, 0o600);
    }
    for d in [root.join("cam1"), root.join("cam1").join(DAY)] {
        let mode = std::fs::metadata(&d).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o700);
    }
}

#[test]
fn at_most_one_part_file_exists_at_any_time() {
    let dir = private_tempdir();
    let root = hot_root(dir.path());
    let (store, script) = TestStore::new(&root);
    let (index, _) = TestIndex::open(dir.path());
    let (mut recorder, health) =
        Recorder::new(cam(), RecorderConfig::default(), store, index, None).unwrap();
    let mut feeder = Feeder::new();
    let mut seen_part = false;
    for frame in stream(&mut feeder, 130, 10, 20) {
        recorder.push_frame(frame);
        let parts = part_files(&root);
        assert!(parts.len() <= 1, "{parts:?}");
        seen_part |= parts.len() == 1;
    }
    assert!(seen_part);
    assert_eq!(health.borrow().state, RecorderState::Recording);
    let end = recorder.finish();
    assert_eq!(end.segments_indexed, 3);
    assert_eq!(part_files(&root).len(), 0);
    assert_eq!(script.lock().unwrap().max_open, 1);
}

#[test]
fn a_graceful_stop_flushes_and_indexes_the_open_segment() {
    let dir = private_tempdir();
    let root = hot_root(dir.path());
    let (store, _) = TestStore::new(&root);
    let (index, _) = TestIndex::open(dir.path());
    let (mut recorder, _) =
        Recorder::new(cam(), RecorderConfig::default(), store, index, None).unwrap();
    let mut feeder = Feeder::new();
    // 5 s of a segment that would have run for 60 s.
    for frame in stream(&mut feeder, 5, 10, 20) {
        recorder.push_frame(frame);
    }
    assert_eq!(part_files(&root).len(), 1);
    let end = recorder.finish();
    assert_eq!(end.segments_indexed, 1);
    assert_eq!(part_files(&root).len(), 0);
    let (index, _) = TestIndex::open(dir.path());
    let rows = rows(&index);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record.frame_count, 50);
    assert_eq!(rows[0].record.duration_ms, 5_000);
    let rel = RelPath::new(&cam(), rows[0].record.started_at_ms).to_string();
    let bytes = std::fs::read(root.join(rel)).unwrap();
    assert_eq!(rows[0].record.bytes, u64::try_from(bytes.len()).unwrap());
    assert_eq!(summarize(&mut SliceSource(&bytes)).unwrap().frame_count, 50);
}
