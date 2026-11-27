//! Segment handling: discontinuity, parameter change, B slices, the clock, keys and the close
//! sequence's failure paths, against a real `HotStore` and a real `Index`.

#![expect(
    clippy::unwrap_used,
    clippy::many_single_char_names,
    clippy::arithmetic_side_effects,
    reason = "test code on small synthetic values; a panic is a failure; one table per invariant"
)]

mod common;

use std::path::{Path, PathBuf};

use common::rig::*;
use common::*;
use wardenlens_core::recording::{RelPath, SegmentConfig, SegmentRecord};
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_recorder::{HoldReason, Recorder, RecorderConfig, RecorderState};

// ---- discontinuity, parameters ----

#[test]
fn a_discontinuity_on_a_delta_frame_closes_the_segment_and_waits_for_a_keyframe() {
    let mut r = Rig::new();
    r.start();
    for _ in 1..20 {
        r.feed(Slice::P);
    }
    r.gop(5); // i = 20..24
    let s = r.spec(Slice::P).with_loss(); // i = 25
    r.push(&s);
    assert_eq!(r.state(), RecorderState::Waiting);
    for _ in 26..40 {
        r.feed(Slice::P);
    }
    r.gop(11); // i = 40..50
    let d = r.finish();
    assert_eq!(d.frames(), [25, 11]);
    assert_eq!(d.durations(), [2500, 1100]);
    assert_eq!(d.end.frames_dropped, 15);
}

#[test]
fn a_discontinuity_on_a_keyframe_closes_and_restarts_at_once() {
    let mut r = Rig::new();
    r.start();
    for _ in 1..20 {
        r.feed(Slice::P);
    }
    let s = r.spec(Slice::Idr).with_loss();
    r.push(&s);
    for _ in 0..9 {
        r.feed(Slice::P);
    }
    let d = r.finish();
    assert_eq!(d.frames(), [20, 10]);
    assert_eq!(d.end.frames_dropped, 0);
}

#[test]
fn a_reconnect_starts_a_new_segment_with_media_time_zero() {
    let mut r = Rig::new();
    r.start();
    for _ in 1..10 {
        r.feed(Slice::P);
    }
    r.feeder.reconnect();
    // RTP restarts anywhere after a reconnect.
    let s = Spec::key(7).with_params(params(&SPS_A));
    r.push(&s);
    for k in 1..5 {
        r.push(&Spec::p(7 + k * 9000));
    }
    let d = r.finish();
    assert_eq!(d.frames(), [10, 5]);
    assert_eq!(d.durations(), [1000, 500]);
}

#[test]
fn a_parameter_change_closes_the_segment_and_the_new_file_carries_the_new_parameters() {
    let mut r = Rig::new();
    r.start();
    for _ in 1..10 {
        r.feed(Slice::P);
    }
    // The same parameters again on a delta frame: no change, no cut.
    let s = r.spec(Slice::P).with_params(params(&SPS_A));
    r.push(&s);
    for _ in 11..20 {
        r.feed(Slice::P);
    }
    let s = r.spec(Slice::Idr).with_params(params(&SPS_B));
    r.push(&s);
    for _ in 21..30 {
        r.feed(Slice::P);
    }
    let d = r.finish();
    assert_eq!(d.frames(), [20, 10]);
    let (a, b) = (d.file(0), d.file(1));
    assert!(contains(&a, &SPS_A) && !contains(&a, &SPS_B));
    assert!(contains(&b, &SPS_B) && !contains(&b, &SPS_A));
}

#[test]
fn unusable_parameters_hold_recording_until_good_ones_arrive() {
    let mut r = Rig::new();
    let bad = wardenlens_ingest::RawParams {
        sps: vec![0x67, 1],
        pps: PPS.to_vec(),
    };
    let s = r.spec(Slice::Idr).with_params(bad);
    r.push(&s);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::BadParameters));
    r.feed(Slice::P);
    r.feed(Slice::Idr); // no parameters yet: still held, nothing written
    assert_eq!(tree(&r.root).len(), 0);
    let s = r.spec(Slice::Idr).with_params(params(&SPS_A));
    r.push(&s);
    assert_eq!(r.state(), RecorderState::Recording);
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!(d.frames(), [2]);
    assert_eq!(d.end.frames_dropped, 3);
}

#[test]
fn keyframes_without_parameters_are_dropped() {
    let mut r = Rig::new();
    let s = r.spec(Slice::Idr);
    r.push(&s);
    assert_eq!(r.state(), RecorderState::Waiting);
    assert_eq!(tree(&r.root).len(), 0);
    assert_eq!(r.health().frames_dropped, 1);
}

// ---- B slices (#157): no wrong timestamps, a clear hold ----

fn b_scenario(bad: Slice) -> Done {
    let mut r = Rig::new();
    r.start();
    for _ in 1..30 {
        r.feed(Slice::P);
    }
    r.feed(bad); // i = 30
    assert_eq!(r.state(), RecorderState::Held(HoldReason::BFramesDetected));
    // The hold is for good: keyframes, new parameters and a reconnect do not lift it.
    for _ in 31..40 {
        r.feed(Slice::P);
    }
    r.feeder.reconnect();
    let s = r.spec(Slice::Idr).with_params(params(&SPS_B));
    r.push(&s);
    for _ in 41..50 {
        r.feed(Slice::P);
    }
    assert_eq!(r.state(), RecorderState::Held(HoldReason::BFramesDetected));
    r.finish()
}

#[test]
fn a_b_slice_closes_the_segment_before_it_and_holds_recording_off() {
    let d = b_scenario(Slice::Type(1));
    assert_eq!(d.frames(), [30]);
    assert_eq!(d.durations(), [3000]);
    assert_eq!(d.end.frames_dropped, 20);
    assert_eq!(
        d.end.state,
        RecorderState::Held(HoldReason::BFramesDetected)
    );
    // Nothing else on disk: no second file, no .part.
    assert_eq!(tree(&d.root).len(), 1);
    assert!(!contains(&d.file(0), &SPS_B));
}

#[test]
fn a_b_slice_behind_another_nal_unit_is_found() {
    assert_eq!(b_scenario(Slice::PThenB).frames(), [30]);
}

#[test]
fn a_b_slice_in_the_very_first_frame_creates_nothing() {
    let mut r = Rig::new();
    let s = r.spec(Slice::Type(6)).with_params(params(&SPS_A));
    r.push(&s);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::BFramesDetected));
    assert_eq!(tree(&r.root).len(), 0);
    assert_eq!(r.finish().rows.len(), 0);
}

#[test]
fn every_slice_type_of_table_7_6_is_judged() {
    // slice_type 1 and 6 are B; 0..=9 are valid; above 9 the header is malformed.
    for t in 0..=12u32 {
        let mut r = Rig::new();
        r.start();
        r.feed(Slice::Type(t));
        r.feed(Slice::P);
        let b = t == 1 || t == 6;
        let state = r.state();
        let h = r.health();
        assert_eq!(
            state == RecorderState::Held(HoldReason::BFramesDetected),
            b,
            "slice_type {t}"
        );
        assert_eq!(h.stream_errors, u64::from(t > 9), "slice_type {t}");
        let d = r.finish();
        let want = if b || t > 9 { 1 } else { 3 };
        assert_eq!(d.frames().first().copied(), Some(want), "slice_type {t}");
    }
}

#[test]
fn a_cut_off_slice_header_is_a_stream_error_not_a_hold() {
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    r.feed(Slice::Cut);
    assert_eq!(r.state(), RecorderState::Waiting);
    r.gop(3);
    let d = r.finish();
    assert_eq!(d.frames(), [2, 3]);
    assert_eq!(d.end.stream_errors, 1);
}

// ---- the wall clock ----

#[test]
fn the_wall_clock_bounds_are_exact() {
    let rows = [
        (946_684_799_999_i64, false),
        (946_684_800_000, true),
        (4_102_444_799_999, true),
        (4_102_444_800_000, false),
        (0, false),
        (-1, false),
        (i64::MIN, false),
        (i64::MAX, false),
    ];
    for (at, ok) in rows {
        let mut r = Rig::new();
        r.feeder.clock.set(at);
        let f = r.feeder.frame(&Spec::key(0).with_params(params(&SPS_A)));
        r.rec.push_frame(f);
        let want = if ok {
            RecorderState::Recording
        } else {
            RecorderState::Held(HoldReason::ClockOutOfRange)
        };
        assert_eq!(r.state(), want, "{at}");
        assert_eq!(tree(&r.root).len(), usize::from(ok), "{at}");
        // The clock recovers: recording resumes at the next keyframe.
        r.feeder.clock.set(T0);
        let f = r.feeder.frame(&Spec::key(9000));
        r.rec.push_frame(f);
        assert_eq!(r.state(), RecorderState::Recording, "{at}");
        let d = r.finish();
        assert_eq!(d.rows.len(), 1, "{at}");
        assert_eq!(
            d.end.segments_indexed,
            u64::try_from(d.rows.len()).unwrap(),
            "{at}"
        );
    }
}

#[test]
fn a_clock_that_leaves_its_range_mid_segment_closes_the_segment() {
    let mut r = Rig::new();
    r.start();
    for _ in 1..10 {
        r.feed(Slice::P);
    }
    r.feeder.clock.set(5_000_000_000_000);
    r.feed(Slice::P);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::ClockOutOfRange));
    assert_eq!(part_files(&r.root).len(), 0);
    // Back in range: the hold ends at once, recording resumes at the next keyframe.
    r.feeder.clock.set(T0 + 5_000);
    r.feed(Slice::P);
    assert_eq!(r.state(), RecorderState::Waiting);
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Recording);
    let d = r.finish();
    assert_eq!(d.frames(), [10, 1]);
}

// ---- unique started_at_ms ----

/// Segments of 10 s: a keyframe every 10 s of media time, all stamped `arrival`.
fn three_segments_at(r: &mut Rig, arrival: [i64; 3]) {
    for (k, at) in arrival.into_iter().enumerate() {
        r.feeder.clock.set(at);
        let f = r
            .feeder
            .frame(&Spec::key(u32::try_from(k).unwrap() * 900_000).with_params(params(&SPS_A)));
        r.rec.push_frame(f);
        r.feeder.clock.set(at);
        let f = r
            .feeder
            .frame(&Spec::p(u32::try_from(k).unwrap() * 900_000 + 9000));
        r.rec.push_frame(f);
    }
}

fn short() -> RecorderConfig {
    fast().with_segment(SegmentConfig::new(10, 1 << 30).unwrap())
}

#[test]
fn equal_arrivals_get_distinct_keys_one_millisecond_apart() {
    let mut r = Rig::build(short(), None, |_, _| {});
    three_segments_at(&mut r, [T0, T0, T0]);
    let d = r.finish();
    let keys: Vec<i64> = d
        .rows
        .iter()
        .map(|x| x.record.started_at_ms.as_i64())
        .collect();
    assert_eq!(keys, [T0, T0 + 1, T0 + 2]);
    assert_eq!(d.end.clock_stepped_back, 1); // the 2nd is equal (no warning), the 3rd is behind T0+1
    for row in &d.rows {
        let rel = RelPath::new(&row.record.camera, row.record.started_at_ms);
        assert!(d.root.join(rel.to_string()).is_file());
    }
}

#[test]
fn a_clock_stepped_back_keeps_its_arrival_and_raises_a_warning() {
    let mut r = Rig::build(short(), None, |_, _| {});
    three_segments_at(&mut r, [T0, T0 - 3_600_000, T0 + 20_000]);
    let d = r.finish();
    let keys: Vec<i64> = d
        .rows
        .iter()
        .map(|x| x.record.started_at_ms.as_i64())
        .collect();
    assert_eq!(keys, [T0 - 3_600_000, T0, T0 + 20_000]);
    assert_eq!(d.end.clock_stepped_back, 1);
}

#[test]
fn a_forward_step_does_not_compress_the_index() {
    let mut r = Rig::build(short(), None, |_, _| {});
    three_segments_at(&mut r, [T0, T0 + 7_200_000, T0 + 7_200_001]);
    let d = r.finish();
    let keys: Vec<i64> = d
        .rows
        .iter()
        .map(|x| x.record.started_at_ms.as_i64())
        .collect();
    assert_eq!(keys, [T0, T0 + 7_200_000, T0 + 7_200_001]);
    assert_eq!(d.end.clock_stepped_back, 0);
}

fn row(at: i64) -> SegmentRecord {
    SegmentRecord::new(cam(), ms(at), 1000, 100, 1)
}

#[test]
fn the_key_is_seeded_from_the_index_maximum() {
    let mut r = Rig::build(short(), None, |_, idx| {
        idx.inner.insert(&row(T0), Tier::Hot).unwrap();
    });
    three_segments_at(&mut r, [T0, T0 - 5000, T0 + 100_000]);
    let d = r.finish();
    let keys: Vec<i64> = d
        .rows
        .iter()
        .map(|x| x.record.started_at_ms.as_i64())
        .collect();
    assert_eq!(keys, [T0 - 5000, T0, T0 + 1, T0 + 100_000]);
}

#[test]
fn a_key_below_the_maximum_is_probed_against_every_row() {
    // Rows at T0, T0+1 and T0+200: an arrival at T0 must skip both taken keys.
    let mut r = Rig::build(short(), None, |_, idx| {
        for at in [T0, T0 + 1, T0 + 200] {
            idx.inner.insert(&row(at), Tier::Hot).unwrap();
        }
    });
    three_segments_at(&mut r, [T0, T0 + 100_000, T0 + 200_000]);
    let d = r.finish();
    let keys: Vec<i64> = d
        .rows
        .iter()
        .map(|x| x.record.started_at_ms.as_i64())
        .collect();
    assert_eq!(
        keys,
        [T0, T0 + 1, T0 + 2, T0 + 200, T0 + 100_000, T0 + 200_000]
    );
}

#[test]
fn the_key_is_seeded_from_the_reconciliation_walk_maximum() {
    let mut r = Rig::build(short(), Some(T0), |_, _| {});
    three_segments_at(&mut r, [T0, T0 + 100_000, T0 + 200_000]);
    let d = r.finish();
    assert_eq!(d.rows[0].record.started_at_ms.as_i64(), T0 + 1);
}

fn plant(root: &Path, key: i64, suffix: &str) -> PathBuf {
    let rel = RelPath::new(&cam(), ms(key)).to_string();
    let path = root.join(format!("{rel}{suffix}"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

#[test]
fn foreign_files_at_a_key_are_never_touched_or_replaced() {
    type Plant = fn(&Path);
    let table: [(&str, Plant); 5] = [
        ("an orphan .mp4", |p| std::fs::write(p, b"orphan").unwrap()),
        ("a stale .part", |p| std::fs::write(p, b"stale").unwrap()),
        ("a dangling symlink", |p| {
            std::os::unix::fs::symlink("/nonexistent-wardenlens-target", p).unwrap();
        }),
        ("a directory", |p| std::fs::create_dir(p).unwrap()),
        ("a fifo", |p| {
            let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
            let _ = c;
            std::process::Command::new("mkfifo")
                .arg(p)
                .status()
                .unwrap();
        }),
    ];
    for (name, make) in table {
        for suffix in ["", ".part"] {
            let mut r = Rig::build(short(), None, |root, _| {
                make(&plant(root, T0, suffix));
            });
            three_segments_at(&mut r, [T0, T0 + 100_000, T0 + 200_000]);
            let planted = plant(&r.root, T0, suffix);
            let before = std::fs::symlink_metadata(&planted).unwrap().len();
            let d = r.finish();
            let keys: Vec<i64> = d
                .rows
                .iter()
                .map(|x| x.record.started_at_ms.as_i64())
                .collect();
            assert_eq!(
                keys,
                [T0 + 1, T0 + 100_000, T0 + 200_000],
                "{name} {suffix}"
            );
            assert_eq!(
                std::fs::symlink_metadata(&planted).unwrap().len(),
                before,
                "{name} {suffix}"
            );
            if name == "an orphan .mp4" && suffix.is_empty() {
                assert_eq!(std::fs::read(&planted).unwrap(), b"orphan");
            }
        }
    }
}

#[test]
fn a_symlinked_camera_or_day_directory_is_refused_and_nothing_is_written_through_it() {
    for day in [false, true] {
        let mut r = Rig::build(short(), None, |root, _| {
            let outside = root.parent().unwrap().join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            if day {
                std::fs::create_dir_all(root.join("cam1")).unwrap();
                std::os::unix::fs::symlink(&outside, root.join("cam1").join(DAY)).unwrap();
            } else {
                std::os::unix::fs::symlink(&outside, root.join("cam1")).unwrap();
            }
        });
        three_segments_at(&mut r, [T0, T0 + 100_000, T0 + 200_000]);
        assert_eq!(
            r.state(),
            RecorderState::Held(HoldReason::WriteFailed),
            "{day}"
        );
        let outside = r.root.parent().unwrap().join("outside");
        assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0, "{day}");
        assert!(r.finish().rows.is_empty(), "{day}");
    }
}

#[test]
fn a_recorder_cannot_be_built_when_the_index_seed_cannot_be_read() {
    let dir = private_tempdir();
    let (store, _) = TestStore::new(&hot_root(dir.path()));
    let (index, script) = TestIndex::open(dir.path());
    script.lock().unwrap().seed_error = Some(wardenlens_index::IndexError::Busy { op: "x" });
    let e = Recorder::new(cam(), fast(), store, index, None)
        .err()
        .unwrap();
    assert!(matches!(e, wardenlens_recorder::RecorderError::Seed(_)));
    assert!(e.to_string().contains("busy"));
}
