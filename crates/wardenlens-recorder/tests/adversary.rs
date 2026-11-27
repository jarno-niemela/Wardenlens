//! Adversarial checks of ticket #57 (PR #191): rows against files over hostile timestamp
//! patterns, nothing dropped silently, crash leftovers, foreign files at the final name,
//! quarantine exhaustion, the resume threshold and restarts.

#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::similar_names,
    reason = "test code on small synthetic values; a panic is a failure"
)]

mod common;

use common::rig::*;
use common::*;
use proptest::prelude::*;
use wardenlens_core::mp4box::{SliceSource, summarize};
use wardenlens_core::recording::{RelPath, SegmentConfig};
use wardenlens_index::IndexError;
use wardenlens_recorder::{HoldReason, Recorder, RecorderState, StoreError};

fn short() -> wardenlens_recorder::RecorderConfig {
    fast().with_segment(SegmentConfig::new(10, 1 << 30).unwrap())
}

/// Checks every row against its file with an independent parser.
fn rows_match_files(d: &Done) {
    for (i, row) in d.rows.iter().enumerate() {
        let file = d.file(i);
        let rec = &row.record;
        assert_eq!(
            rec.bytes,
            u64::try_from(file.len()).unwrap(),
            "row {i} bytes"
        );
        let sum = summarize(&mut SliceSource(&file)).unwrap();
        assert_eq!(rec.duration_ms, sum.duration_ms, "row {i} duration");
        assert_eq!(rec.frame_count, sum.frame_count, "row {i} frames");
        let (mvhd, mehd) = header_durations(&file);
        assert_eq!(mvhd, mehd, "row {i} header durations");
        assert_eq!(mvhd.div_ceil(90), rec.duration_ms, "row {i} mvhd");
    }
    // Nothing on disk that the index does not know, and no leftover `.part`.
    assert_eq!(tree(&d.root).len(), d.rows.len(), "{:?}", tree(&d.root));
}

#[derive(Debug, Clone)]
struct F {
    gap_ms: i64,
    rtp_step: i64,
    key: bool,
    loss: bool,
    size: usize,
}

fn frame_strategy() -> impl Strategy<Value = F> {
    let step = prop_oneof![
        4 => 2_000i64..=6_000,
        1 => Just(0i64),
        1 => 1i64..=3,
        1 => Just(900_000i64),
        1 => 900_001i64..=3_000_000,
        1 => -200_000i64..0,
    ];
    (
        0i64..=1_500,
        step,
        prop::bool::weighted(0.08),
        prop::bool::weighted(0.01),
        prop_oneof![9 => 7usize..=600, 1 => Just(5usize)],
    )
        .prop_map(|(gap_ms, rtp_step, key, loss, size)| F {
            gap_ms,
            rtp_step,
            key,
            loss,
            size,
        })
}

fn run_frames(frames: &[F]) -> Done {
    let mut r = Rig::build(short(), None, |_, _| {});
    let mut rtp: i64 = 1_000;
    for (i, f) in frames.iter().enumerate() {
        rtp += f.rtp_step;
        r.feeder.clock.advance(f.gap_ms);
        let wrapped = u32::try_from(rtp.rem_euclid(1 << 32)).unwrap();
        let mut spec = if i == 0 || f.key {
            Spec::key(wrapped)
        } else {
            Spec::p(wrapped)
        }
        .with_size(f.size);
        if i == 0 {
            spec = spec.with_params(params(&SPS_A));
        }
        if f.loss && i != 0 {
            spec = spec.with_loss();
        }
        let frame = r.feeder.frame(&spec);
        r.rec.push_frame(frame);
    }
    r.finish()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// ADR 0005 and the ticket: every row's duration, frames and bytes match the file, over
    /// jittery, frozen, jumping and backward RTP clocks; and every frame is either in a file or
    /// counted as dropped (nothing vanishes silently).
    #[test]
    fn rows_match_files_and_no_frame_vanishes_over_hostile_timestamps(
        frames in prop::collection::vec(frame_strategy(), 1..500)
    ) {
        let d = run_frames(&frames);
        rows_match_files(&d);
        let written: u64 = d.rows.iter().map(|r| r.record.frame_count).sum();
        prop_assert_eq!(
            written + d.end.frames_dropped,
            u64::try_from(frames.len()).unwrap(),
            "health {:?}", d.end
        );
        prop_assert_eq!(d.end.segments_aborted, 0);
    }
}

/// A crash (the recorder dropped without `finish`) after a mix of aborted segments, lost name
/// races, discontinuities and parameter changes leaves at most one `.part`.
#[test]
fn a_crash_after_mixed_failures_leaves_at_most_one_part() {
    let mut r = Rig::build(short(), None, |_, _| {});
    r.start();
    for _ in 0..10 {
        r.feed(Slice::P);
    }
    {
        let mut s = r.store.lock().unwrap();
        s.appends_until_error = Some(0);
        s.append_error = Some(StoreError::Io {
            op: "write",
            kind: std::io::ErrorKind::Other,
        });
    }
    r.gop(10); // the keyframe flush fails, the segment is aborted
    r.store.lock().unwrap().create_error = Some(StoreError::NameTaken);
    r.gop(10);
    let s = r.spec(Slice::Idr).with_loss();
    r.push(&s);
    let s = r.spec(Slice::Idr).with_params(params(&SPS_B));
    r.push(&s);
    for _ in 0..5 {
        r.feed(Slice::P);
    }
    assert_eq!(r.state(), RecorderState::Recording);
    let root = r.root.clone();
    let dir = r.dir;
    drop(r.rec); // crash: no close sequence
    let parts = part_files(&root);
    assert_eq!(parts.len(), 1, "{parts:?}");
    drop(dir);
}

/// A file that appears at the final `.mp4` name while the segment is being written is never
/// replaced or removed by the close (`RENAME_NOREPLACE`), and no `.part` is left behind.
#[test]
fn a_file_planted_at_the_final_name_mid_segment_is_never_replaced() {
    let mut r = Rig::build(short(), None, |_, _| {});
    r.start();
    r.feed(Slice::P);
    let rel = RelPath::new(&cam(), ms(T0 + 100)).to_string();
    let planted = r.root.join(&rel);
    assert!(!planted.exists());
    std::fs::write(&planted, b"foreign").unwrap();
    let d = r.finish();
    assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
    assert_eq!(part_files(&d.root).len(), 0);
    // By the round-2 ruling the segment lands at the next free key.
    assert_eq!(d.rows.len(), 1);
    assert_eq!(d.rows[0].record.started_at_ms.as_i64(), T0 + 101);
}

/// When every quarantine name is taken, the file stays in place (fsutil returns
/// `QuarantineOutcome::Exhausted`). Health must not claim it was quarantined: it is a
/// finished file left for reconciliation, i.e. `segments_unindexed`.
#[test]
fn an_exhausted_quarantine_is_not_counted_as_quarantined() {
    let mut r = Rig::build(short(), None, |root, _| {
        let rel = RelPath::new(&cam(), ms(T0 + 100)).to_string();
        let q = root.join("_quarantine").join(&rel);
        std::fs::create_dir_all(q.parent().unwrap()).unwrap();
        std::fs::write(&q, b"q").unwrap();
        for n in 1..=1000 {
            std::fs::write(format!("{}.{n}", q.display()), b"q").unwrap();
        }
    });
    r.index.lock().unwrap().insert_errors = vec![IndexError::Duplicate].into();
    r.start();
    r.feed(Slice::P);
    let d = r.finish();
    let rel = RelPath::new(&cam(), ms(T0 + 100)).to_string();
    assert!(
        d.root.join(&rel).is_file(),
        "the file was left in place (exhausted)"
    );
    assert_eq!(
        (d.end.segments_quarantined, d.end.segments_unindexed),
        (0, 1),
        "health claims a quarantine that did not happen: {:?}",
        d.end
    );
}

/// The resume threshold is exact: one byte short holds, exactly enough resumes.
#[test]
fn the_resume_threshold_after_a_full_volume_is_exact() {
    let config = short().with_resume_free_bytes(1_000);
    let mut r = Rig::build(config, None, |_, _| {});
    r.store.lock().unwrap().create_error = Some(StoreError::NoSpace);
    r.start();
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    r.store.lock().unwrap().available = Some(999);
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    assert_eq!(part_files(&r.root).len(), 0);
    r.store.lock().unwrap().available = Some(1_000);
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Recording);
    r.feed(Slice::P);
    let d = r.finish();
    assert_eq!(d.frames(), [2]);
    rows_match_files(&d);
}

/// A finished file the index never got (busy through every retry) is found by the next run's
/// key probe even when the clock lands exactly on its key and the seed knows nothing of it.
#[test]
fn an_unindexed_file_from_a_previous_run_is_never_reused_after_a_restart() {
    let dir = private_tempdir();
    let root = hot_root(dir.path());
    {
        let (store, _) = TestStore::new(&root);
        let (index, script) = TestIndex::open(dir.path());
        script.lock().unwrap().insert_errors =
            (0..10).map(|_| IndexError::Busy { op: "insert" }).collect();
        let (mut rec, _) = Recorder::new(cam(), short(), store, index, None).unwrap();
        let mut feeder = Feeder::new();
        rec.push_frame(feeder.frame(&Spec::key(0).with_params(params(&SPS_A))));
        rec.push_frame(feeder.frame(&Spec::p(9000)));
        let end = rec.finish();
        assert_eq!(end.segments_unindexed, 1);
    }
    let orphan = root.join(RelPath::new(&cam(), ms(T0)).to_string());
    let before = std::fs::read(&orphan).unwrap();
    let (store, _) = TestStore::new(&root);
    let (index, _) = TestIndex::open(dir.path());
    let (mut rec, _) = Recorder::new(cam(), short(), store, index, None).unwrap();
    let mut feeder = Feeder::new(); // the clock is back at T0
    rec.push_frame(feeder.frame(&Spec::key(0).with_params(params(&SPS_A))));
    rec.push_frame(feeder.frame(&Spec::p(9000)));
    let end = rec.finish();
    assert_eq!(end.segments_indexed, 1);
    assert_eq!(std::fs::read(&orphan).unwrap(), before);
    let (index, _) = TestIndex::open(dir.path());
    let keys: Vec<i64> = rows(&index)
        .iter()
        .map(|r| r.record.started_at_ms.as_i64())
        .collect();
    assert_eq!(keys, [T0 + 1]);
}

/// Segments either side of midnight UTC land in their own day directories, both `0700`.
#[test]
fn segments_across_midnight_go_to_their_own_day_directories() {
    use std::os::unix::fs::PermissionsExt;
    // 2023-11-14T23:59:59.000Z
    let before_midnight = 1_700_006_399_000;
    let mut r = Rig::build(short(), None, |_, _| {});
    r.feeder.clock.set(before_midnight);
    let f = r.feeder.frame(&Spec::key(0).with_params(params(&SPS_A)));
    r.rec.push_frame(f);
    r.feeder.clock.set(before_midnight + 999);
    let f = r.feeder.frame(&Spec::p(9000));
    r.rec.push_frame(f);
    r.feeder.clock.set(before_midnight + 11_000);
    let f = r.feeder.frame(&Spec::key(909_000));
    r.rec.push_frame(f);
    let d = r.finish();
    let names = tree(&d.root);
    assert_eq!(
        names,
        [
            "cam1/2023-11-14/235959-000.mp4",
            "cam1/2023-11-15/000010-000.mp4"
        ]
    );
    for day in ["2023-11-14", "2023-11-15"] {
        let mode = std::fs::metadata(d.root.join("cam1").join(day))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o700);
    }
    rows_match_files(&d);
}

/// A B slice seen while the recorder is held for a full volume still latches the B-frame hold;
/// space coming back must not lift it.
#[test]
fn a_b_slice_during_a_storage_hold_still_latches_the_b_frame_hold() {
    let mut r = Rig::build(short(), None, |_, _| {});
    r.store.lock().unwrap().create_error = Some(StoreError::NoSpace);
    r.start();
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    r.feed(Slice::B);
    r.store.lock().unwrap().available = Some(1 << 40);
    r.feed(Slice::Idr);
    r.feed(Slice::P);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::BFramesDetected));
    let d = r.finish();
    assert_eq!(d.rows.len(), 0);
    assert_eq!(tree(&d.root).len(), 0);
}

/// A frozen RTP clock with a moving wall clock is cut by the arrival-span bound (ADR 0005 rule
/// 3a); every file still matches its row.
#[test]
fn a_frozen_rtp_clock_is_cut_by_arrival_and_rows_still_match_files() {
    let mut r = Rig::build(short(), None, |_, _| {});
    let f = r.feeder.frame(&Spec::key(5).with_params(params(&SPS_A)));
    r.rec.push_frame(f);
    for i in 1..1_000u32 {
        r.feeder.clock.advance(100);
        let spec = if i % 20 == 0 {
            Spec::key(5)
        } else {
            Spec::p(5)
        };
        let f = r.feeder.frame(&spec);
        r.rec.push_frame(f);
    }
    let d = r.finish();
    assert!(d.rows.len() >= 2, "{:?}", d.durations());
    rows_match_files(&d);
}

/// More samples than one `trun` may hold in a single GOP: the fragment is split by the sample
/// bound (not the byte cap), and the file must stay readable by the core box parser that the
/// reconciliation adoption walk uses (ADR 0005 section 11). The writer's bound
/// (`MAX_SAMPLES_PER_FRAGMENT` = 100,000, a 1.2 MB `trun`) is above the parser's
/// `MAX_PAYLOAD_LEN` (1 MiB, about 87,380 samples).
#[test]
fn a_gop_over_the_sample_table_bound_stays_readable_by_the_adoption_parser() {
    let mut r = Rig::build(short(), None, |_, _| {});
    let f = r
        .feeder
        .frame(&Spec::key(0).with_params(params(&SPS_A)).with_size(7));
    r.rec.push_frame(f);
    let n = u32::try_from(wardenlens_mp4::MAX_SAMPLES_PER_FRAGMENT).unwrap() + 10;
    for _ in 0..n {
        // RTP frozen and wall clock frozen: only the +1 tick clamp moves media time.
        let f = r.feeder.frame(&Spec::p(0).with_size(7));
        r.rec.push_frame(f);
    }
    let d = r.finish();
    assert_eq!(d.frames(), [u64::from(n) + 1]);
    let file = d.file(0);
    assert_eq!(file.windows(4).filter(|w| *w == b"moof").count(), 2);
    rows_match_files(&d);
}
