//! Adversary for #195: the rename bump that asks the index, the read-only hold and the file cap.

mod common;

use common::rig::*;
use common::*;
use wardenlens_core::mp4box::{SliceSource, summarize};
use wardenlens_index::IndexError;
use wardenlens_recorder::{HoldReason, RecorderState};

fn mp4s(root: &std::path::Path) -> Vec<String> {
    tree(root)
        .into_iter()
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("mp4"))
                && !n.starts_with("_quarantine")
        })
        .collect()
}

/// A finished, fsynced recording is never thrown away because the index could not answer a
/// read while the rename was bumped (an unanswerable index is "held" for every bumped key, so
/// all eight tries are skipped and the `.part` is deleted). Before #195 the file landed on the
/// next key; reconciliation now never deletes a foreign twin, so keeping it is safe.
#[test]
fn adversary_a_finished_segment_survives_an_index_that_cannot_answer_during_the_bump() {
    let (r, planted) = bumped_rig();
    r.index.lock().unwrap().list_errors = 1_000;
    let d = r.finish();
    assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
    let files = mp4s(&d.root);
    assert!(
        files.len() >= 2,
        "the recording was deleted: {:?} {:?}",
        tree(&d.root),
        d.end
    );
    assert_eq!(d.end.segments_aborted, 0, "{:?}", d.end);
}

/// The configured byte limit holds for every file, also for a segment whose first frame alone
/// passes it (the cut only runs before frames appended to an open segment).
#[test]
fn adversary_a_first_frame_bigger_than_the_limit_never_makes_a_bigger_file() {
    let limit = 5_000;
    let config = fast().with_file_limits(limit, 1_000);
    let mut r = Rig::build(config, None, |_, _| {});
    let s = r
        .spec(Slice::Idr)
        .with_params(params(&SPS_A))
        .with_size(20_000);
    r.push(&s);
    r.feed(Slice::P);
    let d = r.finish();
    for f in mp4s(&d.root) {
        let len = std::fs::metadata(d.root.join(&f)).unwrap().len();
        assert!(len <= limit, "{f}: {len} > {limit}");
    }
}

/// Every finished file at the real limits is adoptable even with the largest frames ingest lets
/// through (8 MiB): the margin covers one frame.
#[test]
#[ignore = "writes ~1.1 GiB; run manually"]
fn adversary_big_frames_near_the_real_cap_stay_adoptable() {
    let mut r = Rig::new();
    // 8 MiB keyframes: 1 GiB - 16 MiB holds 126 of them with overhead.
    let big = 8 << 20;
    for i in 0..140u32 {
        let mut spec = Spec::key(i * 9000).with_size(big);
        if i == 0 {
            spec = spec.with_params(params(&SPS_A));
        }
        r.feeder.clock.advance(100);
        let f = r.feeder.frame(&spec);
        r.rec.push_frame(f);
    }
    let d = r.finish();
    assert!(d.rows.len() >= 2, "{:?}", d.end);
    for (i, row) in d.rows.iter().enumerate() {
        let bytes = d.file(i);
        assert_eq!(u64::try_from(bytes.len()).unwrap(), row.record.bytes);
        let s = summarize(&mut SliceSource(&bytes)).unwrap();
        assert_eq!(s.frame_count, row.record.frame_count);
    }
    assert_eq!(d.frames().iter().sum::<u64>(), 140);
}

/// The read-only hold never wedges: once the index takes writes again a probe ends it, also
/// when the probe's insert first meets transient errors.
#[test]
fn adversary_a_probe_that_meets_busy_then_succeeds_ends_the_hold() {
    let mut r = Rig::new();
    r.index.lock().unwrap().insert_forever = Some(|| IndexError::Sqlite {
        op: "insert",
        code: Some(rusqlite::ErrorCode::ReadOnly),
    });
    r.start();
    r.feed(Slice::P);
    let s = r.spec_loss();
    r.push(&s);
    assert_eq!(r.state(), RecorderState::Held(HoldReason::IndexReadOnly));
    {
        let mut s = r.index.lock().unwrap();
        s.insert_forever = None;
        s.insert_errors = (0..3).map(|_| IndexError::Busy { op: "insert" }).collect();
    }
    for _ in 0..33 {
        r.gop(2);
        let s = r.spec_loss();
        r.push(&s);
    }
    assert_eq!(r.state(), RecorderState::Waiting, "{:?}", r.health());
    let d = r.finish();
    assert_eq!(d.end.segments_quarantined, 0);
    assert_eq!(d.end.segments_indexed, 1);
}

/// A read-only index while recording: a graceful stop keeps every file, and no `.part` is left.
#[test]
fn adversary_finish_during_a_read_only_hold_leaves_no_part_and_no_quarantine() {
    let mut r = Rig::new();
    r.index.lock().unwrap().insert_forever = Some(|| IndexError::Sqlite {
        op: "insert",
        code: Some(rusqlite::ErrorCode::CannotOpen),
    });
    r.start();
    for _ in 0..5 {
        r.gop(3);
    }
    let d = r.finish();
    assert_eq!(part_files(&d.root).len(), 0);
    assert_eq!(d.end.segments_quarantined, 0);
    assert_eq!(
        u64::try_from(mp4s(&d.root).len()).unwrap(),
        d.end.segments_unindexed
    );
}

trait LossSpec {
    fn spec_loss(&mut self) -> Spec;
}

impl LossSpec for Rig {
    fn spec_loss(&mut self) -> Spec {
        self.spec(Slice::P).with_loss()
    }
}
