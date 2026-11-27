//! Adversary, #195 round 2: where a finished recording ends up when no name is free.

mod common;

use common::rig::*;
use common::*;
use wardenlens_core::mp4box::{SliceSource, summarize};
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{SegmentIndex, Tier};

/// Every bumped key is held and the hot quarantine cannot be created (`_quarantine` is a regular
/// file, as a failed mkdir on a full volume would be). The sealed `.part` is "left in place",
/// but a hot `*.mp4.part` in a day directory is exactly what start-up reconciliation deletes
/// (ADR 0005 section 9, `.part` rule; `reconcile/walk.rs::delete_parts`). A finished, fsynced
/// recording must not be left under a name the next start unlinks.
#[test]
fn adversary_a_sealed_segment_with_no_free_name_and_no_quarantine_is_not_left_as_a_deletable_part()
{
    let mut r = Rig::build(fast(), None, |root, index| {
        for n in 1..=7 {
            let rec = SegmentRecord::new(cam(), ms(T0 + 100 + n), 1_000, 4_096, 10);
            index.insert(&rec, Tier::Archive).unwrap();
        }
        std::fs::write(root.join("_quarantine"), b"not a dir").unwrap();
    });
    r.start();
    r.feed(Slice::P);
    let planted = r.root.join(RelPath::new(&cam(), ms(T0 + 100)).to_string());
    std::fs::write(&planted, b"foreign").unwrap();
    let d = r.finish();
    // The recording exists and is whole, under a name start-up does not delete: not a
    // `.part` (deleted as "interrupted"), but `<name>.mp4.unsealed` (left, `unknown_left`).
    assert_eq!(part_files(&d.root).len(), 0, "{:?}", tree(&d.root));
    let kept: Vec<String> = tree(&d.root)
        .into_iter()
        .filter(|n| n.ends_with(".mp4.unsealed"))
        .collect();
    assert_eq!(kept.len(), 1, "{:?} {:?}", tree(&d.root), d.end);
    let bytes = std::fs::read(d.root.join(&kept[0])).unwrap();
    summarize(&mut SliceSource(&bytes)).unwrap();
    assert_eq!((d.end.segments_aborted, d.end.segments_quarantined), (0, 1));
}

/// A first keyframe too big for the file limit is dropped (a stream error), and recording
/// resumes at the next keyframe that fits: the drop never wedges the recorder.
#[test]
fn adversary_an_oversized_first_keyframe_is_dropped_and_the_next_keyframe_records() {
    let limit = 5_000;
    let mut r = Rig::build(fast().with_file_limits(limit, 1_000), None, |_, _| {});
    let s = r
        .spec(Slice::Idr)
        .with_params(params(&SPS_A))
        .with_size(20_000);
    r.push(&s);
    r.feed(Slice::P);
    r.feed(Slice::P);
    r.gop(3);
    r.gop(3);
    let d = r.finish();
    assert!(d.end.stream_errors >= 1, "{:?}", d.end);
    assert!(d.end.segments_indexed >= 1, "{:?}", d.end);
    assert_eq!(d.frames().iter().sum::<u64>(), 6, "{:?}", d.end);
    for i in 0..d.rows.len() {
        assert!(u64::try_from(d.file(i).len()).unwrap() <= limit);
    }
}

/// An oversized keyframe in the middle of a stream is dropped alone: the segments around it
/// are kept and indexed, nothing is aborted.
#[test]
fn adversary_an_oversized_keyframe_mid_stream_drops_only_its_gop() {
    let limit = 5_000;
    let mut r = Rig::build(fast().with_file_limits(limit, 1_000), None, |_, _| {});
    r.start();
    r.feed(Slice::P);
    let s = r.spec(Slice::Idr).with_size(20_000);
    r.push(&s);
    r.feed(Slice::P);
    r.gop(2);
    let d = r.finish();
    assert_eq!(d.end.segments_aborted, 0, "{:?}", d.end);
    assert_eq!(d.end.segments_quarantined, 0, "{:?}", d.end);
    assert_eq!(d.frames().iter().sum::<u64>(), 4, "{:?}", d.end);
}

/// The unchecked key (index unanswerable during the bump) is used once; a later segment in the
/// same run never lands on a key a file or row already has, and every file is distinct.
#[test]
fn adversary_after_an_unchecked_bump_the_next_segment_takes_a_fresh_key() {
    let (mut r, planted) = bumped_rig();
    r.index.lock().unwrap().list_errors = 1;
    r.gop(2);
    r.gop(2);
    let d = r.finish();
    assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
    assert_eq!(d.end.segments_aborted, 0, "{:?}", d.end);
    assert!(part_files(&d.root).is_empty(), "{:?}", tree(&d.root));
    // The archive row is intact, and every indexed row has its own file of its size.
    assert_eq!(d.rows[0].record.bytes, 4_096);
    for (i, row) in d.rows.iter().enumerate().skip(1) {
        assert_eq!(u64::try_from(d.file(i).len()).unwrap(), row.record.bytes);
    }
    let files = tree(&d.root).len();
    // planted + unchecked file + one per indexed hot row
    assert_eq!(files, 2 + d.rows.len() - 1, "{:?}", tree(&d.root));
}
