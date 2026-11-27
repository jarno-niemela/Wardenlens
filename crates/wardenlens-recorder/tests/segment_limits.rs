//! The segment cap counts the file, not only the frames (#195): a finished segment never passes
//! what the adoption parser (`core::mp4box::summarize`) accepts, neither in bytes (container
//! overhead included) nor in fragments.

#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code on small synthetic values; a panic is a failure"
)]

mod common;

use common::rig::*;
use common::*;
use proptest::prelude::*;
use wardenlens_core::mp4box::{MAX_FILE_LEN, MAX_FRAGMENTS, SliceSource, summarize};
use wardenlens_core::recording::RelPath;

/// Every `.mp4` the rig left, with its length, parsed by the adoption parser.
fn adopted(d: &Done) -> Vec<(u64, u64)> {
    d.rows
        .iter()
        .map(|r| {
            let path = d
                .root
                .join(RelPath::new(&r.record.camera, r.record.started_at_ms).to_string());
            let bytes = std::fs::read(path).unwrap();
            let s = summarize(&mut SliceSource(&bytes)).unwrap();
            assert_eq!(u64::try_from(bytes.len()).unwrap(), r.record.bytes);
            assert_eq!(
                s.frame_count, r.record.frame_count,
                "the row matches the file"
            );
            (r.record.bytes, s.frame_count)
        })
        .collect()
}

/// Frames of `sizes` bytes, a keyframe every `gop`, 100 ms apart.
fn run(limit: u64, fragments: u64, sizes: &[usize], gop: usize) -> Done {
    let config = fast().with_file_limits(limit, fragments);
    let mut r = Rig::build(config, None, |_, _| {});
    for (i, size) in sizes.iter().enumerate() {
        let slice = if i % gop == 0 { Slice::Idr } else { Slice::P };
        let mut spec = r.spec(slice).with_size(*size);
        if i == 0 {
            spec = spec.with_params(params(&SPS_A));
        }
        r.push(&spec);
    }
    r.finish()
}

#[test]
fn no_file_passes_the_byte_limit_and_every_one_is_adoptable() {
    let limit = 20_000;
    let d = run(limit, 1_000, &[900; 300], 7);
    let files = adopted(&d);
    assert!(files.len() > 5, "the limit cut the stream: {files:?}");
    for (len, _) in &files {
        assert!(*len <= limit, "{len} > {limit}");
    }
    // Nothing is lost beyond the frames a cut drops while waiting for a keyframe.
    let kept: u64 = files.iter().map(|f| f.1).sum();
    assert!(kept >= 250, "{kept} of 300 frames kept");
    assert_eq!(d.end.segments_aborted, 0, "{:?}", d.end);
}

#[test]
fn the_fragment_limit_cuts_before_the_count_the_parser_refuses() {
    // Every frame a keyframe: one fragment per frame.
    let d = run(u64::MAX, 7, &[100; 30], 1);
    let files = adopted(&d);
    assert!(files.len() >= 4, "{files:?}");
    for (_, frames) in &files {
        assert!(*frames <= 7, "{frames} fragments");
    }
    // A keyframe is the cut frame itself, so it starts the next segment at once: no frame lost.
    assert_eq!(files.iter().map(|f| f.1).sum::<u64>(), 30);
}

/// The real limits, against the real parser: a stream of tiny keyframes makes one fragment per
/// frame, and the segment is closed below the parser's count, so it is adopted, not quarantined.
#[test]
fn a_flood_of_keyframes_never_makes_a_file_the_adoption_parser_refuses() {
    let mut r = Rig::new();
    let n = usize::try_from(MAX_FRAGMENTS).unwrap() + 500;
    for i in 0..n {
        let mut spec = Spec::key(u32::try_from(i).unwrap()).with_size(6);
        if i == 0 {
            spec = spec.with_params(params(&SPS_A));
        }
        let f = r.feeder.frame(&spec);
        r.rec.push_frame(f);
    }
    let d = r.finish();
    let files = adopted(&d);
    assert_eq!(files.len(), 2, "{files:?}");
    assert!(files[0].1 < MAX_FRAGMENTS, "{} fragments", files[0].1);
    assert!(
        files[0].1 >= MAX_FRAGMENTS - 2_000,
        "cut close to the limit"
    );
    assert_eq!(
        files.iter().map(|f| f.1).sum::<u64>(),
        u64::try_from(n).unwrap()
    );
    assert!(files.iter().all(|f| f.0 < MAX_FILE_LEN));
    assert_eq!((d.end.segments_aborted, d.end.segments_quarantined), (0, 0));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Whatever the frame sizes and keyframe spacing, no file passes the limit (TEST-9).
    #[test]
    fn no_file_passes_the_limit_for_any_frame_sizes(
        sizes in proptest::collection::vec(6usize..3_000, 20..200),
        gop in 1usize..20,
        limit in 8_000u64..40_000,
    ) {
        let d = run(limit, 1_000, &sizes, gop);
        for (len, _) in adopted(&d) {
            prop_assert!(len <= limit, "{} > {}", len, limit);
        }
    }
}
