//! Round-3 adversarial tests for the arrival-span bound (ticket #103, ADR 0005 section 2 rule 3a):
//! the exact re-anchor threshold and the anchor of a segment started by a keyframe cut.
#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on small bounded literals"
)]

use wardenlens_core::recording::{Decision, FrameMeta, SegmentConfig, Segmenter};
use wardenlens_core::time::UnixMs;

const T0: i64 = 1_700_000_000_000;

fn frame(key: bool, rtp: u32, at: i64) -> FrameMeta {
    FrameMeta::new(key, rtp, UnixMs::new(at).unwrap(), 100)
}

/// Target 10 s, so the hard maximum is 20 s and the arrival bound 40 s.
fn seg10() -> Segmenter {
    Segmenter::new(
        "cam".parse().unwrap(),
        SegmentConfig::new(10, 1 << 30).unwrap(),
    )
}

/// Frozen RTP. Keyframe at T0, a 30 s forward step (+10 s, mark T0+30 s), a step back by `back`
/// ms, then 40 ms frames. Returns the index (1-based) of the 40 ms frame that closes the segment,
/// or `None` if none of 2000 does.
fn closing_frame_after_back_step(back: i64) -> Option<u32> {
    let mut s = seg10();
    assert_eq!(s.push(frame(true, 7, T0)).decision, Decision::StartNew);
    assert_eq!(
        s.push(frame(false, 7, T0 + 30_000)).decision,
        Decision::Append
    );
    let mut at = T0 + 30_000 - back;
    assert_eq!(s.push(frame(false, 7, at)).decision, Decision::Append);
    for i in 1..=2000 {
        at += 40;
        if s.push(frame(false, 7, at)).decision == Decision::Drop {
            return Some(i);
        }
    }
    None
}

#[test]
fn backward_step_of_exactly_ten_seconds_keeps_the_mark() {
    // ADR: only a step back of MORE than 10 s re-anchors. Exactly 10 s keeps the mark at
    // T0+30 s: the 40 ms frames first climb 10 s back to it (250 frames, adding 0), then add
    // the missing 30 s (750 frames): the 1000th closes.
    assert_eq!(closing_frame_after_back_step(10_000), Some(1000));
}

#[test]
fn backward_step_of_ten_seconds_plus_one_ms_re_anchors() {
    // 10_001 ms back re-anchors at the new arrival: the span (10 s) grows from there, so the
    // 40 ms frames add the missing 30 s in 750 frames.
    assert_eq!(closing_frame_after_back_step(10_001), Some(750));
}

#[test]
fn segment_started_by_a_keyframe_target_cut_anchors_at_its_own_first_arrival() {
    // Sound RTP for the first segment: 40 ms frames at 25 fps, with one 9 s forward arrival
    // step (mark 9 s ahead). The keyframe at media 10 s (the target) arrives 5 s below that
    // mark and cuts the segment. The RTP then freezes. The new segment must count from its own
    // first arrival: 40 s of 40 ms frames (1000) close it. A segment that inherited the old
    // mark would hide 5 s and close only at frame 1125.
    let mut s = seg10();
    let mut rtp = 1000u32;
    let mut at = T0;
    assert_eq!(s.push(frame(true, rtp, at)).decision, Decision::StartNew);
    for i in 1..250 {
        rtp += 3600;
        at += if i == 100 { 9_000 } else { 40 };
        assert_eq!(s.push(frame(false, rtp, at)).decision, Decision::Append);
    }
    rtp += 3600;
    let kf = at - 5_000;
    let k = s.push(frame(true, rtp, kf));
    assert_eq!(k.decision, Decision::StartNew);
    assert!(k.closed.is_some(), "the target keyframe closes the segment");
    at = kf;
    for i in 1..=1000 {
        at += 40;
        let p = s.push(frame(false, rtp, at));
        assert_eq!(p.decision == Decision::Drop, i == 1000, "frame {i}");
    }
}
