//! Adversarial tests for `core::recording` (ticket #45).
#![expect(clippy::unwrap_used, reason = "test code")]

use wardenlens_core::recording::{
    CameraId, Decision, FrameMeta, MediaClock, PushError, RelPath, SegmentConfig, Segmenter,
};
use wardenlens_core::time::UnixMs;

const T0: i64 = 1_700_000_000_000;
const MAX_STEP_TICKS: u64 = 900_000;

fn frame(key: bool, rtp: u32, at: i64, bytes: u64) -> FrameMeta {
    FrameMeta::new(key, rtp, UnixMs::new(at).unwrap(), bytes)
}

fn seg(target: u32, cap: u64) -> Segmenter {
    Segmenter::new(
        "cam".parse().unwrap(),
        SegmentConfig::new(target, cap).unwrap(),
    )
}

// ---------- RelPath parse: non-ASCII in the fixed-width clock field ----------

#[test]
fn relpath_parse_multibyte_clock_field_does_not_panic() {
    // "aé123" is 6 bytes; byte 2 is inside 'é' (bytes 1..3), so split_at(2) would panic.
    for s in [
        "cam-1/2024-02-29/a\u{e9}123-042.mp4",
        "cam-1/2024-02-29/12a\u{e9}1-042.mp4",
        "cam-1/2024-02-29/\u{20ac}123-042.mp4",
        "cam-1/2024-02-29/1\u{20ac}12-042.mp4",
    ] {
        assert!(s.parse::<RelPath>().is_err(), "{s:?} accepted");
    }
}

#[test]
fn relpath_rejects_assorted_hostile_names() {
    for s in [
        "cam-1/2024-02-29/134507-042.mp4\0",
        "cam-1\0/2024-02-29/134507-042.mp4",
        "cam-1/2024-02-29/134507-042.MP4",
        "cam-1/2024-02-29/134507-0420.mp4",
        "cam-1/2024-02-29/134507--42.mp4",
        "cam-1/2024-02-29/1345-07-042.mp4",
        "cam-1/2024-02-29/134507-042.mp4.part",
        "cam-1//2024-02-29/134507-042.mp4",
        "cam-1/2024-02-29\\134507-042.mp4",
        "cam-1/2024-02-29/134507-042.mp4\n",
        " cam-1/2024-02-29/134507-042.mp4",
        "cam-1/+024-02-29/134507-042.mp4",
        "cam-1/2024-02-00/000000-000.mp4",
        "cam-1/2024-00-01/000000-000.mp4",
        "cam-1/2024-13-01/000000-000.mp4",
        "cam-1/2024-02-29/236000-000.mp4",
        "cam-1/2024-02-29/235960-000.mp4",
        "cam-1/\u{ff12}024-02-29/134507-042.mp4",
        "_quarantine/cam-1/2024-02-29/134507-042.mp4",
    ] {
        assert!(s.parse::<RelPath>().is_err(), "{s:?}");
    }
}

#[test]
fn relpath_round_trips_leap_days_and_day_edges() {
    let cam: CameraId = "x".parse().unwrap();
    for s in [
        "x/2000-02-29/000000-000.mp4",
        "x/2096-02-29/235959-999.mp4",
        "x/2024-12-31/235959-999.mp4",
        "x/2025-01-01/000000-000.mp4",
    ] {
        let p: RelPath = s.parse().unwrap();
        assert_eq!(p.camera(), &cam);
        assert_eq!(RelPath::new(&cam, p.started_at()).to_string(), s);
    }
}

// ---------- MediaClock ----------

fn run(rtps: &[u32]) -> Vec<u64> {
    let mut c = MediaClock::default();
    rtps.iter().map(|&r| c.push(r)).collect()
}

#[test]
fn wrap_exactly_at_zero_crossing() {
    assert_eq!(run(&[u32::MAX, 0, 3599]), [0, 1, 3600]);
}

#[test]
fn half_range_jump_is_a_rebase_not_a_giant_step() {
    let d = run(&[0, 3600, 0x8000_0000 + 3600, 0x8000_0000 + 7200]);
    for w in d.windows(2) {
        assert!(w[1] > w[0] && w[1] - w[0] <= MAX_STEP_TICKS, "{d:?}");
    }
    assert_eq!(d, [0, 3600, 7200, 10_800]);
}

#[test]
fn many_wraps_keep_following_the_line() {
    let mut c = MediaClock::default();
    let start = u32::MAX - 1_000_000;
    let mut last = 0;
    // 3 full wraps worth at 10 s steps.
    let steps = 3 * (u64::from(u32::MAX) / 900_000 + 1);
    for i in 0..steps {
        let rtp = start.wrapping_add(u32::try_from((i * 900_000) % (1u64 << 32)).unwrap());
        let d = c.push(rtp);
        assert_eq!(d, i * 900_000);
        last = d;
    }
    assert!(last > 3 * u64::from(u32::MAX));
}

#[test]
fn rebase_after_jitter_keeps_a_good_step_not_one_tick() {
    // ADR: re-base "keeps the last good duration". After a clamped jitter frame the
    // stored step is 1 tick; check what the re-base uses.
    let d = run(&[0, 3600, 7200, 3600, 7200 + 2_000_000]);
    let rebase_step = d[4] - d[3];
    assert!(
        rebase_step >= 3600,
        "re-base after jitter used step {rebase_step} ticks: {d:?}"
    );
}

#[test]
fn backward_rebase_then_forward_resumes_regular_pacing() {
    let d = run(&[5_000_000, 5_003_600, 5_007_200, 100, 3700, 7300]);
    assert_eq!(d, [0, 3600, 7200, 10_800, 14_400, 18_000]);
}

#[test]
fn reset_then_wrap_is_independent_of_previous_stream() {
    let mut c = MediaClock::default();
    c.push(0);
    c.push(u32::MAX / 2);
    c.reset();
    assert_eq!(c.push(u32::MAX), 0);
    assert_eq!(c.push(3599), 3600);
}

// ---------- Segmenter ----------

#[test]
fn frozen_rtp_segment_is_bounded_in_frames() {
    // Camera sends the same RTP timestamp forever at 25 fps. Media time advances 1 tick
    // per frame, so the 10 s target needs 900,000 frames (10 h of wall time).
    let mut s = seg(10, 1 << 30);
    let mut starts = 0;
    let mut closes = 0;
    for i in 0..(25 * 600) {
        let p = s.push(frame(i % 25 == 0, 12345, T0 + i64::from(i) * 40, 1000));
        if p.decision == Decision::StartNew {
            starts += 1;
        }
        if p.closed.is_some() {
            closes += 1;
        }
    }
    // 10 minutes of wall-clock frames with a 10 s target and 20 s hard max.
    assert!(
        closes >= 1,
        "no segment closed in 600 s of wall time (starts={starts}); the arrival bound did not fire"
    );
}

#[test]
fn keyframe_reaching_byte_cap_starts_new_and_records_old() {
    let mut s = seg(10, 1000);
    s.push(frame(true, 0, T0, 600));
    let p = s.push(frame(true, 3600, T0 + 40, 600));
    assert_eq!(p.decision, Decision::StartNew);
    let r = p.closed.unwrap();
    assert_eq!((r.frame_count, r.bytes), (1, 600));
}

#[test]
fn oversized_first_keyframe_then_p_frame_closes_and_drops() {
    // Larger than the byte cap but within the 8 MiB frame limit.
    let big = 8 << 20;
    let mut s = seg(10, 100);
    let p0 = s.push(frame(true, 0, T0, big));
    assert_eq!(p0.decision, Decision::StartNew);
    let p1 = s.push(frame(false, 3600, T0 + 40, 1));
    assert_eq!(p1.decision, Decision::Drop);
    let r = p1.closed.unwrap();
    assert_eq!((r.frame_count, r.bytes), (1, big));
    assert_eq!(s.push(frame(false, 7200, T0 + 80, 1)).closed, None);
}

#[test]
fn huge_rtp_jump_mid_segment_does_not_trigger_hard_max() {
    let mut s = seg(10, 1 << 30);
    s.push(frame(true, 0, T0, 1));
    let p = s.push(frame(false, 3_000_000_000, T0 + 40, 1));
    assert_eq!(p.decision, Decision::Append);
    assert!(p.dts.unwrap() <= MAX_STEP_TICKS);
}

#[test]
fn keyframe_cut_dts_restarts_at_zero_and_continues() {
    let mut s = seg(10, 1 << 30);
    for i in 0..10u32 {
        s.push(frame(i == 0, i * 90_000, T0, 1));
    }
    let k = s.push(frame(true, 10 * 90_000, T0, 1));
    assert_eq!((k.decision, k.dts), (Decision::StartNew, Some(0)));
    let n = s.push(frame(false, 10 * 90_000 + 3600, T0, 1));
    assert_eq!(n.dts, Some(3600));
}

#[test]
fn hard_max_with_rebasing_stream_still_bounded() {
    // Every frame jumps forward > 10 s (re-base each time). Steps stay at last good step.
    let mut s = seg(290, u64::MAX);
    let mut rtp = 0u32;
    let mut max_dur = 0;
    for i in 0..20_000u32 {
        let p = s.push(frame(i % 1000 == 0, rtp, T0, 1));
        if let Some(r) = p.closed {
            max_dur = max_dur.max(r.duration_ms);
        }
        rtp = rtp.wrapping_add(if i % 2 == 0 { 900_000 } else { 900_001 });
    }
    if let Some(r) = s.finish() {
        max_dur = max_dur.max(r.duration_ms);
    }
    assert!(max_dur <= 600_000, "{max_dur}");
}

#[test]
fn records_frame_count_sum_matches_appends_with_finish_midstream() {
    let mut s = seg(10, 1 << 30);
    let mut appended = 0u64;
    let mut counted = 0u64;
    for round in 0..3u32 {
        for i in 0..50u32 {
            let p = s.push(frame(i % 7 == 0, round * 7 + i * 30_000, T0, 1));
            if p.decision != Decision::Drop {
                appended += 1;
            }
            if let Some(r) = p.closed {
                counted += r.frame_count;
            }
        }
        if let Some(r) = s.finish() {
            counted += r.frame_count;
        }
    }
    assert_eq!(appended, counted);
}

#[test]
fn frame_over_8_mib_is_a_typed_stream_error() {
    let mut s = seg(10, u64::MAX);
    s.push(frame(true, 0, T0, 1));
    let p = s.push(frame(false, 3600, T0 + 40, (8 << 20) + 1));
    assert_eq!(p.error, Some(PushError::FrameTooLarge));
    assert!(p.closed.is_some());
}
