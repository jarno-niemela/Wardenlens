//! Round-2 adversarial tests for the arrival-span bound (ticket #103, ADR 0005 section 2 rule 3a):
//! the per-frame 10 s cap, the high-water mark and the re-anchor on a backward step over 10 s.
#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on small bounded literals"
)]

use wardenlens_core::recording::{Decision, FrameMeta, Pushed, SegmentConfig, Segmenter};
use wardenlens_core::time::UnixMs;

const T0: i64 = 1_700_000_000_000;
const MIN_MS: i64 = 946_684_800_000; // 2000-01-01
const MAX_MS: i64 = 4_102_444_799_999; // 2099-12-31

fn frame(key: bool, rtp: u32, at: i64, bytes: u64) -> FrameMeta {
    FrameMeta::new(key, rtp, UnixMs::new(at).unwrap(), bytes)
}

fn default_seg() -> Segmenter {
    Segmenter::new("cam".parse().unwrap(), SegmentConfig::default())
}

/// 25 fps, GOP 50 (2 s), default config. `rtp(i)` and the host-clock offset `off(i)` (ms, added
/// to the true time `i * 40`) per frame. Returns every frame's result.
fn run(n: u32, rtp: impl Fn(u32) -> u32, off: impl Fn(u32) -> i64) -> Vec<Pushed> {
    let mut s = default_seg();
    (0..n)
        .map(|i| {
            s.push(frame(
                i % 50 == 0,
                rtp(i),
                T0 + i64::from(i) * 40 + off(i),
                1000,
            ))
        })
        .collect()
}

/// True-time length (frames) of every closed segment: from its start frame to the closing frame.
fn real_lengths(out: &[Pushed]) -> Vec<u64> {
    out.iter()
        .filter_map(|p| p.closed.as_ref().map(|r| r.frame_count))
        .collect()
}

fn drops(out: &[Pushed]) -> usize {
    out.iter().filter(|p| p.decision == Decision::Drop).count()
}

// ---------- frozen RTP: the bound holds in true time under host-clock events ----------

/// 240 s at 25 fps.
const BOUND_FRAMES: u64 = 6000;

#[test]
fn frozen_rtp_with_one_large_backward_step_is_still_bounded_in_true_time() {
    // The host clock steps back one hour at frame 2000 (80 s in): the re-anchor must keep
    // counting, so the segment closes 240 s of true time after it opened.
    let out = run(25 * 800, |_| 7, |i| if i < 2000 { 0 } else { -3_600_000 });
    let lens = real_lengths(&out);
    assert_ne!(lens.len(), 0);
    assert!(lens.iter().all(|&n| n <= BOUND_FRAMES + 1), "{lens:?}");
}

#[test]
fn frozen_rtp_with_one_backward_step_of_exactly_ten_seconds_is_delayed_by_at_most_ten_seconds() {
    // Exactly 10 s back does not re-anchor: the span stalls 10 s, per ADR "at most that step".
    let out = run(25 * 800, |_| 7, |i| if i < 2000 { 0 } else { -10_000 });
    let first = real_lengths(&out)[0];
    assert!(
        first <= BOUND_FRAMES + 250 + 1,
        "first segment {first} frames"
    );
    assert!(first > BOUND_FRAMES, "the 10 s step should delay the cut");
}

#[test]
fn frozen_rtp_with_backward_step_just_over_ten_seconds_re_anchors() {
    // measured from the high-water mark (the previous frame, 40 ms earlier): 10_041 ms back is
    // 10_001 ms below the mark.
    let out = run(25 * 800, |_| 7, |i| if i < 2000 { 0 } else { -10_041 });
    // the re-anchoring frame itself adds 0, so one frame (40 ms) later than 240 s
    assert_eq!(real_lengths(&out)[0], BOUND_FRAMES + 1);
}

#[test]
fn frozen_rtp_with_small_oscillation_closes_near_240_s_of_true_time() {
    // Two daemons disagreeing by 5 s, flipping every 3 s: the span tracks true time.
    let out = run(
        25 * 1000,
        |_| 7,
        |i| if (i / 75) % 2 == 1 { 5_000 } else { 0 },
    );
    let lens = real_lengths(&out);
    assert!(lens.len() >= 3, "{lens:?}");
    for n in lens {
        // within one 5 s flip of 240 s
        assert!(n.abs_diff(BOUND_FRAMES) <= 125 + 1, "{n}");
    }
}

#[test]
fn frozen_rtp_with_large_oscillation_closes_no_later_than_240_s() {
    // Disagreement of 30 s, flipping every 3 s: each forward flip adds the 10 s cap, each
    // backward flip re-anchors; the segment closes earlier than 240 s, never later.
    let out = run(
        25 * 1000,
        |_| 7,
        |i| if (i / 75) % 2 == 1 { 30_000 } else { 0 },
    );
    let lens = real_lengths(&out);
    assert_ne!(lens.len(), 0);
    assert!(lens.iter().all(|&n| n <= BOUND_FRAMES), "{lens:?}");
}

#[test]
fn frozen_rtp_with_host_clock_slewed_back_after_a_forward_step_stays_close_to_the_bound() {
    // NTP steps the clock 1 h forward wrongly, then a daemon slews it back at 8.3 % (chrony's
    // default maxslewrate): the span counts 91.7 % of true time, so up to about 262 s.
    let out = run(
        25 * 2000,
        |_| 7,
        |i| {
            if i < 1000 {
                0
            } else {
                // offset 1 h, decreasing by 83 ms per real second (3.32 ms per frame)
                3_600_000 - (i64::from(i - 1000) * 332) / 100
            }
        },
    );
    let lens = real_lengths(&out);
    assert_ne!(lens.len(), 0);
    assert!(lens.iter().all(|&n| n <= 6600), "{lens:?}");
}

/// Host-clock offset (ms) at frame `i`: each period of `up` ms of true time is split into blocks
/// of `back` ms; the offset is `up` in the first block and drops by `back` (a backward step of
/// exactly `back`) at the start of each later block, then jumps forward again at the next period.
/// The offset stays within `[back, up]`, so over each period the host clock advances exactly as
/// far as true time.
fn stepped_correction(i: u32, up: i64, back: i64) -> i64 {
    let period = u32::try_from(up / 40).unwrap();
    let block = u32::try_from(back / 40).unwrap();
    up - back * i64::from((i % period) / block)
}

#[test]
#[ignore = "wall-clock lag-and-catch-up; follow-up #183 (monotonic arrival)"]
fn frozen_rtp_with_forward_step_corrected_by_small_backward_steps_exceeds_the_bound() {
    // The host clock steps forward 100 s, then is stepped back 10 s every 10 s (each back step
    // keeps the mark), and repeats. Its offset stays within 10..100 s; over each 100 s period the
    // host clock advances exactly 100 s. The span gains only one capped 10 s step per period,
    // so a frozen-RTP segment stays open 10x the 240 s bound.
    let off = |i: u32| stepped_correction(i, 100_000, 10_000);
    // sanity: the offset is bounded and the clock net-advances at real rate
    for i in 0..25 * 400 {
        assert!(
            (10_000..=100_000).contains(&off(i)),
            "off({i}) = {}",
            off(i)
        );
    }
    let out = run(25 * 600, |_| 7, off);
    let lens = real_lengths(&out);
    assert!(
        !lens.is_empty() && lens.iter().all(|&n| n <= BOUND_FRAMES + 250),
        "no segment closed within 600 s of true time, or too long: {lens:?}"
    );
}

#[test]
#[ignore = "wall-clock lag-and-catch-up; follow-up #183 (monotonic arrival)"]
fn frozen_rtp_with_hour_step_corrected_by_ten_second_back_steps_is_open_for_hours() {
    // As above with a 1 h forward step: the offset stays within 10 s..1 h, yet the span gains
    // about 20 s per hour of true time. Two hours of true time pass without a close.
    let off = |i: u32| stepped_correction(i, 3_600_000, 10_000);
    let out = run(25 * 7200, |_| 7, off);
    let lens = real_lengths(&out);
    assert!(
        !lens.is_empty() && lens.iter().all(|&n| n <= BOUND_FRAMES + 250),
        "no segment closed within 2 h of true time, or too long: {lens:?}"
    );
}

#[test]
#[ignore = "wall-clock lag-and-catch-up; follow-up #183 (monotonic arrival)"]
fn frozen_rtp_with_host_clock_that_stalls_and_catches_up_is_bounded() {
    // The host clock reading sticks for 100 s, then steps forward 100 s to true time, and
    // repeats (a stuck clocksource catching up). The clock is never more than 100 s off and
    // keeps true time on average, but each catch-up step counts only 10 s, so the span gains
    // 10 s per 100 s of true time: a frozen-RTP segment would stay open about 2400 s.
    let off = |i: u32| -i64::from(i % 2500) * 40;
    let out = run(25 * 900, |_| 7, off);
    let lens = real_lengths(&out);
    assert!(
        !lens.is_empty() && lens.iter().all(|&n| n <= BOUND_FRAMES + 2500),
        "no segment closed within 900 s of true time, or too long: {lens:?}"
    );
}

// ---------- healthy streams are not cut by plausible clock events ----------

#[test]
fn healthy_stream_survives_a_backward_hour_step_and_its_correction() {
    // Wrong NTP answer: -1 h at 30 s, corrected +1 h at 50 s. Sound RTP: no frame dropped and
    // every segment is the 60 s target.
    let out = run(
        25 * 600,
        |i| i * 3600,
        |i| {
            if (750..1250).contains(&i) {
                -3_600_000
            } else {
                0
            }
        },
    );
    assert_eq!(drops(&out), 0);
    assert!(real_lengths(&out).iter().all(|&n| n == 1500));
}

#[test]
fn healthy_stream_survives_three_boot_steps_in_one_segment() {
    // Several steps at first sync (+1 h, +2 h, +3 h) inside one segment add at most 30 s.
    let out = run(
        25 * 600,
        |i| i * 3600,
        |i| match i {
            0..100 => 0,
            100..200 => 3_600_000,
            200..300 => 7_200_000,
            _ => 10_800_000,
        },
    );
    assert_eq!(drops(&out), 0);
    assert!(real_lengths(&out).iter().all(|&n| n == 1500));
}

#[test]
fn healthy_stream_with_jittery_bursty_arrivals_is_not_cut() {
    // Frames arrive in 1 s bursts (25 frames with the same arrival), sound RTP.
    let out = run(25 * 600, |i| i * 3600, |i| -i64::from(i % 25) * 40);
    assert_eq!(drops(&out), 0);
    assert!(real_lengths(&out).iter().all(|&n| n == 1500));
}

#[test]
fn healthy_stream_with_oscillating_ten_second_disagreement_is_not_cut() {
    let out = run(
        25 * 900,
        |i| i * 3600,
        |i| if (i / 25) % 2 == 1 { 10_000 } else { 0 },
    );
    assert_eq!(drops(&out), 0);
    assert!(real_lengths(&out).iter().all(|&n| n == 1500));
}

// ---------- arithmetic at the edges of the accepted wall-clock window ----------

#[test]
fn wall_clock_extremes_never_panic_and_backward_extreme_adds_nothing() {
    let mut s = default_seg();
    assert_eq!(
        s.push(frame(true, 0, MAX_MS, 10)).decision,
        Decision::StartNew
    );
    // full backward step: re-anchor, adds 0
    let p = s.push(frame(false, 1, MIN_MS, 10));
    assert_eq!((p.decision, p.closed), (Decision::Append, None));
    // 23 forward extremes: 230 s
    for i in 0..23u32 {
        let a = s.push(frame(false, 2 + 2 * i, MAX_MS, 10));
        assert_eq!(a.decision, Decision::Append, "up {i}");
        let b = s.push(frame(false, 3 + 2 * i, MIN_MS, 10));
        assert_eq!(b.decision, Decision::Append, "down {i}");
    }
    // the 24th forward step reaches 240 s
    let p = s.push(frame(false, 100, MAX_MS, 10));
    assert_eq!(p.decision, Decision::Drop);
    assert!(p.closed.is_some());
}

#[test]
fn invalid_frame_does_not_leak_arrival_state_into_the_next_segment() {
    let mut s = default_seg();
    s.push(frame(true, 0, T0, 10));
    for i in 1..20 {
        s.push(frame(false, 0, T0 + i * 10_000, 10)); // 190 s of span
    }
    let e = s.push(frame(false, 0, T0 + 200_000, 0)); // empty frame: closes
    assert!(e.closed.is_some());
    // The next segment must start from 0 span: 23 more steps of 10 s still append.
    assert_eq!(
        s.push(frame(true, 0, T0 + 210_000, 10)).decision,
        Decision::StartNew
    );
    for i in 1..24 {
        let p = s.push(frame(false, 0, T0 + 210_000 + i * 10_000, 10));
        assert_eq!(p.decision, Decision::Append, "frame {i}");
    }
}

proptest::proptest! {
    /// Frozen RTP, a host clock with bounded offset |off| <= 10 s that changes by arbitrary
    /// steps: every segment closes within 240 s + 20 s + 1 GOP of true time.
    #[test]
    #[ignore = "wall-clock lag-and-catch-up; follow-up #183 (monotonic arrival)"]
    fn frozen_rtp_with_bounded_host_offset_is_bounded_in_true_time(
        steps in proptest::collection::vec((1u32..500, -10_000i64..=10_000), 1..200),
    ) {
        let mut offsets = Vec::new();
        for (len, o) in steps {
            for _ in 0..len { offsets.push(o); }
        }
        let n = u32::try_from(offsets.len()).unwrap().min(25 * 1200);
        let out = run(n, |_| 7, |i| offsets[usize::try_from(i).unwrap()]);
        // also: a segment still open at the end must not be older than the bound
        let mut open_since: Option<u32> = None;
        for (i, p) in out.iter().enumerate() {
            let i = u32::try_from(i).unwrap();
            if p.closed.is_some() || p.decision == Decision::Drop { open_since = None; }
            if p.decision == Decision::StartNew { open_since = Some(i); }
            if let Some(st) = open_since {
                proptest::prop_assert!(
                    u64::from(i - st) <= BOUND_FRAMES + 500 + 50,
                    "segment open {} frames", i - st
                );
            }
        }
    }
}
