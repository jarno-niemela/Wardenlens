//! Adversarial tests for the arrival-span segment bound (ticket #103, ADR 0005 section 2 rule 3a).
#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on small bounded literals"
)]

use wardenlens_core::recording::{Decision, FrameMeta, Pushed, SegmentConfig, Segmenter};
use wardenlens_core::time::UnixMs;

const T0: i64 = 1_700_000_000_000;

fn frame(key: bool, rtp: u32, at: i64, bytes: u64) -> FrameMeta {
    FrameMeta::new(key, rtp, UnixMs::new(at).unwrap(), bytes)
}

fn default_seg() -> Segmenter {
    Segmenter::new("cam".parse().unwrap(), SegmentConfig::default())
}

fn starts(out: &[Pushed]) -> Vec<usize> {
    out.iter()
        .enumerate()
        .filter(|(_, p)| p.decision == Decision::StartNew)
        .map(|(i, _)| i)
        .collect()
}

// ---------- the bound fires where the ADR says (defaults: 240 s) ----------

#[test]
fn frozen_rtp_default_config_closes_at_240_s_of_arrival() {
    let mut s = default_seg();
    let out: Vec<Pushed> = (0..25 * 800u32)
        .map(|i| s.push(frame(i % 25 == 0, 42, T0 + i64::from(i) * 40, 1000)))
        .collect();
    // 240 s at 40 ms per frame is frame 6000, which is a keyframe.
    assert_eq!(starts(&out), [0, 6000, 12_000, 18_000]);
    for r in out.iter().filter_map(|p| p.closed.as_ref()) {
        assert_eq!(r.frame_count, 6000);
        assert!(r.duration_ms < 600_000, "{r:?}");
    }
}

#[test]
fn backward_drift_default_config_is_bounded_and_never_starts_on_a_non_keyframe() {
    let mut s = default_seg();
    let frames: Vec<(bool, Pushed)> = (0..25 * 1000u32)
        .map(|i| {
            let key = i % 50 == 0;
            let rtp = 4_000_000_000u32.wrapping_sub(i * 90);
            (key, s.push(frame(key, rtp, T0 + i64::from(i) * 40, 1000)))
        })
        .collect();
    let mut closes = 0;
    for (key, p) in &frames {
        if p.decision == Decision::StartNew {
            assert!(*key, "segment started on a non-keyframe");
        }
        if let Some(r) = &p.closed {
            closes += 1;
            assert!(r.frame_count <= 6000, "{r:?}");
        }
    }
    assert!(closes >= 4);
}

#[test]
fn keyframe_only_frozen_stream_is_bounded() {
    let mut s = default_seg();
    let out: Vec<Pushed> = (0..25 * 500u32)
        .map(|i| s.push(frame(true, 7, T0 + i64::from(i) * 40, 10)))
        .collect();
    assert!(out.iter().all(|p| p.decision != Decision::Drop));
    assert_eq!(starts(&out), [0, 6000, 12_000]);
}

#[test]
fn extreme_wall_clock_steps_add_one_capped_step_each_and_never_panic() {
    // 2000-01-01 to 2099-12-31 and back: the span arithmetic saturates, never panics, and one
    // forward step adds at most the 10 s per-step cap (round 2 ruling; round 1 expected a cut).
    let lo = 946_684_800_000;
    let hi = 4_102_444_799_999;
    let mut s = default_seg();
    s.push(frame(true, 0, lo, 10));
    let p = s.push(frame(false, 3600, hi, 10));
    assert_eq!((p.decision, p.closed), (Decision::Append, None));
    // Alternate lo / hi on non-keyframes: each hi adds 10 s (each lo adds 0), so the 240 s bound
    // is reached at the 24th forward step, frame index 47, and the segment closes exactly once.
    let mut closes = Vec::new();
    for i in 2..60u32 {
        let at = if i % 2 == 0 { lo } else { hi };
        let p = s.push(frame(false, i * 3600, at, 10));
        if let Some(r) = p.closed {
            closes.push((i, p.decision, r.frame_count));
        } else if closes.is_empty() {
            assert_eq!(p.decision, Decision::Append, "frame {i}");
        } else {
            assert_eq!(p.decision, Decision::Drop, "frame {i}");
        }
    }
    assert_eq!(closes, [(47, Decision::Drop, 47)]);
    // A new segment starts only on a keyframe, and closes nothing.
    let k = s.push(frame(true, 60 * 3600, lo, 10));
    assert_eq!((k.decision, k.closed), (Decision::StartNew, None));
    let q = s.push(frame(false, 61 * 3600, hi, 10));
    assert_eq!((q.decision, q.closed), (Decision::Append, None));
}

#[test]
fn healthy_stream_at_max_target_never_hits_the_arrival_bound() {
    // 290 s target, 1 fps, GOP 10: cut at 290 s media, bound (1160 s) never reached.
    let mut s = Segmenter::new(
        "cam".parse().unwrap(),
        SegmentConfig::new(SegmentConfig::MAX_TARGET_SECS, 1 << 40).unwrap(),
    );
    let out: Vec<Pushed> = (0..3000u32)
        .map(|i| {
            s.push(frame(
                i % 10 == 0,
                i * 90_000,
                T0 + i64::from(i) * 1000,
                100,
            ))
        })
        .collect();
    assert!(out.iter().all(|p| p.decision != Decision::Drop));
    for r in out.iter().filter_map(|p| p.closed.as_ref()) {
        assert_eq!(r.frame_count, 290);
        assert_eq!(r.duration_ms, 290_000);
    }
}

// ---------- minimality: a healthy stream must not lose frames to a host clock step ----------

/// 25 fps with a sound RTP clock, GOP 50 (2 s), default config. `at(i)` gives the arrival offset.
fn healthy(n: u32, at: impl Fn(u32) -> i64) -> Vec<Pushed> {
    let mut s = default_seg();
    (0..n)
        .map(|i| s.push(frame(i % 50 == 0, i * 3600, T0 + at(i), 1000)))
        .collect()
}

#[test]
fn forward_wall_clock_step_on_a_healthy_stream_drops_no_frames() {
    // NTP steps the host clock forward one hour at frame 1030 (a non-keyframe, 41.2 s in),
    // as on a host without an RTC at first sync. The camera's RTP clock is sound: media time
    // bounds the segment. ADR rule 3a says such a cut "only costs a segment boundary".
    let out = healthy(25 * 200, |i| {
        let t = i64::from(i) * 40;
        if i < 1030 { t } else { t + 3_600_000 }
    });
    let dropped: Vec<usize> = out
        .iter()
        .enumerate()
        .filter(|(_, p)| p.decision == Decision::Drop)
        .map(|(i, _)| i)
        .collect();
    assert!(
        dropped.is_empty(),
        "healthy frames dropped after a wall-clock step: {} frames {:?}..",
        dropped.len(),
        dropped.first()
    );
}

#[test]
fn oscillating_wall_clock_does_not_cut_a_healthy_stream_early() {
    // Two time daemons fighting: the clock alternates +500 ms / -500 ms around true time.
    // Real time per segment is 60 s; the forward-step sum is about 6.75x that.
    let out = healthy(25 * 300, |i| {
        i64::from(i) * 40 + if i % 2 == 1 { 500 } else { 0 }
    });
    let dropped = out.iter().filter(|p| p.decision == Decision::Drop).count();
    let lens: Vec<u64> = out
        .iter()
        .filter_map(|p| p.closed.as_ref().map(|r| r.frame_count))
        .collect();
    assert_eq!(
        dropped, 0,
        "frames dropped; closed segment lengths {lens:?}"
    );
    assert!(lens.iter().all(|&n| n == 1500), "{lens:?}");
}

proptest::proptest! {
    /// Any arrival pattern (monotonic, with stalls and bursts) and frozen or normal RTP:
    /// segments start only on keyframes, every frame closes at most one segment, and for
    /// monotonic arrivals the appended span stays under 240 s.
    #[test]
    fn monotonic_arrival_span_is_bounded_and_starts_are_keyframes(
        frames in proptest::collection::vec(
            (proptest::bool::weighted(0.02), proptest::bool::ANY, 0i64..2000),
            1..3000,
        ),
    ) {
        let mut s = default_seg();
        let mut at = T0;
        let mut first: Option<i64> = None;
        let mut rtp = 0u32;
        for (key, frozen, dat) in frames {
            at += dat;
            if !frozen { rtp = rtp.wrapping_add(3600); }
            let p = s.push(frame(key, rtp, at, 100));
            match p.decision {
                Decision::StartNew => {
                    proptest::prop_assert!(key);
                    first = Some(at);
                }
                Decision::Append => {
                    let f = first.unwrap();
                    proptest::prop_assert!(at - f < 240_000, "span {}", at - f);
                }
                _ => {
                    first = None;
                }
            }
        }
    }
}
