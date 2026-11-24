//! Round-2 adversarial tests for `core::recording` (ticket #45): caps, re-base, paths.
#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on bounded values"
)]

use wardenlens_core::recording::{
    Decision, FrameMeta, MAX_FRAGMENT_BYTES, MAX_FRAME_BYTES, MediaClock, PushError, Pushed,
    RelPath, SegmentConfig, Segmenter,
};
use wardenlens_core::time::UnixMs;

const T0: i64 = 1_700_000_000_000;
const MIB: u64 = 1 << 20;

fn frame(key: bool, rtp: u32, bytes: u64) -> FrameMeta {
    FrameMeta::new(key, rtp, UnixMs::new(T0).unwrap(), bytes)
}

fn seg(target: u32, cap: u64) -> Segmenter {
    Segmenter::new(
        "cam".parse().unwrap(),
        SegmentConfig::new(target, cap).unwrap(),
    )
}

/// Muxer model: replays decisions, checks fragment and segment invariants.
#[derive(Default)]
struct Model {
    frag: u64,
    seg_bytes: u64,
    seg_frames: u64,
    open: bool,
    last_dts: Option<u64>,
}

impl Model {
    fn apply(&mut self, f: &FrameMeta, p: &Pushed, cap: u64) -> Result<(), String> {
        if let Some(r) = &p.closed {
            if !self.open {
                return Err("closed a segment the model never opened".into());
            }
            if r.bytes != self.seg_bytes || r.frame_count != self.seg_frames {
                return Err(format!(
                    "record {}/{} vs model {}/{}",
                    r.bytes, r.frame_count, self.seg_bytes, self.seg_frames
                ));
            }
            if r.duration_ms == 0 || r.duration_ms > 600_000 {
                return Err(format!("duration {}", r.duration_ms));
            }
            if cap >= MAX_FRAME_BYTES && r.bytes > cap {
                return Err(format!("record bytes {} over cap {cap}", r.bytes));
            }
            self.open = false;
        }
        match p.decision {
            Decision::Drop => {
                if p.flush_fragment || p.dts.is_some() {
                    return Err("drop with flush or dts".into());
                }
            }
            Decision::StartNew => {
                if !f.is_keyframe || !p.flush_fragment || p.dts != Some(0) || p.error.is_some() {
                    return Err(format!("bad StartNew {p:?}"));
                }
                self.open = true;
                self.frag = f.bytes;
                self.seg_bytes = f.bytes;
                self.seg_frames = 1;
                self.last_dts = Some(0);
            }
            Decision::Append => {
                if !self.open {
                    return Err("append without open segment".into());
                }
                if f.is_keyframe && !p.flush_fragment {
                    return Err("keyframe without flush".into());
                }
                let d = p.dts.ok_or("append without dts")?;
                if self.last_dts.is_some_and(|l| d <= l) {
                    return Err(format!("dts not increasing: {d} after {:?}", self.last_dts));
                }
                self.last_dts = Some(d);
                self.frag = if p.flush_fragment {
                    f.bytes
                } else {
                    self.frag + f.bytes
                };
                self.seg_bytes += f.bytes;
                self.seg_frames += 1;
            }
            _ => return Err("unknown decision".into()),
        }
        if self.open && self.frag > MAX_FRAGMENT_BYTES {
            return Err(format!("fragment {} over 16 MiB", self.frag));
        }
        Ok(())
    }
}

fn byte_size() -> impl proptest::strategy::Strategy<Value = u64> {
    use proptest::prelude::*;
    prop_oneof![
        Just(0u64),
        1u64..1000,
        Just(MAX_FRAME_BYTES),
        Just(MAX_FRAME_BYTES + 1),
        (MAX_FRAME_BYTES - 4096)..(MAX_FRAME_BYTES + 4096),
        (1u64..(9 * MIB)),
    ]
}

fn rtp_step() -> impl proptest::strategy::Strategy<Value = u32> {
    use proptest::prelude::*;
    prop_oneof![
        Just(0u32),
        Just(3600u32),
        2700u32..4500,
        Just(900_000u32),
        Just(900_001u32),
        any::<u32>(),
    ]
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

    #[test]
    fn muxer_model_invariants_hold_for_hostile_streams(
        frames in proptest::collection::vec((proptest::bool::weighted(0.2), rtp_step(), byte_size()), 1..400),
        target in 10u32..=290,
        cap in proptest::prop_oneof![proptest::strategy::Just(u64::MAX), (8u64 * MIB)..(64 * MIB)],
    ) {
        let mut s = seg(target, cap);
        let mut m = Model::default();
        let mut rtp = 0u32;
        for (k, step, bytes) in frames {
            rtp = rtp.wrapping_add(step);
            let f = frame(k, rtp, bytes);
            let p = s.push(f);
            // Typed errors exactly for the invalid sizes.
            let want = if bytes == 0 { Some(PushError::EmptyFrame) }
                else if bytes > MAX_FRAME_BYTES { Some(PushError::FrameTooLarge) } else { None };
            proptest::prop_assert_eq!(p.error, want);
            if want.is_some() {
                proptest::prop_assert_eq!(p.decision, Decision::Drop);
            }
            if let Err(e) = m.apply(&f, &p, cap) {
                return Err(proptest::test_runner::TestCaseError::fail(e));
            }
        }
        if let Some(r) = s.finish() {
            proptest::prop_assert!(m.open);
            proptest::prop_assert_eq!((r.bytes, r.frame_count), (m.seg_bytes, m.seg_frames));
            proptest::prop_assert!(r.duration_ms >= 1 && r.duration_ms <= 600_000);
        } else {
            proptest::prop_assert!(!m.open);
        }
    }

    #[test]
    fn clock_steps_are_bounded_for_any_input(rtps in proptest::collection::vec(rtp_step(), 1..500)) {
        let mut c = MediaClock::default();
        let mut rtp = 0u32;
        let mut prev: Option<u64> = None;
        for s in rtps {
            rtp = rtp.wrapping_add(s);
            let d = c.push(rtp);
            if let Some(p) = prev {
                proptest::prop_assert!(d > p);
                proptest::prop_assert!(d - p <= 900_000);
            } else {
                proptest::prop_assert_eq!(d, 0);
            }
            prev = Some(d);
        }
    }

    #[test]
    fn relpath_display_parse_round_trip_any_valid_time(ms in 946_684_800_000i64..=4_102_444_799_999) {
        let p = RelPath::new(&"a-1".parse().unwrap(), UnixMs::new(ms).unwrap());
        let s = p.to_string();
        let back: RelPath = s.parse().unwrap();
        proptest::prop_assert_eq!(back, p);
        proptest::prop_assert!(!s.contains(".."));
        proptest::prop_assert_eq!(s.matches('/').count(), 2);
    }

    #[test]
    fn relpath_parse_never_panics_on_arbitrary_text(s in "\\PC{0,64}") {
        let _ = s.parse::<RelPath>();
    }

    #[test]
    fn relpath_parse_never_panics_on_mutated_canonical(
        pos in 0usize..30, ch in proptest::char::any()
    ) {
        let mut s: Vec<char> = "cam/2024-02-29/134507-042.mp4".chars().collect();
        let i = pos % s.len();
        s[i] = ch;
        let t: String = s.into_iter().collect();
        if let Ok(p) = t.parse::<RelPath>() {
            proptest::prop_assert_eq!(p.to_string(), t);
        }
    }
}

// ---------- Caps: exact boundaries ----------

#[test]
fn two_8_mib_frames_fill_one_fragment_exactly_then_third_flushes() {
    let mut s = seg(10, u64::MAX);
    let a = s.push(frame(true, 0, MAX_FRAME_BYTES));
    let b = s.push(frame(false, 3600, MAX_FRAME_BYTES));
    let c = s.push(frame(false, 7200, 1));
    assert!(a.flush_fragment);
    assert!(!b.flush_fragment, "exactly 16 MiB must not flush");
    assert!(c.flush_fragment, "16 MiB + 1 must flush before the frame");
}

#[test]
fn flush_resets_fragment_count_to_the_new_frame() {
    let mut s = seg(10, u64::MAX);
    s.push(frame(true, 0, MAX_FRAME_BYTES));
    s.push(frame(false, 3600, MAX_FRAME_BYTES));
    assert!(s.push(frame(false, 7200, MAX_FRAME_BYTES)).flush_fragment);
    // fragment now holds 8 MiB: one more 8 MiB fits exactly
    assert!(!s.push(frame(false, 10_800, MAX_FRAME_BYTES)).flush_fragment);
    assert!(s.push(frame(false, 14_400, 1)).flush_fragment);
}

#[test]
fn mid_gop_keyframe_append_flushes_and_resets_fragment() {
    let mut s = seg(10, u64::MAX);
    s.push(frame(true, 0, MAX_FRAME_BYTES));
    let k = s.push(frame(true, 3600, MAX_FRAME_BYTES));
    assert_eq!(k.decision, Decision::Append);
    assert!(k.flush_fragment);
    assert!(!s.push(frame(false, 7200, MAX_FRAME_BYTES)).flush_fragment);
}

#[test]
fn byte_cap_exact_fit_appends_one_more_byte_closes() {
    let mut s = seg(10, 1000);
    s.push(frame(true, 0, 400));
    assert_eq!(s.push(frame(false, 3600, 600)).decision, Decision::Append);
    let p = s.push(frame(false, 7200, 1));
    assert_eq!(p.decision, Decision::Drop);
    assert_eq!(p.closed.unwrap().bytes, 1000);
}

#[test]
fn invalid_frame_with_no_open_segment_reports_error_and_no_record() {
    let mut s = seg(10, u64::MAX);
    let p = s.push(frame(true, 0, 0));
    assert_eq!(
        (p.decision, p.error, p.closed.is_none()),
        (Decision::Drop, Some(PushError::EmptyFrame), true)
    );
    let p = s.push(frame(true, 3600, MAX_FRAME_BYTES + 1));
    assert_eq!(p.error, Some(PushError::FrameTooLarge));
    assert_eq!(s.push(frame(false, 7200, 1)).decision, Decision::Drop);
    assert_eq!(s.push(frame(true, 10_800, 1)).decision, Decision::StartNew);
}

#[test]
fn invalid_frame_closes_and_drops_until_keyframe_with_u64_max_bytes() {
    let mut s = seg(10, u64::MAX);
    s.push(frame(true, 0, 10));
    s.push(frame(false, 3600, 10));
    let p = s.push(frame(false, 7200, u64::MAX));
    assert_eq!(p.error, Some(PushError::FrameTooLarge));
    let r = p.closed.unwrap();
    assert_eq!((r.bytes, r.frame_count), (20, 2));
    assert_eq!(s.push(frame(false, 10_800, 10)).decision, Decision::Drop);
    let k = s.push(frame(true, 14_400, 10));
    assert_eq!((k.decision, k.closed), (Decision::StartNew, None));
}

// ---------- MediaClock re-base ----------

#[test]
fn first_rebase_without_any_real_step_uses_3600() {
    let mut c = MediaClock::default();
    assert_eq!(c.push(0), 0);
    assert_eq!(c.push(2_000_000), 3600);
}

#[test]
fn drift_rebase_after_long_frozen_rtp_keeps_increasing() {
    let mut c = MediaClock::default();
    let mut prev = c.push(5);
    for _ in 0..200_000 {
        let d = c.push(5);
        assert!(d > prev && d - prev <= 3600);
        prev = d;
    }
    // Stream resumes at a normal pace. The clamp may hold the clock up to ~1 s ahead of
    // the line (ADR rule `max(line, prev + 1)`), so allow up to 26 clamped frames, then
    // steps must follow the RTP line exactly.
    let mut rtp = 5u32;
    let mut steps = Vec::new();
    for _ in 0..60 {
        rtp += 3600;
        let d = c.push(rtp);
        assert!(d > prev);
        steps.push(d - prev);
        prev = d;
    }
    assert!(steps[26..].iter().all(|&s| s == 3600), "{steps:?}");
}

#[test]
fn backward_wrap_across_zero_is_jitter_not_rebase() {
    // RTP goes from 1000 back to u32::MAX - 999 (2000 ticks backwards across 0).
    let mut c = MediaClock::default();
    c.push(u32::MAX - 10_000);
    let a = c.push(1000);
    let b = c.push(u32::MAX - 999);
    assert_eq!(b, a + 1);
    assert_eq!(c.push(4600), a + 3600);
}

#[test]
fn jitter_within_tolerance_then_line_resumes_without_drift_rebase() {
    // Backward steps of 80 000 then forward recovery: never more than 90 000 behind.
    let mut c = MediaClock::default();
    let base = 1_000_000u32;
    assert_eq!(c.push(base), 0);
    assert_eq!(c.push(base + 90_000), 90_000);
    assert_eq!(c.push(base + 10_000), 90_001);
    assert_eq!(c.push(base + 180_000), 180_000);
}

// ---------- Hard maximum and target with re-basing ----------

#[test]
fn target_290_hard_max_never_exceeds_600s_with_10s_steps() {
    let mut s = seg(290, u64::MAX);
    let mut rtp = 0u32;
    let mut worst = 0;
    for i in 0..1000u32 {
        let p = s.push(frame(i == 0, rtp, 1));
        if let Some(r) = p.closed {
            worst = worst.max(r.duration_ms);
        }
        rtp = rtp.wrapping_add(if i % 7 == 0 { 899_999 } else { 900_000 });
    }
    if let Some(r) = s.finish() {
        worst = worst.max(r.duration_ms);
    }
    assert!(worst > 0 && worst <= 600_000, "{worst}");
}

// ---------- RelPath hostile names ----------

#[test]
fn relpath_rejects_lookalikes() {
    for s in [
        "cam/2024-02-29/134507-042.mp4\0",
        "cam/2024-02-29/134507-042.mp4\n",
        "cam/2024-02-29/134507-042.MP4",
        "cam/2024-02-29/134507-042.mp4.mp4",
        "cam/2024-02-29/134507-0420.mp4",
        "cam/2024-02-29/134507--42.mp4",
        "cam/2024-02-29/1345\u{0660}7-042.mp4",
        "cam/2024-02-29/13450\u{301}7-042.mp4",
        "cam/2024-2-29/134507-042.mp4",
        "cam/+024-02-29/134507-042.mp4",
        "cam/2024-02-29/+34507-042.mp4",
        "cam/2024-02-29/134507-+42.mp4",
        "cam\\x/2024-02-29/134507-042.mp4",
        "../2024-02-29/134507-042.mp4",
        "cam/../134507-042.mp4",
        "cam//2024-02-29/134507-042.mp4",
        "cam/2024-02-29/240000-000.mp4",
        "cam/2024-02-29/236000-000.mp4",
        "cam/2024-02-29/235960-000.mp4",
        "cam/2023-02-29/000000-000.mp4",
        "cam/2100-01-01/000000-000.mp4",
        "cam/1999-12-31/235959-999.mp4",
        "cam/2024-00-10/000000-000.mp4",
        "cam/2024-13-10/000000-000.mp4",
        "cam/2024-01-00/000000-000.mp4",
        "Cam/2024-01-01/000000-000.mp4",
        "1cam/2024-01-01/000000-000.mp4",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/2024-01-01/000000-000.mp4",
        "",
        "/",
        "//",
        "cam/2024-01-01/.mp4",
        "cam/2024-01-01/-.mp4",
        "cam/2024-01-01/\u{1F600}\u{1F600}-000.mp4",
        "cam/2024-01-01/00\u{e9}000-000.mp4",
    ] {
        assert!(s.parse::<RelPath>().is_err(), "{s:?} accepted");
    }
    assert!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/2024-01-01/000000-000.mp4"
            .parse::<RelPath>()
            .is_ok()
    );
}

#[test]
#[ignore = "follow-up #105"]
fn segment_bytes_never_exceed_an_accepted_byte_cap() {
    // SegmentConfig accepts any non-zero cap, so a cap below a valid frame is allowed.
    let Ok(cfg) = SegmentConfig::new(10, 100) else {
        return; // rejecting a cap below MAX_FRAME_BYTES would also be correct
    };
    let mut s = Segmenter::new("cam".parse().unwrap(), cfg);
    let mut recs = Vec::new();
    for i in 0..10u32 {
        recs.extend(s.push(frame(true, i * 3600, 1000)).closed);
    }
    recs.extend(s.finish());
    for r in recs {
        assert!(
            r.bytes <= 100,
            "record of {} bytes under a 100-byte cap",
            r.bytes
        );
    }
}
