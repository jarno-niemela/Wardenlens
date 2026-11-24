//! `MediaClock`: strictly increasing 90 kHz media time from RTP timestamps.

/// Ticks per second of the media timescale (RTP video clock).
pub(crate) const TICKS_PER_SECOND: u64 = 90_000;

/// Largest step between two samples, 10 s; also the forward re-base threshold.
pub(crate) const MAX_STEP_TICKS: u64 = 10 * TICKS_PER_SECOND;

/// A backward step of more than this (about 1 s) is a re-base, less is jitter.
const BACKWARD_REBASE_TICKS: i64 = 90_000;

/// Re-base step used before any unclamped step has been seen (25 fps).
const DEFAULT_STEP_TICKS: u64 = 3600;

#[derive(Debug, Clone, Copy)]
struct State {
    /// Raw RTP timestamp of the previous frame, for the wrapping difference.
    last_rtp: u32,
    /// Unwrapped RTP position of the previous frame.
    last_ext: i64,
    /// Unwrapped RTP position that maps to media time 0.
    base: i64,
    /// Media time of the previous frame.
    dts: u64,
    /// Last unclamped step, reused when a re-base keeps the media time continuous.
    /// Starts at one frame of 25 fps (3600 ticks) until a real step is seen.
    last_good_step: u64,
}

/// Turns RTP timestamps into strictly increasing media time (ADR 0005 section 2).
///
/// `dts_i = max(rtp_i - rtp_0, dts_{i-1} + 1)`: it clamps instead of
/// accumulating, so jitter (Tapo, Dahua) does not drift the total. A forward
/// jump of more than 10 s or a backward step of more than about 1 s re-bases:
/// the step keeps the last good duration and the clock continues from the new
/// RTP value. The 32-bit RTP counter is unwrapped with a signed wrapping
/// difference. Not trusted for streams with frame reordering until the #55
/// check passes.
///
/// ```
/// use wardenlens_core::recording::MediaClock;
/// let mut clock = MediaClock::default();
/// assert_eq!(clock.push(1000), 0);
/// assert_eq!(clock.push(4600), 3600);
/// assert_eq!(clock.push(4600), 3601); // equal timestamp: one tick later
/// ```
#[derive(Debug, Clone, Default)]
pub struct MediaClock {
    state: Option<State>,
}

impl MediaClock {
    /// Returns the media time in ticks of a frame with RTP timestamp `rtp`.
    ///
    /// The first frame after creation or [`reset`](Self::reset) is time 0.
    /// The result is strictly greater than the previous one, and the step is
    /// between 1 tick and 10 s. All arithmetic saturates; it cannot panic.
    pub fn push(&mut self, rtp: u32) -> u64 {
        let Some(prev) = self.state else {
            self.state = Some(State {
                last_rtp: rtp,
                last_ext: i64::from(rtp),
                base: i64::from(rtp),
                dts: 0,
                last_good_step: DEFAULT_STEP_TICKS,
            });
            return 0;
        };
        let delta = i64::from(i32::from_ne_bytes(
            rtp.wrapping_sub(prev.last_rtp).to_ne_bytes(),
        ));
        let ext = prev.last_ext.saturating_add(delta);
        let line_signed = ext.saturating_sub(prev.base);
        // The RTP line has fallen far behind media time: a run of small backward
        // steps, each too short to re-base on its own, would otherwise freeze it.
        let drift = i64::try_from(prev.dts)
            .unwrap_or(i64::MAX)
            .saturating_sub(line_signed)
            > BACKWARD_REBASE_TICKS;
        let rebase = delta < -BACKWARD_REBASE_TICKS
            || drift
            || u64::try_from(delta).is_ok_and(|d| d > MAX_STEP_TICKS);
        let (dts, base, good) = if rebase {
            let dts = prev.dts.saturating_add(prev.last_good_step);
            (
                dts,
                ext.saturating_sub(i64::try_from(dts).unwrap_or(i64::MAX)),
                prev.last_good_step,
            )
        } else {
            let line = u64::try_from(line_signed).unwrap_or(0);
            let floor = prev.dts.saturating_add(1);
            let dts = line.max(floor);
            // Only a step that followed the RTP line (not clamped) is "good".
            let good = if line >= floor {
                dts.saturating_sub(prev.dts)
            } else {
                prev.last_good_step
            };
            (dts, prev.base, good)
        };
        self.state = Some(State {
            last_rtp: rtp,
            last_ext: ext,
            base,
            dts,
            last_good_step: good,
        });
        dts
    }

    /// Forgets the stream, so the next frame is time 0 (after a discontinuity).
    pub fn reset(&mut self) {
        self.state = None;
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic on small bounded literals"
    )]

    use super::*;

    fn run(rtps: &[u32]) -> Vec<u64> {
        let mut c = MediaClock::default();
        rtps.iter().map(|&r| c.push(r)).collect()
    }

    #[test]
    fn first_frame_is_zero_whatever_the_rtp_start() {
        assert_eq!(run(&[0]), [0]);
        assert_eq!(run(&[u32::MAX]), [0]);
        assert_eq!(run(&[123_456_789, 123_460_389]), [0, 3600]);
    }

    #[test]
    fn regular_25_fps_follows_rtp() {
        assert_eq!(run(&[0, 3600, 7200, 10_800]), [0, 3600, 7200, 10_800]);
    }

    #[test]
    fn equal_timestamp_becomes_one_tick() {
        assert_eq!(run(&[0, 3600, 3600, 7200]), [0, 3600, 3601, 7200]);
    }

    #[test]
    fn small_backward_step_is_clamped_and_does_not_accumulate() {
        // Tapo style: pairs of frames in decode order jitter; the next normal frame is back on the line.
        assert_eq!(run(&[0, 7200, 3600, 10_800]), [0, 7200, 7201, 10_800]);
    }

    #[test]
    fn jittery_stream_does_not_drift_over_many_frames() {
        let mut c = MediaClock::default();
        let mut last = 0;
        for i in 0..10_000u32 {
            // every third frame arrives with the previous frame's timestamp
            let rtp = if i % 3 == 2 { (i - 1) * 3600 } else { i * 3600 };
            last = c.push(rtp);
        }
        let expected = u64::from(9_999u32 * 3600);
        assert!(last.abs_diff(expected) < 100, "{last} vs {expected}");
    }

    #[test]
    fn wrap_at_32_bits_is_unwrapped() {
        let a = u32::MAX - 3599;
        assert_eq!(
            run(&[a, a.wrapping_add(3600), a.wrapping_add(7200)]),
            [0, 3600, 7200]
        );
    }

    #[test]
    fn forward_jump_of_exactly_ten_seconds_is_not_a_rebase() {
        assert_eq!(run(&[0, 3600, 3600 + 900_000]), [0, 3600, 903_600]);
    }

    #[test]
    fn forward_jump_over_ten_seconds_rebases_with_last_good_step() {
        let dts = run(&[0, 3600, 3600 + 900_001, 3600 + 900_001 + 3600]);
        assert_eq!(dts, [0, 3600, 7200, 10_800]);
    }

    #[test]
    fn backward_step_over_a_second_rebases() {
        let dts = run(&[1_000_000, 1_003_600, 500_000, 503_600]);
        assert_eq!(dts, [0, 3600, 7200, 10_800]);
    }

    #[test]
    fn backward_step_of_exactly_a_second_is_jitter() {
        assert_eq!(run(&[200_000, 203_600, 113_600]), [0, 3600, 3601]);
    }

    #[test]
    fn rebase_after_jitter_uses_the_last_good_step() {
        let d = run(&[0, 3600, 7200, 3600, 7200 + 2_000_000]);
        assert_eq!(d, [0, 3600, 7200, 7201, 7201 + 3600]);
    }

    #[test]
    fn run_of_sub_second_backward_steps_does_not_freeze_media_time() {
        // Each step back is 80 000 ticks (jitter alone); the line drifts away and re-bases.
        let d = run(&[200_000, 203_600, 123_600, 43_600, 47_200]);
        assert_eq!(d, [0, 3600, 3601, 7201, 10_801]);
    }

    #[test]
    fn reolink_variable_frame_rate_follows_the_rtp_line_exactly() {
        let steps = [3000u32, 3600, 4500, 2700, 3000, 4500, 3600, 2700];
        let mut rtp = 1_000u32;
        let mut want = 0u64;
        let mut c = MediaClock::default();
        assert_eq!(c.push(rtp), 0);
        for s in steps {
            rtp = rtp.wrapping_add(s);
            want += u64::from(s);
            assert_eq!(c.push(rtp), want);
        }
    }

    #[test]
    fn reset_starts_a_new_stream_at_zero() {
        let mut c = MediaClock::default();
        c.push(5);
        c.push(3605);
        c.reset();
        assert_eq!(c.push(99), 0);
    }

    proptest::proptest! {
        #[test]
        fn strictly_increasing_with_bounded_steps(rtps in proptest::collection::vec(proptest::num::u32::ANY, 1..200)) {
            let dts = run(&rtps);
            for w in dts.windows(2) {
                proptest::prop_assert!(w[1] > w[0]);
                proptest::prop_assert!(w[1] - w[0] <= MAX_STEP_TICKS);
            }
        }
    }
}
