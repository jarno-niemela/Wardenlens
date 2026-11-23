//! Exponential, capped backoff with injected jitter.

use crate::time::DurationMs;

/// A source of random `u64`s, injected so backoff is deterministic in tests.
pub trait JitterSource {
    /// The next value.
    fn next_u64(&mut self) -> u64;
}

/// Exponential backoff: `base * 2^attempt`, capped, with jitter that never goes
/// below `base` or above `cap`.
///
/// Jitter rule: once the delay has grown past `base` it shaves up to a quarter
/// off. The first delay (`exp == base`) cannot shave, so it spreads upward
/// instead, over `base..=base + 25 %` (clamped to `cap`), so cameras that fail
/// together do not retry in lockstep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    base: DurationMs,
    cap: DurationMs,
}

impl Backoff {
    /// ADR 0002 single-request contract: 2 s growing to 5 s.
    pub const DEFAULT: Self = Self {
        base: DurationMs::from_secs(2),
        cap: DurationMs::from_secs(5),
    };

    /// A backoff starting at `base` and capped at `cap` (raised to `base` if smaller).
    pub fn new(base: DurationMs, cap: DurationMs) -> Self {
        Self {
            base,
            cap: cap.max(base),
        }
    }

    /// The longest delay this backoff produces.
    pub const fn cap(&self) -> DurationMs {
        self.cap
    }

    /// The delay before retry number `attempt` (zero-based), always within `base..=cap`.
    pub fn delay(&self, attempt: u32, jitter: &mut impl JitterSource) -> DurationMs {
        // Past 63 doublings every u64 base has saturated; clamp the shift to stay defined.
        let factor = 1u64.checked_shl(attempt.min(63)).unwrap_or(u64::MAX);
        let exp = self
            .base
            .as_millis()
            .saturating_mul(factor)
            .min(self.cap.as_millis());
        let base = self.base.as_millis();
        let (low, high) = if exp <= base {
            (
                base,
                base.saturating_add(base / 4).min(self.cap.as_millis()),
            )
        } else {
            (exp.saturating_sub(exp / 4).max(base).min(exp), exp)
        };
        let span = high.saturating_sub(low);
        let raw = jitter.next_u64();
        // `span + 1` may overflow only for a u64::MAX cap; then use the raw value.
        let offset = span
            .checked_add(1)
            .and_then(|m| raw.checked_rem(m))
            .unwrap_or(raw);
        DurationMs::from_millis(low.saturating_add(offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// `SplitMix64`, seeded.
    struct Seeded(u64);
    impl JitterSource for Seeded {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    struct Fixed(u64);
    impl JitterSource for Fixed {
        fn next_u64(&mut self) -> u64 {
            self.0
        }
    }

    #[test]
    fn same_seed_gives_same_delays() {
        let run = |seed| {
            let mut s = Seeded(seed);
            (0..10)
                .map(|a| Backoff::DEFAULT.delay(a, &mut s))
                .collect::<Vec<_>>()
        };
        assert_eq!(run(7), run(7));
        assert_ne!(run(7), run(8));
    }

    #[test]
    fn zero_jitter_gives_the_lower_bound_and_max_jitter_the_exponential() {
        let b = Backoff::DEFAULT;
        // attempt 1: exp 4000, low 3000
        assert_eq!(b.delay(1, &mut Fixed(0)).as_millis(), 3000);
        assert!(b.delay(1, &mut Fixed(u64::MAX)).as_millis() <= 4000);
        // attempt 0 spreads over base..=base+25 %: 2000..=2500
        assert_eq!(b.delay(0, &mut Fixed(0)).as_millis(), 2000);
        assert_eq!(b.delay(0, &mut Fixed(500)).as_millis(), 2500);
        assert_eq!(b.delay(0, &mut Fixed(501)).as_millis(), 2000);
        assert_eq!(b.delay(0, &mut Fixed(12345)).as_millis(), 2321);
    }

    #[test]
    fn grows_then_caps_at_five_seconds() {
        let b = Backoff::DEFAULT;
        assert!(b.delay(2, &mut Fixed(u64::MAX)).as_millis() <= 5000);
        assert_eq!(b.delay(2, &mut Fixed(0)).as_millis(), 3750);
        assert_eq!(b.delay(u32::MAX, &mut Fixed(0)).as_millis(), 3750);
    }

    #[test]
    fn cap_below_base_is_raised_to_base() {
        let b = Backoff::new(DurationMs::from_secs(3), DurationMs::from_secs(1));
        assert_eq!(b.delay(5, &mut Fixed(99)).as_millis(), 3000);
    }

    #[test]
    fn zero_base_yields_zero_delay() {
        let b = Backoff::new(DurationMs::from_millis(0), DurationMs::from_millis(0));
        assert_eq!(b.delay(3, &mut Fixed(u64::MAX)).as_millis(), 0);
    }

    #[test]
    fn extreme_durations_do_not_overflow() {
        let max = DurationMs::from_millis(u64::MAX);
        let b = Backoff::new(max, max);
        let _ = b.delay(u32::MAX, &mut Fixed(u64::MAX));
    }

    proptest! {
        #[test]
        fn delay_stays_within_base_and_cap(
            base in 0u64..100_000, cap in 0u64..1_000_000, attempt in any::<u32>(), seed in any::<u64>()
        ) {
            let b = Backoff::new(DurationMs::from_millis(base), DurationMs::from_millis(cap));
            let d = b.delay(attempt, &mut Seeded(seed)).as_millis();
            prop_assert!(d >= base);
            prop_assert!(d <= cap.max(base));
        }
    }
}
