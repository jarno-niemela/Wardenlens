//! The clock traits and the time newtypes.
//!
//! Two clocks, used for different things:
//!
//! * **Wall clock** ([`Clock`], [`Timestamp`], [`UnixMs`]): UTC Unix
//!   milliseconds (ADR 0005). It can step. Used for recording `started_at_ms`
//!   and for reports, never for deadlines.
//! * **Monotonic clock** ([`MonotonicClock`], [`MonoMs`]): never goes backwards.
//!   Used by the connection state machine for every timeout and deadline.

use core::fmt;

/// Earliest accepted wall-clock value: 2000-01-01T00:00:00Z in Unix ms (ADR 0005).
const MIN_WALL_CLOCK_MS: i64 = 946_684_800_000;
/// Latest accepted wall-clock value: 2099-12-31T23:59:59.999Z in Unix ms (ADR 0005).
const MAX_WALL_CLOCK_MS: i64 = 4_102_444_799_999;

/// A span of time in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DurationMs(u64);

impl DurationMs {
    /// A duration of `ms` milliseconds.
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// A duration of `secs` seconds, saturating at the maximum.
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1000))
    }

    /// The length in milliseconds.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// The sum of two durations, saturating at the maximum.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }
}

/// A point in time: UTC Unix milliseconds (ADR 0005).
///
/// Any `i64` is representable (clocks can be wrong). To prove a value is a
/// plausible recording time, convert it to [`UnixMs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// A timestamp from UTC Unix milliseconds.
    pub const fn from_unix_millis(ms: i64) -> Self {
        Self(ms)
    }

    /// UTC Unix milliseconds.
    pub const fn as_unix_millis(self) -> i64 {
        self.0
    }

    /// This timestamp plus `d`, saturating at the maximum.
    #[must_use]
    pub fn saturating_add(self, d: DurationMs) -> Self {
        let ms = i64::try_from(d.0).unwrap_or(i64::MAX);
        Self(self.0.saturating_add(ms))
    }

    /// Time elapsed since `earlier`; zero if `earlier` is not earlier.
    pub fn saturating_duration_since(self, earlier: Self) -> DurationMs {
        if self.0 >= earlier.0 {
            DurationMs(self.0.abs_diff(earlier.0))
        } else {
            DurationMs(0)
        }
    }
}

/// A point on a monotonic clock: milliseconds since an arbitrary origin (for
/// example process start) that never goes backwards. Meaningless as a date; use
/// [`Timestamp`] for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoMs(u64);

impl MonoMs {
    /// A monotonic instant `ms` milliseconds after the origin.
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Milliseconds since the origin.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// This instant plus `d`, saturating at the maximum.
    #[must_use]
    pub const fn saturating_add(self, d: DurationMs) -> Self {
        Self(self.0.saturating_add(d.0))
    }

    /// Time elapsed since `earlier`; zero if `earlier` is not earlier.
    pub const fn saturating_duration_since(self, earlier: Self) -> DurationMs {
        DurationMs(self.0.saturating_sub(earlier.0))
    }
}

/// A wall-clock instant proven to lie within 2000-01-01..=2099-12-31 UTC
/// (ADR 0005), in Unix milliseconds.
///
/// The only ways to build one are [`UnixMs::new`] and `TryFrom<Timestamp>`, so
/// holding a `UnixMs` is proof of the bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixMs(i64);

impl UnixMs {
    /// A bounded instant from Unix milliseconds.
    ///
    /// # Errors
    /// [`WallClockError::TooEarly`] before the year 2000 and
    /// [`WallClockError::TooLate`] after the year 2099. The recorder holds off
    /// recording on either.
    pub const fn new(ms: i64) -> Result<Self, WallClockError> {
        if ms < MIN_WALL_CLOCK_MS {
            Err(WallClockError::TooEarly(ms))
        } else if ms > MAX_WALL_CLOCK_MS {
            Err(WallClockError::TooLate(ms))
        } else {
            Ok(Self(ms))
        }
    }

    /// The value in Unix milliseconds, always within the accepted window.
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

impl TryFrom<Timestamp> for UnixMs {
    type Error = WallClockError;

    fn try_from(t: Timestamp) -> Result<Self, Self::Error> {
        Self::new(t.0)
    }
}

impl From<UnixMs> for Timestamp {
    fn from(u: UnixMs) -> Self {
        Self(u.0)
    }
}

impl fmt::Display for UnixMs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ms", self.0)
    }
}

/// A wall-clock value outside 2000..=2099 UTC; carries the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WallClockError {
    /// Before 2000-01-01T00:00:00Z.
    TooEarly(i64),
    /// After 2099-12-31T23:59:59.999Z.
    TooLate(i64),
}

impl fmt::Display for WallClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooEarly(ms) => write!(f, "wall clock {ms} ms is before the year 2000"),
            Self::TooLate(ms) => write!(f, "wall clock {ms} ms is after the year 2099"),
        }
    }
}

impl core::error::Error for WallClockError {}

/// A source of the current wall-clock time. Adapters implement it with the
/// real clock; tests use fakes.
pub trait Clock {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// A source of monotonic time. Adapters implement it (for example from
/// `std::time::Instant` relative to a process origin); tests use fakes.
pub trait MonotonicClock {
    /// The current monotonic time.
    fn now(&self) -> MonoMs;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use proptest::prelude::*;

    struct FakeClock(Cell<i64>);
    impl Clock for FakeClock {
        fn now(&self) -> Timestamp {
            Timestamp::from_unix_millis(self.0.get())
        }
    }

    #[test]
    fn fake_clock_reports_its_value() {
        let c = FakeClock(Cell::new(1_700_000_000_000));
        assert_eq!(c.now().as_unix_millis(), 1_700_000_000_000);
        c.0.set(5);
        assert_eq!(c.now().as_unix_millis(), 5);
    }

    #[test]
    fn unix_ms_accepts_exact_bounds() {
        assert_eq!(
            UnixMs::new(946_684_800_000).map(UnixMs::as_i64),
            Ok(946_684_800_000)
        );
        assert_eq!(
            UnixMs::try_from(Timestamp::from_unix_millis(4_102_444_799_999)).map(UnixMs::as_i64),
            Ok(4_102_444_799_999)
        );
    }

    #[test]
    fn unix_ms_rejects_just_outside_bounds() {
        assert_eq!(
            UnixMs::new(946_684_799_999),
            Err(WallClockError::TooEarly(946_684_799_999))
        );
        assert_eq!(
            UnixMs::new(4_102_444_800_000),
            Err(WallClockError::TooLate(4_102_444_800_000))
        );
        assert!(UnixMs::new(i64::MIN).is_err());
        assert!(UnixMs::new(i64::MAX).is_err());
        assert!(UnixMs::new(-1).is_err());
        assert!(UnixMs::new(0).is_err());
        assert!(UnixMs::try_from(Timestamp::from_unix_millis(0)).is_err());
    }

    #[test]
    fn unix_ms_orders_and_displays() {
        let a = UnixMs::new(1_700_000_000_000);
        let b = UnixMs::new(1_700_000_000_001);
        assert!(matches!((a, b), (Ok(a), Ok(b)) if a < b));
        assert_eq!(a.map(|u| u.to_string()), Ok("1700000000000 ms".to_owned()));
        assert_eq!(
            a.map(Timestamp::from),
            Ok(Timestamp::from_unix_millis(1_700_000_000_000))
        );
    }

    #[test]
    fn error_message_is_lowercase_without_punctuation() {
        let msg = WallClockError::TooEarly(0).to_string();
        assert!(msg.starts_with("wall clock"));
        assert!(!msg.ends_with('.'));
    }

    #[test]
    fn add_saturates_instead_of_overflowing() {
        let t = Timestamp::from_unix_millis(i64::MAX - 1);
        assert_eq!(
            t.saturating_add(DurationMs::from_millis(u64::MAX))
                .as_unix_millis(),
            i64::MAX
        );
        assert_eq!(DurationMs::from_secs(u64::MAX).as_millis(), u64::MAX);
        assert_eq!(
            DurationMs::from_millis(u64::MAX)
                .saturating_add(DurationMs::from_millis(1))
                .as_millis(),
            u64::MAX
        );
    }

    #[test]
    fn mono_ms_arithmetic_saturates() {
        let a = MonoMs::from_millis(10);
        let b = MonoMs::from_millis(25);
        assert_eq!(b.saturating_duration_since(a), DurationMs::from_millis(15));
        assert_eq!(a.saturating_duration_since(b), DurationMs::from_millis(0));
        assert_eq!(
            MonoMs::from_millis(u64::MAX)
                .saturating_add(DurationMs::from_millis(1))
                .as_millis(),
            u64::MAX
        );
        assert!(a < b);
    }

    struct FakeMono(Cell<u64>);
    impl MonotonicClock for FakeMono {
        fn now(&self) -> MonoMs {
            MonoMs::from_millis(self.0.get())
        }
    }

    #[test]
    fn fake_monotonic_clock_reports_its_value() {
        let c = FakeMono(Cell::new(3));
        assert_eq!(c.now().as_millis(), 3);
    }

    #[test]
    fn duration_since_is_zero_when_going_backwards() {
        let a = Timestamp::from_unix_millis(10);
        let b = Timestamp::from_unix_millis(25);
        assert_eq!(b.saturating_duration_since(a), DurationMs::from_millis(15));
        assert_eq!(a.saturating_duration_since(b), DurationMs::from_millis(0));
    }

    #[test]
    fn duration_since_spans_the_full_i64_range_exactly() {
        let min = Timestamp::from_unix_millis(i64::MIN);
        let max = Timestamp::from_unix_millis(i64::MAX);
        assert_eq!(max.saturating_duration_since(min).as_millis(), u64::MAX);
        assert_eq!(min.saturating_duration_since(max).as_millis(), 0);
    }

    proptest! {
        #[test]
        fn add_then_since_round_trips(t in -1_000_000_000_000i64..5_000_000_000_000, d in 0u64..1_000_000_000) {
            let start = Timestamp::from_unix_millis(t);
            let end = start.saturating_add(DurationMs::from_millis(d));
            prop_assert_eq!(end.saturating_duration_since(start).as_millis(), d);
        }

        #[test]
        fn unix_ms_matches_bounds(ms in any::<i64>()) {
            prop_assert_eq!(
                UnixMs::new(ms).is_ok(),
                (946_684_800_000..=4_102_444_799_999).contains(&ms)
            );
        }
    }
}
