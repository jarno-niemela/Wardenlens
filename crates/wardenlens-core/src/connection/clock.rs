//! The `Clock` trait and the time newtypes (ADR 0005: UTC Unix milliseconds).

use core::fmt;

/// Earliest accepted wall-clock value: 2000-01-01T00:00:00Z in Unix ms (ADR 0005).
const MIN_WALL_CLOCK_MS: i64 = 946_684_800_000;
/// Latest accepted wall-clock value: 2099-12-31T23:59:59.999Z in Unix ms (ADR 0005).
const MAX_WALL_CLOCK_MS: i64 = 4_102_444_799_999;

/// A span of time in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration(u64);

impl Duration {
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
}

/// A point in time: UTC Unix milliseconds (ADR 0005).
///
/// Any `i64` is representable; range checking against the recorder's accepted
/// window is done explicitly by [`Timestamp::check_wall_clock`].
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

    #[must_use]
    /// This timestamp plus `d`, saturating at the maximum.
    pub fn saturating_add(self, d: Duration) -> Self {
        let ms = i64::try_from(d.0).unwrap_or(i64::MAX);
        Self(self.0.saturating_add(ms))
    }

    /// Time elapsed since `earlier`; zero if `earlier` is not earlier.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        let diff = self.0.saturating_sub(earlier.0);
        Duration(u64::try_from(diff).unwrap_or(0))
    }

    /// Checks that this value is a plausible recording wall clock.
    ///
    /// # Errors
    /// [`WallClockError::TooEarly`] before the year 2000 and
    /// [`WallClockError::TooLate`] after the year 2099. The recorder holds off
    /// recording on either.
    pub fn check_wall_clock(self) -> Result<Self, WallClockError> {
        if self.0 < MIN_WALL_CLOCK_MS {
            Err(WallClockError::TooEarly(self))
        } else if self.0 > MAX_WALL_CLOCK_MS {
            Err(WallClockError::TooLate(self))
        } else {
            Ok(self)
        }
    }
}

/// A wall-clock value outside 2000..=2099 UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WallClockError {
    /// Before 2000-01-01T00:00:00Z.
    TooEarly(Timestamp),
    /// After 2099-12-31T23:59:59.999Z.
    TooLate(Timestamp),
}

impl fmt::Display for WallClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooEarly(t) => write!(f, "wall clock {} ms is before the year 2000", t.0),
            Self::TooLate(t) => write!(f, "wall clock {} ms is after the year 2099", t.0),
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
    fn accepts_exact_wall_clock_bounds() {
        assert!(
            Timestamp::from_unix_millis(946_684_800_000)
                .check_wall_clock()
                .is_ok()
        );
        assert!(
            Timestamp::from_unix_millis(4_102_444_799_999)
                .check_wall_clock()
                .is_ok()
        );
    }

    #[test]
    fn rejects_wall_clock_just_outside_bounds() {
        let early = Timestamp::from_unix_millis(946_684_799_999);
        let late = Timestamp::from_unix_millis(4_102_444_800_000);
        assert_eq!(
            early.check_wall_clock(),
            Err(WallClockError::TooEarly(early))
        );
        assert_eq!(late.check_wall_clock(), Err(WallClockError::TooLate(late)));
        assert!(
            Timestamp::from_unix_millis(i64::MIN)
                .check_wall_clock()
                .is_err()
        );
        assert!(Timestamp::from_unix_millis(-1).check_wall_clock().is_err());
        assert!(Timestamp::from_unix_millis(0).check_wall_clock().is_err());
    }

    #[test]
    fn error_message_is_lowercase_without_punctuation() {
        let msg = WallClockError::TooEarly(Timestamp::from_unix_millis(0)).to_string();
        assert!(msg.starts_with("wall clock"));
        assert!(!msg.ends_with('.'));
    }

    #[test]
    fn add_saturates_instead_of_overflowing() {
        let t = Timestamp::from_unix_millis(i64::MAX - 1);
        assert_eq!(
            t.saturating_add(Duration::from_millis(u64::MAX))
                .as_unix_millis(),
            i64::MAX
        );
        assert_eq!(Duration::from_secs(u64::MAX).as_millis(), u64::MAX);
    }

    #[test]
    fn duration_since_is_zero_when_going_backwards() {
        let a = Timestamp::from_unix_millis(10);
        let b = Timestamp::from_unix_millis(25);
        assert_eq!(b.saturating_duration_since(a), Duration::from_millis(15));
        assert_eq!(a.saturating_duration_since(b), Duration::from_millis(0));
        let extreme = Timestamp::from_unix_millis(i64::MIN);
        assert_eq!(
            Timestamp::from_unix_millis(i64::MAX)
                .saturating_duration_since(extreme)
                .as_millis(),
            u64::MAX >> 1
        );
    }

    proptest! {
        #[test]
        fn add_then_since_round_trips(t in -1_000_000_000_000i64..5_000_000_000_000, d in 0u64..1_000_000_000) {
            let start = Timestamp::from_unix_millis(t);
            let end = start.saturating_add(Duration::from_millis(d));
            prop_assert_eq!(end.saturating_duration_since(start).as_millis(), d);
        }

        #[test]
        fn wall_clock_check_matches_bounds(ms in any::<i64>()) {
            let ok = Timestamp::from_unix_millis(ms).check_wall_clock().is_ok();
            prop_assert_eq!(ok, (946_684_800_000..=4_102_444_799_999).contains(&ms));
        }
    }
}
