//! Per-camera connection state and its pure transition function.

use super::backoff::{Backoff, JitterSource};
use super::clock::{Duration, Timestamp};

/// Why a connection attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureKind {
    /// Connect or read timed out.
    Timeout,
    /// The peer refused or reset the connection.
    Refused,
    /// Credentials were rejected.
    Auth,
    /// The peer spoke something unexpected.
    Protocol,
    /// Anything else.
    Other,
}

/// What happened to a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A connection attempt succeeded.
    Connected,
    /// A connection attempt (or the live stream) failed.
    Failed(FailureKind),
    /// Time passed; carries the current time.
    Tick(Timestamp),
}

/// The retry policy: backoff shape and total budget before degrading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionPolicy {
    /// Delay between attempts.
    pub backoff: Backoff,
    /// Time since the first failure of an outage after which the camera is degraded.
    pub budget: Duration,
}

impl ConnectionPolicy {
    /// ADR 0002: 2-5 s backoff, three minute budget.
    pub const DEFAULT: Self = Self {
        backoff: Backoff::DEFAULT,
        budget: Duration::from_secs(180),
    };
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Where a camera connection is in its life cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionState {
    /// An attempt is in flight. `outage_start` is when the current outage began
    /// (`None` for the very first attempt); `attempt` counts failures so far.
    Connecting {
        /// Failures in this outage so far.
        attempt: u32,
        /// First failure of the outage, if any.
        outage_start: Option<Timestamp>,
    },
    /// Connected and receiving.
    Streaming,
    /// Waiting to retry after a failure.
    Backoff {
        /// Failures in this outage so far (at least 1).
        attempt: u32,
        /// Retry no earlier than this.
        until: Timestamp,
        /// First failure of the outage.
        outage_start: Timestamp,
    },
    /// The retry budget is spent. The adapter keeps retrying in the background
    /// (at the policy's capped backoff) and serves cached data meanwhile.
    Degraded {
        /// When the camera became degraded.
        since: Timestamp,
        /// The most recent failure.
        last_error_kind: FailureKind,
    },
}

impl ConnectionState {
    /// The state of a camera that has not tried to connect yet.
    pub const INITIAL: Self = Self::Connecting {
        attempt: 0,
        outage_start: None,
    };
}

/// Pure transition: the next state after `event`.
///
/// `now` is the time the event was observed (for `Tick` it equals the carried
/// value). Jitter for the backoff delay comes from `jitter`. A failure moves
/// to `Backoff` until the budget (measured from the outage's first failure)
/// is spent, then to `Degraded`; `Connected` always returns to `Streaming`.
pub fn transition(
    state: ConnectionState,
    event: Event,
    now: Timestamp,
    policy: &ConnectionPolicy,
    jitter: &mut impl JitterSource,
) -> ConnectionState {
    use ConnectionState::{Backoff, Connecting, Degraded, Streaming};
    match (state, event) {
        (_, Event::Connected) => Streaming,
        (Degraded { since, .. }, Event::Failed(kind)) => Degraded {
            since,
            last_error_kind: kind,
        },
        (Degraded { .. } | Streaming | Backoff { .. } | Connecting { .. }, Event::Tick(t)) => {
            tick(state, t)
        }
        // A failure while already waiting is stale (the attempt it belongs to is over).
        (Backoff { .. }, Event::Failed(_)) => state,
        (Streaming, Event::Failed(kind)) => fail(0, None, kind, now, policy, jitter),
        (
            Connecting {
                attempt,
                outage_start,
            },
            Event::Failed(kind),
        ) => fail(attempt, outage_start, kind, now, policy, jitter),
    }
}

fn fail(
    attempt: u32,
    outage_start: Option<Timestamp>,
    kind: FailureKind,
    now: Timestamp,
    policy: &ConnectionPolicy,
    jitter: &mut impl JitterSource,
) -> ConnectionState {
    let outage_start = outage_start.unwrap_or(now);
    if now.saturating_duration_since(outage_start) >= policy.budget {
        return ConnectionState::Degraded {
            since: now,
            last_error_kind: kind,
        };
    }
    let delay = policy.backoff.delay(attempt, jitter);
    ConnectionState::Backoff {
        attempt: attempt.saturating_add(1),
        until: now.saturating_add(delay),
        outage_start,
    }
}

fn tick(state: ConnectionState, now: Timestamp) -> ConnectionState {
    match state {
        ConnectionState::Backoff {
            attempt,
            until,
            outage_start,
        } => {
            if now >= until {
                ConnectionState::Connecting {
                    attempt,
                    outage_start: Some(outage_start),
                }
            } else {
                state
            }
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ConnectionState::{Backoff as Bo, Connecting, Degraded, Streaming};

    struct Fixed(u64);
    impl JitterSource for Fixed {
        fn next_u64(&mut self) -> u64 {
            self.0
        }
    }

    fn ts(ms: i64) -> Timestamp {
        Timestamp::from_unix_millis(1_700_000_000_000_i64.saturating_add(ms))
    }

    fn step(s: ConnectionState, e: Event, now: Timestamp) -> ConnectionState {
        transition(s, e, now, &ConnectionPolicy::DEFAULT, &mut Fixed(0))
    }

    #[test]
    fn first_failure_enters_backoff_with_outage_start() {
        let s = step(
            ConnectionState::INITIAL,
            Event::Failed(FailureKind::Timeout),
            ts(0),
        );
        assert_eq!(
            s,
            Bo {
                attempt: 1,
                until: ts(2000),
                outage_start: ts(0)
            }
        );
    }

    #[test]
    fn tick_before_until_keeps_waiting_and_after_reconnects() {
        let b = Bo {
            attempt: 1,
            until: ts(2000),
            outage_start: ts(0),
        };
        assert_eq!(step(b, Event::Tick(ts(1999)), ts(1999)), b);
        assert_eq!(
            step(b, Event::Tick(ts(2000)), ts(2000)),
            Connecting {
                attempt: 1,
                outage_start: Some(ts(0))
            }
        );
    }

    #[test]
    fn success_returns_to_streaming_from_every_state() {
        for s in [
            ConnectionState::INITIAL,
            Streaming,
            Bo {
                attempt: 3,
                until: ts(9),
                outage_start: ts(0),
            },
            Degraded {
                since: ts(5),
                last_error_kind: FailureKind::Auth,
            },
        ] {
            assert_eq!(step(s, Event::Connected, ts(10)), Streaming);
        }
    }

    #[test]
    fn failure_while_streaming_starts_a_new_outage() {
        let s = step(Streaming, Event::Failed(FailureKind::Refused), ts(500));
        assert_eq!(
            s,
            Bo {
                attempt: 1,
                until: ts(2500),
                outage_start: ts(500)
            }
        );
    }

    #[test]
    fn stale_failure_during_backoff_is_ignored() {
        let b = Bo {
            attempt: 2,
            until: ts(9000),
            outage_start: ts(0),
        };
        assert_eq!(step(b, Event::Failed(FailureKind::Timeout), ts(100)), b);
    }

    /// ADR 0002 worst case: 8 consecutive failures over ~130 s (about 16 s per
    /// failed attempt, plus the backoff). Not degraded before three minutes.
    #[test]
    fn eight_failures_over_130_s_are_not_degraded() {
        let mut s = ConnectionState::INITIAL;
        let mut t = 0;
        for _ in 0..8 {
            s = step(s, Event::Failed(FailureKind::Timeout), ts(t));
            assert!(!matches!(s, Degraded { .. }), "degraded at {t} ms");
            t += 18_500;
            // The backoff elapses and the next attempt starts.
            s = step(s, Event::Tick(ts(t)), ts(t));
            assert!(matches!(s, Connecting { .. }));
        }
        assert!((130_000..180_000).contains(&t));
    }

    #[test]
    fn degrades_once_the_three_minute_budget_is_spent() {
        let mut s = step(
            ConnectionState::INITIAL,
            Event::Failed(FailureKind::Timeout),
            ts(0),
        );
        // Just inside the budget: a failure at 179.999 s is still a backoff.
        s = step(s, Event::Tick(ts(179_000)), ts(179_000));
        assert!(matches!(s, Connecting { .. }));
        s = step(s, Event::Failed(FailureKind::Refused), ts(179_999));
        assert!(matches!(s, Bo { .. }));
        // The next attempt fails past 180 s: degraded.
        s = step(s, Event::Tick(ts(183_000)), ts(183_000));
        s = step(s, Event::Failed(FailureKind::Timeout), ts(183_000));
        assert_eq!(
            s,
            Degraded {
                since: ts(183_000),
                last_error_kind: FailureKind::Timeout
            }
        );
    }

    #[test]
    fn failure_at_the_budget_degrades_with_its_kind() {
        let c = Connecting {
            attempt: 9,
            outage_start: Some(ts(0)),
        };
        let s = step(c, Event::Failed(FailureKind::Auth), ts(180_000));
        assert_eq!(
            s,
            Degraded {
                since: ts(180_000),
                last_error_kind: FailureKind::Auth
            }
        );
    }

    #[test]
    fn degraded_keeps_since_and_updates_the_error_and_recovers() {
        let d = Degraded {
            since: ts(1),
            last_error_kind: FailureKind::Timeout,
        };
        assert_eq!(
            step(d, Event::Failed(FailureKind::Protocol), ts(50)),
            Degraded {
                since: ts(1),
                last_error_kind: FailureKind::Protocol
            }
        );
        assert_eq!(step(d, Event::Tick(ts(60)), ts(60)), d);
        assert_eq!(step(d, Event::Connected, ts(70)), Streaming);
    }

    #[test]
    fn clock_stepping_back_does_not_degrade_or_panic() {
        let b = Bo {
            attempt: 1,
            until: ts(2000),
            outage_start: ts(100_000),
        };
        assert_eq!(step(b, Event::Tick(ts(0)), ts(0)), b);
    }

    #[test]
    fn huge_attempt_counter_saturates() {
        let c = Connecting {
            attempt: u32::MAX,
            outage_start: Some(ts(0)),
        };
        let s = step(c, Event::Failed(FailureKind::Other), ts(10));
        assert!(matches!(
            s,
            Bo {
                attempt: u32::MAX,
                ..
            }
        ));
    }

    #[test]
    fn success_resets_the_outage() {
        let mut s = step(
            ConnectionState::INITIAL,
            Event::Failed(FailureKind::Timeout),
            ts(0),
        );
        s = step(s, Event::Connected, ts(1000));
        s = step(s, Event::Failed(FailureKind::Timeout), ts(170_000));
        assert_eq!(
            s,
            Bo {
                attempt: 1,
                until: ts(172_000),
                outage_start: ts(170_000)
            }
        );
    }
}
