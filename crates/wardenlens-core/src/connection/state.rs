//! Per-camera connection state and its pure transition function.
//!
//! # Clock
//!
//! The state machine runs on a **monotonic** clock ([`MonoMs`]), so there are
//! no clock steps to handle: time never goes backwards and an NTP or manual
//! wall-clock change cannot stall or shorten a retry. Wall-clock time
//! ([`crate::time::Timestamp`]) is for recording timestamps and reports only.
//!
//! # Adapter contract
//!
//! * Pass monotonic time, for example `std::time::Instant` measured from a
//!   process-wide origin, as the `now` of every [`transition`] call.
//! * Send an [`Event::Tick`] at least every `backoff.cap`. A coarser cadence
//!   only delays actions (retry, attempt timeout, degrading) by up to one tick
//!   period; it never stalls them and never prevents degrading.
//! * A `now` earlier than a time the state already stores is a contract
//!   violation. It is handled with saturating arithmetic (the elapsed time is
//!   zero), never panics and never stalls: a later, correct tick resolves it.
//! * **Stability.** A `Connected` only counts as recovery after the stream has
//!   stayed up for `min_stable`; see [`Outage`].

use super::backoff::{Backoff, JitterSource};
use crate::time::{DurationMs, MonoMs};

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

/// What happened to a connection. The time of the event is the `now` argument
/// of [`transition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A connection attempt succeeded.
    Connected,
    /// A connection attempt (or the live stream) failed.
    Failed(FailureKind),
    /// Time passed. Drives backoff expiry, attempt timeouts, background
    /// retries while degraded and the stability check.
    ///
    /// The adapter sends one at least every `backoff.cap`, with monotonic
    /// `now`. A `Tick` in `Connecting` at or after `attempt_started +
    /// connect_timeout` always fails the attempt, however late it arrives.
    Tick,
}

/// The retry policy: backoff shape, total budget, stability and attempt timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionPolicy {
    /// Delay between attempts.
    pub backoff: Backoff,
    /// Time since the first failure of an outage after which the camera is degraded.
    pub budget: DurationMs,
    /// How long a stream must stay up for a `Connected` to count as recovery.
    /// A drop sooner than this continues the previous outage.
    pub min_stable: DurationMs,
    /// How long one connection attempt may run; a `Tick` past it is a failure.
    pub connect_timeout: DurationMs,
}

impl ConnectionPolicy {
    /// ADR 0002: 2-5 s backoff, three minute budget, 10 s attempts, 30 s stability.
    pub const DEFAULT: Self = Self {
        backoff: Backoff::DEFAULT,
        budget: DurationMs::from_secs(180),
        min_stable: DurationMs::from_secs(30),
        connect_timeout: DurationMs::from_secs(10),
    };
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// An ongoing outage: the retry bookkeeping that survives until a connection
/// proves stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outage {
    /// Failures in this outage so far.
    pub attempt: u32,
    /// First failure of the outage.
    pub start: MonoMs,
    /// When the camera became degraded, if it has.
    pub degraded_since: Option<MonoMs>,
}

/// Where a camera connection is in its life cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionState {
    /// An attempt is in flight.
    Connecting {
        /// The outage being retried (`None` for the very first attempt).
        outage: Option<Outage>,
        /// When this attempt began; `None` until the first event tells us.
        attempt_started: Option<MonoMs>,
    },
    /// Connected and receiving.
    Streaming {
        /// When the stream came up.
        since: MonoMs,
        /// The outage this connection ended, kept until the stream has been up
        /// for `min_stable`; a drop before then continues it.
        prior: Option<Outage>,
    },
    /// Waiting to retry after a failure.
    Backoff {
        /// The outage in progress (`attempt >= 1`).
        outage: Outage,
        /// Retry no earlier than this.
        until: MonoMs,
    },
    /// The retry budget is spent. The state machine keeps scheduling retries,
    /// one per (jittered) backoff cap, and the adapter serves cached data meanwhile.
    Degraded {
        /// When the camera became degraded.
        since: MonoMs,
        /// The most recent failure.
        last_error_kind: FailureKind,
        /// The next background retry is due at this time.
        next_retry: MonoMs,
    },
}

impl ConnectionState {
    /// The state of a camera that has not tried to connect yet.
    pub const INITIAL: Self = Self::Connecting {
        outage: None,
        attempt_started: None,
    };
}

/// Pure transition: the next state after `event`, observed at monotonic `now`.
///
/// A failure moves to `Backoff` until the budget (measured from the outage's
/// first failure) is spent, then to `Degraded`. `Connected` moves to
/// `Streaming`, remembering the outage until the stream proves stable. Jitter
/// for backoff delays (including degraded background retries) comes from
/// `jitter`. See the module docs for the adapter contract.
pub fn transition(
    state: ConnectionState,
    event: Event,
    now: MonoMs,
    policy: &ConnectionPolicy,
    jitter: &mut impl JitterSource,
) -> ConnectionState {
    use ConnectionState::{Backoff, Connecting, Degraded, Streaming};
    match (state, event) {
        (Connecting { outage, .. }, Event::Connected) => streaming(now, outage),
        (Backoff { outage, .. }, Event::Connected) => streaming(now, Some(outage)),
        (Degraded { since, .. }, Event::Connected) => streaming(now, Some(degraded_outage(since))),
        (
            Degraded {
                since, next_retry, ..
            },
            Event::Failed(kind),
        ) => Degraded {
            since,
            last_error_kind: kind,
            next_retry,
        },
        // A duplicate `Connected`, or a failure while already waiting (stale: the
        // attempt it belongs to is over), changes nothing.
        (Streaming { .. }, Event::Connected) | (Backoff { .. }, Event::Failed(_)) => state,
        (Streaming { since, prior }, Event::Failed(kind)) => {
            let outage = if stable(since, now, policy) {
                None
            } else {
                prior
            };
            fail(outage, kind, now, policy, jitter)
        }
        (Connecting { outage, .. }, Event::Failed(kind)) => fail(outage, kind, now, policy, jitter),
        (_, Event::Tick) => tick(state, now, policy, jitter),
    }
}

fn streaming(now: MonoMs, prior: Option<Outage>) -> ConnectionState {
    ConnectionState::Streaming { since: now, prior }
}

fn degraded_outage(since: MonoMs) -> Outage {
    Outage {
        attempt: 0,
        start: since,
        degraded_since: Some(since),
    }
}

fn stable(since: MonoMs, now: MonoMs, policy: &ConnectionPolicy) -> bool {
    now.saturating_duration_since(since) >= policy.min_stable
}

/// The next background retry while degraded: the backoff at its cap, jittered.
fn degraded_retry(
    now: MonoMs,
    policy: &ConnectionPolicy,
    jitter: &mut impl JitterSource,
) -> MonoMs {
    now.saturating_add(policy.backoff.delay(u32::MAX, jitter))
}

fn fail(
    outage: Option<Outage>,
    kind: FailureKind,
    now: MonoMs,
    policy: &ConnectionPolicy,
    jitter: &mut impl JitterSource,
) -> ConnectionState {
    let o = outage.unwrap_or(Outage {
        attempt: 0,
        start: now,
        degraded_since: None,
    });
    if let Some(since) = o.degraded_since {
        return ConnectionState::Degraded {
            since,
            last_error_kind: kind,
            next_retry: degraded_retry(now, policy, jitter),
        };
    }
    if now.saturating_duration_since(o.start) >= policy.budget {
        return ConnectionState::Degraded {
            since: now,
            last_error_kind: kind,
            next_retry: degraded_retry(now, policy, jitter),
        };
    }
    let delay = policy.backoff.delay(o.attempt, jitter);
    ConnectionState::Backoff {
        outage: Outage {
            attempt: o.attempt.saturating_add(1),
            ..o
        },
        until: now.saturating_add(delay),
    }
}

fn tick(
    state: ConnectionState,
    now: MonoMs,
    policy: &ConnectionPolicy,
    jitter: &mut impl JitterSource,
) -> ConnectionState {
    use ConnectionState::{Backoff, Connecting, Degraded, Streaming};
    match state {
        Connecting {
            outage,
            attempt_started,
        } => match attempt_started {
            // First tick: anchor the attempt.
            None => Connecting {
                outage,
                attempt_started: Some(now),
            },
            Some(started) if now.saturating_duration_since(started) >= policy.connect_timeout => {
                fail(outage, FailureKind::Timeout, now, policy, jitter)
            }
            Some(_) => state,
        },
        Backoff { outage, until } => {
            if now >= until {
                Connecting {
                    outage: Some(outage),
                    attempt_started: Some(now),
                }
            } else {
                state
            }
        }
        Degraded {
            since, next_retry, ..
        } => {
            if now >= next_retry {
                Connecting {
                    outage: Some(degraded_outage(since)),
                    attempt_started: Some(now),
                }
            } else {
                state
            }
        }
        Streaming { since, prior } => {
            if prior.is_some() && stable(since, now, policy) {
                Streaming { since, prior: None }
            } else {
                state
            }
        }
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

    const ORIGIN: u64 = 1_000_000;

    fn rel(t: MonoMs) -> i64 {
        i64::try_from(t.as_millis().saturating_sub(ORIGIN)).unwrap_or(i64::MAX)
    }

    fn ts(ms: i64) -> MonoMs {
        MonoMs::from_millis(ORIGIN.saturating_add_signed(ms))
    }

    fn step(s: ConnectionState, e: Event, now: MonoMs) -> ConnectionState {
        transition(s, e, now, &ConnectionPolicy::DEFAULT, &mut Fixed(0))
    }

    fn outage(attempt: u32, start: i64) -> Outage {
        Outage {
            attempt,
            start: ts(start),
            degraded_since: None,
        }
    }

    fn up(since: i64) -> ConnectionState {
        Streaming {
            since: ts(since),
            prior: None,
        }
    }

    const FAIL: Event = Event::Failed(FailureKind::Timeout);

    #[test]
    fn first_failure_enters_backoff_with_outage_start() {
        let s = step(ConnectionState::INITIAL, FAIL, ts(0));
        assert_eq!(
            s,
            Bo {
                outage: outage(1, 0),
                until: ts(2000)
            }
        );
    }

    #[test]
    fn tick_before_until_keeps_waiting_and_after_reconnects() {
        let b = Bo {
            outage: outage(1, 0),
            until: ts(2000),
        };
        assert_eq!(step(b, Event::Tick, ts(1999)), b);
        assert_eq!(
            step(b, Event::Tick, ts(2000)),
            Connecting {
                outage: Some(outage(1, 0)),
                attempt_started: Some(ts(2000))
            }
        );
    }

    #[test]
    fn success_returns_to_streaming_from_every_state() {
        for s in [
            ConnectionState::INITIAL,
            Bo {
                outage: outage(3, 0),
                until: ts(9),
            },
            Degraded {
                since: ts(5),
                last_error_kind: FailureKind::Auth,
                next_retry: ts(5005),
            },
        ] {
            assert!(matches!(
                step(s, Event::Connected, ts(10)),
                Streaming { since, .. } if since == ts(10)
            ));
        }
    }

    #[test]
    fn duplicate_connected_keeps_the_stream_anchor() {
        assert_eq!(step(up(0), Event::Connected, ts(10)), up(0));
    }

    #[test]
    fn failure_while_streaming_starts_a_new_outage() {
        let s = step(up(0), Event::Failed(FailureKind::Refused), ts(500));
        // Not stable for 30 s, but there was no prior outage: this one starts now.
        assert_eq!(
            s,
            Bo {
                outage: outage(1, 500),
                until: ts(2500)
            }
        );
    }

    #[test]
    fn stale_failure_during_backoff_is_ignored() {
        let b = Bo {
            outage: outage(2, 0),
            until: ts(9000),
        };
        assert_eq!(step(b, FAIL, ts(100)), b);
    }

    /// ADR 0002 worst case with realistic timings: every attempt runs to the 10 s
    /// timeout, then backs off. At least 8 failures happen before the budget is
    /// spent, and the first failure at or after 180 s is the one that degrades.
    #[test]
    fn first_failure_at_or_after_the_budget_degrades() {
        let mut s = ConnectionState::INITIAL;
        let mut t = 10_000; // first attempt times out
        let first = t;
        let mut failures = 0;
        loop {
            s = step(s, FAIL, ts(t));
            failures += 1;
            let elapsed = t - first;
            if elapsed >= 180_000 {
                assert!(matches!(s, Degraded { .. }), "not degraded at {elapsed} ms");
                break;
            }
            assert!(
                !matches!(s, Degraded { .. }),
                "degraded early at {elapsed} ms"
            );
            let Bo { until, .. } = s else {
                unreachable!("{s:?}")
            };
            let resume = rel(until);
            s = step(s, Event::Tick, ts(resume));
            assert!(matches!(s, Connecting { .. }));
            t = resume + 10_000;
        }
        assert!(failures > 8, "only {failures} failures");
    }

    #[test]
    fn degrades_exactly_at_the_budget() {
        let c = |started| Connecting {
            outage: Some(outage(9, 0)),
            attempt_started: Some(ts(started)),
        };
        assert!(matches!(step(c(175_000), FAIL, ts(179_999)), Bo { .. }));
        assert_eq!(
            step(c(175_000), Event::Failed(FailureKind::Auth), ts(180_000)),
            Degraded {
                since: ts(180_000),
                last_error_kind: FailureKind::Auth,
                next_retry: ts(183_750)
            }
        );
    }

    #[test]
    fn degraded_keeps_since_updates_the_error_and_recovers() {
        let d = Degraded {
            since: ts(1),
            last_error_kind: FailureKind::Timeout,
            next_retry: ts(5001),
        };
        assert_eq!(
            step(d, Event::Failed(FailureKind::Protocol), ts(50)),
            Degraded {
                since: ts(1),
                last_error_kind: FailureKind::Protocol,
                next_retry: ts(5001)
            }
        );
        assert_eq!(step(d, Event::Tick, ts(60)), d);
        assert!(matches!(
            step(d, Event::Connected, ts(70)),
            Streaming { .. }
        ));
    }

    #[test]
    fn degraded_retries_in_the_background_paced_at_the_cap() {
        let mut s = Degraded {
            since: ts(0),
            last_error_kind: FailureKind::Timeout,
            next_retry: ts(5000),
        };
        s = step(s, Event::Tick, ts(4999));
        assert!(matches!(s, Degraded { .. }));
        s = step(s, Event::Tick, ts(5000));
        assert!(matches!(s, Connecting { .. }));
        // The retry fails: still degraded since the original time, next try one cap later.
        s = step(s, Event::Failed(FailureKind::Refused), ts(6000));
        assert_eq!(
            s,
            Degraded {
                since: ts(0),
                last_error_kind: FailureKind::Refused,
                next_retry: ts(9750)
            }
        );
    }

    #[test]
    fn hung_attempt_times_out_on_tick() {
        let c = Connecting {
            outage: None,
            attempt_started: Some(ts(0)),
        };
        assert_eq!(step(c, Event::Tick, ts(9_999)), c);
        assert_eq!(
            step(c, Event::Tick, ts(10_000)),
            Bo {
                outage: outage(1, 10_000),
                until: ts(12_000)
            }
        );
    }

    #[test]
    fn first_tick_anchors_the_attempt() {
        assert_eq!(
            step(ConnectionState::INITIAL, Event::Tick, ts(7)),
            Connecting {
                outage: None,
                attempt_started: Some(ts(7))
            }
        );
    }

    #[test]
    fn stale_now_does_not_panic_or_stall() {
        // A contract violation: `now` is earlier than the stored times.
        let b = Bo {
            outage: outage(1, 100_000),
            until: ts(102_000),
        };
        assert_eq!(step(b, Event::Tick, ts(0)), b);
        assert!(matches!(
            step(b, Event::Tick, ts(102_000)),
            Connecting { .. }
        ));
        let c = Connecting {
            outage: Some(outage(1, 100_000)),
            attempt_started: Some(ts(100_000)),
        };
        assert_eq!(step(c, Event::Tick, ts(0)), c);
        assert!(matches!(step(c, FAIL, ts(0)), Bo { .. }));
        assert!(matches!(step(c, Event::Tick, ts(110_000)), Bo { .. }));
        assert_eq!(step(up(100), Event::Tick, ts(0)), up(100));
    }

    #[test]
    fn late_tick_always_times_out_the_attempt() {
        let c = Connecting {
            outage: Some(outage(3, 0)),
            attempt_started: Some(ts(1000)),
        };
        for late in [11_000, 25_000, 100_000] {
            assert!(
                matches!(step(c, Event::Tick, ts(late)), Bo { .. }),
                "{late}"
            );
        }
        // Past the budget it degrades however late the tick is.
        assert!(matches!(step(c, Event::Tick, ts(200_000)), Degraded { .. }));
    }

    #[test]
    fn degraded_retries_are_jittered() {
        let d = |n| {
            let c = Connecting {
                outage: Some(degraded_outage(ts(0))),
                attempt_started: Some(ts(0)),
            };
            transition(
                c,
                Event::Failed(FailureKind::Timeout),
                ts(1000),
                &ConnectionPolicy::DEFAULT,
                &mut Fixed(n),
            )
        };
        assert_ne!(d(0), d(1));
        assert!(matches!(d(0), Degraded { next_retry, .. } if next_retry == ts(4750)));
    }

    #[test]
    fn huge_attempt_counter_saturates() {
        let c = Connecting {
            outage: Some(outage(u32::MAX, 0)),
            attempt_started: None,
        };
        let s = step(c, Event::Failed(FailureKind::Other), ts(10));
        assert!(matches!(s, Bo { outage, .. } if outage.attempt == u32::MAX));
    }

    #[test]
    fn success_resets_the_outage_once_stable() {
        let mut s = step(ConnectionState::INITIAL, FAIL, ts(0));
        s = step(s, Event::Connected, ts(1000));
        s = step(s, FAIL, ts(170_000));
        assert_eq!(
            s,
            Bo {
                outage: outage(1, 170_000),
                until: ts(172_000)
            }
        );
    }

    #[test]
    fn stable_stream_drops_the_prior_outage_on_tick() {
        let mut s = step(ConnectionState::INITIAL, FAIL, ts(0));
        s = step(s, Event::Connected, ts(1000));
        assert!(matches!(s, Streaming { prior: Some(_), .. }));
        s = step(s, Event::Tick, ts(30_999));
        assert!(matches!(s, Streaming { prior: Some(_), .. }));
        s = step(s, Event::Tick, ts(31_000));
        assert_eq!(s, up(1000));
    }

    /// A camera that connects and drops at once keeps its outage and attempts,
    /// so it eventually degrades instead of flapping forever.
    #[test]
    fn flapping_camera_eventually_degrades() {
        let mut s = step(ConnectionState::INITIAL, FAIL, ts(0));
        let mut t = 0;
        let mut last_attempt = 0;
        for _ in 0..200 {
            let Bo { outage: o, until } = s else {
                break;
            };
            assert!(o.attempt > last_attempt);
            last_attempt = o.attempt;
            t = rel(until);
            s = step(s, Event::Tick, ts(t));
            s = step(s, Event::Connected, ts(t));
            t += 1000; // up for one second, then it drops
            s = step(s, FAIL, ts(t));
        }
        assert!(matches!(s, Degraded { .. }), "{s:?}");
        assert!(t >= 180_000);
    }

    #[test]
    fn degraded_camera_that_flaps_stays_degraded() {
        let d = Degraded {
            since: ts(0),
            last_error_kind: FailureKind::Timeout,
            next_retry: ts(5000),
        };
        let s = step(d, Event::Connected, ts(6000));
        let s = step(s, FAIL, ts(7000));
        assert!(matches!(s, Degraded { since, .. } if since == ts(0)));
    }
}
