//! Per-camera connection state and its pure transition function.
//!
//! # Clock steps
//!
//! Time is a wall clock (ADR 0005), so it can step. The state machine treats
//! every event time as untrusted and applies three rules:
//!
//! * **Backward step.** A wait whose deadline is further away than the backoff
//!   cap (`until - now > cap`) can only be the result of the clock going back;
//!   the wait counts as elapsed. An outage that appears to start in the future
//!   (`outage_start > now`) restarts at `now`. A streaming or attempt anchor in
//!   the future is re-anchored at `now`.
//! * **Forward step.** The gap between consecutive events of one cycle is
//!   bounded by `backoff cap + connect_timeout` (the *max gap*): a backoff
//!   expires within `cap` and an attempt ends within `connect_timeout`. A
//!   larger gap is a forward step (or a stalled adapter); the gap is not
//!   counted against the budget and the outage clock restarts at `now`.
//! * **Stability.** A `Connected` only counts as recovery after the stream has
//!   stayed up for `min_stable`; see [`Outage`].

use super::backoff::{Backoff, JitterSource};
use crate::time::{DurationMs, Timestamp};

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

    /// The longest legitimate gap between two events of one retry cycle.
    fn max_gap(&self) -> DurationMs {
        self.backoff.cap().saturating_add(self.connect_timeout)
    }
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
    pub start: Timestamp,
    /// When the camera became degraded, if it has.
    pub degraded_since: Option<Timestamp>,
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
        attempt_started: Option<Timestamp>,
    },
    /// Connected and receiving.
    Streaming {
        /// When the stream came up.
        since: Timestamp,
        /// The outage this connection ended, kept until the stream has been up
        /// for `min_stable`; a drop before then continues it.
        prior: Option<Outage>,
    },
    /// Waiting to retry after a failure.
    Backoff {
        /// The outage in progress (`attempt >= 1`).
        outage: Outage,
        /// Retry no earlier than this.
        until: Timestamp,
    },
    /// The retry budget is spent. The state machine keeps scheduling retries,
    /// one per backoff cap, and the adapter serves cached data meanwhile.
    Degraded {
        /// When the camera became degraded.
        since: Timestamp,
        /// The most recent failure.
        last_error_kind: FailureKind,
        /// The next background retry is due at this time.
        next_retry: Timestamp,
    },
}

impl ConnectionState {
    /// The state of a camera that has not tried to connect yet.
    pub const INITIAL: Self = Self::Connecting {
        outage: None,
        attempt_started: None,
    };
}

/// Pure transition: the next state after `event`, observed at `now`.
///
/// A failure moves to `Backoff` until the budget (measured from the outage's
/// first failure) is spent, then to `Degraded`. `Connected` moves to
/// `Streaming`, remembering the outage until the stream proves stable. Jitter
/// for the backoff delay comes from `jitter`. See the module docs for how
/// clock steps are handled.
pub fn transition(
    state: ConnectionState,
    event: Event,
    now: Timestamp,
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
            fail(outage, None, kind, now, policy, jitter)
        }
        (
            Connecting {
                outage,
                attempt_started,
            },
            Event::Failed(kind),
        ) => fail(outage, attempt_started, kind, now, policy, jitter),
        (_, Event::Tick) => tick(state, now, policy, jitter),
    }
}

fn streaming(now: Timestamp, prior: Option<Outage>) -> ConnectionState {
    ConnectionState::Streaming { since: now, prior }
}

fn degraded_outage(since: Timestamp) -> Outage {
    Outage {
        attempt: 0,
        start: since,
        degraded_since: Some(since),
    }
}

fn stable(since: Timestamp, now: Timestamp, policy: &ConnectionPolicy) -> bool {
    now.saturating_duration_since(since) >= policy.min_stable
}

fn fail(
    outage: Option<Outage>,
    attempt_started: Option<Timestamp>,
    kind: FailureKind,
    now: Timestamp,
    policy: &ConnectionPolicy,
    jitter: &mut impl JitterSource,
) -> ConnectionState {
    let mut o = outage.unwrap_or(Outage {
        attempt: 0,
        start: now,
        degraded_since: None,
    });
    let stepped_forward =
        attempt_started.is_some_and(|s| now.saturating_duration_since(s) > policy.max_gap());
    if now < o.start || stepped_forward {
        o.start = now;
    }
    let paced = now.saturating_add(policy.backoff.cap());
    if let Some(since) = o.degraded_since {
        return ConnectionState::Degraded {
            since,
            last_error_kind: kind,
            next_retry: paced,
        };
    }
    if now.saturating_duration_since(o.start) >= policy.budget {
        return ConnectionState::Degraded {
            since: now,
            last_error_kind: kind,
            next_retry: paced,
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
    now: Timestamp,
    policy: &ConnectionPolicy,
    jitter: &mut impl JitterSource,
) -> ConnectionState {
    use ConnectionState::{Backoff, Connecting, Degraded, Streaming};
    match state {
        Connecting {
            outage,
            attempt_started,
        } => {
            let outage = outage.map(|o| clamp_start(o, now));
            let Some(started) = attempt_started.filter(|s| *s <= now) else {
                // First tick, or the clock went back: (re)anchor the attempt.
                return Connecting {
                    outage,
                    attempt_started: Some(now),
                };
            };
            let elapsed = now.saturating_duration_since(started);
            if elapsed > policy.max_gap() {
                // Forward step: fresh outage clock, fresh attempt.
                Connecting {
                    outage: outage.map(|o| Outage { start: now, ..o }),
                    attempt_started: Some(now),
                }
            } else if elapsed >= policy.connect_timeout {
                fail(
                    outage,
                    Some(started),
                    FailureKind::Timeout,
                    now,
                    policy,
                    jitter,
                )
            } else {
                Connecting {
                    outage,
                    attempt_started,
                }
            }
        }
        Backoff { outage, until } => {
            let mut outage = clamp_start(outage, now);
            let went_back = until.saturating_duration_since(now) > policy.backoff.cap();
            if now >= until || went_back {
                if now.saturating_duration_since(until) > policy.max_gap() {
                    outage.start = now;
                }
                Connecting {
                    outage: Some(outage),
                    attempt_started: Some(now),
                }
            } else {
                Backoff { outage, until }
            }
        }
        Degraded {
            since, next_retry, ..
        } => {
            let went_back = next_retry.saturating_duration_since(now) > policy.backoff.cap();
            if now >= next_retry || went_back {
                Connecting {
                    outage: Some(degraded_outage(since)),
                    attempt_started: Some(now),
                }
            } else {
                state
            }
        }
        Streaming { since, prior } => {
            if now < since {
                Streaming { since: now, prior }
            } else if prior.is_some() && stable(since, now, policy) {
                Streaming { since, prior: None }
            } else {
                state
            }
        }
    }
}

/// An outage cannot have started after `now`: if it appears to, the clock went back.
fn clamp_start(o: Outage, now: Timestamp) -> Outage {
    if o.start > now {
        Outage { start: now, ..o }
    } else {
        o
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
            let resume = until.as_unix_millis() - 1_700_000_000_000;
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
                next_retry: ts(185_000)
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
                next_retry: ts(11_000)
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
    fn backward_step_in_backoff_retries_without_stalling() {
        let b = Bo {
            outage: outage(1, 100_000),
            until: ts(102_000),
        };
        // The clock jumps back an hour; the very next tick retries and the outage restarts.
        let now = ts(-3_500_000);
        assert_eq!(
            step(b, Event::Tick, now),
            Connecting {
                outage: Some(outage(1, -3_500_000)),
                attempt_started: Some(now)
            }
        );
    }

    #[test]
    fn small_backward_step_clamps_the_outage_start_and_keeps_waiting() {
        let b = Bo {
            outage: outage(1, 100_000),
            until: ts(3000),
        };
        assert_eq!(
            step(b, Event::Tick, ts(0)),
            Bo {
                outage: outage(1, 0),
                until: ts(3000)
            }
        );
    }

    #[test]
    fn backward_step_while_degraded_retries() {
        let d = Degraded {
            since: ts(0),
            last_error_kind: FailureKind::Timeout,
            next_retry: ts(1_000_000),
        };
        assert!(matches!(step(d, Event::Tick, ts(10)), Connecting { .. }));
    }

    #[test]
    fn forward_step_does_not_count_the_gap_against_the_budget() {
        let mut s = step(ConnectionState::INITIAL, FAIL, ts(0));
        let now = ts(86_400_000);
        s = step(s, Event::Tick, now);
        s = step(s, FAIL, now);
        assert_eq!(
            s,
            Bo {
                // The attempt count is kept (delays keep escalating); only the clock restarts.
                outage: outage(2, 86_400_000),
                until: ts(86_403_000)
            }
        );
    }

    #[test]
    fn forward_step_during_an_attempt_restarts_the_outage_clock() {
        let c = Connecting {
            outage: Some(outage(3, 0)),
            attempt_started: Some(ts(1000)),
        };
        let now = ts(86_400_000);
        let s = step(c, FAIL, now);
        assert!(matches!(s, Bo { outage, .. } if outage.start == now && outage.attempt == 4));
        let t = step(c, Event::Tick, now);
        assert_eq!(
            t,
            Connecting {
                outage: Some(Outage {
                    start: now,
                    ..outage(3, 0)
                }),
                attempt_started: Some(now)
            }
        );
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
            t = until.as_unix_millis() - 1_700_000_000_000;
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
