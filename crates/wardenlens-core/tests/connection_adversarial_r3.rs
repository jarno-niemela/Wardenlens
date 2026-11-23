//! Round-3 adversarial tests for #46: the monotonic connection state machine
//! under arbitrary tick cadence, failure latency and degraded/recovery paths.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "test helpers do millisecond arithmetic on small bounded values"
)]

use proptest::prelude::*;
use wardenlens_core::connection::{
    ConnectionPolicy, ConnectionState, Event, FailureKind, JitterSource, Outage, transition,
};
use wardenlens_core::time::{DurationMs, MonoMs};

struct Fixed(u64);
impl JitterSource for Fixed {
    fn next_u64(&mut self) -> u64 {
        self.0
    }
}

struct Lcg(u64);
impl JitterSource for Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

const BASE: u64 = 1_000_000;

fn ts(ms: i64) -> MonoMs {
    MonoMs::from_millis(BASE.saturating_add_signed(ms))
}

fn rel(t: MonoMs) -> i64 {
    i64::try_from(t.as_millis().saturating_sub(BASE)).unwrap_or(i64::MAX)
}

const FAIL: Event = Event::Failed(FailureKind::Refused);

/// A degraded camera that stays hung keeps retrying in the background for any
/// tick cadence, and never leaves Degraded/Connecting.
fn degraded_retry_gaps(cadence: i64, seed: u64) -> Result<Vec<i64>, String> {
    let p = ConnectionPolicy::DEFAULT;
    let mut j = Lcg(seed);
    let mut s = ConnectionState::Degraded {
        since: ts(0),
        last_error_kind: FailureKind::Timeout,
        next_retry: ts(5_000),
    };
    let mut t = 0;
    let mut retries = vec![];
    while t <= 600_000 {
        let before = s;
        s = transition(s, Event::Tick, ts(t), &p, &mut j);
        if matches!(before, ConnectionState::Degraded { .. })
            && matches!(s, ConnectionState::Connecting { .. })
        {
            retries.push(t);
        }
        match s {
            ConnectionState::Degraded { since, .. } if since != ts(0) => {
                return Err(format!("since moved: {since:?}"));
            }
            ConnectionState::Degraded { .. } | ConnectionState::Connecting { .. } => {}
            other => return Err(format!("left degraded without success: {other:?}")),
        }
        t += cadence;
    }
    Ok(retries
        .iter()
        .zip(retries.iter().skip(1))
        .map(|(a, b)| b - a)
        .collect())
}

proptest! {
    #[test]
    fn degraded_background_retries_never_stall(cadence in 1i64..=60_000, seed in any::<u64>()) {
        let gaps = degraded_retry_gaps(cadence, seed).map_err(TestCaseError::fail)?;
        prop_assert!(!gaps.is_empty() || cadence > 150_000);
        for g in gaps {
            // timeout (10 s) + cap (5 s) + up to two tick periods of delay
            prop_assert!(g <= 15_000 + 2 * cadence, "gap {} at cadence {}", g, cadence);
        }
    }

    /// Adapter reports `Failed` itself after `latency` ms (possibly longer than
    /// connect_timeout, in which case the tick timeout wins and the late Failed
    /// is stale). Any cadence, any latency, random jitter: degrades no earlier
    /// than the budget after the first failure and within a bounded slack.
    #[test]
    fn hung_camera_with_adapter_failures_degrades_in_bounds(
        cadence in 1i64..=30_000,
        latency in 0i64..=60_000,
        seed in any::<u64>(),
    ) {
        let p = ConnectionPolicy::DEFAULT;
        let mut j = Lcg(seed);
        let mut s = ConnectionState::INITIAL;
        let mut attempt_start = Some(0i64);
        let mut next_tick = 0i64;
        let mut first: Option<i64> = None;
        let mut degraded_at = None;
        let mut t;
        for _ in 0..1_000_000 {
            let fail_at = attempt_start.map(|a| a + latency);
            // next event: tick or adapter failure, whichever is earlier
            let (ev, at) = match fail_at {
                Some(f) if f < next_tick => (FAIL, f),
                _ => (Event::Tick, next_tick),
            };
            t = at;
            if ev == Event::Tick { next_tick += cadence; } else { attempt_start = None; }
            let before = s;
            s = transition(s, ev, ts(t), &p, &mut j);
            if first.is_none() && matches!(s, ConnectionState::Backoff { .. } | ConnectionState::Degraded { .. }) {
                first = Some(t);
            }
            if !matches!(before, ConnectionState::Connecting { .. }) && matches!(s, ConnectionState::Connecting { .. }) {
                attempt_start = Some(t);
            }
            if let ConnectionState::Degraded { since, .. } = s {
                degraded_at = Some(rel(since));
                break;
            }
            if t > 3_000_000 { break; }
        }
        let f = first.unwrap_or(-1);
        prop_assert!(degraded_at.is_some(), "never degraded, first fail {}", f);
        let d = degraded_at.unwrap_or(0);
        prop_assert!(d - f >= 180_000, "early: {} {}", d, f);
        prop_assert!(d - f <= 180_000 + 10_000.max(latency) + 5_000 + 2 * cadence, "late: {} {}", d, f);
    }
}

#[test]
fn degraded_then_stable_stream_then_failure_starts_a_fresh_outage() {
    let p = ConnectionPolicy::DEFAULT;
    let d = ConnectionState::Degraded {
        since: ts(0),
        last_error_kind: FailureKind::Timeout,
        next_retry: ts(5_000),
    };
    let s = transition(d, Event::Connected, ts(6_000), &p, &mut Fixed(0));
    // No tick during the stream: the failure itself must see that it was stable.
    let s = transition(s, FAIL, ts(36_000), &p, &mut Fixed(0));
    assert_eq!(
        s,
        ConnectionState::Backoff {
            outage: Outage {
                attempt: 1,
                start: ts(36_000),
                degraded_since: None
            },
            until: ts(38_000)
        }
    );
}

#[test]
fn degraded_then_unstable_stream_stays_degraded_with_fresh_retry() {
    let p = ConnectionPolicy::DEFAULT;
    let d = ConnectionState::Degraded {
        since: ts(0),
        last_error_kind: FailureKind::Timeout,
        next_retry: ts(5_000),
    };
    let s = transition(d, Event::Connected, ts(6_000), &p, &mut Fixed(0));
    let s = transition(s, Event::Tick, ts(35_999), &p, &mut Fixed(0));
    let s = transition(
        s,
        Event::Failed(FailureKind::Auth),
        ts(35_999),
        &p,
        &mut Fixed(0),
    );
    assert_eq!(
        s,
        ConnectionState::Degraded {
            since: ts(0),
            last_error_kind: FailureKind::Auth,
            next_retry: ts(35_999 + 3_750)
        }
    );
}

/// The attempt timeout is measured from the tick that started the attempt, not
/// from `until`: a late backoff-ending tick must not eat into the attempt.
#[test]
fn late_backoff_tick_gives_the_attempt_its_full_timeout() {
    let p = ConnectionPolicy::DEFAULT;
    let b = ConnectionState::Backoff {
        outage: Outage {
            attempt: 1,
            start: ts(0),
            degraded_since: None,
        },
        until: ts(2_000),
    };
    let s = transition(b, Event::Tick, ts(9_000), &p, &mut Fixed(0));
    let s2 = transition(s, Event::Tick, ts(18_999), &p, &mut Fixed(0));
    assert!(matches!(s2, ConnectionState::Connecting { .. }), "{s2:?}");
    let s3 = transition(s, Event::Tick, ts(19_000), &p, &mut Fixed(0));
    assert!(matches!(s3, ConnectionState::Backoff { .. }), "{s3:?}");
}

#[test]
fn zero_connect_timeout_fails_on_the_next_tick_not_the_starting_one() {
    let p = ConnectionPolicy {
        connect_timeout: DurationMs::from_millis(0),
        ..ConnectionPolicy::DEFAULT
    };
    let b = ConnectionState::Backoff {
        outage: Outage {
            attempt: 1,
            start: ts(0),
            degraded_since: None,
        },
        until: ts(2_000),
    };
    let s = transition(b, Event::Tick, ts(2_000), &p, &mut Fixed(0));
    assert!(matches!(s, ConnectionState::Connecting { .. }));
    let s = transition(s, Event::Tick, ts(2_000), &p, &mut Fixed(0));
    assert!(matches!(s, ConnectionState::Backoff { .. }));
}

#[test]
fn end_of_monotonic_time_never_panics() {
    let p = ConnectionPolicy::DEFAULT;
    let end = MonoMs::from_millis(u64::MAX);
    let mut s = ConnectionState::INITIAL;
    for e in [
        Event::Tick,
        FAIL,
        Event::Tick,
        Event::Tick,
        Event::Connected,
        FAIL,
        Event::Tick,
    ] {
        s = transition(s, e, end, &p, &mut Fixed(u64::MAX));
    }
    let d = transition(
        ConnectionState::Connecting {
            outage: Some(Outage {
                attempt: 3,
                start: MonoMs::from_millis(0),
                degraded_since: None,
            }),
            attempt_started: Some(MonoMs::from_millis(0)),
        },
        Event::Tick,
        end,
        &p,
        &mut Fixed(u64::MAX),
    );
    assert!(matches!(d, ConnectionState::Degraded { next_retry, .. } if next_retry == end));
    assert!(matches!(
        transition(d, Event::Tick, end, &p, &mut Fixed(0)),
        ConnectionState::Connecting { .. }
    ));
}

#[test]
fn degraded_retries_continue_at_extreme_cadences() {
    for cadence in [1, 4_999, 5_000, 5_001, 9_999, 10_000, 15_001, 60_000] {
        let gaps = degraded_retry_gaps(cadence, 7).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !gaps.is_empty(),
            "no background retries at cadence {cadence}"
        );
        assert!(
            gaps.iter().all(|&g| g <= 15_000 + 2 * cadence),
            "cadence {cadence}: {gaps:?}"
        );
    }
}
