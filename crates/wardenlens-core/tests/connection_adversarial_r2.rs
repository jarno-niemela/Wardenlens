//! Round-2 adversarial tests for #46, adapted to the monotonic clock: liveness
//! against adapter tick cadence, degraded pacing, flapping and boundaries.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "integration-test helpers outside #[test] fns do millisecond arithmetic on small bounded values"
)]

use proptest::prelude::*;
use wardenlens_core::connection::{
    ConnectionPolicy, ConnectionState, Event, FailureKind, JitterSource, transition,
};
use wardenlens_core::time::{DurationMs, MonoMs};

struct Fixed(u64);
impl JitterSource for Fixed {
    fn next_u64(&mut self) -> u64 {
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

fn step(s: ConnectionState, e: Event, now: MonoMs) -> ConnectionState {
    transition(s, e, now, &ConnectionPolicy::DEFAULT, &mut Fixed(0))
}

const FAIL: Event = Event::Failed(FailureKind::Timeout);

/// Drive a hung camera (no Connected, no Failed) with ticks every `cadence` ms
/// for `horizon` ms. Returns the first time it is Degraded, if ever, and the
/// time of the first failure.
fn hung_with_ticks(cadence: i64, horizon: i64) -> (Option<i64>, Option<i64>) {
    let mut s = ConnectionState::INITIAL;
    let mut t = 0;
    let mut first_fail = None;
    while t <= horizon {
        s = step(s, Event::Tick, ts(t));
        if first_fail.is_none() && matches!(s, ConnectionState::Backoff { .. }) {
            first_fail = Some(t);
        }
        if matches!(s, ConnectionState::Degraded { .. }) {
            return (Some(t), first_fail);
        }
        t += cadence;
    }
    (None, first_fail)
}

#[test]
fn hung_camera_with_one_second_ticks_degrades_after_the_budget() {
    let (degraded, first) = hung_with_ticks(1000, 600_000);
    let (Some(d), Some(f)) = (degraded, first) else {
        panic!("never degraded: {degraded:?} first failure {first:?}");
    };
    assert!(d - f >= 180_000, "degraded early: {d} - {f}");
    assert!(d - f <= 200_000, "degraded late: {d} - {f}");
}

/// The module docs call a gap above `cap + connect_timeout` (15 s) a forward
/// step. An adapter that ticks every 15.001 s (timer slack, a busy runtime)
/// is not a clock step, yet a hung attempt must still time out and the
/// camera must still degrade. Observed: it stays in `Connecting` forever.
/// Ticks every 8 s are well inside the documented max gap (each gap between
/// consecutive events is 8 s), but the Connecting branch measures the gap from
/// `attempt_started`: the tick at 16 s sees 16 s > 15 s, treats it as a forward
/// step and re-anchors instead of timing out. Repeats forever. Every cadence
/// in 7.5 s < c < 10 s stalls the same way.
#[test]
fn hung_camera_with_eight_second_ticks_times_out_and_degrades() {
    let (degraded, first) = hung_with_ticks(8_000, 3_600_000);
    assert!(
        first.is_some(),
        "hung attempt never timed out with 8 s ticks"
    );
    assert!(degraded.is_some(), "never degraded within an hour");
}

#[test]
fn hung_camera_with_ticks_just_above_max_gap_still_degrades() {
    let (degraded, first) = hung_with_ticks(15_001, 3_600_000);
    assert!(
        first.is_some(),
        "hung attempt never timed out with 15.001 s ticks"
    );
    assert!(degraded.is_some(), "never degraded within an hour");
}

/// An adapter that enforces its own socket timeout (ADR 0002's spike used 25 s
/// for RTSP) and reports `Failed` itself, ticking only to end each backoff.
/// Every failure lands more than 15 s after the attempt started, so each one
/// restarts the outage clock and the camera never degrades.
#[test]
fn adapter_reported_failures_after_a_slow_socket_timeout_still_degrade() {
    let mut s = ConnectionState::INITIAL;
    // The first attempt starts at 0 (anchored by a tick).
    s = step(s, Event::Tick, ts(0));
    let mut t = 0;
    for _ in 0..100 {
        t += 25_000; // socket timeout fires
        s = step(s, FAIL, ts(t));
        match s {
            ConnectionState::Degraded { .. } => return,
            ConnectionState::Backoff { until, .. } => {
                t = rel(until);
                s = step(s, Event::Tick, until);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    panic!("never degraded after 100 failures over {t} ms: {s:?}");
}

/// A stale `now` (contract violation) neither panics nor stalls.
#[test]
fn stale_now_does_not_panic_or_stall() {
    let d = ConnectionState::Degraded {
        since: ts(1_000_000),
        last_error_kind: FailureKind::Timeout,
        next_retry: ts(1_005_000),
    };
    assert_eq!(step(d, Event::Tick, ts(0)), d);
    let s = step(d, Event::Tick, ts(1_005_000));
    assert!(matches!(s, ConnectionState::Connecting { .. }));
    let s = step(s, Event::Tick, ts(1_015_000));
    assert!(matches!(s, ConnectionState::Degraded { .. }));
}

/// Background retries of degraded cameras that failed together stay in lockstep.
#[test]
fn degraded_background_retries_are_jittered() {
    let c = ConnectionState::Connecting {
        outage: None,
        attempt_started: Some(ts(0)),
    };
    let policy = ConnectionPolicy {
        budget: DurationMs::from_millis(0),
        ..ConnectionPolicy::DEFAULT
    };
    let a = transition(c, FAIL, ts(1000), &policy, &mut Fixed(0));
    let b = transition(c, FAIL, ts(1000), &policy, &mut Fixed(1));
    let (
        ConnectionState::Degraded { next_retry: ra, .. },
        ConnectionState::Degraded { next_retry: rb, .. },
    ) = (a, b)
    else {
        panic!("{a:?} {b:?}");
    };
    assert_ne!(ra, rb, "degraded retries are not jittered");
}

#[test]
fn backoff_boundary_is_exact() {
    let b = ConnectionState::Backoff {
        outage: wardenlens_core::connection::Outage {
            attempt: 2,
            start: ts(0),
            degraded_since: None,
        },
        until: ts(10_000),
    };
    assert_eq!(step(b, Event::Tick, ts(9_999)), b);
    assert!(matches!(
        step(b, Event::Tick, ts(10_000)),
        ConnectionState::Connecting { .. }
    ));
}

/// A camera that stays up just under `min_stable` each time, with one-second
/// ticks, degrades once its flapping spans the budget; one that stays up for
/// `min_stable` recovers every time and never degrades.
#[test]
fn flapping_boundary_at_min_stable() {
    for (up_ms, expect_degraded) in [(29_999, true), (30_000, false)] {
        let mut s = ConnectionState::INITIAL;
        let mut t = 0;
        s = step(s, FAIL, ts(t));
        let mut degraded = false;
        while t < 1_200_000 {
            t += 1000;
            s = step(s, Event::Tick, ts(t));
            if matches!(s, ConnectionState::Connecting { .. }) {
                s = step(s, Event::Connected, ts(t));
                let end = t + up_ms;
                // tick during the stream, but not at exactly min_stable
                while t + 1000 < end {
                    t += 1000;
                    s = step(s, Event::Tick, ts(t));
                }
                t = end;
                s = step(s, FAIL, ts(t));
            }
            if matches!(s, ConnectionState::Degraded { .. }) {
                degraded = true;
                break;
            }
        }
        assert_eq!(degraded, expect_degraded, "up {up_ms} ms: {s:?}");
    }
}

proptest! {
    /// For ANY tick cadence (1 ms to 60 s) a hung camera degrades no earlier
    /// than the budget after its first failure and no later than budget +
    /// cadence + connect_timeout (plus one backoff cycle and cadence of slack).
    #[test]
    fn hung_camera_degrades_for_any_cadence(cadence in 1i64..=60_000) {
        let (degraded, first) = hung_with_ticks(cadence, 2_000_000);
        prop_assert!(first.is_some());
        prop_assert!(degraded.is_some());
        let (d, f) = (degraded.unwrap_or(0), first.unwrap_or(0));
        prop_assert!(d - f >= 180_000, "early: {} {}", d, f);
        prop_assert!(d - f <= 180_000 + 10_000 + 5_000 + 2 * cadence, "late: {} {}", d, f);
    }

    /// Monotonic time, arbitrary interleavings of failures and ticks with any
    /// gaps, never Connected: once degraded, the outage
    /// measured from the very first failure is at least the budget.
    #[test]
    fn no_false_degrade_with_monotonic_time(
        events in proptest::collection::vec((any::<bool>(), 1i64..60_000), 1..400)
    ) {
        let mut s = ConnectionState::INITIAL;
        let mut t = 0i64;
        let mut first: Option<i64> = None;
        for (is_fail, dt) in events {
            t += dt;
            s = step(s, if is_fail { FAIL } else { Event::Tick }, ts(t));
            if first.is_none() && matches!(s, ConnectionState::Backoff { .. }) {
                first = Some(t);
            }
            if let ConnectionState::Degraded { since, .. } = s {
                let f = first.unwrap_or(t);
                prop_assert!(rel(since) - f >= 180_000, "degraded at {} first {}", rel(since), f);
                break;
            }
        }
    }
}
