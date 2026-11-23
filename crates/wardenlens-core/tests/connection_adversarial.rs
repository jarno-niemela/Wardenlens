//! Adversarial tests for the connection module (#46): state machine, backoff, time arithmetic.

use proptest::prelude::*;
use wardenlens_core::connection::{
    Backoff, ConnectionPolicy, ConnectionState, Event, FailureKind, JitterSource, Outage,
    transition,
};
use wardenlens_core::time::{DurationMs, Timestamp};

struct Fixed(u64);
impl JitterSource for Fixed {
    fn next_u64(&mut self) -> u64 {
        self.0
    }
}

struct Seq(Vec<u64>, usize);
impl JitterSource for Seq {
    fn next_u64(&mut self) -> u64 {
        let v = self.0.get(self.1).copied().unwrap_or(0);
        self.1 = self.1.saturating_add(1);
        v
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

const MAX_DELAY_MS: i64 = 5_000;

// ---------- liveness under wall-clock steps ----------

/// The Clock is a wall clock (ADR 0005). If it steps back by an hour while a camera is in
/// Backoff, the retry must not be postponed by that hour: a retry is never more than the
/// backoff cap away from the time it was scheduled.
#[test]
fn backward_clock_step_during_backoff_does_not_stall_retries() {
    let s = step(
        ConnectionState::INITIAL,
        Event::Failed(FailureKind::Timeout),
        ts(0),
    );
    // Clock steps back one hour; ticks keep arriving for 10 s of real time.
    let stepped = -3_600_000;
    let mut cur = s;
    let mut retried_at = None;
    for real in (0..=10_000).step_by(500) {
        let now = ts(stepped + real);
        cur = step(cur, Event::Tick, now);
        if retried_at.is_none() && matches!(cur, ConnectionState::Connecting { .. }) {
            retried_at = Some(real);
        }
    }
    // The retry starts at the first tick (and has since timed out into a new backoff).
    assert_eq!(retried_at, Some(0), "no retry: {cur:?}");
}

/// Forward step: an NTP step right after boot must not mark a camera degraded after one
/// real failure-retry cycle of a few seconds; the gap is not counted against the budget.
#[test]
fn forward_clock_step_does_not_degrade_after_one_retry() {
    let mut s = step(
        ConnectionState::INITIAL,
        Event::Failed(FailureKind::Timeout),
        ts(0),
    );
    // NTP step +1 day.
    let now = ts(86_400_000);
    s = step(s, Event::Tick, now);
    s = step(s, Event::Failed(FailureKind::Timeout), now);
    assert!(matches!(s, ConnectionState::Backoff { .. }), "{s:?}");
}

// ---------- state x event table ----------

fn all_states() -> Vec<ConnectionState> {
    vec![
        ConnectionState::INITIAL,
        ConnectionState::Connecting {
            outage: Some(outage(3, 0)),
            attempt_started: Some(ts(0)),
        },
        ConnectionState::Streaming {
            since: ts(0),
            prior: None,
        },
        ConnectionState::Backoff {
            outage: outage(2, 0),
            until: ts(10_000),
        },
        ConnectionState::Degraded {
            since: ts(0),
            last_error_kind: FailureKind::Refused,
            next_retry: ts(5000),
        },
    ]
}

#[test]
fn connected_always_streams() {
    for s in all_states() {
        let n = step(s, Event::Connected, ts(5));
        assert!(
            matches!(n, ConnectionState::Streaming { .. }),
            "{s:?} -> {n:?}"
        );
        if !matches!(s, ConnectionState::Streaming { .. }) {
            assert!(matches!(n, ConnectionState::Streaming { since, .. } if since == ts(5)));
        }
    }
}

/// Ticks at any time, including the extremes of `i64`, never panic and never turn a
/// non-streaming state into a streaming one.
#[test]
fn tick_never_panics_or_streams() {
    for s in all_states() {
        for t in [i64::MIN, -1, 0, 1, i64::MAX] {
            let now = Timestamp::from_unix_millis(t);
            let n = step(s, Event::Tick, now);
            assert_eq!(
                matches!(n, ConnectionState::Streaming { .. }),
                matches!(s, ConnectionState::Streaming { .. }),
                "{s:?} -> {n:?}"
            );
        }
    }
}

#[test]
fn failure_never_jumps_to_streaming_or_connecting() {
    for s in all_states() {
        for t in [0, 100_000, 179_999, 180_000, 10_000_000] {
            let n = step(s, Event::Failed(FailureKind::Other), ts(t));
            assert!(
                matches!(
                    n,
                    ConnectionState::Backoff { .. } | ConnectionState::Degraded { .. }
                ),
                "{s:?} + Failed at {t} -> {n:?}"
            );
        }
    }
}

// ---------- budget ----------

/// Budget is measured from the first failure of the outage, not reset by retries.
#[test]
fn budget_is_not_reset_by_retry_cycles() {
    let mut s = ConnectionState::INITIAL;
    let mut t = 0;
    let mut degraded_at = None;
    for _ in 0..1000 {
        s = step(s, Event::Failed(FailureKind::Timeout), ts(t));
        if matches!(s, ConnectionState::Degraded { .. }) {
            degraded_at = Some(t);
            break;
        }
        let ConnectionState::Backoff { until, .. } = s else {
            panic!("expected backoff, got {s:?}");
        };
        t = until.as_unix_millis() - 1_700_000_000_000;
        s = step(s, Event::Tick, ts(t));
        t += 1; // the attempt fails 1 ms later
    }
    let at = degraded_at.expect("never degraded");
    assert!(
        (180_000..180_000 + MAX_DELAY_MS + 1).contains(&at),
        "degraded at {at}"
    );
}

/// ADR 0002 worst case with the actual 10 s timeouts and 5 s pauses (~16 s per round):
/// 8 failures, then success, then the camera is streaming and never degraded.
#[test]
fn adr_0002_worst_case_with_real_timings_recovers_without_degrading() {
    let mut s = ConnectionState::INITIAL;
    let mut t = 10_000; // first attempt times out after 10 s
    for i in 0..8 {
        s = step(s, Event::Failed(FailureKind::Timeout), ts(t));
        assert!(
            matches!(s, ConnectionState::Backoff { .. }),
            "failure {i}: {s:?}"
        );
        let ConnectionState::Backoff { until, .. } = s else {
            unreachable!()
        };
        let resume = until.as_unix_millis() - 1_700_000_000_000;
        s = step(s, Event::Tick, ts(resume));
        t = resume + 10_000;
    }
    assert!(t < 190_000);
    s = step(s, Event::Connected, ts(t));
    assert!(matches!(s, ConnectionState::Streaming { .. }));
}

#[test]
fn zero_budget_degrades_on_first_failure() {
    let p = ConnectionPolicy {
        backoff: Backoff::DEFAULT,
        budget: DurationMs::from_millis(0),
        ..ConnectionPolicy::DEFAULT
    };
    let n = transition(
        ConnectionState::Streaming {
            since: ts(0),
            prior: None,
        },
        Event::Failed(FailureKind::Auth),
        ts(0),
        &p,
        &mut Fixed(0),
    );
    assert_eq!(
        n,
        ConnectionState::Degraded {
            since: ts(0),
            last_error_kind: FailureKind::Auth,
            next_retry: ts(5000)
        }
    );
}

#[test]
fn infinite_budget_never_degrades_even_across_the_whole_timeline() {
    let p = ConnectionPolicy {
        backoff: Backoff::DEFAULT,
        budget: DurationMs::from_millis(u64::MAX),
        ..ConnectionPolicy::DEFAULT
    };
    // The outage spans u64::MAX - 1 ms, one short of the (unreachable) budget.
    let c = ConnectionState::Connecting {
        outage: Some(Outage {
            attempt: 5,
            start: Timestamp::from_unix_millis(i64::MIN + 1),
            degraded_since: None,
        }),
        attempt_started: None,
    };
    let n = transition(
        c,
        Event::Failed(FailureKind::Timeout),
        Timestamp::from_unix_millis(i64::MAX),
        &p,
        &mut Fixed(u64::MAX),
    );
    assert!(matches!(n, ConnectionState::Backoff { .. }), "{n:?}");
}

#[test]
fn backoff_until_saturates_at_end_of_time_and_tick_still_fires() {
    let now = Timestamp::from_unix_millis(i64::MAX - 10);
    let s = step(
        ConnectionState::Streaming {
            since: ts(0),
            prior: None,
        },
        Event::Failed(FailureKind::Timeout),
        now,
    );
    let ConnectionState::Backoff { until, .. } = s else {
        panic!("{s:?}")
    };
    assert_eq!(until.as_unix_millis(), i64::MAX);
    let end = Timestamp::from_unix_millis(i64::MAX);
    assert!(matches!(
        step(s, Event::Tick, end),
        ConnectionState::Connecting { .. }
    ));
}

#[test]
fn backoff_from_negative_time_works() {
    let now = Timestamp::from_unix_millis(i64::MIN);
    let s = step(
        ConnectionState::Streaming {
            since: ts(0),
            prior: None,
        },
        Event::Failed(FailureKind::Timeout),
        now,
    );
    let ConnectionState::Backoff { until, .. } = s else {
        panic!("{s:?}")
    };
    assert_eq!(until.as_unix_millis(), i64::MIN + 2000);
}

// ---------- duration arithmetic ----------

/// `i64::MAX - i64::MIN` is `2^64 - 1`, which fits in a u64; saturating should not clip at `i64::MAX`.
#[test]
fn duration_since_spans_the_full_i64_range_exactly() {
    let d = Timestamp::from_unix_millis(i64::MAX)
        .saturating_duration_since(Timestamp::from_unix_millis(i64::MIN));
    assert_eq!(d.as_millis(), u64::MAX);
}

#[test]
fn duration_since_across_zero_is_exact() {
    let d =
        Timestamp::from_unix_millis(5).saturating_duration_since(Timestamp::from_unix_millis(-5));
    assert_eq!(d.as_millis(), 10);
}

// ---------- backoff math ----------

#[test]
fn default_backoff_matches_adr_0002_range_for_all_attempts() {
    for a in (0..64).chain([u32::MAX - 1, u32::MAX]) {
        for j in [0, 1, 1250, 1251, u64::MAX / 2, u64::MAX] {
            let d = Backoff::DEFAULT.delay(a, &mut Fixed(j)).as_millis();
            assert!((2000..=5000).contains(&d), "attempt {a} jitter {j}: {d}");
        }
    }
}

#[test]
fn default_backoff_reaches_the_cap_exactly() {
    // span at the cap is 3750..=5000 (1251 values); raw 1250 must give 5000.
    assert_eq!(
        Backoff::DEFAULT.delay(5, &mut Fixed(1250)).as_millis(),
        5000
    );
    assert_eq!(
        Backoff::DEFAULT.delay(5, &mut Fixed(1251)).as_millis(),
        3750
    );
}

#[test]
fn backoff_is_monotone_in_attempt_at_fixed_zero_jitter() {
    let b = Backoff::new(
        DurationMs::from_millis(100),
        DurationMs::from_millis(1_000_000),
    );
    let mut prev = 0;
    for a in 0..70 {
        let d = b.delay(a, &mut Fixed(0)).as_millis();
        assert!(d >= prev, "attempt {a}: {d} < {prev}");
        prev = d;
    }
}

#[test]
fn backoff_consumes_exactly_one_jitter_value_per_delay() {
    let mut src = Seq(vec![0, 1250, 0, 1250], 0);
    let ds: Vec<u64> = (0..4)
        .map(|_| Backoff::DEFAULT.delay(9, &mut src).as_millis())
        .collect();
    assert_eq!(ds, vec![3750, 5000, 3750, 5000]);
}

#[test]
fn max_base_and_cap_do_not_overflow_and_stay_in_range() {
    for (base, cap) in [
        (u64::MAX, u64::MAX),
        (u64::MAX - 1, u64::MAX),
        (1, u64::MAX),
        (u64::MAX / 2 + 1, u64::MAX),
    ] {
        let b = Backoff::new(DurationMs::from_millis(base), DurationMs::from_millis(cap));
        for a in [0, 1, 2, 63, 64, u32::MAX] {
            for j in [0, 1, u64::MAX - 1, u64::MAX] {
                let d = b.delay(a, &mut Fixed(j)).as_millis();
                assert!(
                    d >= base && d <= cap,
                    "base {base} cap {cap} a {a} j {j}: {d}"
                );
            }
        }
    }
}

proptest! {
    #[test]
    fn delay_in_range_for_full_u64_domain(base in any::<u64>(), cap in any::<u64>(), attempt in any::<u32>(), j in any::<u64>()) {
        let b = Backoff::new(DurationMs::from_millis(base), DurationMs::from_millis(cap));
        let d = b.delay(attempt, &mut Fixed(j)).as_millis();
        prop_assert!(d >= base);
        prop_assert!(d <= cap.max(base));
    }

    /// Jitter never shaves more than a quarter off the un-jittered delay.
    #[test]
    fn delay_at_least_three_quarters_of_exponential(base in 0u64..1_000_000, cap in 0u64..100_000_000, attempt in 0u32..80, j in any::<u64>()) {
        let b = Backoff::new(DurationMs::from_millis(base), DurationMs::from_millis(cap));
        let cap = cap.max(base);
        let exp = base.saturating_mul(1u64.checked_shl(attempt.min(63)).unwrap_or(u64::MAX)).min(cap);
        let d = b.delay(attempt, &mut Fixed(j)).as_millis();
        // The first delay (exp == base) spreads upward by up to 25 % instead.
        let high = if exp <= base { base.saturating_add(base / 4).min(cap) } else { exp };
        prop_assert!(d <= high);
        prop_assert!(d >= exp.saturating_sub(exp / 4));
    }

    /// Random event sequences never panic and keep invariants: Backoff attempt >= 1,
    /// outage start <= until, the wait is at most the cap, and a camera only becomes
    /// degraded from a state whose outage has run for the whole budget.
    #[test]
    fn random_event_sequences_keep_invariants(
        events in proptest::collection::vec((0u8..3, 0u8..5, 0i64..20_000), 0..200),
        seed in any::<u64>()
    ) {
        let mut s = ConnectionState::INITIAL;
        let mut t = 0i64;
        let mut j = Fixed(seed);
        let policy = ConnectionPolicy::DEFAULT;
        for (kind, fk, dt) in events {
            t = t.saturating_add(dt);
            let now = ts(t);
            let ev = match kind {
                0 => Event::Connected,
                1 => Event::Failed([FailureKind::Timeout, FailureKind::Refused, FailureKind::Auth, FailureKind::Protocol, FailureKind::Other][usize::from(fk)]),
                _ => Event::Tick,
            };
            let prev = s;
            s = transition(s, ev, now, &policy, &mut j);
            match s {
                ConnectionState::Backoff { outage, until } => {
                    prop_assert!(outage.attempt >= 1);
                    prop_assert!(outage.start <= until);
                    prop_assert!(outage.degraded_since.is_none());
                    prop_assert!(until.as_unix_millis().saturating_sub(now.as_unix_millis()) <= 5000);
                }
                ConnectionState::Degraded { since, next_retry, .. } => {
                    prop_assert!(next_retry >= since);
                    let prior_outage = match prev {
                        ConnectionState::Connecting { outage, .. } => outage,
                        ConnectionState::Streaming { prior, .. } => prior,
                        _ => None,
                    };
                    if let Some(o) = prior_outage.filter(|o| o.degraded_since.is_none()) {
                        prop_assert!(since.as_unix_millis().saturating_sub(o.start.as_unix_millis()) >= 180_000);
                    }
                }
                _ => {}
            }
        }
    }
}
