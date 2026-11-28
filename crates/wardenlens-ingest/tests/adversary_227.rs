//! Adversary tests (#227) for `Supervisor::spawn_observed`, through the public API only.
//!
//! Every async test runs on tokio's paused clock (TEST-5).

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns; a panic fails the test"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{Instant, sleep};
use wardenlens_core::connection::{Backoff, ConnectionState, FailureKind, JitterSource};
use wardenlens_core::time::{DurationMs, Timestamp};
use wardenlens_ingest::{
    CancelToken, ConnectionNotice, Frame, FrameMapper, FrameSource, IngestError, InstantClock,
    RawParams, RawVideoFrame, StreamSource, Supervisor, SupervisorConfig,
};

struct Fixed0;
impl JitterSource for Fixed0 {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

fn key_frame() -> Frame {
    let t = Timestamp::from_unix_millis(1_700_000_000_000);
    FrameMapper::new()
        .map(
            RawVideoFrame {
                data: vec![0, 0, 0, 1, 0x65],
                is_random_access_point: true,
                rtp_timestamp: 0,
                clock_rate: 90_000,
                loss: 0,
                params: Some(RawParams {
                    sps: vec![0x67, 1],
                    pps: vec![0x68, 1],
                }),
            },
            t,
        )
        .unwrap()
        .unwrap()
}

enum Step {
    Frame,
    Sleep(Duration),
    Eof,
}

enum Attempt {
    OpenFails(IngestError),
    Stream(Vec<Step>),
}

struct Fake {
    script: VecDeque<Attempt>,
    opens: Arc<Mutex<Vec<Instant>>>,
}

struct FakeStream(VecDeque<Step>);

impl StreamSource for Fake {
    type Stream = FakeStream;
    async fn open(&mut self, _idle: Duration) -> Result<FakeStream, IngestError> {
        self.opens.lock().unwrap().push(Instant::now());
        tokio::task::yield_now().await;
        match self
            .script
            .pop_front()
            .unwrap_or(Attempt::OpenFails(IngestError::AuthRejected))
        {
            Attempt::OpenFails(e) => Err(e),
            Attempt::Stream(s) => Ok(FakeStream(s.into())),
        }
    }
}

impl FrameSource for FakeStream {
    async fn next_frame(&mut self) -> Result<Option<Frame>, IngestError> {
        tokio::task::yield_now().await;
        loop {
            match self.0.pop_front() {
                Some(Step::Frame) => return Ok(Some(key_frame())),
                Some(Step::Sleep(d)) => sleep(d).await,
                Some(Step::Eof) | None => return Ok(None),
            }
        }
    }
}

type Seen = Arc<Mutex<Vec<(Instant, ConnectionNotice)>>>;

struct Rig {
    seen: Seen,
    opens: Arc<Mutex<Vec<Instant>>>,
    state: watch::Receiver<ConnectionState>,
    cancel: CancelToken,
    _frames: tokio::sync::mpsc::Receiver<Frame>,
}

fn rig(script: Vec<Attempt>, config: SupervisorConfig) -> Rig {
    let seen: Seen = Arc::default();
    let sink = Arc::clone(&seen);
    let opens = Arc::default();
    let cancel = CancelToken::new();
    let (frames, state, _dropped, _task) = Supervisor::spawn_observed(
        Fake {
            script: script.into(),
            opens: Arc::clone(&opens),
        },
        InstantClock::new(),
        Backoff::DEFAULT,
        Fixed0,
        config,
        cancel.clone(),
        move |n| sink.lock().unwrap().push((Instant::now(), n)),
    );
    Rig {
        seen,
        opens,
        state,
        cancel,
        _frames: frames,
    }
}

fn failed(seen: &Seen) -> Vec<(Instant, wardenlens_ingest::FailureNote)> {
    seen.lock()
        .unwrap()
        .iter()
        .filter_map(|(t, n)| match n {
            ConnectionNotice::Failed(f) => Some((*t, *f)),
            _ => None,
        })
        .collect()
}

/// A camera that refuses every login for ten minutes: one notice per failed open, attempts
/// 1..=n without a gap (also while degraded), the retry delay within the backoff cap and equal to
/// the wait the supervisor then actually does (floored at its 100 ms pause), and `degraded` set
/// from the first failure past the budget on.
#[tokio::test(start_paused = true)]
async fn a_dead_camera_reports_every_failure_with_consecutive_attempts_for_ten_minutes() {
    let r = rig(Vec::new(), SupervisorConfig::default());
    sleep(Duration::from_secs(600)).await;
    r.cancel.cancel();
    let notes = failed(&r.seen);
    let opens = r.opens.lock().unwrap().clone();
    assert!(notes.len() > 100, "{}", notes.len());
    assert!(
        !r.seen
            .lock()
            .unwrap()
            .iter()
            .any(|(_, n)| *n == ConnectionNotice::Recovered)
    );
    // Every open failed and produced exactly one notice (the last open may still be pending).
    assert!(
        opens.len() == notes.len() || opens.len() == notes.len() + 1,
        "opens {} notes {}",
        opens.len(),
        notes.len()
    );
    let first = notes[0].1.at;
    for (i, (t, n)) in notes.iter().enumerate() {
        assert_eq!(n.attempt, u32::try_from(i + 1).unwrap(), "{n:?}");
        assert_eq!(n.kind, FailureKind::Auth);
        assert!(n.retry_in <= DurationMs::from_secs(5), "{n:?}");
        assert!(n.retry_in >= DurationMs::from_secs(2), "{n:?}");
        let past_budget = n.at.saturating_duration_since(first) >= DurationMs::from_secs(180);
        assert_eq!(n.degraded, past_budget, "#{i}: {n:?}");
        if let Some(next_open) = opens.get(i + 1) {
            let waited = next_open.duration_since(*t);
            let promised = Duration::from_millis(n.retry_in.as_millis());
            assert!(
                waited >= promised && waited <= promised + Duration::from_millis(200),
                "#{i}: waited {waited:?}, promised {promised:?}"
            );
        }
    }
    assert!(notes.iter().any(|(_, n)| n.degraded));
}

/// Short flaps keep one outage (no `Recovered`, attempts go on); a stream that stays up past
/// `min_stable` ends it once, and the next failure is attempt 1 of a new backoff (not degraded).
#[tokio::test(start_paused = true)]
async fn flaps_keep_counting_a_stable_stream_recovers_once_and_the_count_restarts() {
    let mut cfg = SupervisorConfig::default();
    cfg.idle_timeout = Duration::from_secs(60);
    cfg.min_stable = DurationMs::from_secs(30);
    let flap = || Attempt::Stream(vec![Step::Frame, Step::Eof]);
    let script = vec![
        Attempt::OpenFails(IngestError::OpenFailed),
        flap(),
        flap(),
        Attempt::Stream(vec![
            Step::Frame,
            Step::Sleep(Duration::from_secs(31)),
            Step::Frame,
            Step::Eof,
        ]),
        Attempt::OpenFails(IngestError::OpenFailed),
    ];
    let mut r = rig(script, cfg);
    sleep(Duration::from_secs(70)).await;
    r.cancel.cancel();
    let _ = r.state.borrow_and_update();
    let seen: Vec<ConnectionNotice> = r.seen.lock().unwrap().iter().map(|(_, n)| *n).collect();
    let summary: Vec<String> = seen
        .iter()
        .map(|n| match n {
            ConnectionNotice::Failed(f) => {
                format!("F{}{}", f.attempt, if f.degraded { "d" } else { "" })
            }
            ConnectionNotice::Recovered => "R".to_owned(),
            _ => "?".to_owned(),
        })
        .collect();
    // open fails (1), flap (2), flap (3), stable stream: R, its EOF (1), open fails (2), ...
    assert!(
        summary.len() >= 6 && summary[..6] == ["F1", "F2", "F3", "R", "F1", "F2"],
        "{summary:?}"
    );
    assert_eq!(
        summary.iter().filter(|s| *s == "R").count(),
        1,
        "{summary:?}"
    );
}

/// A degraded camera that comes back and stays up recovers; the next failure is a fresh backoff.
#[tokio::test(start_paused = true)]
async fn a_degraded_camera_that_recovers_starts_a_fresh_backoff() {
    let mut cfg = SupervisorConfig::default();
    cfg.idle_timeout = Duration::from_secs(60);
    cfg.budget = DurationMs::from_secs(5);
    cfg.min_stable = DurationMs::from_secs(5);
    let mut script: Vec<Attempt> = (0..5)
        .map(|_| Attempt::OpenFails(IngestError::AuthRejected))
        .collect();
    script.push(Attempt::Stream(vec![
        Step::Frame,
        Step::Sleep(Duration::from_secs(6)),
        Step::Frame,
        Step::Eof,
    ]));
    script.push(Attempt::OpenFails(IngestError::OpenFailed));
    let r = rig(script, cfg);
    sleep(Duration::from_secs(60)).await;
    r.cancel.cancel();
    let seen: Vec<ConnectionNotice> = r.seen.lock().unwrap().iter().map(|(_, n)| *n).collect();
    let pos = seen
        .iter()
        .position(|n| *n == ConnectionNotice::Recovered)
        .unwrap_or_else(|| panic!("{seen:?}"));
    assert!(
        seen[..pos]
            .iter()
            .any(|n| matches!(n, ConnectionNotice::Failed(f) if f.degraded))
    );
    let ConnectionNotice::Failed(after) = seen[pos + 1] else {
        panic!("{seen:?}");
    };
    assert_eq!((after.attempt, after.degraded), (1, false), "{seen:?}");
}
