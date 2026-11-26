//! Round-5 adversarial tests for the ingest `Supervisor` (#56), through the public API only.
//!
//! Every async test runs on tokio's paused clock (TEST-5).

#![expect(
    dead_code,
    reason = "shared rig helpers copied from adversary_56_r4.rs"
)]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "test-only time arithmetic on small values"
)]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns; a panic fails the test"
)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep};
use wardenlens_core::connection::{Backoff, ConnectionState, JitterSource};
use wardenlens_core::time::{DurationMs, Timestamp};
use wardenlens_ingest::{
    CancelToken, DroppedFrames, Frame, FrameMapper, FrameSource, H264Params, IngestError,
    InstantClock, RawParams, RawVideoFrame, StreamSource, Supervisor, SupervisorConfig,
};

struct Fixed0;
impl JitterSource for Fixed0 {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

fn raw(id: u32, key: bool, params: Option<u8>) -> RawVideoFrame {
    RawVideoFrame {
        data: vec![0, 0, 0, 1, if key { 0x65 } else { 0x41 }],
        is_random_access_point: key,
        rtp_timestamp: i64::from(id),
        clock_rate: 90_000,
        loss: 0,
        params: params.map(|t| RawParams {
            sps: vec![0x67, t],
            pps: vec![0x68, t],
        }),
    }
}

/// A frame tagged `id` (its `rtp_ts_90k`), without discontinuity unless asked.
fn mk(id: u32, key: bool, params: Option<u8>, disc: bool) -> Frame {
    let t = Timestamp::from_unix_millis(1_700_000_000_000);
    let mut m = FrameMapper::new();
    if !disc {
        // The first mapped frame of a mapper is a discontinuity; burn it.
        let _ = m.map(raw(0, true, Some(1)), t).unwrap().unwrap();
    }
    m.map(raw(id, key, params), t).unwrap().unwrap()
}

fn p(tag: u8) -> H264Params {
    // Build through the mapper too, to get the exact value it produces.
    let t = Timestamp::from_unix_millis(0);
    FrameMapper::new()
        .map(raw(0, true, Some(tag)), t)
        .unwrap()
        .unwrap()
        .params
        .unwrap()
}

enum Step {
    Frame(Frame),
    Sleep(Duration),
    Err(IngestError),
    Eof,
    Silent,
}

enum Attempt {
    OpenFails(IngestError),
    OpenHangs,
    Stream(Vec<Step>),
}

#[derive(Default)]
struct Shared {
    opens: Mutex<Vec<Instant>>,
    live: AtomicUsize,
    live_at_open: Mutex<Vec<usize>>,
}

struct Fake {
    script: VecDeque<Attempt>,
    shared: Arc<Shared>,
    /// What an exhausted script does.
    after: fn() -> Attempt,
}

struct FakeStream {
    steps: VecDeque<Step>,
    shared: Arc<Shared>,
}

impl Drop for FakeStream {
    fn drop(&mut self) {
        self.shared.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl StreamSource for Fake {
    type Stream = FakeStream;
    async fn open(&mut self, _idle: Duration) -> Result<FakeStream, IngestError> {
        let sh = Arc::clone(&self.shared);
        sh.opens.lock().unwrap().push(Instant::now());
        sh.live_at_open
            .lock()
            .unwrap()
            .push(sh.live.load(Ordering::SeqCst));
        let next = self.script.pop_front().unwrap_or_else(self.after);
        match next {
            Attempt::OpenFails(e) => Err(e),
            Attempt::OpenHangs => std::future::pending().await,
            Attempt::Stream(steps) => {
                sh.live.fetch_add(1, Ordering::SeqCst);
                Ok(FakeStream {
                    steps: steps.into(),
                    shared: sh,
                })
            }
        }
    }
}

impl FrameSource for FakeStream {
    async fn next_frame(&mut self) -> Result<Option<Frame>, IngestError> {
        tokio::task::yield_now().await;
        loop {
            match self.steps.pop_front() {
                Some(Step::Frame(f)) => return Ok(Some(f)),
                Some(Step::Sleep(d)) => sleep(d).await,
                Some(Step::Err(e)) => return Err(e),
                Some(Step::Eof) => return Ok(None),
                Some(Step::Silent) | None => std::future::pending::<()>().await,
            }
        }
    }
}

struct Rig {
    frames: mpsc::Receiver<Frame>,
    state: watch::Receiver<ConnectionState>,
    dropped: DroppedFrames,
    cancel: CancelToken,
    shared: Arc<Shared>,
}

fn fail_open() -> Attempt {
    Attempt::OpenFails(IngestError::OpenFailed)
}

fn rig_with(
    script: Vec<Attempt>,
    after: fn() -> Attempt,
    backoff: Backoff,
    config: SupervisorConfig,
) -> Rig {
    let shared = Arc::new(Shared::default());
    let cancel = CancelToken::new();
    let (frames, state, dropped) = Supervisor::spawn(
        Fake {
            script: script.into(),
            shared: Arc::clone(&shared),
            after,
        },
        InstantClock::new(),
        backoff,
        Fixed0,
        config,
        cancel.clone(),
    );
    Rig {
        frames,
        state,
        dropped,
        cancel,
        shared,
    }
}

fn rig(script: Vec<Attempt>, config: SupervisorConfig) -> Rig {
    rig_with(script, fail_open, Backoff::DEFAULT, config)
}

fn cfg() -> SupervisorConfig {
    SupervisorConfig::default()
}

fn is_backoff(s: &ConnectionState) -> bool {
    matches!(s, ConnectionState::Backoff { .. })
}

fn is_streaming(s: &ConnectionState) -> bool {
    matches!(s, ConnectionState::Streaming { .. })
}

impl Rig {
    async fn wait(&mut self, f: impl Fn(&ConnectionState) -> bool) -> ConnectionState {
        *self.state.wait_for(f).await.unwrap()
    }
    fn opens(&self) -> usize {
        self.shared.opens.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------------------------
// Round 5: the first-to-last stability rule, attacked from the edges
// ---------------------------------------------------------------------------------------------

/// Every state the watch reports within `horizon` of paused time; frames drained if `drain`.
async fn observe(r: &mut Rig, horizon: Duration, drain: bool) -> Vec<ConnectionState> {
    let end = Instant::now() + horizon;
    let mut seen = vec![*r.state.borrow_and_update()];
    loop {
        tokio::select! {
            changed = tokio::time::timeout_at(end, r.state.changed()) => match changed {
                Ok(Ok(())) => seen.push(*r.state.borrow_and_update()),
                _ => break,
            },
            Some(_) = r.frames.recv(), if drain => {}
        }
    }
    seen
}

fn any_degraded(seen: &[ConnectionState]) -> bool {
    seen.iter()
        .any(|s| matches!(s, ConnectionState::Degraded { .. }))
}

/// The `attempt` of every distinct Backoff entry, in order.
fn backoff_attempts(seen: &[ConnectionState]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut was = false;
    for s in seen {
        match s {
            ConnectionState::Backoff { outage, .. } => {
                if !was {
                    out.push(outage.attempt);
                }
                was = true;
            }
            _ => was = false,
        }
    }
    out
}

/// A keyframe, then one P frame a second for `secs` seconds, then `tail`.
fn frames_for(secs: u32, tail: Vec<Step>) -> Attempt {
    let mut steps = vec![Step::Frame(mk(1, true, Some(1), true))];
    for i in 0..secs {
        steps.push(Step::Sleep(Duration::from_secs(1)));
        steps.push(Step::Frame(mk(i + 2, false, None, false)));
    }
    steps.extend(tail);
    Attempt::Stream(steps)
}

fn silence_then_eof() -> Vec<Step> {
    vec![Step::Sleep(Duration::from_secs(9)), Step::Eof]
}

/// `min_stable == 0`: a single frame then an instant EOF is a stable stream, so every failure
/// starts a fresh outage (the discount must not turn "zero uptime" into "not stable").
#[tokio::test(start_paused = true)]
async fn a_zero_min_stable_makes_a_single_frame_session_stable() {
    let mut c = cfg();
    c.min_stable = DurationMs::from_millis(0);
    let mut r = rig_with(
        vec![],
        || Attempt::Stream(vec![Step::Frame(mk(1, true, Some(1), true)), Step::Eof]),
        Backoff::DEFAULT,
        c,
    );
    let seen = observe(&mut r, Duration::from_mins(10), true).await;
    let a = backoff_attempts(&seen);
    assert!(a.len() >= 10, "{a:?}");
    assert!(a.iter().all(|&n| n == 1), "{a:?}");
    assert!(!any_degraded(&seen));
    r.cancel.cancel();
}

/// Frames the supervisor drops because the consumer lags still prove the camera is up: 40 s of
/// frames into a full channel, then a hang ended by EOF, is a stable stream.
#[tokio::test(start_paused = true)]
async fn frames_dropped_for_a_lagging_consumer_still_count_as_uptime() {
    let mut c = cfg();
    c.channel_capacity = 1;
    let mut r = rig_with(
        vec![],
        || frames_for(40, silence_then_eof()),
        Backoff::DEFAULT,
        c,
    );
    let seen = observe(&mut r, Duration::from_mins(10), false).await;
    let a = backoff_attempts(&seen);
    assert!(a.len() >= 3, "{a:?}");
    assert!(a.iter().all(|&n| n == 1), "{a:?}");
    assert!(!any_degraded(&seen));
    assert!(r.dropped.get() > 100, "dropped {}", r.dropped.get());
    r.cancel.cancel();
}

/// The first state after the first `Streaming` that ends it.
fn after_first_stream(seen: &[ConnectionState]) -> Option<ConnectionState> {
    let i = seen.iter().position(is_streaming)?;
    seen.get(i..)?.iter().find(|s| !is_streaming(s)).copied()
}

/// A degraded camera whose stream then runs `secs` seconds and hangs until an EOF inside the
/// idle window.
fn degraded_then_stream(secs: u32) -> Rig {
    let mut c = cfg();
    c.budget = DurationMs::from_secs(10);
    let mut script: Vec<Attempt> = (0..8).map(|_| fail_open()).collect();
    script.push(frames_for(secs, silence_then_eof()));
    rig_with(script, fail_open, Backoff::DEFAULT, c)
}

/// Degraded, then 31 s of frames and a hang ended by EOF: recovered, so a fresh outage.
#[tokio::test(start_paused = true)]
async fn a_degraded_camera_recovers_through_a_stable_stream_ended_by_eof() {
    let mut r = degraded_then_stream(31);
    let seen = observe(&mut r, Duration::from_mins(10), true).await;
    let i = seen.iter().position(is_streaming).unwrap();
    assert!(
        any_degraded(seen.get(..i).unwrap()),
        "never degraded before streaming"
    );
    let next = after_first_stream(&seen);
    assert!(
        matches!(next, Some(ConnectionState::Backoff { outage, .. }) if outage.attempt == 1 && outage.degraded_since.is_none()),
        "{next:?}"
    );
    r.cancel.cancel();
}

/// Degraded, then 29 s of frames and a hang ended by EOF: not recovered, stays degraded with the
/// same `since`.
#[tokio::test(start_paused = true)]
async fn a_degraded_camera_with_29s_of_frames_then_eof_stays_degraded() {
    let mut r = degraded_then_stream(29);
    let seen = observe(&mut r, Duration::from_mins(10), true).await;
    let i = seen.iter().position(is_streaming).unwrap();
    let before = seen.get(..i).unwrap().iter().rev().find_map(|s| match s {
        ConnectionState::Degraded { since, .. } => Some(*since),
        _ => None,
    });
    assert!(before.is_some(), "never degraded before streaming");
    let next = after_first_stream(&seen);
    assert!(
        matches!(next, Some(ConnectionState::Degraded { since, .. }) if Some(since) == before),
        "{next:?} vs {before:?}"
    );
    r.cancel.cancel();
}

/// Two hours of a flapping camera (25 s of frames, a 9 s hang, EOF): it degrades, keeps
/// retrying to the end (liveness), never spins, and every open finds the old stream dropped.
#[tokio::test(start_paused = true)]
async fn two_hours_of_flapping_stays_live_bounded_and_drops_each_stream_first() {
    let mut r = rig_with(
        vec![],
        || frames_for(25, silence_then_eof()),
        Backoff::DEFAULT,
        cfg(),
    );
    let seen = observe(&mut r, Duration::from_hours(2), true).await;
    assert!(any_degraded(&seen));
    // Once degraded, never a Backoff again (no recovery: 25 s < min_stable).
    let d = seen
        .iter()
        .position(|s| matches!(s, ConnectionState::Degraded { .. }))
        .unwrap();
    assert!(
        !seen.get(d..).unwrap().iter().any(is_backoff),
        "left degraded"
    );
    let opens = r.shared.opens.lock().unwrap().clone();
    // One session is at least 34 s; the pauses add more. 2 h / 34 s = 211.
    assert!(opens.len() > 100 && opens.len() <= 212, "{}", opens.len());
    let last = *opens.last().unwrap();
    assert!(
        Instant::now().duration_since(last) < Duration::from_secs(60),
        "retries stopped"
    );
    assert!(
        r.shared
            .live_at_open
            .lock()
            .unwrap()
            .iter()
            .all(|&n| n == 0),
        "an open found the previous stream alive"
    );
    r.cancel.cancel();
}
