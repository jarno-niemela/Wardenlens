//! Round-4 adversarial tests for the ingest `Supervisor` (#56), through the public API only.
//!
//! Every async test runs on tokio's paused clock (TEST-5).

#![expect(
    dead_code,
    reason = "shared rig helpers copied from adversary_56_r3.rs"
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
// Round 4: stability is judged from the first frame to the last, for every way a session ends
// ---------------------------------------------------------------------------------------------

/// Every state the watch reports within `horizon` of paused time, frames drained as they come.
async fn observe(r: &mut Rig, horizon: Duration) -> Vec<ConnectionState> {
    let end = Instant::now() + horizon;
    let mut seen = vec![*r.state.borrow_and_update()];
    loop {
        tokio::select! {
            changed = tokio::time::timeout_at(end, r.state.changed()) => match changed {
                Ok(Ok(())) => seen.push(*r.state.borrow_and_update()),
                _ => break,
            },
            Some(_) = r.frames.recv() => {}
        }
    }
    seen
}

fn max_attempt(seen: &[ConnectionState]) -> u32 {
    seen.iter()
        .filter_map(|s| match s {
            ConnectionState::Backoff { outage, .. } => Some(outage.attempt),
            _ => None,
        })
        .max()
        .unwrap_or(0)
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

fn silent_9s_then_eof() -> Attempt {
    frames_for(21, vec![Step::Sleep(Duration::from_secs(9)), Step::Eof])
}

fn silent_9s_then_reset() -> Attempt {
    frames_for(
        21,
        vec![
            Step::Sleep(Duration::from_secs(9)),
            Step::Err(IngestError::StreamFailed),
        ],
    )
}

fn up_21s_then_source_frame_timeout() -> Attempt {
    frames_for(
        21,
        vec![
            Step::Sleep(Duration::from_secs(9)),
            Step::Err(IngestError::FrameTimeout),
        ],
    )
}

fn up_29s_then_stall() -> Attempt {
    frames_for(29, vec![Step::Silent])
}

fn up_30s_then_stall() -> Attempt {
    frames_for(30, vec![Step::Silent])
}

fn opens_then_stalls() -> Attempt {
    Attempt::Stream(vec![Step::Silent])
}

/// A camera whose stream hangs and whose RTSP server then closes the connection 9 s later
/// (inside the 10 s idle timeout). It delivered frames for only 21 s, less than `min_stable`, so
/// the outage must continue, exactly as for a hang detected by the idle timeout.
#[tokio::test(start_paused = true)]
async fn a_hang_ended_by_eof_inside_the_idle_window_is_not_uptime() {
    let mut r = rig_with(vec![], silent_9s_then_eof, Backoff::DEFAULT, cfg());
    let seen = observe(&mut r, Duration::from_mins(15)).await;
    assert!(
        max_attempt(&seen) >= 2,
        "backoff reset after 21 s of frames: {:?}",
        backoff_attempts(&seen)
    );
    assert!(any_degraded(&seen), "never degraded");
    r.cancel.cancel();
}

/// The same hang ended by a connection reset (`StreamFailed`).
#[tokio::test(start_paused = true)]
async fn a_hang_ended_by_a_reset_inside_the_idle_window_is_not_uptime() {
    let mut r = rig_with(vec![], silent_9s_then_reset, Backoff::DEFAULT, cfg());
    let seen = observe(&mut r, Duration::from_mins(15)).await;
    assert!(
        max_attempt(&seen) >= 2,
        "backoff reset after 21 s of frames: {:?}",
        backoff_attempts(&seen)
    );
    assert!(any_degraded(&seen), "never degraded");
    r.cancel.cancel();
}

/// A source that reports `FrameTimeout` itself (before the supervisor's own idle timer).
#[tokio::test(start_paused = true)]
async fn a_source_reported_frame_timeout_is_not_uptime() {
    let mut r = rig_with(
        vec![],
        up_21s_then_source_frame_timeout,
        Backoff::DEFAULT,
        cfg(),
    );
    let seen = observe(&mut r, Duration::from_mins(15)).await;
    assert!(max_attempt(&seen) >= 2, "{:?}", backoff_attempts(&seen));
    assert!(any_degraded(&seen));
    let last_kind = seen.iter().rev().find_map(|s| match s {
        ConnectionState::Degraded {
            last_error_kind, ..
        } => Some(*last_error_kind),
        _ => None,
    });
    assert_eq!(
        last_kind,
        Some(wardenlens_core::connection::FailureKind::Timeout)
    );
    r.cancel.cancel();
}

/// Boundary below: 29 s of frames then a stall continues the outage.
#[tokio::test(start_paused = true)]
async fn twenty_nine_seconds_of_frames_then_a_stall_continue_the_outage() {
    let mut r = rig_with(vec![], up_29s_then_stall, Backoff::DEFAULT, cfg());
    let seen = observe(&mut r, Duration::from_mins(10)).await;
    let a = backoff_attempts(&seen);
    assert!(a.len() >= 3, "{a:?}");
    assert_eq!(&a[..3], &[1, 2, 3], "{a:?}");
    r.cancel.cancel();
}

/// Boundary at: 30 s of frames (== `min_stable`) then a stall is a stable stream: every failure
/// starts a fresh outage, so the camera never degrades (the discount must not over-discount).
#[tokio::test(start_paused = true)]
async fn thirty_seconds_of_frames_then_a_stall_reset_the_outage() {
    let mut r = rig_with(vec![], up_30s_then_stall, Backoff::DEFAULT, cfg());
    let seen = observe(&mut r, Duration::from_mins(10)).await;
    let a = backoff_attempts(&seen);
    assert!(a.len() >= 3, "{a:?}");
    assert!(a.iter().all(|&n| n == 1), "{a:?}");
    assert!(!any_degraded(&seen));
    r.cancel.cancel();
}

/// A camera that opens and never sends a frame: no `Streaming`, the outage grows, and it
/// degrades with `Timeout`.
#[tokio::test(start_paused = true)]
async fn a_stall_with_zero_frames_never_streams_and_degrades() {
    let mut r = rig_with(vec![], opens_then_stalls, Backoff::DEFAULT, cfg());
    let seen = observe(&mut r, Duration::from_mins(10)).await;
    assert!(!seen.iter().any(is_streaming));
    assert!(max_attempt(&seen) >= 2);
    assert!(any_degraded(&seen));
    r.cancel.cancel();
}

/// Once degraded, a camera that streams 21 s and stalls each time stays degraded with the same
/// `since`: the discount never turns a degraded camera into a fresh outage.
#[tokio::test(start_paused = true)]
async fn a_degraded_camera_that_streams_briefly_stays_degraded() {
    let mut c = cfg();
    c.budget = DurationMs::from_millis(0);
    let mut r = rig_with(
        vec![Attempt::OpenFails(IngestError::OpenFailed)],
        || frames_for(21, vec![Step::Silent]),
        Backoff::DEFAULT,
        c,
    );
    let seen = observe(&mut r, Duration::from_mins(10)).await;
    assert!(seen.iter().any(is_streaming));
    assert!(!seen.iter().any(is_backoff), "left degraded: {seen:?}");
    let sinces: Vec<_> = seen
        .iter()
        .filter_map(|s| match s {
            ConnectionState::Degraded { since, .. } => Some(*since),
            _ => None,
        })
        .collect();
    assert!(sinces.windows(2).all(|w| w[0] == w[1]), "{sinces:?}");
    r.cancel.cancel();
}
