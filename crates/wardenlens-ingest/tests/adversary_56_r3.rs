//! Round-3 adversarial tests for the ingest `Supervisor` (#56), through the public API only.
//!
//! Every async test runs on tokio's paused clock (TEST-5).

#![allow(dead_code, reason = "shared rig helpers copied from adversary_56.rs")]
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
// Discontinuity and params

// ---------------------------------------------------------------------------------------------
// Round 3
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

/// A keyframe, then one P frame a second for `secs` seconds, then `tail`.
fn frames_for(secs: u32, tail: Step) -> Attempt {
    let mut steps = vec![Step::Frame(mk(1, true, Some(1), true))];
    for i in 0..secs {
        steps.push(Step::Sleep(Duration::from_secs(1)));
        steps.push(Step::Frame(mk(i + 2, false, None, false)));
    }
    steps.push(tail);
    Attempt::Stream(steps)
}

fn up_21s_then_stall() -> Attempt {
    frames_for(21, Step::Silent)
}

fn up_21s_then_eof() -> Attempt {
    frames_for(21, Step::Eof)
}

fn one_frame_then_stall() -> Attempt {
    frames_for(0, Step::Silent)
}

/// Control: with the defaults (`min_stable` 30 s, budget 180 s) a camera that delivers 21 s of
/// frames and then closes is not stable; the outage continues and the camera degrades.
#[tokio::test(start_paused = true)]
async fn a_camera_up_21s_then_eof_each_time_keeps_its_outage_and_degrades() {
    let mut r = rig_with(vec![], up_21s_then_eof, Backoff::DEFAULT, cfg());
    let seen = observe(&mut r, Duration::from_mins(15)).await;
    assert!(max_attempt(&seen) >= 2, "{seen:?}");
    assert!(any_degraded(&seen), "{seen:?}");
    r.cancel.cancel();
}

/// The same camera, but each session ends in a stall instead of an EOF. It still delivered
/// frames for only 21 s (< `min_stable` 30 s), so the outage must continue as in the EOF case.
/// The stall is only detected 10 s (idle timeout) after the last frame, and the supervisor
/// measures stability up to that detection, so 21 s of frames count as 31 s "up".
#[tokio::test(start_paused = true)]
async fn a_camera_up_21s_then_stalling_each_time_keeps_its_outage_and_degrades() {
    let mut r = rig_with(vec![], up_21s_then_stall, Backoff::DEFAULT, cfg());
    let seen = observe(&mut r, Duration::from_mins(15)).await;
    assert!(
        max_attempt(&seen) >= 2,
        "backoff reset after every 21 s session: {seen:?}"
    );
    assert!(any_degraded(&seen), "never degraded: {seen:?}");
    r.cancel.cancel();
}

/// With `idle_timeout >= min_stable` a camera that sends a single frame per session and then
/// stalls looks "stable" every time: the backoff never grows and the camera never degrades.
#[tokio::test(start_paused = true)]
async fn one_frame_per_session_is_never_stable_even_with_a_long_idle_timeout() {
    let mut c = cfg();
    c.idle_timeout = Duration::from_secs(30); // == the default min_stable
    let mut r = rig_with(vec![], one_frame_then_stall, Backoff::DEFAULT, c);
    let seen = observe(&mut r, Duration::from_mins(20)).await;
    assert!(
        max_attempt(&seen) >= 2,
        "one frame then silence reset the backoff: {seen:?}"
    );
    assert!(any_degraded(&seen), "never degraded: {seen:?}");
    r.cancel.cancel();
}

/// Owed params are paid once: after they ride on a keyframe, a later drop run without params
/// must not hand them out again.
#[tokio::test(start_paused = true)]
async fn owed_params_are_paid_once_not_again_after_a_later_drop() {
    let mut c = cfg();
    c.channel_capacity = 1;
    let start = Instant::now();
    let mut r = rig(
        vec![Attempt::Stream(vec![
            Step::Frame(mk(1, true, Some(1), true)),   // delivered
            Step::Frame(mk(2, false, Some(2), false)), // full: dropped, owes params 2
            Step::Sleep(Duration::from_secs(1)),
            Step::Frame(mk(3, true, None, false)), // delivered with params 2
            Step::Frame(mk(4, false, None, false)), // full: dropped, nothing owed
            Step::Sleep(Duration::from_secs(1)),
            Step::Frame(mk(5, true, None, false)), // delivered, no params
            Step::Silent,
        ])],
        c,
    );
    tokio::time::sleep_until(start + Duration::from_millis(500)).await;
    let f1 = r.frames.recv().await.unwrap();
    assert_eq!((f1.rtp_ts_90k, f1.discontinuity), (1, true));
    tokio::time::sleep_until(start + Duration::from_millis(1500)).await;
    let f3 = r.frames.recv().await.unwrap();
    assert_eq!(f3.rtp_ts_90k, 3);
    assert!(f3.discontinuity);
    assert_eq!(f3.params, Some(p(2)));
    tokio::time::sleep_until(start + Duration::from_millis(2500)).await;
    let f5 = r.frames.recv().await.unwrap();
    assert_eq!(f5.rtp_ts_90k, 5);
    assert!(f5.discontinuity);
    assert_eq!(f5.params, None, "params 2 were handed out twice");
    assert_eq!(r.dropped.get(), 2);
    r.cancel.cancel();
}

/// Degraded background retries are spaced by the jittered cap: `delay(u32::MAX)` with zero
/// jitter is 3 750 ms for the 2-5 s default.
#[tokio::test(start_paused = true)]
async fn degraded_retries_follow_the_jittered_cap() {
    let mut c = cfg();
    c.budget = DurationMs::from_millis(0);
    let r = rig(vec![], c);
    sleep(Duration::from_secs(40)).await;
    let opens = r.shared.opens.lock().unwrap().clone();
    assert!(opens.len() >= 5, "{}", opens.len());
    let want = Duration::from_millis(Backoff::DEFAULT.delay(u32::MAX, &mut Fixed0).as_millis());
    assert_eq!(want, Duration::from_millis(3_750));
    for w in opens.windows(2) {
        let gap = w[1] - w[0];
        assert!(
            gap >= want && gap <= want + Duration::from_millis(2),
            "{gap:?}"
        );
    }
    r.cancel.cancel();
}

/// Cancelling during the minimum pause between attempts (zero backoff, instant failures) stops
/// the task within a second.
#[tokio::test(start_paused = true)]
async fn cancelling_during_the_minimum_pause_stops_within_a_second() {
    let zero = Backoff::new(DurationMs::from_millis(0), DurationMs::from_millis(0));
    let mut r = rig_with(vec![], fail_open, zero, cfg());
    sleep(Duration::from_millis(1050)).await;
    let t = Instant::now();
    r.cancel.cancel();
    let closed = tokio::time::timeout(Duration::from_secs(1), async {
        while r.frames.recv().await.is_some() {}
        while r.state.changed().await.is_ok() {}
    })
    .await;
    assert!(closed.is_ok());
    assert!(t.elapsed() < Duration::from_secs(1));
    let n = r.opens();
    assert!((10..=12).contains(&n), "{n} opens in ~1 s");
}
