//! Adversarial tests for the ingest `Supervisor` (#56), through the public API only.
//!
//! Every async test runs on tokio's paused clock: no real sleeps, no racing threads (TEST-5).
//! Frames are built through the public `FrameMapper`, because `Frame` is `#[non_exhaustive]`.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns; a panic fails the test"
)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc::error::TryRecvError;
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

/// A source's own mid-stream discontinuity (RTP loss) must survive the supervisor.
#[tokio::test(start_paused = true)]
async fn a_source_discontinuity_mid_stream_is_passed_through() {
    let mut r = rig(
        vec![Attempt::Stream(vec![
            Step::Frame(mk(1, true, Some(1), false)),
            Step::Frame(mk(2, false, None, false)),
            Step::Frame(mk(3, false, None, true)),
            Step::Frame(mk(4, false, None, false)),
            Step::Silent,
        ])],
        cfg(),
    );
    let got: Vec<bool> = [
        r.frames.recv().await.unwrap(),
        r.frames.recv().await.unwrap(),
        r.frames.recv().await.unwrap(),
        r.frames.recv().await.unwrap(),
    ]
    .iter()
    .map(|f| f.discontinuity)
    .collect();
    assert_eq!(got, vec![true, false, true, false]);
    r.cancel.cancel();
}

/// A keyframe dropped while the channel is full (and nothing was being dropped before) must hand
/// its params and a discontinuity to the next delivered keyframe.
#[tokio::test(start_paused = true)]
async fn a_dropped_keyframe_hands_params_and_discontinuity_to_the_next_keyframe() {
    let mut c = cfg();
    c.channel_capacity = 1;
    let mut r = rig(
        vec![Attempt::Stream(vec![
            Step::Frame(mk(1, true, Some(1), false)), // delivered, channel full
            Step::Frame(mk(2, true, Some(2), false)), // dropped: full
            Step::Sleep(Duration::from_secs(1)),      // the consumer reads here
            Step::Frame(mk(3, false, None, false)),   // dropped: waiting for a keyframe
            Step::Frame(mk(4, true, None, false)),    // delivered
            Step::Frame(mk(5, false, None, false)),   // delivered after the consumer reads
            Step::Silent,
        ])],
        c,
    );
    // Do not read until the supervisor sits in the scripted 1 s sleep, past the drop.
    r.wait(is_streaming).await;
    sleep(Duration::from_millis(500)).await;
    assert_eq!(r.dropped.get(), 1);
    let f1 = r.frames.recv().await.unwrap();
    assert_eq!(f1.rtp_ts_90k, 1);
    let f4 = r.frames.recv().await.unwrap();
    assert_eq!(f4.rtp_ts_90k, 4);
    assert!(f4.discontinuity);
    assert_eq!(f4.params, Some(p(2)));
    let f5 = r.frames.recv().await.unwrap();
    assert_eq!(f5.rtp_ts_90k, 5);
    assert!(!f5.discontinuity && f5.params.is_none());
    assert_eq!(r.dropped.get(), 2);
    r.cancel.cancel();
}

/// A delivered keyframe's own params are newer than params owed from earlier dropped frames.
#[tokio::test(start_paused = true)]
async fn a_keyframes_own_params_win_over_owed_ones() {
    let mut c = cfg();
    c.channel_capacity = 1;
    let mut r = rig(
        vec![Attempt::Stream(vec![
            Step::Frame(mk(1, true, Some(1), false)),
            Step::Frame(mk(2, false, Some(2), false)), // dropped, owes 2
            Step::Sleep(Duration::from_secs(1)),
            Step::Frame(mk(3, false, Some(3), false)), // dropped, owes 3
            Step::Frame(mk(4, true, Some(4), false)),  // own params 4
            Step::Silent,
        ])],
        c,
    );
    r.wait(is_streaming).await;
    sleep(Duration::from_millis(500)).await;
    assert_eq!(r.dropped.get(), 1);
    r.frames.recv().await.unwrap();
    let f = r.frames.recv().await.unwrap();
    assert_eq!(f.rtp_ts_90k, 4);
    assert_eq!(f.params, Some(p(4)));
    assert!(f.discontinuity);
    r.cancel.cancel();
}

/// Params owed by a frame dropped in session 1 must not be stamped onto a frame of session 2:
/// session 2 is a new RTSP session whose parameter sets are its own.
#[tokio::test(start_paused = true)]
async fn params_owed_by_an_old_session_do_not_leak_into_the_next() {
    let mut c = cfg();
    c.channel_capacity = 1;
    let mut r = rig(
        vec![
            Attempt::Stream(vec![
                Step::Frame(mk(1, true, Some(1), false)),  // delivered
                Step::Frame(mk(2, false, Some(9), false)), // dropped (full), owes params 9
                Step::Eof,
            ]),
            Attempt::Stream(vec![Step::Frame(mk(10, true, None, false)), Step::Silent]),
        ],
        c,
    );
    r.wait(is_backoff).await;
    assert_eq!(r.frames.recv().await.unwrap().rtp_ts_90k, 1);
    let f = r.frames.recv().await.unwrap();
    assert_eq!(f.rtp_ts_90k, 10);
    assert!(f.discontinuity);
    assert_eq!(
        f.params, None,
        "session 1's params were stamped on session 2's keyframe"
    );
    r.cancel.cancel();
}

/// Many short sessions with a reading consumer: each session's first frame, and only it, is a
/// discontinuity; nothing is dropped; no two streams are ever alive at once.
#[tokio::test(start_paused = true)]
async fn two_hundred_sessions_mark_exactly_their_first_frames() {
    const SESSIONS: u32 = 200;
    let script = (0..SESSIONS)
        .map(|s| {
            Attempt::Stream(vec![
                Step::Frame(mk(s * 10 + 1, true, Some(1), false)),
                Step::Frame(mk(s * 10 + 2, false, None, false)),
                Step::Frame(mk(s * 10 + 3, false, None, false)),
                Step::Eof,
            ])
        })
        .collect();
    let mut r = rig(script, cfg());
    for s in 0..SESSIONS {
        for i in 1..=3 {
            let f = r.frames.recv().await.unwrap();
            assert_eq!(f.rtp_ts_90k, s * 10 + i, "order");
            assert_eq!(f.discontinuity, i == 1, "session {s} frame {i}");
        }
    }
    assert_eq!(r.dropped.get(), 0);
    assert!(
        r.shared
            .live_at_open
            .lock()
            .unwrap()
            .iter()
            .all(|n| *n == 0)
    );
    r.cancel.cancel();
}

// ---------------------------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------------------------

/// Opened but silent is not streaming.
#[tokio::test(start_paused = true)]
async fn an_open_but_silent_stream_never_reports_streaming() {
    let mut r = rig(vec![Attempt::Stream(vec![Step::Silent])], cfg());
    sleep(Duration::from_secs(5)).await;
    assert_eq!(r.opens(), 1);
    assert!(
        matches!(*r.state.borrow(), ConnectionState::Connecting { .. }),
        "{:?}",
        *r.state.borrow()
    );
    let s = r
        .wait(|s| !matches!(s, ConnectionState::Connecting { .. }))
        .await;
    assert!(is_backoff(&s), "{s:?}");
    r.cancel.cancel();
}

/// Frames spaced just under the idle timeout keep one session up.
#[tokio::test(start_paused = true)]
async fn frames_just_inside_the_idle_timeout_keep_the_session() {
    let mut c = cfg();
    c.idle_timeout = Duration::from_secs(1);
    let mut steps = vec![Step::Frame(mk(1, true, Some(1), false))];
    for i in 2..30 {
        steps.push(Step::Sleep(Duration::from_millis(990)));
        steps.push(Step::Frame(mk(i, false, None, false)));
    }
    steps.push(Step::Silent);
    let mut r = rig(vec![Attempt::Stream(steps)], c);
    for _ in 1..30 {
        r.frames.recv().await.unwrap();
    }
    assert_eq!(r.opens(), 1);
    assert!(is_streaming(&r.state.borrow()));
    r.cancel.cancel();
}

/// Degraded, then a stream that stays up past `min_stable`: the next failure is a fresh outage
/// (Backoff attempt 1), not Degraded again.
#[tokio::test(start_paused = true)]
async fn a_degraded_camera_that_recovers_starts_a_fresh_outage() {
    let mut c = cfg();
    c.budget = DurationMs::from_secs(1);
    c.min_stable = DurationMs::from_secs(5);
    let mut r = rig(
        vec![
            fail_open(),
            fail_open(),
            Attempt::Stream(vec![
                Step::Frame(mk(1, true, Some(1), false)),
                Step::Sleep(Duration::from_secs(6)),
                Step::Frame(mk(2, false, None, false)),
                Step::Eof,
            ]),
        ],
        c,
    );
    r.wait(|s| matches!(s, ConnectionState::Degraded { .. }))
        .await;
    r.wait(is_streaming).await;
    let s = r.wait(|s| !is_streaming(s)).await;
    match s {
        ConnectionState::Backoff { outage, .. } => assert_eq!(outage.attempt, 1),
        other => panic!("expected a fresh backoff, got {other:?}"),
    }
    r.cancel.cancel();
}

// ---------------------------------------------------------------------------------------------
// Spinning and extreme configuration
// ---------------------------------------------------------------------------------------------

/// Streams that open and end at once, with a zero backoff: attempts stay at least 100 ms apart.
#[tokio::test(start_paused = true)]
async fn instant_eof_streams_with_zero_backoff_do_not_spin() {
    let zero = Backoff::new(DurationMs::from_millis(0), DurationMs::from_millis(0));
    let r = rig_with(vec![], || Attempt::Stream(vec![Step::Eof]), zero, cfg());
    sleep(Duration::from_secs(1)).await;
    let n = r.opens();
    assert!((9..=11).contains(&n), "{n} attempts in one second");
    r.cancel.cancel();
}

/// Streams that deliver one frame then end at once, zero backoff: no spin either.
#[tokio::test(start_paused = true)]
async fn one_frame_streams_with_zero_backoff_do_not_spin() {
    let zero = Backoff::new(DurationMs::from_millis(0), DurationMs::from_millis(0));
    let mut r = rig_with(
        vec![],
        || Attempt::Stream(vec![Step::Frame(mk(1, true, Some(1), false)), Step::Eof]),
        zero,
        cfg(),
    );
    sleep(Duration::from_secs(1)).await;
    let n = r.opens();
    assert!((9..=11).contains(&n), "{n} attempts in one second");
    // Every one of them was a discontinuity.
    while let Ok(f) = r.frames.try_recv() {
        assert!(f.discontinuity);
    }
    r.cancel.cancel();
}

/// A zero connect timeout with an open that hangs: every attempt times out at once, spaced.
#[tokio::test(start_paused = true)]
async fn a_zero_connect_timeout_does_not_spin() {
    let zero = Backoff::new(DurationMs::from_millis(0), DurationMs::from_millis(0));
    let mut c = cfg();
    c.connect_timeout = DurationMs::from_millis(0);
    let r = rig_with(vec![], || Attempt::OpenHangs, zero, c);
    sleep(Duration::from_secs(1)).await;
    let n = r.opens();
    assert!((9..=11).contains(&n), "{n} attempts in one second");
    r.cancel.cancel();
}

/// Maximal timeouts and backoff: no overflow panic kills the task; cancel still stops it.
#[tokio::test(start_paused = true)]
async fn maximal_timeouts_do_not_kill_the_task() {
    let mut c = cfg();
    c.idle_timeout = Duration::MAX;
    c.connect_timeout = DurationMs::from_millis(u64::MAX);
    c.min_stable = DurationMs::from_millis(u64::MAX);
    c.budget = DurationMs::from_millis(u64::MAX);
    let huge = Backoff::new(
        DurationMs::from_millis(u64::MAX),
        DurationMs::from_millis(u64::MAX),
    );
    let mut r = rig_with(
        vec![Attempt::Stream(vec![
            Step::Frame(mk(1, true, Some(1), false)),
            Step::Silent,
        ])],
        fail_open,
        huge,
        c,
    );
    r.frames.recv().await.unwrap();
    sleep(Duration::from_secs(3600)).await;
    assert!(matches!(r.frames.try_recv(), Err(TryRecvError::Empty)));
    assert!(is_streaming(&r.state.borrow()));
    r.cancel.cancel();
    assert!(r.frames.recv().await.is_none());
}

/// A maximal backoff: the task sits in Backoff without panicking and cancel still stops it.
#[tokio::test(start_paused = true)]
async fn a_maximal_backoff_waits_and_still_cancels() {
    let huge = Backoff::new(
        DurationMs::from_millis(u64::MAX),
        DurationMs::from_millis(u64::MAX),
    );
    let mut r = rig_with(vec![], fail_open, huge, cfg());
    r.wait(is_backoff).await;
    sleep(Duration::from_hours(24)).await;
    assert_eq!(r.opens(), 1);
    assert!(matches!(r.frames.try_recv(), Err(TryRecvError::Empty)));
    r.cancel.cancel();
    assert!(r.frames.recv().await.is_none());
}

// ---------------------------------------------------------------------------------------------
// Cancellation and receivers
// ---------------------------------------------------------------------------------------------

async fn state_closes(mut st: watch::Receiver<ConnectionState>) -> bool {
    tokio::time::timeout(Duration::from_secs(1), async {
        while st.changed().await.is_ok() {}
    })
    .await
    .is_ok()
}

#[tokio::test(start_paused = true)]
async fn dropping_the_frame_receiver_during_backoff_stops_the_task() {
    let mut r = rig(vec![], cfg());
    r.wait(is_backoff).await;
    let Rig {
        frames,
        state,
        shared,
        ..
    } = r;
    let before = shared.opens.lock().unwrap().len();
    drop(frames);
    assert!(state_closes(state).await);
    assert_eq!(shared.opens.lock().unwrap().len(), before);
}

#[tokio::test(start_paused = true)]
async fn dropping_the_frame_receiver_during_a_hanging_open_stops_the_task() {
    let r = rig(vec![Attempt::OpenHangs], cfg());
    sleep(Duration::from_secs(1)).await;
    let Rig { frames, state, .. } = r;
    drop(frames);
    assert!(state_closes(state).await);
}

/// The consumer reads frames but no longer watches the state: frames keep flowing.
#[tokio::test(start_paused = true)]
async fn dropping_only_the_state_receiver_keeps_frames_flowing() {
    let r = rig(
        vec![
            Attempt::Stream(vec![Step::Frame(mk(1, true, Some(1), false)), Step::Eof]),
            Attempt::Stream(vec![Step::Frame(mk(2, true, Some(1), false)), Step::Silent]),
        ],
        cfg(),
    );
    let Rig {
        mut frames,
        state,
        cancel,
        ..
    } = r;
    drop(state);
    assert_eq!(frames.recv().await.unwrap().rtp_ts_90k, 1);
    assert_eq!(frames.recv().await.unwrap().rtp_ts_90k, 2);
    cancel.cancel();
}

/// A flooding source with a consumer that never reads: cancel still stops it and frees the stream.
#[tokio::test(start_paused = true)]
async fn cancel_stops_a_flooding_source_with_a_stalled_consumer() {
    let mut c = cfg();
    c.channel_capacity = 4;
    let steps = (0..20_000)
        .map(|i| Step::Frame(mk(i, i % 25 == 0, None, false)))
        .chain([Step::Silent])
        .collect();
    let mut r = rig(vec![Attempt::Stream(steps)], c);
    r.wait(is_streaming).await;
    r.cancel.cancel();
    let t = Instant::now();
    let mut n = 0;
    while r.frames.recv().await.is_some() {
        n += 1;
    }
    assert!(n <= 4);
    assert!(t.elapsed() < Duration::from_secs(1));
    assert_eq!(r.shared.live.load(Ordering::SeqCst), 0);
}

/// Keyframe-wait from session 1 must not carry into session 2 once the consumer has caught up:
/// session 2's frames are not "dropped because the consumer lagged" (the counter's meaning), and
/// whether they are delivered must not depend on the previous session's channel history.
#[tokio::test(start_paused = true)]
async fn keyframe_wait_does_not_outlive_its_session() {
    let mut c = cfg();
    c.channel_capacity = 1;
    let mut r = rig(
        vec![
            Attempt::Stream(vec![
                Step::Frame(mk(1, true, Some(1), false)), // delivered
                Step::Frame(mk(2, false, None, false)),   // dropped (full): 1
                Step::Eof,
            ]),
            Attempt::Stream(vec![
                Step::Frame(mk(10, false, Some(2), false)),
                Step::Sleep(Duration::from_secs(1)),
                Step::Frame(mk(11, true, None, false)),
                Step::Silent,
            ]),
        ],
        c,
    );
    r.wait(is_backoff).await;
    assert_eq!(r.dropped.get(), 1);
    // The consumer catches up before session 2 starts.
    assert_eq!(r.frames.recv().await.unwrap().rtp_ts_90k, 1);
    let f = r.frames.recv().await.unwrap();
    assert_eq!(
        (f.rtp_ts_90k, r.dropped.get()),
        (10, 1),
        "session 2's first frame was dropped as lag although the channel was empty"
    );
    r.cancel.cancel();
}
