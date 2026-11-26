//! Round-2 adversarial tests for the ingest `Supervisor` (#56), through the public API only.
//!
//! Every async test runs on tokio's paused clock (TEST-5).

#![allow(dead_code, reason = "shared rig helpers copied from adversary_56.rs")]
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
// Round 2
// ---------------------------------------------------------------------------------------------

/// The config field says "at least 1 is used" and `# Panics` lists only "outside a runtime": a
/// large capacity must be clamped (or refused), not panic inside tokio's `mpsc::channel`.
#[tokio::test(start_paused = true)]
async fn a_huge_channel_capacity_does_not_panic_spawn() {
    for cap in [usize::MAX, (usize::MAX >> 3) + 1] {
        let mut c = cfg();
        c.channel_capacity = cap;
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rig(vec![Attempt::OpenHangs], c)
        }));
        assert!(got.is_ok(), "spawn panicked for channel_capacity {cap}");
        if let Ok(r) = got {
            r.cancel.cancel();
        }
    }
}

/// The largest capacity tokio accepts still works (boundary just below the panic).
#[tokio::test(start_paused = true)]
async fn the_largest_accepted_capacity_spawns_and_delivers() {
    let mut c = cfg();
    c.channel_capacity = usize::MAX >> 3;
    let mut r = rig(
        vec![Attempt::Stream(vec![
            Step::Frame(mk(1, true, Some(1), true)),
            Step::Silent,
        ])],
        c,
    );
    let f = tokio::time::timeout(Duration::from_secs(5), r.frames.recv()).await;
    assert_eq!(f.unwrap().unwrap().rtp_ts_90k, 1);
    r.cancel.cancel();
}

/// A `FrameSource` whose `next_frame` is always ready (nothing in the trait forbids it) must not
/// starve the runtime: another task on a current-thread runtime gets to cancel it long before the
/// source runs dry.
#[tokio::test(start_paused = true)]
async fn an_always_ready_source_cannot_starve_the_runtime() {
    struct Hot {
        produced: Arc<AtomicUsize>,
    }
    struct HotStream {
        produced: Arc<AtomicUsize>,
        frame: Frame,
    }
    impl StreamSource for Hot {
        type Stream = HotStream;
        fn open(
            &mut self,
            _idle: Duration,
        ) -> impl Future<Output = Result<HotStream, IngestError>> + Send {
            std::future::ready(Ok(HotStream {
                produced: Arc::clone(&self.produced),
                frame: mk(1, true, None, false),
            }))
        }
    }
    impl FrameSource for HotStream {
        async fn next_frame(&mut self) -> Result<Option<Frame>, IngestError> {
            if self.produced.fetch_add(1, Ordering::SeqCst) >= 50_000 {
                std::future::pending::<()>().await;
            }
            Ok(Some(self.frame.clone()))
        }
    }
    let produced = Arc::new(AtomicUsize::new(0));
    let cancel = CancelToken::new();
    let (_frames, _state, _dropped, handle) = Supervisor::spawn_joinable(
        Hot {
            produced: Arc::clone(&produced),
        },
        InstantClock::new(),
        Backoff::DEFAULT,
        Fixed0,
        cfg(),
        cancel.clone(),
    );
    let c2 = cancel.clone();
    let p2 = Arc::clone(&produced);
    let at_cancel = tokio::spawn(async move {
        let n = p2.load(Ordering::SeqCst);
        c2.cancel();
        n
    })
    .await
    .unwrap();
    handle.await.unwrap();
    assert!(
        at_cancel < 50_000,
        "the canceller only ran after the source was exhausted ({at_cancel} frames)"
    );
}

/// `min_stable` boundary: a stream that was up for exactly `min_stable` ends the outage (fresh
/// attempt 1); one up for 1 ms less continues it.
#[tokio::test(start_paused = true)]
async fn min_stable_is_inclusive_at_the_exact_boundary() {
    // The failed open makes attempt 1; a continued outage goes to 2, a fresh one restarts at 1.
    for (up_ms, want) in [(1_999_u64, 2_u32), (2_000, 1)] {
        let mut c = cfg();
        c.min_stable = DurationMs::from_millis(2_000);
        c.idle_timeout = Duration::from_secs(60);
        let mut r = rig(
            vec![
                fail_open(),
                Attempt::Stream(vec![
                    Step::Frame(mk(1, true, Some(1), true)),
                    Step::Sleep(Duration::from_millis(up_ms)),
                    Step::Eof,
                ]),
            ],
            c,
        );
        // Attempt 1 after the failed open.
        r.wait(|s| matches!(s, ConnectionState::Backoff { outage, .. } if outage.attempt == 1))
            .await;
        r.wait(is_streaming).await;
        let s = r.wait(is_backoff).await;
        let ConnectionState::Backoff { outage, .. } = s else {
            unreachable!()
        };
        assert_eq!(outage.attempt, want, "up for {up_ms} ms");
        r.cancel.cancel();
    }
}

/// `spawn_joinable`: dropping the frame receiver mid-session ends the task and frees the stream.
#[tokio::test(start_paused = true)]
async fn the_joinable_task_ends_when_the_receiver_is_dropped() {
    let shared = Arc::new(Shared::default());
    let (frames, _state, _d, handle) = Supervisor::spawn_joinable(
        Fake {
            script: vec![Attempt::Stream(vec![
                Step::Frame(mk(1, true, Some(1), true)),
                Step::Silent,
            ])]
            .into(),
            shared: Arc::clone(&shared),
            after: fail_open,
        },
        InstantClock::new(),
        Backoff::DEFAULT,
        Fixed0,
        cfg(),
        CancelToken::new(),
    );
    let mut frames = frames;
    tokio::time::timeout(Duration::from_secs(5), frames.recv())
        .await
        .unwrap()
        .unwrap();
    drop(frames);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .is_ok()
    );
    assert_eq!(shared.live.load(Ordering::SeqCst), 0);
}

/// Long multi-session simulation with a lagging consumer, mid-session parameter changes and
/// keyframes every 5 frames. Oracle: the consumer's view of the current params (last `Some`
/// received) always equals what the source had at that frame; any gap in ids is flagged as a
/// discontinuity; a gap inside a session lands on a keyframe; each session's first delivered
/// frame is a discontinuity.
#[tokio::test(start_paused = true)]
async fn a_lagging_consumer_over_many_sessions_never_sees_stale_params_or_a_silent_gap() {
    const SESSIONS: u32 = 25;
    const PER: u32 = 30;
    let mut c = cfg();
    c.channel_capacity = 2;
    let mut expected = std::collections::HashMap::<u32, (u8, u32, bool, bool)>::default();
    let mut script = Vec::new();
    let mut tag: u8 = 0;
    let mut seed: u64 = 7;
    for s in 0..SESSIONS {
        let mut steps = Vec::new();
        for j in 0..PER {
            let id = s * 1000 + j;
            let key = j % 5 == 0 || j == PER - 1;
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let change = j == 0 || (seed >> 33).is_multiple_of(7);
            if change {
                tag = tag.wrapping_add(1);
            }
            expected.insert(id, (tag, s, key, change));
            steps.push(Step::Frame(mk(id, key, change.then_some(tag), j == 0)));
            let gap = if j == PER - 2 {
                400
            } else {
                10 + (seed >> 40) % 15
            };
            steps.push(Step::Sleep(Duration::from_millis(gap)));
        }
        steps.push(Step::Eof);
        script.push(Attempt::Stream(steps));
    }
    let mut r = rig(script, c);
    let last = (SESSIONS - 1) * 1000 + PER - 1;
    let mut cur: Option<u8> = None;
    let mut prev: Option<u32> = None;
    let mut sessions_seen = 0;
    let mut owed_handed = 0;
    let mut gaps = 0;
    let deadline = Instant::now() + Duration::from_secs(3600);
    loop {
        assert!(Instant::now() < deadline, "the last frame never arrived");
        sleep(Duration::from_millis(35)).await;
        let f = match r.frames.try_recv() {
            Ok(f) => f,
            Err(TryRecvError::Empty) => continue,
            Err(TryRecvError::Disconnected) => panic!("closed"),
        };
        let id = f.rtp_ts_90k;
        let (want_tag, sess, key, own) = expected[&id];
        if f.params.is_some() && !own {
            owed_handed += 1;
        }
        if let Some(pp) = &f.params {
            cur = Some(pp.sps[1]);
        }
        let new_session = prev.is_none_or(|p| p / 1000 != sess);
        if new_session {
            sessions_seen += 1;
            assert!(f.discontinuity, "first delivered frame of session {sess}");
            assert!(f.params.is_some(), "session {sess} starts without params");
        } else if prev.is_some_and(|p| p + 1 != id) {
            gaps += 1;
            assert!(f.discontinuity, "gap before {id} not flagged");
            assert!(key, "gap inside session lands on non-keyframe {id}");
        }
        assert_eq!(cur, Some(want_tag), "stale params at {id}");
        prev = Some(id);
        if id == last {
            break;
        }
    }
    assert_eq!(sessions_seen, SESSIONS);
    assert!(r.dropped.get() > 0, "the consumer must actually lag");
    assert!(
        gaps > 0 && owed_handed > 0,
        "gaps {gaps}, owed params handed {owed_handed}"
    );
    r.cancel.cancel();
}
