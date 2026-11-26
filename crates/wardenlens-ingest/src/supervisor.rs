//! [`Supervisor`]: keeps one camera stream connected and reports its [`ConnectionState`].
//!
//! The supervisor owns a [`StreamSource`] (the retina session, [`RetinaSource`], or a fake). It
//! opens the source, forwards frames into a bounded channel, and on EOF, an error or a read-idle
//! timeout it **drops the old stream first** (so retina's buffered assembly is freed, ADR 0002
//! accepted risk 12) and then reconnects after the core [`Backoff`] delay.
//!
//! # Discontinuity
//!
//! The ticket asks for a "Discontinuity marker" after a reconnect. [`Frame::discontinuity`]
//! already means "frames may be missing before this one" and the recorder closes its segment on
//! it (ADR 0005, the #55 row), so no second marker is invented: the supervisor sets that flag on
//! the first frame of every session, and on the first frame delivered after frames were dropped
//! because the consumer lagged.
//!
//! # Connection state
//!
//! The state is driven by the pure core [`transition`] on a monotonic clock. `Connected` is sent
//! when the first frame of a session arrives, not when the session opens, so a camera that opens
//! and then stays silent never shows as streaming. "Successful" for the backoff reset is the core
//! rule: a stream that stayed up for `min_stable` ends the outage; a drop before then continues
//! it, so a camera that flaps keeps its grown delay. Only [`FailureKind`]s enter the state; the
//! error text of a camera never does ([`failure_kind`]).
//!
//! # Backpressure and memory
//!
//! The channel holds at most `channel_capacity` frames (at most [`MAX_FRAME_BYTES`] each) and the
//! supervisor holds at most one more. When it is full the frame is dropped and counted, and so is
//! every non-keyframe after it, until a keyframe fits; that keyframe carries `discontinuity`. A
//! dropped frame's parameter sets are kept and handed to the next delivered frame.

use std::future::Future;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout};
use wardenlens_core::camera::{Credential, Host, RtspPath};
use wardenlens_core::catalogue::StreamRole;
use wardenlens_core::connection::{Backoff, JitterSource};
use wardenlens_core::connection::{
    ConnectionPolicy, ConnectionState, Event, FailureKind, transition,
};
use wardenlens_core::time::{Clock, DurationMs, MonoMs, MonotonicClock};

use crate::error::IngestError;
use crate::frame::{Frame, H264Params};
use crate::session::{FRAME_TIMEOUT, FrameStream, open_stream};

/// Shortest idle timeout and reconnect pause the supervisor accepts. A smaller configured value
/// is raised to it, so a zero cannot turn the reconnect loop into a busy loop.
const MIN_PAUSE: Duration = Duration::from_millis(MIN_PAUSE_MS);
const MIN_PAUSE_MS: u64 = 100;

/// Largest channel capacity accepted; a bigger one is lowered to it. With the 8 MiB frame cap
/// this bounds the channel to 8 GiB in the (absurd) worst case, and keeps `spawn` clear of
/// tokio's own limit, which panics.
pub const MAX_CHANNEL_CAPACITY: usize = 1024;

/// Default channel capacity, in frames. Worst case memory is this times [`MAX_FRAME_BYTES`]
/// (typical frames are a small fraction of that); lower it for many cameras.
///
/// [`MAX_FRAME_BYTES`]: crate::MAX_FRAME_BYTES
const DEFAULT_CHANNEL_CAPACITY: usize = 64;

/// An open stream of frames.
pub trait FrameSource: Send + 'static {
    /// The next frame, `Ok(None)` at a clean end. After an error or end the supervisor drops the
    /// stream and never calls this again.
    fn next_frame(&mut self) -> impl Future<Output = Result<Option<Frame>, IngestError>> + Send;
}

/// Something that can open a [`FrameSource`], again and again.
pub trait StreamSource: Send + 'static {
    /// The stream this source opens.
    type Stream: FrameSource;

    /// Opens a new session. `idle_timeout` is the supervisor's read-idle limit; the supervisor
    /// enforces it itself, a source may use it to fail sooner.
    fn open(
        &mut self,
        idle_timeout: Duration,
    ) -> impl Future<Output = Result<Self::Stream, IngestError>> + Send;
}

impl<C: Clock + Send + 'static> FrameSource for FrameStream<C> {
    fn next_frame(&mut self) -> impl Future<Output = Result<Option<Frame>, IngestError>> + Send {
        FrameStream::next_frame(self)
    }
}

/// The retina session of [`open_stream`] as a [`StreamSource`].
pub struct RetinaSource<C> {
    host: Host,
    port: NonZeroU16,
    path: RtspPath,
    credential: Option<Credential>,
    role: StreamRole,
    clock: C,
}

impl<C> RetinaSource<C> {
    /// A source for one stream of one camera. `clock` stamps frame arrival times.
    pub fn new(
        host: Host,
        port: NonZeroU16,
        path: RtspPath,
        credential: Option<Credential>,
        role: StreamRole,
        clock: C,
    ) -> Self {
        Self {
            host,
            port,
            path,
            credential,
            role,
            clock,
        }
    }
}

impl<C: Clock + Clone + Send + 'static> StreamSource for RetinaSource<C> {
    type Stream = FrameStream<C>;

    async fn open(&mut self, idle_timeout: Duration) -> Result<Self::Stream, IngestError> {
        let stream = open_stream(
            &self.host,
            self.port,
            &self.path,
            self.credential.as_ref(),
            self.role,
            self.clock.clone(),
        )
        .await?;
        Ok(stream.with_frame_timeout(idle_timeout))
    }
}

/// A cancellation token: clone it, hand a clone to the supervisor, call [`CancelToken::cancel`].
#[derive(Clone)]
pub struct CancelToken(Arc<watch::Sender<bool>>);

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    /// A token that is not cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(watch::channel(false).0))
    }

    /// Cancels every clone. Idempotent.
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }

    /// Whether [`CancelToken::cancel`] was called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Completes once the token is cancelled.
    pub async fn cancelled(&self) {
        let mut rx = self.0.subscribe();
        // The sender lives in `self`, so this cannot see a closed channel.
        let _ = rx.wait_for(|c| *c).await;
    }
}

/// A monotonic clock over tokio's time (so paused test time moves it), zero when created.
#[derive(Debug, Clone, Copy)]
pub struct InstantClock(Instant);

impl InstantClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for InstantClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for InstantClock {
    fn now(&self) -> MonoMs {
        let ms = self.0.elapsed().as_millis();
        MonoMs::from_millis(u64::try_from(ms).unwrap_or(u64::MAX))
    }
}

/// `SplitMix64`: the backoff jitter. Seed it from anything that differs per camera.
#[derive(Debug, Clone, Copy)]
pub struct SplitMixJitter(u64);

impl SplitMixJitter {
    /// A generator from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl JitterSource for SplitMixJitter {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// How many frames were dropped because the consumer lagged. Clone it to read from anywhere.
#[derive(Debug, Clone, Default)]
pub struct DroppedFrames(Arc<AtomicU64>);

impl DroppedFrames {
    /// Frames dropped so far (not counting frames the source itself dropped as oversize).
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn add(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Supervisor settings. Build with [`SupervisorConfig::default`] and change fields.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SupervisorConfig {
    /// Reconnect when no frame arrives for this long. Default [`FRAME_TIMEOUT`] (10 s); at least
    /// 100 ms is used.
    pub idle_timeout: Duration,
    /// Frames the channel holds. Clamped to `1..=`[`MAX_CHANNEL_CAPACITY`].
    pub channel_capacity: usize,
    /// Time from the first failure of an outage after which the state is `Degraded`.
    pub budget: DurationMs,
    /// How long a stream must stay up for the backoff to reset.
    pub min_stable: DurationMs,
    /// How long opening may take. At least 100 ms is used (the same floor as `idle_timeout`
    /// and the pause between attempts).
    pub connect_timeout: DurationMs,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        let p = ConnectionPolicy::DEFAULT;
        Self {
            idle_timeout: FRAME_TIMEOUT,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            budget: p.budget,
            min_stable: p.min_stable,
            connect_timeout: p.connect_timeout,
        }
    }
}

/// Maps an ingest error to the kind that may enter the connection state. Nothing else of the
/// error (not even an RTSP status) crosses.
#[must_use]
pub fn failure_kind(e: &IngestError) -> FailureKind {
    match e {
        IngestError::OpenTimeout | IngestError::FrameTimeout => FailureKind::Timeout,
        IngestError::OpenFailed => FailureKind::Refused,
        IngestError::AuthRejected => FailureKind::Auth,
        IngestError::Rejected(_)
        | IngestError::NoVideoStream
        | IngestError::UnsupportedCodec
        | IngestError::Map(_) => FailureKind::Protocol,
        IngestError::InvalidUrl | IngestError::StreamFailed => FailureKind::Other,
    }
}

/// Entry point; see the module docs.
#[derive(Debug, Clone, Copy)]
pub struct Supervisor;

impl Supervisor {
    /// Starts the supervisor task on the current tokio runtime.
    ///
    /// Returns the frame channel, the connection state and the dropped-frame counter. The task
    /// ends, closing both channels and dropping any open stream, when `cancel` is cancelled
    /// (within one poll, so well inside a second) or when the frame receiver is dropped.
    /// `clock` times the state machine, `backoff` spaces reconnects and `jitter` randomizes them.
    ///
    /// The task is detached; use [`Supervisor::spawn_joinable`] to await its teardown.
    ///
    /// # Panics
    /// Panics if called outside a tokio runtime (it uses `tokio::spawn`).
    #[must_use]
    pub fn spawn<S, M, J>(
        source: S,
        clock: M,
        backoff: Backoff,
        jitter: J,
        config: SupervisorConfig,
        cancel: CancelToken,
    ) -> (
        mpsc::Receiver<Frame>,
        watch::Receiver<ConnectionState>,
        DroppedFrames,
    )
    where
        S: StreamSource,
        M: MonotonicClock + Send + 'static,
        J: JitterSource + Send + 'static,
    {
        let (frames, state, dropped, _task) =
            Self::spawn_joinable(source, clock, backoff, jitter, config, cancel);
        (frames, state, dropped)
    }

    /// Like [`Supervisor::spawn`], and also returns the task's handle: after cancelling, awaiting
    /// it returns once the stream is dropped and the task has ended.
    ///
    /// # Panics
    /// Panics if called outside a tokio runtime (it uses `tokio::spawn`).
    #[must_use]
    pub fn spawn_joinable<S, M, J>(
        source: S,
        clock: M,
        backoff: Backoff,
        jitter: J,
        config: SupervisorConfig,
        cancel: CancelToken,
    ) -> (
        mpsc::Receiver<Frame>,
        watch::Receiver<ConnectionState>,
        DroppedFrames,
        tokio::task::JoinHandle<()>,
    )
    where
        S: StreamSource,
        M: MonotonicClock + Send + 'static,
        J: JitterSource + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(config.channel_capacity.clamp(1, MAX_CHANNEL_CAPACITY));
        let (state_tx, state_rx) = watch::channel(ConnectionState::INITIAL);
        let dropped = DroppedFrames::default();
        let task = Task {
            source,
            clock,
            jitter,
            policy: ConnectionPolicy {
                backoff,
                budget: config.budget,
                min_stable: config.min_stable,
                connect_timeout: config
                    .connect_timeout
                    .max(DurationMs::from_millis(MIN_PAUSE_MS)),
            },
            idle: config.idle_timeout.max(MIN_PAUSE),
            tx,
            state_tx,
            state: ConnectionState::INITIAL,
            cancel,
            dropped: dropped.clone(),
            pacer: Pacer::default(),
        };
        let handle = tokio::spawn(task.run());
        (rx, state_rx, dropped, handle)
    }
}

/// Why a session ended.
enum Ended {
    /// Stop the whole task.
    Stop,
    /// Reconnect after this failure.
    Failed(FailureKind),
}

/// The delivery bookkeeping that outlives one frame.
#[derive(Default)]
struct Pacer {
    /// Frames were dropped (or a session began): the next delivered frame is a discontinuity.
    pending_discontinuity: bool,
    /// Frames are being dropped until the next keyframe.
    dropping: bool,
    /// Parameter sets of a dropped frame, owed to the next delivered one.
    owed_params: Option<H264Params>,
}

struct Task<S, M, J> {
    source: S,
    clock: M,
    jitter: J,
    policy: ConnectionPolicy,
    idle: Duration,
    tx: mpsc::Sender<Frame>,
    state_tx: watch::Sender<ConnectionState>,
    state: ConnectionState,
    cancel: CancelToken,
    dropped: DroppedFrames,
    pacer: Pacer,
}

impl<S: StreamSource, M: MonotonicClock, J: JitterSource> Task<S, M, J> {
    async fn run(mut self) {
        let mut last_attempt: Option<Instant> = None;
        loop {
            if !self.wait_until_connecting().await {
                return;
            }
            // A zero backoff must not make a failing source spin: attempts are at least
            // MIN_PAUSE apart (never binds with the 2 s default).
            if let Some(at) = last_attempt {
                tokio::select! {
                    () = self.cancel.cancelled() => return,
                    () = self.tx.closed() => return,
                    () = tokio::time::sleep_until(at.checked_add(MIN_PAUSE).unwrap_or(at)) => {}
                }
            }
            last_attempt = Some(Instant::now());
            let failure = match self.session().await {
                Ended::Stop => return,
                Ended::Failed(kind) => kind,
            };
            // The stream was dropped inside `session`, before this backoff starts.
            self.apply(Event::Failed(failure));
        }
    }

    fn apply(&mut self, event: Event) {
        let next = transition(
            self.state,
            event,
            self.clock.now(),
            &self.policy,
            &mut self.jitter,
        );
        self.state = next;
        self.state_tx.send_if_modified(|s| {
            if *s == next {
                false
            } else {
                *s = next;
                true
            }
        });
    }

    /// Sleeps through `Backoff` and `Degraded` until the state machine says to connect again.
    /// `false` when cancelled or when nobody watches any more.
    async fn wait_until_connecting(&mut self) -> bool {
        loop {
            self.apply(Event::Tick);
            let due = match self.state {
                ConnectionState::Backoff { until, .. } => until,
                ConnectionState::Degraded { next_retry, .. } => next_retry,
                _ => return !self.cancel.is_cancelled(),
            };
            let remaining = due.saturating_duration_since(self.clock.now()).as_millis();
            // At least 1 ms, so a clock that does not move cannot spin this loop.
            let wait = Duration::from_millis(remaining.max(1));
            tokio::select! {
                () = self.cancel.cancelled() => return false,
                () = self.tx.closed() => return false,
                () = sleep(wait) => {}
            }
        }
    }

    /// One connection attempt and, if it opens, the stream that follows. The stream is dropped
    /// before this returns.
    async fn session(&mut self) -> Ended {
        let limit = Duration::from_millis(self.policy.connect_timeout.as_millis());
        let idle = self.idle;
        let opened = tokio::select! {
            () = self.cancel.cancelled() => return Ended::Stop,
            () = self.tx.closed() => return Ended::Stop,
            r = timeout(limit, self.source.open(idle)) => r,
        };
        let mut stream = match opened {
            Err(_) => return Ended::Failed(FailureKind::Timeout),
            Ok(Err(e)) => return Ended::Failed(failure_kind(&e)),
            Ok(Ok(stream)) => stream,
        };
        // Nothing owed or being dropped crosses a reconnect: the new session starts clean and
        // its first frame is a discontinuity.
        self.pacer = Pacer {
            pending_discontinuity: true,
            ..Pacer::default()
        };
        let mut first = true;
        loop {
            let item = tokio::select! {
                () = self.cancel.cancelled() => return Ended::Stop,
                () = self.tx.closed() => return Ended::Stop,
                r = timeout(idle, stream.next_frame()) => r,
            };
            let frame = match item {
                Err(_) => return Ended::Failed(FailureKind::Timeout),
                Ok(Err(e)) => return Ended::Failed(failure_kind(&e)),
                Ok(Ok(None)) => return Ended::Failed(FailureKind::Other),
                Ok(Ok(Some(frame))) => frame,
            };
            if first {
                first = false;
                self.apply(Event::Connected);
            } else {
                self.apply(Event::Tick);
            }
            if !self.deliver(frame) {
                return Ended::Stop;
            }
            // An always-ready source must not starve the runtime (cancel included).
            tokio::task::consume_budget().await;
        }
    }

    /// Hands a frame to the consumer or drops it. `false` when the consumer is gone.
    fn deliver(&mut self, mut frame: Frame) -> bool {
        let p = &mut self.pacer;
        if p.dropping && !frame.is_keyframe {
            self.dropped.add();
            if frame.params.is_some() {
                p.owed_params = frame.params.take();
            }
            return true;
        }
        frame.discontinuity |= p.pending_discontinuity || p.dropping;
        if frame.params.is_none() {
            frame.params = p.owed_params.take();
        }
        match self.tx.try_send(frame) {
            Ok(()) => {
                p.dropping = false;
                p.pending_discontinuity = false;
                p.owed_params = None;
                true
            }
            Err(TrySendError::Closed(_)) => false,
            Err(TrySendError::Full(mut frame)) => {
                self.dropped.add();
                p.dropping = true;
                p.pending_discontinuity = true;
                // Keep what the dropped frame carried that the next one must not lose.
                if frame.params.is_some() {
                    p.owed_params = frame.params.take();
                }
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::arithmetic_side_effects,
        reason = "test-only time arithmetic on small values"
    )]

    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use tokio::sync::Notify;
    use wardenlens_core::time::Timestamp;

    use super::*;

    /// Always returns the same value: `Backoff::delay(0, ..)` is then 2000 ms, attempt 1 is 3000.
    struct Fixed0;
    impl JitterSource for Fixed0 {
        fn next_u64(&mut self) -> u64 {
            0
        }
    }

    fn frame(key: bool) -> Frame {
        Frame {
            data: vec![0, 0, 0, 1, 0x65],
            is_keyframe: key,
            rtp_ts_90k: 0,
            arrival: Timestamp::from_unix_millis(1_700_000_000_000),
            params: None,
            discontinuity: false,
        }
    }

    fn params(tag: u8) -> H264Params {
        H264Params {
            sps: vec![0x67, tag],
            pps: vec![0x68, tag],
        }
    }

    enum Step {
        Frame(Frame),
        Sleep(Duration),
        Err(IngestError),
        Gate(Arc<Notify>),
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
            match self.script.pop_front() {
                // An exhausted script keeps failing, so the supervisor keeps backing off.
                None => Err(IngestError::OpenFailed),
                Some(Attempt::OpenFails(e)) => Err(e),
                Some(Attempt::OpenHangs) => std::future::pending().await,
                Some(Attempt::Stream(steps)) => {
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
            // Lets the runtime run other tasks; a real socket read does the same.
            tokio::task::yield_now().await;
            loop {
                match self.steps.pop_front() {
                    Some(Step::Frame(f)) => return Ok(Some(f)),
                    Some(Step::Sleep(d)) => sleep(d).await,
                    Some(Step::Err(e)) => return Err(e),
                    Some(Step::Gate(n)) => n.notified().await,
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
        t0: Instant,
    }

    fn rig(script: Vec<Attempt>, config: SupervisorConfig) -> Rig {
        let shared = Arc::new(Shared::default());
        let cancel = CancelToken::new();
        let t0 = Instant::now();
        let (frames, state, dropped) = Supervisor::spawn(
            Fake {
                script: script.into(),
                shared: Arc::clone(&shared),
            },
            InstantClock::new(),
            Backoff::DEFAULT,
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
            t0,
        }
    }

    impl Rig {
        async fn wait_state(&mut self, want: impl Fn(&ConnectionState) -> bool) -> ConnectionState {
            *self.state.wait_for(want).await.unwrap()
        }

        fn opens(&self) -> Vec<Instant> {
            self.shared.opens.lock().unwrap().clone()
        }
    }

    fn is_streaming(s: &ConnectionState) -> bool {
        matches!(s, ConnectionState::Streaming { .. })
    }

    fn backoff_attempt(s: &ConnectionState) -> Option<u32> {
        match s {
            ConnectionState::Backoff { outage, .. } => Some(outage.attempt),
            _ => None,
        }
    }

    fn expected_delay(attempt: u32) -> Duration {
        let ms = Backoff::DEFAULT.delay(attempt, &mut Fixed0).as_millis();
        Duration::from_millis(ms)
    }

    fn near(actual: Duration, want: Duration) {
        assert!(
            actual >= want && actual <= want + Duration::from_millis(2),
            "{actual:?} vs {want:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fail_twice_stream_go_silent_then_eof_follows_the_core_backoff() {
        let mut r = rig(
            vec![
                Attempt::OpenFails(IngestError::OpenFailed),
                Attempt::OpenFails(IngestError::AuthRejected),
                Attempt::Stream(vec![
                    Step::Frame(frame(true)),
                    Step::Frame(frame(false)),
                    Step::Silent,
                ]),
                Attempt::Stream(vec![Step::Frame(frame(true)), Step::Eof]),
            ],
            SupervisorConfig::default(),
        );
        assert_eq!(*r.state.borrow(), ConnectionState::INITIAL);

        // Two failed opens, then a stream. The first frame says Connected.
        let s = r.wait_state(is_streaming).await;
        let ConnectionState::Streaming { prior: Some(o), .. } = s else {
            panic!("expected an outage to be remembered: {s:?}");
        };
        assert_eq!(o.attempt, 2);
        let first = r.frames.recv().await.unwrap();
        assert!(first.is_keyframe && first.discontinuity);
        let second = r.frames.recv().await.unwrap();
        assert!(!second.discontinuity);

        // Silent for the idle timeout (10 s), then a backoff, then a reconnect.
        let t_silent = Instant::now();
        let s = r.wait_state(|s| backoff_attempt(s).is_some()).await;
        near(t_silent.elapsed(), FRAME_TIMEOUT);
        // The stream was only up for 0 s: still the same outage, attempt 2 -> 3.
        assert_eq!(backoff_attempt(&s), Some(3));

        let again = r.frames.recv().await.unwrap();
        assert!(again.discontinuity, "first frame after a reconnect");
        // The scripted EOF, then the script runs out and every open fails.
        r.wait_state(|s| backoff_attempt(s).is_some_and(|a| a >= 4))
            .await;

        let opens = r.opens();
        assert!(opens.len() >= 4, "{} opens", opens.len());
        // Attempt k waits the core delay for k (failures 0 and 1), then continued attempts.
        let gaps: Vec<Duration> = opens.windows(2).map(|w| w[1] - w[0]).collect();
        near(gaps[0], expected_delay(0));
        near(gaps[1], expected_delay(1));
        // Open 3 -> silent -> idle timeout 10 s -> failure -> delay for attempt 2.
        near(gaps[2], FRAME_TIMEOUT + expected_delay(2));
        assert!(
            r.shared
                .live_at_open
                .lock()
                .unwrap()
                .iter()
                .all(|n| *n == 0),
            "an old stream was alive while a new one opened"
        );
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn a_stable_stream_resets_the_backoff_a_short_one_does_not() {
        let cfg = SupervisorConfig {
            min_stable: DurationMs::from_secs(5),
            ..SupervisorConfig::default()
        };
        let long = || {
            Attempt::Stream(vec![
                Step::Frame(frame(true)),
                Step::Sleep(Duration::from_secs(6)),
                Step::Frame(frame(false)),
                Step::Eof,
            ])
        };
        let short = || Attempt::Stream(vec![Step::Frame(frame(true)), Step::Eof]);
        let mut r = rig(
            vec![
                Attempt::OpenFails(IngestError::OpenFailed),
                Attempt::OpenFails(IngestError::OpenFailed),
                long(),
                short(),
                short(),
            ],
            cfg,
        );
        // After the long stream the outage ends: the failure starts a new one, attempt 0 -> 1.
        r.wait_state(|s| backoff_attempt(s).is_some_and(|a| a >= 3))
            .await;
        // Drain to the point after the long stream.
        let mut seen = Vec::new();
        while seen.len() < 3 {
            seen.push(r.frames.recv().await.unwrap());
        }
        let opens = r.opens();
        let gaps: Vec<Duration> = opens.windows(2).map(|w| w[1] - w[0]).collect();
        // gap[2] is open(long) -> open(short): 6 s of stream, then the reset delay (attempt 0).
        near(gaps[2], Duration::from_secs(6) + expected_delay(0));
        // gap[3] is short -> short: the stream was not stable, so the delay continues (attempt 1).
        near(gaps[3], expected_delay(1));
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn the_idle_timeout_is_configurable() {
        let cfg = SupervisorConfig {
            idle_timeout: Duration::from_secs(3),
            ..SupervisorConfig::default()
        };
        let mut r = rig(vec![Attempt::Stream(vec![Step::Silent])], cfg);
        let start = Instant::now();
        r.wait_state(|s| backoff_attempt(s).is_some()).await;
        near(start.elapsed(), Duration::from_secs(3));
        match *r.state.borrow() {
            ConnectionState::Backoff { .. } => {}
            s => panic!("{s:?}"),
        }
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn an_open_that_hangs_times_out() {
        let mut r = rig(vec![Attempt::OpenHangs], SupervisorConfig::default());
        let start = Instant::now();
        r.wait_state(|s| backoff_attempt(s).is_some()).await;
        near(start.elapsed(), Duration::from_secs(10));
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_frame_is_a_discontinuity_even_if_the_source_forgot() {
        let mut r = rig(
            vec![Attempt::Stream(vec![
                Step::Frame(frame(true)),
                Step::Frame(frame(false)),
                Step::Silent,
            ])],
            SupervisorConfig::default(),
        );
        assert!(r.frames.recv().await.unwrap().discontinuity);
        assert!(!r.frames.recv().await.unwrap().discontinuity);
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn a_lagging_consumer_loses_frames_up_to_the_next_keyframe() {
        let cfg = SupervisorConfig {
            channel_capacity: 2,
            ..SupervisorConfig::default()
        };
        let gate = Arc::new(Notify::new());
        let mut k4 = frame(true);
        k4.params = Some(params(4));
        let mut p2 = frame(false);
        p2.params = Some(params(2));
        let mut r = rig(
            vec![Attempt::Stream(vec![
                Step::Frame(frame(true)),  // delivered
                Step::Frame(frame(false)), // delivered, channel full
                Step::Frame(p2),           // dropped, carries params
                Step::Frame(frame(false)), // dropped (waiting for a keyframe)
                Step::Frame(k4),           // dropped: still full
                Step::Gate(Arc::clone(&gate)),
                Step::Frame(frame(false)), // dropped: not a keyframe
                Step::Frame(frame(true)),  // delivered
                Step::Frame(frame(false)), // delivered
                Step::Silent,
            ])],
            cfg,
        );
        // Let the supervisor run into the gate while nobody reads.
        r.wait_state(is_streaming).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(r.frames.len(), 2);
        assert_eq!(r.dropped.get(), 3);

        assert!(r.frames.recv().await.unwrap().discontinuity);
        assert!(!r.frames.recv().await.unwrap().discontinuity);
        gate.notify_one();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(r.dropped.get(), 4);
        let k = r.frames.recv().await.unwrap();
        assert!(k.is_keyframe && k.discontinuity, "{k:?}");
        // The dropped keyframe's parameter sets were handed on (the latest one wins).
        assert_eq!(k.params, Some(params(4)));
        let p = r.frames.recv().await.unwrap();
        assert!(!p.is_keyframe && !p.discontinuity && p.params.is_none());
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn a_consumer_that_never_reads_cannot_grow_memory() {
        const TOTAL: usize = 5_000;
        let cfg = SupervisorConfig {
            channel_capacity: 8,
            ..SupervisorConfig::default()
        };
        let steps = (0..TOTAL)
            .map(|i| Step::Frame(frame(i % 10 == 0)))
            .chain([Step::Silent])
            .collect();
        let mut r = rig(vec![Attempt::Stream(steps)], cfg);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(r.frames.len(), 8);
        assert_eq!(r.dropped.get(), u64::try_from(TOTAL - 8).unwrap());
        // What was kept is the head of the stream; draining it frees the channel.
        for _ in 0..8 {
            r.frames.recv().await.unwrap();
        }
        assert!(r.frames.try_recv().is_err());
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn zero_capacity_and_zero_idle_are_raised_not_panicked_or_spun() {
        let cfg = SupervisorConfig {
            channel_capacity: 0,
            idle_timeout: Duration::ZERO,
            ..SupervisorConfig::default()
        };
        let mut r = rig(
            vec![Attempt::Stream(vec![
                Step::Frame(frame(true)),
                Step::Silent,
            ])],
            cfg,
        );
        assert!(r.frames.recv().await.is_some());
        let start = Instant::now();
        r.wait_state(|s| backoff_attempt(s).is_some()).await;
        near(start.elapsed(), MIN_PAUSE);
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_backoff_does_not_spin_the_reconnect_loop() {
        let shared = Arc::new(Shared::default());
        let cancel = CancelToken::new();
        let zero = Backoff::new(DurationMs::from_millis(0), DurationMs::from_millis(0));
        let (_frames, _state, _d) = Supervisor::spawn(
            Fake {
                script: VecDeque::new(),
                shared: Arc::clone(&shared),
            },
            InstantClock::new(),
            zero,
            Fixed0,
            SupervisorConfig::default(),
            cancel.clone(),
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        let n = shared.opens.lock().unwrap().len();
        assert!((9..=11).contains(&n), "{n} attempts in one second");
        cancel.cancel();
    }

    /// Cancel at each phase: the task ends (both channels close) inside a second, and no stream
    /// is left alive.
    async fn assert_stops(mut r: Rig) {
        let t = Instant::now();
        r.cancel.cancel();
        let closed = timeout(Duration::from_secs(1), async {
            while r.frames.recv().await.is_some() {}
            while r.state.changed().await.is_ok() {}
        })
        .await;
        assert!(closed.is_ok(), "did not stop within a second");
        assert!(t.elapsed() < Duration::from_secs(1));
        assert_eq!(r.shared.live.load(Ordering::SeqCst), 0, "a stream leaked");
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_while_streaming_stops_within_a_second() {
        let mut r = rig(
            vec![Attempt::Stream(vec![
                Step::Frame(frame(true)),
                Step::Silent,
            ])],
            SupervisorConfig::default(),
        );
        r.wait_state(is_streaming).await;
        assert_stops(r).await;
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_while_backing_off_stops_within_a_second() {
        let mut r = rig(vec![], SupervisorConfig::default());
        r.wait_state(|s| backoff_attempt(s).is_some()).await;
        assert_stops(r).await;
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_while_opening_stops_within_a_second() {
        let r = rig(vec![Attempt::OpenHangs], SupervisorConfig::default());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_stops(r).await;
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_before_anything_runs_stops() {
        let r = rig(
            vec![Attempt::Stream(vec![Step::Silent])],
            SupervisorConfig::default(),
        );
        assert_stops(r).await;
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_frame_receiver_stops_the_task_and_frees_the_stream() {
        let r = rig(
            vec![Attempt::Stream(vec![
                Step::Frame(frame(true)),
                Step::Silent,
            ])],
            SupervisorConfig::default(),
        );
        let Rig {
            frames,
            mut state,
            shared,
            ..
        } = r;
        drop(frames);
        let closed = timeout(Duration::from_secs(1), async {
            while state.changed().await.is_ok() {}
        })
        .await;
        assert!(closed.is_ok());
        assert_eq!(shared.live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_old_stream_is_dropped_before_the_backoff_starts() {
        let mut r = rig(
            vec![
                Attempt::Stream(vec![Step::Frame(frame(true)), Step::Eof]),
                Attempt::Stream(vec![Step::Silent]),
            ],
            SupervisorConfig::default(),
        );
        r.wait_state(|s| backoff_attempt(s).is_some()).await;
        // In backoff the failed stream is already gone.
        assert_eq!(r.shared.live.load(Ordering::SeqCst), 0);
        r.cancel.cancel();
    }

    /// Every `IngestError` variant and the kind it maps to. The match inside forces a new variant
    /// to be added here.
    fn all_errors() -> Vec<(IngestError, FailureKind)> {
        use crate::frame::MapError;
        let probe = IngestError::InvalidUrl;
        match probe {
            IngestError::InvalidUrl
            | IngestError::OpenFailed
            | IngestError::OpenTimeout
            | IngestError::AuthRejected
            | IngestError::Rejected(_)
            | IngestError::NoVideoStream
            | IngestError::UnsupportedCodec
            | IngestError::StreamFailed
            | IngestError::FrameTimeout
            | IngestError::Map(_) => {}
        }
        vec![
            (IngestError::InvalidUrl, FailureKind::Other),
            (IngestError::OpenFailed, FailureKind::Refused),
            (IngestError::OpenTimeout, FailureKind::Timeout),
            (IngestError::AuthRejected, FailureKind::Auth),
            (IngestError::Rejected(404), FailureKind::Protocol),
            (IngestError::NoVideoStream, FailureKind::Protocol),
            (IngestError::UnsupportedCodec, FailureKind::Protocol),
            (IngestError::StreamFailed, FailureKind::Other),
            (IngestError::FrameTimeout, FailureKind::Timeout),
            (
                IngestError::Map(MapError::MalformedFrame),
                FailureKind::Protocol,
            ),
            (
                IngestError::Map(MapError::UnsupportedClockRate),
                FailureKind::Protocol,
            ),
            (
                IngestError::Map(MapError::BadParameterSet),
                FailureKind::Protocol,
            ),
        ]
    }

    #[test]
    fn every_error_maps_to_its_kind() {
        for (e, kind) in all_errors() {
            assert_eq!(failure_kind(&e), kind, "{e:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_state_carries_the_kind_and_nothing_of_the_error() {
        // A zero budget makes the first failure `Degraded`, which is the state that stores a kind.
        // Every variant goes through a live stream failing, and none of its text may show.
        for (e, kind) in all_errors() {
            let cfg = SupervisorConfig {
                budget: DurationMs::from_millis(0),
                ..SupervisorConfig::default()
            };
            let mut r = rig(
                vec![Attempt::Stream(vec![
                    Step::Frame(frame(true)),
                    Step::Err(e),
                ])],
                cfg,
            );
            let s = r
                .wait_state(|s| matches!(s, ConnectionState::Degraded { .. }))
                .await;
            let ConnectionState::Degraded {
                last_error_kind, ..
            } = s
            else {
                panic!("{s:?}")
            };
            assert_eq!(last_error_kind, kind, "{e:?}");
            let text = format!("{s:?}");
            for needle in ["404", "Rejected", "Map", "Malformed", "rtsp", "Ingest"] {
                assert!(!text.contains(needle), "{needle} in {text}");
            }
            r.cancel.cancel();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_hang_and_eof_are_reported_with_their_kinds() {
        let cases = [
            (Attempt::Stream(vec![Step::Silent]), FailureKind::Timeout),
            (Attempt::OpenHangs, FailureKind::Timeout),
            (Attempt::Stream(vec![Step::Eof]), FailureKind::Other),
        ];
        for (attempt, want) in cases {
            let cfg = SupervisorConfig {
                budget: DurationMs::from_millis(0),
                ..SupervisorConfig::default()
            };
            let mut r = rig(vec![attempt], cfg);
            let s = r
                .wait_state(|s| matches!(s, ConnectionState::Degraded { .. }))
                .await;
            let ConnectionState::Degraded {
                last_error_kind, ..
            } = s
            else {
                panic!("{s:?}")
            };
            assert_eq!(last_error_kind, want);
            r.cancel.cancel();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn owed_params_and_the_keyframe_wait_do_not_cross_a_reconnect() {
        let cfg = SupervisorConfig {
            channel_capacity: 2,
            ..SupervisorConfig::default()
        };
        let mut p1 = frame(false);
        p1.params = Some(params(1));
        let mut r = rig(
            vec![
                Attempt::Stream(vec![
                    Step::Frame(frame(true)),
                    Step::Frame(frame(false)),
                    Step::Frame(p1), // dropped: full, owes params(1)
                    Step::Eof,
                ]),
                Attempt::Stream(vec![Step::Frame(frame(true)), Step::Silent]),
            ],
            cfg,
        );
        // Session 1 ends with the channel full and the params of its last frame owed. Drain it,
        // so that session 2's keyframe is delivered.
        tokio::time::sleep(Duration::from_secs(1)).await;
        r.frames.recv().await.unwrap();
        r.frames.recv().await.unwrap();
        assert_eq!(r.dropped.get(), 1, "the P with params");
        tokio::time::sleep(Duration::from_secs(5)).await;
        let k = timeout(Duration::from_secs(60), r.frames.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(k.is_keyframe && k.discontinuity);
        assert_eq!(k.params, None, "session 1's owed params leaked");
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn the_keyframe_wait_ends_with_its_session() {
        let cfg = SupervisorConfig {
            channel_capacity: 1,
            ..SupervisorConfig::default()
        };
        let mut r = rig(
            vec![
                Attempt::Stream(vec![
                    Step::Frame(frame(true)),
                    Step::Frame(frame(false)), // dropped: full, now waiting for a keyframe
                    Step::Eof,
                ]),
                // A new session whose first frame is not a keyframe is still delivered.
                Attempt::Stream(vec![Step::Frame(frame(false)), Step::Silent]),
            ],
            cfg,
        );
        // Session 1 ends (and sits in backoff) with the channel full; free it, then session 2 runs.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(r.frames.recv().await.unwrap().is_keyframe);
        tokio::time::sleep(Duration::from_secs(5)).await;
        let next = timeout(Duration::from_secs(60), r.frames.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!next.is_keyframe && next.discontinuity);
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn connected_is_the_first_frame_not_the_open() {
        // min_stable (2 s) is shorter than the idle timeout (5 s): if an open counted as
        // Connected, the silent session would look stable and reset the backoff.
        let cfg = SupervisorConfig {
            idle_timeout: Duration::from_secs(5),
            min_stable: DurationMs::from_secs(2),
            ..SupervisorConfig::default()
        };
        let mut r = rig(vec![Attempt::Stream(vec![Step::Silent])], cfg);
        let mut seen = Vec::new();
        while backoff_attempt(&seen.last().copied().unwrap_or(ConnectionState::INITIAL))
            .is_none_or(|a| a < 4)
        {
            timeout(Duration::from_secs(120), r.state.changed())
                .await
                .unwrap()
                .unwrap();
            seen.push(*r.state.borrow());
        }
        assert!(!seen.iter().any(is_streaming), "{seen:?}");
        let attempts: Vec<u32> = seen.iter().filter_map(backoff_attempt).collect();
        assert!(attempts.windows(2).all(|w| w[1] >= w[0]), "{attempts:?}");
        assert_eq!(attempts.last().copied(), Some(4));
        let opens = r.opens();
        let gaps: Vec<Duration> = opens.windows(2).map(|w| w[1] - w[0]).collect();
        // Silent session: idle timeout, then the delay for attempt 1 (the outage continues).
        near(gaps[0], Duration::from_secs(5) + expected_delay(0));
        near(gaps[1], expected_delay(1));
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn the_task_handle_completes_after_cancel() {
        let shared = Arc::new(Shared::default());
        let cancel = CancelToken::new();
        let (mut frames, _state, _d, handle) = Supervisor::spawn_joinable(
            Fake {
                script: vec![Attempt::Stream(vec![
                    Step::Frame(frame(true)),
                    Step::Silent,
                ])]
                .into(),
                shared: Arc::clone(&shared),
            },
            InstantClock::new(),
            Backoff::DEFAULT,
            Fixed0,
            SupervisorConfig::default(),
            cancel.clone(),
        );
        frames.recv().await.unwrap();
        cancel.cancel();
        assert!(timeout(Duration::from_secs(1), handle).await.is_ok());
        assert_eq!(shared.live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_connect_timeout_is_raised() {
        let cfg = SupervisorConfig {
            connect_timeout: DurationMs::from_millis(0),
            ..SupervisorConfig::default()
        };
        let mut r = rig(vec![Attempt::OpenHangs], cfg);
        let start = Instant::now();
        r.wait_state(|s| backoff_attempt(s).is_some()).await;
        near(start.elapsed(), MIN_PAUSE);
        r.cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_camera_ends_up_degraded_with_the_error_kind() {
        let cfg = SupervisorConfig {
            budget: DurationMs::from_secs(30),
            ..SupervisorConfig::default()
        };
        // Every open is refused as unauthorized.
        let script = (0..200)
            .map(|_| Attempt::OpenFails(IngestError::AuthRejected))
            .collect();
        let mut r = rig(script, cfg);
        let s = r
            .wait_state(|s| matches!(s, ConnectionState::Degraded { .. }))
            .await;
        let ConnectionState::Degraded {
            last_error_kind, ..
        } = s
        else {
            panic!("{s:?}")
        };
        assert_eq!(last_error_kind, FailureKind::Auth);
        assert!(r.t0.elapsed() >= Duration::from_secs(30));
        r.cancel.cancel();
    }

    #[test]
    fn the_defaults_match_the_ticket() {
        let c = SupervisorConfig::default();
        assert_eq!(c.idle_timeout, Duration::from_secs(10));
        assert!(c.channel_capacity >= 1);
    }

    #[tokio::test]
    async fn the_cancel_token_is_shared_and_idempotent() {
        let t = CancelToken::new();
        let u = t.clone();
        assert!(!t.is_cancelled());
        u.cancel();
        u.cancel();
        assert!(t.is_cancelled());
        t.cancelled().await;
    }

    #[test]
    fn the_jitter_is_deterministic_per_seed() {
        let mut a = SplitMixJitter::new(1);
        let mut b = SplitMixJitter::new(1);
        let mut c = SplitMixJitter::new(2);
        assert_eq!(a.next_u64(), b.next_u64());
        assert_ne!(a.next_u64(), c.next_u64());
    }
}
