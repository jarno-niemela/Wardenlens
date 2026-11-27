//! The composition root of `wardenlens serve` (ticket #68, ADR 0004 section 9, ADR 0005 sections
//! 6 to 9): everything that does I/O is wired here and nowhere else.
//!
//! **Locks.** The process lock is `wardenlens.lock` next to the index, taken in
//! `commands::serve` before `Index::open` (a second `serve` with the same state directory is
//! refused). [`run`] takes a second exclusive `flock` on `.wardenlens.lock` inside the hot root,
//! so two instances with different state directories over one hot root are refused too (they
//! would run two storage loops on the same files, ADR 0005 section 7). `Index::open`'s own
//! `flock` serialises only openers and is released after the open; `token` and `import` therefore
//! run beside a live `serve` and serialise with it only through that open. There is exactly one
//! [`Index`] per process: it is shared behind [`SharedIndex`].
//!
//! **Start-up order** (ADR 0005, the #68 row): the hot root is opened once and locked, the
//! storage loop is built on that handle, the start-up reconciliation probes both volumes and runs
//! the decision table, and only then do the storage thread and the recorders start. A missing,
//! read-only, unmarked or same-filesystem archive starts in `archive_unavailable` mode; a hot root
//! that cannot be opened refuses to start. All of this blocking work runs on the blocking pool and
//! is raced against the stop signal, so a SIGTERM during a long walk exits at once ([`Stopped::Abandoned`]).
//!
//! Per camera: a recorder (on a blocking thread), an ingest supervisor (async), and two small
//! watcher tasks (connection state for the API, a full-volume wake for the storage loop). A camera
//! that cannot be set up is logged by id and skipped; the others run. Decrypted credentials exist
//! only inside the stream sources handed in by the caller (SEC-6).
//!
//! **Shutdown**: the API stops accepting, ingest is cancelled, each recorder drains its queue and
//! flushes and indexes its open segment, the storage thread finishes its tick; all of it within
//! the deadline ([`Tuning::shutdown_deadline`]). When a part overruns it, [`run`] returns
//! [`ServeError::ShutdownTimeout`] and the caller must release the runtime with
//! [`release_runtime`], which abandons blocking tasks instead of waiting for them: a tokio runtime
//! dropped normally waits without limit for `spawn_blocking` work (a storage tick of up to 64
//! moves, a recorder stuck in `fsync`). Abandoning a tier move or a `.part` file is crash-safe
//! (ADR 0005 sections 7 and 9: the same state a power cut leaves, repaired at the next start).

mod http;
mod index;
mod limits;
mod lock;
mod status;
mod storage_task;

use std::future::Future;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use wardenlens_core::camera::{Camera, CameraId};
use wardenlens_core::config::Config;
use wardenlens_core::connection::Backoff;
use wardenlens_core::recording::{RecordingError, SegmentConfig};
use wardenlens_core::time::Timestamp;
use wardenlens_fsutil::RootDir;
use wardenlens_index::Index;
use wardenlens_ingest::{
    CancelToken, InstantClock, SplitMixJitter, StreamSource, Supervisor, SupervisorConfig,
};
use wardenlens_recorder::{
    ChannelSource, HoldReason, HotStore, Recorder, RecorderConfig, RecorderHealth, RecorderState,
};
use wardenlens_storage::{
    Reconciled, Storage, StorageConfig, StorageError, StorageFiles, StorageLoop, TickError,
    VolumeUsage,
};

pub(crate) use self::http::{Accept, ConnectionStats, HttpLimits};
use self::index::SharedIndex;
pub(crate) use self::limits::raise_nofile_limit;
use self::status::{Directory, Links, Snapshots, track_link};
use self::storage_task::Wake;

/// Segment size cap handed to the segmenter (ADR 0005 section 2: 1 GiB).
const MAX_SEGMENT_BYTES: u64 = 1 << 30;
/// How often the storage loop ticks when nothing wakes it earlier.
pub(crate) const STORAGE_INTERVAL: Duration = Duration::from_secs(30);
/// How long shutdown may take (ticket #68: exit 0 within 10 s).
pub(crate) const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// One camera to run: what the API shows of it and the source its main stream is read from.
pub(crate) struct CameraInput<S> {
    pub(crate) camera: Camera,
    pub(crate) source: S,
}

/// Knobs with production defaults; tests shrink them.
#[derive(Clone)]
pub(crate) struct Tuning {
    pub(crate) storage_interval: Duration,
    pub(crate) shutdown_deadline: Duration,
    pub(crate) http: HttpLimits,
    pub(crate) supervisor: SupervisorConfig,
    pub(crate) recorder: RecorderConfig,
    /// Connections served now and at most; read at shutdown.
    pub(crate) stats: ConnectionStats,
    /// Test hook run before each recorder is built (to hold a camera in start-up).
    #[cfg(test)]
    pub(crate) before_recorder: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Two directories of one filesystem as hot and archive (storage's test switch).
    #[cfg(test)]
    pub(crate) allow_same_filesystem: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            storage_interval: STORAGE_INTERVAL,
            shutdown_deadline: SHUTDOWN_DEADLINE,
            http: HttpLimits::default(),
            supervisor: SupervisorConfig::default(),
            recorder: RecorderConfig::default(),
            stats: ConnectionStats::default(),
            #[cfg(test)]
            before_recorder: None,
            #[cfg(test)]
            allow_same_filesystem: false,
        }
    }
}

/// Why the service could not start or did not stop cleanly. Nothing here carries a path, a
/// camera address or a credential.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ServeError {
    /// Another instance holds the lock inside the hot root.
    #[error("another wardenlens instance is using the hot root (it holds its lock)")]
    HotRootLocked,
    /// The lock file inside the hot root cannot be created or locked.
    #[error("the hot root lock cannot be taken")]
    HotRootLock(#[source] lock::LockError),
    /// The storage loop could not be built, or the hot root cannot be opened (the only volume
    /// problem that refuses to start).
    #[error("the storage loop cannot be built")]
    Storage(#[source] StorageError),
    /// The start-up reconciliation could not probe the hot volume.
    #[error("the start-up reconciliation failed")]
    Reconcile(#[source] TickError),
    /// `recording.segment_target_secs` was refused by the segmenter.
    #[error("the segment settings are invalid")]
    Segment(#[source] RecordingError),
    /// A thread could not be started.
    #[error("a service thread could not be started")]
    Thread(#[source] std::io::Error),
    /// The start-up task failed (it panicked).
    #[error("the start-up task failed")]
    Startup,
    /// Some part of the service was still running when the deadline passed.
    #[error("the service did not stop within {0:?}")]
    ShutdownTimeout(Duration),
}

/// The wall clock, for arrival times and tick times.
pub(crate) fn wall_now() -> Timestamp {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    Timestamp::from_unix_millis(ms)
}

/// The wall clock as the core `Clock` port (frame arrival times).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemClock;

impl wardenlens_core::time::Clock for SystemClock {
    fn now(&self) -> Timestamp {
        wall_now()
    }
}

/// A camera whose tasks are running.
struct Running {
    supervisor: JoinHandle<()>,
    recorder: JoinHandle<RecorderHealth>,
    /// Wakes the storage loop on `ENOSPC`; ends with the recorder's health channel. Kept here so
    /// that the wiring cannot be dropped without the compiler noticing (see `stop_all`).
    wake_watcher: JoinHandle<()>,
}

/// How a service that did not fail ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stopped {
    /// Started, then stopped on the signal with every part finished in time.
    Clean,
    /// The signal arrived during start-up: nothing was started, and blocking start-up work (a
    /// long reconciliation walk) may still be running. Release the runtime with
    /// [`release_runtime`]`(runtime, false)`.
    Abandoned,
}

/// How long a clean release waits for blocking tasks that are still running (a DNS lookup that
/// ingest started for a camera host, an API index read).
const CLEAN_GRACE: Duration = Duration::from_secs(1);

/// Releases the runtime after [`run`]; always with `shutdown_timeout`, never a plain drop,
/// because dropping a multi-thread runtime waits without limit for `spawn_blocking` tasks (even
/// after every part stopped in time, a hung `getaddrinfo` would hold the process). A clean stop
/// waits at most [`CLEAN_GRACE`] for leftovers; after an overrun or an abandoned start-up it does
/// not wait at all, so the 10 s deadline holds. What is abandoned is crash-safe (see the module
/// docs).
pub(crate) fn release_runtime(runtime: tokio::runtime::Runtime, clean: bool) {
    runtime.shutdown_timeout(if clean { CLEAN_GRACE } else { Duration::ZERO });
}

/// Aborts a task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What start-up built before the recorders start.
struct Prepared<U> {
    looper: StorageLoop<SharedIndex, wardenlens_storage::RealFs, U>,
    files: StorageFiles<SharedIndex>,
    /// The hot root, opened once; the storage loop has its own descriptor of the same directory.
    hot: Arc<RootDir>,
    /// Held until the service has stopped.
    _lock: std::fs::File,
    reconciled: Reconciled,
}

/// Opens and locks the hot root, builds the storage loop on it and runs the start-up
/// reconciliation (which probes both volumes first). All of it blocks, so it runs on the blocking
/// pool.
async fn prepare<U: VolumeUsage + Send + 'static>(
    config: &Config,
    index: &SharedIndex,
    usage: U,
    tuning: &Tuning,
) -> Result<Prepared<U>, ServeError> {
    let cfg = storage_config(config, tuning);
    let index = index.clone();
    tokio::task::spawn_blocking(move || {
        let hot_error = |e| ServeError::Storage(StorageError::HotRoot(e));
        let hot = RootDir::open(&cfg.hot_root).map_err(hot_error)?;
        let lock = lock::lock_hot_root(&hot)?;
        let shared = hot.try_clone().map_err(hot_error)?;
        let (mut looper, files) =
            Storage::open_on(hot, cfg, index, usage).map_err(ServeError::Storage)?;
        let reconciled = looper.reconcile_startup().map_err(ServeError::Reconcile)?;
        Ok(Prepared {
            looper,
            files,
            hot: Arc::new(shared),
            _lock: lock,
            reconciled,
        })
    })
    .await
    .map_err(|_| ServeError::Startup)?
}

/// Runs the service until `shutdown` completes, then stops it in order.
///
/// # Errors
/// [`ServeError`]: a start-up refusal, or a shutdown that overran its deadline (the caller then
/// calls [`release_runtime`] with `false`).
pub(crate) async fn run<S, L, U>(
    config: &Config,
    index: Index,
    cameras: Vec<CameraInput<S>>,
    listener: L,
    shutdown: impl Future<Output = ()> + Send + 'static,
    tuning: Tuning,
    usage: U,
) -> Result<Stopped, ServeError>
where
    S: StreamSource,
    L: Accept,
    U: VolumeUsage + Send + 'static,
{
    // The signal becomes a token, so start-up and the running service can both wait on it.
    let stop = CancelToken::new();
    let _watcher = AbortOnDrop(tokio::spawn({
        let stop = stop.clone();
        async move {
            shutdown.await;
            stop.cancel();
        }
    }));
    let index = SharedIndex::new(index);
    let segment = SegmentConfig::new(config.segment_target_secs(), MAX_SEGMENT_BYTES)
        .map_err(ServeError::Segment)?;
    let recorder_config = tuning.recorder.with_segment(segment);

    let prepared = tokio::select! {
        biased;
        () = stop.cancelled() => {
            tracing::info!("stopped during start-up; nothing was started");
            return Ok(Stopped::Abandoned);
        }
        p = prepare(config, &index, usage, &tuning) => p?,
    };
    let Prepared {
        looper,
        files,
        hot,
        _lock,
        reconciled,
    } = prepared;
    log_reconciliation(&reconciled);

    let (snapshots_tx, snapshots_rx) = watch::channel(looper.snapshot());
    let storage = storage_task::spawn(looper, tuning.storage_interval, snapshots_tx, wall_now)
        .map_err(ServeError::Thread)?;

    let links = Links::default();
    let cancel = CancelToken::new();
    let (running, directory) = start_cameras(
        cameras,
        &Shared {
            hot,
            index: index.clone(),
            config: recorder_config,
            supervisor: tuning.supervisor,
            cancel: cancel.clone(),
            stop: stop.clone(),
            links: links.clone(),
            reconciled: &reconciled,
            #[cfg(test)]
            before_recorder: tuning.before_recorder.clone(),
        },
        &storage,
    )
    .await;
    tracing::info!(cameras = %running.len(), "recording started");

    let router = wardenlens_api::router(
        Arc::new(index.clone()),
        Directory::new(directory),
        links,
        Snapshots::new(snapshots_rx),
        index.clone(),
        files,
    );
    let stop_http = CancelToken::new();
    let http = tokio::spawn(http::serve(
        listener,
        router,
        tuning.http,
        tuning.stats.clone(),
        stop_http.clone(),
    ));

    stop.cancelled().await;
    tracing::info!("shutting down");
    let parts = Parts {
        running,
        storage,
        http,
        stop_http,
        cancel,
    };
    shut_down(parts, tuning.shutdown_deadline, &tuning.stats).await
}

/// The running parts that [`shut_down`] stops.
struct Parts {
    running: Vec<Running>,
    storage: storage_task::StorageTask,
    http: JoinHandle<()>,
    stop_http: CancelToken,
    cancel: CancelToken,
}

/// Stops every part within `limit`.
async fn shut_down(
    parts: Parts,
    limit: Duration,
    stats: &ConnectionStats,
) -> Result<Stopped, ServeError> {
    // A deadline that cannot be represented is "now": stop as fast as possible.
    let now = Instant::now();
    let deadline = now.checked_add(limit).unwrap_or(now);
    parts.stop_http.cancel();
    parts.cancel.cancel();
    let on_time = stop_all(parts.running, parts.storage, parts.http, deadline).await;
    tracing::info!(peak_connections = stats.peak(), "API connections at most");
    if on_time {
        Ok(Stopped::Clean)
    } else {
        Err(ServeError::ShutdownTimeout(limit))
    }
}

/// Counts only: never a name (SEC-6).
fn log_reconciliation(reconciled: &Reconciled) {
    let report = &reconciled.report;
    tracing::info!(
        adopted = report.adopted,
        quarantined = report.quarantined,
        missing = report.missing,
        size_mismatch = report.size_mismatch,
        unverified = report.unverified,
        archive_unavailable = report.archive_unavailable,
        walk_cap_exceeded = report.walk_cap_exceeded,
        "start-up reconciliation done"
    );
    if report.health_error() {
        tracing::error!("start-up reconciliation reports a health error");
    }
}

/// Starts every camera that can be set up; returns what runs and what the API shows. A camera
/// that fails is logged by id and left out.
async fn start_cameras<S: StreamSource>(
    cameras: Vec<CameraInput<S>>,
    shared: &Shared<'_>,
    storage: &storage_task::StorageTask,
) -> (Vec<Running>, Vec<Camera>) {
    let mut directory = Vec::new();
    let mut running = Vec::new();
    for (position, input) in cameras.into_iter().enumerate() {
        if shared.stop.is_cancelled() {
            tracing::info!("stopped while starting cameras; the rest are not started");
            break;
        }
        let id = input.camera.id().clone();
        let setup = Setup {
            shared,
            wake: storage.waker(),
            seed: u64::try_from(position).unwrap_or(0),
        };
        if let Ok(r) = setup.start(&id, input.source).await {
            running.push(r);
            directory.push(input.camera);
        } else if !shared.stop.is_cancelled() {
            tracing::error!(camera = %id, "camera skipped: its recorder could not be set up");
        }
    }
    (running, directory)
}

/// Waits for every part to stop, in order, until `deadline`. `false` if any part overran it.
async fn stop_all(
    running: Vec<Running>,
    storage: storage_task::StorageTask,
    http: JoinHandle<()>,
    deadline: Instant,
) -> bool {
    let mut on_time = true;
    for r in running {
        on_time &= within(deadline, r.supervisor).await.is_some();
        if let Some(health) = within(deadline, r.recorder).await {
            tracing::info!(
                segments_indexed = health.segments_indexed,
                segments_aborted = health.segments_aborted,
                segments_unindexed = health.segments_unindexed,
                "recorder stopped"
            );
        } else {
            on_time = false;
        }
        // It ends by itself with the recorder's health channel; make sure either way.
        r.wake_watcher.abort();
    }
    let storage_stopped = tokio::task::spawn_blocking(move || storage.stop());
    on_time &= within(deadline, storage_stopped).await.is_some();
    on_time &= within(deadline, http).await.is_some();
    on_time
}

/// Awaits `handle` until `deadline`. `None` when it did not finish in time or panicked.
async fn within<T>(deadline: Instant, handle: JoinHandle<T>) -> Option<T> {
    match tokio::time::timeout_at(deadline, handle).await {
        Ok(Ok(v)) => Some(v),
        Ok(Err(_)) => {
            tracing::error!("a service task ended abnormally");
            None
        }
        Err(_) => None,
    }
}

fn storage_config(config: &Config, tuning: &Tuning) -> StorageConfig {
    let actions = usize::try_from(config.max_actions_per_tick()).unwrap_or(usize::MAX);
    let cfg = StorageConfig::new(
        config.hot_root().to_path_buf(),
        config.archive_root().to_path_buf(),
        config.storage_policy(),
    )
    .with_max_actions_per_tick(actions);
    #[cfg(test)]
    let cfg = cfg.with_allow_same_filesystem(tuning.allow_same_filesystem);
    #[cfg(not(test))]
    let _ = tuning;
    cfg
}

/// What every camera's tasks share.
struct Shared<'a> {
    hot: Arc<RootDir>,
    index: SharedIndex,
    config: RecorderConfig,
    supervisor: SupervisorConfig,
    cancel: CancelToken,
    links: Links,
    /// The stop signal: a camera that is still being set up when it arrives is not started.
    stop: CancelToken,
    /// Test hook run on the blocking pool before a recorder is built.
    #[cfg(test)]
    before_recorder: Option<Arc<dyn Fn() + Send + Sync>>,
    /// The start-up reconciliation: the newest key it saw per camera is the recorder's seed.
    reconciled: &'a Reconciled,
}

/// What one camera's tasks need.
struct Setup<'a> {
    shared: &'a Shared<'a>,
    wake: Sender<Wake>,
    seed: u64,
}

impl Setup<'_> {
    /// Builds the recorder first (so a failure leaves nothing running), then the ingest
    /// supervisor and the watchers. The recorder's set-up reads the index and clones a
    /// descriptor, so it runs on the blocking pool. The error is logged here without detail.
    async fn start<S: StreamSource>(self, id: &CameraId, source: S) -> Result<Running, ()> {
        let shared = self.shared;
        let built = {
            let (id, hot, index) = (id.clone(), Arc::clone(&shared.hot), shared.index.clone());
            let (config, newest) = (shared.config, shared.reconciled.newest.get(&id));
            #[cfg(test)]
            let hook = shared.before_recorder.clone();
            let blocking = tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                if let Some(h) = hook {
                    h();
                }
                let root = hot.try_clone().map_err(|e| {
                    tracing::error!(camera = %id, error = %e, "cannot open the hot root for the camera");
                })?;
                Recorder::new(
                    id.clone(),
                    config,
                    HotStore::new(root, id.clone()),
                    index,
                    newest,
                )
                .map_err(|e| tracing::error!(camera = %id, error = %e, "cannot build the recorder"))
            });
            // A set-up that hangs (a busy index) must not hold the stop: abandon it.
            tokio::select! {
                biased;
                () = shared.stop.cancelled() => return Err(()),
                built = blocking => built,
            }
        };
        let Ok(Ok((recorder, health))) = built else {
            return Err(());
        };
        let jitter_seed = self.seed ^ u64::try_from(wall_now().as_unix_millis()).unwrap_or(0);
        let (frames, state, _dropped, supervisor) = Supervisor::spawn_joinable(
            source,
            InstantClock::new(),
            Backoff::DEFAULT,
            SplitMixJitter::new(jitter_seed),
            shared.supervisor,
            shared.cancel.clone(),
        );
        tokio::spawn(track_link(
            id.clone(),
            state,
            shared.links.clone(),
            wall_now,
        ));
        let wake_watcher = wire_storage_wake(health, self.wake);
        let recorder =
            tokio::task::spawn_blocking(move || recorder.run(ChannelSource::new(frames)));
        Ok(Running {
            supervisor,
            recorder,
            wake_watcher,
        })
    }
}

/// Whether a recorder in `state` is held off by a full hot volume (`ENOSPC`).
fn state_is_full(state: RecorderState) -> bool {
    state == RecorderState::Held(HoldReason::StorageFull)
}

fn health_is_full(h: &RecorderHealth) -> bool {
    state_is_full(h.state)
}

/// Wakes the storage loop whenever this recorder reports a full hot volume (one wake per rising
/// edge; the interval tick covers a volume that stays full).
fn wire_storage_wake(
    health: watch::Receiver<RecorderHealth>,
    wake: Sender<Wake>,
) -> JoinHandle<()> {
    tokio::spawn(wake_when(health, health_is_full, wake))
}

/// Sends [`Wake::Tick`] each time `wanted` turns true, until the sender of `rx` is gone. One edge
/// is one tick; the interval tick covers a volume that stays full.
pub(crate) async fn wake_when<T: Send + Sync>(
    mut rx: watch::Receiver<T>,
    wanted: impl Fn(&T) -> bool + Send,
    wake: Sender<Wake>,
) {
    let mut was = false;
    loop {
        let now = {
            let value = rx.borrow_and_update();
            wanted(&value)
        };
        if now && !was && wake.send(Wake::Tick).is_err() {
            break;
        }
        was = now;
        if rx.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests;
