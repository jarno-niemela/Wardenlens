//! The composition root of `wardenlens serve` (ticket #68, ADR 0004 section 9, ADR 0005 sections
//! 6 to 9): everything that does I/O is wired here and nowhere else.
//!
//! Start-up order (ADR 0005, the #68 row): the index is open (its exclusive lock is the process
//! lock, so a second instance is refused), then [`Storage::open`] opens the hot root (the only
//! volume problem that refuses to start), then the start-up reconciliation probes both volumes
//! and runs the decision table, and only then do the storage loop and the recorders start. A
//! missing, read-only, unmarked or same-filesystem archive starts in `archive_unavailable` mode.
//!
//! Per camera: a recorder (on a blocking thread), an ingest supervisor (async), and two small
//! watcher tasks (connection state for the API, a full-volume wake for the storage loop). A camera
//! that cannot be set up is logged by id and skipped; the others run. Decrypted credentials exist
//! only inside the stream sources handed in by the caller (SEC-6).
//!
//! Shutdown: the API stops accepting, ingest is cancelled, each recorder drains its queue and
//! flushes and indexes its open segment, the storage thread finishes its tick; all of it within
//! the deadline ([`Tuning::shutdown_deadline`]).

mod http;
mod index;
mod limits;
mod status;
mod storage_task;

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use wardenlens_core::camera::{Camera, CameraId};
use wardenlens_core::config::Config;
use wardenlens_core::connection::Backoff;
use wardenlens_core::recording::{RecordingError, SegmentConfig};
use wardenlens_core::time::Timestamp;
use wardenlens_fsutil::{FsError, RootDir};
use wardenlens_index::Index;
use wardenlens_ingest::{
    CancelToken, InstantClock, SplitMixJitter, StreamSource, Supervisor, SupervisorConfig,
};
use wardenlens_recorder::{
    ChannelSource, HoldReason, HotStore, Recorder, RecorderConfig, RecorderHealth, RecorderState,
};
use wardenlens_storage::{Newest, StatvfsUsage, Storage, StorageConfig, StorageError, TickError};

pub(crate) use self::http::{ConnectionStats, HttpLimits};
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
#[derive(Debug, Clone)]
pub(crate) struct Tuning {
    pub(crate) storage_interval: Duration,
    pub(crate) shutdown_deadline: Duration,
    pub(crate) http: HttpLimits,
    pub(crate) supervisor: SupervisorConfig,
    pub(crate) recorder: RecorderConfig,
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
            #[cfg(test)]
            allow_same_filesystem: false,
        }
    }
}

/// Why the service could not start or did not stop cleanly. Nothing here carries a path, a
/// camera address or a credential.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ServeError {
    /// The hot root cannot be opened (the only volume problem that refuses to start).
    #[error("the hot root cannot be used")]
    HotRoot(#[source] FsError),
    /// The storage loop could not be built.
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
    /// The start-up task failed.
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
}

/// Runs the service until `shutdown` completes, then stops it in order.
///
/// # Errors
/// [`ServeError`]: a start-up refusal, or a shutdown that overran its deadline.
pub(crate) async fn run<S: StreamSource>(
    config: &Config,
    index: Index,
    cameras: Vec<CameraInput<S>>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()>,
    tuning: Tuning,
    stats: ConnectionStats,
) -> Result<(), ServeError> {
    let index = SharedIndex::new(index);
    let segment = SegmentConfig::new(config.segment_target_secs(), MAX_SEGMENT_BYTES)
        .map_err(ServeError::Segment)?;
    let recorder_config = tuning.recorder.with_segment(segment);

    let storage_config = storage_config(config, &tuning);
    let (mut looper, files) =
        Storage::open(storage_config, index.clone(), StatvfsUsage).map_err(ServeError::Storage)?;
    let hot = RootDir::open(config.hot_root()).map_err(ServeError::HotRoot)?;

    // Probe both volumes, then the decision table; the recorders start after it (ADR 0005).
    let (looper, reconciled) = tokio::task::spawn_blocking(move || {
        let done = looper.reconcile_startup();
        (looper, done)
    })
    .await
    .map_err(|_| ServeError::Startup)?;
    let reconciled = reconciled.map_err(ServeError::Reconcile)?;
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

    let (snapshots_tx, snapshots_rx) = watch::channel(looper.snapshot());
    let storage = storage_task::spawn(looper, tuning.storage_interval, snapshots_tx, wall_now)
        .map_err(ServeError::Thread)?;

    let links = Links::default();
    let cancel = CancelToken::new();
    let (running, directory) = start_cameras(
        cameras,
        &Shared {
            hot: &hot,
            index: &index,
            config: recorder_config,
            supervisor: tuning.supervisor,
            cancel: &cancel,
            links: &links,
            newest: &reconciled.newest,
        },
        &storage,
    );
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
        stats,
        stop_http.clone(),
    ));

    shutdown.await;
    tracing::info!("shutting down");
    // A deadline that cannot be represented is "now": stop as fast as possible.
    let now = Instant::now();
    let deadline = now.checked_add(tuning.shutdown_deadline).unwrap_or(now);
    stop_http.cancel();
    cancel.cancel();
    let on_time = stop_all(running, storage, http, deadline).await;
    if on_time {
        Ok(())
    } else {
        Err(ServeError::ShutdownTimeout(tuning.shutdown_deadline))
    }
}

/// Starts every camera that can be set up; returns what runs and what the API shows. A camera
/// that fails is logged by id and left out.
fn start_cameras<S: StreamSource>(
    cameras: Vec<CameraInput<S>>,
    shared: &Shared<'_>,
    storage: &storage_task::StorageTask,
) -> (Vec<Running>, Vec<Camera>) {
    let mut directory = Vec::new();
    let mut running = Vec::new();
    for (position, input) in cameras.into_iter().enumerate() {
        let id = input.camera.id().clone();
        let setup = Setup {
            shared,
            wake: storage.waker(),
            seed: u64::try_from(position).unwrap_or(0),
        };
        if let Ok(r) = setup.start(&id, input.source) {
            running.push(r);
            directory.push(input.camera);
        } else {
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
    hot: &'a RootDir,
    index: &'a SharedIndex,
    config: RecorderConfig,
    supervisor: SupervisorConfig,
    cancel: &'a CancelToken,
    links: &'a Links,
    /// The newest key the start-up reconciliation saw per camera (the recorder's seed).
    newest: &'a Newest,
}

/// What one camera's tasks need.
struct Setup<'a> {
    shared: &'a Shared<'a>,
    wake: std::sync::mpsc::Sender<Wake>,
    seed: u64,
}

impl Setup<'_> {
    /// Builds the recorder first (so a failure leaves nothing running), then the ingest
    /// supervisor and the watchers. The error is logged here without detail.
    fn start<S: StreamSource>(self, id: &CameraId, source: S) -> Result<Running, ()> {
        let shared = self.shared;
        let root = shared.hot.try_clone().map_err(|e| {
            tracing::error!(camera = %id, error = %e, "cannot open the hot root for the camera");
        })?;
        let (recorder, health) = Recorder::new(
            id.clone(),
            shared.config,
            HotStore::new(root, id.clone()),
            shared.index.clone(),
            shared.newest.get(id),
        )
        .map_err(|e| tracing::error!(camera = %id, error = %e, "cannot build the recorder"))?;
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
        tokio::spawn(wake_when(health, storage_full, self.wake));
        let recorder =
            tokio::task::spawn_blocking(move || recorder.run(ChannelSource::new(frames)));
        Ok(Running {
            supervisor,
            recorder,
        })
    }
}

/// The recorder reports a full hot volume (`ENOSPC`).
fn storage_full(h: &RecorderHealth) -> bool {
    h.state == RecorderState::Held(HoldReason::StorageFull)
}

/// Sends [`Wake::Tick`] each time `wanted` turns true, until the sender of `rx` is gone. One edge
/// is one tick; the interval tick covers a volume that stays full.
pub(crate) async fn wake_when<T: Send + Sync>(
    mut rx: watch::Receiver<T>,
    wanted: impl Fn(&T) -> bool + Send,
    wake: std::sync::mpsc::Sender<Wake>,
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
