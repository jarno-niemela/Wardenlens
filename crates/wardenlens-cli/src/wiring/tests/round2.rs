//! Fix round 2 of #68: the runtime release, the ENOSPC wake where it is wired, a stop signal during
//! start-up, accept errors, and a failing start-up probe.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wardenlens_core::storage::{StorageSnapshot, Tier, VolumeSpace};
use wardenlens_fsutil::RootDir;
use wardenlens_recorder::{HoldReason, RecorderHealth, RecorderState};
use wardenlens_storage::ProbeError;

use super::*;

/// Past the deadline the exit path abandons a blocking task that would run for 30 s: the release
/// returns at once, and `serve` reports it as exit 1.
#[test]
fn releasing_the_runtime_after_an_overrun_does_not_wait_for_blocking_tasks() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // A blocking task that outlives the test.
        tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(30)));
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    let at = std::time::Instant::now();
    release_runtime(runtime, false);
    // The stuck task sleeps 30 s; waiting for it would exceed this (TEST-5: not a load gauge).
    assert!(at.elapsed() < Duration::from_secs(20), "{:?}", at.elapsed());
}

/// A clean release of an idle runtime is quick.
#[test]
fn a_clean_release_of_an_idle_runtime_is_quick() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    release_runtime(runtime, true);
}

/// The predicate over every state and every hold reason: only `StorageFull` is "full".
#[test]
fn only_a_held_storage_full_state_is_full() {
    let table = [
        (RecorderState::Waiting, false),
        (RecorderState::Recording, false),
        (RecorderState::Held(HoldReason::BFramesDetected), false),
        (RecorderState::Held(HoldReason::ClockOutOfRange), false),
        (RecorderState::Held(HoldReason::StorageFull), true),
        (RecorderState::Held(HoldReason::WriteFailed), false),
        (RecorderState::Held(HoldReason::BadParameters), false),
        (RecorderState::Held(HoldReason::IndexUnavailable), false),
        (RecorderState::Held(HoldReason::IndexReadOnly), false),
    ];
    for (state, full) in table {
        assert_eq!(state_is_full(state), full, "{state:?}");
    }
}

/// A real recorder's health value (the type cannot be built outside its crate): a recorder that
/// saw nothing and was finished.
fn idle_health(site: &Site) -> RecorderHealth {
    let index = SharedIndex::new(Index::open(site.config.database_path()).unwrap());
    let id = CameraId::new("cam-health").unwrap();
    let root = RootDir::open(&site.hot()).unwrap();
    let (recorder, _rx) = Recorder::new(
        id.clone(),
        RecorderConfig::default(),
        HotStore::new(root, id),
        index,
        None,
    )
    .unwrap();
    recorder.finish()
}

/// The ENOSPC wake where it is wired: a recorder health that moves to `Held(StorageFull)` makes
/// the storage loop tick long before its (hour-long) interval; another hold (`WriteFailed`) does
/// not. Ticks are counted by the loop's clock, and every wait is on that observable count with a
/// timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_recorder_wakes_the_storage_loop_before_the_interval() {
    let site = Site::new();
    let health = idle_health(&site);
    let (tx, rx) = watch::channel(health);
    let (snap_tx, _snap_rx) = watch::channel(StorageSnapshot::initial());
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    let task = storage_task::spawn(
        storage::looper(&site),
        Duration::from_secs(3600),
        snap_tx,
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
            wall_now()
        },
    )
    .unwrap();
    wire_storage_wake(rx, task.waker());
    let ticks_after = |n: usize| {
        let count = Arc::clone(&count);
        async move {
            // Hang guard (TEST-5): 30 s, far above host load.
            tokio::time::timeout(Duration::from_secs(30), async {
                while count.load(Ordering::SeqCst) <= n {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok()
        }
    };
    assert!(ticks_after(0).await, "the loop ticks at start");
    let at_start = count.load(Ordering::SeqCst);

    // Another hold is not a wake: no tick follows within a generous wait.
    let mut other = health;
    other.state = RecorderState::Held(HoldReason::WriteFailed);
    tx.send_replace(other);
    let early = tokio::time::timeout(Duration::from_millis(300), ticks_after(at_start)).await;
    assert!(early.is_err(), "a WriteFailed hold ticked the storage loop");

    let mut full = health;
    full.state = RecorderState::Held(HoldReason::StorageFull);
    tx.send_replace(full);
    assert!(
        ticks_after(at_start).await,
        "StorageFull did not wake the loop"
    );
    tokio::task::spawn_blocking(move || task.stop())
        .await
        .unwrap();
}

/// The state of a probe that blocks once: armed flag, release signal, "entered" signal.
type Block = (
    AtomicBool,
    Mutex<std::sync::mpsc::Receiver<()>>,
    Mutex<Option<std::sync::mpsc::Sender<()>>>,
);

/// A volume source for the start-up reconciliation: it fails the hot volume, or blocks the first
/// probe until released.
#[derive(Clone)]
struct Startup {
    fail_hot: bool,
    block: Option<Arc<Block>>,
}

impl VolumeUsage for Startup {
    fn space(&self, tier: Tier, root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        if self.fail_hot && tier == Tier::Hot {
            return Err(ProbeError::Unusable);
        }
        if let Some(b) = self
            .block
            .as_ref()
            .filter(|b| b.0.swap(false, Ordering::SeqCst))
        {
            if let Some(tx) = b.2.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let _ = b.1.lock().unwrap().recv();
        }
        StatvfsUsage.space(tier, root)
    }
}

/// `ServeError::Reconcile`: the hot volume cannot be probed at start-up, so nothing starts.
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_hot_volume_at_start_up_is_a_reconcile_error() {
    let site = Site::new();
    let svc = site.start_with(
        Vec::<CameraInput<Fake>>::new(),
        quick(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        Startup {
            fail_hot: true,
            block: None,
        },
    );
    let r = tokio::time::timeout(Duration::from_secs(10), svc.task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(r, Err(ServeError::Reconcile(_))), "{r:?}");
    // The hot-root lock file was released with the failed start.
    let hot = RootDir::open(&site.hot()).unwrap();
    lock::lock_hot_root(&hot).unwrap();
}

/// A stop signal while the start-up reconciliation is stuck returns at once with nothing
/// started, and releasing the runtime does not wait for the stuck probe.
#[test]
fn a_stop_signal_during_a_stuck_start_up_exits_promptly() {
    let site = Site::new();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let usage = Startup {
        fail_hot: false,
        block: Some(Arc::new((
            AtomicBool::new(true),
            Mutex::new(release_rx),
            Mutex::new(Some(entered_tx)),
        ))),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let at = std::time::Instant::now();
    let result = runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let svc = site.start_with(Vec::<CameraInput<Fake>>::new(), quick(), listener, usage);
        // The reconciliation is inside the probe and will not return by itself.
        tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
            .await
            .unwrap();
        let (_took, result) = svc.shutdown().await;
        result
    });
    assert_eq!(result.unwrap(), Stopped::Abandoned);
    release_runtime(runtime, false);
    // The exit contract: the stuck reconciliation must not hold the exit past the 10 s
    // SHUTDOWN_DEADLINE.
    assert!(at.elapsed() < Duration::from_secs(10), "{:?}", at.elapsed());
    assert_eq!(
        site.files(".mp4") + site.files(".part"),
        0,
        "nothing was started"
    );
    let _ = release_tx.send(());
}

/// An acceptor that fails its first calls (as `EMFILE` does), then delegates.
struct Flaky {
    inner: TcpListener,
    failures: Arc<AtomicUsize>,
    seen: Arc<AtomicUsize>,
}

impl Accept for Flaky {
    async fn accept(&mut self) -> std::io::Result<TcpStream> {
        self.seen.fetch_add(1, Ordering::SeqCst);
        if self.failures.load(Ordering::SeqCst) > 0 {
            self.failures.fetch_sub(1, Ordering::SeqCst);
            return Err(std::io::Error::from_raw_os_error(24));
        }
        self.inner.accept().await.map(|(s, _)| s)
    }
}

/// Accept errors are logged and backed off; the loop keeps serving afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn accept_errors_do_not_end_the_loop() {
    let site = Site::new();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = inner.local_addr().unwrap();
    let failures = Arc::new(AtomicUsize::new(3));
    let seen = Arc::new(AtomicUsize::new(0));
    let flaky = Flaky {
        inner,
        failures: Arc::clone(&failures),
        seen: Arc::clone(&seen),
    };
    let svc = site.start_on(
        Vec::<CameraInput<Fake>>::new(),
        quick(),
        flaky,
        addr,
        StatvfsUsage,
    );
    let (status, _) = svc.get("/api/v1/health").await;
    assert_eq!(status, 200);
    assert_eq!(
        failures.load(Ordering::SeqCst),
        0,
        "the failures were consumed"
    );
    assert!(seen.load(Ordering::SeqCst) >= 4);
    svc.shutdown().await.1.unwrap();
}

/// A stop signal while a camera is still being set up (its recorder build is held by the test
/// hook) is not held up by it: the service stops cleanly, within the deadline, with that camera
/// not started.
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_signal_during_camera_start_up_does_not_wait_for_the_camera() {
    /// Counts how often ingest opened it: a camera that was never started is never opened.
    struct Counting(Arc<AtomicUsize>);

    impl StreamSource for Counting {
        type Stream = FakeStream;

        fn open(
            &mut self,
            _idle: Duration,
        ) -> impl Future<Output = Result<FakeStream, IngestError>> + Send {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(IngestError::OpenFailed))
        }
    }

    let site = Site::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let entered = Mutex::new(Some(entered_tx));
    let release = Mutex::new(release_rx);
    let mut tuning = quick();
    tuning.before_recorder = Some(Arc::new(move || {
        if let Some(tx) = entered.lock().unwrap().take() {
            let _ = tx.send(());
        }
        let _ = release.lock().unwrap().recv();
    }));
    let opens = Arc::new(AtomicUsize::new(0));
    let svc = site
        .start(
            vec![CameraInput {
                camera: camera("cam-ok", "192.0.2.10"),
                source: Counting(Arc::clone(&opens)),
            }],
            tuning,
        )
        .await;
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    let at = std::time::Instant::now();
    let stopped = tokio::time::timeout(Duration::from_secs(10), svc.shutdown())
        .await
        .expect("the stop is not held by the camera that is being set up");
    // The 10 s timeout above is the real check; this is a redundant margin (TEST-5).
    assert!(at.elapsed() < Duration::from_secs(30));
    assert_eq!(stopped.1.unwrap(), Stopped::Clean);
    // Let the abandoned set-up finish; its recorder is dropped, and ingest never opened it.
    let _ = release_tx.send(());
    assert_eq!(opens.load(Ordering::SeqCst), 0, "the camera was started");
}
