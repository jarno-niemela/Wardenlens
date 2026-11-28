//! End-to-end tests of the composition root with fake stream sources and temporary volumes
//! (ticket #68). Synthetic camera ids and TEST-NET addresses only; nothing here contacts a camera
//! or reads the user's configuration, data directory or vault.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "tests: small bounded synthetic values"
)]

use std::collections::VecDeque;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use wardenlens_api::token::Token;
use wardenlens_core::camera::{Camera, CameraId, DisplayName, Host, ModelRef, RtspPath, StreamSet};
use wardenlens_core::config::Config;
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_core::token_store::{NewToken, TokenName};
use wardenlens_core::video::{Frame, H264Params};
use wardenlens_index::Index;
use wardenlens_ingest::{FrameSource, IngestError, StreamSource};
use wardenlens_storage::{ARCHIVE_MARKER, StatvfsUsage, VolumeUsage};

use super::*;

mod accept;
mod adversary;
mod adversary_r2;
mod adversary_r3;
mod round2;
mod storage;

const SPS: [u8; 7] = [0x67, 0x42, 0xc0, 0x0a, 0xf8, 0x41, 0xa2];
const PPS: [u8; 4] = [0x68, 0xce, 0x38, 0x80];

/// A fake source: frames pushed by the test, or a source that never opens.
enum Fake {
    Live(Option<mpsc::UnboundedReceiver<Frame>>),
    Fails,
}

struct FakeStream(VecDeque<Frame>, mpsc::UnboundedReceiver<Frame>);

impl FrameSource for FakeStream {
    async fn next_frame(&mut self) -> Result<Option<Frame>, IngestError> {
        if let Some(f) = self.0.pop_front() {
            return Ok(Some(f));
        }
        match self.1.recv().await {
            Some(f) => Ok(Some(f)),
            // The test keeps its sender; a closed one means "no more frames, stay connected".
            None => std::future::pending().await,
        }
    }
}

impl StreamSource for Fake {
    type Stream = FakeStream;

    fn open(
        &mut self,
        _idle: Duration,
    ) -> impl Future<Output = Result<FakeStream, IngestError>> + Send {
        std::future::ready(match self {
            Self::Live(rx) => rx
                .take()
                .map(|rx| FakeStream(VecDeque::new(), rx))
                .ok_or(IngestError::OpenFailed),
            Self::Fails => Err(IngestError::OpenFailed),
        })
    }
}

fn avcc(key: bool) -> Vec<u8> {
    let (header, first) = if key { (0x65, 0x88) } else { (0x41, 0xe0) };
    let mut v = 398u32.to_be_bytes().to_vec();
    v.push(header);
    v.push(first);
    v.resize(4 + 398, 0xaa);
    v
}

/// `count` frames one second apart starting at `start_ms`, a keyframe every fifth; the first
/// carries the parameter sets and is a discontinuity, as ingest's first frame of a session is.
fn frames(first_index: u32, count: u32, start_ms: i64) -> Vec<Frame> {
    (first_index..first_index + count)
        .map(|i| {
            let first = i == 0;
            Frame::new(
                avcc(i % 5 == 0),
                i % 5 == 0,
                i * 90_000,
                Timestamp::from_unix_millis(start_ms + i64::from(i) * 1000),
                first.then(|| H264Params::new(SPS.to_vec(), PPS.to_vec())),
                first,
            )
        })
        .collect()
}

fn camera(id: &str, host: &str) -> Camera {
    Camera::new(
        CameraId::new(id).unwrap(),
        DisplayName::new("Test camera").unwrap(),
        ModelRef::new("acme", "c1").unwrap(),
        Host::new(host).unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(RtspPath::new("/stream1").unwrap(), None),
    )
}

fn private_dir(p: &Path) {
    fs::create_dir_all(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

/// The temporary site: volumes, index, a token, the config.
struct Site {
    dir: TempDir,
    config: Config,
    token: String,
}

impl Site {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path().display().to_string();
        for d in ["hot", "archive", "state"] {
            private_dir(&dir.path().join(d));
        }
        fs::write(dir.path().join("archive").join(ARCHIVE_MARKER), b"").unwrap();
        let config = Config::from_toml_str(&format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[recording]\nsegment_target_secs = 10\n\
             [database]\npath = \"{t}/state/index.db\"\n[secrets]\nkey_file = \"{t}/keys/k\"\n"
        ))
        .unwrap();
        let mut index = Index::open(config.database_path()).unwrap();
        let token = Token::generate().unwrap();
        index
            .insert_token(&NewToken {
                id: *token.id(),
                digest: token.secret().digest(),
                name: TokenName::new("test").unwrap(),
                created_at: UnixMs::new(1_700_000_000_000).unwrap(),
            })
            .unwrap();
        drop(index);
        Self {
            dir,
            config,
            token: token.expose(),
        }
    }

    fn hot(&self) -> PathBuf {
        self.dir.path().join("hot")
    }

    /// Hot-tier files with this suffix, whatever the camera and day.
    fn files(&self, suffix: &str) -> usize {
        let mut n = 0;
        let mut stack = vec![self.hot()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.to_string_lossy().ends_with(suffix) {
                    n += 1;
                }
            }
        }
        n
    }

    /// Starts the service on a loopback listener.
    async fn start<S: StreamSource>(
        &self,
        cameras: Vec<CameraInput<S>>,
        tuning: Tuning,
    ) -> Running_ {
        self.start_with(
            cameras,
            tuning,
            TcpListener::bind("127.0.0.1:0").await.unwrap(),
            StatvfsUsage,
        )
    }

    /// As `start`, with the acceptor and the volume source chosen by the test.
    fn start_with<S, U>(
        &self,
        cameras: Vec<CameraInput<S>>,
        tuning: Tuning,
        listener: TcpListener,
        usage: U,
    ) -> Running_
    where
        S: StreamSource,
        U: VolumeUsage + Send + 'static,
    {
        let addr = listener.local_addr().unwrap();
        self.start_on(cameras, tuning, listener, addr, usage)
    }

    fn start_on<S, L, U>(
        &self,
        cameras: Vec<CameraInput<S>>,
        tuning: Tuning,
        listener: L,
        addr: SocketAddr,
        usage: U,
    ) -> Running_
    where
        S: StreamSource,
        L: Accept,
        U: VolumeUsage + Send + 'static,
    {
        let index = Index::open(self.config.database_path()).unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let stats = tuning.stats.clone();
        let config = self.config.clone();
        let task = tokio::spawn(async move {
            run(
                &config,
                index,
                cameras,
                listener,
                async {
                    let _ = rx.await;
                },
                tuning,
                usage,
            )
            .await
        });
        Running_ {
            addr,
            token: self.token.clone(),
            stop: Some(stop),
            task,
            stats,
        }
    }
}

/// A running service.
struct Running_ {
    addr: SocketAddr,
    token: String,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<Stopped, ServeError>>,
    stats: ConnectionStats,
}

impl Running_ {
    /// Stops the service and returns how long that took and its result.
    async fn shutdown(mut self) -> (Duration, Result<Stopped, ServeError>) {
        let at = std::time::Instant::now();
        self.stop.take().unwrap().send(()).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(20), self.task)
            .await
            .expect("the service stops")
            .unwrap();
        (at.elapsed(), r)
    }

    /// `GET path` with the bearer token; the status and the body.
    async fn get(&self, path: &str) -> (u16, serde_json::Value) {
        let mut s = TcpStream::connect(self.addr).await.unwrap();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            self.token
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text.split(' ').nth(1).unwrap().parse().unwrap();
        let body = text.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        (
            status,
            serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
        )
    }
}

async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..300 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn quick() -> Tuning {
    Tuning {
        storage_interval: Duration::from_millis(100),
        allow_same_filesystem: true,
        ..Tuning::default()
    }
}

fn now_ms() -> i64 {
    wall_now().as_unix_millis()
}

/// Acceptance: fake sources and temporary volumes; one camera fails to open and the other
/// records; the API lists the segments and shows both tiers; the failing camera does not
/// disturb the healthy one.
#[tokio::test(flavor = "multi_thread")]
async fn e2e_recordings_are_listed_both_tiers_are_shown_and_a_failing_camera_is_isolated() {
    let site = Site::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let svc = site
        .start(
            vec![
                CameraInput {
                    camera: camera("cam-bad", "192.0.2.20"),
                    source: Fake::Fails,
                },
                CameraInput {
                    camera: camera("cam-ok", "192.0.2.10"),
                    source: Fake::Live(Some(rx)),
                },
            ],
            quick(),
        )
        .await;
    // 22 frames one second apart with a keyframe every fifth: the 10 s target is reached at the
    // keyframe of frame 10 and again at frame 20, so two segments close while running.
    for f in frames(0, 22, now_ms() - 3_600_000) {
        tx.send(f).unwrap();
    }
    eventually("two segments are listed", || async {
        let (status, body) = svc.get("/api/v1/recordings?camera=cam-ok").await;
        status == 200 && body["segments"].as_array().is_some_and(|s| s.len() == 2)
    })
    .await;
    let (_, list) = svc.get("/api/v1/recordings?camera=cam-ok").await;
    assert_eq!(list["segments"][0]["camera"], "cam-ok");
    assert_eq!(list["segments"][0]["tier"], "hot");
    assert!(list["segments"][0]["bytes"].as_u64().unwrap() > 0);
    // The failing camera has no segments and the API still answers for it.
    let (status, bad) = svc.get("/api/v1/recordings?camera=cam-bad").await;
    assert_eq!(status, 200);
    assert_eq!(bad["segments"].as_array().unwrap().len(), 0);

    // Both tiers are shown, and the storage loop has ticked (it ticks at start and every 100 ms).
    eventually("the storage snapshot has both tiers", || async {
        let (_, s) = svc.get("/api/v1/storage").await;
        s["hot"]["total_bytes"].is_u64()
            && s["archive"]["total_bytes"].is_u64()
            && s["archive"]["state"] == "available"
            && s["hot"]["segments"].as_u64().is_some_and(|n| n >= 2)
    })
    .await;

    // Connection state: the healthy camera streams, the failing one does not.
    eventually("cam-ok is streaming", || async {
        let (_, c) = svc.get("/api/v1/cameras/cam-ok").await;
        c["connection"]["state"] == "streaming"
    })
    .await;
    let (_, c) = svc.get("/api/v1/cameras/cam-bad").await;
    assert_ne!(c["connection"]["state"], "streaming");

    // No token, no data.
    let mut s = TcpStream::connect(svc.addr).await.unwrap();
    s.write_all(b"GET /api/v1/storage HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).await.unwrap();
    assert!(buf.starts_with("HTTP/1.1 401"), "{buf}");

    let (took, result) = svc.shutdown().await;
    result.unwrap();
    assert!(took < Duration::from_secs(10), "stopped in {took:?}");
}

/// Acceptance: SIGTERM-equivalent shutdown flushes and indexes the open segment and finishes
/// within 10 s; the next start sees the row (and the reconciliation does not touch it).
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_flushes_and_indexes_the_open_segment_within_the_deadline() {
    let site = Site::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let svc = site
        .start(
            vec![CameraInput {
                camera: camera("cam-ok", "192.0.2.10"),
                source: Fake::Live(Some(rx)),
            }],
            quick(),
        )
        .await;
    // Three seconds of video: no segment has closed yet.
    for f in frames(0, 3, now_ms() - 3_600_000) {
        tx.send(f).unwrap();
    }
    eventually("the segment is open", || async { site.files(".part") == 1 }).await;
    assert_eq!(site.files(".mp4"), 0);
    let (took, result) = svc.shutdown().await;
    result.unwrap();
    assert!(took < Duration::from_secs(10), "stopped in {took:?}");
    assert_eq!(site.files(".part"), 0, "no .part is left");
    assert_eq!(site.files(".mp4"), 1, "the open segment was finished");

    // Restart: the segment is listed, and the first run's reconciliation had nothing to repair.
    let svc = site.start::<Fake>(Vec::new(), quick()).await;
    let (status, list) = svc.get("/api/v1/recordings?camera=cam-ok").await;
    assert_eq!(status, 200);
    assert_eq!(list["segments"].as_array().unwrap().len(), 1);
    svc.shutdown().await.1.unwrap();
}

/// A service with no cameras still runs and answers; the health route is open.
#[tokio::test(flavor = "multi_thread")]
async fn a_service_without_cameras_serves_the_api() {
    let site = Site::new();
    let svc = site.start::<Fake>(Vec::new(), quick()).await;
    let (status, body) = svc.get("/api/v1/cameras").await;
    assert_eq!(status, 200);
    assert!(body.as_array().is_some_and(Vec::is_empty) || body["cameras"].is_array());
    svc.shutdown().await.1.unwrap();
}

/// The ENOSPC wake: a rising edge sends one tick; staying true sends no more; a new edge sends
/// again; the task ends when the sender of the channel is dropped. Nothing here sleeps: the
/// predicate counts the states it has judged, so "no tick" is asserted only after the task has
/// seen the value, and a tick is waited for with a timeout.
#[tokio::test]
async fn wake_when_sends_one_tick_per_rising_edge() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (tx, rx) = tokio::sync::watch::channel(0u8);
    let (wake, inbox) = std::sync::mpsc::channel();
    let judged = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&judged);
    let task = tokio::spawn(wake_when(
        rx,
        move |v| {
            counter.fetch_add(1, Ordering::SeqCst);
            *v >= 2
        },
        wake,
    ));
    // Waits until the task has judged `n` values in total.
    let judged_at_least = |n: usize| {
        let judged = Arc::clone(&judged);
        async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                while judged.load(Ordering::SeqCst) < n {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the task judged the value");
        }
    };
    let send = |value: u8, n: usize| {
        tx.send_replace(value);
        judged_at_least(n)
    };
    // The task first judges the initial value; later values would coalesce with it before.
    judged_at_least(1).await;
    send(1, 2).await;
    assert!(inbox.try_recv().is_err(), "not full yet");
    send(2, 3).await;
    assert_eq!(
        inbox.recv_timeout(Duration::from_secs(5)).unwrap(),
        Wake::Tick
    );
    send(3, 4).await;
    assert!(inbox.try_recv().is_err(), "still full: no second tick");
    send(0, 5).await;
    send(2, 6).await;
    assert_eq!(
        inbox.recv_timeout(Duration::from_secs(5)).unwrap(),
        Wake::Tick,
        "a new edge ticks again"
    );
    drop(tx);
    task.await.unwrap();
}

/// Shutdown reports a part that does not stop within the deadline, and does not wait for it
/// longer than the deadline; with every part stopped it reports success.
#[tokio::test(flavor = "multi_thread")]
async fn stop_all_reports_a_part_that_overruns_the_deadline() {
    let site = Site::new();
    let storage = |site: &Site| {
        let (tx, _rx) = watch::channel(wardenlens_core::storage::StorageSnapshot::initial());
        storage_task::spawn(
            storage::looper(site),
            Duration::from_secs(3600),
            tx,
            wall_now,
        )
        .unwrap()
    };
    let stuck = tokio::spawn(std::future::pending::<()>());
    let at = std::time::Instant::now();
    let deadline = Instant::now() + Duration::from_millis(300);
    assert!(!stop_all(Vec::new(), storage(&site), stuck, deadline).await);
    // `stuck` never ends; the 300 ms deadline must cut it off. A huge bound still catches a hang.
    assert!(at.elapsed() < Duration::from_secs(30), "{:?}", at.elapsed());

    let done = tokio::spawn(async {});
    let deadline = Instant::now() + Duration::from_secs(10);
    assert!(stop_all(Vec::new(), storage(&site), done, deadline).await);
}
