//! Adversarial tests (PR #198 verification): keep-alive idleness, trickled headers, sources that
//! hang, and a storage tick that overruns the shutdown deadline.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use wardenlens_core::storage::{Tier, VolumeSpace};
use wardenlens_fsutil::RootDir;
use wardenlens_storage::{ProbeError, VolumeUsage};

use super::*;

fn short(timeout: Duration) -> Tuning {
    Tuning {
        http: HttpLimits {
            header_read_timeout: timeout,
            ..HttpLimits::default()
        },
        ..quick()
    }
}

/// Reads one response (headers plus a `Content-Length` body) off a keep-alive connection.
async fn read_one_response(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk))
            .await
            .expect("response arrives")
            .unwrap();
        assert!(n > 0, "closed before a full response");
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).into_owned();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if body.len() >= len {
                return text;
            }
        }
    }
}

/// A keep-alive connection that completed one request and then goes idle must be closed by the
/// server within the header timeout (ADR 0004: the header timeout also bounds idle keep-alive).
#[tokio::test(flavor = "multi_thread")]
async fn a_keep_alive_connection_idle_after_a_request_is_closed_within_the_header_timeout() {
    let site = Site::new();
    let svc = site
        .start::<Fake>(Vec::new(), short(Duration::from_secs(1)))
        .await;
    let mut s = TcpStream::connect(svc.addr).await.unwrap();
    s.write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let resp = read_one_response(&mut s).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    // Now idle: the server must close within the 1 s timeout (5 s slack).
    let mut b = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(6), s.read(&mut b)).await;
    assert!(
        matches!(r, Ok(Ok(0) | Err(_))),
        "an idle keep-alive connection was still open 6 s after its response: {r:?}"
    );
    svc.shutdown().await.1.unwrap();
}

/// Headers trickled one byte at a time never complete: the connection is closed within the
/// header timeout, not kept alive by each byte.
#[tokio::test(flavor = "multi_thread")]
async fn trickled_header_bytes_do_not_extend_the_header_timeout() {
    let site = Site::new();
    let svc = site
        .start::<Fake>(Vec::new(), short(Duration::from_secs(1)))
        .await;
    let mut s = TcpStream::connect(svc.addr).await.unwrap();
    let start = std::time::Instant::now();
    let line = b"GET /api/v1/health HTTP/1.1\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut closed = false;
    for b in line.iter().cycle().take(200) {
        if s.write_all(&[*b]).await.is_err() {
            closed = true;
            break;
        }
        // Peek for a close without blocking.
        let mut probe = [0u8; 64];
        // Any completed read (EOF, reset, or a 408 before the close) ends the connection.
        if tokio::time::timeout(Duration::from_millis(100), s.read(&mut probe))
            .await
            .is_ok()
        {
            closed = true;
            break;
        }
    }
    assert!(
        closed,
        "a trickling client kept the connection open for 20 s"
    );
    assert!(
        start.elapsed() < Duration::from_secs(6),
        "closed only after {:?}",
        start.elapsed()
    );
    svc.shutdown().await.1.unwrap();
}

/// A source whose `open` never completes and ignores cancellation.
struct Hangs;

impl StreamSource for Hangs {
    type Stream = FakeStream;

    fn open(
        &mut self,
        _idle: Duration,
    ) -> impl Future<Output = Result<FakeStream, IngestError>> + Send {
        std::future::pending()
    }
}

/// A camera that hangs in `open` does not hold the shutdown: the service still stops on time
/// and the other camera's open segment is flushed and indexed.
#[tokio::test(flavor = "multi_thread")]
async fn a_camera_hung_in_open_does_not_hold_shutdown() {
    enum Either {
        Live(Fake),
        Hung(Hangs),
    }
    impl StreamSource for Either {
        type Stream = FakeStream;
        fn open(
            &mut self,
            idle: Duration,
        ) -> impl Future<Output = Result<FakeStream, IngestError>> + Send {
            let fut: std::pin::Pin<
                Box<dyn Future<Output = Result<FakeStream, IngestError>> + Send>,
            > = match self {
                Self::Live(f) => Box::pin(f.open(idle)),
                Self::Hung(h) => Box::pin(h.open(idle)),
            };
            fut
        }
    }
    let site = Site::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let svc = site
        .start(
            vec![
                CameraInput {
                    camera: camera("cam-hung", "192.0.2.30"),
                    source: Either::Hung(Hangs),
                },
                CameraInput {
                    camera: camera("cam-ok", "192.0.2.10"),
                    source: Either::Live(Fake::Live(Some(rx))),
                },
            ],
            quick(),
        )
        .await;
    for f in frames(0, 3, now_ms() - 3_600_000) {
        tx.send(f).unwrap();
    }
    eventually("the segment is open", || async { site.files(".part") == 1 }).await;
    let (took, result) = svc.shutdown().await;
    result.unwrap();
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(site.files(".part"), 0);
    assert_eq!(site.files(".mp4"), 1);
}

/// A `VolumeUsage` that, once armed, blocks the next probe until released (a hung NFS or a slow
/// archive copy: a storage tick that runs past the shutdown deadline).
#[derive(Clone)]
struct Gate {
    armed: Arc<AtomicBool>,
    entered: Arc<Mutex<Option<std::sync::mpsc::Sender<()>>>>,
    release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
}

impl VolumeUsage for Gate {
    fn space(&self, tier: Tier, root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            if let Some(tx) = self.entered.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let _ = self.release.lock().unwrap().recv();
        }
        StatvfsUsage.space(tier, root)
    }
}

/// `serve` releases its runtime when `run` returns (`ShutdownTimeout` included) with
/// [`release_runtime`]. If a storage tick is still running then, a plain drop would wait for the
/// blocking `storage.stop()` join, so the process would not exit when the deadline is missed. This
/// test reproduces `commands::serve::start`'s shape (runtime built, `block_on`, runtime released)
/// around the real `stop_all` and storage thread: past the deadline the process exits without
/// waiting for blocking tasks.
#[test]
fn a_storage_tick_past_the_deadline_does_not_hold_the_process_past_it() {
    let site = Site::new();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let gate = Gate {
        armed: Arc::new(AtomicBool::new(false)),
        entered: Arc::new(Mutex::new(Some(entered_tx))),
        release: Arc::new(Mutex::new(release_rx)),
    };
    let index = SharedIndex::new(Index::open(site.config.database_path()).unwrap());
    let cfg = wardenlens_storage::StorageConfig::new(
        site.config.hot_root().to_path_buf(),
        site.config.archive_root().to_path_buf(),
        site.config.storage_policy(),
    )
    .with_allow_same_filesystem(true);
    let (looper, _files) = Storage::open(cfg, index, gate.clone()).unwrap();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let on_time = runtime.block_on(async {
        let (tx, _rx) = watch::channel(wardenlens_core::storage::StorageSnapshot::initial());
        let storage = storage_task::spawn(looper, Duration::from_millis(20), tx, wall_now).unwrap();
        gate.armed.store(true, Ordering::SeqCst);
        // The storage thread is now inside a tick that will not finish by itself.
        entered_rx.recv().unwrap();
        let http = tokio::spawn(async {});
        let deadline = Instant::now() + Duration::from_millis(300);
        stop_all(Vec::new(), storage, http, deadline).await
    });
    assert!(!on_time, "the overrun is reported");

    // `start` releases the runtime here; the process should now be able to exit.
    let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        release_runtime(runtime, false);
        let _ = dropped_tx.send(());
    });
    let exited = dropped_rx.recv_timeout(Duration::from_secs(3)).is_ok();
    // Unblock the tick so the test cleans up either way.
    let _ = release_tx.send(());
    let _ = dropped_rx.recv_timeout(Duration::from_secs(10));
    assert!(
        exited,
        "dropping the runtime after a missed deadline blocked on the storage tick: \
         `serve` would not exit (with 1) until the tick ends"
    );
}
