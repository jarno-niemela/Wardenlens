//! Adversarial tests, round 2 of PR #198: a *clean* stop must not hold the process on blocking
//! work either. `release_runtime(_, true)` drops the runtime, which waits without limit for every
//! `spawn_blocking` task still running. Ingest's real source reaches such a task on every connect
//! to a camera named by a DNS host (retina calls `TcpStream::connect((host, port))`, whose
//! `lookup_host` runs `getaddrinfo` on the blocking pool). A hung resolver at SIGTERM then keeps
//! `serve` alive past the 10 s deadline even though every part "stopped in time".

use std::sync::Mutex;

use super::*;

/// A source whose `open` resolves its host on the blocking pool, as tokio's `lookup_host` does,
/// with a resolver that does not answer until the test releases it.
struct HangingResolver {
    entered: Option<std::sync::mpsc::Sender<()>>,
    release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
}

impl StreamSource for HangingResolver {
    type Stream = FakeStream;

    fn open(
        &mut self,
        _idle: Duration,
    ) -> impl Future<Output = Result<FakeStream, IngestError>> + Send {
        let entered = self.entered.take();
        let release = Arc::clone(&self.release);
        async move {
            let _ = tokio::task::spawn_blocking(move || {
                if let Some(tx) = entered {
                    let _ = tx.send(());
                }
                // getaddrinfo stuck on an unreachable name server.
                let _ = release.lock().unwrap().recv();
            })
            .await;
            Err(IngestError::OpenFailed)
        }
    }
}

#[test]
fn a_clean_stop_does_not_wait_for_a_hung_dns_lookup() {
    let site = Site::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let source = HangingResolver {
        entered: Some(entered_tx),
        release: Arc::new(Mutex::new(release_rx)),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let svc = site
            .start(
                vec![CameraInput {
                    camera: camera("cam-dns", "camera.invalid"),
                    source,
                }],
                quick(),
            )
            .await;
        // The supervisor is inside the lookup.
        tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
            .await
            .unwrap();
        let (took, result) = svc.shutdown().await;
        assert!(took < Duration::from_secs(10), "{took:?}");
        result
    });
    // Every part stopped in time, so `serve` takes the clean path.
    let clean = matches!(result, Ok(Stopped::Clean));
    assert!(clean, "{result:?}");

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        release_runtime(runtime, clean);
        let _ = done_tx.send(());
    });
    let exited = done_rx.recv_timeout(Duration::from_secs(3)).is_ok();
    // Unblock the lookup so the test cleans up either way.
    let _ = release_tx.send(());
    let _ = done_rx.recv_timeout(Duration::from_secs(10));
    assert!(
        exited,
        "the clean release waited for a blocking DNS lookup: `serve` does not exit until the \
         resolver answers"
    );
}
