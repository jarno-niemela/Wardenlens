//! The accept loop (ADR 0004 section 9): header and idle timeouts, the connection cap, and the
//! rule that hostile connections do not stop recording.

use super::*;

/// The cap of ADR 0004 section 9, written out so that changing the constant fails the tests.
const CAP: usize = 256;

/// These tests count this process's descriptors and hold hundreds of sockets: they run one at a
/// time (the other tests of the binary use a few dozen descriptors at most).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

fn short(timeout: Duration) -> Tuning {
    Tuning {
        http: HttpLimits {
            header_read_timeout: timeout,
            ..HttpLimits::default()
        },
        ..quick()
    }
}

/// True when the server closed the connection (EOF or reset) within `within`.
async fn closed_within(mut s: TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 64];
    match tokio::time::timeout(within, s.read(&mut buf)).await {
        Ok(Ok(0) | Err(_)) => true,
        // A 408 answer followed by a close counts as closed too: read on until EOF.
        Ok(Ok(_)) => tokio::time::timeout(within, s.read_to_end(&mut Vec::new()))
            .await
            .is_ok(),
        Err(_) => false,
    }
}

/// A connection that sends partial headers and an idle one are both closed within the timeout,
/// and recording continues while 300 of them are held.
#[tokio::test(flavor = "multi_thread")]
async fn partial_header_and_idle_connections_are_closed_and_recording_continues() {
    let _serial = SERIAL.lock().await;
    raise_nofile_limit().unwrap();
    let site = Site::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let svc = site
        .start(
            vec![CameraInput {
                camera: camera("cam-ok", "192.0.2.10"),
                source: Fake::Live(Some(rx)),
            }],
            short(Duration::from_secs(2)),
        )
        .await;
    for f in frames(0, 12, now_ms() - 3_600_000) {
        tx.send(f).unwrap();
    }
    eventually("a segment is on disk", || async { site.files(".mp4") == 1 }).await;

    let mut held = Vec::new();
    for i in 0..300 {
        let mut s = TcpStream::connect(svc.addr).await.unwrap();
        if i % 2 == 0 {
            // Partial headers: the request line and one header, never the blank line.
            s.write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: x\r\n")
                .await
                .unwrap();
        }
        held.push(s);
    }
    // Recording continues while the connections are held (the API may be saturated by design;
    // the files are the evidence).
    for f in frames(12, 10, now_ms() - 3_600_000) {
        tx.send(f).unwrap();
    }
    eventually(
        "a second segment closes while 300 connections are open",
        || async { site.files(".mp4") == 2 },
    )
    .await;
    assert!(svc.stats.peak() <= CAP);

    // Every one of them is closed by the server within the header timeout (1 s; 9 s of slack for host load, under the 10 s default).
    let mut ok = 0;
    for s in held {
        if closed_within(s, Duration::from_secs(9)).await {
            ok += 1;
        }
    }
    assert_eq!(
        ok, 300,
        "every partial-header and idle connection was closed"
    );
    // The API answers again.
    let (status, _) = svc.get("/api/v1/health").await;
    assert_eq!(status, 200);
    svc.shutdown().await.1.unwrap();
}

/// About 2000 connections never make more than 256 served at once, and the process's descriptor
/// count stays bounded (the rest wait in the kernel backlog or are refused by the client side).
#[tokio::test(flavor = "multi_thread")]
async fn two_thousand_connections_never_exceed_the_cap() {
    let _serial = SERIAL.lock().await;
    raise_nofile_limit().unwrap();
    let site = Site::new();
    let svc = site
        .start::<Fake>(Vec::new(), short(Duration::from_secs(1)))
        .await;
    let before = fd_count();
    let mut tasks = Vec::new();
    for _ in 0..2000 {
        let addr = svc.addr;
        tasks.push(tokio::spawn(async move {
            // Connections beyond the backlog may stall in the handshake; that is the point.
            let Ok(Ok(mut s)) =
                tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await
            else {
                return;
            };
            let _ = tokio::time::timeout(Duration::from_secs(4), s.read(&mut [0u8; 8])).await;
        }));
    }
    // While they churn, sample the server's descriptor use from the outside.
    let mut most = 0;
    for _ in 0..30 {
        most = most.max(fd_count());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert!(svc.stats.peak() > 0, "some connections were served");
    assert!(
        svc.stats.peak() <= CAP,
        "peak {} over the cap",
        svc.stats.peak()
    );
    // Client sockets (2000, in this same process) and at most 256 served ones; a leak in the
    // server would show as growth past that.
    assert!(most <= before + 2000 + CAP + 256, "fds {most} vs {before}");
    eventually("the descriptors are released", || async {
        fd_count() <= before + 16
    })
    .await;
    svc.shutdown().await.1.unwrap();
}

/// Accept errors do not end the loop; stopping the service closes the listener and finishes
/// even with a client that never sends anything.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_does_not_wait_for_an_idle_client_past_the_grace() {
    let site = Site::new();
    let svc = site
        .start::<Fake>(Vec::new(), short(Duration::from_secs(60)))
        .await;
    let _idle = TcpStream::connect(svc.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (took, r) = svc.shutdown().await;
    r.unwrap();
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn the_cap_and_the_header_timeout_are_the_documented_ones() {
    assert_eq!(http::MAX_CONNECTIONS, 256);
    assert_eq!(http::HEADER_READ_TIMEOUT, Duration::from_secs(10));
    assert_eq!(HttpLimits::default().max_connections, 256);
}
