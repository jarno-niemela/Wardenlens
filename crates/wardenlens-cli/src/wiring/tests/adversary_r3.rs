//! Adversarial tests, round 3 of PR #198. Synthetic temporary sites only.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// A stop during the first camera's set-up starts no recorder build for the cameras after it
/// (the `break` in `start_cameras`), and the stop is clean.
#[test]
fn a_stop_during_the_first_cameras_set_up_builds_no_later_camera() {
    let site = Site::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let entered = Mutex::new(Some(entered_tx));
    let release = Mutex::new(release_rx);
    let mut tuning = quick();
    let counter = Arc::clone(&calls);
    tuning.before_recorder = Some(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        if let Some(tx) = entered.lock().unwrap().take() {
            let _ = tx.send(());
            let _ = release.lock().unwrap().recv();
        }
    }));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (took, result) = runtime.block_on(async {
        let mut cams = Vec::new();
        for i in 0..3 {
            let (_tx, rx) = mpsc::unbounded_channel();
            cams.push(CameraInput {
                camera: camera(&format!("cam-{i}"), "192.0.2.10"),
                source: Fake::Live(Some(rx)),
            });
        }
        let svc = site.start(cams, tuning).await;
        tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
            .await
            .unwrap();
        svc.shutdown().await
    });
    assert_eq!(result.unwrap(), Stopped::Clean);
    assert!(took < Duration::from_secs(10), "{took:?}");
    // Let the held build finish, then wait for every blocking task that was started.
    let _ = release_tx.send(());
    runtime.shutdown_timeout(Duration::from_secs(5));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a later camera was built");
}
