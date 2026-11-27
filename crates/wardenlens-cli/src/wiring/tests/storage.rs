//! The storage thread: it ticks at start, on the interval and on a wake, and it stops promptly.

use super::*;
use wardenlens_core::storage::StorageSnapshot;
use wardenlens_storage::{StatvfsUsage, Storage, StorageConfig};

pub(super) fn looper(
    site: &Site,
) -> wardenlens_storage::StorageLoop<SharedIndex, wardenlens_storage::RealFs, StatvfsUsage> {
    let index = SharedIndex::new(Index::open(site.config.database_path()).unwrap());
    let cfg = StorageConfig::new(
        site.config.hot_root().to_path_buf(),
        site.config.archive_root().to_path_buf(),
        site.config.storage_policy(),
    )
    .with_allow_same_filesystem(true);
    Storage::open(cfg, index, StatvfsUsage).unwrap().0
}

pub(super) async fn ticks(
    rx: &mut watch::Receiver<StorageSnapshot>,
    after: Option<Timestamp>,
) -> Timestamp {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let seen = rx.borrow_and_update().last_tick;
            if let Some(t) = seen.filter(|t| after.is_none_or(|a| *t > a)) {
                return t;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .expect("a tick happens")
}

#[tokio::test(flavor = "multi_thread")]
async fn it_ticks_at_start_and_on_a_wake_long_before_the_interval() {
    let site = Site::new();
    let (tx, mut rx) = watch::channel(StorageSnapshot::initial());
    let task = storage_task::spawn(looper(&site), Duration::from_secs(3600), tx, wall_now).unwrap();
    let first = ticks(&mut rx, None).await;
    // Timestamps have millisecond resolution: make sure the next tick is later.
    tokio::time::sleep(Duration::from_millis(5)).await;
    task.waker().send(Wake::Tick).unwrap();
    let second = ticks(&mut rx, Some(first)).await;
    assert!(
        second > first,
        "a wake ticks without waiting for the interval"
    );
    let at = std::time::Instant::now();
    tokio::task::spawn_blocking(move || task.stop())
        .await
        .unwrap();
    assert!(
        at.elapsed() < Duration::from_secs(5),
        "stop does not wait for the interval"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn it_ticks_on_the_interval_without_a_wake() {
    let site = Site::new();
    let (tx, mut rx) = watch::channel(StorageSnapshot::initial());
    let task = storage_task::spawn(looper(&site), Duration::from_millis(50), tx, wall_now).unwrap();
    let first = ticks(&mut rx, None).await;
    let second = ticks(&mut rx, Some(first)).await;
    assert!(second > first);
    tokio::task::spawn_blocking(move || task.stop())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn many_wakes_are_served_by_few_ticks_and_a_dropped_sender_stops_the_loop() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let site = Site::new();
    let (tx, mut rx) = watch::channel(StorageSnapshot::initial());
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    let now = move || {
        counter.fetch_add(1, Ordering::Relaxed);
        wall_now()
    };
    let task = storage_task::spawn(looper(&site), Duration::from_secs(3600), tx, now).unwrap();
    let first = ticks(&mut rx, None).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let waker = task.waker();
    for _ in 0..1000 {
        waker.send(Wake::Tick).unwrap();
    }
    ticks(&mut rx, Some(first)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let n = count.load(Ordering::Relaxed);
    assert!(n < 100, "1000 wakes caused {n} ticks");
    // `stop` consumes the task; the sender the test holds goes too.
    drop(waker);
    tokio::task::spawn_blocking(move || task.stop())
        .await
        .unwrap();
}
