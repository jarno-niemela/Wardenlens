//! The storage loop on its own thread (ADR 0005 section 6): one tick at start and then one per
//! interval, plus one whenever a recorder reports a full hot volume. The loop blocks on files and
//! SQLite, so it never runs on the async workers.
//!
//! The snapshot of each tick is published for the API; the loop is the only writer of `tier`.

use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::watch;
use wardenlens_core::storage::SegmentIndex;
use wardenlens_core::storage::{StorageSnapshot, Tier};
use wardenlens_core::time::Timestamp;
use wardenlens_storage::{Fs, Observer, StorageLoop, VolumeUsage};

/// What wakes the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wake {
    /// Tick now (a recorder met a full volume).
    Tick,
    /// Leave the loop.
    Stop,
}

/// Logs quarantine evictions: the files are evidence of a corruption and an operator should hear
/// about it first. Counts and the tier only.
struct LogObserver;

impl Observer for LogObserver {
    fn quarantine_eviction(&self, tier: Tier, files: usize) {
        tracing::warn!(?tier, files, "quarantined files are about to be evicted");
    }
}

/// A running storage thread.
pub(crate) struct StorageTask {
    wake: Sender<Wake>,
    thread: JoinHandle<()>,
}

impl StorageTask {
    /// A sender that wakes the loop.
    pub(crate) fn waker(&self) -> Sender<Wake> {
        self.wake.clone()
    }

    /// Asks the loop to stop and waits for it. A tick in progress finishes first.
    pub(crate) fn stop(self) {
        // The thread may already be gone; then there is nothing to stop.
        let _ = self.wake.send(Wake::Stop);
        if self.thread.join().is_err() {
            tracing::error!("the storage loop ended abnormally");
        }
    }
}

/// Starts the loop. The first tick runs at once so the API has a snapshot; `snapshots` receives
/// the snapshot after every tick, failed ones included.
pub(crate) fn spawn<I, F, U>(
    mut looper: StorageLoop<I, F, U>,
    interval: Duration,
    snapshots: watch::Sender<StorageSnapshot>,
    now: impl Fn() -> Timestamp + Send + 'static,
) -> std::io::Result<StorageTask>
where
    I: SegmentIndex + Send + 'static,
    F: Fs + Send + 'static,
    U: VolumeUsage + Send + 'static,
{
    looper.set_observer(Box::new(LogObserver));
    let (wake, inbox) = mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("storage-loop".to_owned())
        .spawn(move || {
            loop {
                tick(&mut looper, now());
                snapshots.send_replace(looper.snapshot());
                match inbox.recv_timeout(interval) {
                    Ok(Wake::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                    Ok(Wake::Tick) | Err(RecvTimeoutError::Timeout) => {}
                }
                // Several recorders can report a full volume at once: one tick serves them all.
                let mut stop = false;
                while let Ok(w) = inbox.try_recv() {
                    stop |= w == Wake::Stop;
                }
                if stop {
                    break;
                }
            }
        })?;
    Ok(StorageTask { wake, thread })
}

fn tick<I, F, U>(looper: &mut StorageLoop<I, F, U>, now: Timestamp)
where
    I: SegmentIndex,
    F: Fs,
    U: VolumeUsage,
{
    match looper.tick(now) {
        Ok(r) => {
            if r.index_health_error || r.returned_pass_unfinished || r.truncated {
                tracing::warn!(
                    index_health_error = r.index_health_error,
                    returned_pass_unfinished = r.returned_pass_unfinished,
                    truncated = r.truncated,
                    "storage tick needs attention"
                );
            }
            tracing::debug!(moved = r.moved, deleted = r.deleted, "storage tick");
        }
        Err(e) => tracing::warn!(error = %e, "storage tick failed"),
    }
}
