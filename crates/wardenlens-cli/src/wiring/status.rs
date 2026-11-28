//! The live views the API reads: the camera directory, the connection state of each camera and
//! the latest storage snapshot. Each is a small adapter over data the service already holds;
//! none holds a credential, a path or a root.

use std::collections::HashMap;
use std::future::{Future, ready};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::watch;
use wardenlens_core::camera::{
    Camera, CameraDirectory, CameraId, CameraStatus, DirectoryError, LastFailure, LinkStatus,
};
use wardenlens_core::connection::{ConnectionState, FailureKind};
use wardenlens_core::storage::{StorageSnapshot, StorageStatus, StorageStatusError};
use wardenlens_core::time::Timestamp;

/// The cameras that were registered when the service started (host and name read from the vault
/// once, at start-up; there is no hot reload). A [`Camera`] holds no credential.
#[derive(Debug, Clone)]
pub(crate) struct Directory(Arc<Vec<Camera>>);

impl Directory {
    /// The cameras ordered by id, as the port promises.
    pub(crate) fn new(mut cameras: Vec<Camera>) -> Self {
        cameras.sort_by(|a, b| a.id().cmp(b.id()));
        Self(Arc::new(cameras))
    }
}

impl CameraDirectory for Directory {
    fn list(&self) -> impl Future<Output = Result<Vec<Camera>, DirectoryError>> + Send {
        ready(Ok(self.0.to_vec()))
    }

    fn get(
        &self,
        id: &CameraId,
    ) -> impl Future<Output = Result<Option<Camera>, DirectoryError>> + Send {
        ready(Ok(self.0.iter().find(|c| c.id() == id).cloned()))
    }
}

/// The latest [`LinkStatus`] of each supervised camera.
#[derive(Debug, Clone, Default)]
pub(crate) struct Links(Arc<Mutex<HashMap<CameraId, LinkStatus>>>);

impl Links {
    /// Records the state and `since` of `status` for `camera`. The failure record belongs to
    /// [`Links::record_failure`] and [`Links::record_recovery`] and is kept as it is, so the two
    /// writers (the state mirror and the supervisor's observer) cannot overwrite each other.
    pub(crate) fn set(&self, camera: &CameraId, status: LinkStatus) {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = map.entry(camera.clone()).or_insert(status);
        entry.state = status.state;
        entry.since = status.since;
    }

    /// Records a failed attempt of `camera`: its kind, when, and the failures so far in the
    /// outage.
    pub(crate) fn record_failure(
        &self,
        camera: &CameraId,
        kind: FailureKind,
        at: Timestamp,
        attempts: u32,
    ) {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = map
            .entry(camera.clone())
            .or_insert_with(|| LinkStatus::from_state(&ConnectionState::INITIAL, at));
        entry.last_failure = Some(LastFailure { kind, at });
        entry.attempts = attempts;
    }

    /// The outage of `camera` is over: its attempt count starts over (the last failure stays).
    pub(crate) fn record_recovery(&self, camera: &CameraId) {
        if let Some(entry) = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(camera)
        {
            entry.attempts = 0;
        }
    }

    fn get(&self, camera: &CameraId) -> Option<LinkStatus> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(camera)
            .copied()
    }
}

impl CameraStatus for Links {
    fn status(&self, id: &CameraId) -> impl Future<Output = Option<LinkStatus>> + Send {
        ready(self.get(id))
    }
}

/// The status for `state` at `now`, keeping the `since` of the previous status while the coarse
/// state is unchanged (a changed failure kind alone is not a new state; see `LinkStatus`).
pub(crate) fn next_status(
    previous: Option<LinkStatus>,
    state: &ConnectionState,
    now: Timestamp,
) -> LinkStatus {
    let fresh = LinkStatus::from_state(state, now);
    match previous {
        Some(p) if p.state.same_coarse(&fresh.state) => LinkStatus {
            state: fresh.state,
            since: p.since,
            ..p
        },
        Some(p) => LinkStatus {
            last_failure: p.last_failure,
            attempts: p.attempts,
            ..fresh
        },
        _ => fresh,
    }
}

/// Mirrors the connection state of `camera` into `links` until the supervisor ends.
pub(crate) async fn track_link(
    camera: CameraId,
    mut state: watch::Receiver<ConnectionState>,
    links: Links,
    now: impl Fn() -> Timestamp + Send,
) {
    let mut previous = None;
    loop {
        let current = *state.borrow_and_update();
        let status = next_status(previous, &current, now());
        links.set(&camera, status);
        previous = Some(status);
        if state.changed().await.is_err() {
            break;
        }
    }
}

/// The storage snapshot the loop publishes after every tick.
#[derive(Debug, Clone)]
pub(crate) struct Snapshots(watch::Receiver<StorageSnapshot>);

impl Snapshots {
    pub(crate) fn new(rx: watch::Receiver<StorageSnapshot>) -> Self {
        Self(rx)
    }
}

impl StorageStatus for Snapshots {
    fn snapshot(&self) -> impl Future<Output = Result<StorageSnapshot, StorageStatusError>> + Send {
        ready(Ok(*self.0.borrow()))
    }
}

#[cfg(test)]
mod tests {
    use wardenlens_core::camera::LinkState;
    use wardenlens_core::connection::FailureKind;

    use super::*;

    fn at(ms: i64) -> Timestamp {
        Timestamp::from_unix_millis(ms)
    }

    #[test]
    fn since_is_kept_while_the_coarse_state_is_the_same() {
        let first = next_status(None, &ConnectionState::INITIAL, at(10));
        assert_eq!(first.state, LinkState::Connecting);
        assert_eq!(first.since, at(10));
        let again = next_status(Some(first), &ConnectionState::INITIAL, at(99));
        assert_eq!(again.since, at(10), "the same state keeps its since");
    }

    #[tokio::test]
    async fn the_state_mirror_and_the_failure_record_do_not_overwrite_each_other() {
        let links = Links::default();
        let id = CameraId::new("cam-a").unwrap();
        // The observer can run before the mirror's first write.
        links.record_failure(&id, FailureKind::Auth, at(30), 2);
        links.set(&id, next_status(None, &ConnectionState::INITIAL, at(40)));
        let s = links.status(&id).await.unwrap();
        assert_eq!((s.state, s.since), (LinkState::Connecting, at(40)));
        assert_eq!(s.attempts, 2);
        assert_eq!(
            s.last_failure,
            Some(LastFailure {
                kind: FailureKind::Auth,
                at: at(30)
            })
        );
        // A later state write keeps the record.
        links.set(&id, next_status(Some(s), &ConnectionState::INITIAL, at(50)));
        assert_eq!(links.status(&id).await.unwrap().attempts, 2);
        // A recovery restarts the count and keeps the last failure.
        links.record_recovery(&id);
        let s = links.status(&id).await.unwrap();
        assert_eq!(s.attempts, 0);
        assert!(s.last_failure.is_some());
        // A recovery of an unknown camera does nothing.
        links.record_recovery(&CameraId::new("cam-z").unwrap());
        assert!(
            links
                .status(&CameraId::new("cam-z").unwrap())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_directory_is_ordered_and_finds_by_id() {
        let dir = Directory::new(Vec::new());
        assert_eq!(dir.list().await.unwrap().len(), 0);
        let id = CameraId::new("cam-a").unwrap();
        assert!(dir.get(&id).await.unwrap().is_none());
        let links = Links::default();
        assert!(links.status(&id).await.is_none());
        links.set(
            &id,
            LinkStatus {
                state: LinkState::Degraded(FailureKind::Timeout),
                since: at(5),
                last_failure: None,
                attempts: 0,
            },
        );
        assert_eq!(links.status(&id).await.unwrap().since, at(5));
    }
}
