//! The live views the API reads: the camera directory, the connection state of each camera and
//! the latest storage snapshot. Each is a small adapter over data the service already holds;
//! none holds a credential, a path or a root.

use std::collections::HashMap;
use std::future::{Future, ready};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::watch;
use wardenlens_core::camera::{
    Camera, CameraDirectory, CameraId, CameraStatus, DirectoryError, LinkStatus,
};
use wardenlens_core::connection::ConnectionState;
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
    /// Records `status` for `camera`.
    pub(crate) fn set(&self, camera: &CameraId, status: LinkStatus) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(camera.clone(), status);
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
            },
        );
        assert_eq!(links.status(&id).await.unwrap().since, at(5));
    }
}
