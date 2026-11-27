//! The one open index, shared by the recorders, the storage loop and the API.
//!
//! There is exactly one [`Index`] per process (a second one on the same file in one process would
//! close descriptors the first depends on, ADR 0005 section 5). It is not the process lock: that
//! is `wardenlens.lock`, taken in `commands::serve`; `Index::open`'s own `flock` is released after
//! the open. [`SharedIndex`] puts it behind a mutex and implements the core ports
//! on the handle: [`SegmentIndex`] for the recorders and the storage loop (each call is one
//! statement or transaction, so the lock is held briefly), and the two asynchronous read ports of
//! the API ([`SegmentLister`], [`TokenStore`]), which run on the blocking pool because SQLite
//! blocks (ADR 0005 section 4). Errors reach the API without detail (SEC-6).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{
    IndexedSegment, SegmentCursor, SegmentId, SegmentIndex, SegmentListError, SegmentLister,
    SegmentPage, StoredSegment, Tier, TierTotals,
};
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_core::token_store::{TokenId, TokenRecord, TokenStore, TokenStoreError};
use wardenlens_index::{Index, IndexError};

/// The index behind a lock, cloneable.
#[derive(Clone)]
pub(crate) struct SharedIndex(Arc<Mutex<Index>>);

impl std::fmt::Debug for SharedIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedIndex { .. }")
    }
}

impl SharedIndex {
    pub(crate) fn new(index: Index) -> Self {
        Self(Arc::new(Mutex::new(index)))
    }

    /// Every call is one statement or transaction: a panic elsewhere cannot leave half a row
    /// behind, so a poisoned lock is still usable (the storage crate holds the same rule).
    fn lock(&self) -> MutexGuard<'_, Index> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SegmentIndex for SharedIndex {
    type Error = IndexError;

    fn insert(&mut self, record: &SegmentRecord, tier: Tier) -> Result<SegmentId, IndexError> {
        self.lock().insert(record, tier)
    }

    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, IndexError> {
        self.lock().get(id)
    }

    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, IndexError> {
        self.lock().list(camera, from, to, limit, cursor)
    }

    fn set_tier(&mut self, id: SegmentId, tier: Tier) -> Result<(), IndexError> {
        self.lock().set_tier(id, tier)
    }

    fn delete(&mut self, id: SegmentId) -> Result<(), IndexError> {
        self.lock().delete(id)
    }

    fn oldest(
        &self,
        tier: Tier,
        after: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, IndexError> {
        self.lock().oldest(tier, after, n)
    }

    fn newest(&self, tier: Tier) -> Result<Option<StoredSegment>, IndexError> {
        self.lock().newest(tier)
    }

    fn bytes_by_tier(&self) -> Result<TierTotals, IndexError> {
        self.lock().bytes_by_tier()
    }

    fn latest_started_at(&self, camera: &CameraId) -> Result<Option<UnixMs>, IndexError> {
        self.lock().latest_started_at(camera)
    }
}

impl SegmentLister for SharedIndex {
    async fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, SegmentListError> {
        let index = self.clone();
        let camera = camera.clone();
        let cursor = cursor.cloned();
        let result = tokio::task::spawn_blocking(move || {
            SegmentIndex::list(&index, &camera, from, to, limit, cursor.as_ref())
        })
        .await
        .map_err(|_| SegmentListError::Failed)?;
        result.map_err(|e| match e {
            IndexError::InvalidCursor(_) => SegmentListError::InvalidCursor,
            _ => SegmentListError::Failed,
        })
    }
}

impl TokenStore for SharedIndex {
    async fn find(&self, id: &TokenId) -> Result<Option<TokenRecord>, TokenStoreError> {
        let index = self.clone();
        let id = *id;
        tokio::task::spawn_blocking(move || index.lock().find_token(&id))
            .await
            .map_err(|_| TokenStoreError)?
            .map_err(|_| TokenStoreError)
    }
}
