//! The index as the storage crate holds it: shared between the loop and the `SegmentFiles`
//! implementation, locked per call (never across a file operation).

use std::sync::{Arc, Mutex, PoisonError};

use wardenlens_core::recording::RelPath;
use wardenlens_core::storage::{
    IndexedSegment, SegmentId, SegmentIndex, StoredSegment, Tier, TierTotals,
};
use wardenlens_core::time::Timestamp;

/// An index call failed. The cause is dropped on purpose: it can carry row data (SEC-6), and the
/// loop's reaction does not depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndexFault;

/// The index behind a lock.
#[derive(Debug)]
pub(crate) struct SharedIndex<I> {
    inner: Arc<Mutex<I>>,
}

impl<I> Clone for SharedIndex<I> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<I: SegmentIndex> SharedIndex<I> {
    pub(crate) fn new(index: I) -> Self {
        Self {
            inner: Arc::new(Mutex::new(index)),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut I) -> R) -> R {
        // Every index call is one SQL statement or transaction: a panic elsewhere cannot leave a
        // half-applied row behind, so a poisoned lock is still usable.
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut g)
    }

    pub(crate) fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, IndexFault> {
        self.with(|i| i.get(id)).map_err(|_| IndexFault)
    }

    pub(crate) fn set_tier(&self, id: SegmentId, tier: Tier) -> Result<(), IndexFault> {
        self.with(|i| i.set_tier(id, tier)).map_err(|_| IndexFault)
    }

    pub(crate) fn delete(&self, id: SegmentId) -> Result<(), IndexFault> {
        self.with(|i| i.delete(id)).map_err(|_| IndexFault)
    }

    pub(crate) fn totals(&self) -> Result<TierTotals, IndexFault> {
        self.with(|i| i.bytes_by_tier()).map_err(|_| IndexFault)
    }

    pub(crate) fn oldest(
        &self,
        tier: Tier,
        after: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, IndexFault> {
        self.with(|i| i.oldest(tier, after, n))
            .map_err(|_| IndexFault)
    }
}

/// The three components of a segment's path, derived from its row (never stored, never from a
/// camera: SEC-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rel {
    pub(crate) camera: String,
    pub(crate) day: String,
    pub(crate) name: String,
}

impl Rel {
    pub(crate) fn of(row: &IndexedSegment) -> Option<Self> {
        let text = RelPath::new(&row.record.camera, row.record.started_at_ms).to_string();
        let mut it = text.split('/');
        let (camera, day, name, None) = (it.next()?, it.next()?, it.next()?, it.next()) else {
            return None;
        };
        Some(Self {
            camera: camera.to_owned(),
            day: day.to_owned(),
            name: name.to_owned(),
        })
    }

    pub(crate) fn comps(&self) -> [&str; 3] {
        [&self.camera, &self.day, &self.name]
    }

    pub(crate) fn dir(&self) -> [&str; 2] {
        [&self.camera, &self.day]
    }

    pub(crate) fn part_name(&self) -> String {
        format!("{}.part", self.name)
    }
}
