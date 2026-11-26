//! The index as the storage crate holds it: shared between the loop and the `SegmentFiles`
//! implementation, locked per call (never across a file operation).

use std::sync::{Arc, Mutex, PoisonError};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{
    IndexedSegment, MAX_LIST_LIMIT, SegmentId, SegmentIndex, StoredSegment, Tier, TierTotals,
};
use wardenlens_core::time::{Timestamp, UnixMs};

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

    /// Add a row (reconciliation adopts a file that has none).
    pub(crate) fn insert(
        &self,
        record: &SegmentRecord,
        tier: Tier,
    ) -> Result<SegmentId, IndexFault> {
        self.with(|i| i.insert(record, tier))
            .map_err(|_| IndexFault)
    }

    /// The rows of `camera` that start in `[from_ms, to_ms)`, paged through the port, at most
    /// `max_rows` of them. The flag says the range held more (the rows are then a prefix).
    pub(crate) fn rows_started_in(
        &self,
        camera: &CameraId,
        from_ms: i64,
        to_ms: i64,
        max_rows: usize,
    ) -> Result<(Vec<IndexedSegment>, bool), IndexFault> {
        let (from, to) = (
            Timestamp::from_unix_millis(from_ms),
            Timestamp::from_unix_millis(to_ms),
        );
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = self
                .with(|i| i.list(camera, from, to, MAX_LIST_LIMIT, cursor.as_ref()))
                .map_err(|_| IndexFault)?;
            for row in page.items {
                // `list` returns every segment that overlaps the range; one that started
                // earlier belongs to the previous day's directory.
                if row.record.started_at_ms.as_i64() < from_ms {
                    continue;
                }
                if out.len() >= max_rows {
                    return Ok((out, true));
                }
                out.push(row);
            }
            match page.next {
                Some(c) => cursor = Some(c),
                None => return Ok((out, false)),
            }
        }
    }

    pub(crate) fn totals(&self) -> Result<TierTotals, IndexFault> {
        self.with(|i| i.bytes_by_tier()).map_err(|_| IndexFault)
    }

    pub(crate) fn newest(&self, tier: Tier) -> Result<Option<StoredSegment>, IndexFault> {
        self.with(|i| i.newest(tier)).map_err(|_| IndexFault)
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
    pub(crate) camera_id: CameraId,
    pub(crate) started: UnixMs,
    pub(crate) camera: String,
    pub(crate) day: String,
    pub(crate) name: String,
}

impl Rel {
    pub(crate) fn of(row: &IndexedSegment) -> Option<Self> {
        Self::from_key(&row.record.camera, row.record.started_at_ms)
    }

    /// The path of the key `(camera, started_at)`.
    pub(crate) fn from_key(camera_id: &CameraId, started_at: UnixMs) -> Option<Self> {
        let text = RelPath::new(camera_id, started_at).to_string();
        let mut it = text.split('/');
        let (camera, day, name, None) = (it.next()?, it.next()?, it.next()?, it.next()) else {
            return None;
        };
        Some(Self {
            camera_id: camera_id.clone(),
            started: started_at,
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
