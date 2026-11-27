//! Questions to the index and the store about one key.

use wardenlens_core::camera::CameraId;
use wardenlens_core::storage::{IndexedSegment, MAX_LIST_LIMIT, SegmentIndex};
use wardenlens_core::time::{DurationMs, Timestamp, UnixMs};

use crate::store::SegmentStore;

/// Pages of overlapping rows read for one key; a segment overlaps only a handful of rows, so
/// more than this means the answer is unknown.
const PROBE_PAGES: usize = 4;

/// A probe that could not answer, and who failed to. The key is never assumed free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unknown {
    /// The volume could not be asked.
    Store,
    /// The index could not be asked.
    Index,
}

/// The row of `camera` that started at exactly `key`, if any. A row starting at `key` overlaps
/// `[key, key + 1)`, so the range listing finds it.
pub(crate) fn find_row<I: SegmentIndex>(
    index: &I,
    camera: &CameraId,
    key: UnixMs,
) -> Result<Option<IndexedSegment>, Unknown> {
    let from = Timestamp::from(key);
    let to = from.saturating_add(DurationMs::from_millis(1));
    let mut cursor = None;
    for _ in 0..PROBE_PAGES {
        let page = index
            .list(camera, from, to, MAX_LIST_LIMIT, cursor.as_ref())
            .map_err(|_| Unknown::Index)?;
        if let Some(found) = page
            .items
            .into_iter()
            .find(|s| s.record.started_at_ms == key)
        {
            return Ok(Some(found));
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => return Ok(None),
        }
    }
    Err(Unknown::Index)
}

/// Whether a segment of `camera` with this `started_at_ms` exists: a file on the hot volume or a
/// row.
pub(crate) fn key_taken<S: SegmentStore, I: SegmentIndex>(
    store: &mut S,
    index: &I,
    camera: &CameraId,
    key: UnixMs,
) -> Result<bool, Unknown> {
    if store.key_taken(key).map_err(|_| Unknown::Store)? {
        return Ok(true);
    }
    Ok(find_row(index, camera, key)?.is_some())
}
