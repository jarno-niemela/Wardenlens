//! The `SegmentLister` port: the recordings API's read-only, asynchronous view of
//! [`SegmentIndex::list`](super::SegmentIndex::list) (ticket #62).
//!
//! The index itself is a synchronous, mutable port (SQLite). The API never holds it: it takes this
//! read port as a generic, and the composition root adapts the index to it. The contract of the
//! listing (the half-open overlap range, the order, the page size) is that of `SegmentIndex::list`.

use std::future::Future;

use crate::camera::CameraId;
use crate::time::Timestamp;

use super::index::{SegmentCursor, SegmentPage};

/// Why a listing failed. Carries no detail: no row data, path or storage text (SEC-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SegmentListError {
    /// The cursor is malformed or was issued for another camera. A client error.
    #[error("invalid cursor")]
    InvalidCursor,
    /// Any other failure (storage, a corrupt row, a limit the implementation refuses). A
    /// server error.
    #[error("segment listing failed")]
    Failed,
}

/// Read access to the segment listing.
pub trait SegmentLister {
    /// Lists the segments of `camera` overlapping `[from, to)` as
    /// [`SegmentIndex::list`](super::SegmentIndex::list) does. `limit` is 1 to
    /// [`MAX_LIST_LIMIT`](super::MAX_LIST_LIMIT); the caller checks it.
    ///
    /// # Errors
    /// [`SegmentListError::InvalidCursor`] for a cursor the implementation refuses,
    /// [`SegmentListError::Failed`] for anything else.
    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> impl Future<Output = Result<SegmentPage, SegmentListError>> + Send;
}
