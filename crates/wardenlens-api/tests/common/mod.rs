//! Shared stand-ins for the recordings ports in tests that do not exercise them.

use std::future::Future;

use wardenlens_core::camera::CameraId;
use wardenlens_core::storage::{SegmentCursor, SegmentListError, SegmentLister, SegmentPage};
use wardenlens_core::time::Timestamp;

/// Lists nothing.
pub(crate) struct NoLister;

impl SegmentLister for NoLister {
    fn list(
        &self,
        _camera: &CameraId,
        _from: Timestamp,
        _to: Timestamp,
        _limit: usize,
        _cursor: Option<&SegmentCursor>,
    ) -> impl Future<Output = Result<SegmentPage, SegmentListError>> + Send {
        std::future::ready(Ok(SegmentPage::new(Vec::new(), None)))
    }
}
