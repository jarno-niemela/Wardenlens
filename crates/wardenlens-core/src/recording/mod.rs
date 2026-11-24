//! Pure recording logic: segment cutting, monotonic media time and segment paths.
//!
//! Rules come from ADR 0005 section 2 (segment rule, timestamp policy) and
//! section 3 (on-disk layout). Nothing here performs I/O or reads a clock; the
//! recorder supplies arrival times and RTP timestamps.

mod clock;
mod path;
mod segmenter;

pub use clock::{MAX_STEP_TICKS, MediaClock, TICKS_PER_SECOND};
pub use path::{CameraId, RecordingError, RelPath};
pub use segmenter::{
    Decision, FrameMeta, Pushed, SegmentConfig, SegmentRecord, Segmenter, ticks_to_ms_ceil,
};
