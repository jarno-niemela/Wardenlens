//! RTSP/TCP ingest: one H.264 video stream per session, as timestamped AVCC frames.
//!
//! [`open_stream`] connects with `retina` over TCP interleaved transport and returns a
//! [`FrameStream`]. Each [`Frame`] carries the RTP timestamp, the arrival time from the injected
//! `Clock`, the SPS/PPS when they are new, and a discontinuity flag (ADR 0005, the #55 row).
//! Reconnecting is the caller's job (a later task); this crate ends the stream on an error.
//!
//! The retina-to-[`Frame`] mapping is the pure [`FrameMapper`]. [`sps_reordering`] and
//! [`contains_b_slice`] answer ADR 0005 open risk 1 (does a stream reorder frames?) for the
//! owner's manual run; they work on any SPS bytes and need no camera.
//!
//! Everything a camera sends is untrusted: sizes are capped, nothing panics and errors carry no
//! camera data (see [`IngestError`]). The crate does not log. retina logs through the `log`
//! facade and some of its records (for example the unassigned-channel warning) include peer
//! addresses, so the binary must not forward `retina` records below `error` to its logs.

mod error;
mod frame;
mod session;
pub mod sps;
#[cfg(test)]
mod testsupport;

pub use error::IngestError;
pub use frame::{
    Frame, FrameMapper, H264_CLOCK_RATE_HZ, H264Params, MAX_FRAME_BYTES, MAX_PARAM_SET_BYTES,
    MapError, RawParams, RawVideoFrame, contains_b_slice,
};
pub use session::{
    FRAME_TIMEOUT, FrameStream, OPEN_TIMEOUT, StreamInfo, open_stream, select_video_stream,
};
pub use sps::{NoReorderReason, ReorderVerdict, SpsError, SpsSummary, parse_sps, sps_reordering};
