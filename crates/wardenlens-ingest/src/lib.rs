//! RTSP/TCP ingest: one H.264 video stream per session, as timestamped AVCC frames.
//!
//! [`open_stream`] connects with `retina` over TCP interleaved transport and returns a
//! [`FrameStream`]. Each [`Frame`] carries the RTP timestamp, the arrival time from the injected
//! `Clock`, the SPS/PPS when they are new, and a discontinuity flag (ADR 0005, the #55 row).
//! A [`FrameStream`] ends on its first error; [`Supervisor`] reopens it with backoff and reports the
//! [`wardenlens_core::connection::ConnectionState`].
//!
//! The retina-to-[`Frame`] mapping is the pure [`FrameMapper`]. [`sps_reordering`] and
//! [`contains_b_slice`] answer ADR 0005 open risk 1 (does a stream reorder frames?) for the
//! owner's manual run; they work on any SPS bytes and need no camera.
//!
//! Everything a camera sends is untrusted: nothing here panics and errors carry no camera data
//! (see [`IngestError`]). The 8 MiB frame cap ([`MAX_FRAME_BYTES`]) applies to a frame after
//! retina has assembled it from RTP packets; retina does not bound that assembly, so a hostile
//! camera can make one session hold memory up to its link rate times [`FRAME_TIMEOUT`] before the
//! cap sees the frame (ADR 0002 accepted risk 12, follow-up #155). The crate does not log. retina logs through the `log`
//! facade and some of its records (for example the unassigned-channel warning) include peer
//! addresses, so the binary must not forward `retina` records below `error` to its logs.

mod error;
mod frame;
mod session;
pub mod sps;
mod supervisor;
#[cfg(test)]
mod testsupport;

pub use error::IngestError;
pub use frame::{
    Frame, FrameMapper, H264_CLOCK_RATE_HZ, H264Params, H264ParamsExt, MAX_FRAME_BYTES,
    MAX_PARAM_SET_BYTES, MapError, RawParams, RawVideoFrame, contains_b_slice,
};
pub use session::{
    FRAME_TIMEOUT, FrameStream, OPEN_TIMEOUT, StreamInfo, open_stream, select_video_stream,
};
pub use sps::{NoReorderReason, ReorderVerdict, SpsError, SpsSummary, parse_sps, sps_reordering};
pub use supervisor::{
    CancelToken, ConnectionNotice, DroppedFrames, FailureNote, FrameSource, InstantClock,
    MAX_CHANNEL_CAPACITY, RetinaSource, SplitMixJitter, StreamSource, Supervisor, SupervisorConfig,
    failure_kind,
};
