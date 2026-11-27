//! Decoded-free video types shared by ingest (producer) and the recorder (consumer): one H.264
//! access unit as AVCC bytes with its timing, plus the bit-level helpers both need.
//!
//! Pure data and byte parsing: no I/O (ADR 0005 section 11, ARCH-1).

mod bits;
mod nal;

use core::fmt;

use crate::time::Timestamp;

pub use bits::{Bits, BitsError, unescape};
pub use nal::{AvccError, contains_b_slice, nal_units};

/// The parameter sets that a decoder or an MP4 muxer needs, as raw NAL units (one byte NAL header,
/// no start code, no length prefix).
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct H264Params {
    /// The sequence parameter set NAL unit.
    pub sps: Vec<u8>,
    /// The picture parameter set NAL unit.
    pub pps: Vec<u8>,
}

impl H264Params {
    /// The parameter sets, as raw NAL units.
    #[must_use]
    pub fn new(sps: Vec<u8>, pps: Vec<u8>) -> Self {
        Self { sps, pps }
    }
}

impl fmt::Debug for H264Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H264Params")
            .field("sps_len", &self.sps.len())
            .field("pps_len", &self.pps.len())
            .finish()
    }
}

/// One video access unit.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Frame {
    /// The NAL units in AVCC form: each preceded by its length as a 4 byte big-endian number.
    /// Parameter sets are not inline; they are in [`Frame::params`].
    pub data: Vec<u8>,
    /// A random access point: decoding can start here.
    pub is_keyframe: bool,
    /// The low 32 bits of the RTP timestamp, 90 kHz ticks. It wraps; the `MediaClock` unwraps it.
    pub rtp_ts_90k: u32,
    /// When the last packet of the frame arrived, from the injected wall `Clock`.
    pub arrival: Timestamp,
    /// The parameter sets, on the first frame of a session and on every frame that changes them.
    /// `Some` is also the signal that a parameter change begins here: close the segment.
    pub params: Option<H264Params>,
    /// Frames may be missing before this one: it is the first of a session, RTP packets were lost
    /// before it, or an oversized frame was dropped before it.
    pub discontinuity: bool,
}

impl Frame {
    /// A frame. Ingest builds them; the recorder reads them.
    #[must_use]
    pub fn new(
        data: Vec<u8>,
        is_keyframe: bool,
        rtp_ts_90k: u32,
        arrival: Timestamp,
        params: Option<H264Params>,
        discontinuity: bool,
    ) -> Self {
        Self {
            data,
            is_keyframe,
            rtp_ts_90k,
            arrival,
            params,
            discontinuity,
        }
    }
}

impl fmt::Debug for Frame {
    /// Prints sizes, never video bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("len", &self.data.len())
            .field("is_keyframe", &self.is_keyframe)
            .field("rtp_ts_90k", &self.rtp_ts_90k)
            .field("arrival", &self.arrival)
            .field("params", &self.params)
            .field("discontinuity", &self.discontinuity)
            .finish()
    }
}
