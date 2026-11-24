//! Validated H.264 parameter sets.

use crate::error::Mp4Error;
use crate::sps::{MAX_SPS_LEN, SpsInfo, parse_sps};

/// Largest PPS (NAL header included) we accept.
pub const MAX_PPS_LEN: usize = 1024;

/// A validated SPS/PPS pair plus the dimensions parsed from the SPS.
///
/// Built once at the trust boundary (TYPE-2); [`crate::init_segment`] takes it without
/// re-checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H264Params {
    sps: Vec<u8>,
    pps: Vec<u8>,
    info: SpsInfo,
}

impl H264Params {
    /// Validate and copy an SPS and a PPS.
    ///
    /// Both are raw NAL units: the one-byte NAL header first, no start code, no length
    /// prefix. Width and height come from the parsed SPS (cropping applied).
    ///
    /// # Errors
    /// A typed [`Mp4Error`] if either is empty, larger than 1024 bytes, not the right NAL
    /// type, or the SPS does not parse.
    pub fn new(sps: &[u8], pps: &[u8]) -> Result<Self, Mp4Error> {
        let info = parse_sps(sps)?;
        debug_assert!(sps.len() <= MAX_SPS_LEN);
        if pps.is_empty() || pps.len() > MAX_PPS_LEN {
            return Err(Mp4Error::PpsLength {
                len: pps.len(),
                max: MAX_PPS_LEN,
            });
        }
        if pps.first().is_none_or(|h| h & 0x80 != 0 || h & 0x1f != 8) {
            return Err(Mp4Error::NotAPps);
        }
        Ok(Self {
            sps: sps.to_vec(),
            pps: pps.to_vec(),
            info,
        })
    }

    /// The SPS NAL unit as given.
    #[must_use]
    pub fn sps(&self) -> &[u8] {
        &self.sps
    }

    /// The PPS NAL unit as given.
    #[must_use]
    pub fn pps(&self) -> &[u8] {
        &self.pps
    }

    /// The fields parsed from the SPS.
    #[must_use]
    pub fn info(&self) -> &SpsInfo {
        &self.info
    }

    /// Display width in pixels, from the SPS.
    #[must_use]
    pub fn width(&self) -> u16 {
        self.info.width
    }

    /// Display height in pixels, from the SPS.
    #[must_use]
    pub fn height(&self) -> u16 {
        self.info.height
    }
}
