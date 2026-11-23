//! Fragmented MP4 writer for H.264 passthrough (ADR 0005 sections 1 to 3).
//!
//! One video track, timescale 90 kHz: [`init_segment`] gives `ftyp` + `moov` once per file,
//! [`Fragment::write`] gives one `moof` + `mdat` per GOP. No I/O beyond [`std::io::Write`],
//! no dependencies beyond `thiserror`, no `unsafe`. Every box size goes through `u32::try_from`.
//!
//! Camera-supplied SPS and PPS are bounded and the SPS is parsed defensively
//! ([`parse_sps`]); samples are checked to be well-formed AVCC before any byte is written.
//!
//! ```
//! use wardenlens_mp4::{annexb_to_avcc, init_segment, Fragment, H264Params, Sample};
//!
//! // A 16x16 baseline SPS and a PPS (raw NAL units, no start code).
//! let sps = [0x67, 0x42, 0xc0, 0x0a, 0xf8, 0x41, 0xa2];
//! let pps = [0x68, 0xce, 0x38, 0x80];
//! let params = H264Params::new(&sps, &pps)?;
//! let init = init_segment(&params)?;
//!
//! let sample = annexb_to_avcc(&[0, 0, 0, 1, 0x65, 0x88, 0x84])?;
//! let mut file = init.bytes().to_vec();
//! let samples = [Sample { data: &sample, duration: 3600, is_sync: true }];
//! Fragment::write(1, 0, &samples, &mut file)?;
//! assert_eq!(&file[4..8], b"ftyp");
//! # Ok::<(), wardenlens_mp4::Mp4Error>(())
//! ```

mod annexb;
mod boxes;
mod error;
mod fragment;
mod init;
mod params;
mod sps;

pub use annexb::annexb_to_avcc;
pub use error::Mp4Error;
pub use fragment::{Fragment, MAX_SAMPLE_LEN, MAX_SAMPLES_PER_FRAGMENT, Sample};
pub use init::{DurationPatch, InitSegment, TIMESCALE, init_segment};
pub use params::{H264Params, MAX_PPS_LEN};
pub use sps::{MAX_SPS_LEN, SpsInfo, parse_sps};
