//! `moof` + `mdat` fragment writing (ADR 0005 section 3).

use std::io::Write;

use crate::boxes::{offset, patch_u32, put_u32, put_u64, write_box, write_full_box};
use crate::error::Mp4Error;

/// Largest single sample (one frame) accepted: 8 MiB (ADR 0005 section 2).
pub const MAX_SAMPLE_LEN: usize = 8 * 1024 * 1024;

/// Most samples in one fragment. A GOP is far smaller; this bounds the `trun` table so the `moof`
/// stays within the payload cap of the adoption parser (`core::mp4box`), the one source of it.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "const context (`usize::try_from` is not const); the value is below 2^17"
)]
pub const MAX_SAMPLES_PER_FRAGMENT: usize =
    wardenlens_core::mp4box::MAX_SAMPLES_PER_FRAGMENT as usize;

/// The track id used by [`crate::init_segment`] and every fragment.
pub(crate) const TRACK_ID: u32 = 1;

const TFHD_DEFAULT_BASE_IS_MOOF: u32 = 0x02_0000;
/// data offset, sample duration, sample size, sample flags present.
const TRUN_FLAGS: u32 = 0x00_0701;
const SYNC_SAMPLE_FLAGS: u32 = 0x0200_0000;
const NON_SYNC_SAMPLE_FLAGS: u32 = 0x0101_0000;
const MDAT_HEADER_LEN: usize = 8;

/// One video sample (one access unit).
#[derive(Debug, Clone, Copy)]
pub struct Sample<'a> {
    /// AVCC data: 4-byte big-endian length prefixed NAL units, no SPS/PPS.
    pub data: &'a [u8],
    /// Duration in 90 kHz ticks.
    pub duration: u32,
    /// True for an IDR (sync) sample.
    pub is_sync: bool,
}

/// Writer for one movie fragment. It has no state: see [`Fragment::write`].
#[derive(Debug, Clone, Copy)]
pub struct Fragment;

impl Fragment {
    /// Write `moof` (`mfhd`, `traf` with `tfhd`, `tfdt` v1, `trun`) followed by `mdat`.
    ///
    /// `sequence` is the `mfhd` sequence number (1, 2, ... in a file) and
    /// `base_media_time` the decode time of the first sample in 90 kHz ticks.
    /// Offsets are relative to the start of the `moof` (`default-base-is-moof`), samples carry
    /// no composition offsets (PTS = DTS). Every sample is checked to be well-formed AVCC.
    /// The output is built in memory except the sample bytes, which go straight to `out`;
    /// nothing is written if validation fails.
    ///
    /// # Errors
    /// [`Mp4Error::NoSamples`], [`Mp4Error::TooManySamples`], [`Mp4Error::EmptySample`],
    /// [`Mp4Error::SampleTooLarge`], [`Mp4Error::InvalidAvcc`], [`Mp4Error::BoxTooLarge`]
    /// (the `mdat` or `moof` would not fit a `u32` size) or [`Mp4Error::Io`].
    pub fn write<W: Write>(
        sequence: u32,
        base_media_time: u64,
        samples: &[Sample<'_>],
        out: &mut W,
    ) -> Result<(), Mp4Error> {
        let total = validate(samples)?;
        let mdat_size = total
            .checked_add(MDAT_HEADER_LEN)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(Mp4Error::BoxTooLarge)?;
        let moof = build_moof(sequence, base_media_time, samples)?;
        out.write_all(&moof)?;
        out.write_all(&mdat_size.to_be_bytes())?;
        out.write_all(b"mdat")?;
        for s in samples {
            out.write_all(s.data)?;
        }
        Ok(())
    }
}

/// Validate every sample and return the total payload size.
fn validate(samples: &[Sample<'_>]) -> Result<usize, Mp4Error> {
    if samples.is_empty() {
        return Err(Mp4Error::NoSamples);
    }
    if samples.len() > MAX_SAMPLES_PER_FRAGMENT {
        return Err(Mp4Error::TooManySamples {
            count: samples.len(),
            max: MAX_SAMPLES_PER_FRAGMENT,
        });
    }
    let mut total = 0usize;
    for s in samples {
        if s.data.is_empty() {
            return Err(Mp4Error::EmptySample);
        }
        if s.data.len() > MAX_SAMPLE_LEN {
            return Err(Mp4Error::SampleTooLarge {
                len: s.data.len(),
                max: MAX_SAMPLE_LEN,
            });
        }
        check_avcc(s.data)?;
        total = total
            .checked_add(s.data.len())
            .ok_or(Mp4Error::BoxTooLarge)?;
    }
    Ok(total)
}

/// The length prefixes must tile the data exactly, with no zero-length NAL unit.
fn check_avcc(mut rest: &[u8]) -> Result<(), Mp4Error> {
    while !rest.is_empty() {
        let (prefix, tail) = rest.split_first_chunk::<4>().ok_or(Mp4Error::InvalidAvcc)?;
        let len =
            usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| Mp4Error::InvalidAvcc)?;
        if len == 0 {
            return Err(Mp4Error::InvalidAvcc);
        }
        rest = tail.get(len..).ok_or(Mp4Error::InvalidAvcc)?;
    }
    Ok(())
}

fn build_moof(
    sequence: u32,
    base_media_time: u64,
    samples: &[Sample<'_>],
) -> Result<Vec<u8>, Mp4Error> {
    let mut out = Vec::with_capacity(samples.len().saturating_mul(12).saturating_add(96));
    let mut data_offset_at = 0usize;
    write_box(&mut out, *b"moof", |o| {
        write_full_box(o, *b"mfhd", 0, 0, |o| {
            put_u32(o, sequence);
            Ok(())
        })?;
        write_box(o, *b"traf", |o| {
            write_full_box(o, *b"tfhd", 0, TFHD_DEFAULT_BASE_IS_MOOF, |o| {
                put_u32(o, TRACK_ID);
                Ok(())
            })?;
            write_full_box(o, *b"tfdt", 1, 0, |o| {
                put_u64(o, base_media_time);
                Ok(())
            })?;
            write_full_box(o, *b"trun", 0, TRUN_FLAGS, |o| {
                put_u32(
                    o,
                    u32::try_from(samples.len()).map_err(|_| Mp4Error::BoxTooLarge)?,
                );
                data_offset_at = usize::try_from(offset(o)?).map_err(|_| Mp4Error::BoxTooLarge)?;
                put_u32(o, 0); // data_offset, patched below
                for s in samples {
                    put_u32(o, s.duration);
                    put_u32(
                        o,
                        u32::try_from(s.data.len()).map_err(|_| Mp4Error::BoxTooLarge)?,
                    );
                    put_u32(
                        o,
                        if s.is_sync {
                            SYNC_SAMPLE_FLAGS
                        } else {
                            NON_SYNC_SAMPLE_FLAGS
                        },
                    );
                }
                Ok(())
            })
        })
    })?;
    // The first sample byte follows the moof and the 8-byte mdat header. The field is a
    // signed 32-bit value, so a moof near 2 GiB is an error rather than a wrap.
    let data_offset = out
        .len()
        .checked_add(MDAT_HEADER_LEN)
        .and_then(|n| i32::try_from(n).ok())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(Mp4Error::BoxTooLarge)?;
    patch_u32(&mut out, data_offset_at, data_offset)?;
    Ok(out)
}
