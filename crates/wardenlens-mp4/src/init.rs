//! The init segment: `ftyp` + `moov` (ADR 0005 section 3).

use crate::boxes::{offset, put_u16, put_u32, put_u64, put_zeros, write_box, write_full_box};
use crate::error::Mp4Error;
use crate::fragment::TRACK_ID;
use crate::params::H264Params;

/// Media timescale: 90 kHz, the RTP video clock.
pub const TIMESCALE: u32 = 90_000;

const IDENTITY_MATRIX: [u32; 9] = [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000];

/// A written init segment and where its two duration fields are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitSegment {
    bytes: Vec<u8>,
    mvhd_duration_offset: u64,
    mehd_duration_offset: u64,
}

/// A pair of `pwrite` operations that store the final duration (see [`InitSegment::duration_patch`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurationPatch {
    /// File offset of the 32-bit `mvhd.duration` field.
    pub mvhd_offset: u64,
    /// New big-endian value of `mvhd.duration`.
    pub mvhd_value: [u8; 4],
    /// File offset of the 64-bit `mehd.fragment_duration` field.
    pub mehd_offset: u64,
    /// New big-endian value of `mehd.fragment_duration`.
    pub mehd_value: [u8; 8],
}

impl InitSegment {
    /// The bytes to write at the start of the file.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// File offsets and new values for the total duration, for the recorder to `pwrite` when it
    /// closes a segment. Both fields are 0 in [`InitSegment::bytes`]; offsets are from the file
    /// start (the init segment is the file's first bytes).
    ///
    /// # Errors
    /// [`Mp4Error::DurationTooLarge`] if `ticks` does not fit the 32-bit `mvhd` field.
    pub fn duration_patch(&self, ticks: u64) -> Result<DurationPatch, Mp4Error> {
        let short = u32::try_from(ticks).map_err(|_| Mp4Error::DurationTooLarge { ticks })?;
        Ok(DurationPatch {
            mvhd_offset: self.mvhd_duration_offset,
            mvhd_value: short.to_be_bytes(),
            mehd_offset: self.mehd_duration_offset,
            mehd_value: ticks.to_be_bytes(),
        })
    }
}

/// Write `ftyp` + `moov` for one H.264 video track (timescale 90000, `avc1`/`avcC`,
/// `mvex`/`trex`, zero durations).
///
/// # Errors
/// [`Mp4Error::BoxTooLarge`] if a box would not fit a `u32` size (not reachable with the
/// bounded parameter sets, but sizes are checked regardless).
pub fn init_segment(params: &H264Params) -> Result<InitSegment, Mp4Error> {
    let mut out = Vec::with_capacity(1024);
    write_box(&mut out, *b"ftyp", |o| {
        o.extend_from_slice(b"isom");
        put_u32(o, 512);
        for brand in [b"isom", b"iso5", b"iso6", b"avc1", b"mp41"] {
            o.extend_from_slice(brand);
        }
        Ok(())
    })?;
    let mut movie_dur = 0;
    let mut fragment_dur = 0;
    write_box(&mut out, *b"moov", |o| {
        movie_dur = write_mvhd(o)?;
        write_trak(o, params)?;
        write_box(o, *b"mvex", |o| {
            fragment_dur = write_mehd(o)?;
            write_full_box(o, *b"trex", 0, 0, |o| {
                put_u32(o, TRACK_ID);
                put_u32(o, 1); // default_sample_description_index
                put_zeros(o, 12); // default duration, size, flags
                Ok(())
            })
        })
    })?;
    Ok(InitSegment {
        bytes: out,
        mvhd_duration_offset: movie_dur,
        mehd_duration_offset: fragment_dur,
    })
}

/// Returns the offset of the duration field.
fn write_mvhd(out: &mut Vec<u8>) -> Result<u64, Mp4Error> {
    let mut at = 0;
    write_full_box(out, *b"mvhd", 0, 0, |o| {
        put_zeros(o, 8); // creation, modification time
        put_u32(o, TIMESCALE);
        at = offset(o)?;
        put_u32(o, 0); // duration, patched on close
        put_u32(o, 0x0001_0000); // rate 1.0
        put_u16(o, 0x0100); // volume
        put_zeros(o, 10); // reserved
        for m in IDENTITY_MATRIX {
            put_u32(o, m);
        }
        put_zeros(o, 24); // pre_defined
        put_u32(o, TRACK_ID.saturating_add(1)); // next_track_id
        Ok(())
    })?;
    Ok(at)
}

/// Returns the offset of the duration field.
fn write_mehd(out: &mut Vec<u8>) -> Result<u64, Mp4Error> {
    let mut at = 0;
    write_full_box(out, *b"mehd", 1, 0, |o| {
        at = offset(o)?;
        put_u64(o, 0);
        Ok(())
    })?;
    Ok(at)
}

fn write_trak(out: &mut Vec<u8>, params: &H264Params) -> Result<(), Mp4Error> {
    write_box(out, *b"trak", |o| {
        write_full_box(o, *b"tkhd", 0, 3, |o| {
            put_zeros(o, 8); // creation, modification time
            put_u32(o, TRACK_ID);
            put_zeros(o, 4); // reserved
            put_u32(o, 0); // duration (fragmented: unknown)
            put_zeros(o, 8); // reserved
            put_zeros(o, 8); // layer, alternate group, volume, reserved
            for m in IDENTITY_MATRIX {
                put_u32(o, m);
            }
            put_u32(o, u32::from(params.width()) << 16);
            put_u32(o, u32::from(params.height()) << 16);
            Ok(())
        })?;
        write_box(o, *b"mdia", |o| {
            write_full_box(o, *b"mdhd", 0, 0, |o| {
                put_zeros(o, 8);
                put_u32(o, TIMESCALE);
                put_u32(o, 0);
                put_u16(o, 0x55c4); // language "und"
                put_u16(o, 0);
                Ok(())
            })?;
            write_full_box(o, *b"hdlr", 0, 0, |o| {
                put_u32(o, 0);
                o.extend_from_slice(b"vide");
                put_zeros(o, 12);
                o.extend_from_slice(b"VideoHandler\0");
                Ok(())
            })?;
            write_minf(o, params)
        })
    })
}

fn write_minf(out: &mut Vec<u8>, params: &H264Params) -> Result<(), Mp4Error> {
    write_box(out, *b"minf", |o| {
        write_full_box(o, *b"vmhd", 0, 1, |o| {
            put_zeros(o, 8); // graphicsmode, opcolor
            Ok(())
        })?;
        write_box(o, *b"dinf", |o| {
            write_full_box(o, *b"dref", 0, 0, |o| {
                put_u32(o, 1);
                write_full_box(o, *b"url ", 0, 1, |_| Ok(())) // self-contained
            })
        })?;
        write_box(o, *b"stbl", |o| {
            write_full_box(o, *b"stsd", 0, 0, |o| {
                put_u32(o, 1);
                write_avc1(o, params)
            })?;
            for empty in [b"stts", b"stsc"] {
                write_full_box(o, *empty, 0, 0, |o| {
                    put_u32(o, 0);
                    Ok(())
                })?;
            }
            write_full_box(o, *b"stsz", 0, 0, |o| {
                put_zeros(o, 8); // sample_size, sample_count
                Ok(())
            })?;
            write_full_box(o, *b"stco", 0, 0, |o| {
                put_u32(o, 0);
                Ok(())
            })
        })
    })
}

fn write_avc1(out: &mut Vec<u8>, params: &H264Params) -> Result<(), Mp4Error> {
    write_box(out, *b"avc1", |o| {
        put_zeros(o, 6); // reserved
        put_u16(o, 1); // data_reference_index
        put_zeros(o, 16); // pre_defined, reserved
        put_u16(o, params.width());
        put_u16(o, params.height());
        put_u32(o, 0x0048_0000); // 72 dpi horizontal
        put_u32(o, 0x0048_0000); // 72 dpi vertical
        put_zeros(o, 4);
        put_u16(o, 1); // frame_count
        put_zeros(o, 32); // compressorname
        put_u16(o, 0x0018); // depth
        put_u16(o, 0xffff); // pre_defined = -1
        write_avcc(o, params)
    })
}

fn write_avcc(out: &mut Vec<u8>, params: &H264Params) -> Result<(), Mp4Error> {
    let info = params.info();
    write_box(out, *b"avcC", |o| {
        o.push(1); // configurationVersion
        o.push(info.profile_idc);
        o.push(info.constraint_flags);
        o.push(info.level_idc);
        o.push(0xff); // reserved, lengthSizeMinusOne = 3
        o.push(0xe1); // reserved, one SPS
        put_u16(
            o,
            u16::try_from(params.sps().len()).map_err(|_| Mp4Error::BoxTooLarge)?,
        );
        o.extend_from_slice(params.sps());
        o.push(1); // one PPS
        put_u16(
            o,
            u16::try_from(params.pps().len()).map_err(|_| Mp4Error::BoxTooLarge)?,
        );
        o.extend_from_slice(params.pps());
        if matches!(
            info.profile_idc,
            100 | 110 | 122 | 144 // the profiles whose avcC carries the extension (ISO 14496-15)
        ) {
            o.push(0xfc | info.chroma_format_idc);
            o.push(0xf8 | info.bit_depth_luma.saturating_sub(8));
            o.push(0xf8 | info.bit_depth_chroma.saturating_sub(8));
            o.push(0); // no SPS extensions
        }
        Ok(())
    })
}
