//! Bounded, defensive H.264 sequence parameter set parser (ITU-T H.264 section 7.3.2.1.1).
//!
//! The SPS comes from a camera and is hostile input (SEC-2): the length is capped before any
//! work, every read is bounds-checked, and every loop count is capped. It extracts only what
//! the writer needs: profile, level, chroma format, bit depths and the cropped dimensions.

use crate::error::Mp4Error;

/// Largest SPS (NAL header included) we accept. Real SPSs are well under 100 bytes.
pub const MAX_SPS_LEN: usize = 1024;

/// The fields of an SPS that the muxer uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpsInfo {
    /// `profile_idc`.
    pub profile_idc: u8,
    /// The constraint-set flags byte (`profile_compatibility`).
    pub constraint_flags: u8,
    /// `level_idc`.
    pub level_idc: u8,
    /// `chroma_format_idc` (1, 4:2:0, when the profile does not carry it).
    pub chroma_format_idc: u8,
    /// Luma bit depth (8 when the profile does not carry it).
    pub bit_depth_luma: u8,
    /// Chroma bit depth (8 when the profile does not carry it).
    pub bit_depth_chroma: u8,
    /// Display width in pixels after cropping, 1..=65535.
    pub width: u16,
    /// Display height in pixels after cropping, 1..=65535.
    pub height: u16,
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn bit(&mut self) -> Result<u8, Mp4Error> {
        let byte = self.data.get(self.pos / 8).ok_or(Mp4Error::SpsTruncated)?;
        let shift = 7u32.saturating_sub(u32::try_from(self.pos % 8).unwrap_or(0));
        self.pos = self.pos.checked_add(1).ok_or(Mp4Error::SpsTruncated)?;
        Ok((byte >> shift) & 1)
    }

    fn flag(&mut self) -> Result<bool, Mp4Error> {
        Ok(self.bit()? == 1)
    }

    fn bits(&mut self, n: u32) -> Result<u32, Mp4Error> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | u32::from(self.bit()?);
        }
        Ok(v)
    }

    fn byte(&mut self) -> Result<u8, Mp4Error> {
        u8::try_from(self.bits(8)?).map_err(|_| Mp4Error::SpsTruncated)
    }

    /// Exp-Golomb `ue(v)`, at most 31 leading zeros so the value fits `u32`.
    fn ue(&mut self) -> Result<u32, Mp4Error> {
        let mut zeros = 0u32;
        while self.bit()? == 0 {
            zeros = zeros.checked_add(1).ok_or(Mp4Error::SpsTruncated)?;
            if zeros > 31 {
                return Err(Mp4Error::SpsInvalid("exp-golomb code too long"));
            }
        }
        let rest = u64::from(self.bits(zeros)?);
        let overflow = || Mp4Error::SpsInvalid("exp-golomb overflow");
        let base = 1u64
            .checked_shl(zeros)
            .ok_or_else(overflow)?
            .saturating_sub(1);
        u32::try_from(base.saturating_add(rest)).map_err(|_| overflow())
    }

    /// `ue(v)` that must not exceed `max`.
    fn ue_max(&mut self, max: u32, what: &'static str) -> Result<u32, Mp4Error> {
        let v = self.ue()?;
        if v > max {
            return Err(Mp4Error::SpsInvalid(what));
        }
        Ok(v)
    }

    /// Signed Exp-Golomb `se(v)`.
    fn se(&mut self) -> Result<i64, Mp4Error> {
        let k = i64::from(self.ue()?);
        let magnitude = k.saturating_add(1) / 2;
        Ok(if k % 2 == 1 {
            magnitude
        } else {
            magnitude.saturating_neg()
        })
    }
}

/// Remove emulation-prevention bytes (`00 00 03` becomes `00 00`).
fn unescape(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rbsp.len());
    let mut zeros = 0u8;
    for &b in rbsp {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
        out.push(b);
    }
    out
}

fn skip_scaling_list(bits: &mut Bits<'_>, size: u32) -> Result<(), Mp4Error> {
    let (mut last, mut next) = (8i64, 8i64);
    for _ in 0..size {
        if next != 0 {
            next = last
                .saturating_add(bits.se()?)
                .saturating_add(256)
                .rem_euclid(256);
        }
        if next != 0 {
            last = next;
        }
    }
    Ok(())
}

struct ChromaInfo {
    format: u32,
    separate_planes: bool,
    depth_luma: u32,
    depth_chroma: u32,
}

/// The high-profile extension fields; other profiles imply 4:2:0 at 8 bits.
fn parse_chroma(bits: &mut Bits<'_>, profile_idc: u8) -> Result<ChromaInfo, Mp4Error> {
    let mut info = ChromaInfo {
        format: 1,
        separate_planes: false,
        depth_luma: 8,
        depth_chroma: 8,
    };
    if !matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        return Ok(info);
    }
    info.format = bits.ue_max(3, "chroma_format_idc out of range")?;
    if info.format == 3 {
        info.separate_planes = bits.flag()?;
    }
    info.depth_luma = bits.ue_max(6, "bit depth out of range")?.saturating_add(8);
    info.depth_chroma = bits.ue_max(6, "bit depth out of range")?.saturating_add(8);
    bits.bit()?; // qpprime_y_zero_transform_bypass_flag
    if bits.flag()? {
        let lists = if info.format == 3 { 12 } else { 8 };
        for i in 0..lists {
            if bits.flag()? {
                skip_scaling_list(bits, if i < 6 { 16 } else { 64 })?;
            }
        }
    }
    Ok(info)
}

fn skip_poc(bits: &mut Bits<'_>) -> Result<(), Mp4Error> {
    bits.ue_max(12, "log2_max_frame_num out of range")?;
    match bits.ue_max(2, "pic_order_cnt_type out of range")? {
        0 => {
            bits.ue_max(12, "log2_max_poc_lsb out of range")?;
        }
        1 => {
            bits.bit()?;
            bits.se()?;
            bits.se()?;
            let cycle = bits.ue_max(255, "poc cycle length out of range")?;
            for _ in 0..cycle {
                bits.se()?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parse an SPS NAL unit (with its one-byte NAL header, without start code).
///
/// # Errors
/// A typed [`Mp4Error`] for an empty, oversized, truncated or out-of-range SPS. Never panics.
pub fn parse_sps(nal: &[u8]) -> Result<SpsInfo, Mp4Error> {
    if nal.is_empty() || nal.len() > MAX_SPS_LEN {
        return Err(Mp4Error::SpsLength {
            len: nal.len(),
            max: MAX_SPS_LEN,
        });
    }
    let (&header, body) = nal.split_first().ok_or(Mp4Error::NotAnSps)?;
    if header & 0x80 != 0 || header & 0x1f != 7 {
        return Err(Mp4Error::NotAnSps);
    }
    let rbsp = unescape(body);
    let mut bits = Bits::new(&rbsp);
    let profile_idc = bits.byte()?;
    let constraint_flags = bits.byte()?;
    let level_idc = bits.byte()?;
    bits.ue_max(31, "seq_parameter_set_id out of range")?;
    let chroma = parse_chroma(&mut bits, profile_idc)?;
    skip_poc(&mut bits)?;
    bits.ue()?; // max_num_ref_frames
    bits.bit()?; // gaps_in_frame_num_value_allowed_flag
    let width_mbs = bits.ue()?;
    let height_map_units = bits.ue()?;
    let frame_mbs_only = bits.flag()?;
    if !frame_mbs_only {
        bits.bit()?; // mb_adaptive_frame_field_flag
    }
    bits.bit()?; // direct_8x8_inference_flag
    let crop = if bits.flag()? {
        [bits.ue()?, bits.ue()?, bits.ue()?, bits.ue()?]
    } else {
        [0; 4]
    };
    let (width, height) = dimensions(&chroma, frame_mbs_only, width_mbs, height_map_units, crop)?;
    Ok(SpsInfo {
        profile_idc,
        constraint_flags,
        level_idc,
        chroma_format_idc: u8::try_from(chroma.format).unwrap_or(1),
        bit_depth_luma: u8::try_from(chroma.depth_luma).unwrap_or(8),
        bit_depth_chroma: u8::try_from(chroma.depth_chroma).unwrap_or(8),
        width,
        height,
    })
}

/// Cropped dimensions (H.264 equations 7-19 to 7-24), checked, within 1..=65535.
fn dimensions(
    chroma: &ChromaInfo,
    frame_mbs_only: bool,
    width_mbs_minus1: u32,
    height_units_minus1: u32,
    [left, right, top, bottom]: [u32; 4],
) -> Result<(u16, u16), Mp4Error> {
    let range = || Mp4Error::SpsInvalid("dimensions out of range");
    let map_unit_rows: u64 = if frame_mbs_only { 1 } else { 2 };
    // Each `ue(v)` is below 2^32, so with u64 these cannot overflow; they are checked anyway.
    let mbs = |n: u32, rows: u64| {
        u64::from(n)
            .checked_add(1)
            .and_then(|v| v.checked_mul(16))
            .and_then(|v| v.checked_mul(rows))
            .ok_or_else(range)
    };
    let full_w = mbs(width_mbs_minus1, 1)?;
    let full_h = mbs(height_units_minus1, map_unit_rows)?;
    let chroma_array_type = if chroma.separate_planes {
        0
    } else {
        chroma.format
    };
    // CropUnitX and CropUnitY: SubWidthC and SubHeightC for 4:2:0 and 4:2:2, 1 otherwise.
    let (unit_x, sub_height): (u64, u64) = match chroma_array_type {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    };
    let crop = |a: u32, b: u32, unit: u64| {
        u64::from(a)
            .checked_add(u64::from(b))
            .and_then(|v| v.checked_mul(unit))
            .ok_or_else(range)
    };
    let crop_w = crop(left, right, unit_x)?;
    let crop_h = crop(
        top,
        bottom,
        sub_height.checked_mul(map_unit_rows).ok_or_else(range)?,
    )?;
    let w = full_w
        .checked_sub(crop_w)
        .filter(|w| *w > 0)
        .ok_or(Mp4Error::SpsInvalid("crop exceeds width"))?;
    let h = full_h
        .checked_sub(crop_h)
        .filter(|h| *h > 0)
        .ok_or(Mp4Error::SpsInvalid("crop exceeds height"))?;
    match (u16::try_from(w), u16::try_from(h)) {
        (Ok(w), Ok(h)) => Ok((w, h)),
        _ => Err(range()),
    }
}
