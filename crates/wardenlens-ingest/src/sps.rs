//! A bounded H.264 SPS reader that answers one question: can this stream reorder frames?
//!
//! ADR 0005 open risk 1: the recorder writes PTS = DTS, which is right only when pictures are
//! output in decoding order. The SPS says so in three places (ITU-T H.264 section 7.3.2.1.1 and
//! annex E.1.1): `pic_order_cnt_type`, the VUI `max_num_reorder_frames` (bitstream restriction)
//! and the profile. [`parse_sps`] reads exactly the syntax elements that lead to those fields and
//! [`SpsSummary::reordering`] turns them into a [`ReorderVerdict`].
//!
//! The input is untrusted camera data. Nothing here panics, indexes or allocates more than the
//! input length ([`MAX_PARAM_SET_BYTES`] at most), and no error carries input bytes.

use crate::MAX_PARAM_SET_BYTES;

/// Why an SPS could not be read. Never carries input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpsError {
    /// The input is longer than [`MAX_PARAM_SET_BYTES`].
    #[error("SPS is longer than the {MAX_PARAM_SET_BYTES} byte limit")]
    TooLong,
    /// The NAL header is not that of an SPS (type 7, forbidden bit clear).
    #[error("NAL unit is not an SPS")]
    NotSps,
    /// The data ended inside the syntax elements read.
    #[error("SPS is truncated")]
    Truncated,
    /// A value is outside the range the specification allows.
    #[error("SPS has a value outside its allowed range")]
    OutOfRange,
}

/// The SPS fields that decide frame reordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpsSummary {
    /// `profile_idc`.
    pub profile_idc: u8,
    /// The constraint flag byte (`constraint_set0_flag` is the most significant bit).
    pub constraint_flags: u8,
    /// `pic_order_cnt_type`, 0 to 2.
    pub pic_order_cnt_type: u8,
    /// VUI `max_num_reorder_frames`, if the SPS carries a bitstream restriction.
    pub max_num_reorder_frames: Option<u32>,
}

/// Why a stream cannot reorder frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoReorderReason {
    /// `pic_order_cnt_type` 2: output order is decoding order by definition (spec 8.2.1.3).
    PocType2,
    /// The VUI declares `max_num_reorder_frames` 0.
    VuiZeroReorder,
    /// An intra-only profile (44, or a High family profile with `constraint_set3_flag`).
    IntraOnlyProfile,
    /// Baseline (`profile_idc` 66) has no B slices; the verdict assumes picture order counts rise
    /// in decoding order, as every encoder produces for P-only streams.
    BaselineProfile,
}

/// Whether the SPS lets the stream reorder frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReorderVerdict {
    /// Output order equals decoding order, for the given reason.
    NoReordering(NoReorderReason),
    /// The VUI allows up to this many frames of reordering (at least 1). The stream may still
    /// never use it; look for B slices with [`crate::contains_b_slice`].
    ReorderingAllowed(u32),
    /// The SPS neither proves nor excludes reordering (for example Main or High profile, POC type
    /// 0, no bitstream restriction). Decide by looking for B slices with
    /// [`crate::contains_b_slice`].
    Undetermined,
}

impl SpsSummary {
    /// The verdict for these fields.
    ///
    /// A declared reordering wins over every other rule, so a contradictory SPS errs towards
    /// "reordering" instead of hiding it.
    #[must_use]
    pub fn reordering(&self) -> ReorderVerdict {
        if let Some(n) = self.max_num_reorder_frames
            && n > 0
        {
            return ReorderVerdict::ReorderingAllowed(n);
        }
        if self.pic_order_cnt_type == 2 {
            return ReorderVerdict::NoReordering(NoReorderReason::PocType2);
        }
        if self.max_num_reorder_frames == Some(0) {
            return ReorderVerdict::NoReordering(NoReorderReason::VuiZeroReorder);
        }
        if self.is_intra_only() {
            return ReorderVerdict::NoReordering(NoReorderReason::IntraOnlyProfile);
        }
        if self.profile_idc == 66 {
            return ReorderVerdict::NoReordering(NoReorderReason::BaselineProfile);
        }
        ReorderVerdict::Undetermined
    }

    fn is_intra_only(&self) -> bool {
        // constraint_set3_flag is bit 0x10 of the constraint byte (spec A.2.8 to A.2.11).
        let set3 = self.constraint_flags & 0x10 != 0;
        self.profile_idc == 44 || (set3 && matches!(self.profile_idc, 86 | 100 | 110 | 122 | 244))
    }
}

/// Reads an SPS NAL unit (with its one byte header, emulation prevention bytes allowed) and
/// returns the fields that decide reordering.
///
/// RBSP trailing bits and bytes after the SPS are not checked: the answer does not depend on them.
///
/// # Errors
/// [`SpsError`] for an input that is not an SPS, is too long, is cut off or holds a value outside
/// its range. The SPS of a stream whose VUI is cut off is reported as `Truncated`, not guessed.
pub fn parse_sps(nal: &[u8]) -> Result<SpsSummary, SpsError> {
    if nal.len() > MAX_PARAM_SET_BYTES {
        return Err(SpsError::TooLong);
    }
    let header = *nal.first().ok_or(SpsError::Truncated)?;
    if header & 0x80 != 0 || header & 0x1f != 7 {
        return Err(SpsError::NotSps);
    }
    let rbsp = unescape(nal.get(1..).unwrap_or_default());
    read_sps(&mut Bits::new(&rbsp))
}

/// [`parse_sps`] followed by [`SpsSummary::reordering`].
///
/// # Errors
/// As [`parse_sps`].
pub fn sps_reordering(nal: &[u8]) -> Result<ReorderVerdict, SpsError> {
    parse_sps(nal).map(|s| s.reordering())
}

/// Removes emulation prevention bytes (`00 00 03` becomes `00 00`, spec 7.4.1).
pub(crate) fn unescape(escaped: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut zeros = 0_u8;
    for &b in escaped {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
        out.push(b);
    }
    out
}

/// MSB-first bit reader over a byte slice. Every read either consumes input or fails.
pub(crate) struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn bit(&mut self) -> Result<u32, SpsError> {
        let byte = *self.data.get(self.pos / 8).ok_or(SpsError::Truncated)?;
        let shift = 7_u32.saturating_sub(u32::try_from(self.pos % 8).unwrap_or(0));
        self.pos = self.pos.saturating_add(1);
        Ok(u32::from(byte.checked_shr(shift).unwrap_or(0) & 1))
    }

    /// Up to 32 bits as a number.
    fn bits(&mut self, n: u32) -> Result<u32, SpsError> {
        if n > 32 {
            return Err(SpsError::OutOfRange);
        }
        let mut v = 0_u64;
        for _ in 0..n {
            v = (v << 1) | u64::from(self.bit()?);
        }
        u32::try_from(v).map_err(|_| SpsError::OutOfRange)
    }

    fn skip(&mut self, n: u32) -> Result<(), SpsError> {
        self.bits(n).map(drop)
    }

    /// `ue(v)`: Exp-Golomb, at most 31 leading zeros so the value fits in `u32` (spec 9.1).
    pub(crate) fn ue(&mut self) -> Result<u32, SpsError> {
        let mut zeros = 0_u32;
        while self.bit()? == 0 {
            zeros = zeros.saturating_add(1);
            if zeros > 31 {
                return Err(SpsError::OutOfRange);
            }
        }
        let suffix = u64::from(self.bits(zeros)?);
        let base = (1_u64 << zeros).saturating_sub(1);
        u32::try_from(base.saturating_add(suffix)).map_err(|_| SpsError::OutOfRange)
    }

    /// `ue(v)` that must not exceed `max`.
    fn ue_max(&mut self, max: u32) -> Result<u32, SpsError> {
        let v = self.ue()?;
        if v > max {
            return Err(SpsError::OutOfRange);
        }
        Ok(v)
    }

    /// `se(v)`: the signed mapping of `ue(v)` (spec 9.1.1), only needed to skip the value.
    fn se(&mut self) -> Result<i64, SpsError> {
        let k = i64::from(self.ue()?);
        let magnitude = k.saturating_add(1) / 2;
        Ok(if k % 2 == 1 {
            magnitude
        } else {
            magnitude.saturating_neg()
        })
    }

    fn flag(&mut self) -> Result<bool, SpsError> {
        self.bit().map(|b| b == 1)
    }
}

/// High family profiles carry the chroma and scaling list syntax (spec 7.3.2.1.1).
fn has_chroma_info(profile_idc: u8) -> bool {
    matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    )
}

fn read_sps(r: &mut Bits<'_>) -> Result<SpsSummary, SpsError> {
    let profile_idc = u8::try_from(r.bits(8)?).map_err(|_| SpsError::OutOfRange)?;
    let constraint_flags = u8::try_from(r.bits(8)?).map_err(|_| SpsError::OutOfRange)?;
    r.skip(8)?; // level_idc
    r.ue_max(31)?; // seq_parameter_set_id
    if has_chroma_info(profile_idc) {
        skip_chroma_info(r)?;
    }
    r.ue_max(12)?; // log2_max_frame_num_minus4
    let pic_order_cnt_type = r.ue_max(2)?;
    match pic_order_cnt_type {
        0 => {
            r.ue_max(12)?; // log2_max_pic_order_cnt_lsb_minus4
        }
        1 => {
            r.skip(1)?; // delta_pic_order_always_zero_flag
            r.se()?;
            r.se()?;
            for _ in 0..r.ue_max(255)? {
                r.se()?;
            }
        }
        _ => {}
    }
    r.ue_max(16)?; // max_num_ref_frames
    r.skip(1)?; // gaps_in_frame_num_value_allowed_flag
    r.ue()?; // pic_width_in_mbs_minus1
    r.ue()?; // pic_height_in_map_units_minus1
    if !r.flag()? {
        // frame_mbs_only_flag is 0
        r.skip(1)?; // mb_adaptive_frame_field_flag
    }
    r.skip(1)?; // direct_8x8_inference_flag
    if r.flag()? {
        // frame_cropping_flag
        for _ in 0..4 {
            r.ue()?;
        }
    }
    let max_num_reorder_frames = if r.flag()? { read_vui(r)? } else { None };
    Ok(SpsSummary {
        profile_idc,
        constraint_flags,
        pic_order_cnt_type: u8::try_from(pic_order_cnt_type).map_err(|_| SpsError::OutOfRange)?,
        max_num_reorder_frames,
    })
}

fn skip_chroma_info(r: &mut Bits<'_>) -> Result<(), SpsError> {
    let chroma_format_idc = r.ue_max(3)?;
    if chroma_format_idc == 3 {
        r.skip(1)?; // separate_colour_plane_flag
    }
    r.ue_max(6)?; // bit_depth_luma_minus8
    r.ue_max(6)?; // bit_depth_chroma_minus8
    r.skip(1)?; // qpprime_y_zero_transform_bypass_flag
    if r.flag()? {
        // seq_scaling_matrix_present_flag
        let lists = if chroma_format_idc == 3 { 12 } else { 8 };
        for i in 0..lists {
            if r.flag()? {
                skip_scaling_list(r, if i < 6 { 16 } else { 64 })?;
            }
        }
    }
    Ok(())
}

/// `scaling_list()` (spec 7.3.2.1.1.1): the values are not needed, only their length.
fn skip_scaling_list(r: &mut Bits<'_>, size: u32) -> Result<(), SpsError> {
    let mut last = 8_i64;
    let mut next = 8_i64;
    for _ in 0..size {
        if next != 0 {
            let delta = r.se()?;
            if !(-128..=127).contains(&delta) {
                return Err(SpsError::OutOfRange);
            }
            next = last
                .saturating_add(delta)
                .saturating_add(256)
                .rem_euclid(256);
        }
        if next != 0 {
            last = next;
        }
    }
    Ok(())
}

/// `vui_parameters()` (spec E.1.1) up to and including the bitstream restriction.
fn read_vui(r: &mut Bits<'_>) -> Result<Option<u32>, SpsError> {
    if r.flag()? {
        // aspect_ratio_info_present_flag; 255 is Extended_SAR
        if r.bits(8)? == 255 {
            r.skip(32)?;
        }
    }
    if r.flag()? {
        r.skip(1)?; // overscan_appropriate_flag
    }
    if r.flag()? {
        // video_signal_type_present_flag
        r.skip(4)?; // video_format, video_full_range_flag
        if r.flag()? {
            r.skip(24)?; // colour description
        }
    }
    if r.flag()? {
        // chroma_loc_info_present_flag
        r.ue_max(5)?;
        r.ue_max(5)?;
    }
    if r.flag()? {
        // timing_info_present_flag
        r.skip(32)?;
        r.skip(32)?;
        r.skip(1)?; // fixed_frame_rate_flag
    }
    let nal_hrd = r.flag()?;
    if nal_hrd {
        skip_hrd(r)?;
    }
    let vcl_hrd = r.flag()?;
    if vcl_hrd {
        skip_hrd(r)?;
    }
    if nal_hrd || vcl_hrd {
        r.skip(1)?; // low_delay_hrd_flag
    }
    r.skip(1)?; // pic_struct_present_flag
    if !r.flag()? {
        return Ok(None); // bitstream_restriction_flag
    }
    r.skip(1)?; // motion_vectors_over_pic_boundaries_flag
    for _ in 0..4 {
        r.ue()?; // max_bytes_per_pic_denom .. log2_max_mv_length_vertical
    }
    let reorder = r.ue_max(16)?;
    r.ue_max(16)?; // max_dec_frame_buffering
    Ok(Some(reorder))
}

/// `hrd_parameters()` (spec E.1.2).
fn skip_hrd(r: &mut Bits<'_>) -> Result<(), SpsError> {
    let cpb_cnt = r.ue_max(31)?.saturating_add(1);
    r.skip(8)?; // bit_rate_scale, cpb_size_scale
    for _ in 0..cpb_cnt {
        r.ue()?;
        r.ue()?;
        r.skip(1)?; // cbr_flag
    }
    r.skip(20) // four 5-bit length fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{
        BitWriter, Poc, Restriction, SpsSpec, Vui, base_spec, escape, sps_strategy,
    };
    use h264_reader::nal::sps::SeqParameterSet;
    use h264_reader::rbsp::{BitReader, ByteReader};
    use proptest::prelude::*;

    fn with_reorder(mut s: SpsSpec, reorder: Option<u32>) -> SpsSpec {
        s.vui = Some(Vui {
            restriction: reorder.map(|r| Restriction {
                mv_over_boundaries: true,
                denoms: [2, 1, 16, 16],
                reorder: r,
                dec_buf: 16,
            }),
            ..Vui::default()
        });
        s
    }

    fn verdict(s: &SpsSpec) -> ReorderVerdict {
        sps_reordering(&s.nal()).unwrap()
    }

    // Hand assembled from the syntax table, not from the test writer.
    // Baseline, level 1.0, pic_order_cnt_type 2, one reference frame, 16x16, no VUI. Bits after
    // the header: id '1', frame_num bits '1', poc type '011', max refs '010', gaps '0', width '1',
    // height '1', frame_mbs_only '1', direct_8x8 '1', cropping '0', vui '0', stop bit '1'.
    const HAND_BASELINE_POC2: [u8; 6] = [0x67, 0x42, 0x00, 0x0a, 0xda, 0x79];
    // As above for Main profile with pic_order_cnt_type 0 (poc type '1', poc lsb bits '1'): the
    // SPS proves nothing about reordering.
    const HAND_MAIN_POC0: [u8; 6] = [0x67, 0x4d, 0x00, 0x1f, 0xf4, 0xf2];

    #[test]
    fn hand_assembled_vectors() {
        let s = parse_sps(&HAND_BASELINE_POC2).unwrap();
        assert_eq!((s.profile_idc, s.pic_order_cnt_type), (66, 2));
        assert_eq!(s.max_num_reorder_frames, None);
        assert_eq!(
            s.reordering(),
            ReorderVerdict::NoReordering(NoReorderReason::PocType2)
        );
        let m = parse_sps(&HAND_MAIN_POC0).unwrap();
        assert_eq!((m.profile_idc, m.pic_order_cnt_type), (77, 0));
        assert_eq!(m.reordering(), ReorderVerdict::Undetermined);
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "a data table of cases")]
    fn verdict_table() {
        use NoReorderReason::*;
        use ReorderVerdict::*;
        let none = |p: u8| base_spec(p);
        let poc = |p: u8, poc: Poc| SpsSpec {
            poc,
            ..base_spec(p)
        };
        let flags = |p: u8, c: u8| SpsSpec {
            constraint: c,
            ..base_spec(p)
        };
        let rows: Vec<(&str, SpsSpec, ReorderVerdict)> = vec![
            ("main, poc 0, no vui", none(77), Undetermined),
            ("high, poc 0, no vui", none(100), Undetermined),
            ("extended, poc 0, no vui", none(88), Undetermined),
            ("baseline", none(66), NoReordering(BaselineProfile)),
            ("poc 2", poc(77, Poc::Two), NoReordering(PocType2)),
            (
                "poc 1 stays undetermined",
                poc(
                    77,
                    Poc::One {
                        always_zero: false,
                        non_ref: 0,
                        top_bottom: 0,
                        cycle: vec![2],
                    },
                ),
                Undetermined,
            ),
            (
                "vui reorder 0",
                with_reorder(none(100), Some(0)),
                NoReordering(VuiZeroReorder),
            ),
            (
                "vui reorder 1",
                with_reorder(none(100), Some(1)),
                ReorderingAllowed(1),
            ),
            (
                "vui reorder 16",
                with_reorder(none(77), Some(16)),
                ReorderingAllowed(16),
            ),
            (
                "vui without restriction",
                with_reorder(none(77), None),
                Undetermined,
            ),
            (
                "high intra (set3)",
                flags(100, 0x10),
                NoReordering(IntraOnlyProfile),
            ),
            (
                "high 10 intra",
                flags(110, 0x10),
                NoReordering(IntraOnlyProfile),
            ),
            (
                "high 4:2:2 intra",
                flags(122, 0x10),
                NoReordering(IntraOnlyProfile),
            ),
            (
                "high 4:4:4 intra",
                flags(244, 0x10),
                NoReordering(IntraOnlyProfile),
            ),
            (
                "scalable high intra",
                flags(86, 0x10),
                NoReordering(IntraOnlyProfile),
            ),
            (
                "cavlc 4:4:4 intra",
                none(44),
                NoReordering(IntraOnlyProfile),
            ),
            ("main with set3 is not intra", flags(77, 0x10), Undetermined),
            ("high with other flags only", flags(100, 0xef), Undetermined),
            (
                "poc 2 but vui says reorder",
                with_reorder(poc(100, Poc::Two), Some(2)),
                ReorderingAllowed(2),
            ),
            (
                "baseline but vui says reorder",
                with_reorder(none(66), Some(1)),
                ReorderingAllowed(1),
            ),
            (
                "intra but vui says reorder",
                SpsSpec {
                    constraint: 0x10,
                    ..with_reorder(none(100), Some(3))
                },
                ReorderingAllowed(3),
            ),
            (
                "poc 2 and vui 0: poc rule first",
                with_reorder(poc(77, Poc::Two), Some(0)),
                NoReordering(PocType2),
            ),
        ];
        for (name, spec, want) in rows {
            assert_eq!(verdict(&spec), want, "{name}");
        }
    }

    #[test]
    fn rejects_non_sps_and_oversize() {
        assert_eq!(parse_sps(&[]), Err(SpsError::Truncated));
        assert_eq!(parse_sps(&[0x68, 0xce, 0x3c, 0x80]), Err(SpsError::NotSps));
        // forbidden_zero_bit set
        assert_eq!(parse_sps(&[0xe7, 0x42, 0, 10]), Err(SpsError::NotSps));
        assert_eq!(parse_sps(&[0x67]), Err(SpsError::Truncated));
        let mut big = base_spec(77).nal();
        big.resize(MAX_PARAM_SET_BYTES, 0);
        assert_ne!(
            parse_sps(&big),
            Err(SpsError::TooLong),
            "exactly the limit is read"
        );
        big.push(0);
        assert_eq!(parse_sps(&big), Err(SpsError::TooLong));
    }

    #[test]
    fn out_of_range_values_are_refused() {
        // Each row writes a header and then one bad field.
        let bad = |f: &dyn Fn(&mut BitWriter)| {
            let mut w = BitWriter::default();
            w.u(8, 77);
            w.u(8, 0);
            w.u(8, 30);
            f(&mut w);
            w.trailing();
            let mut nal = vec![0x67];
            nal.extend(escape(&w.bytes));
            parse_sps(&nal)
        };
        assert_eq!(bad(&|w| w.ue(32)), Err(SpsError::OutOfRange), "sps id 32");
        assert_eq!(
            bad(&|w| {
                w.ue(0);
                w.ue(13);
            }),
            Err(SpsError::OutOfRange),
            "log2_max_frame_num"
        );
        assert_eq!(
            bad(&|w| {
                w.ue(0);
                w.ue(0);
                w.ue(3);
            }),
            Err(SpsError::OutOfRange),
            "poc type 3"
        );
        assert_eq!(
            bad(&|w| {
                w.ue(0);
                w.ue(0);
                w.ue(0);
                w.ue(13);
            }),
            Err(SpsError::OutOfRange),
            "poc lsb"
        );
        assert_eq!(
            bad(&|w| {
                w.ue(0);
                w.ue(0);
                w.ue(0);
                w.ue(0);
                w.ue(17);
            }),
            Err(SpsError::OutOfRange),
            "17 reference frames"
        );
        // 32 leading zeros in an Exp-Golomb code
        assert_eq!(bad(&|w| w.u(40, 1)), Err(SpsError::OutOfRange));
        // poc type 1 with 256 cycle entries
        assert_eq!(
            bad(&|w| {
                w.ue(0);
                w.ue(0);
                w.ue(1);
                w.bit(false);
                w.se(0);
                w.se(0);
                w.ue(256);
            }),
            Err(SpsError::OutOfRange)
        );
    }

    #[test]
    fn reorder_above_16_is_refused() {
        let mut s = with_reorder(base_spec(100), Some(17));
        assert_eq!(sps_reordering(&s.nal()), Err(SpsError::OutOfRange));
        s = with_reorder(base_spec(100), Some(16));
        assert!(sps_reordering(&s.nal()).is_ok());
    }

    #[test]
    fn emulation_prevention_is_removed() {
        // A VUI with timing info holds long zero runs; the writer escapes them.
        let mut s = with_reorder(base_spec(100), Some(2));
        if let Some(v) = &mut s.vui {
            v.timing = Some((0, 0, false));
        }
        let nal = s.nal();
        assert!(
            nal.windows(3).any(|w| w == [0, 0, 3]),
            "vector must contain an escape"
        );
        assert_eq!(parse_sps(&nal).unwrap().max_num_reorder_frames, Some(2));
        assert_eq!(unescape(&[0, 0, 3, 1, 0, 0, 3]), [0, 0, 1, 0, 0]);
        assert_eq!(unescape(&[0, 3, 0, 0, 3, 3]), [0, 3, 0, 0, 3]);
    }

    fn oracle(nal: &[u8]) -> Option<SeqParameterSet> {
        SeqParameterSet::from_bits(BitReader::new(ByteReader::skipping_h264_header(nal))).ok()
    }

    proptest! {
        /// Fields read back equal the fields written, for every well-formed SPS, and agree with
        /// the independent parser retina uses wherever that parser accepts the same bytes.
        #[test]
        fn matches_written_fields_and_oracle(spec in sps_strategy()) {
            let nal = spec.nal();
            let got = parse_sps(&nal).unwrap();
            prop_assert_eq!(got.profile_idc, spec.profile);
            prop_assert_eq!(got.constraint_flags, spec.constraint);
            prop_assert_eq!(got.pic_order_cnt_type, spec.poc_type());
            prop_assert_eq!(got.max_num_reorder_frames, spec.declared_reorder());
            if let Some(o) = oracle(&nal) {
                let theirs = o.vui_parameters.and_then(|v| v.bitstream_restrictions)
                    .map(|b| b.max_num_reorder_frames);
                prop_assert_eq!(got.max_num_reorder_frames, theirs);
                let poc = match o.pic_order_cnt {
                    h264_reader::nal::sps::PicOrderCntType::TypeZero { .. } => 0,
                    h264_reader::nal::sps::PicOrderCntType::TypeOne { .. } => 1,
                    h264_reader::nal::sps::PicOrderCntType::TypeTwo => 2,
                };
                prop_assert_eq!(got.pic_order_cnt_type, poc);
            }
        }

        /// Every proper prefix of the syntax elements is refused as truncated; the full RBSP
        /// without its trailing bits still parses (trailing bits are not required).
        #[test]
        fn every_prefix_is_truncated(spec in sps_strategy()) {
            let (rbsp, bits) = spec.rbsp();
            let needed = bits.div_ceil(8);
            for cut in 0..needed {
                let mut nal = vec![0x67];
                nal.extend(escape(rbsp.get(..cut).unwrap()));
                prop_assert_eq!(parse_sps(&nal), Err(SpsError::Truncated), "cut at {}", cut);
            }
            let mut nal = vec![0x67];
            nal.extend(escape(rbsp.get(..needed).unwrap()));
            prop_assert!(parse_sps(&nal).is_ok());
        }

        /// Arbitrary bytes never panic, and an accepted SPS has in-range fields.
        #[test]
        fn arbitrary_bytes_are_total(mut bytes in prop::collection::vec(any::<u8>(), 0..300)) {
            // Make half of the inputs reach the field parser.
            if let Some(h) = bytes.first_mut() { *h = (*h & 0x60) | 7; }
            if let Ok(s) = parse_sps(&bytes) {
                prop_assert!(s.pic_order_cnt_type <= 2);
                prop_assert!(s.max_num_reorder_frames.is_none_or(|n| n <= 16));
            }
            let _ = sps_reordering(&bytes);
        }

        /// A well-formed SPS with random bytes appended where the VUI would end (hostile
        /// components inside a valid frame) never panics.
        #[test]
        fn mutated_valid_sps_is_total(spec in sps_strategy(), at in any::<prop::sample::Index>(), val in any::<u8>()) {
            let mut nal = spec.nal();
            let i = at.index(nal.len());
            if let Some(b) = nal.get_mut(i) { *b = val; }
            let _ = parse_sps(&nal);
        }
    }
}
