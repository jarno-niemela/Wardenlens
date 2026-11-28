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

use wardenlens_core::video::{Bits, BitsError, unescape};

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

impl From<BitsError> for SpsError {
    fn from(e: BitsError) -> Self {
        match e {
            BitsError::OutOfRange => Self::OutOfRange,
            _ => Self::Truncated,
        }
    }
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
    /// An intra-only profile (44, or 86, 110, 122 or 244 with `constraint_set3_flag`).
    IntraOnlyProfile,
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
        ReorderVerdict::Undetermined
    }

    fn is_intra_only(&self) -> bool {
        // constraint_set3_flag is bit 0x10 of the constraint byte. Intra profiles: High 10 Intra
        // (110), High 4:2:2 Intra (122), High 4:4:4 Intra (244) with the flag (spec A.2.8 to
        // A.2.10), CAVLC 4:4:4 Intra (44, always, A.2.11) and Scalable High Intra (86 with the
        // flag). High (100) with the flag is an ordinary High stream.
        let set3 = self.constraint_flags & 0x10 != 0;
        self.profile_idc == 44 || (set3 && matches!(self.profile_idc, 86 | 110 | 122 | 244))
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

/// High family profiles carry the chroma and scaling list syntax (spec 7.3.2.1.1).
fn has_chroma_info(profile_idc: u8) -> bool {
    wardenlens_core::video::is_high_family(profile_idc)
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
    r.skip(20).map_err(SpsError::from) // four 5-bit length fields
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
            ("baseline, poc 0: not proven", none(66), Undetermined),
            (
                "baseline, poc 1: not proven",
                poc(
                    66,
                    Poc::One {
                        always_zero: false,
                        non_ref: 0,
                        top_bottom: 0,
                        cycle: vec![],
                    },
                ),
                Undetermined,
            ),
            ("baseline, poc 2", poc(66, Poc::Two), NoReordering(PocType2)),
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
            (
                "high (100) with set3 is not intra",
                flags(100, 0x10),
                Undetermined,
            ),
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

    /// Whether the oracle (h264-reader) reads this profile's SPS the way the parser does.
    ///
    /// Profile 144 is the High 4:4:4 profile withdrawn from H.264 in 2007: 7.3.2.1.1 no longer
    /// lists it, so a strict reader (h264-reader) treats it as having no chroma syntax. ffmpeg
    /// and the JM decoder still read it as a High profile, and so does `HIGH_FAMILY_PROFILES`,
    /// because cameras and old files in the wild carry it (#54). The parser is right and the
    /// oracle is not an authority on 144: it is excluded from the comparison, not from the
    /// parser (#241).
    fn oracle_agrees_on(profile: u8) -> bool {
        profile != 144
    }

    fn oracle(nal: &[u8]) -> Option<SeqParameterSet> {
        SeqParameterSet::from_bits(BitReader::new(ByteReader::skipping_h264_header(nal))).ok()
    }

    /// #241: the shrunk case. Profile 144 with the High syntax and a reorder bound parses as
    /// written; the strict oracle misreads the same bytes, which is why it is not compared.
    #[test]
    fn profile_144_parses_as_high_family_regression_241() {
        let mut s = with_reorder(base_spec(144), Some(2));
        s.chroma.bit_depths = (1, 0);
        s.gaps = true;
        s.size_mbs = (0, 30);
        let got = parse_sps(&s.nal()).unwrap();
        assert_eq!(got.profile_idc, 144);
        assert_eq!(got.max_num_reorder_frames, Some(2));
        assert!(!oracle_agrees_on(144));
        // The cause, pinned: for some High syntax values the oracle accepts the same bytes and
        // reads a different pic_order_cnt_type (it takes the chroma fields for the frame_num and POC fields).
        // If h264-reader ever learns 144 this fails and 144 can rejoin the comparison.
        let mut disagreements = 0;
        for idc in 0..=3 {
            for depths in [(0, 0), (1, 0), (0, 1), (2, 3)] {
                for gaps in [false, true] {
                    let mut t = s.clone();
                    t.chroma.idc = idc;
                    t.chroma.bit_depths = depths;
                    t.gaps = gaps;
                    let ours = parse_sps(&t.nal()).unwrap();
                    assert_eq!(ours.max_num_reorder_frames, Some(2));
                    let theirs = oracle(&t.nal()).map(|o| match o.pic_order_cnt {
                        h264_reader::nal::sps::PicOrderCntType::TypeZero { .. } => 0,
                        h264_reader::nal::sps::PicOrderCntType::TypeOne { .. } => 1,
                        h264_reader::nal::sps::PicOrderCntType::TypeTwo => 2,
                    });
                    if theirs.is_some_and(|x| x != ours.pic_order_cnt_type) {
                        disagreements += 1;
                    }
                }
            }
        }
        assert!(disagreements > 0, "oracle no longer misreads 144");
        for p in wardenlens_core::video::HIGH_FAMILY_PROFILES {
            if p != 144 {
                assert!(oracle_agrees_on(p), "oracle must still check {p}");
                let mut t = with_reorder(base_spec(p), Some(2));
                if let Some(r) = t.vui.as_mut().and_then(|v| v.restriction.as_mut()) {
                    r.dec_buf = 2; // the oracle bounds it by the level's DPB size
                }
                let theirs = oracle(&t.nal())
                    .unwrap_or_else(|| panic!("oracle rejects {p}"))
                    .vui_parameters
                    .and_then(|v| v.bitstream_restrictions)
                    .map(|b| b.max_num_reorder_frames);
                assert_eq!(theirs, Some(2), "profile {p}");
            }
        }
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
            if let Some(o) = oracle(&nal).filter(|_| oracle_agrees_on(spec.profile)) {
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
