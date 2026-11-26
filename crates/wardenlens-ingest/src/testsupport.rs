//! Test-only SPS and slice writers, built from the syntax tables of ITU-T H.264 (7.3.2.1.1,
//! 7.3.2.1.1.1, E.1.1, E.1.2, 7.3.3), independently of the reader under test.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::manual_is_multiple_of,
    reason = "test-only writers working on small values"
)]

use proptest::prelude::*;

#[derive(Default)]
pub(crate) struct BitWriter {
    pub(crate) bytes: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    pub(crate) fn bit(&mut self, b: bool) {
        if self.bits % 8 == 0 {
            self.bytes.push(0);
        }
        if b && let Some(last) = self.bytes.last_mut() {
            *last |= 0x80 >> (self.bits % 8);
        }
        self.bits += 1;
    }

    pub(crate) fn u(&mut self, n: u32, v: u64) {
        for i in (0..n).rev() {
            self.bit((v >> i) & 1 == 1);
        }
    }

    pub(crate) fn ue(&mut self, v: u32) {
        let x = u64::from(v) + 1;
        let len = 64 - x.leading_zeros();
        self.u(len - 1, 0);
        self.u(len, x);
    }

    pub(crate) fn se(&mut self, v: i32) {
        let k = if v > 0 { 2 * v - 1 } else { -2 * v };
        self.ue(u32::try_from(k).unwrap());
    }

    pub(crate) fn bit_len(&self) -> usize {
        self.bits
    }

    /// Appends the RBSP trailing bits.
    pub(crate) fn trailing(&mut self) {
        self.bit(true);
        while self.bits % 8 != 0 {
            self.bit(false);
        }
    }
}

/// Inserts emulation prevention bytes (spec 7.4.1).
pub(crate) fn escape(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut zeros = 0;
    for &b in rbsp {
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    out
}

#[derive(Debug, Clone)]
pub(crate) struct Hrd {
    pub(crate) cpbs: Vec<(u32, u32, bool)>,
    pub(crate) scales: (u8, u8),
    pub(crate) lens: [u8; 4],
}

#[derive(Debug, Clone)]
pub(crate) struct Restriction {
    pub(crate) mv_over_boundaries: bool,
    pub(crate) denoms: [u32; 4],
    pub(crate) reorder: u32,
    pub(crate) dec_buf: u32,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Vui {
    pub(crate) aspect_idc: Option<u8>,
    pub(crate) overscan: Option<bool>,
    pub(crate) signal: Option<(u8, bool, Option<[u8; 3]>)>,
    pub(crate) chroma_loc: Option<(u32, u32)>,
    pub(crate) timing: Option<(u32, u32, bool)>,
    pub(crate) nal_hrd: Option<Hrd>,
    pub(crate) vcl_hrd: Option<Hrd>,
    pub(crate) low_delay: bool,
    pub(crate) pic_struct: bool,
    pub(crate) restriction: Option<Restriction>,
}

#[derive(Debug, Clone)]
pub(crate) struct Chroma {
    pub(crate) idc: u32,
    pub(crate) separate_planes: bool,
    pub(crate) bit_depths: (u32, u32),
    pub(crate) bypass: bool,
    /// One entry per scaling list: `None` is "not present", `Some(values)` the list; the first 0
    /// ends it (the writer then stops, as the syntax does).
    pub(crate) scaling: Option<Vec<Option<Vec<u8>>>>,
}

#[derive(Debug, Clone)]
pub(crate) enum Poc {
    Zero {
        log2_lsb_minus4: u32,
    },
    One {
        always_zero: bool,
        non_ref: i32,
        top_bottom: i32,
        cycle: Vec<i32>,
    },
    Two,
}

#[derive(Debug, Clone)]
pub(crate) struct SpsSpec {
    pub(crate) profile: u8,
    pub(crate) constraint: u8,
    pub(crate) level: u8,
    pub(crate) id: u32,
    pub(crate) chroma: Chroma,
    pub(crate) log2_frame_num_minus4: u32,
    pub(crate) poc: Poc,
    pub(crate) max_ref: u32,
    pub(crate) gaps: bool,
    pub(crate) size_mbs: (u32, u32),
    /// `Some(mbaff)` is `frame_mbs_only_flag` 0.
    pub(crate) interlaced: Option<bool>,
    pub(crate) direct_8x8: bool,
    pub(crate) crop: Option<[u32; 4]>,
    pub(crate) vui: Option<Vui>,
}

pub(crate) fn has_chroma(profile: u8) -> bool {
    matches!(
        profile,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    )
}

fn write_hrd(w: &mut BitWriter, h: &Hrd) {
    w.ue(u32::try_from(h.cpbs.len() - 1).unwrap());
    w.u(4, u64::from(h.scales.0));
    w.u(4, u64::from(h.scales.1));
    for &(rate, size, cbr) in &h.cpbs {
        w.ue(rate);
        w.ue(size);
        w.bit(cbr);
    }
    for l in h.lens {
        w.u(5, u64::from(l));
    }
}

fn write_vui(w: &mut BitWriter, v: &Vui) {
    w.bit(v.aspect_idc.is_some());
    if let Some(idc) = v.aspect_idc {
        w.u(8, u64::from(idc));
        if idc == 255 {
            w.u(32, 0x0140_00f0);
        }
    }
    w.bit(v.overscan.is_some());
    if let Some(o) = v.overscan {
        w.bit(o);
    }
    w.bit(v.signal.is_some());
    if let Some((fmt, full, colour)) = v.signal {
        w.u(3, u64::from(fmt));
        w.bit(full);
        w.bit(colour.is_some());
        if let Some(c) = colour {
            for b in c {
                w.u(8, u64::from(b));
            }
        }
    }
    w.bit(v.chroma_loc.is_some());
    if let Some((a, b)) = v.chroma_loc {
        w.ue(a);
        w.ue(b);
    }
    w.bit(v.timing.is_some());
    if let Some((units, scale, fixed)) = v.timing {
        w.u(32, u64::from(units));
        w.u(32, u64::from(scale));
        w.bit(fixed);
    }
    w.bit(v.nal_hrd.is_some());
    if let Some(h) = &v.nal_hrd {
        write_hrd(w, h);
    }
    w.bit(v.vcl_hrd.is_some());
    if let Some(h) = &v.vcl_hrd {
        write_hrd(w, h);
    }
    if v.nal_hrd.is_some() || v.vcl_hrd.is_some() {
        w.bit(v.low_delay);
    }
    w.bit(v.pic_struct);
    w.bit(v.restriction.is_some());
    if let Some(r) = &v.restriction {
        w.bit(r.mv_over_boundaries);
        for d in r.denoms {
            w.ue(d);
        }
        w.ue(r.reorder);
        w.ue(r.dec_buf);
    }
}

fn write_scaling_list(w: &mut BitWriter, values: &[u8]) {
    let mut last = 8_i32;
    for &v in values {
        let mut d = i32::from(v) - last;
        if d > 127 {
            d -= 256;
        }
        if d < -128 {
            d += 256;
        }
        w.se(d);
        if v == 0 {
            return;
        }
        last = i32::from(v);
    }
}

impl SpsSpec {
    /// The SPS NAL unit: header byte, escaped RBSP with trailing bits.
    pub(crate) fn nal(&self) -> Vec<u8> {
        let (rbsp, _) = self.rbsp();
        let mut nal = vec![0x67];
        nal.extend(escape(&rbsp));
        nal
    }

    /// The RBSP and the bit length of the syntax elements before the trailing bits.
    pub(crate) fn rbsp(&self) -> (Vec<u8>, usize) {
        let mut w = BitWriter::default();
        w.u(8, u64::from(self.profile));
        w.u(8, u64::from(self.constraint));
        w.u(8, u64::from(self.level));
        w.ue(self.id);
        if has_chroma(self.profile) {
            let c = &self.chroma;
            w.ue(c.idc);
            if c.idc == 3 {
                w.bit(c.separate_planes);
            }
            w.ue(c.bit_depths.0);
            w.ue(c.bit_depths.1);
            w.bit(c.bypass);
            w.bit(c.scaling.is_some());
            if let Some(lists) = &c.scaling {
                for l in lists {
                    w.bit(l.is_some());
                    if let Some(values) = l {
                        write_scaling_list(&mut w, values);
                    }
                }
            }
        }
        w.ue(self.log2_frame_num_minus4);
        match &self.poc {
            Poc::Zero { log2_lsb_minus4 } => {
                w.ue(0);
                w.ue(*log2_lsb_minus4);
            }
            Poc::One {
                always_zero,
                non_ref,
                top_bottom,
                cycle,
            } => {
                w.ue(1);
                w.bit(*always_zero);
                w.se(*non_ref);
                w.se(*top_bottom);
                w.ue(u32::try_from(cycle.len()).unwrap());
                for &o in cycle {
                    w.se(o);
                }
            }
            Poc::Two => w.ue(2),
        }
        w.ue(self.max_ref);
        w.bit(self.gaps);
        w.ue(self.size_mbs.0);
        w.ue(self.size_mbs.1);
        w.bit(self.interlaced.is_none());
        if let Some(mbaff) = self.interlaced {
            w.bit(mbaff);
        }
        w.bit(self.direct_8x8);
        w.bit(self.crop.is_some());
        if let Some(c) = self.crop {
            for v in c {
                w.ue(v);
            }
        }
        w.bit(self.vui.is_some());
        if let Some(v) = &self.vui {
            write_vui(&mut w, v);
        }
        let bits = w.bit_len();
        w.trailing();
        (w.bytes, bits)
    }

    /// The reorder value the SPS declares, if any.
    pub(crate) fn declared_reorder(&self) -> Option<u32> {
        self.vui
            .as_ref()
            .and_then(|v| v.restriction.as_ref())
            .map(|r| r.reorder)
    }

    pub(crate) fn poc_type(&self) -> u8 {
        match self.poc {
            Poc::Zero { .. } => 0,
            Poc::One { .. } => 1,
            Poc::Two => 2,
        }
    }
}

/// A plain Main profile spec with no VUI, level 4.0, 1280x720 in macroblocks.
pub(crate) fn base_spec(profile: u8) -> SpsSpec {
    SpsSpec {
        profile,
        constraint: 0,
        level: 40,
        id: 0,
        chroma: Chroma {
            idc: 1,
            separate_planes: false,
            bit_depths: (0, 0),
            bypass: false,
            scaling: None,
        },
        log2_frame_num_minus4: 0,
        poc: Poc::Zero { log2_lsb_minus4: 2 },
        max_ref: 1,
        gaps: false,
        size_mbs: (79, 44),
        interlaced: None,
        direct_8x8: true,
        crop: None,
        vui: None,
    }
}

/// A slice NAL unit (type 1, or 5 when `idr`) whose header starts `first_mb_in_slice`,
/// `slice_type`, followed by filler.
pub(crate) fn slice_nal(idr: bool, first_mb: u32, slice_type: u32) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.ue(first_mb);
    w.ue(slice_type);
    w.u(24, 0x00ab_cdef);
    w.trailing();
    let mut nal = vec![if idr { 0x65 } else { 0x41 }];
    nal.extend(escape(&w.bytes));
    nal
}

/// AVCC framing of NAL units.
pub(crate) fn avcc(nals: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in nals {
        out.extend(u32::try_from(n.len()).unwrap().to_be_bytes());
        out.extend(n);
    }
    out
}

fn hrd_strategy() -> impl Strategy<Value = Hrd> {
    (
        prop::collection::vec((0..1_000_000_u32, 0..1_000_000_u32, any::<bool>()), 1..=4),
        (0..16_u8, 0..16_u8),
        prop::array::uniform4(0..32_u8),
    )
        .prop_map(|(cpbs, scales, lens)| Hrd { cpbs, scales, lens })
}

fn vui_strategy() -> impl Strategy<Value = Vui> {
    let a = (
        prop::option::of(prop_oneof![Just(255_u8), 0..=16_u8]),
        prop::option::of(any::<bool>()),
        prop::option::of((0..8_u8, any::<bool>(), prop::option::of(any::<[u8; 3]>()))),
        prop::option::of((0..=5_u32, 0..=5_u32)),
        prop::option::of((any::<u32>(), any::<u32>(), any::<bool>())),
    );
    let b = (
        prop::option::of(hrd_strategy()),
        prop::option::of(hrd_strategy()),
        any::<bool>(),
        any::<bool>(),
        prop::option::of((
            any::<bool>(),
            prop::array::uniform4(0..20_u32),
            0..=16_u32,
            0..=16_u32,
        )),
    );
    (a, b).prop_map(|(a, b)| Vui {
        aspect_idc: a.0,
        overscan: a.1,
        signal: a.2,
        chroma_loc: a.3,
        timing: a.4,
        nal_hrd: b.0,
        vcl_hrd: b.1,
        low_delay: b.2,
        pic_struct: b.3,
        restriction: b.4.map(|(mv, denoms, reorder, dec_buf)| Restriction {
            mv_over_boundaries: mv,
            denoms,
            reorder,
            dec_buf,
        }),
    })
}

fn chroma_strategy() -> impl Strategy<Value = Chroma> {
    let list = |size: usize| {
        prop::option::of(prop::collection::vec(
            prop_oneof![1 => Just(0_u8), 300 => 1..=255_u8],
            size..=size,
        ))
    };
    (
        0..=3_u32,
        any::<bool>(),
        (0..=6_u32, 0..=6_u32),
        any::<bool>(),
        prop::option::of((
            prop::collection::vec(list(16), 6..=6),
            prop::collection::vec(list(64), 6..=6),
        )),
    )
        .prop_map(
            |(idc, separate_planes, bit_depths, bypass, scaling)| Chroma {
                idc,
                separate_planes,
                bit_depths,
                bypass,
                scaling: scaling.map(|(small, big)| {
                    // 8 lists, or 12 for 4:4:4.
                    let take = if idc == 3 { 12 } else { 8 };
                    small.into_iter().chain(big).take(take).collect()
                }),
            },
        )
}

fn poc_strategy() -> impl Strategy<Value = Poc> {
    prop_oneof![
        (0..=12_u32).prop_map(|log2_lsb_minus4| Poc::Zero { log2_lsb_minus4 }),
        (
            any::<bool>(),
            -1000..1000_i32,
            -1000..1000_i32,
            prop::collection::vec(-1000..1000_i32, 0..6),
        )
            .prop_map(|(always_zero, non_ref, top_bottom, cycle)| Poc::One {
                always_zero,
                non_ref,
                top_bottom,
                cycle,
            }),
        Just(Poc::Two),
    ]
}

/// Well-formed SPS specs: every profile family, every POC type, scaling lists, cropping, fields,
/// and a VUI whose every optional part may be present, which is the shape that precedes the
/// bitstream restriction.
pub(crate) fn sps_strategy() -> impl Strategy<Value = SpsSpec> {
    let profile = prop_oneof![
        Just(66_u8),
        Just(77),
        Just(88),
        Just(100),
        Just(110),
        Just(122),
        Just(244),
        Just(44),
        Just(83),
        Just(86),
        Just(118),
        Just(128),
    ];
    (
        (
            profile,
            any::<u8>(),
            any::<u8>(),
            0..=31_u32,
            chroma_strategy(),
        ),
        (0..=12_u32, poc_strategy(), 0..=16_u32, any::<bool>()),
        (
            (0..200_u32, 0..200_u32),
            prop::option::of(any::<bool>()),
            any::<bool>(),
            prop::option::of(prop::array::uniform4(0..100_u32)),
            prop::option::of(vui_strategy()),
        ),
    )
        .prop_map(|(a, b, c)| SpsSpec {
            profile: a.0,
            constraint: a.1,
            level: a.2,
            id: a.3,
            chroma: a.4,
            log2_frame_num_minus4: b.0,
            poc: b.1,
            max_ref: b.2,
            gaps: b.3,
            size_mbs: c.0,
            interlaced: c.1,
            direct_8x8: c.2,
            crop: c.3,
            vui: c.4,
        })
}
