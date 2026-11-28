//! Round-1 adversarial tests for #241 (PR #248): the h264-reader oracle and `parse_sps` must
//! disagree on no `profile_idc` except the withdrawn 144, over the whole `u8` profile space.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "test bit writer; a panic fails the test"
)]

use h264_reader::nal::sps::{PicOrderCntType, SeqParameterSet};
use h264_reader::rbsp::{BitReader, ByteReader};
use wardenlens_core::video::is_high_family;
use wardenlens_ingest::parse_sps;

#[derive(Default)]
struct W {
    bits: Vec<bool>,
}

impl W {
    fn u(&mut self, n: u32, v: u64) {
        for i in (0..n).rev() {
            self.bits.push((v >> i) & 1 == 1);
        }
    }
    fn bit(&mut self, b: bool) {
        self.bits.push(b);
    }
    fn ue(&mut self, v: u32) {
        let x = u64::from(v) + 1;
        let len = 64 - x.leading_zeros();
        self.u(len - 1, 0);
        self.u(len, x);
    }
    fn nal(mut self) -> Vec<u8> {
        self.bits.push(true);
        while !self.bits.len().is_multiple_of(8) {
            self.bits.push(false);
        }
        let rbsp: Vec<u8> = self
            .bits
            .chunks(8)
            .map(|c| c.iter().fold(0_u8, |a, &b| (a << 1) | u8::from(b)))
            .collect();
        let mut nal = vec![0x67];
        let mut zeros = 0;
        for b in rbsp {
            if zeros >= 2 && b <= 3 {
                nal.push(3);
                zeros = 0;
            }
            nal.push(b);
            zeros = if b == 0 { zeros + 1 } else { 0 };
        }
        nal
    }
}

#[derive(Clone, Copy)]
struct Case {
    chroma_idc: u32,
    depths: (u32, u32),
    poc: u32,
    reorder: Option<u32>,
}

/// An SPS for `profile`, with the High syntax exactly when the shared table says so.
fn sps(profile: u8, c: Case) -> Vec<u8> {
    let mut w = W::default();
    w.u(8, u64::from(profile));
    w.u(8, 0);
    w.u(8, 40);
    w.ue(0);
    if is_high_family(profile) {
        w.ue(c.chroma_idc);
        if c.chroma_idc == 3 {
            w.bit(false);
        }
        w.ue(c.depths.0);
        w.ue(c.depths.1);
        w.bit(false);
        w.bit(false);
    }
    w.ue(0); // log2_max_frame_num_minus4
    w.ue(c.poc);
    if c.poc == 0 {
        w.ue(2);
    } else if c.poc == 1 {
        w.bit(false);
        w.ue(0); // se 0
        w.ue(0);
        w.ue(0);
    }
    w.ue(1); // max_num_ref_frames
    w.bit(false);
    w.ue(79);
    w.ue(44);
    w.bit(true); // frame_mbs_only
    w.bit(true);
    w.bit(false); // no cropping
    match c.reorder {
        None => w.bit(false),
        Some(r) => {
            w.bit(true); // vui
            for _ in 0..5 {
                w.bit(false); // aspect, overscan, signal, chroma loc, timing
            }
            w.bit(false); // nal hrd
            w.bit(false); // vcl hrd
            w.bit(false); // pic_struct
            w.bit(true); // bitstream_restriction
            w.bit(true);
            w.ue(2);
            w.ue(1);
            w.ue(16);
            w.ue(16);
            w.ue(r);
            w.ue(r.max(1));
        }
    }
    w.nal()
}

fn oracle(nal: &[u8]) -> Option<(u8, Option<u32>)> {
    let s =
        SeqParameterSet::from_bits(BitReader::new(ByteReader::skipping_h264_header(nal))).ok()?;
    let poc = match s.pic_order_cnt {
        PicOrderCntType::TypeZero { .. } => 0,
        PicOrderCntType::TypeOne { .. } => 1,
        PicOrderCntType::TypeTwo => 2,
    };
    let reorder = s
        .vui_parameters
        .and_then(|v| v.bitstream_restrictions)
        .map(|b| b.max_num_reorder_frames);
    Some((poc, reorder))
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for chroma_idc in 0..=3 {
        for depths in [(0, 0), (1, 0), (0, 1), (2, 3), (6, 6)] {
            for poc in 0..=2 {
                for reorder in [None, Some(0), Some(2)] {
                    out.push(Case {
                        chroma_idc,
                        depths,
                        poc,
                        reorder,
                    });
                }
            }
        }
    }
    out
}

#[test]
fn parser_reads_written_fields_for_every_profile_value() {
    for p in 0..=u8::MAX {
        for c in cases() {
            let got = parse_sps(&sps(p, c)).unwrap();
            assert_eq!(got.profile_idc, p);
            assert_eq!(u32::from(got.pic_order_cnt_type), c.poc, "profile {p}");
            assert_eq!(got.max_num_reorder_frames, c.reorder, "profile {p}");
        }
    }
}

#[test]
fn oracle_disagrees_with_parser_only_on_profile_144() {
    let mut disagree = Vec::new();
    let mut rejected_all = Vec::new();
    for p in 0..=u8::MAX {
        let mut accepted = 0;
        let mut bad = false;
        for c in cases() {
            let nal = sps(p, c);
            let ours = parse_sps(&nal).unwrap();
            if let Some(theirs) = oracle(&nal) {
                accepted += 1;
                if theirs != (ours.pic_order_cnt_type, ours.max_num_reorder_frames) {
                    bad = true;
                }
            }
        }
        if bad {
            disagree.push(p);
        }
        if accepted == 0 {
            rejected_all.push(p);
        }
    }
    assert_eq!(disagree, [144], "profiles the oracle misreads");
    assert!(
        rejected_all.is_empty(),
        "oracle rejects every case for {rejected_all:?}"
    );
}
