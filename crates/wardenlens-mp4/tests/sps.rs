//! SPS parser tests, including the never-panics property (TEST-3).

#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code: helpers outside #[test] fns on synthetic data; panics are failures"
)]

use proptest::prelude::*;
use wardenlens_mp4::{Mp4Error, parse_sps};

/// Bit writer for building SPS payloads in tests.
#[derive(Default)]
struct W(Vec<bool>);

impl W {
    fn bits(&mut self, v: u32, n: u32) -> &mut Self {
        for i in (0..n).rev() {
            self.0.push((v >> i) & 1 == 1);
        }
        self
    }
    fn ue(&mut self, v: u32) -> &mut Self {
        let x = u64::from(v) + 1;
        let len = 64 - x.leading_zeros();
        for _ in 1..len {
            self.0.push(false);
        }
        for i in (0..len).rev() {
            self.0.push((x >> i) & 1 == 1);
        }
        self
    }
    fn se(&mut self, v: i32) -> &mut Self {
        let k = if v > 0 { 2 * v - 1 } else { -2 * v };
        self.ue(u32::try_from(k).unwrap())
    }
    fn finish(&mut self) -> Vec<u8> {
        self.0.push(true);
        while !self.0.len().is_multiple_of(8) {
            self.0.push(false);
        }
        let mut out = vec![0x67];
        for c in self.0.chunks(8) {
            out.push(c.iter().fold(0u8, |a, b| (a << 1) | u8::from(*b)));
        }
        out
    }
}

struct Spec {
    profile: u8,
    chroma: u32,
    w_mbs: u32,
    h_units: u32,
    frame_mbs_only: bool,
    crop: Option<[u32; 4]>,
}

fn build(s: &Spec) -> Vec<u8> {
    let mut w = W::default();
    w.bits(u32::from(s.profile), 8).bits(0, 8).bits(30, 8).ue(0);
    if s.profile >= 100 {
        w.ue(s.chroma);
        if s.chroma == 3 {
            w.bits(0, 1);
        }
        w.ue(0).ue(0).bits(0, 1).bits(0, 1);
    }
    w.ue(0).ue(0).ue(0).ue(4).bits(0, 1); // log2_max_frame_num, poc type 0, poc lsb, ref frames, gaps
    w.ue(s.w_mbs - 1).ue(s.h_units - 1);
    w.bits(u32::from(s.frame_mbs_only), 1);
    if !s.frame_mbs_only {
        w.bits(0, 1);
    }
    w.bits(1, 1);
    match s.crop {
        Some(c) => {
            w.bits(1, 1);
            for v in c {
                w.ue(v);
            }
        }
        None => {
            w.bits(0, 1);
        }
    }
    w.finish()
}

fn base() -> Spec {
    Spec {
        profile: 66,
        chroma: 1,
        w_mbs: 40,
        h_units: 30,
        frame_mbs_only: true,
        crop: None,
    }
}

#[test]
fn parses_uncropped_baseline() {
    let i = parse_sps(&build(&base())).unwrap();
    assert_eq!((i.width, i.height), (640, 480));
    assert_eq!((i.profile_idc, i.level_idc), (66, 30));
    assert_eq!((i.chroma_format_idc, i.bit_depth_luma), (1, 8));
}

#[test]
fn applies_cropping_for_1080p() {
    let s = Spec {
        profile: 100,
        w_mbs: 120,
        h_units: 68,
        crop: Some([0, 0, 0, 4]),
        ..base()
    };
    let i = parse_sps(&build(&s)).unwrap();
    assert_eq!((i.width, i.height), (1920, 1080));
}

#[test]
fn interlaced_stream_doubles_height_and_crop_unit() {
    let s = Spec {
        frame_mbs_only: false,
        h_units: 34,
        crop: Some([0, 0, 0, 2]),
        ..base()
    };
    // 34 * 16 * 2 = 1088 rows, crop 2 * (2 * 2) = 8 -> 1080.
    assert_eq!(parse_sps(&build(&s)).unwrap().height, 1080);
}

#[test]
fn crop_units_follow_chroma_format() {
    let s = Spec {
        profile: 244,
        chroma: 3,
        crop: Some([1, 1, 1, 1]),
        ..base()
    };
    let i = parse_sps(&build(&s)).unwrap();
    assert_eq!((i.width, i.height), (638, 478));
    let s = Spec {
        profile: 100,
        chroma: 0,
        crop: Some([1, 1, 1, 1]),
        ..base()
    };
    let i = parse_sps(&build(&s)).unwrap();
    assert_eq!((i.width, i.height), (638, 478));
    let s = Spec {
        profile: 122,
        chroma: 2,
        crop: Some([1, 1, 1, 1]),
        ..base()
    };
    let i = parse_sps(&build(&s)).unwrap();
    assert_eq!((i.width, i.height), (636, 478));
}

#[test]
fn skips_scaling_lists() {
    let mut w = W::default();
    w.bits(100, 8)
        .bits(0, 8)
        .bits(40, 8)
        .ue(0)
        .ue(1)
        .ue(0)
        .ue(0)
        .bits(0, 1);
    w.bits(1, 1); // seq_scaling_matrix_present
    for i in 0..8 {
        if i == 0 {
            // a list that ends early: delta_scale -8 gives nextScale 0
            w.bits(1, 1).se(-8);
        } else {
            w.bits(0, 1);
        }
    }
    w.ue(0)
        .ue(0)
        .ue(0)
        .ue(1)
        .bits(0, 1)
        .ue(19)
        .ue(14)
        .bits(1, 1)
        .bits(1, 1)
        .bits(0, 1);
    let i = parse_sps(&w.finish()).unwrap();
    assert_eq!((i.width, i.height), (320, 240));
}

#[test]
fn rejects_crop_that_removes_the_whole_picture() {
    let s = Spec {
        w_mbs: 1,
        crop: Some([4, 4, 0, 0]),
        ..base()
    };
    assert!(matches!(
        parse_sps(&build(&s)),
        Err(Mp4Error::SpsInvalid(_))
    ));
}

#[test]
fn rejects_dimensions_beyond_16_bits() {
    let s = Spec {
        w_mbs: 4097,
        ..base()
    };
    assert!(matches!(
        parse_sps(&build(&s)),
        Err(Mp4Error::SpsInvalid(_))
    ));
    let s = Spec {
        w_mbs: 4095,
        ..base()
    };
    assert_eq!(parse_sps(&build(&s)).unwrap().width, 65_520);
}

#[test]
fn rejects_wrong_nal_type_empty_and_oversized() {
    assert!(matches!(parse_sps(&[]), Err(Mp4Error::SpsLength { .. })));
    assert!(matches!(
        parse_sps(&[0x68, 1, 2, 3]),
        Err(Mp4Error::NotAnSps)
    ));
    assert!(matches!(
        parse_sps(&[0xe7, 1, 2, 3]),
        Err(Mp4Error::NotAnSps)
    ));
    assert!(matches!(
        parse_sps(&vec![0x67; 1025]),
        Err(Mp4Error::SpsLength { .. })
    ));
}

#[test]
fn rejects_truncated_sps_at_every_length() {
    let full = build(&Spec {
        crop: Some([0, 0, 0, 4]),
        ..base()
    });
    for n in 1..full.len() - 1 {
        assert!(parse_sps(&full[..n]).is_err(), "prefix of {n} bytes parsed");
    }
}

#[test]
fn rejects_overlong_exp_golomb_code() {
    let sps = [0x67, 66, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0x80];
    assert!(parse_sps(&sps).is_err());
}

proptest! {
    #[test]
    fn never_panics_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..1100)) {
        let _ = parse_sps(&data);
    }

    #[test]
    fn never_panics_on_sps_shaped_bytes(
        profile in prop_oneof![Just(66u8), Just(100u8), Just(244u8), any::<u8>()],
        tail in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut v = vec![0x67, profile];
        v.extend(tail);
        let _ = parse_sps(&v);
    }

    #[test]
    fn built_sps_round_trips_dimensions(w in 1u32..200, h in 1u32..200, only in any::<bool>()) {
        let s = Spec { w_mbs: w, h_units: h, frame_mbs_only: only, ..base() };
        let i = parse_sps(&build(&s)).unwrap();
        prop_assert_eq!(u32::from(i.width), w * 16);
        prop_assert_eq!(u32::from(i.height), h * 16 * if only { 1 } else { 2 });
    }
}
