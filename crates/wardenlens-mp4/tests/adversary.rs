//! Adversarial tests for the fMP4 writer (PR #98, ticket #54): real-encoder SPSs as an oracle,
//! hostile SPS / Annex-B / sample input, the u32 `mdat` boundary and decode checks per pixel format.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::print_stderr,
    clippy::too_many_lines,
    reason = "test code: helpers outside #[test] fns on synthetic data; panics are failures"
)]

use std::path::Path;
use std::process::Command;

use proptest::prelude::*;
use wardenlens_core::mp4box::{SliceSource, parse_header, summarize};
use wardenlens_mp4::{
    Fragment, H264Params, MAX_SAMPLE_LEN, Mp4Error, Sample, annexb_to_avcc, init_segment, parse_sps,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// (name, SPS hex, PPS hex, width, height, `profile_idc`, `chroma_format_idc`, luma depth) as
/// produced by libx264 (ffmpeg 8.0.1) and reported by ffprobe for the same stream.
type SpsCase = (
    &'static str,
    &'static str,
    &'static str,
    u16,
    u16,
    u8,
    u8,
    u8,
);

const REAL_SPS: &[SpsCase] = &[
    (
        "baseline 176x144",
        "6742c00bd902c4ec0440000003004000000c83c50a92",
        "68cb83cb20",
        176,
        144,
        66,
        1,
        8,
    ),
    (
        "baseline 4096x2304",
        "6742c033da004000486c0440000003004000000c83c60ca8",
        "68ce0fc8",
        4096,
        2304,
        66,
        1,
        8,
    ),
    (
        "main 322x182 (crop)",
        "674d400deca0a8cf11360220000003002000000641e28532c0",
        "68ebe3cb20",
        322,
        182,
        77,
        1,
        8,
    ),
    (
        "high 1920x1080",
        "67640028acd940780227e5c044000003000400000300c83c60c658",
        "68ebe3cb22c0",
        1920,
        1080,
        100,
        1,
        8,
    ),
    (
        "high scaling lists",
        "6764000dacd941519e226c0440000003004000000c83c50a6580",
        "68ebe3cb3002c0",
        322,
        182,
        100,
        1,
        8,
    ),
    (
        "high monochrome",
        "6764000df365054678f8bc05b2000003000200000300641e28532c",
        "68ebe3cb22c0",
        322,
        182,
        100,
        0,
        8,
    ),
    (
        "high10",
        "676e000da6cd941519e226c044000003000400000300c83c50a658",
        "68ebe3cb22c0",
        322,
        182,
        110,
        1,
        10,
    ),
    (
        "high422",
        "677a000dbcd941519e222f011000000300100000030320f1429960",
        "68ebe3cb22c0",
        322,
        182,
        122,
        2,
        8,
    ),
    (
        "high422 10-bit interlaced scaling",
        "677a0015b6cd941533c44d808800000300080000030190f8a14cb0",
        "68fba3cb3002c0",
        322,
        182,
        122,
        2,
        10,
    ),
    (
        "high444",
        "67f4000c919b282833f1b808800000030080000019078a14cb",
        "68ebe3c44844",
        320,
        180,
        244,
        3,
        8,
    ),
    (
        "high444 scaling (12 lists)",
        "67f4000c919b282833f1b808800000030080000019078a14cb",
        "68ebe3c44c000440",
        320,
        180,
        244,
        3,
        8,
    ),
    (
        "high444 2x2",
        "67f4000a919b2bf1f1f808800000030080000019078912cb",
        "68ebe3c44844",
        2,
        2,
        244,
        3,
        8,
    ),
    (
        "high interlaced 1920x1080",
        "67640028acd94078044fde0220000003002000000643e2c5b2c0",
        "68fba3cb22c0",
        1920,
        1080,
        100,
        1,
        8,
    ),
    (
        "high interlaced 322x180",
        "67640015acd941533c4498088000000300800000190f8a14cb",
        "68fba3cb22c0",
        322,
        180,
        100,
        1,
        8,
    ),
];

#[test]
fn real_encoder_sps_parse_matches_ffprobe() {
    for &(name, sps, pps, w, h, profile, chroma, depth) in REAL_SPS {
        let sps = hex(sps);
        let info = parse_sps(&sps).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((info.width, info.height), (w, h), "{name}: dimensions");
        assert_eq!(info.profile_idc, profile, "{name}: profile");
        assert_eq!(info.chroma_format_idc, chroma, "{name}: chroma");
        assert_eq!(info.bit_depth_luma, depth, "{name}: luma depth");
        assert_eq!(info.bit_depth_chroma, depth, "{name}: chroma depth");
        let params = H264Params::new(&sps, &hex(pps)).unwrap();
        let init = init_segment(&params).unwrap();
        // The whole init segment must be walkable.
        walk(init.bytes());
    }
}

/// Walk all boxes recursively, checking every size tiles its parent exactly.
fn walk(buf: &[u8]) {
    const CONTAINERS: [&[u8; 4]; 7] = [
        b"moov", b"trak", b"mdia", b"minf", b"stbl", b"mvex", b"dinf",
    ];
    let mut at = 0usize;
    while at < buf.len() {
        let rest = &buf[at..];
        let h = parse_header(rest, rest.len() as u64).unwrap();
        let size = usize::try_from(h.size()).unwrap();
        assert!(size >= 8 && size <= rest.len());
        if CONTAINERS.contains(&&h.fourcc()) {
            walk(&rest[8..size]);
        }
        at += size;
    }
    assert_eq!(at, buf.len());
}

fn find<'a>(buf: &'a [u8], path: &[&[u8; 4]]) -> &'a [u8] {
    let mut cur = buf;
    for (depth, want) in path.iter().enumerate() {
        let mut at = 0usize;
        loop {
            let rest = &cur[at..];
            let h = parse_header(rest, rest.len() as u64).unwrap();
            let size = usize::try_from(h.size()).unwrap();
            if h.fourcc() == **want {
                cur = &rest[8..size];
                break;
            }
            at += size;
            assert!(at < cur.len(), "box {depth} not found");
        }
    }
    cur
}

#[test]
fn avcc_high_extension_carries_422_10bit_fields() {
    let (_, sps, pps, ..) = REAL_SPS[8];
    let params = H264Params::new(&hex(sps), &hex(pps)).unwrap();
    let init = init_segment(&params).unwrap();
    let stsd = find(
        init.bytes(),
        &[b"moov", b"trak", b"mdia", b"minf", b"stbl", b"stsd"],
    );
    // stsd: version/flags + entry_count, then the avc1 box.
    let avc1 = &stsd[8..];
    let avcc_box = find(&avc1[8 + 78..], &[b"avcC"]);
    let sps_len = hex(sps).len();
    let pps_len = hex(pps).len();
    assert_eq!(avcc_box.len(), 6 + 2 + sps_len + 1 + 2 + pps_len + 4);
    assert_eq!(&avcc_box[..6], &[1, 122, 0x00, 0x15, 0xff, 0xe1]);
    let ext = &avcc_box[avcc_box.len() - 4..];
    assert_eq!(ext, &[0xfc | 2, 0xf8 | 2, 0xf8 | 2, 0]);
}

/// Profile 144 (the withdrawn High 4:4:4) carries `chroma_format_idc` and bit depths in its SPS
/// (ffmpeg and the JM decoder both read them). The writer emits the avcC High extension for 144,
/// so the parser must read those fields too, or the dimensions and the extension are wrong.
#[test]
#[ignore = "follow-up #100"]
fn profile_144_sps_reads_the_chroma_fields() {
    // profile 144, constraint 0, level 30, sps_id 0, chroma_format_idc 3, separate_planes 0,
    // bit depths 0/0, qpprime 0, no scaling, log2_max_frame_num 0, poc type 0, poc lsb 0,
    // ref frames 1, gaps 0, 40x30 MBs, frame_mbs_only 1, direct8x8 1, no crop, no vui.
    let mut bits: Vec<bool> = Vec::new();
    let mut put = |v: u32, n: u32| {
        for i in (0..n).rev() {
            bits.push((v >> i) & 1 == 1);
        }
    };
    let ue = |v: u32| -> (u32, u32) {
        let x = v + 1;
        let len = 32 - x.leading_zeros();
        (x, 2 * len - 1)
    };
    put(144, 8);
    put(0, 8);
    put(30, 8);
    for (v, extra) in [(0u32, None), (3, Some((0u32, 1u32)))] {
        let (x, n) = ue(v);
        put(x, n);
        if let Some((b, m)) = extra {
            put(b, m);
        }
    }
    for v in [0u32, 0] {
        let (x, n) = ue(v);
        put(x, n);
    }
    put(0, 1);
    put(0, 1);
    for v in [0u32, 0, 0, 1] {
        let (x, n) = ue(v);
        put(x, n);
    }
    put(0, 1);
    for v in [39u32, 29] {
        let (x, n) = ue(v);
        put(x, n);
    }
    put(1, 1);
    put(1, 1);
    put(0, 1);
    put(0, 1);
    put(1, 1);
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }
    let mut sps = vec![0x67];
    for c in bits.chunks(8) {
        sps.push(c.iter().fold(0u8, |a, b| (a << 1) | u8::from(*b)));
    }
    let info = parse_sps(&sps).unwrap();
    assert_eq!(info.chroma_format_idc, 3);
    assert_eq!((info.width, info.height), (640, 480));
}

/// `mdat` size is total + 8; exactly `u32::MAX` must be accepted, one more byte rejected.
/// The samples all borrow one 8 MiB buffer and the output goes to `io::sink`.
#[test]
fn mdat_size_boundary_at_u32_max() {
    let mut big = vec![0x41u8; MAX_SAMPLE_LEN];
    big[..4].copy_from_slice(&u32::try_from(MAX_SAMPLE_LEN - 4).unwrap().to_be_bytes());
    let full = u64::from(u32::MAX) - 8;
    let n_big = usize::try_from(full / MAX_SAMPLE_LEN as u64).unwrap();
    let rem = usize::try_from(full % MAX_SAMPLE_LEN as u64).unwrap();
    let mut last = vec![0x41u8; rem];
    last[..4].copy_from_slice(&u32::try_from(rem - 4).unwrap().to_be_bytes());
    let mut samples: Vec<Sample<'_>> = (0..n_big)
        .map(|_| Sample {
            data: &big,
            duration: 1,
            is_sync: false,
        })
        .collect();
    samples.push(Sample {
        data: &last,
        duration: 1,
        is_sync: false,
    });
    Fragment::write(1, 0, &samples, &mut std::io::sink()).unwrap();

    let mut last1 = vec![0x41u8; rem + 1];
    last1[..4].copy_from_slice(&u32::try_from(rem - 3).unwrap().to_be_bytes());
    *samples.last_mut().unwrap() = Sample {
        data: &last1,
        duration: 1,
        is_sync: false,
    };
    let mut out = Vec::new();
    assert!(matches!(
        Fragment::write(1, 0, &samples, &mut out),
        Err(Mp4Error::BoxTooLarge)
    ));
    assert!(out.is_empty(), "bytes written before the size error");
}

#[test]
fn rejects_invalid_avcc_in_a_later_sample_without_writing() {
    let good = [0, 0, 0, 2, 0x65, 1];
    let bad_cases: [&[u8]; 5] = [
        &[0, 0, 0, 3, 0x41, 1],          // prefix overruns
        &[0, 0, 0, 1, 0x41, 9],          // trailing garbage shorter than a prefix
        &[0, 0, 0, 0],                   // zero-length NAL
        &[0xff, 0xff, 0xff, 0xff, 0x41], // huge prefix
        &[0, 0, 1],                      // shorter than a prefix
    ];
    for bad in bad_cases {
        let samples = [
            Sample {
                data: &good,
                duration: 1,
                is_sync: true,
            },
            Sample {
                data: bad,
                duration: 1,
                is_sync: false,
            },
        ];
        let mut out = Vec::new();
        assert!(
            matches!(
                Fragment::write(1, 0, &samples, &mut out),
                Err(Mp4Error::InvalidAvcc)
            ),
            "{bad:?}"
        );
        assert_eq!(out, Vec::<u8>::new());
    }
}

#[test]
fn annexb_edge_cases() {
    // Start code at the very end: nothing after it.
    assert_eq!(
        annexb_to_avcc(&[0, 0, 1, 0x41, 7, 0, 0, 1]).unwrap(),
        [0, 0, 0, 2, 0x41, 7]
    );
    // Many leading zeros before the first start code.
    assert_eq!(
        annexb_to_avcc(&[0, 0, 0, 0, 0, 0, 1, 0x65, 1]).unwrap(),
        [0, 0, 0, 2, 0x65, 1]
    );
    // Back-to-back start codes and long zero runs between NALs.
    assert_eq!(
        annexb_to_avcc(&[0, 0, 1, 0, 0, 1, 0x09, 0xf0, 0, 0, 0, 0, 0, 0, 1, 0x41, 2]).unwrap(),
        [0, 0, 0, 2, 0x09, 0xf0, 0, 0, 0, 2, 0x41, 2]
    );
    // Only zero bytes, or only a bare 2-byte prefix.
    assert!(matches!(
        annexb_to_avcc(&[0, 0, 0, 0]),
        Err(Mp4Error::NoStartCode)
    ));
    assert!(matches!(
        annexb_to_avcc(&[0, 0]),
        Err(Mp4Error::NoStartCode)
    ));
    // SPS/PPS with nal_ref_idc 0 are still dropped.
    assert_eq!(
        annexb_to_avcc(&[0, 0, 1, 0x07, 1, 0, 0, 1, 0x08, 2, 0, 0, 1, 0x01, 3]).unwrap(),
        [0, 0, 0, 2, 0x01, 3]
    );
}

/// Output growth: an input at the limit made only of 3-byte start codes grows by a third.
#[test]
fn annexb_output_growth_is_bounded_by_the_limit() {
    let mut data = Vec::with_capacity(MAX_SAMPLE_LEN);
    while data.len() + 4 <= MAX_SAMPLE_LEN {
        data.extend_from_slice(&[0, 0, 1, 0x41]);
    }
    assert!(matches!(
        annexb_to_avcc(&data),
        Err(Mp4Error::SampleTooLarge { .. })
    ));
}

/// A NAL body that cannot contain a start code and does not end with a zero byte.
fn nal_strategy() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0x65u8),
            Just(0x41u8),
            Just(0x06u8),
            Just(0x09u8),
            Just(0x01u8)
        ],
        proptest::collection::vec(any::<u8>(), 0..40),
    )
        .prop_map(|(h, body)| {
            let mut nal = vec![h];
            let mut zeros = 0;
            for b in body {
                if zeros >= 2 && b <= 3 {
                    nal.push(3);
                    zeros = 0;
                }
                zeros = if b == 0 { zeros + 1 } else { 0 };
                nal.push(b);
            }
            if *nal.last().unwrap() == 0 {
                nal.push(0x80);
            }
            nal
        })
}

proptest! {
    #[test]
    fn annexb_round_trips_nal_lists(
        nals in proptest::collection::vec(nal_strategy(), 1..8),
        four in proptest::collection::vec(any::<bool>(), 8),
        trailing in proptest::collection::vec(0usize..4, 8),
    ) {
        let mut annexb = Vec::new();
        let mut expected = Vec::new();
        for (i, nal) in nals.iter().enumerate() {
            if four[i] { annexb.push(0); }
            annexb.extend_from_slice(&[0, 0, 1]);
            annexb.extend_from_slice(nal);
            annexb.extend(std::iter::repeat_n(0u8, trailing[i]));
            expected.extend_from_slice(&u32::try_from(nal.len()).unwrap().to_be_bytes());
            expected.extend_from_slice(nal);
        }
        prop_assert_eq!(annexb_to_avcc(&annexb).unwrap(), expected);
    }

    #[test]
    fn annexb_never_panics_and_output_is_valid_avcc(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(avcc) = annexb_to_avcc(&data)
            && !avcc.is_empty()
        {
            let s = [Sample { data: &avcc, duration: 1, is_sync: true }];
            Fragment::write(1, 0, &s, &mut Vec::new()).unwrap();
        }
    }

    #[test]
    fn annexb_never_panics_on_start_code_heavy_input(
        data in proptest::collection::vec(prop_oneof![Just(0u8), Just(1u8), Just(3u8), Just(7u8), Just(8u8), any::<u8>()], 0..256)
    ) {
        let _ = annexb_to_avcc(&data);
    }

    #[test]
    fn fragment_data_offset_points_at_first_sample(
        sizes in proptest::collection::vec(1usize..64, 1..40),
        base in any::<u64>(),
        seq in any::<u32>(),
    ) {
        let datas: Vec<Vec<u8>> = sizes.iter().enumerate().map(|(i, n)| {
            let mut v = u32::try_from(*n).unwrap().to_be_bytes().to_vec();
            v.extend(std::iter::repeat_n(u8::try_from(i % 250 + 1).unwrap(), *n));
            v
        }).collect();
        let samples: Vec<Sample<'_>> = datas.iter().enumerate()
            .map(|(i, d)| Sample { data: d, duration: 3600, is_sync: i == 0 }).collect();
        let mut out = Vec::new();
        Fragment::write(seq, base, &samples, &mut out).unwrap();
        let moof = parse_header(&out, out.len() as u64).unwrap();
        let moof_len = usize::try_from(moof.size()).unwrap();
        let mdat = parse_header(&out[moof_len..], (out.len() - moof_len) as u64).unwrap();
        prop_assert_eq!(&mdat.fourcc(), b"mdat");
        prop_assert_eq!(moof_len + usize::try_from(mdat.size()).unwrap(), out.len());
        let trun = find(&out, &[b"moof", b"traf", b"trun"]);
        prop_assert_eq!(&trun[..4], &[0, 0, 7, 1]);
        prop_assert_eq!(u32::from_be_bytes(trun[4..8].try_into().unwrap()) as usize, samples.len());
        let off = usize::try_from(u32::from_be_bytes(trun[8..12].try_into().unwrap())).unwrap();
        prop_assert_eq!(&out[off..off + datas[0].len()], &datas[0][..]);
        let tfdt = find(&out, &[b"moof", b"traf", b"tfdt"]);
        prop_assert_eq!(&tfdt[..4], &[1, 0, 0, 0]);
        prop_assert_eq!(u64::from_be_bytes(tfdt[4..12].try_into().unwrap()), base);
        let mfhd = find(&out, &[b"moof", b"mfhd"]);
        prop_assert_eq!(u32::from_be_bytes(mfhd[4..8].try_into().unwrap()), seq);
        let mut file = init_segment(&H264Params::new(&hex(REAL_SPS[0].1), &hex(REAL_SPS[0].2)).unwrap()).unwrap().bytes().to_vec();
        file.extend_from_slice(&out);
        let summary = summarize(&mut SliceSource(&file)).unwrap();
        prop_assert_eq!(summary.frame_count, samples.len() as u64);
    }

    #[test]
    fn params_never_panic_on_hostile_pps(pps in proptest::collection::vec(any::<u8>(), 0..1100)) {
        let sps = hex(REAL_SPS[0].1);
        match H264Params::new(&sps, &pps) {
            Ok(p) => {
                prop_assert!(!pps.is_empty() && pps.len() <= 1024 && pps[0] & 0x1f == 8 && pps[0] & 0x80 == 0);
                init_segment(&p).unwrap();
            }
            Err(e) => {
                let ok = matches!(e, Mp4Error::PpsLength { .. } | Mp4Error::NotAPps);
                prop_assert!(ok);
            }
        }
    }

    #[test]
    fn sps_with_emulation_bytes_inserted_anywhere_never_panics(
        idx in 0usize..14,
        junk in proptest::collection::vec(any::<u8>(), 0..32),
        cut in 1usize..80,
    ) {
        let mut sps = hex(REAL_SPS[idx].1);
        let at = cut.min(sps.len());
        sps.splice(at..at, junk);
        if let Ok(info) = parse_sps(&sps) {
            prop_assert!(info.width > 0 && info.height > 0);
            prop_assert!(info.chroma_format_idc <= 3);
            prop_assert!((8..=14).contains(&info.bit_depth_luma));
        }
    }
}

// ---------------------------------------------------------------------------------------
// Decode checks for more pixel formats than the shipped fixture (ignored; needs ffmpeg).

fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("-version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn nal_units(data: &[u8]) -> Vec<&[u8]> {
    let starts: Vec<usize> = data
        .windows(3)
        .enumerate()
        .filter(|(_, w)| *w == [0, 0, 1])
        .map(|(i, _)| i + 3)
        .collect();
    let mut out = Vec::new();
    for (k, &s) in starts.iter().enumerate() {
        let mut end = starts.get(k + 1).map_or(data.len(), |n| n - 3);
        while end > s && data[end - 1] == 0 {
            end -= 1;
        }
        out.push(&data[s..end]);
    }
    out
}

/// Access units for single-slice streams: a new AU starts at AUD/SEI/SPS/PPS or a slice with
/// `first_mb_in_slice == 0` once the current AU holds a slice.
fn access_units(nals: &[&[u8]]) -> Vec<(Vec<u8>, bool)> {
    let mut aus: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut has_slice = false;
    for nal in nals {
        let ty = nal[0] & 0x1f;
        let is_slice = matches!(ty, 1 | 5);
        let starts_au = matches!(ty, 6..=9) || (is_slice && nal[1] & 0x80 != 0);
        if (starts_au && has_slice) || aus.is_empty() {
            has_slice = false;
            aus.push((Vec::new(), false));
        }
        has_slice |= is_slice;
        let au = aus.last_mut().unwrap();
        au.0.extend_from_slice(&[0, 0, 0, 1]);
        au.0.extend_from_slice(nal);
        au.1 |= ty == 5;
    }
    aus
}

fn framemd5(path: &Path) -> String {
    let out = Command::new("ffmpeg")
        .args(["-v", "error", "-xerror", "-i"])
        .arg(path)
        .args(["-f", "framemd5", "-"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ffmpeg failed on {}: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut acc, l| {
            let f: Vec<_> = l.split(',').map(str::trim).collect();
            acc.push_str(f[f.len() - 2]);
            acc.push(',');
            acc.push_str(f[f.len() - 1]);
            acc.push('\n');
            acc
        })
}

#[test]
#[ignore = "needs ffmpeg with libx264; run with --ignored"]
fn every_pixel_format_and_scan_mode_decodes_identically() {
    if !tool_available("ffmpeg") || !tool_available("ffprobe") {
        eprintln!("ffmpeg/ffprobe not found: skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cases: &[(&str, &str, &[&str])] = &[
        ("baseline", "176x144", &["-profile:v", "baseline"]),
        ("main_crop", "322x182", &["-profile:v", "main"]),
        ("high_cqm", "322x182", &["-x264opts", "cqm=jvt"]),
        ("gray", "322x182", &["-pix_fmt", "gray"]),
        ("hi10", "322x182", &["-pix_fmt", "yuv420p10le"]),
        ("hi422", "322x182", &["-pix_fmt", "yuv422p"]),
        (
            "hi422_10_intl",
            "322x182",
            &[
                "-pix_fmt",
                "yuv422p10le",
                "-x264opts",
                "interlaced=1:cqm=jvt",
            ],
        ),
        ("hi444", "320x180", &["-pix_fmt", "yuv444p"]),
        (
            "hi444_cqm",
            "320x180",
            &["-pix_fmt", "yuv444p", "-x264opts", "cqm=jvt"],
        ),
        ("intl", "322x180", &["-x264opts", "interlaced=1"]),
        ("multislice", "320x240", &["-x264opts", "slices=4"]),
    ];
    for (name, size, extra) in cases {
        let src = dir.path().join(format!("{name}.h264"));
        let st = Command::new("ffmpeg")
            .args(["-v", "error", "-y", "-f", "lavfi", "-i"])
            .arg(format!("testsrc2=size={size}:rate=25"))
            .args([
                "-t",
                "1",
                "-c:v",
                "libx264",
                "-bf",
                "0",
                "-g",
                "10",
                "-sc_threshold",
                "0",
            ])
            .args(*extra)
            .args(["-f", "h264"])
            .arg(&src)
            .status()
            .unwrap();
        assert!(st.success(), "{name}: ffmpeg encode failed");
        let source = std::fs::read(&src).unwrap();
        let nals = nal_units(&source);
        let sps = nals.iter().find(|n| n[0] & 0x1f == 7).unwrap();
        let pps = nals.iter().find(|n| n[0] & 0x1f == 8).unwrap();
        let params = H264Params::new(sps, pps).unwrap_or_else(|e| panic!("{name}: {e}"));
        let aus: Vec<(Vec<u8>, bool)> = access_units(&nals)
            .into_iter()
            .map(|(au, k)| (annexb_to_avcc(&au).unwrap(), k))
            .collect();
        let init = init_segment(&params).unwrap();
        let mut file = init.bytes().to_vec();
        let (mut seq, mut start) = (1u32, 0usize);
        while start < aus.len() {
            let end = (start + 1..aus.len())
                .find(|i| aus[*i].1)
                .unwrap_or(aus.len());
            let group: Vec<Sample<'_>> = aus[start..end]
                .iter()
                .map(|(d, k)| Sample {
                    data: d,
                    duration: 3600,
                    is_sync: *k,
                })
                .collect();
            Fragment::write(seq, start as u64 * 3600, &group, &mut file).unwrap();
            seq += 1;
            start = end;
        }
        let mp4 = dir.path().join(format!("{name}.mp4"));
        std::fs::write(&mp4, &file).unwrap();
        let probe = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=width,height",
                "-of",
                "csv=p=0",
            ])
            .arg(&mp4)
            .output()
            .unwrap();
        let src_probe = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=width,height",
                "-of",
                "csv=p=0",
            ])
            .arg(&src)
            .output()
            .unwrap();
        assert_eq!(probe.stdout, src_probe.stdout, "{name}: dimensions");
        assert_eq!(
            format!("{},{}\n", params.width(), params.height()).as_bytes(),
            &src_probe.stdout[..],
            "{name}: parsed SPS dimensions"
        );
        assert_eq!(framemd5(&mp4), framemd5(&src), "{name}: frames differ");
    }
}
