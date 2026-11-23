//! Golden-structure tests: walk the writer's output with `core::mp4box` (ADR 0005 section 1).

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names,
    clippy::as_conversions,
    reason = "test code: helpers outside #[test] fns on synthetic data; panics are failures"
)]

use wardenlens_core::mp4box::{SliceSource, parse_header, summarize};
use wardenlens_mp4::{DurationPatch, Fragment, H264Params, Mp4Error, Sample, init_segment};

/// SPS and PPS of `tests/fixtures/testsrc.h264`: High profile, 320x180 (cropped from 320x192).
const SPS: [u8; 24] = [
    0x67, 0x64, 0x00, 0x0c, 0xac, 0xb4, 0x0a, 0x0c, 0xfc, 0xf8, 0x08, 0x80, 0x00, 0x00, 0x03, 0x00,
    0x80, 0x00, 0x00, 0x19, 0x07, 0x8a, 0x15, 0x50,
];
const PPS: [u8; 5] = [0x68, 0xef, 0x06, 0x72, 0xc0];

/// One AVCC sample holding a single NAL unit of `n` bytes.
fn avcc(nal_type: u8, n: usize) -> Vec<u8> {
    let mut v = u32::try_from(n).unwrap().to_be_bytes().to_vec();
    v.push(nal_type);
    v.resize(4 + n, 0xaa);
    v
}

/// Top-level or child boxes of `buf` as (fourcc, offset of box start, whole box).
fn boxes(buf: &[u8]) -> Vec<([u8; 4], usize, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < buf.len() {
        let rest = &buf[at..];
        let h = parse_header(rest, rest.len() as u64).unwrap();
        let size = usize::try_from(h.size()).unwrap();
        out.push((h.fourcc(), at, &rest[..size]));
        at += size;
    }
    out
}

fn body(b: &[u8]) -> &[u8] {
    &b[8..]
}

fn child(parent: &[u8], fourcc: [u8; 4]) -> &[u8] {
    boxes(body(parent))
        .into_iter()
        .find(|(f, _, _)| *f == fourcc)
        .unwrap_or_else(|| panic!("missing {}", String::from_utf8_lossy(&fourcc)))
        .2
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

fn params() -> H264Params {
    H264Params::new(&SPS, &PPS).unwrap()
}

fn file(sample_sets: &[Vec<(Vec<u8>, u32, bool)>]) -> Vec<u8> {
    let mut buf = init_segment(&params()).unwrap().bytes().to_vec();
    let mut t = 0u64;
    for (i, set) in sample_sets.iter().enumerate() {
        let samples: Vec<Sample<'_>> = set
            .iter()
            .map(|(d, dur, k)| Sample {
                data: d,
                duration: *dur,
                is_sync: *k,
            })
            .collect();
        Fragment::write(u32::try_from(i + 1).unwrap(), t, &samples, &mut buf).unwrap();
        t += set.iter().map(|s| u64::from(s.1)).sum::<u64>();
    }
    buf
}

#[test]
fn init_segment_has_the_documented_box_hierarchy() {
    let init = init_segment(&params()).unwrap();
    let top = boxes(init.bytes());
    let names: Vec<_> = top.iter().map(|b| b.0).collect();
    assert_eq!(names, [*b"ftyp", *b"moov"]);
    assert_eq!(&body(top[0].2)[..8], b"isom\0\0\x02\0");

    let moov = top[1].2;
    let moov_children: Vec<_> = boxes(body(moov)).iter().map(|b| b.0).collect();
    assert_eq!(moov_children, [*b"mvhd", *b"trak", *b"mvex"]);

    let mvex: Vec<_> = boxes(body(child(moov, *b"mvex")))
        .iter()
        .map(|b| b.0)
        .collect();
    assert_eq!(mvex, [*b"mehd", *b"trex"]);

    let trak = child(moov, *b"trak");
    let trak_children: Vec<_> = boxes(body(trak)).iter().map(|b| b.0).collect();
    assert_eq!(trak_children, [*b"tkhd", *b"mdia"]);
    let mdia = child(trak, *b"mdia");
    let minf = child(mdia, *b"minf");
    let stbl = child(minf, *b"stbl");
    let stbl_children: Vec<_> = boxes(body(stbl)).iter().map(|b| b.0).collect();
    assert_eq!(
        stbl_children,
        [*b"stsd", *b"stts", *b"stsc", *b"stsz", *b"stco"]
    );
    // mdhd timescale
    assert_eq!(u32_at(body(child(mdia, *b"mdhd")), 12), 90_000);
    // tkhd flags 3, dimensions 320x180 as 16.16
    let tkhd = body(child(trak, *b"tkhd"));
    assert_eq!(u32_at(tkhd, 0), 3);
    assert_eq!(u32_at(tkhd, 76), 320 << 16);
    assert_eq!(u32_at(tkhd, 80), 180 << 16);
}

#[test]
fn avcc_carries_sps_and_pps_and_the_high_profile_extension() {
    let init = init_segment(&params()).unwrap();
    let moov = boxes(init.bytes())[1].2;
    let stbl = child(
        child(child(child(moov, *b"trak"), *b"mdia"), *b"minf"),
        *b"stbl",
    );
    let stsd = child(stbl, *b"stsd");
    let avc1 = &body(stsd)[8..];
    assert_eq!(&avc1[4..8], b"avc1");
    assert_eq!(u16::from_be_bytes([avc1[32], avc1[33]]), 320);
    assert_eq!(u16::from_be_bytes([avc1[34], avc1[35]]), 180);
    let avcc = boxes(&avc1[8 + 78..])[0].2;
    assert_eq!(&avcc[4..8], b"avcC");
    let b = body(avcc);
    assert_eq!(&b[..6], [1, 0x64, 0x00, 0x0c, 0xff, 0xe1]);
    assert_eq!(&b[6..8], [0, 24]);
    assert_eq!(&b[8..32], SPS);
    assert_eq!(&b[32..35], [1, 0, 5]);
    assert_eq!(&b[35..40], PPS);
    assert_eq!(&b[40..], [0xfd, 0xf8, 0xf8, 0]); // 4:2:0, 8-bit, no extensions
}

#[test]
fn fragment_layout_matches_adr_0005() {
    let samples = [
        (avcc(0x65, 10), 3600, true),
        (avcc(0x41, 5), 3600, false),
        (avcc(0x41, 7), 3000, false),
    ];
    let mut buf = Vec::new();
    let refs: Vec<Sample<'_>> = samples
        .iter()
        .map(|(d, dur, k)| Sample {
            data: d,
            duration: *dur,
            is_sync: *k,
        })
        .collect();
    Fragment::write(7, 123_456_789_012, &refs, &mut buf).unwrap();

    let top = boxes(&buf);
    assert_eq!(
        top.iter().map(|b| b.0).collect::<Vec<_>>(),
        [*b"moof", *b"mdat"]
    );
    let moof = top[0].2;
    assert_eq!(
        boxes(body(moof)).iter().map(|b| b.0).collect::<Vec<_>>(),
        [*b"mfhd", *b"traf"]
    );
    assert_eq!(u32_at(body(child(moof, *b"mfhd")), 4), 7);
    let traf = child(moof, *b"traf");
    assert_eq!(
        boxes(body(traf)).iter().map(|b| b.0).collect::<Vec<_>>(),
        [*b"tfhd", *b"tfdt", *b"trun"]
    );
    let tfhd = body(child(traf, *b"tfhd"));
    assert_eq!(u32_at(tfhd, 0), 0x02_0000); // default-base-is-moof, version 0
    assert_eq!(u32_at(tfhd, 4), 1);
    let tfdt = body(child(traf, *b"tfdt"));
    assert_eq!(u32_at(tfdt, 0), 0x0100_0000); // version 1
    assert_eq!(
        u64::from_be_bytes(tfdt[4..12].try_into().unwrap()),
        123_456_789_012
    );

    let trun = body(child(traf, *b"trun"));
    assert_eq!(u32_at(trun, 0), 0x00_0701);
    assert_eq!(u32_at(trun, 4), 3); // sample count
    let data_offset = u32_at(trun, 8) as usize;
    // Offset is from the moof start and lands on the first mdat payload byte.
    assert_eq!(data_offset, moof.len() + 8);
    assert_eq!(&buf[data_offset..data_offset + 4], &samples[0].0[..4]);
    let entries: Vec<_> = (0..3)
        .map(|i| {
            (
                u32_at(trun, 12 + 12 * i),
                u32_at(trun, 16 + 12 * i),
                u32_at(trun, 20 + 12 * i),
            )
        })
        .collect();
    assert_eq!(
        entries,
        [
            (3600, 14, 0x0200_0000),
            (3600, 9, 0x0101_0000),
            (3000, 11, 0x0101_0000)
        ]
    );
    let mdat = top[1].2;
    assert_eq!(mdat.len(), 8 + 14 + 9 + 11);
}

#[test]
fn core_parser_accepts_a_whole_file_and_counts_frames_and_duration() {
    let gop = |n: usize| -> Vec<(Vec<u8>, u32, bool)> {
        (0..n)
            .map(|i| (avcc(if i == 0 { 0x65 } else { 0x41 }, 20 + i), 3600, i == 0))
            .collect()
    };
    let buf = file(&[gop(25), gop(25)]);
    let summary = summarize(&mut SliceSource(&buf)).unwrap();
    assert_eq!(summary.frame_count, 50);
    assert_eq!(summary.duration_ms, 2000);
}

#[test]
fn single_sample_fragment_is_accepted_by_the_core_parser() {
    let buf = file(&[vec![(avcc(0x65, 1), 1, true)]]);
    let summary = summarize(&mut SliceSource(&buf)).unwrap();
    assert_eq!(summary.frame_count, 1);
}

#[test]
fn duration_patch_points_at_the_zero_fields_and_round_trips() {
    let init = init_segment(&params()).unwrap();
    let patch: DurationPatch = init.duration_patch(0x0123_4567).unwrap();
    let b = init.bytes();
    let (m, e) = (
        usize::try_from(patch.mvhd_offset).unwrap(),
        usize::try_from(patch.mehd_offset).unwrap(),
    );
    assert_eq!(&b[m..m + 4], [0; 4]);
    assert_eq!(&b[e..e + 8], [0; 8]);
    assert_eq!(patch.mvhd_value, 0x0123_4567u32.to_be_bytes());
    assert_eq!(patch.mehd_value, 0x0123_4567u64.to_be_bytes());

    let mut patched = file(&[vec![(avcc(0x65, 4), 90_000, true)]]);
    patched[m..m + 4].copy_from_slice(&patch.mvhd_value);
    patched[e..e + 8].copy_from_slice(&patch.mehd_value);
    // mvhd: duration sits after version/flags, two times and the timescale.
    let mvhd = child(boxes(&patched)[1].2, *b"mvhd");
    assert_eq!(u32_at(body(mvhd), 16), 0x0123_4567);
    let mvex = child(boxes(&patched)[1].2, *b"mvex");
    let mehd = body(child(mvex, *b"mehd"));
    assert_eq!(
        u64::from_be_bytes(mehd[4..12].try_into().unwrap()),
        0x0123_4567
    );
    summarize(&mut SliceSource(&patched)).unwrap();
}

#[test]
fn duration_patch_rejects_ticks_beyond_32_bits() {
    let init = init_segment(&params()).unwrap();
    assert!(init.duration_patch(u64::from(u32::MAX)).is_ok());
    assert!(matches!(
        init.duration_patch(u64::from(u32::MAX) + 1),
        Err(Mp4Error::DurationTooLarge { .. })
    ));
}

#[test]
fn rejects_empty_fragment() {
    assert!(matches!(
        Fragment::write(1, 0, &[], &mut Vec::new()),
        Err(Mp4Error::NoSamples)
    ));
}

#[test]
fn rejects_empty_sample() {
    let s = [Sample {
        data: &[],
        duration: 1,
        is_sync: true,
    }];
    assert!(matches!(
        Fragment::write(1, 0, &s, &mut Vec::new()),
        Err(Mp4Error::EmptySample)
    ));
}

#[test]
fn rejects_sample_that_is_not_avcc_without_writing_anything() {
    let bad: [&[u8]; 4] = [
        &[0, 0, 0, 5, 1, 2],       // length beyond the data
        &[0, 0, 0, 1, 1, 9],       // trailing byte
        &[0, 0, 1],                // truncated prefix
        &[0, 0, 0, 0, 0, 0, 0, 1], // zero-length NAL
    ];
    for data in bad {
        let s = [Sample {
            data,
            duration: 1,
            is_sync: true,
        }];
        let mut out = Vec::new();
        assert!(matches!(
            Fragment::write(1, 0, &s, &mut out),
            Err(Mp4Error::InvalidAvcc)
        ));
        assert_eq!(out, Vec::<u8>::new());
    }
}

#[test]
fn sample_size_limit_is_8_mib_inclusive() {
    let ok = avcc(0x41, 8 * 1024 * 1024 - 4);
    let s = [Sample {
        data: &ok,
        duration: 1,
        is_sync: false,
    }];
    assert!(Fragment::write(1, 0, &s, &mut std::io::sink()).is_ok());
    let big = avcc(0x41, 8 * 1024 * 1024 - 3);
    let s = [Sample {
        data: &big,
        duration: 1,
        is_sync: false,
    }];
    assert!(matches!(
        Fragment::write(1, 0, &s, &mut std::io::sink()),
        Err(Mp4Error::SampleTooLarge { .. })
    ));
}

#[test]
fn rejects_more_samples_than_the_bound() {
    let data = avcc(0x41, 1);
    let one = Sample {
        data: &data,
        duration: 1,
        is_sync: false,
    };
    let many = vec![one; 100_001];
    assert!(matches!(
        Fragment::write(1, 0, &many, &mut std::io::sink()),
        Err(Mp4Error::TooManySamples { .. })
    ));
    assert!(Fragment::write(1, 0, &many[..100_000], &mut std::io::sink()).is_ok());
}

#[test]
fn surfaces_writer_failure_as_io_error() {
    struct Failing;
    impl std::io::Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let data = avcc(0x65, 3);
    let s = [Sample {
        data: &data,
        duration: 1,
        is_sync: true,
    }];
    assert!(matches!(
        Fragment::write(1, 0, &s, &mut Failing),
        Err(Mp4Error::Io(_))
    ));
}

#[test]
fn params_reject_bad_parameter_sets() {
    assert!(matches!(
        H264Params::new(&[], &PPS),
        Err(Mp4Error::SpsLength { .. })
    ));
    assert!(matches!(
        H264Params::new(&SPS, &[]),
        Err(Mp4Error::PpsLength { .. })
    ));
    assert!(matches!(
        H264Params::new(&SPS, &[0x67, 1]),
        Err(Mp4Error::NotAPps)
    ));
    assert!(matches!(
        H264Params::new(&SPS, &vec![0x68; 1025]),
        Err(Mp4Error::PpsLength { .. })
    ));
    assert!(matches!(
        H264Params::new(&PPS, &PPS),
        Err(Mp4Error::NotAnSps)
    ));
}
