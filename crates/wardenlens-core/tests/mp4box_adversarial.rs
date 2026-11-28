//! Adversarial tests for `core::mp4box` (ticket #86): hostile fMP4 inputs through the public API.

#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::trivially_copy_pass_by_ref,
    reason = "integration-test helpers outside #[test] fns build synthetic boxes; clippy.toml in-tests allowances do not reach them"
)]

use std::time::{Duration, Instant};

use wardenlens_core::mp4box::{
    ByteSource, MAX_FILE_LEN, MAX_PAYLOAD_LEN, Mp4BoxError, Mp4Summary, SliceSource, SourceError,
    parse_header, summarize,
};

fn mk_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len() + 8).unwrap();
    let mut v = size.to_be_bytes().to_vec();
    v.extend_from_slice(fourcc);
    v.extend_from_slice(payload);
    v
}

fn raw_header(size: u32, fourcc: &[u8; 4]) -> Vec<u8> {
    let mut v = size.to_be_bytes().to_vec();
    v.extend_from_slice(fourcc);
    v
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

fn ftyp() -> Vec<u8> {
    mk_box(b"ftyp", b"isom\0\0\0\0isom")
}

fn mdhd(version: u8, timescale: u32) -> Vec<u8> {
    let mut p = vec![version, 0, 0, 0];
    p.extend_from_slice(&vec![0; if version == 1 { 16 } else { 8 }]);
    p.extend_from_slice(&timescale.to_be_bytes());
    p.extend_from_slice(&[0; 4]);
    mk_box(b"mdhd", &p)
}

fn trak(timescale: u32) -> Vec<u8> {
    mk_box(b"trak", &mk_box(b"mdia", &mdhd(0, timescale)))
}

fn moov(timescale: u32) -> Vec<u8> {
    mk_box(b"moov", &trak(timescale))
}

fn tfhd(flags: u32, tail: &[u8]) -> Vec<u8> {
    let mut p = flags.to_be_bytes().to_vec();
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(tail);
    mk_box(b"tfhd", &p)
}

fn trun_writer(durations: &[u32]) -> Vec<u8> {
    let mut p = 0x0000_0701u32.to_be_bytes().to_vec();
    p.extend_from_slice(&u32::try_from(durations.len()).unwrap().to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    for d in durations {
        p.extend_from_slice(&d.to_be_bytes());
        p.extend_from_slice(&100u32.to_be_bytes());
        p.extend_from_slice(&0x0101_0000u32.to_be_bytes());
    }
    mk_box(b"trun", &p)
}

fn trun_raw(flags: u32, count: u32, tail: &[u8]) -> Vec<u8> {
    let mut p = flags.to_be_bytes().to_vec();
    p.extend_from_slice(&count.to_be_bytes());
    p.extend_from_slice(tail);
    mk_box(b"trun", &p)
}

fn moof(traf_children: &[Vec<u8>]) -> Vec<u8> {
    mk_box(
        b"moof",
        &cat(&[
            mk_box(b"mfhd", &[0; 8]),
            mk_box(b"traf", &cat(traf_children)),
        ]),
    )
}

fn mdat() -> Vec<u8> {
    mk_box(b"mdat", &[0; 4])
}

fn run(bytes: &[u8]) -> Result<Mp4Summary, Mp4BoxError> {
    summarize(&mut SliceSource(bytes))
}

fn file_with_moov(moov_box: Vec<u8>) -> Vec<u8> {
    cat(&[
        ftyp(),
        moov_box,
        moof(&[tfhd(0x02_0000, &[]), trun_writer(&[3000])]),
        mdat(),
    ])
}

// ---------------------------------------------------------------- children inside parents

/// ADR 0005 section 9: "a child that does not lie inside its parent" must be rejected.
/// Here the moov holds a valid trak followed by a sibling whose size runs past the moov.
#[test]
fn moov_child_after_mdhd_exceeding_parent_is_rejected() {
    let moov_box = mk_box(
        b"moov",
        &cat(&[trak(90_000), raw_header(0x7fff_ffff, b"udta")]),
    );
    let r = run(&file_with_moov(moov_box));
    assert!(
        matches!(r, Err(Mp4BoxError::ExceedsParent { .. })),
        "got {r:?}"
    );
}

/// The same hostile sibling placed before the trak is rejected; the result must not depend
/// on sibling order.
#[test]
fn moov_child_before_trak_exceeding_parent_is_rejected() {
    let moov_box = mk_box(
        b"moov",
        &cat(&[raw_header(0x7fff_ffff, b"udta"), trak(90_000)]),
    );
    let r = run(&file_with_moov(moov_box));
    assert!(
        matches!(r, Err(Mp4BoxError::ExceedsParent { .. })),
        "got {r:?}"
    );
}

/// Three trailing bytes inside the moov after the trak are a trailing partial box.
#[test]
fn moov_trailing_partial_box_after_trak_is_rejected() {
    let moov_box = mk_box(b"moov", &cat(&[trak(90_000), vec![0, 0, 0]]));
    let r = run(&file_with_moov(moov_box));
    assert_eq!(r, Err(Mp4BoxError::TrailingPartialBox));
}

/// A hostile sibling inside the trak after the mdia (also skipped by the early return).
#[test]
fn trak_child_after_mdia_with_size_zero_is_rejected() {
    let trak_box = mk_box(
        b"trak",
        &cat(&[mk_box(b"mdia", &mdhd(0, 90_000)), raw_header(0, b"edts")]),
    );
    let r = run(&file_with_moov(mk_box(b"moov", &trak_box)));
    assert!(matches!(r, Err(Mp4BoxError::InvalidSize(0))), "got {r:?}");
}

#[test]
fn traf_child_exceeding_parent_is_rejected() {
    let f = cat(&[
        ftyp(),
        moov(90_000),
        moof(&[
            tfhd(0x02_0000, &[]),
            trun_writer(&[3000]),
            raw_header(0x7fff_ffff, b"sdtp"),
        ]),
        mdat(),
    ]);
    assert!(matches!(run(&f), Err(Mp4BoxError::ExceedsParent { .. })));
}

// ---------------------------------------------------------------- caps and boundaries

#[test]
fn moof_payload_exactly_one_mib_is_accepted_and_one_more_byte_rejected() {
    let build = |payload_len: usize| {
        let base = cat(&[
            mk_box(b"mfhd", &[0; 8]),
            mk_box(b"traf", &cat(&[tfhd(0x02_0000, &[]), trun_writer(&[90])])),
        ]);
        let pad = payload_len - base.len() - 8;
        let payload = cat(&[base, mk_box(b"free", &vec![0; pad])]);
        assert_eq!(payload.len(), payload_len);
        cat(&[ftyp(), moov(90_000), mk_box(b"moof", &payload), mdat()])
    };
    let cap = usize::try_from(MAX_PAYLOAD_LEN).unwrap();
    assert_eq!(run(&build(cap)).unwrap().frame_count, 1);
    assert_eq!(
        run(&build(cap + 1)),
        Err(Mp4BoxError::PayloadTooLarge {
            len: MAX_PAYLOAD_LEN + 1
        })
    );
}

/// Lazily generated virtual file: a fixed prefix then one huge `mdat` filling to `len`.
/// Records the largest byte range ever requested.
struct Virtual {
    prefix: Vec<u8>,
    len: u64,
    max_read: usize,
    reads: u64,
    past_end: bool,
}

impl ByteSource for Virtual {
    fn byte_len(&self) -> u64 {
        self.len
    }
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.reads += 1;
        self.max_read = self.max_read.max(buf.len());
        if offset + buf.len() as u64 > self.len {
            self.past_end = true;
            return Err(SourceError);
        }
        for (i, b) in buf.iter_mut().enumerate() {
            let pos = offset + i as u64;
            *b = if pos < self.prefix.len() as u64 {
                self.prefix[usize::try_from(pos).unwrap()]
            } else {
                0xee
            };
        }
        Ok(())
    }
}

#[test]
fn file_of_exactly_one_gib_with_huge_mdat_is_summarised_without_reading_mdat() {
    let head = cat(&[
        ftyp(),
        moov(90_000),
        moof(&[tfhd(0x02_0000, &[]), trun_writer(&[90_000])]),
    ]);
    let mdat_size = u32::try_from(MAX_FILE_LEN - head.len() as u64).unwrap();
    let prefix = cat(&[head, raw_header(mdat_size, b"mdat")]);
    let mut v = Virtual {
        prefix,
        len: MAX_FILE_LEN,
        max_read: 0,
        reads: 0,
        past_end: false,
    };
    let s = summarize(&mut v).unwrap();
    assert_eq!((s.duration_ms, s.frame_count), (1000, 1));
    assert!(v.max_read <= 1024, "read {} bytes at once", v.max_read);
    assert!(v.reads < 10);
    assert!(!v.past_end);
}

#[test]
fn byte_len_u64_max_is_rejected_before_any_read() {
    let mut v = Virtual {
        prefix: Vec::new(),
        len: u64::MAX,
        max_read: 0,
        reads: 0,
        past_end: false,
    };
    assert_eq!(
        summarize(&mut v),
        Err(Mp4BoxError::FileTooLarge { len: u64::MAX })
    );
    assert_eq!(v.reads, 0);
}

/// Source whose every 8-byte header is a `free` box of size 8: 1 GiB of tiny boxes.
struct TinyBoxes {
    reads: u64,
}

impl ByteSource for TinyBoxes {
    fn byte_len(&self) -> u64 {
        MAX_FILE_LEN
    }
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.reads += 1;
        // The first box must be an ftyp; everything after it is `free`.
        let h = raw_header(8, if offset == 0 { b"ftyp" } else { b"free" });
        for (i, b) in buf.iter_mut().enumerate() {
            *b = h[i % 8];
        }
        Ok(())
    }
}

#[test]
fn one_gib_of_eight_byte_boxes_is_rejected_quickly() {
    let mut src = TinyBoxes { reads: 0 };
    let t = Instant::now();
    assert_eq!(summarize(&mut src), Err(Mp4BoxError::TooManyBoxes));
    assert!(src.reads <= 300_000, "reads {}", src.reads);
    // Runaway work takes minutes or more; the bound only has to beat that, not host load (TEST-5).
    assert!(t.elapsed() < Duration::from_secs(60));
}

#[test]
fn top_level_box_of_u32_max_in_small_file_exceeds_parent() {
    let f = cat(&[ftyp(), raw_header(u32::MAX, b"mdat")]);
    assert!(matches!(run(&f), Err(Mp4BoxError::ExceedsParent { .. })));
}

#[test]
fn parse_header_remaining_zero_and_u64_max() {
    let h = raw_header(8, b"free");
    assert!(matches!(
        parse_header(&h, 0),
        Err(Mp4BoxError::ExceedsParent { .. })
    ));
    assert_eq!(parse_header(&h, u64::MAX).unwrap().size(), 8);
    let big = raw_header(u32::MAX, b"mdat");
    assert_eq!(
        parse_header(&big, u64::MAX).unwrap().size(),
        u64::from(u32::MAX)
    );
    // Size 1 (largesize) is rejected even when the 64-bit field would be valid.
    let mut ls = raw_header(1, b"mdat");
    ls.extend_from_slice(&16u64.to_be_bytes());
    assert_eq!(parse_header(&ls, 16), Err(Mp4BoxError::LargeSize));
    for s in 2..8 {
        assert_eq!(
            parse_header(&raw_header(s, b"free"), 100),
            Err(Mp4BoxError::InvalidSize(s))
        );
    }
}

// ---------------------------------------------------------------- trun / tfhd

/// Many truns, each claiming `u32::MAX` samples via the tfhd default (entry size 0):
/// must neither iterate per sample nor overflow silently.
#[test]
fn huge_default_sample_counts_do_not_iterate() {
    let mut children = vec![tfhd(0x08, &1u32.to_be_bytes())];
    for _ in 0..10_000 {
        children.push(trun_raw(0, u32::MAX, &[]));
    }
    let f = cat(&[ftyp(), moov(90_000), moof(&children), mdat()]);
    let t = Instant::now();
    let s = run(&f).unwrap();
    // Runaway work takes minutes or more; the bound only has to beat that, not host load (TEST-5).
    assert!(t.elapsed() < Duration::from_secs(60));
    assert_eq!(s.frame_count, u64::from(u32::MAX) * 10_000);
}

#[test]
fn sample_count_times_entry_size_one_over_payload_is_rejected() {
    // flags 0x300: duration + size = 8-byte entries; 2 samples need 16 bytes, give 15.
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0, &[]), trun_raw(0x300, 2, &[0; 15])]),
        mdat(),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::SampleTableTooLarge));
}

#[test]
fn trun_data_offset_and_first_sample_flags_are_skipped_before_the_table() {
    // flags 0x105: data offset + first-sample-flags + per-sample duration.
    let mut tail = 0xdead_beefu32.to_be_bytes().to_vec();
    tail.extend_from_slice(&0x0200_0000u32.to_be_bytes());
    tail.extend_from_slice(&500u32.to_be_bytes());
    tail.extend_from_slice(&500u32.to_be_bytes());
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0, &[]), trun_raw(0x105, 2, &tail)]),
        mdat(),
    ]);
    assert_eq!(
        run(&f).unwrap(),
        Mp4Summary {
            duration_ms: 1000,
            frame_count: 2
        }
    );
}

#[test]
fn trun_missing_its_data_offset_field_is_rejected() {
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0, &[]), trun_raw(0x001, 0, &[0, 0])]),
        mdat(),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::TruncatedBox("trun")));
}

#[test]
fn tfhd_default_duration_after_optional_fields_is_found() {
    // flags 0x0b: base data offset (8) + sample description index (4) + default duration.
    let mut tail = vec![0xff; 8];
    tail.extend_from_slice(&7u32.to_be_bytes());
    tail.extend_from_slice(&40u32.to_be_bytes());
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0x0b, &tail), trun_raw(0, 25, &[])]),
        mdat(),
    ]);
    assert_eq!(
        run(&f).unwrap(),
        Mp4Summary {
            duration_ms: 1000,
            frame_count: 25
        }
    );
}

#[test]
fn tfhd_claiming_default_duration_but_truncated_is_rejected() {
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0x08, &[0, 0]), trun_raw(0, 1, &[])]),
        mdat(),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::TruncatedBox("tfhd")));
}

#[test]
fn tick_sum_overflow_across_fragments_is_a_typed_error() {
    // Each fragment: u32::MAX samples x u32::MAX ticks ~ 2^64 - 2^33; two of them overflow u64.
    let frag = cat(&[
        moof(&[
            tfhd(0x08, &u32::MAX.to_be_bytes()),
            trun_raw(0, u32::MAX, &[]),
        ]),
        mdat(),
    ]);
    let f = cat(&[ftyp(), moov(u32::MAX), frag.clone(), frag]);
    assert_eq!(run(&f), Err(Mp4BoxError::Overflow));
}

// ---------------------------------------------------------------- rounding

#[test]
fn ms_rounding_matches_a_naive_oracle() {
    let cases: &[(u32, u32)] = &[
        (1, 1),
        (1000, 1),
        (1000, 999),
        (1001, 1),
        (90_000, 89),
        (90_000, 179_999),
        (u32::MAX, 1),
        (u32::MAX, u32::MAX),
        (3, 2),
        (7, 7_000_001),
    ];
    for &(ts, d) in cases {
        let f = cat(&[
            ftyp(),
            moov(ts),
            moof(&[tfhd(0, &[]), trun_writer(&[d])]),
            mdat(),
        ]);
        let want = (u128::from(d) * 1000).div_ceil(u128::from(ts)).max(1);
        assert_eq!(
            u128::from(run(&f).unwrap().duration_ms),
            want,
            "ts={ts} d={d}"
        );
    }
}

#[test]
fn mdhd_version_one_timescale_is_read() {
    let moov_box = mk_box(b"moov", &mk_box(b"trak", &mk_box(b"mdia", &mdhd(1, 1000))));
    let f = cat(&[
        ftyp(),
        moov_box,
        moof(&[tfhd(0, &[]), trun_writer(&[1500])]),
        mdat(),
    ]);
    assert_eq!(run(&f).unwrap().duration_ms, 1500);
}

#[test]
fn mdhd_version_two_is_rejected() {
    let moov_box = mk_box(b"moov", &mk_box(b"trak", &mk_box(b"mdia", &mdhd(2, 1000))));
    assert_eq!(
        run(&file_with_moov(moov_box)),
        Err(Mp4BoxError::InvalidField("mdhd"))
    );
}

// ---------------------------------------------------------------- structure / ordering

#[test]
fn moov_after_fragment_is_rejected() {
    let f = cat(&[
        ftyp(),
        moof(&[tfhd(0, &[]), trun_writer(&[1])]),
        mdat(),
        moov(1000),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::FragmentBeforeMoov));
}

#[test]
fn duplicate_moov_after_fragments_is_rejected() {
    let f = cat(&[file_with_moov(moov(1000)), moov(1000)]);
    assert_eq!(run(&f), Err(Mp4BoxError::DuplicateBox("moov")));
}

#[test]
fn two_moofs_in_a_row_are_incomplete() {
    let m = moof(&[tfhd(0, &[]), trun_writer(&[1])]);
    let f = cat(&[ftyp(), moov(1000), m.clone(), m, mdat()]);
    assert_eq!(run(&f), Err(Mp4BoxError::IncompleteFragment));
}

#[test]
fn deep_nesting_inside_moof_traf_does_not_recurse() {
    let mut inner = trun_writer(&[1]);
    for _ in 0..100_000 {
        inner = mk_box(b"traf", &inner);
    }
    let f = cat(&[ftyp(), moov(1000), mk_box(b"moof", &inner), mdat()]);
    // Nested trafs are not on the fixed path; the outer traf has no trun child.
    assert_eq!(run(&f), Err(Mp4BoxError::NoSamples));
}

#[test]
fn deep_nesting_of_mdia_inside_trak_does_not_recurse() {
    let mut inner = mdhd(0, 1000);
    for _ in 0..100_000 {
        inner = mk_box(b"mdia", &inner);
    }
    let f = file_with_moov(mk_box(b"moov", &mk_box(b"trak", &inner)));
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("mdhd")));
}

#[test]
fn reads_never_go_past_byte_len() {
    // byte_len is shorter than the buffer: the walk must stay within byte_len.
    let full = file_with_moov(moov(1000));
    let mut v = Virtual {
        prefix: full.clone(),
        len: full.len() as u64 - 3,
        max_read: 0,
        reads: 0,
        past_end: false,
    };
    assert_eq!(
        summarize(&mut v),
        Err(Mp4BoxError::ExceedsParent {
            size: 12,
            remaining: 9
        })
    );
    assert!(!v.past_end);
}
