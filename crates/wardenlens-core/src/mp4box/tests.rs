//! Tests for the box parser: golden file, edge cases and proptests.

#![expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "fourcc literals are b\"..\" references"
)]

use super::*;
use proptest::prelude::*;

fn mk_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len().saturating_add(8)).unwrap();
    let mut v = size.to_be_bytes().to_vec();
    v.extend_from_slice(fourcc);
    v.extend_from_slice(payload);
    v
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

fn mdhd_v0(timescale: u32) -> Vec<u8> {
    let mut p = vec![0u8; 4];
    p.extend_from_slice(&[0; 8]);
    p.extend_from_slice(&timescale.to_be_bytes());
    p.extend_from_slice(&[0; 4]);
    mk_box(b"mdhd", &p)
}

fn moov(timescale: u32) -> Vec<u8> {
    mk_box(
        b"moov",
        &mk_box(b"trak", &mk_box(b"mdia", &mdhd_v0(timescale))),
    )
}

fn tfhd(default_duration: Option<u32>) -> Vec<u8> {
    let mut p = Vec::new();
    let flags: u32 = if default_duration.is_some() { 0x08 } else { 0 };
    p.extend_from_slice(&flags.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    if let Some(d) = default_duration {
        p.extend_from_slice(&d.to_be_bytes());
    }
    mk_box(b"tfhd", &p)
}

/// `trun` with flags 0x000701 (data offset, duration, size, flags) as our writer emits.
fn trun_durations(durations: &[u32]) -> Vec<u8> {
    let mut p = 0x0000_0701u32.to_be_bytes().to_vec();
    p.extend_from_slice(&u32::try_from(durations.len()).unwrap().to_be_bytes());
    p.extend_from_slice(&0i32.to_be_bytes());
    for d in durations {
        p.extend_from_slice(&d.to_be_bytes());
        p.extend_from_slice(&100u32.to_be_bytes());
        p.extend_from_slice(&0x0101_0000u32.to_be_bytes());
    }
    mk_box(b"trun", &p)
}

fn trun_default(count: u32) -> Vec<u8> {
    let mut p = 0u32.to_be_bytes().to_vec();
    p.extend_from_slice(&count.to_be_bytes());
    mk_box(b"trun", &p)
}

fn moof_with(traf_children: &[Vec<u8>]) -> Vec<u8> {
    let mfhd = mk_box(b"mfhd", &[0; 8]);
    mk_box(b"moof", &cat(&[mfhd, mk_box(b"traf", &cat(traf_children))]))
}

fn ftyp() -> Vec<u8> {
    mk_box(b"ftyp", b"isom\0\0\0\0isom")
}

fn golden() -> Vec<u8> {
    cat(&[
        ftyp(),
        moov(90_000),
        moof_with(&[tfhd(None), trun_durations(&[3000, 3000, 3000])]),
        mk_box(b"mdat", &[0xaa; 300]),
        moof_with(&[tfhd(None), trun_durations(&[3000, 3000])]),
        mk_box(b"mdat", &[0xbb; 200]),
    ])
}

fn run(bytes: &[u8]) -> Result<Mp4Summary, Mp4BoxError> {
    summarize(&mut SliceSource(bytes))
}

#[test]
fn golden_minimal_fmp4_is_summarised() {
    let s = run(&golden()).unwrap();
    assert_eq!(s.frame_count, 5);
    // 15000 ticks at 90 kHz = 166.67 ms, rounded up.
    assert_eq!(s.duration_ms, 167);
}

#[test]
fn header_returns_fourcc_and_sizes() {
    let h = parse_header(&[0, 0, 0, 12, b'm', b'o', b'o', b'v', 1, 2, 3, 4], 12).unwrap();
    assert_eq!(&h.fourcc, b"moov");
    assert_eq!((h.header_len, h.size, h.payload_len()), (8, 12, 4));
}

#[test]
fn header_rejects_size_zero_and_below_eight() {
    for size in [0u32, 2, 7] {
        let mut b = size.to_be_bytes().to_vec();
        b.extend_from_slice(b"free");
        assert_eq!(parse_header(&b, 100), Err(Mp4BoxError::InvalidSize(size)));
    }
}

#[test]
fn header_accepts_size_eight_exactly() {
    assert!(parse_header(&[0, 0, 0, 8, b'f', b'r', b'e', b'e'], 8).is_ok());
}

#[test]
fn header_rejects_largesize() {
    let b = [0, 0, 0, 1, b'm', b'd', b'a', b't', 0, 0, 0, 0, 0, 0, 0, 16];
    assert_eq!(parse_header(&b, 100), Err(Mp4BoxError::LargeSize));
}

#[test]
fn header_rejects_box_larger_than_parent() {
    let b = [0, 0, 0, 20, b'm', b'd', b'a', b't'];
    assert_eq!(
        parse_header(&b, 19),
        Err(Mp4BoxError::ExceedsParent {
            size: 20,
            remaining: 19
        })
    );
    assert!(parse_header(&b, 20).is_ok());
}

#[test]
fn header_rejects_truncated_input() {
    assert_eq!(parse_header(&[], 100), Err(Mp4BoxError::TruncatedHeader));
    assert_eq!(
        parse_header(&[0, 0, 0, 8, 1, 2, 3], 100),
        Err(Mp4BoxError::TruncatedHeader)
    );
}

#[test]
fn rejects_trailing_partial_box() {
    let mut f = golden();
    f.extend_from_slice(&[0, 0, 0]);
    assert_eq!(run(&f), Err(Mp4BoxError::TrailingPartialBox));
}

#[test]
fn rejects_truncated_last_box() {
    let mut f = golden();
    f.truncate(f.len() - 10);
    assert!(matches!(run(&f), Err(Mp4BoxError::ExceedsParent { .. })));
}

#[test]
fn rejects_empty_file() {
    assert_eq!(run(&[]), Err(Mp4BoxError::MissingBox("ftyp")));
}

#[test]
fn rejects_missing_ftyp() {
    let f = cat(&[
        moov(1000),
        moof_with(&[tfhd(None), trun_durations(&[1])]),
        mk_box(b"mdat", &[]),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("ftyp")));
}

#[test]
fn rejects_missing_moov() {
    assert_eq!(run(&ftyp()), Err(Mp4BoxError::MissingBox("moov")));
}

#[test]
fn rejects_file_without_a_fragment() {
    let f = cat(&[ftyp(), moov(1000)]);
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("moof+mdat")));
}

#[test]
fn rejects_moof_without_mdat_at_end() {
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof_with(&[tfhd(None), trun_durations(&[1])]),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::IncompleteFragment));
}

#[test]
fn rejects_moof_followed_by_other_box() {
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof_with(&[tfhd(None), trun_durations(&[1])]),
        mk_box(b"free", &[]),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::IncompleteFragment));
}

#[test]
fn rejects_moof_before_moov() {
    let f = cat(&[
        ftyp(),
        moof_with(&[tfhd(None), trun_durations(&[1])]),
        mk_box(b"mdat", &[]),
        moov(1000),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::FragmentBeforeMoov));
}

#[test]
fn rejects_duplicate_moov() {
    let f = cat(&[ftyp(), moov(1000), moov(1000)]);
    assert_eq!(run(&f), Err(Mp4BoxError::DuplicateBox("moov")));
}

#[test]
fn rejects_zero_timescale() {
    let f = cat(&[ftyp(), moov(0)]);
    assert_eq!(run(&f), Err(Mp4BoxError::InvalidField("mdhd")));
}

#[test]
fn skips_mdat_payload_without_reading_it() {
    struct Counting<'a> {
        inner: SliceSource<'a>,
        bytes_read: u64,
    }
    impl ByteSource for Counting<'_> {
        fn byte_len(&self) -> u64 {
            self.inner.byte_len()
        }
        fn read_exact_at(&mut self, o: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            self.bytes_read = self
                .bytes_read
                .saturating_add(u64::try_from(buf.len()).unwrap());
            self.inner.read_exact_at(o, buf)
        }
    }
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof_with(&[tfhd(None), trun_durations(&[10])]),
        mk_box(b"mdat", &vec![0u8; 500_000]),
    ]);
    let mut src = Counting {
        inner: SliceSource(&f),
        bytes_read: 0,
    };
    summarize(&mut src).unwrap();
    assert!(src.bytes_read < 1000, "read {} bytes", src.bytes_read);
}

#[test]
fn accepts_moov_at_payload_cap_and_rejects_above() {
    let cap = usize::try_from(MAX_PAYLOAD_LEN).unwrap();
    let pad = |payload_len: usize| {
        // moov = trak(mdia(mdhd)) followed by a free box padding the payload.
        let real = moov(1000);
        let used = real.len() - 8;
        let free = mk_box(b"free", &vec![0u8; payload_len - used - 8]);
        let mut inner = real[8..].to_vec();
        inner.extend_from_slice(&free);
        mk_box(b"moov", &inner)
    };
    let tail = cat(&[
        moof_with(&[tfhd(None), trun_durations(&[1])]),
        mk_box(b"mdat", &[]),
    ]);
    let ok = cat(&[ftyp(), pad(cap), tail.clone()]);
    assert!(run(&ok).is_ok());
    let big = cat(&[ftyp(), pad(cap + 1), tail]);
    assert_eq!(
        run(&big),
        Err(Mp4BoxError::PayloadTooLarge {
            len: MAX_PAYLOAD_LEN + 1
        })
    );
}

#[test]
fn rejects_oversized_moof() {
    let big = mk_box(
        b"moof",
        &vec![0u8; usize::try_from(MAX_PAYLOAD_LEN).unwrap() + 1],
    );
    let f = cat(&[ftyp(), moov(1000), big]);
    assert!(matches!(run(&f), Err(Mp4BoxError::PayloadTooLarge { .. })));
}

#[test]
fn rejects_file_over_one_gib() {
    struct Huge;
    impl ByteSource for Huge {
        fn byte_len(&self) -> u64 {
            MAX_FILE_LEN + 1
        }
        fn read_exact_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), SourceError> {
            Err(SourceError)
        }
    }
    assert_eq!(
        summarize(&mut Huge),
        Err(Mp4BoxError::FileTooLarge {
            len: MAX_FILE_LEN + 1
        })
    );
}

#[test]
fn rejects_more_than_the_fragment_cap() {
    let moof = moof_with(&[tfhd(None), trun_default_dur_one()]);
    let mdat = mk_box(b"mdat", &[]);
    let pair = cat(&[moof, mdat]);
    let mut f = cat(&[ftyp(), moov(1000)]);
    let n = usize::try_from(MAX_FRAGMENTS).unwrap();
    for _ in 0..n {
        f.extend_from_slice(&pair);
    }
    let ok = run(&f).unwrap();
    assert_eq!(ok.frame_count, MAX_FRAGMENTS);
    f.extend_from_slice(&pair);
    assert_eq!(run(&f), Err(Mp4BoxError::TooManyFragments));
}

fn trun_default_dur_one() -> Vec<u8> {
    trun_durations(&[1])
}

#[test]
fn uses_tfhd_default_duration() {
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof_with(&[tfhd(Some(40)), trun_default(25)]),
        mk_box(b"mdat", &[]),
    ]);
    let s = run(&f).unwrap();
    assert_eq!((s.frame_count, s.duration_ms), (25, 1000));
}

#[test]
fn rejects_samples_without_any_duration() {
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof_with(&[tfhd(None), trun_default(3)]),
        mk_box(b"mdat", &[]),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::MissingSampleDuration));
}

#[test]
fn rejects_sample_count_larger_than_payload() {
    let mut p = 0x0000_0100u32.to_be_bytes().to_vec();
    p.extend_from_slice(&u32::MAX.to_be_bytes());
    p.extend_from_slice(&[0; 8]);
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof_with(&[tfhd(None), mk_box(b"trun", &p)]),
        mk_box(b"mdat", &[]),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::SampleTableTooLarge));
}

#[test]
fn sample_count_exactly_filling_payload_is_accepted() {
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof_with(&[tfhd(None), trun_durations(&[5, 5])]),
        mk_box(b"mdat", &[]),
    ]);
    assert_eq!(run(&f).unwrap().frame_count, 2);
}

#[test]
fn duration_ms_beyond_u64_is_an_overflow_error() {
    // u32::MAX samples of u32::MAX ticks at timescale 1 is far beyond u64 milliseconds.
    let f = cat(&[
        ftyp(),
        moov(1),
        moof_with(&[tfhd(Some(u32::MAX)), trun_default(u32::MAX)]),
        mk_box(b"mdat", &[]),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::Overflow));
}

#[test]
fn duration_rounds_up_with_minimum_one() {
    let mk = |ts, durs: &[u32]| {
        run(&cat(&[
            ftyp(),
            moov(ts),
            moof_with(&[tfhd(None), trun_durations(durs)]),
            mk_box(b"mdat", &[]),
        ]))
        .unwrap()
        .duration_ms
    };
    assert_eq!(mk(90_000, &[0]), 1);
    assert_eq!(mk(90_000, &[1]), 1);
    assert_eq!(mk(90_000, &[90]), 1);
    assert_eq!(mk(90_000, &[91]), 2);
    assert_eq!(mk(90_000, &[90_000]), 1000);
}

#[test]
fn deep_nesting_of_container_headers_terminates_with_an_error() {
    // About 100k nested trak headers inside one 1 MiB moov.
    let depth = 100_000usize;
    let mut payload = Vec::new();
    for i in 0..depth {
        let remaining = u32::try_from((depth - i) * 8).unwrap();
        payload.extend_from_slice(&remaining.to_be_bytes());
        payload.extend_from_slice(b"trak");
    }
    let f = cat(&[ftyp(), mk_box(b"moov", &payload)]);
    assert!(payload.len() <= 1024 * 1024);
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("mdhd")));
}

#[test]
fn deep_nesting_along_the_fixed_path_is_bounded() {
    let mut inner = mdhd_v0(1000);
    for _ in 0..50 {
        inner = mk_box(b"trak", &inner);
    }
    let f = cat(&[ftyp(), mk_box(b"moov", &inner)]);
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("mdhd")));
}

#[test]
fn source_failure_is_a_typed_error() {
    struct Failing;
    impl ByteSource for Failing {
        fn byte_len(&self) -> u64 {
            64
        }
        fn read_exact_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), SourceError> {
            Err(SourceError)
        }
    }
    assert_eq!(
        summarize(&mut Failing),
        Err(Mp4BoxError::Source(SourceError))
    );
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_in_summarize(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = run(&bytes);
    }

    #[test]
    fn arbitrary_bytes_never_panic_in_parse_header(bytes in proptest::collection::vec(any::<u8>(), 0..32), rem in any::<u64>()) {
        let _ = parse_header(&bytes, rem);
    }

    #[test]
    fn parsed_header_is_always_within_parent(bytes in proptest::collection::vec(any::<u8>(), 0..32), rem in any::<u64>()) {
        if let Ok(h) = parse_header(&bytes, rem) {
            prop_assert!(h.size >= 8 && h.size <= rem);
            prop_assert_eq!(h.header_len, 8);
        }
    }

    #[test]
    fn mutated_golden_file_never_panics(
        edits in proptest::collection::vec((0usize..2000, any::<u8>()), 1..12),
        cut in 0usize..2000,
    ) {
        let mut f = golden();
        for (i, b) in edits {
            if let Some(slot) = f.get_mut(i) {
                *slot = b;
            }
        }
        f.truncate(f.len().saturating_sub(cut % 8));
        let _ = run(&f);
    }

    #[test]
    fn arbitrary_trun_payload_never_panics(
        flags in any::<u32>(),
        count in any::<u32>(),
        tail in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut p = flags.to_be_bytes().to_vec();
        p.extend_from_slice(&count.to_be_bytes());
        p.extend_from_slice(&tail);
        let f = cat(&[
            ftyp(),
            moov(1000),
            moof_with(&[tfhd(Some(1)), mk_box(b"trun", &p)]),
            mk_box(b"mdat", &[]),
        ]);
        let _ = run(&f);
    }
}
