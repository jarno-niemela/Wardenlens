//! Round-2 adversarial tests for `core::mp4box` (ticket #86): fixes since round 1.

#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::trivially_copy_pass_by_ref,
    reason = "integration-test helpers outside #[test] fns build synthetic boxes; clippy.toml in-tests allowances do not reach them"
)]

use std::time::{Duration, Instant};

use wardenlens_core::mp4box::{MAX_PAYLOAD_LEN, Mp4BoxError, Mp4Summary, SliceSource, summarize};

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

fn good_fragment() -> Vec<u8> {
    cat(&[moof(&[tfhd(0x02_0000, &[]), trun_writer(&[3000])]), mdat()])
}

fn traf(children: &[Vec<u8>]) -> Vec<u8> {
    mk_box(b"traf", &cat(children))
}

fn moof_trafs(trafs: &[Vec<u8>]) -> Vec<u8> {
    let mut parts = vec![mk_box(b"mfhd", &[0; 8])];
    parts.extend_from_slice(trafs);
    mk_box(b"moof", &cat(&parts))
}

// ------------------------------------------------ sibling validation along the fixed path

#[test]
fn mdia_child_after_mdhd_exceeding_parent_is_rejected() {
    let mut mdia_payload = mdhd(0, 90_000);
    mdia_payload.extend_from_slice(&raw_header(0x7fff_ffff, b"hdlr"));
    let trak = mk_box(b"trak", &mk_box(b"mdia", &mdia_payload));
    let f = file_with_moov(mk_box(b"moov", &trak));
    assert!(matches!(run(&f), Err(Mp4BoxError::ExceedsParent { .. })));
}

#[test]
fn mdia_trailing_partial_box_after_mdhd_is_rejected() {
    let mut mdia_payload = mdhd(0, 90_000);
    mdia_payload.extend_from_slice(&[0, 0, 0]);
    let trak = mk_box(b"trak", &mk_box(b"mdia", &mdia_payload));
    let f = file_with_moov(mk_box(b"moov", &trak));
    assert_eq!(run(&f), Err(Mp4BoxError::TrailingPartialBox));
}

#[test]
fn second_mdia_with_size_below_eight_is_rejected() {
    let mut trak_payload = mk_box(b"mdia", &mdhd(0, 90_000));
    trak_payload.extend_from_slice(&raw_header(4, b"mdia"));
    let f = file_with_moov(mk_box(b"moov", &mk_box(b"trak", &trak_payload)));
    assert_eq!(run(&f), Err(Mp4BoxError::InvalidSize(4)));
}

#[test]
fn moov_largesize_child_after_trak_is_rejected() {
    let mut p = trak(90_000);
    p.extend_from_slice(&raw_header(1, b"mvex"));
    p.extend_from_slice(&[0; 8]);
    let f = file_with_moov(mk_box(b"moov", &p));
    assert_eq!(run(&f), Err(Mp4BoxError::LargeSize));
}

#[test]
fn traf_child_before_tfhd_exceeding_parent_is_rejected() {
    let mut p = raw_header(0x100, b"sdtp");
    p.extend_from_slice(&tfhd(0x02_0000, &[]));
    let bad = mk_box(b"traf", &p);
    let f = cat(&[ftyp(), moov(90_000), moof_trafs(&[bad]), mdat()]);
    assert!(matches!(run(&f), Err(Mp4BoxError::ExceedsParent { .. })));
}

#[test]
fn moof_child_after_traf_with_size_zero_is_rejected() {
    let mut p = mk_box(b"mfhd", &[0; 8]);
    p.extend_from_slice(&traf(&[tfhd(0x02_0000, &[]), trun_writer(&[3000])]));
    p.extend_from_slice(&raw_header(0, b"free"));
    let f = cat(&[ftyp(), moov(90_000), mk_box(b"moof", &p), mdat()]);
    assert_eq!(run(&f), Err(Mp4BoxError::InvalidSize(0)));
}

#[test]
fn moov_without_trak_reports_missing_mdhd() {
    let f = file_with_moov(mk_box(b"moov", &mk_box(b"mvhd", &[0; 100])));
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("mdhd")));
}

#[test]
fn empty_moov_reports_missing_mdhd() {
    let f = file_with_moov(mk_box(b"moov", &[]));
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("mdhd")));
}

#[test]
fn second_trak_after_a_trak_without_mdhd_is_still_duplicate() {
    let empty_trak = mk_box(b"trak", &[]);
    let f = file_with_moov(mk_box(b"moov", &cat(&[empty_trak, trak(90_000)])));
    assert_eq!(run(&f), Err(Mp4BoxError::DuplicateBox("trak")));
}

#[test]
fn mdhd_nested_too_deep_is_not_found() {
    // moov/trak/mdia/minf/mdhd is not the fixed path.
    let minf = mk_box(b"minf", &mdhd(0, 90_000));
    let trak = mk_box(b"trak", &mk_box(b"mdia", &minf));
    let f = file_with_moov(mk_box(b"moov", &trak));
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("mdhd")));
}

#[test]
fn mdhd_directly_in_trak_is_not_found() {
    let trak = mk_box(b"trak", &mdhd(0, 90_000));
    let f = file_with_moov(mk_box(b"moov", &trak));
    assert_eq!(run(&f), Err(Mp4BoxError::MissingBox("mdhd")));
}

// ------------------------------------------------ top-level ordering

#[test]
fn ftyp_after_fragments_is_duplicate() {
    let f = cat(&[ftyp(), moov(90_000), good_fragment(), ftyp()]);
    assert_eq!(run(&f), Err(Mp4BoxError::DuplicateBox("ftyp")));
}

#[test]
fn mdat_as_first_box_is_rejected() {
    let f = cat(&[mdat(), ftyp(), moov(90_000), good_fragment()]);
    assert!(run(&f).is_err());
}

#[test]
fn second_mdat_after_a_pair_is_misplaced() {
    let f = cat(&[ftyp(), moov(90_000), good_fragment(), mdat()]);
    assert_eq!(run(&f), Err(Mp4BoxError::MisplacedBox("mdat")));
}

#[test]
fn free_between_moof_and_mdat_is_incomplete() {
    let f = cat(&[
        ftyp(),
        moov(90_000),
        moof(&[tfhd(0x02_0000, &[]), trun_writer(&[3000])]),
        mk_box(b"free", &[]),
        mdat(),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::IncompleteFragment));
}

#[test]
fn free_boxes_between_top_level_boxes_are_accepted() {
    let f = cat(&[
        ftyp(),
        mk_box(b"free", &[1, 2, 3]),
        moov(90_000),
        mk_box(b"free", &[]),
        good_fragment(),
        mk_box(b"skip", &[0; 16]),
        good_fragment(),
        mk_box(b"free", &[]),
    ]);
    assert_eq!(
        run(&f),
        Ok(Mp4Summary {
            duration_ms: 67,
            frame_count: 2
        })
    );
}

#[test]
fn ftyp_only_file_is_missing_moov() {
    assert_eq!(run(&ftyp()), Err(Mp4BoxError::MissingBox("moov")));
}

#[test]
fn empty_file_is_missing_ftyp() {
    assert_eq!(run(&[]), Err(Mp4BoxError::MissingBox("ftyp")));
}

#[test]
fn moof_with_zero_samples_then_good_fragment_is_accepted() {
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0x02_0000, &[]), trun_writer(&[])]),
        mdat(),
        cat(&[moof(&[tfhd(0x02_0000, &[]), trun_writer(&[5])]), mdat()]),
    ]);
    assert_eq!(
        run(&f),
        Ok(Mp4Summary {
            duration_ms: 5,
            frame_count: 1
        })
    );
}

// ------------------------------------------------ trun entry_size / rounding

#[test]
fn trun_with_only_sample_size_uses_tfhd_default() {
    // flags 0x200: per-sample size only, entry_size 4, durations from tfhd default.
    let mut tail = Vec::new();
    for _ in 0..3 {
        tail.extend_from_slice(&7u32.to_be_bytes());
    }
    let mut dd = Vec::new();
    dd.extend_from_slice(&1000u32.to_be_bytes());
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0x08, &dd), trun_raw(0x200, 3, &tail)]),
        mdat(),
    ]);
    assert_eq!(
        run(&f),
        Ok(Mp4Summary {
            duration_ms: 3000,
            frame_count: 3
        })
    );
}

#[test]
fn trun_per_sample_duration_overrides_tfhd_default() {
    let mut dd = Vec::new();
    dd.extend_from_slice(&999u32.to_be_bytes());
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0x08, &dd), trun_writer(&[1, 2])]),
        mdat(),
    ]);
    assert_eq!(
        run(&f),
        Ok(Mp4Summary {
            duration_ms: 3,
            frame_count: 2
        })
    );
}

#[test]
fn zero_duration_samples_round_to_minimum_one_ms() {
    let f = cat(&[
        ftyp(),
        moov(90_000),
        moof(&[tfhd(0x02_0000, &[]), trun_writer(&[0, 0, 0])]),
        mdat(),
    ]);
    assert_eq!(
        run(&f),
        Ok(Mp4Summary {
            duration_ms: 1,
            frame_count: 3
        })
    );
}

#[test]
fn ms_overflow_with_timescale_one_is_typed() {
    // ticks near u64::MAX at timescale 1 -> ms > u64::MAX.
    let mut dd = Vec::new();
    dd.extend_from_slice(&u32::MAX.to_be_bytes());
    let f = cat(&[
        ftyp(),
        moov(1),
        moof(&[tfhd(0x08, &dd), trun_raw(0, u32::MAX, &[])]),
        mdat(),
    ]);
    assert_eq!(run(&f), Err(Mp4BoxError::Overflow));
}

// ------------------------------------------------ cost bounds

#[test]
fn one_mib_moof_of_empty_trafs_is_fast() {
    let mut payload = mk_box(b"mfhd", &[0; 8]);
    let empty_traf = mk_box(b"traf", &[]);
    while payload.len() + 8 <= usize::try_from(MAX_PAYLOAD_LEN).unwrap() {
        payload.extend_from_slice(&empty_traf);
    }
    let f = cat(&[
        ftyp(),
        moov(1000),
        mk_box(b"moof", &payload),
        mdat(),
        good_fragment(),
    ]);
    let t = Instant::now();
    let r = run(&f);
    // Runaway work takes minutes or more; the bound only has to beat that, not host load (TEST-5).
    assert!(t.elapsed() < Duration::from_secs(60));
    assert_eq!(r.map(|s| s.frame_count), Ok(1));
}

#[test]
fn one_mib_traf_of_many_truns_is_fast_and_summed() {
    let mut dd = Vec::new();
    dd.extend_from_slice(&1u32.to_be_bytes());
    let mut children = vec![tfhd(0x08, &dd)];
    let t1 = trun_raw(0, 1, &[]);
    let mut n = 0u64;
    let mut used = 8 + 8 + 8 + 16; // mfhd + traf hdr + tfhd
    while used + t1.len() + 8 < usize::try_from(MAX_PAYLOAD_LEN).unwrap() {
        children.push(t1.clone());
        used += t1.len();
        n += 1;
    }
    let f = cat(&[ftyp(), moov(1000), moof(&children), mdat()]);
    let t = Instant::now();
    let r = run(&f);
    // Runaway work takes minutes or more; the bound only has to beat that, not host load (TEST-5).
    assert!(t.elapsed() < Duration::from_secs(60));
    assert_eq!(
        r,
        Ok(Mp4Summary {
            duration_ms: n,
            frame_count: n
        })
    );
}

// ------------------------------------------------ single-track consistency

/// The moov side rejects a second `trak` (single video track). A `moof` carrying two
/// `traf`s (a second track's fragment) is summed into the one track's totals, doubling
/// `frame_count` and duration.
#[test]
#[ignore = "follow-up #96"]
fn moof_with_two_trafs_is_rejected_like_two_traks() {
    let t = traf(&[tfhd(0x02_0000, &[]), trun_writer(&[3000])]);
    let f = cat(&[ftyp(), moov(90_000), moof_trafs(&[t.clone(), t]), mdat()]);
    assert!(
        matches!(run(&f), Err(Mp4BoxError::DuplicateBox(_))),
        "got {:?}",
        run(&f)
    );
}

#[test]
#[ignore = "follow-up #96"]
fn traf_with_two_tfhd_is_rejected() {
    let mut a = Vec::new();
    a.extend_from_slice(&1u32.to_be_bytes());
    let mut b = Vec::new();
    b.extend_from_slice(&1_000_000u32.to_be_bytes());
    let f = cat(&[
        ftyp(),
        moov(1000),
        moof(&[tfhd(0x08, &a), tfhd(0x08, &b), trun_raw(0, 1, &[])]),
        mdat(),
    ]);
    assert!(
        matches!(run(&f), Err(Mp4BoxError::DuplicateBox(_))),
        "got {:?}",
        run(&f)
    );
}

#[test]
#[ignore = "follow-up #96"]
fn mdia_with_two_mdhd_is_rejected() {
    let trak = mk_box(
        b"trak",
        &mk_box(b"mdia", &cat(&[mdhd(0, 1000), mdhd(0, 90_000)])),
    );
    let f = file_with_moov(mk_box(b"moov", &trak));
    assert!(
        matches!(run(&f), Err(Mp4BoxError::DuplicateBox(_))),
        "got {:?}",
        run(&f)
    );
}
