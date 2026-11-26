//! Tests with synthetic values only.

use std::io::{self, Read, Write};

use wardenlens_core::entry::{EntryId, EntryKind};

use super::{MARKER, RedactError, Redactor};

const PASS: &str = "Tr0ub4dor&3-synthetic";
const OTHER: &str = "synthetic-other-secret";

fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

fn redactor(items: &[(&str, EntryKind, Option<&str>, &str)]) -> Redactor {
    let v: Vec<_> = items
        .iter()
        .map(|(i, k, u, s)| (id(i), *k, *u, *s))
        .collect();
    Redactor::new(&v).unwrap()
}

fn secret(value: &str) -> Redactor {
    redactor(&[("tok:a", EntryKind::Secret, None, value)])
}

/// A reader that hands out at most `n` bytes per call.
struct Slow<'a>(&'a [u8], usize);

impl Read for Slow<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.len().min(self.1).min(buf.len());
        let (head, tail) = self.0.split_at(n);
        buf[..n].copy_from_slice(head);
        self.0 = tail;
        Ok(n)
    }
}

fn run(r: &Redactor, input: &[u8], read_size: usize, chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    r.filter_with(Slow(input, read_size), &mut out, chunk)
        .unwrap();
    out
}

fn marked(s: &str) -> Vec<u8> {
    s.replace('#', std::str::from_utf8(MARKER).unwrap())
        .into_bytes()
}

/// Every way of cutting the input: read sizes and chunk sizes from 1 up to past its length.
fn all_cuts(r: &Redactor, input: &[u8], want: &[u8]) {
    for read_size in 1..=input.len().saturating_add(2) {
        for chunk in [1, 2, 3, 5, 7, 8, 64, 65_536] {
            assert_eq!(
                run(r, input, read_size, chunk),
                want,
                "read {read_size} chunk {chunk}"
            );
        }
    }
}

#[test]
fn a_value_is_replaced_whatever_the_chunking() {
    let r = secret(PASS);
    let input = format!("rtsp login {PASS} done");
    all_cuts(&r, input.as_bytes(), &marked("rtsp login # done"));
}

/// A reader that returns each segment in its own read (empty segments are skipped).
struct Segments(std::collections::VecDeque<Vec<u8>>);

impl Read for Segments {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while let Some(mut seg) = self.0.pop_front() {
            if seg.is_empty() {
                continue;
            }
            let n = seg.len().min(buf.len());
            buf[..n].copy_from_slice(&seg[..n]);
            if n < seg.len() {
                self.0.push_front(seg.split_off(n));
            }
            return Ok(n);
        }
        Ok(0)
    }
}

#[test]
fn a_value_split_at_every_position_is_still_found() {
    let r = secret(PASS);
    let input = format!("aa{PASS}bb");
    for cut in 0..=input.len() {
        let (a, b) = input.as_bytes().split_at(cut);
        let mut out = Vec::new();
        let reader = Segments([a.to_vec(), b.to_vec()].into());
        r.filter_with(reader, &mut out, 4096).unwrap();
        assert_eq!(out, marked("aa#bb"), "cut {cut}");
    }
}

#[test]
fn every_form_the_vault_knows_is_replaced() {
    let r = secret("pa ss/word-synthetic");
    let forms = [
        "pa ss/word-synthetic",
        "pa%20ss%2Fword-synthetic",
        "pa%20ss%2fword-synthetic",
        "pa+ss%2Fword-synthetic",
    ];
    for f in forms {
        let input = format!("x {f} y");
        all_cuts(&r, input.as_bytes(), &marked("x # y"));
    }
}

#[test]
fn matching_ignores_ascii_case() {
    let r = secret(PASS);
    let input = PASS.to_ascii_uppercase();
    assert_eq!(run(&r, input.as_bytes(), 3, 4), marked("#"));
}

#[test]
fn overlapping_secrets_are_one_marker_and_leave_no_tail() {
    let r = redactor(&[
        ("tok:a", EntryKind::Secret, None, "abcdefghij"),
        ("tok:b", EntryKind::Secret, None, "ghijklmnop"),
    ]);
    // The values overlap on "ghij": all of "abcdefghijklmnop" goes.
    all_cuts(&r, b"[abcdefghijklmnop]", &marked("[#]"));
    // The longer needle wins over a prefix of it.
    let r = redactor(&[
        ("tok:a", EntryKind::Secret, None, "abcdefg"),
        ("tok:b", EntryKind::Secret, None, "abcdefghijk"),
    ]);
    all_cuts(&r, b"-abcdefghijk-", &marked("-#-"));
}

#[test]
fn touching_matches_join_into_one_marker_whatever_the_chunking() {
    let r = secret(PASS);
    let input = format!("{PASS}{PASS}!");
    all_cuts(&r, input.as_bytes(), &marked("#!"));
}

#[test]
fn a_run_longer_than_the_overlap_stays_one_marker() {
    let r = secret("aaaaaaaa");
    let input = "a".repeat(100);
    all_cuts(&r, input.as_bytes(), &marked("#"));
}

#[test]
fn binary_input_passes_through_byte_for_byte_around_a_match() {
    let r = secret(PASS);
    let mut input: Vec<u8> = (0..=255u8).collect();
    input.extend_from_slice(PASS.as_bytes());
    input.extend_from_slice(&[0, 0xff, 0xfe, 0x80]);
    let mut want: Vec<u8> = (0..=255u8).collect();
    want.extend_from_slice(MARKER);
    want.extend_from_slice(&[0, 0xff, 0xfe, 0x80]);
    all_cuts(&r, &input, &want);
}

#[test]
fn an_empty_vault_copies_everything() {
    let r = Redactor::new(&[]).unwrap();
    assert_eq!(r.needle_count(), 0);
    let input: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();
    assert_eq!(run(&r, &input, 7, 100), input);
    assert_eq!(run(&r, b"", 1, 1), b"");
}

#[test]
fn no_match_means_identical_output() {
    let r = secret(PASS);
    let input = b"nothing to hide here, just text. Tr0ub4dor&3 is only part of it";
    all_cuts(&r, input, input);
}

#[test]
fn the_marker_reveals_no_length_and_no_entry() {
    let a = secret("short-secret-7");
    let b = secret("a-much-longer-synthetic-secret-value-of-forty-bytes");
    let out_a = run(&a, b"short-secret-7", 64, 64);
    let out_b = run(
        &b,
        b"a-much-longer-synthetic-secret-value-of-forty-bytes",
        64,
        64,
    );
    assert_eq!(out_a, MARKER);
    assert_eq!(out_a, out_b);
}

#[test]
fn a_credential_redacts_the_password_and_the_whole_userinfo() {
    let r = redactor(&[("cam:x:login", EntryKind::Credential, Some("admin"), PASS)]);
    // The short username is public text; the userinfo form is replaced as one.
    all_cuts(
        &r,
        b"rtsp://admin:Tr0ub4dor&3-synthetic@192.0.2.9:554/s",
        &marked("rtsp://#192.0.2.9:554/s"),
    );
    let r = redactor(&[("cam:x:login", EntryKind::Credential, Some("admin"), PASS)]);
    let enc = "rtsp://admin:Tr0ub4dor%263-synthetic@h/p";
    let out = run(&r, enc.as_bytes(), 5, 5);
    assert_eq!(out, marked("rtsp://#h/p"));
    // A lone "admin" is not replaced.
    assert_eq!(run(&r, b"admin is here", 64, 64), b"admin is here");
}

#[test]
fn a_long_username_is_replaced_on_its_own() {
    let r = redactor(&[(
        "cam:x:login",
        EntryKind::Credential,
        Some("synthetic-operator"),
        PASS,
    )]);
    assert_eq!(
        run(&r, b"user synthetic-operator ok", 64, 64),
        marked("user # ok")
    );
}

#[test]
fn hosts_and_macs_are_replaced_in_their_text_forms() {
    let r = redactor(&[
        ("cam:x:host", EntryKind::Host, None, "192.0.2.77"),
        ("cam:x:mac", EntryKind::Mac, None, "AA:BB:CC:00:11:22"),
    ]);
    let input = "ip 192.0.2.77 mac aa-bb-cc-00-11-22 and AABBCC001122";
    all_cuts(&r, input.as_bytes(), &marked("ip # mac # and #"));
}

#[test]
fn a_short_entry_is_listed_and_never_replaced() {
    let r = redactor(&[
        ("tok:short", EntryKind::Secret, None, "abc"),
        ("tok:a", EntryKind::Secret, None, PASS),
    ]);
    assert_eq!(r.unredactable().len(), 1);
    assert_eq!(run(&r, b"abc abc", 64, 64), b"abc abc");
}

#[test]
fn memory_stays_bounded_on_a_long_input() {
    // 3 MiB of input with a secret every 1000 bytes, read 4096 at a time.
    let r = secret(PASS);
    let mut input = Vec::new();
    let mut want = Vec::new();
    for _ in 0..3000 {
        input.extend(std::iter::repeat_n(b'.', 1000));
        input.extend_from_slice(PASS.as_bytes());
        want.extend(std::iter::repeat_n(b'.', 1000));
        want.extend_from_slice(MARKER);
    }
    assert_eq!(run(&r, &input, 4096, 4096), want);
}

struct FailRead;
impl Read for FailRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("boom"))
    }
}

struct FailWrite;
impl Write for FailWrite {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Flaky(bool, Vec<u8>);
impl Read for Flaky {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.0 {
            self.0 = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = self.1.len().min(buf.len());
        buf[..n].copy_from_slice(&self.1[..n]);
        self.1.drain(..n);
        Ok(n)
    }
}

#[test]
fn io_errors_are_typed_and_carry_no_value() {
    let r = secret(PASS);
    let e = r.filter(FailRead, Vec::new()).unwrap_err();
    assert!(matches!(e, RedactError::Read(_)));
    let e = r.filter(&b"hello"[..], FailWrite).unwrap_err();
    assert!(matches!(e, RedactError::Write(_)));
    assert!(!format!("{e:?}{e}").contains(PASS));
    // An interrupted read is retried, not an error.
    let mut out = Vec::new();
    r.filter(Flaky(false, PASS.as_bytes().to_vec()), &mut out)
        .unwrap();
    assert_eq!(out, MARKER);
}

#[test]
fn debug_output_shows_counts_not_needles() {
    let r = redactor(&[
        ("tok:a", EntryKind::Secret, None, PASS),
        ("tok:b", EntryKind::Secret, None, OTHER),
    ]);
    let d = format!("{r:?}");
    assert!(!d.contains(PASS) && !d.contains(OTHER), "{d}");
}
