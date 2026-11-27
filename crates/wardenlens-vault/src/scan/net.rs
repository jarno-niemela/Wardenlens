//! Single-pass tokenisers for IPv4, IPv6 and MAC values (ADR 0006 section 7). The stored values
//! are 32, 128 and 48 bit numbers in hash sets; the text is tokenised and each candidate is
//! converted to a number and looked up, so mixed separators never explode a needle set.
//!
//! Every function works on bytes and never slices a `str`. Work per input byte is bounded:
//! an IPv6 run costs at most `2 * 23` parses of at most 45 bytes each.

use std::collections::HashMap;
use std::net::Ipv6Addr;

/// Owners (indices into the matcher's entry list) of one stored number.
pub(super) type Owners = Vec<u32>;

/// A callback for a hit: the owners and the byte range `start..end` of the token.
pub(super) type Hit<'a> = &'a mut dyn FnMut(&[u32], usize, usize);

/// The longest tail of an IPv6 run tried as a sub-run (a full address is at most 45 bytes).
const IPV6_TAIL: usize = 45;

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn nibble(b: u8) -> u64 {
    match b {
        b'0'..=b'9' => u64::from(b.saturating_sub(b'0')),
        b'a'..=b'f' => u64::from(b.saturating_sub(b'a')).saturating_add(10),
        b'A'..=b'F' => u64::from(b.saturating_sub(b'A')).saturating_add(10),
        _ => 0,
    }
}

fn digits(b: &[u8], start: usize) -> usize {
    let mut i = start;
    while b.get(i).is_some_and(u8::is_ascii_digit) {
        i = i.saturating_add(1);
    }
    i
}

/// The offset after one IPv4 separator at `at`: `.`, `-`, `_`, `[.]`, `(.)` or `{.}`.
fn ipv4_separator_end(b: &[u8], at: usize) -> Option<usize> {
    match *b.get(at)? {
        b'.' | b'-' | b'_' => Some(at.saturating_add(1)),
        b'[' | b'(' | b'{' => {
            let close = match b.get(at)? {
                b'[' => b']',
                b'(' => b')',
                _ => b'}',
            };
            (b.get(at.saturating_add(1)) == Some(&b'.')
                && b.get(at.saturating_add(2)) == Some(&close))
            .then_some(at.saturating_add(3))
        }
        _ => None,
    }
}

/// IPv4: dotted fields in chains, 32-bit decimal and hex.
pub(super) fn ipv4(b: &[u8], stored: &HashMap<u32, Owners>, hit: Hit<'_>) {
    if stored.is_empty() {
        return;
    }
    let mut look = |n: u32, at: usize, end: usize| {
        if let Some(owners) = stored.get(&n) {
            hit(owners, at, end);
        }
    };
    // Fields (1 to 3 digits, at most 255) joined by exactly one separator form a chain; every
    // four consecutive fields are a window.
    let mut window = [0u8; 4];
    let mut starts = [0usize; 4];
    let mut count = 0usize;
    let mut expect: Option<usize> = None;
    let mut i = 0;
    while i < b.len() {
        if !b.get(i).is_some_and(u8::is_ascii_digit) {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        i = digits(b, start);
        let run = b.get(start..i).unwrap_or_default();
        if (8..=10).contains(&run.len()) {
            let v = run.iter().fold(0u64, |a, &d| {
                a.saturating_mul(10)
                    .saturating_add(u64::from(d.saturating_sub(b'0')))
            });
            if let Ok(n) = u32::try_from(v) {
                look(n, start, i);
            }
        }
        let field = (run.len() <= 3)
            .then(|| {
                run.iter().fold(0u32, |a, &d| {
                    a.saturating_mul(10)
                        .saturating_add(u32::from(d.saturating_sub(b'0')))
                })
            })
            .and_then(|v| u8::try_from(v).ok());
        let Some(v) = field else {
            count = 0;
            expect = None;
            continue;
        };
        if expect != Some(start) {
            count = 0;
        }
        window.rotate_left(1);
        starts.rotate_left(1);
        window[3] = v;
        starts[3] = start;
        count = count.saturating_add(1).min(4);
        if count == 4 {
            look(u32::from_be_bytes(window), starts[0], i);
        }
        expect = ipv4_separator_end(b, i);
    }
    // Bare hex: a maximal run of exactly 8 hex digits (so `0x` plus 8 digits is found too).
    let mut i = 0;
    while i < b.len() {
        if !b.get(i).copied().is_some_and(is_hex) {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        while b.get(i).copied().is_some_and(is_hex) {
            i = i.saturating_add(1);
        }
        let run = b.get(start..i).unwrap_or_default();
        if run.len() == 8 {
            let v = run.iter().fold(0u64, |a, &d| a.wrapping_shl(4) | nibble(d));
            if let Ok(n) = u32::try_from(v) {
                look(n, start, i);
            }
        }
    }
}

fn is_run_byte(b: u8) -> bool {
    is_hex(b) || b == b':' || b == b'.'
}

/// Parses `candidate` and looks the address up, and an IPv4-mapped one among the IPv4 values.
fn look_ipv6(
    candidate: &[u8],
    at: usize,
    v6: &HashMap<u128, Owners>,
    v4: &HashMap<u32, Owners>,
    hit: Hit<'_>,
) {
    let Some(addr) = std::str::from_utf8(candidate)
        .ok()
        .and_then(|t| t.parse::<Ipv6Addr>().ok())
    else {
        return;
    };
    let end = at.saturating_add(candidate.len());
    if let Some(owners) = v6.get(&u128::from(addr)) {
        hit(owners, at, end);
    }
    if let Some(mapped) = addr.to_ipv4_mapped()
        && let Some(owners) = v4.get(&u32::from(mapped))
    {
        hit(owners, at, end);
    }
}

/// One trimming of a run: the whole variant, then every suffix that starts at a group boundary
/// within its last 45 bytes and ends where the variant ends. Never a prefix.
fn try_variant(
    run: &[u8],
    base: usize,
    v6: &HashMap<u128, Owners>,
    v4: &HashMap<u32, Owners>,
    hit: Hit<'_>,
) {
    if run.is_empty() {
        return;
    }
    look_ipv6(run, base, v6, v4, hit);
    for p in run.len().saturating_sub(IPV6_TAIL)..run.len() {
        let boundary = p == 0 || p.checked_sub(1).and_then(|q| run.get(q)) == Some(&b':');
        if boundary && let Some(tail) = run.get(p..) {
            look_ipv6(tail, base.saturating_add(p), v6, v4, hit);
        }
    }
}

/// IPv6 runs: maximal runs of hex digits, `:` and `.` with at least two colons. The whole run,
/// the run without trailing dots and the run without trailing colons and dots are each tried,
/// with their suffix sub-runs; a later step never depends on an earlier one parsing.
pub(super) fn ipv6(b: &[u8], v6: &HashMap<u128, Owners>, v4: &HashMap<u32, Owners>, hit: Hit<'_>) {
    if v6.is_empty() && v4.is_empty() {
        return;
    }
    let mut i = 0;
    while i < b.len() {
        if !b.get(i).copied().is_some_and(is_run_byte) {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        while b.get(i).copied().is_some_and(is_run_byte) {
            i = i.saturating_add(1);
        }
        let run = b.get(start..i).unwrap_or_default();
        if run.iter().filter(|&&c| c == b':').take(2).count() < 2 {
            continue;
        }
        let dots = run.len().saturating_sub(trailing(run, |c| c == b'.'));
        let both = run
            .len()
            .saturating_sub(trailing(run, |c| c == b'.' || c == b':'));
        for end in [run.len(), dots, both] {
            try_variant(run.get(..end).unwrap_or_default(), start, v6, v4, hit);
        }
    }
}

/// The number of trailing bytes of `run` for which `pred` holds.
fn trailing(run: &[u8], pred: impl Fn(u8) -> bool) -> usize {
    run.iter().rev().take_while(|&&c| pred(c)).count()
}

/// Length in bytes of the UTF-8 sequence that starts with `lead` (1 for a byte that cannot
/// start one). The sequence is not validated: this only decides how far a separator reaches.
fn char_len(lead: u8) -> usize {
    match lead {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 1,
    }
}

type Group = (usize, usize);

/// The 12 hex digits of the last `groups` (one-digit groups zero-padded when `pad`).
fn mac_number(b: &[u8], groups: &[Group], pad: bool) -> u64 {
    let mut acc = 0u64;
    for &(s, e) in groups {
        let g = b.get(s..e).unwrap_or_default();
        if pad && g.len() == 1 {
            acc = acc.wrapping_shl(4);
        }
        for &d in g {
            acc = acc.wrapping_shl(4) | nibble(d);
        }
    }
    acc
}

/// MAC: hex groups joined by one separator character each (any non-hex character), as 6 groups
/// of 1 or 2 digits, 3 of 4, 2 of 6 or 1 of 12. A group is a maximal run of hex digits.
pub(super) fn mac(b: &[u8], stored: &HashMap<u64, Owners>, hit: Hit<'_>) {
    if stored.is_empty() {
        return;
    }
    let mut look = |n: u64, at: usize, end: usize| {
        if let Some(owners) = stored.get(&n) {
            hit(owners, at, end);
        }
    };
    let mut ring: [Group; 6] = [(0, 0); 6];
    let mut count = 0usize;
    let mut expect: Option<usize> = None;
    let mut i = 0;
    while i < b.len() {
        if !b.get(i).copied().is_some_and(is_hex) {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        while b.get(i).copied().is_some_and(is_hex) {
            i = i.saturating_add(1);
        }
        if expect != Some(start) {
            count = 0;
        }
        ring.rotate_left(1);
        ring[5] = (start, i);
        count = count.saturating_add(1).min(6);
        expect = b.get(i).map(|&sep| i.saturating_add(char_len(sep)));
        let len = |k: usize| {
            ring.get(6usize.saturating_sub(k))
                .map(|g| g.1.saturating_sub(g.0))
        };
        let tail = |k: usize| ring.get(6usize.saturating_sub(k)..).unwrap_or_default();
        if len(1) == Some(12) {
            look(mac_number(b, tail(1), false), start, i);
        }
        let first = |k: usize| tail(k).first().map_or(start, |g| g.0);
        if count >= 2 && tail(2).iter().all(|g| g.1.saturating_sub(g.0) == 6) {
            look(mac_number(b, tail(2), false), first(2), i);
        }
        if count >= 3 && tail(3).iter().all(|g| g.1.saturating_sub(g.0) == 4) {
            look(mac_number(b, tail(3), false), first(3), i);
        }
        if count >= 6
            && tail(6)
                .iter()
                .all(|g| (1..=2).contains(&g.1.saturating_sub(g.0)))
        {
            look(mac_number(b, tail(6), true), first(6), i);
        }
    }
}
