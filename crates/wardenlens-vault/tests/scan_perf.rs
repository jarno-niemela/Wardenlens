//! Performance of the scan: under 1 s for 1 MB of text with a realistic vault (ADR 0006 section
//! 7, ticket #75).
//!
//! The regular test uses a bound that only a super-linear algorithm can miss, on inputs built
//! to be the worst case for each tokeniser, so it never flakes on a slow machine. The strict
//! 1 s bound runs on demand: `cargo test -p wardenlens-vault --release --test scan_perf -- --ignored --nocapture`.

#![expect(
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::arithmetic_side_effects,
    reason = "test helpers outside #[test] fns; the bench prints its timing"
)]

use std::time::Instant;

use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_vault::{Matcher, ScanEntry, scan};

fn vault_of(n: usize) -> Matcher {
    let mut entries = Vec::new();
    let mut add = |name: String, kind: EntryKind, value: String| {
        entries.push(ScanEntry {
            id: EntryId::new(&name).unwrap(),
            kind,
            value: SecretString::from(value),
            unscannable: false,
        });
    };
    for i in 0..n {
        match i % 6 {
            0 => add(
                format!("cam:{i}:host"),
                EntryKind::Host,
                format!("192.0.{}.{}", i % 250, i % 200 + 1),
            ),
            1 => add(
                format!("cam:{i}:v6"),
                EntryKind::Host,
                format!("2001:db8::{i:x}"),
            ),
            2 => add(
                format!("cam:{i}:mac"),
                EntryKind::Mac,
                format!("02:00:5e:00:{:02x}:{:02x}", i / 256, i % 256),
            ),
            3 => add(
                format!("cam:{i}:pw"),
                EntryKind::Secret,
                format!("Tr0ub4dor-{i:05}-horse-battery"),
            ),
            4 => add(
                format!("cam:{i}:name"),
                EntryKind::DisplayName,
                format!("Back Door North {i:04}"),
            ),
            _ => add(
                format!("cam:{i}:dns"),
                EntryKind::Host,
                format!("nvr-{i}.example.invalid"),
            ),
        }
    }
    Matcher::new(&entries).unwrap()
}

/// Roughly log-like text: words, numbers, addresses that are not in the vault, JSON and
/// percent-encoding, so every view is built.
fn typical(len: usize) -> Vec<u8> {
    let line = "2026-11-24T10:00:01Z INFO cam stream ok host=198.51.100.7 mac=aa:bb:cc:dd:ee:ff \
                v6=2001:db8:ffff::9 {\"user\":\"svc\",\"note\":\"Front%20Gate \\\"x\\\" \\u2013 caf\u{e9}\"} \
                Tr0ub4dor-00007-horse-batterz Back Door Nortx 0123\n";
    line.as_bytes().iter().copied().cycle().take(len).collect()
}

fn run(m: &Matcher, text: &[u8]) -> f64 {
    let start = Instant::now();
    let r = scan(m, text).unwrap();
    std::hint::black_box(&r);
    start.elapsed().as_secs_f64()
}

fn worst_cases(len: usize) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("typical", typical(len)),
        (
            "one needle everywhere",
            b"Tr0ub4dor-00003-horse-battery "
                .iter()
                .copied()
                .cycle()
                .take(len)
                .collect(),
        ),
        ("colons", b":".iter().copied().cycle().take(len).collect()),
        (
            "hex and colons",
            b"ab:cd:".iter().copied().cycle().take(len).collect(),
        ),
        (
            "digit dots",
            b"1.2.3.4.".iter().copied().cycle().take(len).collect(),
        ),
        (
            "percent",
            b"%41%zz%".iter().copied().cycle().take(len).collect(),
        ),
        (
            "backslashes",
            b"\\u00\\".iter().copied().cycle().take(len).collect(),
        ),
        ("newlines", vec![b'\n'; len]),
        ("invalid utf-8", vec![0xFF; len]),
        (
            "wrapped name",
            b"Back\n    Door\n  North 0003\n"
                .iter()
                .copied()
                .cycle()
                .take(len)
                .collect(),
        ),
    ]
}

/// Debug builds are 10 to 50 times slower than release; 256 KiB at this bound can only be missed
/// by an algorithm that is quadratic (or worse) in the input.
#[test]
fn scan_time_is_not_super_linear_on_worst_case_inputs() {
    let m = vault_of(50);
    for (name, text) in worst_cases(256 * 1024) {
        let secs = run(&m, &text);
        assert!(secs < 30.0, "{name}: {secs:.2} s for 256 KiB");
    }
}

#[test]
#[ignore = "wall-clock bench: run with --release --ignored --nocapture"]
fn one_megabyte_with_fifty_entries_takes_under_a_second() {
    let m = vault_of(50);
    let mut worst = 0.0f64;
    for (name, text) in worst_cases(1024 * 1024) {
        let secs = run(&m, &text);
        eprintln!("scan 1 MiB, 50 entries, {name}: {:.0} ms", secs * 1000.0);
        worst = worst.max(secs);
    }
    assert!(worst < 1.0, "worst case {worst:.2} s");
}
