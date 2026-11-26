//! Adversary tests for #166 round 3 (PR #167): the per-document work budget and the single-pass
//! delimiter cache. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "integration-test helpers and a test oracle outside #[test] fns, where clippy.toml's in-tests allowances do not reach"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use proptest::prelude::*;
use wardenlens_agentdvr::{ImportError, MAX_INPUT_BYTES, MAX_LOGIN_WORK, parse};
use wardenlens_core::camera::ends_with_credential_param_name;

fn xml(body: &str) -> String {
    format!("<objects><cameras>{body}</cameras></objects>")
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// --- Oracle: the round-2 candidate walk, written independently of the cache. ---

fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let h = |o: usize| b.get(i + o).and_then(|c| char::from(*c).to_digit(16));
        if b[i] == b'%'
            && let (Some(hi), Some(lo)) = (h(1), h(2))
        {
            out.push(u8::try_from(hi * 16 + lo).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn oracle(raw: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let mut push = |v: &str| {
        for x in [v, v.trim()] {
            if !x.trim().is_empty() {
                set.insert(x.to_owned());
            }
        }
    };
    let mut both = |p: &str| {
        push(p);
        if p.contains('%')
            && let Some(d) = decode(p)
        {
            push(&d);
        }
    };
    let s = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    match rest.split_once(':') {
        Some((u, after)) if after.contains('@') => both(u),
        _ => both(""),
    }
    let colon = rest.find(':');
    for (at, _) in rest.match_indices('@') {
        match colon {
            Some(c) if c < at => both(&rest[c + 1..at]),
            _ => both(&rest[..at]),
        }
    }
    for (eq, _) in s.match_indices('=') {
        if !ends_with_credential_param_name(&s[..eq]) {
            continue;
        }
        let value = &s[eq + 1..];
        let to_amp = value.find('&').map_or(value, |i| &value[..i]);
        let to_delim = to_amp
            .find(['/', '?', '#', '@', ';'])
            .map_or(to_amp, |i| &to_amp[..i]);
        both(to_amp);
        both(to_delim);
    }
    set
}

fn logins_of_source(src: &str) -> BTreeSet<String> {
    let doc = xml(&format!(
        "<camera id=\"1\" name=\"A\"><settings><videosourcestring>{}</videosourcestring>\
         </settings></camera>",
        esc(src)
    ));
    parse(doc.as_bytes())
        .unwrap()
        .logins
        .iter()
        .map(str::to_owned)
        .collect()
}

fn piece() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "=", "&", "/", "?", "#", "@", ";", ":", "%41", "%", " ", "_", "-", "p", "pw", "pass",
        "user", "x", "é", "rtsp://", "token", "u",
    ])
    .prop_map(str::to_owned)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn the_cached_delimiter_walk_equals_the_naive_oracle(
        parts in prop::collection::vec(piece(), 0..40)
    ) {
        let src: String = parts.concat();
        prop_assert_eq!(logins_of_source(&src), oracle(&src), "source {:?}", src);
    }
}

#[test]
fn the_oracle_reaches_the_cached_branch() {
    // Two credential `=` before the same `&` and delimiter: the second reuses the cache.
    let src = "rtsp://192.0.2.1/s?pw=a;p=b/c&u=d";
    let got = logins_of_source(src);
    assert_eq!(got, oracle(src));
    for want in ["a;p=b/c", "a", "b/c", "b", "d"] {
        assert!(got.contains(want), "{want}");
    }
}

// --- The budget boundary: exact, -1 and +1 (TEST-8). ---

/// The work of one document, from the public counter.
fn work_of(doc: &str) -> Result<usize, ImportError> {
    parse(doc.as_bytes()).map(|i| i.logins.work())
}

/// A document of `n` distinct `@`-heavy sources (charge grows quadratically per source), then a
/// pad login of `pad` bytes of `q`, unique.
fn budget_doc(n: u32, pad: usize) -> String {
    let ats = "@".repeat(1000);
    let mut f = String::new();
    for i in 0..n {
        let _ = write!(f, "<videosourcestring>u:{ats}h{i}</videosourcestring>");
    }
    if pad > 0 {
        let _ = write!(f, "<login>{}</login>", "q".repeat(pad));
    }
    xml(&format!(
        "<camera id=\"1\" name=\"A\"><settings>{f}</settings></camera>"
    ))
}

#[test]
fn the_work_budget_is_exact() {
    // Find the most sources that fit, then pad with a unique login (3 units a byte: collected
    // hash, push, direct hash) to land on the budget exactly.
    let mut n = 1_u32;
    while work_of(&budget_doc(n + 1, 0)).is_ok() {
        n += 1;
    }
    let base = work_of(&budget_doc(n, 0)).unwrap();
    let per_pad_byte = work_of(&budget_doc(n, 2)).unwrap() - work_of(&budget_doc(n, 1)).unwrap();
    assert_eq!(per_pad_byte, 3);
    let room = MAX_LOGIN_WORK - base;
    let pad = room / 3;
    assert!(pad > 0, "room {room}");
    let at = work_of(&budget_doc(n, pad)).unwrap();
    assert!(at <= MAX_LOGIN_WORK && MAX_LOGIN_WORK - at < 3);
    // A pad byte more takes it past the budget unless `at` already sat below by >= 3.
    assert_eq!(
        work_of(&budget_doc(n, pad + 1)).unwrap_err(),
        ImportError::TooManyLogins
    );
}

// --- No legitimate document hits the budget. ---

/// 256 cameras, each with a 4 KiB-class realistic source, a login and a password, padded with
/// other settings up to 8 MiB: a large but ordinary file.
#[test]
fn a_maximal_ordinary_document_stays_well_inside_the_budget() {
    let mut body = String::new();
    let filler = "<x>".to_owned() + &"z".repeat(20_000) + "</x>";
    for i in 1..=256_u32 {
        let long_path = "seg/".repeat(900);
        let _ = write!(
            body,
            "<camera id=\"{i}\" name=\"Cam {i}\"><settings>\
             <videosourcestring>rtsp://user{i}:p%40ss{i}@192.0.2.{h}:554/{long_path}s?ch=1&amp;sub=0\
             </videosourcestring><login>user{i}</login><password>p@ss{i}</password>\
             {filler}</settings></camera>",
            h = i % 250 + 1
        );
    }
    let doc = xml(&body);
    assert!(doc.len() <= MAX_INPUT_BYTES, "{}", doc.len());
    let import = parse(doc.as_bytes()).unwrap();
    let work = import.logins.work();
    assert!(work < MAX_LOGIN_WORK / 4, "work {work}");
}
