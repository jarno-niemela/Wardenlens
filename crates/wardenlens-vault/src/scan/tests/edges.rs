//! Boundaries (6, 7 and 8 bytes), line numbers, deduplication across entries, caps, file
//! classification and SEC-6 (no value reaches any rendering).

use std::fmt::Write as _;

use wardenlens_core::entry::EntryKind;
use wardenlens_core::entry::EntryKind::{DisplayName, Host, Other, Secret, Serial};

use super::{entry, esc, hits, lines, matcher};
use crate::scan::{
    Content, MAX_HITS, MAX_INPUT_LEN, Matcher, ScanEntry, ScanError, classify, scan,
};

fn scannable(kind: EntryKind, value: &str) -> bool {
    let m = matcher(&[entry("e:one", kind, value)]);
    m.unscannable().is_empty() && m.scanned_len() == 1
}

#[test]
fn stored_secret_minimum_is_seven_bytes() {
    assert!(!scannable(Secret, "abcdef"));
    assert!(scannable(Secret, "abcdefg"));
    assert!(scannable(Secret, "abcdefgh"));
    // The unscannable one is never matched, even in its own raw form.
    assert_eq!(lines(Secret, "abcdef", b"abcdef"), Vec::<usize>::new());
    assert_eq!(lines(Secret, "abcdefg", b"abcdefg"), vec![1]);
    assert_eq!(lines(Secret, "abcdefgh", b"abcdefgh"), vec![1]);
}

#[test]
fn squeezed_needle_minimum_is_seven_bytes() {
    // Raw length is 9, 10 and 11 bytes; the squeezed needle is 6, 7 and 8.
    let zw = "\u{200B}";
    assert!(!scannable(Secret, &format!("ab{zw}cdef")));
    assert!(scannable(Secret, &format!("ab{zw}cdefg")));
    assert!(scannable(Secret, &format!("ab{zw}cdefgh")));
    assert!(!scannable(Secret, &format!("{zw}{zw}{zw}{zw}{zw}{zw}{zw}")));
    assert_eq!(lines(Secret, &format!("ab{zw}cdefg"), b"abcdefg"), vec![1]);
}

#[test]
fn serial_minimum_is_seven_bytes_of_the_compact_form() {
    assert!(!scannable(Serial, "AB-1234"));
    assert!(scannable(Serial, "AB-12345"));
    assert!(scannable(Serial, "AB-123456"));
    assert_eq!(lines(Serial, "AB-12345", b"ab12345"), vec![1]);
}

#[test]
fn display_name_needs_every_slug_at_seven_bytes() {
    assert!(!scannable(DisplayName, "ab cdef"));
    assert!(scannable(DisplayName, "ab cdefg"));
    assert!(scannable(DisplayName, "ab cdefgh"));
    assert!(!scannable(Other, "abcdef"));
    assert!(scannable(Other, "abcdefg"));
}

#[test]
fn host_minimums_are_seven_dotted_and_eight_single_label() {
    assert!(!scannable(Host, "a.b.cd"));
    assert!(scannable(Host, "a.b.cde"));
    assert!(!scannable(Host, "nvr-1ab"));
    assert!(scannable(Host, "nvr-1abc"));
    // IP and MAC values have fixed formats and are exempt.
    assert!(scannable(Host, "0.0.0.1"));
    assert!(scannable(Host, "::1"));
    assert!(scannable(EntryKind::Mac, "02:00:5e:00:53:af"));
}

#[test]
fn unscannable_entries_are_listed_by_id_and_kind_and_the_store_flag_is_honoured() {
    let mut flagged = entry("e:public", Secret, "long-enough-secret");
    flagged.unscannable = true;
    let m = matcher(&[
        entry("e:short", Secret, "abc"),
        flagged,
        entry("e:good", Secret, "good-secret-value"),
    ]);
    let listed: Vec<_> = m
        .unscannable()
        .iter()
        .map(|u| (u.id.as_str(), u.kind))
        .collect();
    assert_eq!(listed, vec![("e:short", Secret), ("e:public", Secret)]);
    let r = scan(&m, b"long-enough-secret and good-secret-value").unwrap();
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].id.as_str(), "e:good");
}

#[test]
fn entries_with_equal_values_are_all_reported() {
    let m = matcher(&[
        entry("cam:a:host", Host, "192.0.2.10"),
        entry("cam:b:host", Host, "192.0.2.10"),
        entry("note:a", Other, "nvr-1.example.invalid"),
        entry("cam:c:host", Host, "nvr-1.example.invalid"),
        entry("tok:a", Secret, "shared-secret-1"),
        entry("tok:b", Secret, "shared-secret-1"),
        entry("tok:c", Secret, "shared-secret-1"),
        entry("mac:a", EntryKind::Mac, "02:00:5e:00:53:af"),
        entry("mac:b", EntryKind::Mac, "02-00-5E-00-53-AF"),
        entry("v6:a", Host, "2001:db8::1"),
        entry("v6:b", Host, "2001:DB8:0:0:0:0:0:1"),
    ]);
    let text = "192.0.2.10 nvr-1.example.invalid shared-secret-1 02:00:5e:00:53:af 2001:db8::1";
    let r = scan(&m, text.as_bytes()).unwrap();
    let mut ids: Vec<&str> = r.hits.iter().map(|h| h.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        vec![
            "cam:a:host",
            "cam:b:host",
            "cam:c:host",
            "mac:a",
            "mac:b",
            "note:a",
            "tok:a",
            "tok:b",
            "tok:c",
            "v6:a",
            "v6:b"
        ]
    );
    assert!(r.hits.iter().all(|h| h.line == 1));
}

#[test]
fn a_stored_ipv4_mapped_ipv6_is_also_found_as_its_ipv4_form() {
    assert_eq!(
        lines(Host, "::ffff:192.0.2.10", b"host 192.0.2.10"),
        vec![1]
    );
    assert_eq!(
        lines(Host, "::ffff:192.0.2.10", b"::ffff:c000:20a"),
        vec![1]
    );
}

#[test]
fn each_entry_is_reported_once_per_line_with_the_right_line_number() {
    let text = b"none\nabcdefg abcdefg\n\nx\nabcdefg\r\nabcdefg\rabcdefg";
    // Line 2 holds the value twice (one hit), line 5 ends in CRLF, and the lone `\r` before the
    // last occurrence does not start a line: that occurrence is on line 6 with the one before it.
    assert_eq!(lines(Secret, "abcdefg", text), vec![2, 5, 6]);
    assert_eq!(hits(Secret, "abcdefg", text).len(), 3);
}

#[test]
fn an_encoded_line_break_never_moves_a_hit_to_another_line() {
    // `%0A` and the escapes of U+000A, U+000D, U+0085, U+2028, U+2029 are not decoded, so the
    // decoded and JSON views have the same lines as the text.
    let stored = "pa ss/w0rd!x";
    for t in [
        "a %0A b pa%20ss%2Fw0rd%21x",
        "a %0d b pa%20ss%2Fw0rd%21x",
        "a %C2%85 b pa%20ss%2Fw0rd%21x",
        "a %e2%80%a8 b pa%20ss%2Fw0rd%21x",
        "a %E2%80%A9 b pa%20ss%2Fw0rd%21x",
    ] {
        assert_eq!(lines(Secret, stored, t.as_bytes()), vec![1], "{t}");
    }
    for t in [
        concat!("a ", esc!("000a"), " b pa%20ss%2Fw0rd%21x"),
        concat!("a ", esc!("000D"), " b pa%20ss%2Fw0rd%21x"),
        concat!("a ", esc!("0085"), " b pa%20ss%2Fw0rd%21x"),
        concat!("a ", esc!("2028"), " b pa%20ss%2Fw0rd%21x"),
        concat!("a ", esc!("2029"), " b pa%20ss%2Fw0rd%21x"),
        "a \\n b pa%20ss%2Fw0rd%21x",
    ] {
        assert_eq!(lines(Secret, stored, t.as_bytes()), vec![1], "{t}");
    }
}

#[test]
fn a_wrapped_name_is_reported_at_the_line_where_it_starts() {
    let text = "x\ny\nBack Door\n    North\nz";
    assert_eq!(
        lines(DisplayName, "Back Door North", text.as_bytes()),
        vec![3]
    );
}

#[test]
fn hits_are_capped_and_truncation_is_reported_exactly() {
    let m = matcher(&[entry("e:one", Secret, "abcdefg")]);
    for (n, truncated) in [
        (MAX_HITS - 1, false),
        (MAX_HITS, false),
        (MAX_HITS + 1, true),
    ] {
        let text = "abcdefg\n".repeat(n);
        let r = scan(&m, text.as_bytes()).unwrap();
        assert_eq!(r.hits.len(), n.min(MAX_HITS), "{n}");
        assert_eq!(r.truncated, truncated, "{n}");
    }
}

#[test]
fn input_at_the_cap_is_scanned_and_one_byte_more_is_refused() {
    let m = matcher(&[entry("e:one", Secret, "abcdefg")]);
    let mut text = vec![b' '; MAX_INPUT_LEN];
    text[MAX_INPUT_LEN - 7..].copy_from_slice(b"abcdefg");
    assert_eq!(scan(&m, &text).unwrap().hits.len(), 1);
    text.push(b' ');
    assert!(matches!(scan(&m, &text), Err(ScanError::InputTooLarge)));
}

#[test]
fn too_many_entries_and_too_many_needles_are_refused() {
    let many: Vec<ScanEntry> = (0..=crate::MAX_ENTRIES)
        .map(|i| {
            let mut e = entry(&format!("e:{i}"), Secret, "x");
            e.unscannable = true;
            e
        })
        .collect();
    assert!(matches!(
        Matcher::new(&many),
        Err(ScanError::TooManyEntries)
    ));
    // Each 4096-byte secret expands to well over 100 KiB of needles.
    let big: Vec<ScanEntry> = (0..400)
        .map(|i| {
            entry(
                &format!("e:{i}"),
                Secret,
                &format!("{i:04}{}", "k".repeat(4092)),
            )
        })
        .collect();
    assert!(matches!(
        Matcher::new(&big),
        Err(ScanError::NeedlesTooLarge)
    ));
}

#[test]
fn classify_decodes_utf16_with_a_bom_and_skips_binary() {
    let le: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain("pw abcdefg\nx".encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let be: Vec<u8> = [0xFE, 0xFF]
        .into_iter()
        .chain("pw abcdefg\nx".encode_utf16().flat_map(u16::to_be_bytes))
        .collect();
    for bytes in [le, be] {
        let Content::Text(t) = classify(&bytes) else {
            panic!("a UTF-16 file is text");
        };
        assert_eq!(t.as_ref(), b"pw abcdefg\nx");
        assert_eq!(lines(Secret, "abcdefg", &t), vec![1]);
    }
    // An odd trailing byte is a replacement character, not a panic.
    let Content::Text(t) = classify(&[0xFF, 0xFE, b'a', 0, b'b']) else {
        panic!("text");
    };
    assert_eq!(t.as_ref(), "a\u{FFFD}".as_bytes());
    assert!(matches!(classify(b"ab\0cd"), Content::Binary));
    // The probe covers the first 8 KiB: a NUL at index 8191 is binary, at 8192 it is text.
    let mut data = vec![b'a'; 9000];
    data[8191] = 0;
    assert!(matches!(classify(&data), Content::Binary));
    data[8191] = b'a';
    data[8192] = 0;
    assert!(matches!(classify(&data), Content::Text(_)));
    assert!(matches!(classify(b""), Content::Text(_)));
    assert!(matches!(classify(&[0xFF]), Content::Text(_)));
}

#[test]
fn hits_are_ordered_by_line_then_id() {
    let m = matcher(&[
        entry("b:two", Secret, "second-secret"),
        entry("a:one", Secret, "first-secret"),
    ]);
    let r = scan(&m, b"second-secret first-secret\nfirst-secret").unwrap();
    let got: Vec<(usize, &str)> = r.hits.iter().map(|h| (h.line, h.id.as_str())).collect();
    assert_eq!(got.len(), 3);
    assert!(got.windows(2).all(|w| w[0].0 <= w[1].0));
    assert_eq!(got.last(), Some(&(2, "a:one")));
}

#[test]
fn nothing_printable_holds_a_value_or_a_needle() {
    let secret = "zq-unique-secret-77";
    let ip = "192.0.2.77";
    let m = matcher(&[
        entry("tok:a", Secret, secret),
        entry("cam:a:host", Host, ip),
        entry("cam:a:name", DisplayName, "Zq Unique Name"),
        entry("short", Secret, "zq7"),
    ]);
    let report = scan(&m, format!("{secret} {ip} zq unique name").as_bytes()).unwrap();
    let mut shown = format!("{m:?} {report:?} {:?}", m.unscannable());
    for h in &report.hits {
        write!(shown, "{h:?}").unwrap();
    }
    let source = entry("tok:b", Secret, secret);
    write!(shown, "{source:?}").unwrap();
    let errors = [
        ScanError::InputTooLarge,
        ScanError::TooManyEntries,
        ScanError::NeedlesTooLarge,
        ScanError::Automaton,
        ScanError::Vault(crate::VaultError::WrongKey),
        ScanError::Vault(crate::VaultError::CorruptEntry { id: "tok:a".into() }),
    ];
    for e in &errors {
        write!(shown, "{e} {e:?}").unwrap();
    }
    for needle in [
        secret,
        ip,
        "zq unique name",
        "Zq Unique Name",
        "zq-unique",
        "zq7",
    ] {
        assert!(
            !shown.contains(needle),
            "{needle} reached a rendering: {shown}"
        );
    }
    assert!(shown.contains("tok:a"), "ids are allowed to appear");
}
