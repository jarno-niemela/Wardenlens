//! One table holding every found and not-found example of ticket #75 (all its amendment
//! rounds) and ADR 0006 sections 7 and 8. Each row names its source.

use wardenlens_core::entry::EntryKind;
use wardenlens_core::entry::EntryKind::{
    Credential, DisplayName, Host, Mac, Other, Secret, Serial,
};

use super::{esc, lines};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expect {
    /// The value is found on line 1.
    Found,
    /// Not found (a defined non-match or a documented gap).
    Missing,
}
use Expect::{Found, Missing};

struct Row {
    source: &'static str,
    kind: EntryKind,
    stored: &'static str,
    text: &'static str,
    expect: Expect,
}

const fn row(
    source: &'static str,
    kind: EntryKind,
    stored: &'static str,
    text: &'static str,
    expect: Expect,
) -> Row {
    Row {
        source,
        kind,
        stored,
        text,
        expect,
    }
}

const V4: &str = "192.0.2.10";
const V6: &str = "2001:db8::1";
const MAC: &str = "02:00:5e:00:53:af";
const DNS: &str = "nvr-1.example.invalid";
const SERIAL: &str = "SN-0042-ZQ";
const NAME: &str = "Back Door North";
const DASH_NAME: &str = "Garage \u{2013} Side";
const HYPHEN_NAME: &str = "Garage - Side";
const PW: &str = "correct-horse-9";
const SPECIAL: &str = "pa ss/w0rd!x";
const JSON_PW: &str = "pa\"ss\u{2013}word";

fn ipv4_rows() -> Vec<Row> {
    let s = "ADR 7 host IPv4 worked example";
    let mut rows: Vec<Row> = [
        "192.0.2.10",
        "192-0-2-10",
        "192_0_2_10",
        "192[.]0[.]2[.]10",
        "192.000.002.010",
        "192.0.2.10:554",
        "rtsp://192.0.2.10/stream",
        "\u{FF11}\u{FF19}\u{FF12}\u{FF0E}\u{FF10}\u{FF0E}\u{FF12}\u{FF0E}\u{FF11}\u{FF10}",
        "192%2E0%2E2%2E10",
        "3221225994",
        "0xC000020A",
        "c000020a",
    ]
    .into_iter()
    .map(|t| row(s, Host, V4, t, Found))
    .collect();
    let s = "ADR 7 host IPv4 field form";
    rows.extend(
        [
            "192(.)0{.}2.10",
            "10.192.0.2.10",
            "ip=192.0.2.10,",
            "0xc000020a",
            "192.0.2-10",
        ]
        .into_iter()
        .map(|t| row(s, Host, V4, t, Found)),
    );
    let s = "ADR 7 host IPv4 not found";
    rows.extend(
        [
            "192.0.2.100",
            "192.0.2.1",
            "192.0.2",
            "192 0 2 10",
            "0300.0.02.012",
            "192.0.2.x",
            "1192.0.2.10",
            "192.0.2.256",
            "32212259941",
            "0x1C000020A",
            "c000020a1",
        ]
        .into_iter()
        .map(|t| row(s, Host, V4, t, Missing)),
    );
    let s = "ADR 8 gap list, IPv4 renderings";
    rows.extend(
        [
            "Ipv4Addr::new(192, 0, 2, 10)",
            "[192, 0, 2, 10]",
            "c0.00.02.0a",
            "192&#46;0&#46;2&#46;10",
            "192%252E0%252E2%252E10",
            "64:ff9b::c000:20a",
        ]
        .into_iter()
        .map(|t| row(s, Host, V4, t, Missing)),
    );
    rows
}

fn mapped_rows() -> Vec<Row> {
    let found = "ADR 7 / #75 r1, r4 IPv4-mapped IPv6 of a stored IPv4";
    let mut rows: Vec<Row> = ["::ffff:c000:20a", "::ffff:c000:20a.", "::ffff:192.0.2.10"]
        .into_iter()
        .map(|t| row(found, Host, V4, t, Found))
        .collect();
    rows.push(row(
        "ADR 7 / #75 r4 not found",
        Host,
        V4,
        "::ffff:192.0.2.100",
        Missing,
    ));
    rows
}

fn ipv6_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    let s = "ADR 7 / #75 amendment, r2, r4 IPv6 found for 2001:db8::1";
    for t in [
        "2001:db8::1",
        "2001:0DB8:0:0:0:0:0:1",
        "2001:db8::0.0.0.1",
        "2001:db8::1.",
        "addr:2001:db8::1",
        "Source:2001:db8::1",
        "beef:2001:db8::1",
        "[2001:db8::1]:8080",
        "2001:db8::1%eth0",
    ] {
        rows.push(row(s, Host, V6, t, Found));
    }
    let s = "ADR 7 / #75 r4 IPv6 not found for 2001:db8::1";
    for t in [
        "2001:db8::10",
        "2001:db8::1:2",
        "2001:db8::1234",
        "cafe2001:db8::1",
        "2001:db8::1:554",
        "1.2001:db8::1",
    ] {
        rows.push(row(s, Host, V6, t, Missing));
    }
    let s = "ADR 7 / #75 r5 trailing :: kept (untrimmed and trimmed)";
    rows.push(row(s, Host, "1:2::", "1:2::.", Found));
    rows.push(row(s, Host, "1:2::", "1:2::", Found));
    let s = "ADR 7 / #75 amendment, r2 IPv6 found for fe80::1";
    for t in ["fe80::1:", "Interface:fe80::1", "dead:fe80::1"] {
        rows.push(row(s, Host, "fe80::1", t, Found));
    }
    rows.push(row(
        "ADR 7 / #75 r4 IPv6 not found for fe80::1",
        Host,
        "fe80::1",
        "fe80::1ff:fe23:4567:890a",
        Missing,
    ));
    rows
}

fn mac_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    let s = "ADR 7 / #75 amendment MAC found";
    for t in [
        "02:00:5e:00:53:af",
        "02-00-5E-00-53-AF",
        "0200.5e00.53af",
        "02_00_5e_00_53_af",
        "02 00 5e 00 53 af",
        "02005e0053af",
        "0200 5e00 53af",
        "02:00-5e.00_53 af",
        "2:0:5e:0:53:af",
        "02/00/5e/00/53/af",
    ] {
        rows.push(row(s, Mac, MAC, t, Found));
    }
    let s = "ADR 7 MAC not found";
    for t in [
        "02:00:5e:00:53",
        "02005e0053af11",
        "02:00:5e:00:53:ae",
        "02: 00: 5e: 00: 53: af",
        "02x00x5e",
        "[0x02, 0x00, 0x5e, 0x00, 0x53, 0xaf]",
    ] {
        rows.push(row(s, Mac, MAC, t, Missing));
    }
    rows
}

fn name_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    let s = "ADR 7 host DNS found";
    for t in [
        "NVR-1.Example.INVALID",
        "http://nvr-1.example.invalid:8080/",
        "nvr-1.example.invalid.",
        "a.nvr-1.example.invalid",
    ] {
        rows.push(row(s, Host, DNS, t, Found));
    }
    let s = "ADR 7 host DNS not found";
    for t in [
        "xnvr-1.example.invalid",
        "nvr-1.example.invalid-backup",
        "nvr-1",
        "nvr-1[.]example[.]invalid",
    ] {
        rows.push(row(s, Host, DNS, t, Missing));
    }
    let s = "ADR 7 serial found";
    for t in ["sn-0042-zq", "SN0042ZQ", "sn0042zq", "Serial: SN-0042-ZQ."] {
        rows.push(row(s, Serial, SERIAL, t, Found));
    }
    let s = "ADR 7 serial not found";
    for t in ["SN 0042 ZQ", "XSN-0042-ZQ"] {
        rows.push(row(s, Serial, SERIAL, t, Missing));
    }
    let s = "ADR 7 display-name found";
    for t in [
        "back   door north",
        "BACK DOOR NORTH",
        "back-door-north",
        "back_door_north",
        "BackDoorNorth",
        "Back Door\n    North",
        "Back Door\r\nNorth",
        "Back Door North.",
    ] {
        rows.push(row(s, DisplayName, NAME, t, Found));
    }
    let s = "ADR 7 display-name not found / not handled";
    for t in [
        "Door North",
        "Back Door Northwest",
        "xBack Door North",
        "Back+Door+North",
        "Back Door\n# North",
        "Back Door\n> North",
    ] {
        rows.push(row(s, DisplayName, NAME, t, Missing));
    }
    rows.push(row(
        s,
        Other,
        "12 Example Lane",
        "12   EXAMPLE\n  lane",
        Found,
    ));
    rows.push(row(s, Other, "5550100", "555 0100", Missing));
    rows
}

fn dash_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    let s = "#75 r5 / ADR 7 en dash display name Garage - Side";
    for t in [
        "Garage \u{2013} Side",
        "Garage - Side",
        "GARAGE - SIDE",
        "Garage%20-%20Side",
        "Garage%20%E2%80%93%20Side",
        concat!("Garage ", esc!("2013"), " Side"),
    ] {
        rows.push(row(s, DisplayName, DASH_NAME, t, Found));
    }
    let s = "#75 r5 / ADR 7 secret pa\"ss<en dash>word in a JSON log";
    for t in [
        "\"password\":\"pa\\\"ss\u{2013}word\"",
        concat!("\"password\":\"pa\\\"ss", esc!("2013"), "word\""),
    ] {
        rows.push(row(s, Secret, JSON_PW, t, Found));
    }
    let s = "PR 77 confirmation pass, documented gaps (squeeze-table character in the wrong place)";
    rows.push(row(
        s,
        DisplayName,
        HYPHEN_NAME,
        concat!("Garage ", esc!("2013"), " Side"),
        Missing,
    ));
    rows.push(row(
        s,
        DisplayName,
        HYPHEN_NAME,
        "Garage%20%E2%80%93%20Side",
        Missing,
    ));
    rows.push(row(
        s,
        DisplayName,
        DASH_NAME,
        concat!("Garage%20", esc!("2013"), "%20Side"),
        Missing,
    ));
    rows.push(row(
        s,
        DisplayName,
        HYPHEN_NAME,
        "Garage \u{2013} Side",
        Found,
    ));
    rows
}

fn secret_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    let s = "ADR 7 secret forms (raw, percent, form, every-byte, hex, base64, XML)";
    for (stored, t) in [
        (PW, "xxcorrect-horse-9yy"),
        (SPECIAL, "pa%20ss%2Fw0rd%21x"),
        (SPECIAL, "pa%20ss%2fw0rd%21x"),
        (SPECIAL, "pa+ss%2Fw0rd%21x"),
        (SPECIAL, "%70%61%20%73%73%2F%77%30%72%64%21%78"),
        (SPECIAL, "%70%61%20%73%73%2f%77%30%72%64%21%78"),
        (SPECIAL, "70612073732f773072642178"),
        (SPECIAL, "70612073732F773072642178"),
        (PW, "Authorization: Basic dXNlcjpjb3JyZWN0LWhvcnNlLTk="),
        (PW, "Y29ycmVjdC1ob3JzZS05"),
        (PW, "AGNvcnJlY3QtaG9yc2UtOQ"),
        (PW, "AABjb3JyZWN0LWhvcnNlLTk"),
        ("a>b?c>d?e~", "YT5iP2M+ZD9lfg=="),
        ("a>b?c>d?e~", "YT5iP2M-ZD9lfg"),
        ("a>b?c>d?e~", "E-Yj9jPmQ_ZX"),
        ("a>b?c>d?e~", "hPmI/Yz5kP2V+"),
        ("a<b&c'd\"e>f", "a&lt;b&amp;c&apos;d&quot;e&gt;f"),
        ("pass%77%30rd9", "pass%2577%2530rd9"),
        ("passw0rd9", "pass%77%30rd9"),
        ("abcd\nefgh", "abcd%0Aefgh"),
        ("abcd\nefgh", "abcd%0aefgh"),
        ("abcdefgh", "abcd\u{200B}efgh"),
        (
            "password1",
            "\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}\u{FF11}",
        ),
        (
            "r&d'k3yz!",
            concat!("r", esc!("0026"), "d", esc!("0027"), "k3yz!"),
        ),
        ("s3cretpw", concat!("s", esc!("0033"), "cretpw")),
    ] {
        rows.push(row(s, Secret, stored, t, Found));
    }
    rows.push(row(s, Credential, "Tr0ub4dor-x9", "pw=Tr0ub4dor-x9", Found));
    let s = "ADR 7 / 8 secret not found (case-sensitive, gap list)";
    for (stored, t) in [
        ("Passw0rdX", "passw0rdx"),
        ("abcdefgh", "hgfedcba"),
        ("abcdefgh", "abcdefg"),
        ("abcdefgh", "abcd%E2%80%8Befgh"),
        ("abcdefgh", concat!("abcd", esc!("200b"), "efgh")),
        ("abcdefgh", "abcd%0Aefgh"),
        (
            "correct-horse-9",
            "63 6f 72 72 65 63 74 2d 68 6f 72 73 65 2d 39",
        ),
        ("ab$cdefg", "ab\\$cdefg"),
        ("abcd\nefgh", "abcd\\nefgh"),
        ("abcd\nefgh", concat!("abcd", esc!("000a"), "efgh")),
        (
            JSON_PW,
            concat!("pa\"ss", esc!("2013"), "w", esc!("200b"), "ord"),
        ),
    ] {
        rows.push(row(s, Secret, stored, t, Missing));
    }
    rows.push(row(
        "ADR 7 lookalike and normalisation gaps",
        DisplayName,
        NAME,
        "B\u{0430}ck Door North",
        Missing,
    ));
    rows.push(row(
        "ADR 8 gap 4 (NFD against NFC)",
        Other,
        "Caf\u{E9} Garage",
        "Cafe\u{301} Garage",
        Missing,
    ));
    rows
}

fn all_rows() -> Vec<Row> {
    let mut rows = ipv4_rows();
    rows.extend(mapped_rows());
    rows.extend(ipv6_rows());
    rows.extend(mac_rows());
    rows.extend(name_rows());
    rows.extend(dash_rows());
    rows.extend(secret_rows());
    rows
}

#[test]
fn every_ticket_and_adr_example_is_found_or_missing_as_specified() {
    let rows = all_rows();
    assert!(rows.len() > 150, "the table lost rows: {}", rows.len());
    let found = rows.iter().filter(|r| r.expect == Found).count();
    assert!(
        found > 60 && rows.len() - found > 50,
        "unbalanced table: {found} of {}",
        rows.len()
    );
    for r in &rows {
        let got = lines(r.kind, r.stored, r.text.as_bytes());
        match r.expect {
            Found => assert!(
                got.contains(&1),
                "[{}] expected a hit for stored {:?} in {:?}, got {got:?}",
                r.source,
                r.stored,
                r.text
            ),
            Missing => {
                assert!(
                    got.is_empty(),
                    "[{}] unexpected hit for stored {:?} in {:?}: {got:?}",
                    r.source,
                    r.stored,
                    r.text
                );
                // The matcher is live for this entry: the stored value itself, appended after
                // the text, is found, and on exactly the line after the text's lines.
                let control = format!("{}\n{}", r.text, r.stored);
                let want = r.text.matches('\n').count() + 2;
                assert_eq!(
                    lines(r.kind, r.stored, control.as_bytes()),
                    vec![want],
                    "[{}] control for stored {:?}",
                    r.source,
                    r.stored
                );
            }
        }
    }
}
