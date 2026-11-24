//! Round-3 adversarial tests for the catalogue site-data guard.
//! Every test states behaviour that should hold if the guard does what its docs claim.

use wardenlens_core::catalogue::{CatalogueEntry, CatalogueError, check_source, validate};

const EV: &str = "[[evidence]]\nreference=\"docs/adr/0002-camera-integration.md\"\n";

fn entry_text(extra: &str) -> String {
    format!("vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n{extra}\n{EV}")
}

fn full(toml: &str) -> Result<(), CatalogueError> {
    CatalogueEntry::from_toml_str(toml).and_then(|e| validate(&e))
}

fn quirk(q: &str) -> Result<(), CatalogueError> {
    full(&entry_text(&format!("quirks=['''{q}''']")))
}

fn accepted(inputs: &[&str], f: impl Fn(&str) -> Result<(), CatalogueError>) -> Vec<String> {
    inputs
        .iter()
        .filter(|i| f(i).is_ok())
        .map(|i| format!("{i:?}"))
        .collect()
}

fn rejected(inputs: &[&str], f: impl Fn(&str) -> Result<(), CatalogueError>) -> Vec<String> {
    inputs
        .iter()
        .filter_map(|i| f(i).err().map(|e| format!("{i:?}: {e}")))
        .collect()
}

// ---- Credentials ----

/// ONVIF WS-Security `UsernameToken` and Hikvision ISAPI bodies are XML. The element form carries
/// the secret between tags rather than after `=` or `:`.
#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn xml_element_credentials_are_rejected() {
    let inputs = [
        "<Password>hunter2</Password>",
        "<wsse:Username>admin</wsse:Username><wsse:Password>hunter2</wsse:Password>",
        "<userName>admin</userName><password>hunter2</password>",
        "<token>abc</token>",
    ];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted in raw source: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn compound_secret_keys_are_rejected() {
    let inputs = [
        "secret_key=abc",
        "user_name=admin",
        "passcode=4711",
        "psk=hunter2hunter2",
        "wpa_psk=hunter2",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn other_separators_and_entities_between_key_and_secret_are_rejected() {
    let inputs = [
        "password => hunter2",
        "password -> hunter2",
        "password%20=%20hunter2",
        "password&#x3D;hunter2",
        "admin&#58;hunter2&#64;cam",
        "password\\u003dhunter2",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

/// `admin:x` in an HTTP Basic header is short enough to slip under the serial rule.
#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn short_basic_auth_header_is_rejected() {
    let inputs = [
        "Authorization: Basic YWRtaW46eA==",
        "Authorization: Basic YTpi",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

// ---- Encodings: the allow-list admits alphabetic characters that look like punctuation ----

/// U+A4F8 LISU LETTER TONE MYA TI looks like `.`, U+A4FD LISU LETTER TONE MYA JEU and U+02D0
/// MODIFIER LETTER TRIANGULAR COLON look like `:`. All three are `Lm`, so `is_alphabetic`.
#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn alphabetic_punctuation_lookalikes_are_rejected() {
    let inputs = [
        "camera 192\u{A4F8}168\u{A4F8}1\u{A4F8}20",
        "mac a4\u{A4FD}5e\u{A4FD}60\u{A4FD}00\u{A4FD}11\u{A4FD}22",
        "login admin\u{02D0}hunter2@cam",
        "password\u{02D0}hunter2",
        "fe80\u{02D0}\u{02D0}1",
    ];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

/// `Nl` letter numbers (Roman numerals) are alphabetic, so they pass the allow-list as digits.
#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn letter_number_digits_are_rejected() {
    let inputs = ["camera \u{2160}92.\u{2160}68.\u{2160}.20"];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

// ---- IPv4 partials ----

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn ipv4_with_wildcard_in_an_inner_group_is_rejected() {
    let inputs = ["camera 192.168.x.20", "camera 10.0.*.5"];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

// ---- False positives on legitimate catalogue prose ----

#[test]
fn stream_specs_with_at_sign_are_accepted() {
    let inputs = [
        "Sub stream is 640x360@15fps.",
        "Main stream 1920x1080p30 by default.",
    ];
    let bad = rejected(&inputs, quirk);
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

#[test]
fn protocol_constants_are_accepted() {
    let inputs = [
        // ONVIF WS-Discovery multicast group, a protocol constant, not site data.
        "WS-Discovery probes go to 239.255.255.250 port 3702.",
        // Baichuan magic header.
        "Baichuan frames start with magic 0x0abcdef0.",
    ];
    let bad = rejected(&inputs, quirk);
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

#[test]
fn secret_words_in_descriptive_prose_are_accepted() {
    let inputs = [
        "Login token: expires after one hour.",
        "PIN: four digits, set in the app.",
        "login: required before any CGI call.",
        "Login body shape: {\"User\":{\"userName\":\"<user>\",\"password\":\"<password>\"}}",
    ];
    let bad = rejected(&inputs, quirk);
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

// ---- Robustness ----

/// The realistic hand-pasted forms that carry a plaintext password in XML: ONVIF `CreateUsers`
/// and WS-Security `PasswordText`.
#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn onvif_plaintext_password_bodies_are_rejected() {
    let inputs = [
        "CreateUsers body <tt:User><tt:Username>admin</tt:Username><tt:Password>hunter2</tt:Password><tt:UserLevel>Administrator</tt:UserLevel></tt:User>",
        "<wsse:UsernameToken><wsse:Username>admin</wsse:Username><wsse:Password Type=\"#PasswordText\">hunter2</wsse:Password></wsse:UsernameToken>",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
fn guard_does_not_panic_on_multibyte_boundaries() {
    let tricky = [
        "%3\u{00E9}",
        "%\u{00E9}",
        "&#6\u{00E9}",
        "password\u{00E9}=x",
        "0x\u{00E9}",
        "\u{00E9}:\u{00E9}:\u{00E9}:\u{00E9}",
        "://\u{00E9}@",
        "\u{00E9}.lan",
    ];
    for t in tricky {
        let _ = check_source(t);
        let _ = quirk(t);
    }
    let long = "password=".repeat(7000);
    let _ = check_source(&long);
    let long = "0x".repeat(30_000);
    let _ = check_source(&long);
    let long = "%3d".repeat(20_000);
    let _ = check_source(&long);
}

#[test]
fn unknown_fields_rejected_at_every_level() {
    for extra in [
        "serial=\"x\"",
        "[[streams]]\nrole=\"main\"\ncodec=\"h264\"\nwidth=1\nheight=1\nbitrate=1",
        "[[protocols]]\nkind=\"rtsp\"\nhost=\"x\"",
        "[[events]]\nkind=\"motion\"\nsource=\"cgi\"\nstatus=\"observed\"\nnote=\"x\"",
        "[[evidence]]\nreference=\"x\"\nurl=\"y\"",
        "firmware=[{major=1, minor=0}]",
        "configurable=[\"ptz\"]",
        "support=\"verified\"",
    ] {
        assert!(full(&entry_text(extra)).is_err(), "{extra}");
    }
}
