//! Round-2 adversarial tests for the catalogue site-data guard, parser and matrix.
//! Every test states behaviour that should hold if the guard does what its docs claim.

use wardenlens_core::catalogue::{
    CatalogueEntry, CatalogueError, check_source, render_matrix, validate,
};

const EV: &str = "[[evidence]]\nreference=\"docs/adr/0002-camera-integration.md\"\n";

fn entry_text(extra: &str) -> String {
    format!("vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n{extra}\n{EV}")
}

/// Parse + validate a TOML entry, the full pipeline a caller (and the gate test) runs.
fn full(toml: &str) -> Result<(), CatalogueError> {
    CatalogueEntry::from_toml_str(toml).and_then(|e| validate(&e))
}

/// A quirk written as a TOML literal string (no escapes).
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

// ---- Encodings: claimed fixed in round 2 ----

#[test]
fn invisible_default_ignorable_characters_inside_an_ipv4_are_rejected() {
    // All render as nothing; the address reads as 192.168.1.20.
    let inputs = [
        "host 192.168\u{034F}.1.20",  // combining grapheme joiner
        "host 192.168\u{FE0F}.1.20",  // variation selector-16
        "host 192.168\u{180B}.1.20",  // mongolian free variation selector
        "host 192.168\u{3164}.1.20",  // hangul filler
        "host 192.168\u{115F}.1.20",  // hangul choseong filler
        "host 192.168\u{1D173}.1.20", // musical symbol begin beam (Cf)
        "host 192.168\u{E0100}.1.20", // variation selector-17
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted via entry: {bad:?}");
}

#[test]
fn dot_and_at_lookalikes_are_rejected() {
    let inputs = [
        "host 192\u{3002}168\u{3002}1\u{3002}20", // ideographic full stop
        "host 192\u{2024}168\u{2024}1\u{2024}20", // one dot leader
        "host 192\u{FE52}168\u{FE52}1\u{FE52}20", // small full stop
        "login admin:hunter2\u{FE6B}cam",         // small commercial at
        "rtsp://admin\u{2236}hunter2\u{FE6B}cam/x", // ratio + small at
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
fn ascii_control_escapes_cannot_split_an_ipv4_in_a_parsed_string() {
    // The raw line shows `\u0000`, the parsed value has a NUL between octets; neither scan
    // sees a dotted quad. Control characters have no place in catalogue text.
    let mut bad = Vec::new();
    for esc in ["\\u0000", "\\u0008", "\\u001F", "\\u007F", "\\u001B"] {
        let toml = entry_text(&format!("quirks=[\"host 192.168{esc}.1.20\"]"));
        if full(&toml).is_ok() {
            bad.push(esc);
        }
    }
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
fn control_characters_in_vendor_do_not_reach_the_readme() {
    // An ESC sequence in a model name would be written verbatim into cameras/README.md.
    // The escaped spelling is refused outright (every backslash is, rework 2); the entry is
    // then built as a struct so `validate` still has to reject the control character itself.
    let toml = "vendor=\"A\\u001B[2J\"\nmodel=\"B\"\nsupport=\"verified\"\n[[evidence]]\nreference=\"x\"\n";
    assert!(CatalogueEntry::from_toml_str(toml).is_err());
    let toml = "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n[[evidence]]\nreference=\"x\"\n";
    let mut e = CatalogueEntry::from_toml_str(toml).unwrap();
    e.vendor = "A\u{1B}[2J".to_owned();
    assert!(
        validate(&e).is_err(),
        "control character accepted in vendor: {:?}",
        render_matrix(&[e])
    );
}

// ---- Credentials ----

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn json_style_secret_pairs_are_rejected() {
    let inputs = [
        r#"login body {"password":"hunter2"}"#,
        r#"body {"user": "admin", "pwd": "x"}"#,
        r"send 'token': 'abc'",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn other_common_secret_keys_are_rejected() {
    let inputs = [
        "passphrase=hunter2",
        "apikey=abc",
        "api_key=abc",
        "pin=4711",
        "login=admin",
        "credentials=admin",
        "accesstoken=abc",
        "userpass=x",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn url_encoded_secret_pair_is_rejected() {
    let inputs = ["/x?q=password%3Dhunter2", "password&#61;hunter2"];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

// ---- IPv4 / MAC / serial forms ----

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn defanged_and_alternate_separator_ipv4_is_rejected() {
    let inputs = [
        "camera 192[.]168[.]1[.]20",
        "host ip-192-168-1-20",
        "host 192_168_1_20",
        "subnet 192.168.x.x",
        "octal 0300.0250.0001.0024",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn mac_with_dot_pairs_or_unpadded_groups_is_rejected() {
    let inputs = ["mac a4.5e.60.0b.11.2c", "mac 0-1b-63-84-45-e6"];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn serial_key_value_pairs_are_rejected() {
    let inputs = ["serial=x9k2m4p7q1", "sn: x9k2m4p7q1", "uid=a1b2c3d4"];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn ddns_hostnames_are_rejected() {
    let inputs = [
        "cam at myhouse.duckdns.org",
        "nvr.ddns.net",
        "x.tplinkdns.com",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn ipv4_split_across_two_comment_lines_is_rejected() {
    let toml = format!("# camera at 192.168.\n# 1.20\n{}", entry_text(""));
    assert!(full(&toml).is_err(), "split address in comments accepted");
}

// ---- False positives on legitimate catalogue content ----

#[test]
fn real_vendor_model_names_are_accepted() {
    // Current Hikvision G2P and Dahua EP/T1P model names, as printed by the vendors.
    let models = [
        "DS-2CD2T87G2P-LSU",
        "DS-2CD2387G2P-LSU",
        "IPC-HDBW2431EP-S-0280B",
        "IPC-HFW3849T1P-AS-PV",
    ];
    let mut bad = Vec::new();
    for m in models {
        let toml = format!("vendor=\"V\"\nmodel=\"{m}\"\nsupport=\"community\"\n{EV}");
        if let Err(e) = full(&toml) {
            bad.push(format!("{m}: {e}"));
        }
    }
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

#[test]
fn legitimate_quirk_prose_is_accepted() {
    let inputs = [
        "RTSP auth: digest only, basic is refused.",
        "Fixed in firmware built from commit 0123456789abcdef0123456789abcdef01234567.",
        "Toggle it under Settings.Home in the app.",
        "Default user: the account created in the app.",
    ];
    let bad: Vec<String> = inputs
        .iter()
        .filter_map(|q| quirk(q).err().map(|e| format!("{q:?}: {e}")))
        .collect();
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

// ---- Matrix ----

#[test]
fn backslash_before_pipe_cannot_break_a_matrix_cell() {
    // A backslash in the source is refused (rework 2); the renderer must still escape one that
    // reaches it through a struct.
    assert!(
        CatalogueEntry::from_toml_str("vendor='A\\|B'\nmodel=\"M\"\nsupport=\"partial\"\n")
            .is_err()
    );
    let toml = "vendor='A'\nmodel=\"M\"\nsupport=\"partial\"\n";
    let mut e = CatalogueEntry::from_toml_str(toml).unwrap();
    e.vendor = "A\\|B".to_owned();
    let m = render_matrix(&[e]);
    let row = m.lines().last().unwrap();
    // 9 unescaped pipes = 8 columns.
    let bytes = row.as_bytes();
    let unescaped = (0..bytes.len())
        .filter(|&i| {
            bytes[i] == b'|' && {
                let bs = bytes[..i].iter().rev().take_while(|&&b| b == b'\\').count();
                bs % 2 == 0
            }
        })
        .count();
    assert_eq!(unescaped, 9, "{row}");
}

// ---- Must hold (coverage) ----

#[test]
fn toml_escapes_hiding_ipv4_in_every_string_field_are_caught() {
    let hidden = "192\\u002e168\\u002e1\\u002e20";
    for extra in [
        format!("aliases=[\"{hidden}\"]"),
        format!("quirks=[\"{hidden}\"]"),
        format!("[[protocols]]\nkind=\"rtsp\"\npaths=[\"/{hidden}\"]"),
    ] {
        let toml = entry_text(&extra);
        assert!(
            matches!(full(&toml), Err(CatalogueError::SiteData { .. })),
            "{extra}"
        );
    }
    let toml = format!(
        "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n[[evidence]]\nreference=\"x\"\nsection=\"{hidden}\"\n"
    );
    assert!(matches!(full(&toml), Err(CatalogueError::SiteData { .. })));
    let toml = format!("vendor=\"{hidden}\"\nmodel=\"B\"\nsupport=\"verified\"\n{EV}");
    assert!(matches!(full(&toml), Err(CatalogueError::SiteData { .. })));
}

#[test]
fn multiline_string_line_continuation_cannot_hide_ipv4() {
    let toml = entry_text("quirks=[\"\"\"host 192.168.\\\n   1.20\"\"\"]");
    assert!(matches!(full(&toml), Err(CatalogueError::SiteData { .. })));
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn crlf_entry_files_parse_and_are_scanned() {
    let toml = entry_text("# 10.0.0.1").replace('\n', "\r\n");
    assert!(matches!(
        CatalogueEntry::from_toml_str(&toml),
        Err(CatalogueError::SiteData { .. })
    ));
    let clean = entry_text("").replace('\n', "\r\n");
    assert!(full(&clean).is_ok());
}

#[test]
fn duplicate_keys_and_wrong_types_are_rejected() {
    for extra in [
        "support=\"partial\"",
        "aliases=\"XR\"",
        "quirks=[1]",
        "[[streams]]\nrole=\"main\"\ncodec=\"h264\"\nwidth=1.5\nheight=1",
        "evidence=[{reference=\"x\", Reference=\"y\"}]",
    ] {
        assert!(
            CatalogueEntry::from_toml_str(&entry_text(extra)).is_err(),
            "{extra}"
        );
    }
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn vendor_json_login_bodies_with_credentials_are_rejected() {
    // Reolink HTTP API and Tapo local API login bodies are JSON; a quirk quoting one leaks the
    // password. Same key: value form as round-1 finding 2, with the key quoted.
    let inputs = [
        r#"Login body [{"cmd":"Login","param":{"User":{"userName":"admin","password":"hunter2"}}}]"#,
        r#"Tapo login {"method":"login","params":{"username":"admin","password":"hunter2"}}"#,
    ];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}
