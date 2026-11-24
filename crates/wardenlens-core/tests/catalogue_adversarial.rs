//! Adversarial tests for the catalogue parser, site-data guard and matrix.

use wardenlens_core::catalogue::{
    CatalogueEntry, CatalogueError, SiteDataKind, render_matrix, validate,
};

const EV: &str = "[[evidence]]\nreference=\"docs/adr/0002-camera-integration.md\"\n";

fn entry_text(extra: &str) -> String {
    format!("vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n{extra}\n{EV}")
}

// Parse then validate, as a caller would. `from_toml_str` already scans the raw text, so site
// data may be reported by either step; both are `SiteData` errors.
fn quirk(q: &str) -> Result<(), CatalogueError> {
    let toml = entry_text(&format!("quirks=['''{q}''']"));
    CatalogueEntry::from_toml_str(&toml).and_then(|e| validate(&e))
}

fn path(p: &str) -> Result<(), CatalogueError> {
    let toml = entry_text(&format!("[[protocols]]\nkind=\"rtsp\"\npaths=['''{p}''']"));
    CatalogueEntry::from_toml_str(&toml).and_then(|e| validate(&e))
}

fn is_site(r: &Result<(), CatalogueError>) -> bool {
    matches!(r, Err(CatalogueError::SiteData { .. }))
}

// ---- Expected-to-fail attacks (defects) ----

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn comment_in_entry_file_with_private_ip_is_rejected() {
    // Comments are part of the public file but never reach `validate`.
    let toml = format!(
        "# camera is at 192.168.1.20, login admin:hunter2\n{}",
        entry_text("")
    );
    let r = CatalogueEntry::from_toml_str(&toml).and_then(|e| validate(&e));
    assert!(
        is_site(&r),
        "comment with IP and credentials accepted: {r:?}"
    );
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn password_in_query_string_path_is_rejected() {
    let mut bad: Vec<String> = Vec::new();
    for p in [
        "/cgi-bin/api.cgi?cmd=Snap&channel=0&user=admin&password=hunter2",
        "/user=admin&password=Secret1&channel=1&stream=0.sdp",
        "/cam/realmonitor?channel=1&subtype=0&pwd=hunter2",
    ] {
        if !is_site(&path(p)) {
            bad.push(p.to_owned());
        }
    }
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn partial_private_ipv4_is_rejected() {
    let mut bad: Vec<String> = Vec::new();
    for q in ["camera on 192.168.1.x", "subnet 10.0.0.* only"] {
        if !is_site(&quirk(q)) {
            bad.push(q.to_owned());
        }
    }
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn ipv4_with_invisible_or_fullwidth_characters_is_rejected() {
    let mut bad: Vec<String> = Vec::new();
    for q in [
        "host 192.168\u{200B}.1.20",
        "host 192\u{FF0E}168\u{FF0E}1\u{FF0E}20",
        "host \u{FF11}\u{FF19}\u{FF12}.\u{FF11}\u{FF16}\u{FF18}.1.20",
        "host 0xC0A80114",
    ] {
        if !is_site(&quirk(q)) {
            bad.push(q.to_owned());
        }
    }
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn mac_with_space_or_underscore_separators_is_rejected() {
    let mut bad: Vec<String> = Vec::new();
    for q in ["mac a4 5e 60 00 11 22", "mac a4_5e_60_00_11_22"] {
        if !is_site(&quirk(q)) {
            bad.push(q.to_owned());
        }
    }
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn lowercase_or_grouped_serial_is_rejected() {
    let mut bad: Vec<String> = Vec::new();
    for q in ["sn xk3j9q2m7z8w4p", "sn 2J0A-1B2C-3D4E-5F6G"] {
        if !is_site(&quirk(q)) {
            bad.push(q.to_owned());
        }
    }
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
fn matrix_is_independent_of_input_order_for_equal_slugs() {
    let a =
        CatalogueEntry::from_toml_str(&entry_text("").replace("vendor=\"A\"", "vendor=\"Acme\""))
            .unwrap();
    let b =
        CatalogueEntry::from_toml_str(&entry_text("").replace("vendor=\"A\"", "vendor=\"ACME\""))
            .unwrap();
    assert_eq!(
        render_matrix(&[a.clone(), b.clone()]),
        render_matrix(&[b, a])
    );
}

// ---- Expected-to-pass coverage ----

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn toml_unicode_escapes_are_decoded_before_the_guard() {
    let toml = entry_text("quirks=[\"host \\u0031\\u0039\\u0032.168.1.20\"]");
    let r = validate(&CatalogueEntry::from_toml_str(&toml).unwrap());
    assert!(
        matches!(
            r,
            Err(CatalogueError::SiteData {
                kind: SiteDataKind::Ipv4,
                ..
            })
        ),
        "{r:?}"
    );
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn credentials_in_evidence_reference_url_are_rejected() {
    let toml = "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n[[evidence]]\nreference=\"https://user:ghp_token@github.com/x\"\n";
    let r = CatalogueEntry::from_toml_str(toml).and_then(|e| validate(&e));
    assert!(
        matches!(
            r,
            Err(CatalogueError::SiteData {
                kind: SiteDataKind::Credentials,
                ..
            })
        ),
        "{r:?}"
    );
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn site_data_in_rtsp_path_with_port_and_brackets_is_rejected() {
    for p in ["/x?host=10.1.2.3:554", "/[fe80::1]/x", "/a4:5e:60:00:11:22"] {
        assert!(is_site(&path(p)), "{p}");
    }
}

#[test]
fn unknown_fields_rejected_in_every_nested_table() {
    for extra in [
        "[[streams]]\nrole=\"main\"\ncodec=\"h264\"\nwidth=1\nheight=1\nip=\"x\"",
        "[[protocols]]\nkind=\"rtsp\"\nhost=\"x\"",
        "[[events]]\nkind=\"motion\"\nsource=\"cgi\"\nstatus=\"observed\"\nname=\"x\"",
    ] {
        assert!(
            CatalogueEntry::from_toml_str(&entry_text(extra)).is_err(),
            "{extra}"
        );
    }
    let ev = "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n[[evidence]]\nreference=\"x\"\nurl=\"y\"\n";
    assert!(CatalogueEntry::from_toml_str(ev).is_err());
    assert!(CatalogueEntry::from_toml_str(&entry_text("[extra]\na=1")).is_err());
    assert!(CatalogueEntry::from_toml_str(&entry_text("configurable=[\"reboot\"]")).is_err());
}

#[test]
fn non_finite_and_negative_fps_are_out_of_range() {
    for fps in ["nan", "inf", "-inf", "-1.0", "-0.0"] {
        let toml = entry_text(&format!(
            "[[streams]]\nrole=\"main\"\ncodec=\"h264\"\nwidth=1\nheight=1\nfps={fps}"
        ));
        let r = validate(&CatalogueEntry::from_toml_str(&toml).unwrap());
        assert!(
            matches!(r, Err(CatalogueError::OutOfRange(_))),
            "{fps}: {r:?}"
        );
    }
}

#[test]
fn negative_or_overflowing_numbers_are_parse_errors() {
    for s in [
        "width=-1\nheight=1",
        "width=4294967296\nheight=1",
        "width=1\nheight=1\ngop=-1",
    ] {
        let toml = entry_text(&format!("[[streams]]\nrole=\"main\"\ncodec=\"h264\"\n{s}"));
        assert!(CatalogueEntry::from_toml_str(&toml).is_err(), "{s}");
    }
    let toml = entry_text("[[protocols]]\nkind=\"rtsp\"\nport=65536");
    assert!(CatalogueEntry::from_toml_str(&toml).is_err());
}

#[test]
fn guard_does_not_panic_on_multibyte_and_edge_strings() {
    for q in [
        "",
        "@",
        "://",
        "://@",
        "a://\u{1F600}@",
        "\u{1F600}:\u{1F600}@\u{1F600}",
        "...",
        ":::::",
        "Ünïcödé ∂ 漢字 עברית \u{202E}",
    ] {
        let _ = quirk(q);
    }
    let long = "9.".repeat(20_000);
    let _ = quirk(&long);
}

#[test]
fn checked_in_entry_files_contain_no_site_data_in_comments() {
    // Scan the raw text, comments included, with the same guard by wrapping each line as a quirk.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras");
    for vendor in std::fs::read_dir(&dir).unwrap() {
        let vendor = vendor.unwrap().path();
        if !vendor.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&vendor).unwrap() {
            let f = f.unwrap().path();
            let text = std::fs::read_to_string(&f).unwrap();
            for line in text.lines().filter(|l| l.trim_start().starts_with('#')) {
                assert!(
                    quirk(&line.replace("'''", "")).is_ok(),
                    "{}: comment",
                    f.display()
                );
            }
        }
    }
}
