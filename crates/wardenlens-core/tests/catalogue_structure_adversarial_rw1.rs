//! Adversary round (PR #71 rework 1): the kept structural rules (unknown fields, plain paths,
//! encoding allow-list, CRLF, evidence) against inputs the earlier rounds did not try, now that
//! the shape heuristics no longer back them up.

use wardenlens_core::catalogue::{CatalogueEntry, CatalogueError, lint, lint_source, validate};

const HEAD: &str = "vendor = \"Acme\"\nmodel = \"C1\"\nsupport = \"community\"\n";
const EVIDENCE: &str = "[[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n";

fn full(src: &str) -> Result<CatalogueEntry, CatalogueError> {
    let e = CatalogueEntry::from_toml_str(src)?;
    validate(&e)?;
    Ok(e)
}

fn with_quirk(q: &str) -> String {
    format!("{HEAD}quirks = [\"{q}\"]\n{EVIDENCE}")
}

#[test]
fn clean_crlf_entry_parses_and_validates() {
    let src = format!("{HEAD}quirks = [\"ok\"]\n{EVIDENCE}").replace('\n', "\r\n");
    assert!(full(&src).is_ok());
}

#[test]
fn unknown_fields_are_rejected_in_every_nested_table() {
    for extra in [
        "[[evidence]]\nreference = \"x\"\nurl = \"y\"\n",
        "[[streams]]\nrole = \"main\"\ncodec = \"h264\"\nwidth = 1\nheight = 1\nbitrate = 4\n",
        "[[protocols]]\nkind = \"rtsp\"\nhost = \"h\"\n",
        "[[events]]\nkind = \"motion\"\nsource = \"onvif\"\nstatus = \"observed\"\nnote = \"n\"\n",
        "serial = \"x\"\n",
        "Vendor = \"x\"\n",
    ] {
        let src = if extra.starts_with('[') {
            format!("{HEAD}{EVIDENCE}{extra}")
        } else {
            format!("{HEAD}{extra}{EVIDENCE}")
        };
        assert!(CatalogueEntry::from_toml_str(&src).is_err(), "{extra}");
    }
}

#[test]
fn disallowed_characters_written_as_toml_escapes_are_rejected() {
    for esc in [
        "\\u200B",     // zero-width space
        "\\u202E",     // right-to-left override
        "\\u0000",     // NUL
        "\\u0007",     // BEL
        "\\r",         // bare CR
        "\\n",         // embedded newline
        "\\uFF11",     // fullwidth digit
        "\\u0301",     // combining acute
        "\\uFEFF",     // BOM / zero-width no-break space
        "\\U0001F600", // emoji
        "\\u00A0",     // no-break space
        "\\u0661",     // Arabic-Indic digit one
    ] {
        let src = with_quirk(&format!("a{esc}b"));
        assert!(full(&src).is_err(), "{esc}");
    }
}

#[test]
fn disallowed_raw_characters_in_comments_and_keys_are_rejected() {
    for bad in [
        "\u{200B}",
        "\u{202E}",
        "\u{FEFF}",
        "\u{0}",
        "\u{1B}[2J",
        "\r",
    ] {
        let src = format!("{HEAD}# note a{bad}b\n{EVIDENCE}");
        assert!(CatalogueEntry::from_toml_str(&src).is_err(), "{bad:?}");
    }
    let bom = format!("\u{FEFF}{HEAD}{EVIDENCE}");
    assert!(CatalogueEntry::from_toml_str(&bom).is_err());
}

#[test]
fn protocol_paths_written_with_escapes_are_still_plain_paths() {
    for p in [
        "/x\\u003A//host",  // decodes to "/x://host"
        "\\u002F/host/x",   // decodes to "//host/x"
        "\\u0072tsp://h/x", // decodes to "rtsp://h/x"
        " /x",              // leading space
    ] {
        let src = format!("{HEAD}[[protocols]]\nkind = \"rtsp\"\npaths = [\"{p}\"]\n{EVIDENCE}");
        assert!(full(&src).is_err(), "{p}");
    }
}

#[test]
fn evidence_must_be_present_and_not_blank_even_via_escapes() {
    for ev in [
        "",
        "[[evidence]]\nreference = \"\\t\"\n",
        "[[evidence]]\nreference = \"\\u0020\"\n",
        "[[evidence]]\nsection = \"x\"\n",
        "evidence = []\n",
    ] {
        let src = format!("{HEAD}{ev}");
        assert!(full(&src).is_err(), "{ev}");
    }
}

#[test]
fn lint_never_fails_and_never_echoes_its_input() {
    let secret = "password=hunter2-synthetic 10.9.8.7 a4:5e:60:00:11:22";
    let src = with_quirk(secret);
    let e = full(&src).unwrap_or_else(|err| panic!("lint input must validate: {err}"));
    let w = lint(&e);
    assert_ne!(w.len(), 0);
    let ws = lint_source(&src);
    assert_ne!(ws.len(), 0);
    for x in w.iter().chain(ws.iter()) {
        let s = format!("{x} {x:?}");
        for part in ["hunter2", "10.9.8.7", "a4:5e", "password="] {
            assert!(!s.contains(part), "{s}");
        }
    }
}
