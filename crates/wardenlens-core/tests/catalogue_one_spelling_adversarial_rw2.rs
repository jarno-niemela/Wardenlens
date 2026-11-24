//! Adversary round (PR #71 rework 2): "each value has exactly one spelling". If an entry is
//! accepted (parsed and validated), every decoded string field must appear verbatim in the raw
//! source, because the exact-match vault scan reads the raw file. Also the backslash ban on
//! every line form, with the right line number and without echoing the text.

use proptest::prelude::*;
use wardenlens_core::catalogue::{
    CatalogueEntry, CatalogueError, SiteDataKind, check_source, lint, lint_source, validate,
};

const HEAD: &str = "vendor = \"Acme\"\nmodel = \"C1\"\nsupport = \"community\"\n";
const EVIDENCE: &str = "[[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n";

fn accepted(src: &str) -> Option<CatalogueEntry> {
    let e = CatalogueEntry::from_toml_str(src).ok()?;
    validate(&e).ok()?;
    Some(e)
}

fn all_strings(e: &CatalogueEntry) -> Vec<String> {
    let mut v = vec![e.vendor.clone(), e.model.clone()];
    v.extend(e.aliases.iter().cloned());
    v.extend(e.quirks.iter().cloned());
    for ev in &e.evidence {
        v.push(ev.reference.clone());
        v.extend(ev.section.iter().cloned());
    }
    for p in &e.protocols {
        v.extend(p.paths.iter().cloned());
    }
    v
}

fn assert_one_spelling(src: &str) {
    if let Some(e) = accepted(src) {
        for s in all_strings(&e) {
            assert!(
                src.contains(&s),
                "decoded value {s:?} is not spelled verbatim in the accepted source {src:?}"
            );
        }
    }
}

#[test]
fn every_toml_string_form_that_is_accepted_is_spelled_verbatim() {
    for lit in [
        "\"gw zq-mark-4410\"",
        "'gw zq-mark-4410'",
        "\"\"\"gw zq-mark-4410\"\"\"",
        "'''gw zq-mark-4410'''",
        "\"\"\"\ngw zq-mark-4410\"\"\"",
        "'''\ngw zq-mark-4410'''",
        "\"\"\"\r\ngw zq-mark-4410\"\"\"",
        "\"\"\"gw zq\nmark\"\"\"",
        "'''gw zq\r\nmark'''",
        "\"\"\"a\"\"b\"\"\"",
        "\"\"\"ab\"\"\"\"\"",
        "'''ab'''''",
        "\"a\tb\"",
        "\"\"\"a\\\n  b\"\"\"",
        "\"a\\u002eb\"",
        "'a\\u002eb'",
    ] {
        let src = format!("{HEAD}quirks = [{lit}]\n{EVIDENCE}");
        assert_one_spelling(&src);
        assert_one_spelling(&src.replace('\n', "\r\n"));
    }
}

#[test]
fn quoted_keys_inline_tables_and_dotted_layouts_keep_one_spelling() {
    for src in [
        "\"vendor\" = \"Acme\"\n'model' = 'C1'\nsupport = \"community\"\nevidence = [{reference = 'docs/x.md', section = \"\"\"s 1\"\"\"}]\n",
        "vendor = \"Acme\"\nmodel = \"C1\"\nsupport = \"community\"\nprotocols = [{kind = \"rtsp\", paths = ['/a?b=1&c=2']}]\nevidence = [{reference = 'x'}]\n",
    ] {
        assert!(accepted(src).is_some(), "{src}");
        assert_one_spelling(src);
    }
}

#[test]
fn a_backslash_is_refused_on_every_kind_of_line_and_names_that_line() {
    let cases = [
        "# a comment with \\ in it",
        "quirks = ['literal \\ backslash']",
        "quirks = ['''multi \\ literal''']",
        "quirks = [\"basic \\\\ escaped\"]",
        "\"quoted\\u0020key\" = 1",
        "\\",
    ];
    for line in cases {
        for (src, expected_line) in [
            (format!("{HEAD}{line}\n{EVIDENCE}"), 4),
            (format!("{HEAD}{line}\n{EVIDENCE}").replace('\n', "\r\n"), 4),
            (format!("{HEAD}{EVIDENCE}{line}"), 6),
        ] {
            let err = CatalogueEntry::from_toml_str(&src).expect_err(line);
            assert_eq!(
                err,
                CatalogueError::SiteData {
                    field: format!("line {expected_line}"),
                    kind: SiteDataKind::Encoding
                },
                "{line:?}"
            );
            assert!(!err.to_string().contains("backslash"), "{err}");
            assert!(!err.to_string().contains('\\'), "{err}");
            assert_eq!(check_source(&src), Err(err));
        }
    }
}

#[test]
fn lone_cr_cannot_hide_a_backslash_line_from_the_line_scan() {
    // `lines()` only splits on `\n`; a lone `\r` must still be refused, not let a backslash on
    // a "visual" second line through.
    for src in [
        format!("{HEAD}# note\rquirks = ['a\\b']\n{EVIDENCE}"),
        format!("{HEAD}# note\u{2028}x\\y\n{EVIDENCE}"),
        format!("{HEAD}# note\u{0085}x\\y\n{EVIDENCE}"),
    ] {
        assert!(check_source(&src).is_err(), "{src:?}");
        assert!(CatalogueEntry::from_toml_str(&src).is_err(), "{src:?}");
    }
}

#[test]
fn the_soft_lint_never_fails_validation_and_never_echoes_text() {
    let q = "gateway 192.168.7.7 admin:hunter2 mac a4:5e:60:0b:11:2c cam.lan";
    let src = format!("{HEAD}quirks = ['{q}']\n# 192.168.7.7 password=hunter2\n{EVIDENCE}");
    let e = CatalogueEntry::from_toml_str(&src).expect("lint must not refuse");
    assert_eq!(validate(&e), Ok(()));
    let warnings: Vec<String> = lint(&e)
        .iter()
        .chain(lint_source(&src).iter())
        .map(ToString::to_string)
        .collect();
    assert_ne!(warnings.len(), 0);
    for w in warnings {
        for secret in ["192.168", "hunter2", "a4:5e", "cam.lan"] {
            assert!(!w.contains(secret), "{w}");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn accepted_quirks_are_spelled_verbatim(
        delim in prop::sample::select(vec!["\"", "'", "\"\"\"", "'''"]),
        lead_nl in any::<bool>(),
        body in prop::collection::vec(
            prop::sample::select(vec!['a', '1', '.', '-', '"', '\'', '\n', '\r', '\t', '\\', ' ', '#', 'u', 'U', '0', 'e']),
            0..24,
        ),
        crlf in any::<bool>(),
    ) {
        let body: String = body.into_iter().collect();
        let nl = if lead_nl && delim.len() == 3 { "\n" } else { "" };
        let mut src = format!("{HEAD}quirks = [{delim}{nl}{body}{delim}]\n{EVIDENCE}");
        if crlf {
            src = src.replace('\n', "\r\n");
        }
        assert_one_spelling(&src);
    }

    #[test]
    fn lint_and_check_source_never_panic(text in "\\PC{0,200}") {
        let _ = lint_source(&text);
        let _ = check_source(&text);
        let _ = CatalogueEntry::from_toml_str(&text);
    }
}

#[test]
fn size_limit_is_exactly_64_kib_of_bytes() {
    let base = format!("{HEAD}{EVIDENCE}");
    let pad = |n: usize| format!("{base}#{}\n", "a".repeat(n));
    let fit = 64 * 1024 - base.len() - 2;
    assert!(CatalogueEntry::from_toml_str(&pad(fit)).is_ok());
    assert!(matches!(
        CatalogueEntry::from_toml_str(&pad(fit + 1)),
        Err(CatalogueError::TooLarge { .. })
    ));
    // Multi-byte letters count as bytes, not chars.
    let wide = format!("{base}#{}\n", "\u{e4}".repeat(fit / 2 + 1));
    assert!(matches!(
        CatalogueEntry::from_toml_str(&wide),
        Err(CatalogueError::TooLarge { .. })
    ));
}
