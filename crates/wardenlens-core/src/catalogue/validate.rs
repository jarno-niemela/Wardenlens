//! Entry-level validation: completeness, plausible numbers, and the site-data guard applied to
//! every string of the parsed entry (which also covers TOML `\u` escapes). The text heuristics
//! live in [`guard`](super::guard).

use super::entry::{CatalogueEntry, Event, Evidence, Protocol, Stream};
use super::error::{CatalogueError, SiteDataKind};
use super::guard::{LintWarning, Mode, has_odd_encoding, site_data};

/// Checks an entry for completeness and structure, and every string field for disallowed
/// characters. Shape heuristics are the soft [`lint`], not enforced.
///
/// # Errors
/// [`CatalogueError::Missing`] for an empty vendor, model, evidence list or blank evidence
/// reference, [`CatalogueError::OutOfRange`] for implausible stream numbers,
/// [`CatalogueError::Malformed`] for a protocol path that is not a plain `/path`, and
/// [`CatalogueError::SiteData`] (kind `Encoding`) naming the field (never the value).
pub fn validate(entry: &CatalogueEntry) -> Result<(), CatalogueError> {
    if entry.vendor.trim().is_empty() {
        return Err(CatalogueError::Missing("vendor"));
    }
    if entry.model.trim().is_empty() {
        return Err(CatalogueError::Missing("model"));
    }
    if entry.evidence.is_empty() || entry.evidence.iter().any(|e| e.reference.trim().is_empty()) {
        return Err(CatalogueError::Missing("evidence"));
    }
    if entry
        .evidence
        .iter()
        .any(|e| e.section.as_deref().is_some_and(|s| s.trim().is_empty()))
    {
        return Err(CatalogueError::Missing("evidence section"));
    }
    if entry
        .protocols
        .iter()
        .flat_map(|p| &p.paths)
        .any(|p| !p.starts_with('/') || p.starts_with("//") || p.contains("://"))
    {
        return Err(CatalogueError::Malformed("protocol path"));
    }
    for s in &entry.streams {
        let fps_ok = s.fps.is_none_or(|f| f > 0.0 && f <= 240.0);
        let gop_ok = s.gop.is_none_or(|g| (1..=10_000).contains(&g));
        if !(1..=16_384).contains(&s.width) || !(1..=16_384).contains(&s.height) {
            return Err(CatalogueError::OutOfRange("stream resolution"));
        }
        if !fps_ok {
            return Err(CatalogueError::OutOfRange("stream fps"));
        }
        if !gop_ok {
            return Err(CatalogueError::OutOfRange("stream gop"));
        }
    }
    for (field, value, _) in strings(entry) {
        if has_odd_encoding(value) {
            return Err(CatalogueError::SiteData {
                field,
                kind: SiteDataKind::Encoding,
            });
        }
    }
    Ok(())
}

/// Optional soft lint over every string of a parsed entry (which also covers TOML `\u` escapes):
/// the shape heuristics of the guard module. Returns warnings, never an error; the authoritative
/// check is the exact-match vault scan (ADR 0006, #75).
#[must_use]
pub fn lint(entry: &CatalogueEntry) -> Vec<LintWarning> {
    strings(entry)
        .into_iter()
        .filter_map(|(field, value, mode)| {
            site_data(value, mode).map(|kind| LintWarning { field, kind })
        })
        .collect()
}

/// Every string in the entry with a field label and the rule that applies to it. Exhaustive destructuring (of the entry and of
/// every nested struct that holds strings) means adding a string field without deciding how to
/// check it fails to compile.
fn strings(entry: &CatalogueEntry) -> Vec<(String, &str, Mode)> {
    let CatalogueEntry {
        vendor,
        model,
        aliases,
        quirks,
        evidence,
        protocols,
        support: _,
        firmware: _,
        streams,
        events,
        configurable: _,
    } = entry;
    // `Stream` and `Event` hold only enums and numbers; destructuring them here makes adding a
    // string field to either a compile error until it is checked below.
    for Stream {
        role: _,
        codec: _,
        width: _,
        height: _,
        fps: _,
        gop: _,
    } in streams
    {}
    for Event {
        kind: _,
        source: _,
        status: _,
    } in events
    {}
    let text = Mode::Text;
    let mut out = vec![
        ("vendor".to_owned(), vendor.as_str(), text),
        ("model".to_owned(), model.as_str(), Mode::Model),
    ];
    out.extend(
        aliases
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("aliases[{i}]"), s.as_str(), Mode::Model)),
    );
    out.extend(
        quirks
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("quirks[{i}]"), s.as_str(), text)),
    );
    for (i, e) in evidence.iter().enumerate() {
        let Evidence { reference, section } = e;
        out.push((format!("evidence[{i}].reference"), reference.as_str(), text));
        if let Some(section) = section {
            out.push((format!("evidence[{i}].section"), section.as_str(), text));
        }
    }
    for (i, p) in protocols.iter().enumerate() {
        let Protocol {
            kind: _,
            port: _,
            paths,
        } = p;
        out.extend(
            paths
                .iter()
                .enumerate()
                .map(|(j, s)| (format!("protocols[{i}].paths[{j}]"), s.as_str(), text)),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::entry::SupportLevel;
    use super::super::error::SiteDataKind;
    use super::*;

    /// Built directly, bypassing the source scan in `from_toml_str`, so these tests exercise
    /// `validate` alone.
    fn base() -> CatalogueEntry {
        CatalogueEntry {
            vendor: "A".to_owned(),
            model: "B".to_owned(),
            aliases: vec![],
            support: SupportLevel::Verified,
            firmware: vec![],
            streams: vec![],
            protocols: vec![],
            events: vec![],
            configurable: vec![],
            quirks: vec![],
            evidence: vec![Evidence {
                reference: "docs/x.md".to_owned(),
                section: None,
            }],
        }
    }

    fn stream(extra: impl FnOnce(&mut super::super::entry::Stream)) -> CatalogueEntry {
        let mut s = CatalogueEntry::from_toml_str(
            "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n[[streams]]\nrole=\"main\"\n\
             codec=\"h264\"\nwidth=1\nheight=1\n",
        )
        .unwrap();
        s.evidence = base().evidence;
        if let Some(first) = s.streams.first_mut() {
            extra(first);
        }
        s
    }

    #[test]
    fn accepts_base_entry() {
        assert_eq!(validate(&base()), Ok(()));
    }

    /// One entry per string field, each carrying `bad` (a plain `bad` for text fields, `/bad`
    /// for protocol paths) in that field only, with the label `strings()` must give it.
    fn one_bad_field_each(bad: &str) -> Vec<(CatalogueEntry, &'static str)> {
        let mut cases = Vec::new();
        let mut e = base();
        bad.clone_into(&mut e.vendor);
        cases.push((e, "vendor"));
        let mut e = base();
        bad.clone_into(&mut e.model);
        cases.push((e, "model"));
        let mut e = base();
        e.aliases = vec!["ok".to_owned(), bad.to_owned()];
        cases.push((e, "aliases[1]"));
        let mut e = base();
        e.aliases = vec![bad.to_owned()];
        cases.push((e, "aliases[0]"));
        let mut e = base();
        e.quirks = vec![bad.to_owned()];
        cases.push((e, "quirks[0]"));
        let mut e = base();
        e.evidence = vec![Evidence {
            reference: bad.to_owned(),
            section: None,
        }];
        cases.push((e, "evidence[0].reference"));
        let mut e = base();
        e.evidence = vec![Evidence {
            reference: "x".to_owned(),
            section: Some(bad.to_owned()),
        }];
        cases.push((e, "evidence[0].section"));
        let mut e = base();
        e.protocols = vec![Protocol {
            kind: super::super::entry::ProtocolKind::Rtsp,
            port: None,
            paths: vec!["/ok".to_owned(), format!("/{bad}")],
        }];
        cases.push((e, "protocols[0].paths[1]"));
        let mut e = base();
        e.protocols = vec![Protocol {
            kind: super::super::entry::ProtocolKind::Rtsp,
            port: None,
            paths: vec![format!("/{bad}")],
        }];
        cases.push((e, "protocols[0].paths[0]"));
        cases
    }

    /// A zero-width space between two digits, built from its code point.
    fn encoding_violation() -> String {
        let z = char::from_u32(0x200B).unwrap_or('?');
        format!("1{z}0")
    }

    #[test]
    fn lint_covers_every_string_field() {
        for (e, field) in one_bad_field_each("10.1.2.3") {
            let w = lint(&e);
            assert_eq!(
                w,
                vec![LintWarning {
                    field: field.to_owned(),
                    kind: SiteDataKind::Ipv4
                }],
                "{field}"
            );
        }
    }

    #[test]
    #[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
    fn error_names_the_field_but_not_the_value() {
        let mut e = base();
        e.quirks = vec!["gateway 192.168.7.7".to_owned()];
        let msg = validate(&e).unwrap_err().to_string();
        assert!(msg.contains("quirks[0]"), "{msg}");
        assert!(!msg.contains("192.168"), "{msg}");
    }

    #[test]
    fn lint_warns_per_field_without_the_value_and_validate_still_passes() {
        let mut e = base();
        e.quirks = vec!["gateway 192.168.7.7".to_owned()];
        e.vendor = "10.1.2.3".to_owned();
        let w = lint(&e);
        let fields: Vec<&str> = w.iter().map(|x| x.field.as_str()).collect();
        assert_eq!(fields, ["vendor", "quirks[0]"]);
        assert!(w.iter().all(|x| !x.to_string().contains("192.168")));
        assert_eq!(validate(&e), Ok(()));
        assert_eq!(lint(&base()), vec![]);
    }

    #[test]
    fn validate_enforces_the_encoding_allow_list_in_every_string_field() {
        for (e, field) in one_bad_field_each(&encoding_violation()) {
            assert_eq!(
                validate(&e),
                Err(CatalogueError::SiteData {
                    field: field.to_owned(),
                    kind: SiteDataKind::Encoding
                }),
                "{field}"
            );
        }
    }

    #[test]
    fn requires_non_empty_non_blank_evidence() {
        let mut e = base();
        e.evidence.clear();
        assert_eq!(validate(&e), Err(CatalogueError::Missing("evidence")));
        for blank in ["", "   ", "\t"] {
            let mut e = base();
            e.evidence = vec![Evidence {
                reference: blank.to_owned(),
                section: None,
            }];
            assert_eq!(
                validate(&e),
                Err(CatalogueError::Missing("evidence")),
                "{blank:?}"
            );
        }
    }

    #[test]
    fn rejects_blank_evidence_section() {
        for blank in ["", "  "] {
            let mut e = base();
            e.evidence = vec![Evidence {
                reference: "x".to_owned(),
                section: Some(blank.to_owned()),
            }];
            assert_eq!(
                validate(&e),
                Err(CatalogueError::Missing("evidence section")),
                "{blank:?}"
            );
        }
    }

    #[test]
    fn requires_vendor_and_model() {
        let mut e = base();
        e.vendor = " ".to_owned();
        assert_eq!(validate(&e), Err(CatalogueError::Missing("vendor")));
        let mut e = base();
        e.model = String::new();
        assert_eq!(validate(&e), Err(CatalogueError::Missing("model")));
    }

    #[test]
    fn protocol_paths_must_be_plain_paths() {
        for (path, ok) in [
            ("/11", true),
            ("/cam/realmonitor?channel=1&subtype=0", true),
            ("11", false),
            ("", false),
            ("rtsp://host/x", false),
            ("//host/x", false),
            ("/x?u=http://h", false),
        ] {
            let mut e = base();
            e.protocols = vec![Protocol {
                kind: super::super::entry::ProtocolKind::Rtsp,
                port: None,
                paths: vec![path.to_owned()],
            }];
            assert_eq!(validate(&e).is_ok(), ok, "{path}");
            if !ok {
                assert_eq!(
                    validate(&e),
                    Err(CatalogueError::Malformed("protocol path"))
                );
            }
        }
    }

    #[test]
    fn rejects_implausible_stream_numbers() {
        type Tweak = fn(&mut super::super::entry::Stream);
        let cases: [(&str, Tweak); 7] = [
            ("w0", |s| s.width = 0),
            ("h0", |s| s.height = 0),
            ("w max+1", |s| s.width = 16_385),
            ("fps0", |s| s.fps = Some(0.0)),
            ("fps max+1", |s| s.fps = Some(241.0)),
            ("gop0", |s| s.gop = Some(0)),
            ("gop max+1", |s| s.gop = Some(10_001)),
        ];
        for (name, f) in cases {
            assert!(
                matches!(validate(&stream(f)), Err(CatalogueError::OutOfRange(_))),
                "{name}"
            );
        }
        assert_eq!(validate(&stream(|s| s.width = 16_384)), Ok(()));
    }
}
