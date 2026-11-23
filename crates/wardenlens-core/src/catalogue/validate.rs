//! Entry-level validation: completeness, plausible numbers, and the site-data guard applied to
//! every string of the parsed entry (which also covers TOML `\u` escapes). The text heuristics
//! live in [`guard`](super::guard).

use super::entry::{CatalogueEntry, Evidence, Protocol};
use super::error::CatalogueError;
use super::guard::site_data;

/// Checks an entry for completeness and for site-specific data in any string field.
///
/// # Errors
/// [`CatalogueError::Missing`] for an empty vendor, model, evidence list or blank evidence
/// reference, [`CatalogueError::OutOfRange`] for implausible stream numbers,
/// [`CatalogueError::Malformed`] for a protocol path that is not a plain `/path`, and
/// [`CatalogueError::SiteData`] naming the field (never the value) for site data.
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
        .protocols
        .iter()
        .flat_map(|p| &p.paths)
        .any(|p| !p.starts_with('/') || p.contains("://"))
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
    for (field, value) in strings(entry) {
        if let Some(kind) = site_data(value) {
            return Err(CatalogueError::SiteData { field, kind });
        }
    }
    Ok(())
}

/// Every string in the entry with a field label. Exhaustive destructuring (of the entry and of
/// every nested struct that holds strings) means adding a string field without deciding how to
/// check it fails to compile.
fn strings(entry: &CatalogueEntry) -> Vec<(String, &str)> {
    let CatalogueEntry {
        vendor,
        model,
        aliases,
        quirks,
        evidence,
        protocols,
        support: _,
        firmware: _,
        streams: _,
        events: _,
        configurable: _,
    } = entry;
    let mut out = vec![
        ("vendor".to_owned(), vendor.as_str()),
        ("model".to_owned(), model.as_str()),
    ];
    out.extend(
        aliases
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("aliases[{i}]"), s.as_str())),
    );
    out.extend(
        quirks
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("quirks[{i}]"), s.as_str())),
    );
    for (i, e) in evidence.iter().enumerate() {
        let Evidence { reference, section } = e;
        out.push((format!("evidence[{i}].reference"), reference.as_str()));
        if let Some(section) = section {
            out.push((format!("evidence[{i}].section"), section.as_str()));
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
                .map(|(j, s)| (format!("protocols[{i}].paths[{j}]"), s.as_str())),
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

    #[test]
    fn checks_every_string_field() {
        let bad = "10.1.2.3".to_owned();
        let mut cases = Vec::new();
        let mut e = base();
        e.vendor.clone_from(&bad);
        cases.push((e, "vendor"));
        let mut e = base();
        e.model.clone_from(&bad);
        cases.push((e, "model"));
        let mut e = base();
        e.aliases = vec![bad.clone()];
        cases.push((e, "aliases[0]"));
        let mut e = base();
        e.quirks = vec![bad.clone()];
        cases.push((e, "quirks[0]"));
        let mut e = base();
        e.evidence = vec![Evidence {
            reference: bad.clone(),
            section: None,
        }];
        cases.push((e, "evidence[0].reference"));
        let mut e = base();
        e.evidence = vec![Evidence {
            reference: "x".to_owned(),
            section: Some(bad.clone()),
        }];
        cases.push((e, "evidence[0].section"));
        let mut e = base();
        e.protocols = vec![Protocol {
            kind: super::super::entry::ProtocolKind::Rtsp,
            port: None,
            paths: vec![format!("/{bad}")],
        }];
        cases.push((e, "protocols[0].paths[0]"));
        for (e, field) in cases {
            match validate(&e) {
                Err(CatalogueError::SiteData {
                    field: f,
                    kind: SiteDataKind::Ipv4,
                }) => {
                    assert_eq!(f, field);
                }
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    #[test]
    fn error_names_the_field_but_not_the_value() {
        let mut e = base();
        e.quirks = vec!["gateway 192.168.7.7".to_owned()];
        let msg = validate(&e).unwrap_err().to_string();
        assert!(msg.contains("quirks[0]"), "{msg}");
        assert!(!msg.contains("192.168"), "{msg}");
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
