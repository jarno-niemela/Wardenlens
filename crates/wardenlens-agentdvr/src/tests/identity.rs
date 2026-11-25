//! Invariant 4: ids, names and equal names (TEST-9).
//!
//! Enumeration: an id is never derived from a value (so the name sentinel is in no id); numeric
//! `AgentDVR` ids (present, absent, non-numeric, repeated, zero, maximum); positions; skipped
//! entries; names equal after normalisation (white space forms, invisible characters), names
//! that differ, and equal names where one camera is not imported.

use crate::{ImportError, SkipReason, parse};

use super::fixtures::{Cam, doc, parse_ok};

fn xml_with_ids(ids: &[Option<&str>], names: &[&str]) -> String {
    let mut body = String::new();
    for (n, (id, name)) in ids.iter().zip(names).enumerate() {
        let id_attr = id.map_or_else(String::new, |i| format!(" id=\"{i}\""));
        body.push_str(&format!(
            "<camera{id_attr} name=\"{name}\"><settings><videosourcestring>rtsp://192.0.2.10/s{n}</videosourcestring></settings></camera>"
        ));
    }
    super::fixtures::wrap(&body)
}

fn ids_of(d: &str) -> Vec<String> {
    parse(d.as_bytes())
        .expect("parses")
        .cameras
        .iter()
        .map(|c| c.id.to_string())
        .collect()
}

#[test]
fn ids_are_the_agentdvr_id_else_the_position() {
    let d = xml_with_ids(
        &[
            Some("3"),
            Some("3"),
            None,
            Some("x"),
            Some("0"),
            Some("4294967295"),
            Some("-1"),
        ],
        &["A", "B", "C", "D", "E", "F", "G"],
    );
    assert_eq!(
        ids_of(&d),
        [
            "agentdvr-3",
            "agentdvr-pos-1",
            "agentdvr-pos-2",
            "agentdvr-pos-3",
            "agentdvr-0",
            "agentdvr-4294967295",
            "agentdvr-pos-6"
        ]
    );
}

#[test]
fn ids_are_stable_across_runs_and_unique() {
    let names: Vec<String> = (0..crate::MAX_CAMERAS)
        .map(|n| format!("Cam {n}"))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    // Every third id repeats, every fifth is absent.
    let id_texts: Vec<Option<String>> = (0..crate::MAX_CAMERAS)
        .map(|n| (n % 5 != 0).then(|| (n / 3).to_string()))
        .collect();
    let ids: Vec<Option<&str>> = id_texts.iter().map(Option::as_deref).collect();
    let d = xml_with_ids(&ids, &refs);
    let first = ids_of(&d);
    assert_eq!(first, ids_of(&d));
    assert_eq!(first.len(), crate::MAX_CAMERAS);
    let set: std::collections::BTreeSet<&String> = first.iter().collect();
    assert_eq!(set.len(), first.len());
    assert!(
        first
            .iter()
            .all(|i| i.len() <= wardenlens_core::camera::MAX_CAMERA_ID_LEN)
    );
}

#[test]
fn an_id_is_never_derived_from_the_name() {
    for name in [
        "Alice Bedroom",
        "front-door",
        "Caf\u{e9}",
        "\u{4e2d}\u{6587}",
        "agentdvr-7",
        "cam",
    ] {
        let i = parse_ok(&[Cam::new(name, "rtsp://192.0.2.10/s")]);
        let id = i.cameras[0].id.as_str().to_owned();
        assert_eq!(id, "agentdvr-0", "{name}");
        let squeezed: String = name
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        if squeezed.len() > 3 {
            assert!(!id.contains(&squeezed), "{id} holds {name}");
        }
    }
}

#[test]
fn skipped_entries_do_not_move_other_ids() {
    let cams = [
        Cam::new("One", "rtsp://192.0.2.1/s"),
        Cam::new("Two", "http://192.0.2.2/x"),
        Cam::new("Three", "rtsp://192.0.2.3/s"),
    ];
    let i = parse_ok(&cams);
    let ids: Vec<&str> = i.cameras.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["agentdvr-0", "agentdvr-2"]);
}

#[test]
fn names_equal_after_normalisation_fail_the_import_with_both_positions() {
    let rows: [(&str, &str); 8] = [
        ("Front", "Front"),
        ("Front Door", "Front  Door"),
        ("Front Door", "Front\u{a0}Door"),
        ("Front Door", "Front\tDoor"),
        ("Front Door", " Front Door "),
        ("Front Door", "Fr\u{200b}ont Door"),
        ("Front Door", "Front\u{2028}Door"),
        ("Front", "Fr\u{feff}ont\u{200d}"),
    ];
    for (a, b) in rows {
        let cams = [
            Cam::new("Other", "rtsp://192.0.2.9/s"),
            Cam::new(a, "rtsp://192.0.2.1/s"),
            Cam::new(b, "rtsp://192.0.2.2/s"),
        ];
        let r = parse(doc(&cams).as_bytes());
        assert_eq!(
            r.err(),
            Some(ImportError::DuplicateName {
                first: 1,
                second: 2
            }),
            "{a:?} / {b:?}"
        );
    }
}

#[test]
fn a_duplicate_name_is_found_wherever_the_two_cameras_are() {
    let cams = [
        Cam::new("One", "rtsp://192.0.2.1/s"),
        Cam::new("Two", "rtsp://192.0.2.2/s"),
        Cam::new("One", "rtsp://192.0.2.3/s"),
    ];
    assert_eq!(
        parse(doc(&cams).as_bytes()).err(),
        Some(ImportError::DuplicateName {
            first: 0,
            second: 2
        })
    );
}

#[test]
fn names_that_differ_are_never_merged() {
    let i = parse_ok(&[
        Cam::new("Front", "rtsp://192.0.2.1/s"),
        Cam::new("front", "rtsp://192.0.2.2/s"),
    ]);
    assert_eq!(i.cameras.len(), 2);
    assert_ne!(i.cameras[0].id, i.cameras[1].id);
}

#[test]
fn equal_names_do_not_collide_when_one_of_them_is_not_imported() {
    let cams = [
        Cam::new("Front", "http://192.0.2.1/x"),
        Cam::new("Front", "rtsp://192.0.2.2/s"),
    ];
    let i = parse_ok(&cams);
    assert_eq!(i.cameras.len(), 1);
    assert_eq!(i.skipped[0].reason, SkipReason::UnsupportedScheme);
    let mut deleted = Cam::new("Front", "rtsp://192.0.2.1/s");
    deleted.deleted = Some("true");
    let i = parse_ok(&[deleted, Cam::new("Front", "rtsp://192.0.2.2/s")]);
    assert_eq!((i.cameras.len(), i.skipped.len()), (1, 1));
    let both_skipped = [
        Cam::new("Front", "http://192.0.2.1/x"),
        Cam::new("Front", "http://192.0.2.2/x"),
    ];
    assert_eq!(parse_ok(&both_skipped).skipped.len(), 2);
}
