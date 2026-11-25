//! Invariant 4: names, slugs, dedup and equal names (TEST-9).
//!
//! Enumeration of name forms: plain ASCII, mixed case, punctuation runs, leading digit, leading
//! or trailing separators, non-ASCII only, mixed ASCII and non-ASCII, over-long, white space
//! forms (space, tab, NBSP, line separators), invisible characters, names equal after
//! normalisation, names equal only in slug.

use std::collections::BTreeSet;

use crate::{ImportError, SkipReason, parse};

use super::fixtures::{Cam, doc, parse_ok};

fn ids(names: &[&str]) -> Vec<String> {
    let cams: Vec<Cam> = names
        .iter()
        .enumerate()
        .map(|(i, n)| Cam::new(n, &format!("rtsp://192.0.2.10/s{i}")))
        .collect();
    let i = parse_ok(&cams);
    assert!(i.skipped.is_empty(), "{:?}", i.skipped);
    i.cameras.iter().map(|c| c.id.as_str().to_owned()).collect()
}

fn one_id(name: &str) -> String {
    ids(&[name]).remove(0)
}

#[test]
fn slug_table() {
    let long = "Very Long Camera Name For The Back Garden Gate";
    let rows: [(&str, &str); 23] = [
        ("Front Door", "front-door"),
        ("front", "front"),
        ("FRONT", "front"),
        ("Cam1", "cam1"),
        ("Cam 1", "cam-1"),
        ("  Cam   1  ", "cam-1"),
        ("Front-Door", "front-door"),
        ("Front_Door", "front-door"),
        ("Front.Door", "front-door"),
        ("Front / Door", "front-door"),
        ("--Front--", "front"),
        ("(Front)", "front"),
        ("1st Floor", "cam-1st-floor"),
        ("42", "cam-42"),
        ("_x", "x"),
        ("Caf\u{e9}", "caf"),
        ("\u{dc}n\u{ef}", "n"),
        ("\u{41a}\u{443}\u{445}\u{43d}\u{44f}", "cam"),
        ("\u{4e2d}\u{6587}", "cam"),
        ("\u{ff21}\u{ff22}1", "cam-1"),
        ("a\u{301}b", "a-b"),
        (long, "very-long-camera-name-for-th"),
        ("x", "x"),
    ];
    for (name, id) in rows {
        assert_eq!(one_id(name), id, "name {name:?}");
    }
}

#[test]
fn every_id_is_at_most_32_bytes_and_valid_whatever_the_name() {
    let names = [
        "a".repeat(128),
        "1".repeat(128),
        "\u{4e2d}".repeat(42),
        format!("{}!", "a b ".repeat(31)),
        "-".repeat(3) + &"z".repeat(100),
    ];
    for n in names {
        let id = one_id(&n);
        assert!(id.len() <= 32, "{id}");
        assert!(wardenlens_core::camera::CameraId::new(&id).is_ok(), "{id}");
    }
}

#[test]
fn dedup_is_numbered_in_document_order() {
    assert_eq!(
        ids(&["A b", "A-b", "A_b", "A.b", "a b"]),
        ["a-b", "a-b-2", "a-b-3", "a-b-4", "a-b-5"]
    );
}

#[test]
fn dedup_avoids_a_natural_slug_that_looks_like_a_suffix() {
    assert_eq!(ids(&["X", "X!", "X-2"]), ["x", "x-2", "x-2-2"]);
    assert_eq!(ids(&["A-2", "A", "A!"]), ["a-2", "a", "a-3"]);
    assert_eq!(ids(&["A", "A-2", "A!"]), ["a", "a-2", "a-3"]);
}

#[test]
fn dedup_is_stable_across_runs_and_skips_take_no_id() {
    let cams = vec![
        Cam::new("Cam", "rtsp://192.0.2.1/s"),
        Cam::new("Cam!", "http://192.0.2.2/x"),
        Cam::new("Cam?", "rtsp://192.0.2.3/s"),
        Cam::new("Cam.", "rtsp://192.0.2.4/s"),
    ];
    let first: Vec<String> = parse_ok(&cams)
        .cameras
        .iter()
        .map(|c| c.id.to_string())
        .collect();
    let again: Vec<String> = parse_ok(&cams)
        .cameras
        .iter()
        .map(|c| c.id.to_string())
        .collect();
    assert_eq!(first, ["cam", "cam-2", "cam-3"]);
    assert_eq!(first, again);
}

#[test]
fn many_slug_collisions_stay_unique_and_within_32_bytes() {
    for base in ["x", &"y".repeat(60)] {
        // 256 distinct names (n written as eight `!` or `?`) with one slug.
        let names: Vec<String> = (0..crate::MAX_CAMERAS)
            .map(|n| {
                let bits: String = (0..8)
                    .map(|b| if (n >> b) & 1 == 1 { '!' } else { '?' })
                    .collect();
                format!("{base}{bits}")
            })
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let got = ids(&refs);
        let unique: BTreeSet<&String> = got.iter().collect();
        assert_eq!(unique.len(), crate::MAX_CAMERAS, "{base}");
        assert!(got.iter().all(|i| i.len() <= 32));
        assert!(got.last().expect("last").ends_with("-256"));
    }
}

#[test]
fn names_equal_after_normalisation_fail_the_import() {
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
            Cam::new(a, "rtsp://192.0.2.1/s"),
            Cam::new(b, "rtsp://192.0.2.2/s"),
        ];
        let r = parse(doc(&cams).as_bytes());
        assert_eq!(r.err(), Some(ImportError::DuplicateName), "{a:?} / {b:?}");
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
        Some(ImportError::DuplicateName)
    );
}

#[test]
fn names_that_differ_are_never_merged() {
    // Case differs, so the names differ (the vault's legacy import compares exactly); the ids
    // are told apart by the suffix and both cameras are kept.
    let i = parse_ok(&[
        Cam::new("Front", "rtsp://192.0.2.1/s"),
        Cam::new("front", "rtsp://192.0.2.2/s"),
    ]);
    assert_eq!(i.cameras.len(), 2);
    assert_ne!(i.cameras[0].id, i.cameras[1].id);
    assert_ne!(i.cameras[0].name.expose(), i.cameras[1].name.expose());
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
