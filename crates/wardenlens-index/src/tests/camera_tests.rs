//! The camera registry (ticket #50): round trips, the path and query refusals (one table over the
//! whole surface, TEST-9), a corrupt-row error per column, `remove` leaving orphans, the leak
//! test, the generation bump and the schema identity. Synthetic data only (192.0.2.x, example
//! names).

use std::num::NonZeroU16;

use rusqlite::Connection;
use wardenlens_core::camera::{
    Camera, CameraError, DisplayName, Host, ModelRef, RtspPath, StreamSet,
};
use wardenlens_core::catalogue::CatalogueEntry;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::UnixMs;

use super::*;
use crate::cameras::{CameraRecord, MAX_CAMERAS, vet_path};
use crate::error::IndexError;

const T0: i64 = 1_700_000_000_000;

fn at(ms: i64) -> UnixMs {
    UnixMs::new(ms).unwrap()
}

/// A synthetic catalogue: `acme/c1` lists one query, `acme/c2` lists none.
fn catalogue() -> Vec<CatalogueEntry> {
    let entry = |model: &str, paths: &str| {
        CatalogueEntry::from_toml_str(&format!(
            "vendor = \"Acme\"\nmodel = \"{model}\"\nsupport = \"community\"\n\
             [[protocols]]\nkind = \"rtsp\"\npaths = [{paths}]\n\
             [[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n"
        ))
        .unwrap()
    };
    vec![
        entry("C1", "\"/cam/realmonitor?channel=1&subtype=0\", \"/plain\""),
        entry("C2", "\"/plain\""),
    ]
}

const LISTED: &str = "/cam/realmonitor?channel=1&subtype=0";

fn record(id: &str, model: (&str, &str), port: u16, main: &str, sub: Option<&str>) -> CameraRecord {
    CameraRecord::new(
        cam(id),
        ModelRef::new(model.0, model.1).unwrap(),
        NonZeroU16::new(port).unwrap(),
        StreamSet::new(
            RtspPath::new(main).unwrap(),
            sub.map(|s| RtspPath::new(s).unwrap()),
        ),
    )
}

fn simple(id: &str) -> CameraRecord {
    record(id, ("acme", "c1"), 554, "/main", Some("/sub"))
}

fn generation(idx: &Index) -> i64 {
    idx.conn
        .query_row("SELECT generation FROM index_meta", [], |r| r.get(0))
        .unwrap()
}

/// One raw row, every column a SQL literal; `base()` is a valid one.
#[derive(Clone)]
struct Raw {
    id: &'static str,
    model: &'static str,
    port: &'static str,
    main: &'static str,
    sub: &'static str,
    created: &'static str,
    updated: &'static str,
    basic: &'static str,
}

fn base() -> Raw {
    Raw {
        id: "'cam1'",
        model: "'acme/c1'",
        port: "554",
        main: "'/main'",
        sub: "NULL",
        created: "1700000000000",
        updated: "1700000000000",
        basic: "0",
    }
}

fn insert_raw(c: &Connection, r: &Raw) {
    c.execute_batch(&format!(
        "PRAGMA ignore_check_constraints = ON; \
         INSERT INTO cameras (id, model, rtsp_port, main_path, sub_path, created_at_ms, \
         updated_at_ms, allow_basic_auth) VALUES ({}, {}, {}, {}, {}, {}, {}, {}); \
         PRAGMA ignore_check_constraints = OFF;",
        r.id, r.model, r.port, r.main, r.sub, r.created, r.updated, r.basic
    ))
    .unwrap();
}

fn sql_text(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

// ---- round trip -------------------------------------------------------------------------

#[test]
fn upsert_get_list_round_trip_and_replace_keeps_created_at() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    assert_eq!(idx.get_camera(&cam("cam1"), &cat).unwrap(), None);
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), 0);

    let a = record("cam1", ("acme", "c1"), 554, LISTED, Some("/plain"));
    let b = record("cam0", ("acme", "c2"), 8554, "/b", None);
    idx.upsert_camera(&a, &cat, at(T0)).unwrap();
    idx.upsert_camera(&b, &cat, at(T0 + 5)).unwrap();

    let got = idx.get_camera(&cam("cam1"), &cat).unwrap().unwrap();
    assert_eq!(got.record(), &a);
    assert_eq!(
        (got.created_at(), got.updated_at()),
        (at(T0), at(T0)),
        "a new row has both timestamps equal to now"
    );
    assert_eq!(
        got.record().streams().sub.as_ref().unwrap().as_str(),
        "/plain"
    );
    assert_eq!(got.record().port().get(), 554);
    assert_eq!(got.record().id().as_str(), "cam1");
    assert_eq!(got.record().model().to_string(), "acme/c1");
    let listed = idx.list_cameras(&cat).unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|c| c.record().id().as_str())
            .collect::<Vec<_>>(),
        ["cam0", "cam1"],
        "ordered by id"
    );
    assert_eq!(listed[0].record(), &b);
    assert_eq!(listed[0].record().streams().sub, None);

    // Replace: every column changes, created_at stays, updated_at moves (also backwards: a
    // clock step must not make the row unreadable).
    let a2 = record("cam1", ("acme", "c2"), 1, "/x", None);
    idx.upsert_camera(&a2, &cat, at(T0 - 1000)).unwrap();
    let got = idx.get_camera(&cam("cam1"), &cat).unwrap().unwrap();
    assert_eq!(got.record(), &a2);
    assert_eq!(
        (got.created_at(), got.updated_at()),
        (at(T0), at(T0 - 1000))
    );
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), 2);
}

#[test]
fn from_camera_copies_only_the_registry_fields() {
    let camera = Camera::new(
        cam("cam1"),
        DisplayName::new("Name Sentinel").unwrap(),
        ModelRef::new("acme", "c1").unwrap(),
        Host::new("192.0.2.9").unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(RtspPath::new("/m").unwrap(), None),
    );
    let r = CameraRecord::from_camera(&camera);
    assert_eq!(r.id(), camera.id());
    assert_eq!(r.model(), camera.model());
    assert_eq!(r.port(), camera.port());
    assert_eq!(r.streams(), camera.streams());
    let shown = format!("{r:?}");
    assert!(
        !shown.contains("192.0.2") && !shown.contains("Sentinel"),
        "{shown}"
    );
}

#[test]
fn model_text_is_bounded_by_the_schema_check() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    let v = "v".repeat(31);
    let m = "m".repeat(32);
    // 31 + '/' + 32 = 64 bytes: accepted.
    idx.upsert_camera(&record("cam1", (&v, &m), 554, "/m", None), &cat, at(T0))
        .unwrap();
    assert_eq!(
        idx.get_camera(&cam("cam1"), &cat)
            .unwrap()
            .unwrap()
            .record()
            .model()
            .vendor(),
        v
    );
    let before = generation(&idx);
    for (v, m) in [
        ("v".repeat(32), "m".repeat(32)),
        ("v".repeat(64), "m".repeat(64)),
    ] {
        let e = idx
            .upsert_camera(&record("cam2", (&v, &m), 554, "/m", None), &cat, at(T0))
            .unwrap_err();
        assert!(
            matches!(e, IndexError::InvalidRecord { field: "model" }),
            "{e:?}"
        );
    }
    assert_eq!(generation(&idx), before, "a refused upsert writes nothing");
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), 1);
}

#[test]
fn the_registry_is_bounded() {
    let (f, mut idx) = open_new();
    let cat = catalogue();
    {
        let c = raw(&f.path);
        c.execute_batch("BEGIN").unwrap();
        for n in 0..MAX_CAMERAS {
            c.execute(
                "INSERT INTO cameras VALUES (?1, 'acme/c1', 554, '/m', NULL, ?2, ?2, 0)",
                rusqlite::params![format!("c{n:04}"), T0],
            )
            .unwrap();
        }
        c.execute_batch("COMMIT").unwrap();
    }
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), MAX_CAMERAS);
    let before = generation(&idx);
    let e = idx.upsert_camera(&simple("zzz"), &cat, at(T0)).unwrap_err();
    assert!(
        matches!(e, IndexError::TooManyCameras { max } if max == MAX_CAMERAS),
        "{e:?}"
    );
    assert_eq!(generation(&idx), before);
    // Replacing an existing camera is still allowed when full.
    idx.upsert_camera(&simple("c0007"), &cat, at(T0 + 1))
        .unwrap();
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), MAX_CAMERAS);
}

/// `insert_camera` never replaces: the second of two inserts of one id is refused, with the first
/// row, its `created_at` and the generation untouched; the vetting and the bound are the
/// upsert's.
#[test]
fn insert_camera_refuses_an_existing_id_and_changes_nothing() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    idx.insert_camera(&simple("one"), &cat, at(T0)).unwrap();
    let before = generation(&idx);
    let other = record("one", ("acme", "c2"), 8554, "/plain", None);
    let e = idx.insert_camera(&other, &cat, at(T0 + 5)).unwrap_err();
    assert!(matches!(e, IndexError::CameraExists), "{e:?}");
    assert_eq!(generation(&idx), before);
    let got = idx.get_camera(&cam("one"), &cat).unwrap().unwrap();
    assert_eq!(got.record(), &simple("one"));
    assert_eq!(got.updated_at(), at(T0));
    // An unlisted query is refused as for upsert, and nothing is written.
    let bad = record("two", ("acme", "c2"), 554, "/s?x=1", None);
    let e = idx.insert_camera(&bad, &cat, at(T0)).unwrap_err();
    assert!(
        matches!(e, IndexError::CameraQueryNotAllowed { .. }),
        "{e:?}"
    );
    assert!(idx.get_camera(&cam("two"), &cat).unwrap().is_none());
    // Upsert still replaces.
    idx.upsert_camera(&other, &cat, at(T0 + 9)).unwrap();
    assert_eq!(
        idx.get_camera(&cam("one"), &cat).unwrap().unwrap().record(),
        &other
    );
}

#[test]
fn insert_camera_respects_the_bound() {
    let (f, mut idx) = open_new();
    let cat = catalogue();
    {
        let c = raw(&f.path);
        c.execute_batch("BEGIN").unwrap();
        for n in 0..MAX_CAMERAS {
            c.execute(
                "INSERT INTO cameras VALUES (?1, 'acme/c1', 554, '/m', NULL, ?2, ?2, 0)",
                rusqlite::params![format!("c{n:04}"), T0],
            )
            .unwrap();
        }
        c.execute_batch("COMMIT").unwrap();
    }
    let e = idx.insert_camera(&simple("zzz"), &cat, at(T0)).unwrap_err();
    assert!(matches!(e, IndexError::TooManyCameras { .. }), "{e:?}");
    let e = idx
        .insert_camera(&simple("c0007"), &cat, at(T0))
        .unwrap_err();
    assert!(matches!(e, IndexError::CameraExists), "{e:?}");
}

// ---- generation bump (P2) --------------------------------------------------------------

#[test]
fn writes_bump_the_generation_and_refusals_and_no_ops_do_not() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    let g0 = generation(&idx);
    idx.upsert_camera(&simple("cam1"), &cat, at(T0)).unwrap();
    assert_eq!(generation(&idx), g0 + 1);
    idx.upsert_camera(&simple("cam1"), &cat, at(T0 + 1))
        .unwrap();
    assert_eq!(generation(&idx), g0 + 2);
    // Reads do not.
    idx.get_camera(&cam("cam1"), &cat).unwrap();
    idx.list_cameras(&cat).unwrap();
    idx.orphan_camera_ids().unwrap();
    assert_eq!(generation(&idx), g0 + 2);
    // A refused upsert (query not allowed) writes nothing.
    let bad = record("cam2", ("acme", "c1"), 554, "/s?channel=9", None);
    assert!(idx.upsert_camera(&bad, &cat, at(T0)).is_err());
    assert_eq!(generation(&idx), g0 + 2);
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), 1);
    // remove: one bump when a row went, none for a missing id.
    assert!(idx.remove_camera(&cam("cam1")).unwrap());
    assert_eq!(generation(&idx), g0 + 3);
    assert!(!idx.remove_camera(&cam("cam1")).unwrap());
    assert!(!idx.remove_camera(&cam("nope")).unwrap());
    assert_eq!(generation(&idx), g0 + 3);
}

// ---- the path and query refusals (single choke point) ----------------------------------

const CRED_NAMES: [&str; 9] = [
    "pass", "password", "pwd", "user", "usr", "token", "auth", "key", "secret",
];

fn case_variants(name: &str) -> Vec<String> {
    let mut cap = name.to_owned();
    cap[..1].make_ascii_uppercase();
    vec![name.to_owned(), name.to_ascii_uppercase(), cap]
}

/// Every shape a credential parameter can take in a path, for every listed name, three cases.
fn credential_paths() -> Vec<String> {
    let mut out = Vec::new();
    for name in CRED_NAMES {
        for n in case_variants(name) {
            for shape in [
                format!("/s?{n}=v"),
                format!("/s?a=1&{n}=v"),
                format!("/s?a=1&{n}"),
                format!("/s?{n}"),
                format!("/{n}=v"),
                format!("/s;{n}=v"),
                format!("/s?a=1;{n}=v"),
                format!("/s?{LISTED}&{n}=v"),
            ] {
                out.push(shape);
            }
        }
    }
    out
}

/// Path shapes refused by core's rules, with the rule.
fn syntax_paths() -> Vec<(String, CameraError)> {
    let mut out = vec![
        ("/a@b".to_owned(), CameraError::PathCharset),
        ("/@".to_owned(), CameraError::PathCharset),
        ("/a?x=1@2".to_owned(), CameraError::PathCharset),
        (format!("{LISTED}@h"), CameraError::PathCharset),
        ("@/a".to_owned(), CameraError::PathStart),
        ("/a/../b".to_owned(), CameraError::PathDotSegment),
        ("//x".to_owned(), CameraError::PathStart),
        ("relative".to_owned(), CameraError::PathStart),
        ("/a b".to_owned(), CameraError::PathCharset),
        ("/a#b".to_owned(), CameraError::PathCharset),
        ("/a%41".to_owned(), CameraError::PathCharset),
        (format!("/{}", "a".repeat(512)), CameraError::PathTooLong),
    ];
    for name in CRED_NAMES {
        for n in case_variants(name) {
            out.push((format!("/s?{n}=v"), CameraError::PathCredentialParam));
        }
    }
    out
}

/// Queries the catalogue does not list for `acme/c1`.
const UNLISTED: [&str; 8] = [
    "/cam/realmonitor?channel=2&subtype=0",
    "/cam/realmonitor?channel=1&subtype=0&x=1",
    "/cam/realmonitor?CHANNEL=1&subtype=0",
    "/cam/realmonitor?channel=1",
    "/s?x=1",
    "/s?",
    "/cam/realmonitor?channel=1&subtype=0?",
    "/s?a=b",
];

#[test]
fn vet_path_refuses_the_whole_surface_and_accepts_the_listed() {
    let cat = catalogue();
    let c1 = ModelRef::new("acme", "c1").unwrap();
    for field in ["main_path", "sub_path"] {
        for path in credential_paths() {
            // The same path is refused whether the rule is core's or the allow-list's.
            let e = vet_path(field, &c1, &cat, &path).unwrap_err();
            assert!(
                matches!(e, IndexError::CameraPathInvalid { field: f, source: CameraError::PathCredentialParam } if f == field)
                    || matches!(e, IndexError::CameraQueryNotAllowed { field: f } if f == field),
                "{path}: {e:?}"
            );
        }
        for (path, rule) in syntax_paths() {
            let e = vet_path(field, &c1, &cat, &path).unwrap_err();
            assert!(
                matches!(e, IndexError::CameraPathInvalid { field: f, source } if f == field && source == rule),
                "{path}: {e:?}"
            );
        }
        for path in UNLISTED {
            let e = vet_path(field, &c1, &cat, path).unwrap_err();
            assert!(
                matches!(e, IndexError::CameraQueryNotAllowed { field: f } if f == field),
                "{path}: {e:?}"
            );
        }
        // A listed query is allowed for the model that lists it only.
        assert_eq!(vet_path(field, &c1, &cat, LISTED).unwrap().as_str(), LISTED);
        for other in [("acme", "c2"), ("acme", "nope"), ("zed", "c1")] {
            let m = ModelRef::new(other.0, other.1).unwrap();
            let e = vet_path(field, &m, &cat, LISTED).unwrap_err();
            assert!(
                matches!(e, IndexError::CameraQueryNotAllowed { .. }),
                "{other:?}"
            );
            // ... while a path without a query needs no catalogue entry.
            assert!(vet_path(field, &m, &cat, "/stream1").is_ok());
        }
        // An empty catalogue allows no query at all.
        assert!(matches!(
            vet_path(field, &c1, &[], LISTED),
            Err(IndexError::CameraQueryNotAllowed { .. })
        ));
    }
}

#[test]
fn upsert_refuses_an_unlisted_query_on_either_path_and_writes_nothing() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    let before = generation(&idx);
    for path in UNLISTED {
        for (main, sub, field) in [
            (path, None, "main_path"),
            ("/m", Some(path), "sub_path"),
            (path, Some(path), "main_path"),
        ] {
            let r = record("cam1", ("acme", "c1"), 554, main, sub);
            let e = idx.upsert_camera(&r, &cat, at(T0)).unwrap_err();
            assert!(
                matches!(e, IndexError::CameraQueryNotAllowed { field: f } if f == field),
                "{path}: {e:?}"
            );
        }
        // Model without a catalogue entry, and one that lists no query.
        for m in [("acme", "c2"), ("acme", "nope")] {
            let r = record("cam1", m, 554, path, None);
            assert!(idx.upsert_camera(&r, &cat, at(T0)).is_err(), "{path} {m:?}");
        }
    }
    assert_eq!(generation(&idx), before);
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), 0);
    // The listed query goes in.
    let ok = record("cam1", ("acme", "c1"), 554, LISTED, Some(LISTED));
    idx.upsert_camera(&ok, &cat, at(T0)).unwrap();
    // A record cannot even be built with a credential path or an `@`: core refuses first.
    for path in credential_paths() {
        assert!(RtspPath::new(&path).is_err(), "{path}");
    }
}

#[test]
fn a_stored_row_is_vetted_again_on_read_for_every_refused_path() {
    let (f, idx) = open_new();
    let cat = catalogue();
    // Every refused path, in both columns, as a raw row (a file edited outside this API).
    let mut cases: Vec<(String, &'static str, bool)> = Vec::new(); // (path, column, is_sub)
    let all: Vec<String> = credential_paths()
        .into_iter()
        .chain(syntax_paths().into_iter().map(|(p, _)| p))
        .chain(UNLISTED.iter().map(|s| (*s).to_owned()))
        .collect();
    for p in &all {
        cases.push((p.clone(), "main_path", false));
        cases.push((p.clone(), "sub_path", true));
    }
    {
        let c = raw(&f.path);
        c.execute_batch("BEGIN; PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        for (n, (path, _, is_sub)) in cases.iter().enumerate() {
            let (main, sub) = if *is_sub {
                ("'/ok'".to_owned(), sql_text(path))
            } else {
                (sql_text(path), "NULL".to_owned())
            };
            c.execute_batch(&format!(
                "INSERT INTO cameras VALUES ('c{n:04}', 'acme/c1', 554, {main}, {sub}, {T0}, {T0}, 0);"
            ))
            .unwrap();
        }
        c.execute_batch("COMMIT;").unwrap();
    }
    assert!(cases.len() > 400, "the table is the surface, not a sample");
    for (n, (path, column, _)) in cases.iter().enumerate() {
        let id = cam(&format!("c{n:04}"));
        let e = idx.get_camera(&id, &cat).unwrap_err();
        assert!(
            matches!(
                e,
                IndexError::CameraPathInvalid { field, .. }
                | IndexError::CameraQueryNotAllowed { field } if field == *column
            ),
            "{path} in {column}: {e:?}"
        );
        // The error text never echoes the path (SEC-6).
        assert!(!e.to_string().contains(path.as_str()), "{e}");
    }
    // One bad row fails the whole listing.
    assert!(idx.list_cameras(&cat).is_err());
}

#[test]
fn a_row_valid_under_one_catalogue_is_refused_on_read_under_a_stricter_one() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    idx.upsert_camera(
        &record("cam1", ("acme", "c1"), 554, LISTED, None),
        &cat,
        at(T0),
    )
    .unwrap();
    assert!(idx.get_camera(&cam("cam1"), &cat).unwrap().is_some());
    assert!(matches!(
        idx.get_camera(&cam("cam1"), &[]),
        Err(IndexError::CameraQueryNotAllowed { field: "main_path" })
    ));
    assert!(matches!(
        idx.list_cameras(&[]),
        Err(IndexError::CameraQueryNotAllowed { field: "main_path" })
    ));
}

#[test]
fn every_new_error_variant_has_a_message_that_names_the_rule_only() {
    let cat = catalogue();
    let c1 = ModelRef::new("acme", "c1").unwrap();
    let secret = "Tr0ub4dor-sentinel";
    let e = vet_path("main_path", &c1, &cat, &format!("/s?pass={secret}")).unwrap_err();
    assert!(matches!(e, IndexError::CameraPathInvalid { .. }));
    assert!(
        e.to_string().contains("main_path") && !e.to_string().contains(secret),
        "{e}"
    );
    assert!(!format!("{e:?}").contains(secret), "{e:?}");
    let e = vet_path("sub_path", &c1, &cat, &format!("/s?x={secret}")).unwrap_err();
    assert!(matches!(e, IndexError::CameraQueryNotAllowed { .. }));
    assert!(
        e.to_string().contains("sub_path") && !e.to_string().contains(secret),
        "{e}"
    );
    assert!(!format!("{e:?}").contains(secret), "{e:?}");
    let e = IndexError::CorruptCameraRow { field: "model" };
    assert_eq!(e.to_string(), "stored camera row is invalid: model");
    let e = IndexError::TooManyCameras { max: 3 };
    assert_eq!(e.to_string(), "the camera registry is full (3 cameras)");
    for e in [
        IndexError::CameraQueryNotAllowed { field: "main_path" },
        IndexError::CorruptCameraRow { field: "id" },
        IndexError::TooManyCameras { max: 1 },
        IndexError::CameraExists,
    ] {
        assert!(!e.is_transient());
    }
}

// ---- a corrupt row is a typed error, per column ----------------------------------------

#[test]
fn every_column_of_a_corrupt_row_is_a_typed_error_naming_the_column() {
    let (f, idx) = open_new();
    let cat = catalogue();
    let long_id = "'a12345678901234567890123456789012'"; // 34 bytes
    let cases: Vec<(&str, Raw, &str)> = vec![
        ("id empty", Raw { id: "''", ..base() }, "id"),
        (
            "id upper",
            Raw {
                id: "'Cam1'",
                ..base()
            },
            "id",
        ),
        (
            "id digit first",
            Raw {
                id: "'1cam'",
                ..base()
            },
            "id",
        ),
        (
            "id space",
            Raw {
                id: "'cam 1'",
                ..base()
            },
            "id",
        ),
        (
            "id too long",
            Raw {
                id: long_id,
                ..base()
            },
            "id",
        ),
        (
            "id not utf-8",
            Raw {
                id: "CAST(x'ff61' AS TEXT)",
                ..base()
            },
            "id",
        ),
        (
            "model empty",
            Raw {
                model: "''",
                ..base()
            },
            "model",
        ),
        (
            "model no slash",
            Raw {
                model: "'acme'",
                ..base()
            },
            "model",
        ),
        (
            "model empty model",
            Raw {
                model: "'acme/'",
                ..base()
            },
            "model",
        ),
        (
            "model empty vendor",
            Raw {
                model: "'/c1'",
                ..base()
            },
            "model",
        ),
        (
            "model upper",
            Raw {
                model: "'Acme/c1'",
                ..base()
            },
            "model",
        ),
        (
            "model two slashes",
            Raw {
                model: "'a/b/c'",
                ..base()
            },
            "model",
        ),
        (
            "model underscore",
            Raw {
                model: "'acme/c_1'",
                ..base()
            },
            "model",
        ),
        (
            "model not utf-8",
            Raw {
                model: "CAST(x'ff2f61' AS TEXT)",
                ..base()
            },
            "model",
        ),
        (
            "port zero",
            Raw {
                port: "0",
                ..base()
            },
            "rtsp_port",
        ),
        (
            "port negative",
            Raw {
                port: "-1",
                ..base()
            },
            "rtsp_port",
        ),
        (
            "port 65536",
            Raw {
                port: "65536",
                ..base()
            },
            "rtsp_port",
        ),
        (
            "port huge",
            Raw {
                port: "9223372036854775807",
                ..base()
            },
            "rtsp_port",
        ),
        (
            "main empty",
            Raw {
                main: "''",
                ..base()
            },
            "main_path",
        ),
        (
            "main not utf-8",
            Raw {
                main: "CAST(x'2fff' AS TEXT)",
                ..base()
            },
            "main_path",
        ),
        (
            "sub empty",
            Raw {
                sub: "''",
                ..base()
            },
            "sub_path",
        ),
        (
            "sub not utf-8",
            Raw {
                sub: "CAST(x'2fff' AS TEXT)",
                ..base()
            },
            "sub_path",
        ),
        (
            "created zero",
            Raw {
                created: "0",
                ..base()
            },
            "created_at_ms",
        ),
        (
            "created negative",
            Raw {
                created: "-1",
                ..base()
            },
            "created_at_ms",
        ),
        (
            "created before 2000",
            Raw {
                created: "946684799999",
                ..base()
            },
            "created_at_ms",
        ),
        (
            "created after 2099",
            Raw {
                created: "4102444800000",
                ..base()
            },
            "created_at_ms",
        ),
        (
            "created max",
            Raw {
                created: "9223372036854775807",
                ..base()
            },
            "created_at_ms",
        ),
        (
            "updated zero",
            Raw {
                updated: "0",
                ..base()
            },
            "updated_at_ms",
        ),
        (
            "updated negative",
            Raw {
                updated: "-1",
                ..base()
            },
            "updated_at_ms",
        ),
        (
            "updated before 2000",
            Raw {
                updated: "946684799999",
                ..base()
            },
            "updated_at_ms",
        ),
        (
            "updated after 2099",
            Raw {
                updated: "4102444800000",
                ..base()
            },
            "updated_at_ms",
        ),
        (
            "updated max",
            Raw {
                updated: "9223372036854775807",
                ..base()
            },
            "updated_at_ms",
        ),
        (
            "basic 2",
            Raw {
                basic: "2",
                ..base()
            },
            "allow_basic_auth",
        ),
    ];
    let columns: std::collections::BTreeSet<_> = cases.iter().map(|c| c.2).collect();
    assert_eq!(columns.len(), 8, "a case for every column");
    for (label, row, field) in cases {
        let c = raw(&f.path);
        c.execute_batch("DELETE FROM cameras").unwrap();
        insert_raw(&c, &row);
        let e = idx.list_cameras(&cat).unwrap_err();
        assert!(
            matches!(e, IndexError::CorruptCameraRow { field: got } if got == field),
            "{label}: {e:?}"
        );
        if field != "id" {
            let e = idx.get_camera(&cam("cam1"), &cat).unwrap_err();
            assert!(
                matches!(e, IndexError::CorruptCameraRow { field: got } if got == field),
                "{label} (get): {e:?}"
            );
        }
        assert!(!e.to_string().contains("cam1"), "{label}: {e}");
    }
    // The control: the base row reads back.
    let c = raw(&f.path);
    c.execute_batch("DELETE FROM cameras").unwrap();
    insert_raw(&c, &base());
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), 1);
}

#[test]
fn the_schema_checks_refuse_what_the_reader_would() {
    let (f, _idx) = open_new();
    let c = raw(&f.path);
    let long = |n: usize| sql_text(&format!("/{}", "a".repeat(n - 1)));
    let row = |r: &Raw| {
        c.execute_batch(&format!(
            "INSERT INTO cameras VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
            r.id, r.model, r.port, r.main, r.sub, r.created, r.updated, r.basic
        ))
    };
    let m513 = long(513);
    let m512 = long(512);
    let model65 = sql_text(&"m".repeat(65));
    let model64 = sql_text(&"m".repeat(64));
    let id33 = sql_text(&"c".repeat(33));
    let id32 = sql_text(&"c".repeat(32));
    // The leaked strs live as long as the test; Raw holds &'static str.
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    for (label, r, ok) in [
        ("base", base(), true),
        (
            "id 33",
            Raw {
                id: leak(id33),
                ..base()
            },
            false,
        ),
        (
            "id 32",
            Raw {
                id: leak(id32),
                ..base()
            },
            true,
        ),
        ("id empty", Raw { id: "''", ..base() }, false),
        (
            "model empty",
            Raw {
                id: "'a'",
                model: "''",
                ..base()
            },
            false,
        ),
        (
            "model 65",
            Raw {
                id: "'b'",
                model: leak(model65),
                ..base()
            },
            false,
        ),
        (
            "model 64",
            Raw {
                id: "'c'",
                model: leak(model64),
                ..base()
            },
            true,
        ),
        (
            "port 0",
            Raw {
                id: "'d'",
                port: "0",
                ..base()
            },
            false,
        ),
        (
            "port 65536",
            Raw {
                id: "'e'",
                port: "65536",
                ..base()
            },
            false,
        ),
        (
            "port 65535",
            Raw {
                id: "'f'",
                port: "65535",
                ..base()
            },
            true,
        ),
        (
            "main empty",
            Raw {
                id: "'g'",
                main: "''",
                ..base()
            },
            false,
        ),
        (
            "main 513",
            Raw {
                id: "'h'",
                main: leak(m513),
                ..base()
            },
            false,
        ),
        (
            "main 512",
            Raw {
                id: "'i'",
                main: leak(m512.clone()),
                ..base()
            },
            true,
        ),
        (
            "sub empty",
            Raw {
                id: "'j'",
                sub: "''",
                ..base()
            },
            false,
        ),
        (
            "sub 513",
            Raw {
                id: "'k'",
                sub: leak(long(513)),
                ..base()
            },
            false,
        ),
        (
            "sub 512",
            Raw {
                id: "'l'",
                sub: leak(m512),
                ..base()
            },
            true,
        ),
        (
            "sub null",
            Raw {
                id: "'m'",
                sub: "NULL",
                ..base()
            },
            true,
        ),
        (
            "basic 1",
            Raw {
                id: "'n'",
                basic: "1",
                ..base()
            },
            true,
        ),
        (
            "basic 2",
            Raw {
                id: "'o'",
                basic: "2",
                ..base()
            },
            false,
        ),
        (
            "basic null",
            Raw {
                id: "'p'",
                basic: "NULL",
                ..base()
            },
            false,
        ),
    ] {
        assert_eq!(row(&r).is_ok(), ok, "{label}");
    }
}

// ---- remove leaves segments as orphans --------------------------------------------------

#[test]
fn remove_keeps_the_segments_and_they_are_orphans_by_left_join() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    // No foreign key: segments of a camera that was never registered insert fine.
    let s0 = idx
        .insert(&rec("cam9", BASE, 1000, 5, 1), Tier::Hot)
        .unwrap();
    assert_eq!(idx.orphan_camera_ids().unwrap(), vec![cam("cam9")]);
    idx.upsert_camera(&simple("cam1"), &cat, at(T0)).unwrap();
    idx.upsert_camera(&simple("cam2"), &cat, at(T0)).unwrap();
    let s1 = idx
        .insert(&rec("cam1", BASE, 1000, 5, 1), Tier::Hot)
        .unwrap();
    let s2 = idx
        .insert(&rec("cam1", BASE + 1000, 1000, 5, 1), Tier::Archive)
        .unwrap();
    let s3 = idx
        .insert(&rec("cam2", BASE, 1000, 5, 1), Tier::Hot)
        .unwrap();
    assert_eq!(idx.orphan_camera_ids().unwrap(), vec![cam("cam9")]);

    assert!(idx.remove_camera(&cam("cam1")).unwrap());
    assert_eq!(idx.get_camera(&cam("cam1"), &cat).unwrap(), None);
    assert!(idx.get_camera(&cam("cam2"), &cat).unwrap().is_some());
    // Every segment is still there, untouched, tier included.
    for (id, tier) in [
        (s0, Tier::Hot),
        (s1, Tier::Hot),
        (s2, Tier::Archive),
        (s3, Tier::Hot),
    ] {
        assert_eq!(idx.get(id).unwrap().unwrap().tier, tier);
    }
    let n: i64 = idx
        .conn
        .query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 4);
    // The orphans, by the LEFT JOIN of ADR 0005 section 5, computed here independently.
    let by_sql: Vec<String> = idx
        .conn
        .prepare(
            "SELECT DISTINCT s.camera_id FROM segments s LEFT JOIN cameras c \
             ON c.id = s.camera_id WHERE c.id IS NULL ORDER BY 1",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(by_sql, ["cam1", "cam9"]);
    assert_eq!(
        idx.orphan_camera_ids().unwrap(),
        vec![cam("cam1"), cam("cam9")]
    );

    // Registering the camera again adopts its segments: no longer orphans.
    idx.upsert_camera(&simple("cam1"), &cat, at(T0 + 9))
        .unwrap();
    assert_eq!(idx.orphan_camera_ids().unwrap(), vec![cam("cam9")]);
}

#[test]
fn a_corrupt_segment_camera_id_is_a_typed_error_in_the_orphan_listing() {
    let (f, idx) = open_new();
    raw(&f.path)
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON; INSERT INTO segments \
             (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) \
             VALUES ('Bad Id', 1700000000000, 1000, 1700000001000, 5, 1, 0);",
        )
        .unwrap();
    assert!(matches!(
        idx.orphan_camera_ids(),
        Err(IndexError::CorruptCameraRow { field: "camera_id" })
    ));
}

// ---- the leak test ----------------------------------------------------------------------

/// Sentinels no real value would equal. They are the host, the display name and a credential of
/// synthetic cameras; none of them has any way into the registry's API.
const HOST_SENTINEL: &str = "leakhost-7c1e9a.example.invalid";
const NAME_SENTINEL: &str = "LeakName7c1e9a Door";
const USER_SENTINEL: &str = "leakuser7c1e9a";
const PASS_SENTINEL: &str = "LeakPass7c1e9a-Xk";

fn bytes_of(path: &std::path::Path) -> Vec<u8> {
    let mut all = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        if let Ok(b) = std::fs::read(&p) {
            all.extend(b);
        }
    }
    all
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn the_index_bytes_hold_no_host_name_or_credential() {
    let (f, mut idx) = open_new();
    let cat = catalogue();
    let sentinels = [HOST_SENTINEL, NAME_SENTINEL, USER_SENTINEL, PASS_SENTINEL];
    for (n, id) in ["cam1", "cam2", "cam3"].into_iter().enumerate() {
        let camera = Camera::new(
            cam(id),
            DisplayName::new(&format!("{NAME_SENTINEL} {n}")).unwrap(),
            ModelRef::new("acme", "c1").unwrap(),
            Host::new(HOST_SENTINEL).unwrap(),
            NonZeroU16::new(554).unwrap(),
            StreamSet::new(
                RtspPath::new("/main").unwrap(),
                Some(RtspPath::new(LISTED).unwrap()),
            ),
        );
        // The only way to register it: its registry share. Host and name have no parameter.
        idx.upsert_camera(&CameraRecord::from_camera(&camera), &cat, at(T0 + 1000))
            .unwrap();
        idx.upsert_camera(&CameraRecord::from_camera(&camera), &cat, at(T0 + 2000))
            .unwrap();
        idx.insert(&rec(id, BASE, 1000, 5, 1), Tier::Hot).unwrap();
    }
    idx.remove_camera(&cam("cam3")).unwrap();
    let _ = (USER_SENTINEL, PASS_SENTINEL); // credentials have no type that reaches this crate
    // While open (the data is in the -wal) and after a checkpoint (it is in the main file).
    let live = bytes_of(&f.path);
    assert!(
        contains(&live, "acme/c1") && contains(&live, "/main"),
        "the grep sees the data"
    );
    for s in sentinels {
        assert!(!contains(&live, s), "{s} found in the live index and -wal");
    }
    idx.conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let main = std::fs::read(&f.path).unwrap();
    assert!(contains(&main, "acme/c1"));
    drop(idx);
    let closed = bytes_of(&f.path);
    for s in sentinels {
        assert!(
            !contains(&main, s) && !contains(&closed, s),
            "{s} found after checkpoint"
        );
    }
}

// ---- schema identity and hygiene --------------------------------------------------------

#[test]
fn the_cameras_table_is_exactly_the_adr_columns_and_has_no_foreign_key() {
    let (_f, idx) = open_new();
    let cols: Vec<(String, String, bool, bool)> = idx
        .conn
        .prepare(
            "SELECT name, type, \"notnull\", pk FROM pragma_table_info('cameras') ORDER BY cid",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get::<_, i64>(2)? == 1,
                r.get::<_, i64>(3)? == 1,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let want = [
        ("id", "TEXT", true, true),
        ("model", "TEXT", true, false),
        ("rtsp_port", "INTEGER", true, false),
        ("main_path", "TEXT", true, false),
        ("sub_path", "TEXT", false, false),
        ("created_at_ms", "INTEGER", true, false),
        ("updated_at_ms", "INTEGER", true, false),
        ("allow_basic_auth", "INTEGER", true, false),
    ];
    let want: Vec<_> = want
        .iter()
        .map(|(a, b, c, d)| ((*a).to_owned(), (*b).to_owned(), *c, *d))
        .collect();
    assert_eq!(cols, want);
    for table in ["cameras", "segments"] {
        let n: i64 = idx
            .conn
            .query_row(
                &format!("SELECT count(*) FROM pragma_foreign_key_list('{table}')"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "{table} has a foreign key");
    }
    let strict: i64 = idx
        .conn
        .query_row("SELECT strict FROM pragma_table_list('cameras')", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(strict, 1);
    let version: i64 = idx
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 4);
}

fn code_of(file: &str) -> String {
    std::fs::read_to_string(format!("{}/src/{file}", env!("CARGO_MANIFEST_DIR")))
        .unwrap()
        .lines()
        .take_while(|l| !l.starts_with("#[cfg(test)]"))
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_migration_has_no_credential_host_or_name_column() {
    let sql: String = std::fs::read_to_string(format!(
        "{}/migrations/002_cameras.sql",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
    .lines()
    .filter(|l| !l.trim_start().starts_with("--"))
    .collect::<Vec<_>>()
    .join("\n")
    .to_ascii_lowercase();
    for bad in [
        "host",
        "name",
        "credential",
        "password",
        "secret",
        "token",
        "blob",
        "display",
    ] {
        assert!(!sql.contains(bad), "{bad}");
    }
}

#[test]
fn the_registry_api_has_no_type_that_can_carry_a_host_name_or_credential() {
    let code = code_of("cameras.rs");
    for bad in ["Host", "DisplayName", "Credential", "Secret"] {
        assert!(!code.contains(bad), "cameras.rs mentions {bad}");
    }
}

#[test]
fn camera_paths_are_vetted_at_one_choke_point() {
    // `RtspPath::new` and the allow-list are called once in the crate, inside `vet_path`.
    let mut news = 0;
    let mut allowed = 0;
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().is_some_and(|x| x == "rs") {
            let code = code_of(&p.file_name().unwrap().to_string_lossy());
            news += code.matches("RtspPath::new(").count()
                + code.matches("RtspPath::from_str(").count();
            allowed += code.matches("query_allowed(").count();
        }
    }
    assert_eq!((news, allowed), (1, 1));
    let code = code_of("cameras.rs");
    let at = code.find("fn vet_path").unwrap();
    let body: String = code[at..].chars().take_while(|c| *c != '}').collect();
    assert!(body.contains("RtspPath::new(") && code[at..].contains("query_allowed("));
    // Every path that is stored or read goes through it.
    assert_eq!(
        code.matches("vet_path(").count(),
        4,
        "definition, upsert main, upsert sub, path_col"
    );
}

// ---- the Basic authentication opt-in (ticket #225) --------------------------------------

#[test]
fn the_basic_opt_in_is_off_by_default_and_round_trips_through_insert_and_upsert() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    // Default: a record built with `new` stores 0.
    idx.insert_camera(&simple("cam1"), &cat, at(T0)).unwrap();
    assert!(
        !idx.get_camera(&cam("cam1"), &cat)
            .unwrap()
            .unwrap()
            .record()
            .allow_basic_auth()
    );
    // On: insert stores 1, list and get read it back.
    idx.insert_camera(&simple("cam2").with_allow_basic_auth(true), &cat, at(T0))
        .unwrap();
    let all = idx.list_cameras(&cat).unwrap();
    let flags: Vec<_> = all.iter().map(|s| s.record().allow_basic_auth()).collect();
    assert_eq!(flags, [false, true]);
    assert!(
        idx.get_camera(&cam("cam2"), &cat)
            .unwrap()
            .unwrap()
            .record()
            .allow_basic_auth()
    );
    // An upsert replaces the whole row, flag included, in both directions.
    idx.upsert_camera(
        &simple("cam1").with_allow_basic_auth(true),
        &cat,
        at(T0 + 1),
    )
    .unwrap();
    idx.upsert_camera(&simple("cam2"), &cat, at(T0 + 1))
        .unwrap();
    let flags: Vec<_> = idx
        .list_cameras(&cat)
        .unwrap()
        .iter()
        .map(|s| s.record().allow_basic_auth())
        .collect();
    assert_eq!(flags, [true, false]);
}

/// The index of the previous release (version 3, no `allow_basic_auth` column) with a row opens,
/// migrates to 4 and every existing camera has the opt-in off.
#[test]
fn a_version_3_index_migrates_to_4_with_every_camera_off() {
    use crate::migrate::MIGRATIONS;
    let f = fixture();
    drop(Index::open_with(&f.path, &MIGRATIONS[..3], || {}).unwrap());
    {
        let c = raw(&f.path);
        let cols: i64 = c
            .query_row(
                "SELECT count(*) FROM pragma_table_info('cameras') WHERE name = 'allow_basic_auth'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cols, 0, "the fixture is the old schema");
        c.execute_batch(
            "INSERT INTO cameras VALUES ('old1', 'acme/c1', 554, '/main', '/sub', 1700000000000, 1700000000000), \
             ('old2', 'acme/c1', 554, '/main', NULL, 1700000000000, 1700000000000);",
        )
        .unwrap();
    }
    // The read-only open reports the old schema without touching it.
    assert!(matches!(
        Index::open_read_only(&f.path).unwrap_err(),
        IndexError::NeedsMigration
    ));
    let idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    let rows = idx.list_cameras(&cat).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|s| !s.record().allow_basic_auth()));
    drop(idx);
    Index::open_read_only(&f.path).unwrap();
}

#[test]
fn set_camera_basic_auth_changes_the_flag_and_updated_at_only() {
    let (_f, mut idx) = open_new();
    let cat = catalogue();
    idx.insert_camera(&simple("cam1"), &cat, at(T0)).unwrap();
    let before = idx.get_camera(&cam("cam1"), &cat).unwrap().unwrap();
    let g = generation(&idx);
    assert!(
        idx.set_camera_basic_auth(&cam("cam1"), true, at(T0 + 5))
            .unwrap()
    );
    let after = idx.get_camera(&cam("cam1"), &cat).unwrap().unwrap();
    assert!(after.record().allow_basic_auth());
    assert_eq!(after.record().streams(), before.record().streams());
    assert_eq!(after.record().port(), before.record().port());
    assert_eq!(after.created_at(), before.created_at());
    assert_eq!(after.updated_at(), at(T0 + 5));
    assert!(generation(&idx) > g, "a write bumps the generation");
    assert!(
        idx.set_camera_basic_auth(&cam("cam1"), false, at(T0 + 6))
            .unwrap()
    );
    assert!(
        !idx.get_camera(&cam("cam1"), &cat)
            .unwrap()
            .unwrap()
            .record()
            .allow_basic_auth()
    );
    // An unknown id creates nothing and writes nothing.
    let g = generation(&idx);
    assert!(
        !idx.set_camera_basic_auth(&cam("nope"), true, at(T0 + 7))
            .unwrap()
    );
    assert_eq!(generation(&idx), g);
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), 1);
}
