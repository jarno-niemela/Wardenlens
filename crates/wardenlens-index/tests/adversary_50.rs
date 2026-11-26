//! Adversarial tests for #50 (PR #152): the camera registry. Synthetic data only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::useless_format,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use wardenlens_core::camera::{CameraId, ModelRef, RtspPath, StreamSet};
use wardenlens_core::catalogue::CatalogueEntry;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::UnixMs;
use wardenlens_index::{CameraRecord, Index, IndexError, MAX_CAMERAS};

const T0: i64 = 1_700_000_000_000;
const LISTED: &str = "/cam/realmonitor?channel=1&subtype=0";

struct Fx {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn fixture() -> Fx {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = d.path().join("index.db");
    Fx { _dir: d, path }
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

fn at(ms: i64) -> UnixMs {
    UnixMs::new(ms).unwrap()
}

fn seg(camera: &str, start: i64) -> SegmentRecord {
    SegmentRecord::new(cam(camera), at(start), 1000, 5, 1)
}

fn entry(vendor: &str, model: &str, paths: &str) -> CatalogueEntry {
    CatalogueEntry::from_toml_str(&format!(
        "vendor = \"{vendor}\"\nmodel = \"{model}\"\nsupport = \"community\"\n\
         [[protocols]]\nkind = \"rtsp\"\npaths = [{paths}]\n\
         [[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n"
    ))
    .unwrap()
}

fn catalogue() -> Vec<CatalogueEntry> {
    vec![entry(
        "Acme",
        "C1",
        "\"/cam/realmonitor?channel=1&subtype=0\", \"/plain\"",
    )]
}

fn record(id: &str, model: (&str, &str), main: &str, sub: Option<&str>) -> CameraRecord {
    CameraRecord::new(
        cam(id),
        ModelRef::new(model.0, model.1).unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(
            RtspPath::new(main).unwrap(),
            sub.map(|s| RtspPath::new(s).unwrap()),
        ),
    )
}

fn raw(p: &Path) -> Connection {
    Connection::open(p).unwrap()
}

fn generation(p: &Path) -> i64 {
    raw(p)
        .query_row("SELECT generation FROM index_meta", [], |r| r.get(0))
        .unwrap()
}

fn snapshot(dir: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        let bytes = if e.file_type().unwrap().is_file() {
            Some(std::fs::read(e.path()).unwrap())
        } else {
            None
        };
        out.insert(name, bytes);
    }
    out
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

/// A version-1 index as the first release wrote it: the current file minus the cameras and token tables.
fn make_v1(f: &Fx) {
    let mut idx = Index::open(&f.path).unwrap();
    idx.insert(&seg("cam1", T0), Tier::Hot).unwrap();
    idx.insert(&seg("cam2", T0), Tier::Hot).unwrap();
    drop(idx);
    let c = raw(&f.path);
    c.execute_batch("DROP TABLE api_tokens; DROP TABLE cameras; PRAGMA user_version = 1;")
        .unwrap();
    drop(c);
    assert!(!sidecar(&f.path, "-wal").exists());
}

// ---- migration from a real version-1 file ---------------------------------------------

#[test]
fn a_version_1_index_migrates_to_2_keeping_segments_which_are_then_orphans() {
    let f = fixture();
    make_v1(&f);
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    assert_eq!(idx.list_cameras(&cat).unwrap(), vec![]);
    assert_eq!(
        idx.orphan_camera_ids().unwrap(),
        vec![cam("cam1"), cam("cam2")]
    );
    idx.upsert_camera(&record("cam1", ("acme", "c1"), LISTED, None), &cat, at(T0))
        .unwrap();
    assert_eq!(idx.orphan_camera_ids().unwrap(), vec![cam("cam2")]);
    drop(idx);
    let v: i64 = raw(&f.path)
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
}

#[test]
fn a_version_1_index_with_a_foreign_cameras_table_is_refused_untouched() {
    for ddl in [
        "CREATE TABLE cameras (id TEXT PRIMARY KEY, host TEXT, password TEXT);",
        // Same text as migration 2 but at version 1: still not the v1 schema.
        include_str!("../migrations/002_cameras.sql"),
    ] {
        let f = fixture();
        make_v1(&f);
        let c = raw(&f.path);
        c.execute_batch(ddl).unwrap();
        c.execute_batch("PRAGMA user_version = 1;").unwrap();
        drop(c);
        let dir = f.path.parent().unwrap().to_owned();
        let before = snapshot(&dir);
        let e = Index::open(&f.path).unwrap_err();
        assert!(matches!(e, IndexError::UnexpectedSchema), "{e:?}");
        assert_eq!(before, snapshot(&dir));
    }
}

#[test]
fn a_version_2_index_whose_cameras_table_gained_a_host_column_is_refused() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let c = raw(&f.path);
    c.execute_batch("ALTER TABLE cameras ADD COLUMN host TEXT;")
        .unwrap();
    drop(c);
    let e = Index::open(&f.path).unwrap_err();
    assert!(matches!(e, IndexError::UnexpectedSchema), "{e:?}");
}

// ---- upsert semantics ------------------------------------------------------------------

#[test]
#[ignore = "follow-up #153"]
fn an_upsert_with_an_earlier_clock_never_stores_updated_before_created() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    let r = record("cam1", ("acme", "c1"), "/plain", None);
    idx.upsert_camera(&r, &cat, at(T0 + 60_000)).unwrap();
    // The wall clock stepped back (NTP correction) before the next upsert.
    idx.upsert_camera(&r, &cat, at(T0)).unwrap();
    let got = idx.get_camera(&cam("cam1"), &cat).unwrap().unwrap();
    assert_eq!(got.created_at(), at(T0 + 60_000));
    assert!(
        got.updated_at() >= got.created_at(),
        "updated {:?} < created {:?}",
        got.updated_at(),
        got.created_at()
    );
}

#[test]
fn replacing_a_row_changes_every_registry_field_and_keeps_created_at() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = vec![
        entry("Acme", "C1", "\"/cam/realmonitor?channel=1&subtype=0\""),
        entry("Other Vendor", "X 9", "\"/live?ch=2\""),
    ];
    idx.upsert_camera(
        &record("cam1", ("acme", "c1"), LISTED, Some(LISTED)),
        &cat,
        at(T0),
    )
    .unwrap();
    let new = CameraRecord::new(
        cam("cam1"),
        ModelRef::new("other-vendor", "x-9").unwrap(),
        NonZeroU16::new(65535).unwrap(),
        StreamSet::new(RtspPath::new("/a?ch=2").unwrap(), None),
    );
    idx.upsert_camera(&new, &cat, at(T0 + 7)).unwrap();
    let got = idx.get_camera(&cam("cam1"), &cat).unwrap().unwrap();
    assert_eq!(got.record(), &new);
    assert_eq!((got.created_at(), got.updated_at()), (at(T0), at(T0 + 7)));
    assert_eq!(idx.list_cameras(&cat).unwrap().len(), 1);
}

#[test]
fn refusals_write_nothing_and_do_not_bump_the_generation() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    idx.upsert_camera(
        &record("cam1", ("acme", "c1"), "/plain", None),
        &cat,
        at(T0),
    )
    .unwrap();
    drop(idx);
    let g = generation(&f.path);
    let mut idx = Index::open(&f.path).unwrap();
    let long = "a".repeat(40);
    let refused = [
        // model text over 64 bytes
        record("cam2", (&long, &long), "/plain", None),
        // unlisted query on the sub path only
        record(
            "cam2",
            ("acme", "c1"),
            "/plain",
            Some("/x?channel=2&subtype=0"),
        ),
        // an unknown model with a query
        record("cam2", ("acme", "c9"), "/x?channel=1&subtype=0", None),
        // a replacement of cam1 with an unlisted query: cam1 must stay as it was
        record("cam1", ("acme", "c1"), "/x?a=1", None),
    ];
    for r in &refused {
        assert!(idx.upsert_camera(r, &cat, at(T0 + 1)).is_err());
    }
    let got = idx.get_camera(&cam("cam1"), &cat).unwrap().unwrap();
    assert_eq!(
        got.record(),
        &record("cam1", ("acme", "c1"), "/plain", None)
    );
    assert_eq!(got.updated_at(), at(T0));
    assert_eq!(idx.get_camera(&cam("cam2"), &cat).unwrap(), None);
    assert!(!idx.remove_camera(&cam("cam2")).unwrap());
    drop(idx);
    assert_eq!(generation(&f.path), g);
}

#[test]
fn model_text_boundary_is_exactly_64_bytes() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    // vendor 31 + "/" + model 32 = 64 bytes; one more is 65.
    let v = "v".repeat(31);
    let ok = record("cam1", (&v, &"m".repeat(32)), "/plain", None);
    idx.upsert_camera(&ok, &[], at(T0)).unwrap();
    assert_eq!(
        idx.get_camera(&cam("cam1"), &[]).unwrap().unwrap().record(),
        &ok
    );
    let bad = record("cam2", (&v, &"m".repeat(33)), "/plain", None);
    assert!(matches!(
        idx.upsert_camera(&bad, &[], at(T0)),
        Err(IndexError::InvalidRecord { field: "model" })
    ));
}

#[test]
fn a_512_byte_listed_path_round_trips_on_both_columns() {
    let q = "?channel=1&subtype=0";
    let main = format!("/{}{q}", "a".repeat(512 - 1 - q.len()));
    assert_eq!(main.len(), 512);
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    let r = record("cam1", ("acme", "c1"), &main, Some(&main));
    idx.upsert_camera(&r, &cat, at(T0)).unwrap();
    assert_eq!(idx.list_cameras(&cat).unwrap()[0].record(), &r);
}

// ---- any user's camera set ------------------------------------------------------------

#[test]
fn a_model_missing_from_the_catalogue_registers_with_query_free_paths() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    for (n, (v, m)) in [("zz-vendor", "q1"), ("generic", "onvif-cam"), ("a", "1")]
        .into_iter()
        .enumerate()
    {
        let id = format!("site-{n}");
        let r = record(&id, (v, m), "/stream/main", Some("/stream/sub"));
        idx.upsert_camera(&r, &[], at(T0)).unwrap();
        assert_eq!(
            idx.get_camera(&cam(&id), &[]).unwrap().unwrap().record(),
            &r
        );
    }
    assert_eq!(idx.list_cameras(&[]).unwrap().len(), 3);
}

#[test]
fn catalogue_vendor_and_model_spellings_match_by_slug() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = vec![entry("ACME  Corp.", "IPC/HFW 4431", "\"/live?ch=1\"")];
    let r = record("cam1", ("acme-corp", "ipc-hfw-4431"), "/live?ch=1", None);
    idx.upsert_camera(&r, &cat, at(T0)).unwrap();
    assert!(idx.get_camera(&cam("cam1"), &cat).unwrap().is_some());
}

// ---- stricter catalogue: the bad row can be repaired --------------------------------

#[test]
fn a_row_refused_under_a_stricter_catalogue_can_be_replaced_or_removed() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    idx.upsert_camera(&record("cam1", ("acme", "c1"), LISTED, None), &cat, at(T0))
        .unwrap();
    idx.upsert_camera(&record("cam2", ("acme", "c1"), LISTED, None), &cat, at(T0))
        .unwrap();
    let strict = vec![entry("Acme", "C1", "\"/plain\"")];
    assert!(idx.list_cameras(&strict).is_err());
    // Repair cam1 in place, remove cam2: the listing works again and created_at survived.
    idx.upsert_camera(
        &record("cam1", ("acme", "c1"), "/plain", None),
        &strict,
        at(T0 + 9),
    )
    .unwrap();
    assert!(idx.remove_camera(&cam("cam2")).unwrap());
    let all = idx.list_cameras(&strict).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].created_at(), at(T0));
}

// ---- corrupt rows: no sensitive text in any rendering of the error ------------------

#[test]
fn a_refused_stored_path_never_appears_in_the_error_debug_or_display() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let leaks = [
        "/s?pass=LeakPass7c1e9a",
        "/s?channel=LeakQuery7c1e9a",
        "/u@LeakHost7c1e9a/s",
        "/s;password=LeakPass7c1e9a",
        "/s?Token=LeakPass7c1e9a",
    ];
    {
        let c = raw(&f.path);
        c.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        for (n, p) in leaks.iter().enumerate() {
            c.execute(
                "INSERT INTO cameras VALUES (?1, 'acme/c1', 554, '/plain', ?2, 1, 1)",
                rusqlite::params![format!("cam{n}"), p],
            )
            .unwrap();
        }
    }
    let idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    for n in 0..leaks.len() {
        let e = idx.get_camera(&cam(&format!("cam{n}")), &cat).unwrap_err();
        for text in [format!("{e}"), format!("{e:?}"), format!("{e:#?}")] {
            assert!(!text.contains("Leak"), "{text}");
        }
    }
    let e = idx.list_cameras(&cat).unwrap_err();
    assert!(!format!("{e:?}").contains("Leak"));
}

// ---- orphans ---------------------------------------------------------------------------

#[test]
fn orphan_listing_is_bounded_ordered_and_excludes_registered_ids() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    let n = 1025;
    for i in 0..n {
        let id = format!("o{i:05}");
        idx.insert(&seg(&id, T0), Tier::Hot).unwrap();
        idx.insert(&seg(&id, T0 + 60_000), Tier::Hot).unwrap();
    }
    let got = idx.orphan_camera_ids().unwrap();
    assert_eq!(got.len(), 1024);
    let want: Vec<CameraId> = (0..1024).map(|i| cam(&format!("o{i:05}"))).collect();
    assert_eq!(got, want, "ordered, distinct");
    // Registering the first id moves the window by one: the 1025th becomes visible.
    idx.upsert_camera(
        &record("o00000", ("acme", "c1"), "/plain", None),
        &cat,
        at(T0),
    )
    .unwrap();
    let got = idx.orphan_camera_ids().unwrap();
    assert_eq!(got.first(), Some(&cam("o00001")));
    assert_eq!(got.last(), Some(&cam("o01024")));
    // remove puts it back and never touches its segments.
    assert!(idx.remove_camera(&cam("o00000")).unwrap());
    assert_eq!(
        idx.orphan_camera_ids().unwrap().first(),
        Some(&cam("o00000"))
    );
    drop(idx);
    let segs: i64 = raw(&f.path)
        .query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
        .unwrap();
    assert_eq!(segs, 2 * 1025);
}

#[test]
fn a_registered_camera_without_segments_is_not_an_orphan_and_remove_is_idempotent() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    idx.upsert_camera(
        &record("cam1", ("acme", "c1"), "/plain", None),
        &cat,
        at(T0),
    )
    .unwrap();
    assert_eq!(idx.orphan_camera_ids().unwrap(), vec![]);
    assert!(idx.remove_camera(&cam("cam1")).unwrap());
    assert!(!idx.remove_camera(&cam("cam1")).unwrap());
    assert_eq!(idx.orphan_camera_ids().unwrap(), vec![]);
}

// ---- the cap ---------------------------------------------------------------------------

#[test]
fn the_cap_counts_rows_and_a_removed_slot_is_reusable() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    for i in 0..MAX_CAMERAS {
        idx.upsert_camera(
            &record(&format!("c{i:04}"), ("acme", "c1"), "/plain", None),
            &cat,
            at(T0),
        )
        .unwrap();
    }
    let extra = record("zzz", ("acme", "c1"), "/plain", None);
    assert!(matches!(
        idx.upsert_camera(&extra, &cat, at(T0)),
        Err(IndexError::TooManyCameras { max }) if max == MAX_CAMERAS
    ));
    assert!(idx.remove_camera(&cam("c0000")).unwrap());
    idx.upsert_camera(&extra, &cat, at(T0)).unwrap();
    let all = idx.list_cameras(&cat).unwrap();
    assert_eq!(all.len(), MAX_CAMERAS);
    assert_eq!(all.last().unwrap().record().id(), &cam("zzz"));
}

// ---- the leak grep through the public API only ------------------------------------------

#[test]
fn stored_registry_bytes_are_exactly_the_registry_fields() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    let r = record(
        "probe-7c1e9a",
        ("acme", "c1"),
        "/probe7c1e9a-main",
        Some(LISTED),
    );
    idx.upsert_camera(&r, &cat, at(T0)).unwrap();
    drop(idx);
    let c = raw(&f.path);
    // Every text value stored anywhere in the cameras table.
    let mut stmt = c.prepare("SELECT * FROM cameras").unwrap();
    let ncol = stmt.column_count();
    let mut rows = stmt.query([]).unwrap();
    let mut texts = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        for i in 0..ncol {
            if let Ok(rusqlite::types::ValueRef::Text(t)) = row.get_ref(i) {
                texts.push(String::from_utf8(t.to_vec()).unwrap());
            }
        }
    }
    texts.sort();
    let mut want = vec![
        "probe-7c1e9a".to_owned(),
        "acme/c1".to_owned(),
        "/probe7c1e9a-main".to_owned(),
        LISTED.to_owned(),
    ];
    want.sort();
    assert_eq!(texts, want);
    let main = std::fs::read(&f.path).unwrap();
    assert!(main.windows(17).any(|w| w == b"/probe7c1e9a-main"));
}

// ---- the nine ADR names are refused even when the catalogue lists the query ----------------

const ADR_NAMES: [&str; 9] = [
    "pass", "password", "pwd", "user", "usr", "token", "auth", "key", "secret",
];

fn spellings(name: &str) -> Vec<String> {
    let mut first_upper = name.to_owned();
    first_upper[..1].make_ascii_uppercase();
    let alternating: String = name
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    vec![
        name.to_owned(),
        name.to_ascii_uppercase(),
        first_upper,
        alternating,
    ]
}

/// Every query in which one of the nine names is a parameter name: first, after `&`, `;`,
/// `,` and a second `?`, valued, empty-valued and bare.
fn credential_queries() -> Vec<String> {
    let mut out = Vec::new();
    for n in ADR_NAMES {
        for s in spellings(n) {
            for q in [
                format!("{s}=x"),
                format!("{s}="),
                format!("{s}"),
                format!("channel=1&{s}=x"),
                format!("channel=1&{s}"),
                format!("channel=1;{s}=x"),
                format!("channel=1,{s}=x"),
                format!("channel=1?{s}=x"),
                format!("channel=1&&{s}=x"),
                format!("{s}=x&channel=1"),
                format!("channel={s}&{s}=1"),
            ] {
                out.push(q);
            }
        }
    }
    out
}

#[test]
fn a_listed_query_naming_any_of_the_nine_adr_names_is_still_refused() {
    let queries = credential_queries();
    assert!(queries.len() >= 9 * 4 * 11);
    let paths: Vec<String> = queries.iter().map(|q| format!("\"/x?{q}\"")).collect();
    // The catalogue is structurally valid with these paths: the name rule is the only defence.
    let cat = vec![entry("Acme", "C1", &paths.join(", "))];
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    for q in &queries {
        let text = format!("/x?{q}");
        // Either core refuses to build the path, or the registry refuses to store it.
        if let Ok(p) = RtspPath::new(&text) {
            let r = CameraRecord::new(
                cam("cam1"),
                ModelRef::new("acme", "c1").unwrap(),
                NonZeroU16::new(554).unwrap(),
                StreamSet::new(p, None),
            );
            let e = idx.upsert_camera(&r, &cat, at(T0));
            panic!("{text} was accepted by RtspPath; upsert gave {e:?}");
        }
    }
    assert_eq!(idx.list_cameras(&cat).unwrap(), vec![]);
}

// ---- every committing camera operation writes the instance-id page (the #145 guard) -------

/// Page numbers of the `-wal` frames after byte offset `from`.
fn wal_pages(wal: &[u8], from: usize) -> Vec<u32> {
    let page_size = u32::from_be_bytes(wal[8..12].try_into().unwrap()) as usize;
    let frame = 24 + page_size;
    let mut off = if from < 32 { 32 } else { from };
    let mut out = Vec::new();
    while off + frame <= wal.len() {
        out.push(u32::from_be_bytes(wal[off..off + 4].try_into().unwrap()));
        off += frame;
    }
    out
}

#[test]
fn every_committing_camera_operation_leaves_a_frame_of_the_instance_id_page() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    let cat = catalogue();
    let wal = sidecar(&f.path, "-wal");
    type Op = Box<dyn Fn(&mut Index)>;
    let ops: Vec<(&str, Op)> = vec![
        (
            "upsert new",
            Box::new(|i: &mut Index| {
                i.upsert_camera(
                    &record("cam1", ("acme", "c1"), "/plain", None),
                    &catalogue(),
                    at(T0),
                )
                .unwrap();
            }),
        ),
        (
            "upsert same",
            Box::new(|i: &mut Index| {
                i.upsert_camera(
                    &record("cam1", ("acme", "c1"), "/plain", None),
                    &catalogue(),
                    at(T0 + 1),
                )
                .unwrap();
            }),
        ),
        (
            "remove",
            Box::new(|i: &mut Index| {
                assert!(i.remove_camera(&cam("cam1")).unwrap());
            }),
        ),
    ];
    let _ = &cat;
    for (name, op) in ops {
        let before = std::fs::read(&wal).unwrap().len();
        op(&mut idx);
        let after = std::fs::read(&wal).unwrap();
        let pages = wal_pages(&after, before);
        assert!(!pages.is_empty(), "{name}: no frame");
        assert!(
            pages.contains(&2),
            "{name}: pages {pages:?} lack the instance-id page"
        );
    }
}
