//! Invariant 4: rows written outside SQLite (past the CHECKs) are typed errors on read.
//!
//! The corrupt row is written through a second connection with `ignore_check_constraints`, which
//! models a file edited by another tool.

use wardenlens_core::storage::{SegmentId, SegmentIndex, Tier};

use super::*;
use crate::error::IndexError;

/// Columns `camera_id`, `started_at_ms`, `duration_ms`, `ended_at_ms`, `bytes`, `frame_count`,
/// `tier`, then the field the read is expected to name.
type Row = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

fn bad_rows() -> Vec<(&'static str, Row)> {
    let ok = (
        "'cam1'",
        "1700000000000",
        "1000",
        "1700000001000",
        "5",
        "1",
        "0",
    );
    let mk = |camera, started, dur, ended, bytes, frames, tier, field| -> Row {
        (camera, started, dur, ended, bytes, frames, tier, field)
    };
    let _ = ok;
    vec![
        (
            "started before 2000",
            mk(
                "'cam1'",
                "946684799999",
                "1000",
                "946684800999",
                "5",
                "1",
                "0",
                "started_at_ms",
            ),
        ),
        (
            "started after 2099",
            mk(
                "'cam1'",
                "4102444800000",
                "1000",
                "4102444801000",
                "5",
                "1",
                "0",
                "started_at_ms",
            ),
        ),
        (
            "negative start",
            mk(
                "'cam1'",
                "-1",
                "1000",
                "999",
                "5",
                "1",
                "0",
                "started_at_ms",
            ),
        ),
        (
            "start near i64::MAX",
            mk(
                "'cam1'",
                "9223372036854775806",
                "1",
                "9223372036854775807",
                "5",
                "1",
                "0",
                "started_at_ms",
            ),
        ),
        (
            "zero duration",
            mk(
                "'cam1'",
                "1700000000000",
                "0",
                "1700000000000",
                "5",
                "1",
                "0",
                "duration_ms",
            ),
        ),
        (
            "duration above bound",
            mk(
                "'cam1'",
                "1700000000000",
                "600001",
                "1700000600001",
                "5",
                "1",
                "0",
                "duration_ms",
            ),
        ),
        (
            "negative duration",
            mk(
                "'cam1'",
                "1700000000000",
                "-5",
                "1699999999995",
                "5",
                "1",
                "0",
                "duration_ms",
            ),
        ),
        (
            "ended disagrees",
            mk(
                "'cam1'",
                "1700000000000",
                "1000",
                "1700000000999",
                "5",
                "1",
                "0",
                "ended_at_ms",
            ),
        ),
        (
            "zero bytes",
            mk(
                "'cam1'",
                "1700000000000",
                "1000",
                "1700000001000",
                "0",
                "1",
                "0",
                "bytes",
            ),
        ),
        (
            "negative bytes",
            mk(
                "'cam1'",
                "1700000000000",
                "1000",
                "1700000001000",
                "-5",
                "1",
                "0",
                "bytes",
            ),
        ),
        (
            "zero frames",
            mk(
                "'cam1'",
                "1700000000000",
                "1000",
                "1700000001000",
                "5",
                "0",
                "0",
                "frame_count",
            ),
        ),
        (
            "tier 2",
            mk(
                "'cam1'",
                "1700000000000",
                "1000",
                "1700000001000",
                "5",
                "1",
                "2",
                "tier",
            ),
        ),
        (
            "tier -1",
            mk(
                "'cam1'",
                "1700000000000",
                "1000",
                "1700000001000",
                "5",
                "1",
                "-1",
                "tier",
            ),
        ),
        (
            "camera upper case",
            mk(
                "'CAM1'",
                "1700000000000",
                "1000",
                "1700000001000",
                "5",
                "1",
                "0",
                "camera_id",
            ),
        ),
        (
            "camera with slash",
            mk(
                "'a/b'",
                "1700000000000",
                "1000",
                "1700000001000",
                "5",
                "1",
                "0",
                "camera_id",
            ),
        ),
        (
            "camera 33 chars",
            mk(
                "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
                "1700000000000",
                "1000",
                "1700000001000",
                "5",
                "1",
                "0",
                "camera_id",
            ),
        ),
        (
            "camera starts with digit",
            mk(
                "'1cam'",
                "1700000000000",
                "1000",
                "1700000001000",
                "5",
                "1",
                "0",
                "camera_id",
            ),
        ),
    ]
}

/// Inserts a row bypassing every CHECK and type rule (the STRICT table is bypassed by a copy
/// table without constraints swapped in for the read).
fn write_bad(path: &std::path::Path, row: Row) -> i64 {
    let c = raw(path);
    c.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    c.execute_batch(&format!(
        "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) \
         VALUES ({}, {}, {}, {}, {}, {}, {});",
        row.0, row.1, row.2, row.3, row.4, row.5, row.6
    ))
    .unwrap_or_else(|e| panic!("could not plant row {row:?}: {e}"));
    c.last_insert_rowid()
}

#[test]
fn every_bad_stored_value_is_a_typed_corrupt_row_on_get_list_and_oldest() {
    for (name, row) in bad_rows() {
        let (f, idx) = open_new();
        let id = write_bad(&f.path, row);
        let id = SegmentId::new(u64::try_from(id).unwrap());
        let field = row.7;
        let is =
            |e: &IndexError| matches!(e, IndexError::CorruptRow { field: g, .. } if *g == field);
        let e = idx.get(id).unwrap_err();
        assert!(is(&e), "{name} get: {e:?}");
        // A list can only reach a row whose camera text and bounds let the SQL select it; when it
        // does it must be the same typed error.
        if let Ok(camera) = wardenlens_core::camera::CameraId::new(row.0.trim_matches('\'')) {
            let e = idx
                .list(&camera, ts(i64::MIN), ts(i64::MAX), 10, None)
                .expect_err(name);
            assert!(is(&e), "{name} list: {e:?}");
        }
        for t in [Tier::Hot, Tier::Archive] {
            if let Err(e) = idx.oldest(t, None, 10) {
                assert!(
                    matches!(e, IndexError::CorruptRow { .. }),
                    "{name} oldest: {e:?}"
                );
            }
        }
    }
}

#[test]
fn bad_rows_reach_the_read_paths_at_all() {
    // Guard for the table above: at least the in-range camera rows are visible to `list`.
    let (f, idx) = open_new();
    let id = write_bad(&f.path, bad_rows().remove(7).1); // ended disagrees
    assert!(id > 0);
    let e = idx
        .list(&cam("cam1"), ts(i64::MIN), ts(i64::MAX), 10, None)
        .unwrap_err();
    assert!(
        matches!(
            e,
            IndexError::CorruptRow {
                field: "ended_at_ms",
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn corrupt_row_errors_name_the_id_and_column_only() {
    let (f, idx) = open_new();
    let id = write_bad(&f.path, bad_rows().remove(0).1);
    let e = idx
        .get(SegmentId::new(u64::try_from(id).unwrap()))
        .unwrap_err();
    let text = format!("{e} {e:?}");
    assert!(
        !text.contains("cam1") && !text.contains("9466847"),
        "{text}"
    );
}

#[test]
fn bytes_by_tier_rejects_an_unknown_tier_and_a_negative_sum() {
    let (f, idx) = open_new();
    write_bad(
        &f.path,
        (
            "'cam1'",
            "1700000000000",
            "1000",
            "1700000001000",
            "5",
            "1",
            "7",
            "",
        ),
    );
    assert!(matches!(
        idx.bytes_by_tier().unwrap_err(),
        IndexError::CorruptRow { field: "tier", .. }
    ));
    let (f, idx) = open_new();
    write_bad(
        &f.path,
        (
            "'cam1'",
            "1700000000000",
            "1000",
            "1700000001000",
            "-5",
            "1",
            "0",
            "",
        ),
    );
    assert!(matches!(
        idx.bytes_by_tier().unwrap_err(),
        IndexError::CorruptRow { field: "bytes", .. }
    ));
}

#[test]
fn latest_started_at_rejects_an_out_of_range_start() {
    let (f, idx) = open_new();
    write_bad(&f.path, ("'cam1'", "5", "1000", "1005", "5", "1", "0", ""));
    assert!(matches!(
        idx.latest_started_at(&cam("cam1")).unwrap_err(),
        IndexError::CorruptRow {
            field: "started_at_ms",
            ..
        }
    ));
}

#[test]
fn overflowing_sum_is_an_error_not_a_wrap() {
    let (f, idx) = open_new();
    write_bad(
        &f.path,
        (
            "'cam1'",
            "1700000000000",
            "1000",
            "1700000001000",
            "9223372036854775807",
            "1",
            "0",
            "",
        ),
    );
    write_bad(
        &f.path,
        (
            "'cam1'",
            "1700000010000",
            "1000",
            "1700000011000",
            "9223372036854775807",
            "1",
            "0",
            "",
        ),
    );
    // SQLite refuses the overflowing SUM; it is never wrapped into a small number.
    assert!(matches!(
        idx.bytes_by_tier().unwrap_err(),
        IndexError::Sqlite {
            op: "bytes by tier",
            ..
        }
    ));
}

#[test]
fn bytes_by_tier_rejects_a_bad_row_hidden_in_a_plausible_sum() {
    for (name, a, b) in [
        ("zero", "0", "10"),
        ("negative offset by a large row", "-5", "15"),
        ("above the bound", "68719476737", "1"),
    ] {
        let (f, idx) = open_new();
        let row = |start: &'static str, end: &'static str, bytes: &'static str| {
            ("'cam1'", start, "1000", end, bytes, "1", "0", "")
        };
        write_bad(&f.path, row("1700000000000", "1700000001000", a));
        write_bad(&f.path, row("1700000010000", "1700000011000", b));
        assert!(
            matches!(
                idx.bytes_by_tier().unwrap_err(),
                IndexError::CorruptRow { field: "bytes", .. }
            ),
            "{name}"
        );
    }
}

/// Removes `STRICT` so a column can hold another storage class (a file edited outside SQLite).
fn loosen(path: &std::path::Path) {
    let c = raw(path);
    let sql: String = c
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'segments'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    c.execute_batch("PRAGMA writable_schema = ON").unwrap();
    c.execute(
        "UPDATE sqlite_master SET sql = ?1 WHERE name = 'segments'",
        [sql.replace(") STRICT", ")")],
    )
    .unwrap();
}

/// Every integer column, holding text: each read path that touches it says `CorruptRow`.
#[test]
fn a_wrong_storage_class_in_any_column_is_a_corrupt_row_on_every_read_path() {
    let columns = [
        "started_at_ms",
        "duration_ms",
        "ended_at_ms",
        "bytes",
        "frame_count",
        "tier",
    ];
    for col in columns {
        let (f, idx) = open_new();
        loosen(&f.path);
        let mut values = ["1700000000000", "1000", "1700000001000", "5", "1", "0"];
        let at = columns.iter().position(|c| *c == col).unwrap();
        values[at] = "'x'";
        raw(&f.path)
            .execute_batch(&format!(
                "PRAGMA ignore_check_constraints = ON; INSERT INTO segments \
                 (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) \
                 VALUES ('cam1', {});",
                values.join(", ")
            ))
            .unwrap();
        let is =
            |e: &IndexError| matches!(e, IndexError::CorruptRow { field, .. } if *field == col);
        let e = idx.get(SegmentId::new(1)).unwrap_err();
        assert!(is(&e), "{col} get: {e:?}");
        // Text sorts after every integer, so a text start is not selected by the range at all.
        let listed = idx.list(&cam("cam1"), ts(i64::MIN), ts(i64::MAX), 10, None);
        if col == "started_at_ms" {
            assert_eq!(listed.unwrap().items, []);
        } else {
            let e = listed.unwrap_err();
            assert!(is(&e), "{col} list: {e:?}");
        }
        // The statements that read a column report it too (those that do not read it succeed).
        match col {
            "tier" => {
                assert!(matches!(
                    idx.bytes_by_tier().unwrap_err(),
                    IndexError::CorruptRow { field: "tier", .. }
                ));
            }
            "bytes" => {
                assert!(matches!(
                    idx.bytes_by_tier().unwrap_err(),
                    IndexError::CorruptRow { field: "bytes", .. }
                ));
                let e = idx.oldest(Tier::Hot, None, 10).unwrap_err();
                assert!(is(&e), "oldest: {e:?}");
            }
            "ended_at_ms" => {
                let e = idx.oldest(Tier::Hot, None, 10).unwrap_err();
                assert!(is(&e), "oldest: {e:?}");
            }
            "started_at_ms" => {
                assert!(matches!(
                    idx.latest_started_at(&cam("cam1")).unwrap_err(),
                    IndexError::CorruptRow {
                        field: "started_at_ms",
                        ..
                    }
                ));
            }
            _ => {}
        }
    }
}
