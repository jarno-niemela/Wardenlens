//! Invariant 6: the query plans of ADR 0005 section 5.

use wardenlens_core::storage::{SegmentIndex, Tier};

use super::*;
use crate::sql;

fn populated() -> (Fixture, Index) {
    let (f, mut idx) = open_new();
    for cam_name in ["cam1", "cam2", "cam3"] {
        for k in 0..30 {
            let t = if k % 3 == 0 { Tier::Archive } else { Tier::Hot };
            idx.insert(
                &rec(
                    cam_name,
                    BASE + k * 10_000,
                    9_000,
                    100 + u64::try_from(k).unwrap(),
                    5,
                ),
                t,
            )
            .unwrap();
        }
    }
    (f, idx)
}

fn plan(idx: &Index, stmt: &str, args: &[&dyn rusqlite::ToSql]) -> Vec<String> {
    let mut s = idx
        .conn
        .prepare(&format!("EXPLAIN QUERY PLAN {stmt}"))
        .unwrap();
    s.query_map(args, |r| r.get::<_, String>(3))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn no_scan_or_sort(p: &[String]) {
    for line in p {
        assert!(!line.contains("TEMP B-TREE"), "sorts: {p:?}");
        assert!(
            !line.starts_with("SCAN segments") || line.contains("INDEX"),
            "full scan: {p:?}"
        );
    }
}

#[test]
fn list_searches_the_camera_start_index_without_a_sort() {
    let (_f, idx) = populated();
    let p = plan(
        &idx,
        sql::LIST,
        &[&"cam1", &0_i64, &1_i64, &2_i64, &3_i64, &4_i64, &5_i64],
    );
    assert_eq!(p.len(), 1, "{p:?}");
    assert!(
        p[0].starts_with("SEARCH segments USING INDEX segments_camera_start"),
        "{p:?}"
    );
    assert!(
        p[0].contains("camera_id=?")
            && p[0].contains("started_at_ms>?")
            && p[0].contains("started_at_ms<?"),
        "{p:?}"
    );
    no_scan_or_sort(&p);
}

#[test]
fn oldest_searches_the_tier_end_index_without_a_sort() {
    let (_f, idx) = populated();
    let p = plan(&idx, sql::OLDEST, &[&0_i64, &1_i64, &2_i64, &10_i64]);
    assert_eq!(p.len(), 1, "{p:?}");
    assert!(p[0].starts_with("SEARCH segments USING"), "{p:?}");
    assert!(p[0].contains("INDEX segments_tier_end (tier=?"), "{p:?}");
    no_scan_or_sort(&p);
}

#[test]
fn bytes_by_tier_scans_the_covering_index() {
    let (_f, idx) = populated();
    let p = plan(&idx, sql::BYTES_BY_TIER, &[]);
    assert!(
        p.iter()
            .any(|l| l.starts_with("SCAN segments USING COVERING INDEX segments_tier_end")),
        "{p:?}"
    );
    assert!(!p.iter().any(|l| l.contains("TEMP B-TREE")), "{p:?}");
}

#[test]
fn latest_start_searches_the_camera_index() {
    let (_f, idx) = populated();
    let p = plan(&idx, sql::LATEST_START, &[&"cam1"]);
    assert!(
        p.iter().any(|l| l.starts_with(
            "SEARCH segments USING COVERING INDEX segments_camera_start (camera_id=?)"
        )),
        "{p:?}"
    );
}

#[test]
fn by_id_statements_use_the_primary_key() {
    let (_f, idx) = populated();
    for (name, stmt, args) in [
        ("get", sql::GET, vec![&1_i64 as &dyn rusqlite::ToSql]),
        ("tier_of", sql::TIER_OF, vec![&1_i64]),
        ("delete", sql::DELETE, vec![&1_i64]),
        ("set_tier", sql::SET_TIER, vec![&1_i64, &1_i64, &0_i64]),
    ] {
        let p = plan(&idx, stmt, &args);
        assert!(
            p.iter()
                .all(|l| l.contains("INTEGER PRIMARY KEY (rowid=?)")),
            "{name}: {p:?}"
        );
    }
}

/// Guard the guard: the assertions above fail when the index is missing.
#[test]
fn plan_assertions_fail_without_the_indexes() {
    let (_f, idx) = populated();
    idx.conn
        .execute_batch("DROP INDEX segments_camera_start; DROP INDEX segments_tier_end;")
        .unwrap();
    let p = plan(&idx, sql::OLDEST, &[&0_i64, &1_i64, &2_i64, &10_i64]);
    assert!(!p[0].contains("segments_tier_end"), "{p:?}");
    let p = plan(
        &idx,
        sql::LIST,
        &[&"cam1", &0_i64, &1_i64, &2_i64, &3_i64, &4_i64, &5_i64],
    );
    assert!(
        p.iter()
            .any(|l| l.starts_with("SCAN") || l.contains("TEMP B-TREE")),
        "{p:?}"
    );
}
