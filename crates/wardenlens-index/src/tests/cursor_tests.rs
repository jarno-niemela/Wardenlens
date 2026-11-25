//! Invariant 3: tampered and foreign cursors. The table is the enumeration of what can be wrong
//! with a cursor text; each row must be a typed error, never a panic and never rows.

use wardenlens_core::storage::{SegmentCursor, SegmentIndex, Tier};

use super::*;
use crate::cursor::{Position, decode, encode};
use crate::error::{CursorFault, IndexError};

fn hex(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for b in s.bytes() {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

fn setup() -> (Fixture, Index) {
    let (f, mut idx) = open_new();
    for k in 0..4 {
        idx.insert(&rec("cam1", BASE + k * 1000, 500, 1, 1), Tier::Hot)
            .unwrap();
        idx.insert(&rec("cam2", BASE + k * 1000, 500, 1, 1), Tier::Hot)
            .unwrap();
    }
    (f, idx)
}

#[test]
fn issued_cursors_roundtrip() {
    let p = Position {
        started_at_ms: BASE,
        id: 7,
    };
    let c = encode(&cam("cam1"), p);
    assert_eq!(decode(&cam("cam1"), &c).unwrap(), p);
}

#[test]
fn every_bad_cursor_is_a_typed_error() {
    let (_f, idx) = setup();
    let good = hex(&format!("v1:{BASE}:3:cam1"));
    let table: Vec<(&str, String, CursorFault)> = vec![
        ("empty", String::new(), CursorFault::Malformed),
        ("odd length", format!("{good}0"), CursorFault::Malformed),
        ("not hex", "zz".into(), CursorFault::Malformed),
        (
            "upper-case hex",
            good.to_uppercase(),
            CursorFault::Malformed,
        ),
        ("non-ascii", "é1".into(), CursorFault::Malformed),
        (
            "plain text",
            format!("v1:{BASE}:3:cam1"),
            CursorFault::Malformed,
        ),
        (
            "wrong version",
            hex(&format!("v2:{BASE}:3:cam1")),
            CursorFault::Malformed,
        ),
        (
            "missing field",
            hex(&format!("v1:{BASE}:3")),
            CursorFault::Malformed,
        ),
        (
            "extra field",
            hex(&format!("v1:{BASE}:3:cam1:x")),
            CursorFault::Malformed,
        ),
        (
            "leading plus",
            hex(&format!("v1:+{BASE}:3:cam1")),
            CursorFault::Malformed,
        ),
        (
            "leading zero",
            hex(&format!("v1:{BASE}:03:cam1")),
            CursorFault::Malformed,
        ),
        (
            "negative id",
            hex(&format!("v1:{BASE}:-3:cam1")),
            CursorFault::Malformed,
        ),
        (
            "zero id",
            hex(&format!("v1:{BASE}:0:cam1")),
            CursorFault::Malformed,
        ),
        (
            "id overflow",
            hex(&format!("v1:{BASE}:99999999999999999999:cam1")),
            CursorFault::Malformed,
        ),
        (
            "start before 2000",
            hex("v1:5:3:cam1"),
            CursorFault::Malformed,
        ),
        (
            "start after 2099",
            hex("v1:4102444800000:3:cam1"),
            CursorFault::Malformed,
        ),
        (
            "start not a number",
            hex("v1:abc:3:cam1"),
            CursorFault::Malformed,
        ),
        (
            "invalid camera",
            hex(&format!("v1:{BASE}:3:CAM1")),
            CursorFault::Malformed,
        ),
        (
            "empty camera",
            hex(&format!("v1:{BASE}:3:")),
            CursorFault::Malformed,
        ),
        (
            "camera with slash",
            hex(&format!("v1:{BASE}:3:../x")),
            CursorFault::Malformed,
        ),
        ("invalid utf8", "ff".into(), CursorFault::Malformed),
        ("too long", "a".repeat(194), CursorFault::TooLong),
        ("huge", "a".repeat(1 << 20), CursorFault::TooLong),
        (
            "another camera",
            hex(&format!("v1:{BASE}:3:cam2")),
            CursorFault::WrongCamera,
        ),
        (
            "valid but unknown camera",
            hex(&format!("v1:{BASE}:3:other")),
            CursorFault::WrongCamera,
        ),
    ];
    for (name, token, fault) in table {
        let c = SegmentCursor::from_token(token);
        let e = idx
            .list(&cam("cam1"), ts(0), ts(i64::MAX), 10, Some(&c))
            .unwrap_err();
        assert!(
            matches!(e, IndexError::InvalidCursor(f) if f == fault),
            "{name}: {e:?}"
        );
    }
    // The control row: the same shape, valid.
    let c = SegmentCursor::from_token(good);
    assert!(
        idx.list(&cam("cam1"), ts(0), ts(i64::MAX), 10, Some(&c))
            .is_ok()
    );
}

#[test]
fn a_cursor_error_wins_over_an_empty_range() {
    let (_f, idx) = setup();
    let c = SegmentCursor::from_token("zz".into());
    assert!(idx.list(&cam("cam1"), ts(5), ts(5), 10, Some(&c)).is_err());
}

#[test]
fn a_cursor_from_camera_a_never_yields_rows_of_camera_b() {
    let (_f, idx) = setup();
    let p = idx
        .list(&cam("cam1"), ts(0), ts(i64::MAX), 2, None)
        .unwrap();
    let e = idx
        .list(&cam("cam2"), ts(0), ts(i64::MAX), 2, p.next.as_ref())
        .unwrap_err();
    assert!(matches!(
        e,
        IndexError::InvalidCursor(CursorFault::WrongCamera)
    ));
}

#[test]
fn a_forged_position_cannot_escape_the_range_or_camera_filter() {
    let (_f, idx) = setup();
    // Position before everything: still only cam1 rows inside the range.
    let c = encode(
        &cam("cam1"),
        Position {
            started_at_ms: 946_684_800_000,
            id: 1,
        },
    );
    let p = idx
        .list(&cam("cam1"), ts(BASE + 1000), ts(BASE + 2000), 10, Some(&c))
        .unwrap();
    assert_eq!(p.items.len(), 1);
    assert_eq!(p.items[0].record.camera.as_str(), "cam1");
}
