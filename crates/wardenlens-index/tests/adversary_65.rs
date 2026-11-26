//! Adversarial tests for #65 (PR #173): the `api_tokens` table. Synthetic data only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use rusqlite::Connection;
use wardenlens_core::time::UnixMs;
use wardenlens_core::token_store::{NewToken, RevokeOutcome, TokenId, TokenName};
use wardenlens_index::{Index, IndexError, TOUCH_INTERVAL_MS};

const T0: i64 = 1_700_000_000_000;

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

fn id(s: &str) -> TokenId {
    TokenId::parse(s).unwrap()
}

fn at(ms: i64) -> UnixMs {
    UnixMs::new(ms).unwrap()
}

fn tok(i: &str, b: u8) -> NewToken {
    NewToken {
        id: id(i),
        digest: [b; 32],
        name: TokenName::new("n").unwrap(),
        created_at: at(T0),
    }
}

/// A version-2 index (as released before #65) migrates to version 3 on open, keeping its rows.
#[test]
fn a_version_2_index_migrates_to_3_and_keeps_its_rows() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    {
        let c = Connection::open(&f.path).unwrap();
        c.execute_batch(
            "DROP TABLE api_tokens; PRAGMA user_version = 2; \
             INSERT INTO cameras VALUES ('cam1', 'm', 554, '/a', NULL, 1, 1);",
        )
        .unwrap();
        let v: i64 = c
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 2);
    }
    let mut idx = Index::open(&f.path).unwrap();
    idx.insert_token(&tok("abcdefgh", 1)).unwrap();
    assert_eq!(idx.list_tokens().unwrap().len(), 1);
    drop(idx);
    let c = Connection::open(&f.path).unwrap();
    let v: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
    let cams: i64 = c
        .query_row("SELECT count(*) FROM cameras", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cams, 1);
}

/// The DDL is the ADR 0005 section 5 shape: every constraint is enforced by SQLite itself.
#[test]
fn the_schema_refuses_rows_outside_the_adr_bounds() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let c = Connection::open(&f.path).unwrap();
    let d32 = "x'".to_owned() + &"00".repeat(32) + "'";
    let d31 = "x'".to_owned() + &"00".repeat(31) + "'";
    let n64 = "n".repeat(64);
    let n65 = "n".repeat(65);
    let ok = format!(
        "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('abcdefgh', {d32}, '{n64}', 1)"
    );
    c.execute_batch(&ok).unwrap();
    for bad in [
        format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('abcdefgh', {d32}, 'n', 1)"
        ),
        format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('abcdefg', {d32}, 'n', 1)"
        ),
        format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('bbbbbbbb', {d31}, 'n', 1)"
        ),
        format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('bbbbbbbb', {d32}, '', 1)"
        ),
        format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('bbbbbbbb', {d32}, '{n65}', 1)"
        ),
        format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms, revoked) VALUES ('bbbbbbbb', {d32}, 'n', 1, 2)"
        ),
        format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('bbbbbbbb', '{}', 'n', 1)",
            "a".repeat(32)
        ),
        format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('bbbbbbbb', {d32}, 'n', 'later')"
        ),
    ] {
        assert!(c.execute_batch(&bad).is_err(), "{bad}");
    }
    let nullable: Option<i64> = c
        .query_row(
            "SELECT last_used_at_ms FROM api_tokens WHERE id = 'abcdefgh'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(nullable, None);
}

/// A revoked id is never reissued, even after a reopen.
#[test]
fn a_revoked_id_is_refused_after_a_reopen() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    idx.insert_token(&tok("abcdefgh", 1)).unwrap();
    assert_eq!(
        idx.revoke_token(&id("abcdefgh")).unwrap(),
        RevokeOutcome::Revoked
    );
    drop(idx);
    let mut idx = Index::open(&f.path).unwrap();
    assert!(matches!(
        idx.insert_token(&tok("abcdefgh", 2)),
        Err(IndexError::TokenIdTaken)
    ));
    let r = idx.find_token(&id("abcdefgh")).unwrap().unwrap();
    assert!(r.revoked);
    assert_eq!(r.digest, [1; 32]);
}

/// Touch at the bottom of the clock range: the saturating `due` arithmetic does not wrap.
#[test]
fn touch_at_the_edges_of_the_time_range() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    idx.insert_token(&tok("abcdefgh", 1)).unwrap();
    let lo = 946_684_800_000;
    let hi = 4_102_444_799_999;
    assert!(idx.touch_token(&id("abcdefgh"), at(lo)).unwrap());
    assert!(
        !idx.touch_token(&id("abcdefgh"), at(lo + TOUCH_INTERVAL_MS - 1))
            .unwrap()
    );
    assert!(idx.touch_token(&id("abcdefgh"), at(hi)).unwrap());
    assert!(!idx.touch_token(&id("abcdefgh"), at(hi)).unwrap());
    // A clock back at the bottom never writes again while the stored value is ahead.
    assert!(!idx.touch_token(&id("abcdefgh"), at(lo)).unwrap());
}

/// A long run of requests (every 7 s, two tokens interleaved) writes each token at most once per
/// interval: no drift, and the limit is per token.
#[test]
fn many_touches_in_one_minute_write_once_over_a_long_run() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    idx.insert_token(&tok("abcdefgh", 1)).unwrap();
    idx.insert_token(&tok("bbbbbbbb", 2)).unwrap();
    let mut writes_a = 0;
    let mut writes_b = 0;
    // One request every 7 seconds for 2 hours, both tokens interleaved.
    let mut now = T0;
    while now < T0 + 7_200_000 {
        if idx.touch_token(&id("abcdefgh"), at(now)).unwrap() {
            writes_a += 1;
        }
        if idx.touch_token(&id("bbbbbbbb"), at(now + 3_000)).unwrap() {
            writes_b += 1;
        }
        now += 7_000;
    }
    // Naive oracle: a write happens when nothing was written yet or the last write is at least
    // the interval old. With 7 s steps every gap is 63 s: writes at 0, 63 s, .. below 2 h.
    let mut last: Option<i64> = None;
    let mut want = 0;
    let mut t = 0;
    while t < 7_200_000 {
        if last.is_none_or(|l| l <= t - TOUCH_INTERVAL_MS) {
            last = Some(t);
            want += 1;
        }
        t += 7_000;
    }
    assert_eq!(want, 115);
    assert_eq!(writes_a, want);
    assert_eq!(writes_b, want);
}
