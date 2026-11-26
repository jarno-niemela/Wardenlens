//! The API token table (ticket #65): plain data access, rows never deleted, the `last_used` rate
//! limit in the store, and the `TokenStore` adapter.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use wardenlens_core::time::UnixMs;
use wardenlens_core::token_store::{
    InsertError, MAX_TOKENS, NewToken, RevokeOutcome, TOKEN_ID_LEN, TokenId, TokenName,
    TokenRecord, TokenStore, TokenStoreError,
};

use super::*;
use crate::error::IndexError;
use crate::{TOUCH_INTERVAL_MS, TokenIndex};

const T0: i64 = 1_700_000_000_000;

fn at(ms: i64) -> UnixMs {
    UnixMs::new(ms).unwrap()
}

fn id(s: &str) -> TokenId {
    TokenId::parse(s).unwrap()
}

fn new_token(id_text: &str, digest_byte: u8, name: &str, created: i64) -> NewToken {
    NewToken {
        id: id(id_text),
        digest: [digest_byte; 32],
        name: TokenName::new(name).unwrap(),
        created_at: at(created),
    }
}

/// Polls a future that is already complete (every `TokenIndex` future is).
fn ready<F: Future>(f: F) -> F::Output {
    match pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("a TokenIndex future was not ready"),
    }
}

/// The main file and the `-wal`: what a write changes. The `-shm` is a lock table that any reader
/// touches, so it is left out.
fn durable(dir: &std::path::Path) -> std::collections::BTreeMap<String, Option<Vec<u8>>> {
    let mut all = snapshot(dir);
    all.retain(|name, _| !name.ends_with("-shm"));
    all
}

fn last_used(idx: &Index, id_text: &str) -> Option<i64> {
    idx.conn
        .query_row(
            "SELECT last_used_at_ms FROM api_tokens WHERE id = ?1",
            [id_text],
            |r| r.get(0),
        )
        .unwrap()
}

fn row_count(idx: &Index) -> i64 {
    idx.conn
        .query_row("SELECT count(*) FROM api_tokens", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn insert_then_find_and_list_round_trip_without_the_digest() {
    let (_f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "grafana", T0))
        .unwrap();
    idx.insert_token(&new_token("zzzzzzzz", 9, "backup", T0 + 5))
        .unwrap();
    assert_eq!(
        idx.find_token(&id("abcdefgh")).unwrap(),
        Some(TokenRecord {
            digest: [7; 32],
            revoked: false
        })
    );
    assert_eq!(idx.find_token(&id("aaaaaaaa")).unwrap(), None);
    let list = idx.list_tokens().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, id("abcdefgh"));
    assert_eq!(list[0].name.as_str(), "grafana");
    assert_eq!(list[0].created_at, at(T0));
    assert_eq!(list[0].last_used_at, None);
    assert!(!list[0].revoked);
    assert_eq!(list[1].id, id("zzzzzzzz"));
    // No digest can leak: neither the type nor its Debug output has one.
    assert!(!format!("{list:?}").contains("digest"));
}

#[test]
fn tokens_survive_a_reopen() {
    let (f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "x", T0))
        .unwrap();
    drop(idx);
    let idx = Index::open(&f.path).unwrap();
    assert!(idx.find_token(&id("abcdefgh")).unwrap().is_some());
}

#[test]
fn an_existing_id_is_refused_and_the_stored_row_is_unchanged() {
    let (_f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "first", T0))
        .unwrap();
    // Active, then revoked: the id is taken either way.
    for revoke_first in [false, true] {
        if revoke_first {
            assert_eq!(
                idx.revoke_token(&id("abcdefgh")).unwrap(),
                RevokeOutcome::Revoked
            );
        }
        let err = idx
            .insert_token(&new_token("abcdefgh", 8, "second", T0 + 1))
            .unwrap_err();
        assert!(matches!(err, IndexError::TokenIdTaken), "{err:?}");
        let rec = idx.find_token(&id("abcdefgh")).unwrap().unwrap();
        assert_eq!(rec.digest, [7; 32]);
        assert_eq!(rec.revoked, revoke_first);
        assert_eq!(row_count(&idx), 1);
    }
}

#[test]
fn revoke_sets_the_flag_keeps_the_row_and_is_idempotent() {
    let (_f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "a", T0))
        .unwrap();
    idx.insert_token(&new_token("bbbbbbbb", 8, "b", T0))
        .unwrap();
    assert_eq!(
        idx.revoke_token(&id("abcdefgh")).unwrap(),
        RevokeOutcome::Revoked
    );
    assert_eq!(
        idx.revoke_token(&id("abcdefgh")).unwrap(),
        RevokeOutcome::AlreadyRevoked
    );
    assert_eq!(
        idx.revoke_token(&id("cccccccc")).unwrap(),
        RevokeOutcome::NotFound
    );
    assert_eq!(row_count(&idx), 2, "rows are never deleted");
    let a = idx.find_token(&id("abcdefgh")).unwrap().unwrap();
    assert!(a.revoked);
    assert_eq!(a.digest, [7; 32]);
    assert!(!idx.find_token(&id("bbbbbbbb")).unwrap().unwrap().revoked);
    let list = idx.list_tokens().unwrap();
    assert!(list[0].revoked && !list[1].revoked);
}

#[test]
fn a_revoke_that_changes_nothing_writes_nothing() {
    let (f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "a", T0))
        .unwrap();
    idx.revoke_token(&id("abcdefgh")).unwrap();
    let before = durable(f.dir.path());
    idx.revoke_token(&id("abcdefgh")).unwrap();
    idx.revoke_token(&id("cccccccc")).unwrap();
    assert_eq!(before, durable(f.dir.path()));
}

#[test]
fn last_used_is_written_at_most_once_a_minute_boundaries_exact() {
    let (_f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "a", T0))
        .unwrap();
    let t = id("abcdefgh");
    assert_eq!(last_used(&idx, "abcdefgh"), None);
    assert!(
        idx.touch_token(&t, at(T0 + 10)).unwrap(),
        "first use writes"
    );
    assert_eq!(last_used(&idx, "abcdefgh"), Some(T0 + 10));
    let first = T0 + 10;
    for (now, writes) in [
        (first, false),
        (first + 1, false),
        (first + TOUCH_INTERVAL_MS - 1, false),
        (first + TOUCH_INTERVAL_MS, true),
    ] {
        assert_eq!(idx.touch_token(&t, at(now)).unwrap(), writes, "now={now}");
        assert_eq!(
            last_used(&idx, "abcdefgh"),
            Some(if writes { now } else { first }),
            "now={now}"
        );
        if writes {
            break;
        }
    }
    // The next window starts from the new value.
    let second = first + TOUCH_INTERVAL_MS;
    assert!(
        !idx.touch_token(&t, at(second + TOUCH_INTERVAL_MS - 1))
            .unwrap()
    );
    assert!(
        idx.touch_token(&t, at(second + TOUCH_INTERVAL_MS + 1))
            .unwrap()
    );
}

#[test]
fn a_clock_that_steps_back_never_writes() {
    let (_f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "a", T0))
        .unwrap();
    let t = id("abcdefgh");
    assert!(idx.touch_token(&t, at(T0 + 3_600_000)).unwrap());
    assert!(!idx.touch_token(&t, at(T0)).unwrap());
    assert_eq!(last_used(&idx, "abcdefgh"), Some(T0 + 3_600_000));
}

#[test]
fn the_limit_is_per_token() {
    let (_f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "a", T0))
        .unwrap();
    idx.insert_token(&new_token("bbbbbbbb", 8, "b", T0))
        .unwrap();
    assert!(idx.touch_token(&id("abcdefgh"), at(T0 + 1)).unwrap());
    assert!(idx.touch_token(&id("bbbbbbbb"), at(T0 + 2)).unwrap());
    assert_eq!(last_used(&idx, "bbbbbbbb"), Some(T0 + 2));
}

#[test]
fn a_touch_inside_the_interval_or_for_an_unknown_id_writes_nothing() {
    let (f, mut idx) = open_new();
    idx.insert_token(&new_token("abcdefgh", 7, "a", T0))
        .unwrap();
    assert!(idx.touch_token(&id("abcdefgh"), at(T0 + 1)).unwrap());
    let before = durable(f.dir.path());
    assert!(!idx.touch_token(&id("abcdefgh"), at(T0 + 2)).unwrap());
    assert!(!idx.touch_token(&id("cccccccc"), at(T0 + 2)).unwrap());
    assert_eq!(
        before,
        durable(f.dir.path()),
        "a refused touch takes no write"
    );
    assert_eq!(row_count(&idx), 1, "an unknown id creates no row");
}

#[test]
fn the_table_holds_at_most_max_tokens_and_the_error_is_typed() {
    let (_f, mut idx) = open_new();
    idx.conn
        .execute_batch(&format!(
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < {}) \
             INSERT INTO api_tokens (id, digest, name, created_at_ms) \
             SELECT 'aaaaa' || substr('abcdefghijklmnopqrstuvwxyz234567', (i / 1024) % 32 + 1, 1) \
                 || substr('abcdefghijklmnopqrstuvwxyz234567', (i / 32) % 32 + 1, 1) \
                 || substr('abcdefghijklmnopqrstuvwxyz234567', i % 32 + 1, 1), zeroblob(32), 'n', {T0} FROM n;",
            MAX_TOKENS - 1
        ))
        .unwrap();
    assert_eq!(row_count(&idx), i64::try_from(MAX_TOKENS).unwrap());
    // -1 (full minus one row) and exact are covered by the insert above; +1 is refused.
    let err = idx
        .insert_token(&new_token("bbbbbbbb", 1, "x", T0))
        .unwrap_err();
    assert!(
        matches!(err, IndexError::TooManyTokens { max } if max == MAX_TOKENS),
        "{err:?}"
    );
    assert_eq!(row_count(&idx), i64::try_from(MAX_TOKENS).unwrap());
    assert_eq!(idx.list_tokens().unwrap().len(), MAX_TOKENS);
}

#[test]
fn one_row_below_the_cap_still_inserts() {
    let (_f, mut idx) = open_new();
    idx.conn
        .execute_batch(&format!(
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < {}) \
             INSERT INTO api_tokens (id, digest, name, created_at_ms) \
             SELECT 'aaaaa' || substr('abcdefghijklmnopqrstuvwxyz234567', (i / 1024) % 32 + 1, 1) \
                 || substr('abcdefghijklmnopqrstuvwxyz234567', (i / 32) % 32 + 1, 1) \
                 || substr('abcdefghijklmnopqrstuvwxyz234567', i % 32 + 1, 1), zeroblob(32), 'n', {T0} FROM n;",
            MAX_TOKENS - 2
        ))
        .unwrap();
    idx.insert_token(&new_token("bbbbbbbb", 1, "x", T0))
        .unwrap();
}

#[test]
fn the_schema_enforces_the_adr_bounds() {
    let (_f, idx) = open_new();
    let ins = |id: &str, digest: &str, name: &str, revoked: i64| {
        idx.conn.execute_batch(&format!(
            "INSERT INTO api_tokens (id, digest, name, created_at_ms, revoked) \
             VALUES ('{id}', {digest}, '{name}', {T0}, {revoked});"
        ))
    };
    let z = "zeroblob(32)";
    assert!(ins("abcdefgh", z, "ok", 0).is_ok());
    assert!(ins("abcdefgh", z, "dup", 0).is_err(), "id is UNIQUE");
    assert!(ins("abcdefg", z, "x", 0).is_err(), "id length");
    assert!(ins("abcdefghi", z, "x", 0).is_err(), "id length");
    assert!(
        ins("bbbbbbbb", "zeroblob(31)", "x", 0).is_err(),
        "digest 31"
    );
    assert!(
        ins("bbbbbbbb", "zeroblob(33)", "x", 0).is_err(),
        "digest 33"
    );
    assert!(ins("bbbbbbbb", z, "", 0).is_err(), "empty name");
    assert!(ins("bbbbbbbb", z, &"n".repeat(65), 0).is_err(), "name 65");
    assert!(ins("bbbbbbbb", z, &"n".repeat(64), 0).is_ok(), "name 64");
    assert!(ins("cccccccc", z, "x", 2).is_err(), "revoked in 0..=1");
    let strict: i64 = idx
        .conn
        .query_row(
            "SELECT strict FROM pragma_table_list('api_tokens')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(strict, 1);
    let cols: Vec<(String, String, i64)> = idx
        .conn
        .prepare("SELECT name, type, \"notnull\" FROM pragma_table_info('api_tokens') ORDER BY cid")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let want = [
        ("id", "TEXT", 1),
        ("digest", "BLOB", 1),
        ("name", "TEXT", 1),
        ("created_at_ms", "INTEGER", 1),
        ("last_used_at_ms", "INTEGER", 0),
        ("revoked", "INTEGER", 1),
    ]
    .map(|(n, t, nn)| (n.to_owned(), t.to_owned(), nn));
    assert_eq!(cols, want);
}

#[test]
fn no_statement_deletes_a_token_row() {
    let sql = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sql.rs")).unwrap();
    let tokens = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tokens.rs"))
        .unwrap()
        .to_ascii_uppercase();
    assert!(!sql.to_ascii_uppercase().contains("DELETE FROM API_TOKENS"));
    assert!(!tokens.contains("DELETE FROM"));
}

#[test]
fn a_corrupt_stored_row_is_a_typed_error_naming_the_column_only() {
    // (column, an `INSERT` that the schema accepts but the domain refuses)
    let cases = [
        (
            "id",
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('ABCDEFGH', zeroblob(32), 'n', 1700000000000)",
        ),
        (
            "name",
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('abcdefgh', zeroblob(32), char(10), 1700000000000)",
        ),
        (
            "created_at_ms",
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('abcdefgh', zeroblob(32), 'n', 5)",
        ),
        (
            "last_used_at_ms",
            "INSERT INTO api_tokens (id, digest, name, created_at_ms, last_used_at_ms) VALUES ('abcdefgh', zeroblob(32), 'n', 1700000000000, 5)",
        ),
        (
            "name",
            "INSERT INTO api_tokens (id, digest, name, created_at_ms) VALUES ('abcdefgh', zeroblob(32), '   ', 1700000000000)",
        ),
    ];
    for (column, insert) in cases {
        let (_f, idx) = open_new();
        idx.conn.execute_batch(insert).unwrap();
        let err = idx.list_tokens().unwrap_err();
        assert!(
            matches!(err, IndexError::CorruptTokenRow { field } if field == column),
            "{column}: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("stored token row is invalid: {column}")
        );
    }
}

#[test]
fn a_digest_of_the_wrong_type_is_a_typed_error() {
    // STRICT lets a BLOB column hold only a blob, so the type check is defence in depth: the
    // length is the `CHECK`, and the read refuses a length that a file edit got past it.
    let (_f, idx) = open_new();
    idx.conn
        .execute_batch(
            "PRAGMA ignore_check_constraints = 1; \
             INSERT INTO api_tokens (id, digest, name, created_at_ms) \
             VALUES ('abcdefgh', zeroblob(5), 'n', 1700000000000);",
        )
        .unwrap();
    let err = idx.find_token(&id("abcdefgh")).unwrap_err();
    assert!(
        matches!(err, IndexError::CorruptTokenRow { field: "digest" }),
        "{err:?}"
    );
}

#[test]
fn every_new_error_variant_has_a_message_that_names_no_row() {
    assert_eq!(
        IndexError::TokenIdTaken.to_string(),
        "a token with this id already exists"
    );
    assert_eq!(
        IndexError::TooManyTokens { max: 7 }.to_string(),
        "the token table is full (7 tokens)"
    );
    assert_eq!(
        IndexError::CorruptTokenRow { field: "name" }.to_string(),
        "stored token row is invalid: name"
    );
}

#[test]
fn the_token_store_adapter_covers_every_method_and_maps_errors() {
    let (_f, idx) = open_new();
    let store = TokenIndex::new(idx);
    let t = new_token("abcdefgh", 7, "a", T0);
    assert_eq!(ready(store.insert(&t)), Ok(()));
    assert_eq!(ready(store.insert(&t)), Err(InsertError::IdTaken));
    assert_eq!(
        ready(store.find(&id("abcdefgh"))),
        Ok(Some(TokenRecord {
            digest: [7; 32],
            revoked: false
        }))
    );
    assert_eq!(ready(store.find(&id("bbbbbbbb"))), Ok(None));
    assert_eq!(ready(store.list()).unwrap().len(), 1);
    assert_eq!(
        ready(store.touch_last_used(&id("abcdefgh"), at(T0 + 1))),
        Ok(true)
    );
    assert_eq!(
        ready(store.touch_last_used(&id("abcdefgh"), at(T0 + 2))),
        Ok(false)
    );
    assert_eq!(
        ready(store.revoke(&id("abcdefgh"))),
        Ok(RevokeOutcome::Revoked)
    );
    assert_eq!(
        ready(store.revoke(&id("abcdefgh"))),
        Ok(RevokeOutcome::AlreadyRevoked)
    );
    assert_eq!(
        ready(store.revoke(&id("bbbbbbbb"))),
        Ok(RevokeOutcome::NotFound)
    );
    assert!(ready(store.find(&id("abcdefgh"))).unwrap().unwrap().revoked);
    assert_eq!(format!("{store:?}"), "TokenIndex { .. }");
}

#[test]
fn the_adapter_maps_a_full_table_and_a_poisoned_lock() {
    let (_f, idx) = open_new();
    idx.conn
        .execute_batch(&format!(
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < {}) \
             INSERT INTO api_tokens (id, digest, name, created_at_ms) \
             SELECT 'aaaaa' || substr('abcdefghijklmnopqrstuvwxyz234567', (i / 1024) % 32 + 1, 1) \
                 || substr('abcdefghijklmnopqrstuvwxyz234567', (i / 32) % 32 + 1, 1) \
                 || substr('abcdefghijklmnopqrstuvwxyz234567', i % 32 + 1, 1), zeroblob(32), 'n', {T0} FROM n;",
            MAX_TOKENS - 1
        ))
        .unwrap();
    let store = Arc::new(TokenIndex::new(idx));
    assert_eq!(
        ready(store.insert(&new_token("bbbbbbbb", 1, "x", T0))),
        Err(InsertError::Full)
    );
    let s = Arc::clone(&store);
    let _ = std::thread::spawn(move || {
        let _ = s.with(|_| -> Result<(), IndexError> { panic!("poison the lock") });
    })
    .join();
    let e = TokenStoreError;
    assert_eq!(ready(store.find(&id("bbbbbbbb"))), Err(e));
    assert_eq!(ready(store.list()), Err(e));
    assert_eq!(ready(store.revoke(&id("bbbbbbbb"))), Err(e));
    assert_eq!(
        ready(store.touch_last_used(&id("bbbbbbbb"), at(T0))),
        Err(e)
    );
    assert_eq!(
        ready(store.insert(&new_token("bbbbbbbb", 1, "x", T0))),
        Err(InsertError::Store(e))
    );
}

#[test]
fn ids_of_every_byte_pattern_round_trip_through_the_table() {
    let (_f, mut idx) = open_new();
    for b in 0..32u8 {
        let t = TokenId::from_random([b; TOKEN_ID_LEN]);
        let mut n = new_token("aaaaaaaa", b, "x", T0);
        n.id = t;
        idx.insert_token(&n).unwrap();
        assert_eq!(idx.find_token(&t).unwrap().unwrap().digest, [b; 32]);
    }
    assert_eq!(idx.list_tokens().unwrap().len(), 32);
}
