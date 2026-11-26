//! The API token table (ADR 0004 section 9, ADR 0005 section 5; ticket #65).
//!
//! **Plain data access.** Nothing here hashes, parses or compares a token secret: generation,
//! hashing and verification are `wardenlens-api::token`, which gets the stored digest from
//! [`Index::find_token`] and compares it itself. The table holds the SHA-256 of each secret, the
//! name and the times, never a secret.
//!
//! **Rows are never deleted.** [`Index::revoke_token`] sets `revoked`; the row, and so the id,
//! stays, and [`Index::insert_token`] refuses an id that exists, revoked or not
//! ([`IndexError::TokenIdTaken`]), so an id is never issued twice.
//!
//! **`last_used` rate limit.** It is enforced here, in the store, by the conditional `UPDATE` of
//! [`Index::touch_token`]: a token's `last_used_at_ms` is written only when it is empty or at
//! least [`TOUCH_INTERVAL_MS`] older than `now`. A caller (the API's verifier) may therefore call
//! on every request: within the minute it costs one read and takes no write lock. If the wall
//! clock steps back, `last_used_at_ms` stays ahead of `now` and is not written until `now`
//! catches up (never an unbounded write rate).
//!
//! [`TokenIndex`] makes an [`Index`] a core [`TokenStore`] (verification lookup, for the async API) and a
//! [`TokenAdmin`] (insert, list, revoke, `last_used`). Its futures are
//! already complete when returned and the SQLite call runs on the calling thread, so an async
//! caller on a busy executor wraps calls in `spawn_blocking`, as for the rest of this crate.

use std::future::Future;
use std::sync::Mutex;

use rusqlite::types::ValueRef;
use wardenlens_core::time::UnixMs;
use wardenlens_core::token_store::{
    InsertError, MAX_TOKENS, NewToken, RevokeOutcome, TokenAdmin, TokenId, TokenName, TokenRecord,
    TokenStore, TokenStoreError, TokenSummary,
};

use crate::error::IndexError;
use crate::{Index, sql};

/// The shortest time between two writes of one token's `last_used_at_ms`, in milliseconds.
pub const TOUCH_INTERVAL_MS: i64 = 60_000;

fn corrupt(field: &'static str) -> IndexError {
    IndexError::CorruptTokenRow { field }
}

fn int_col(row: &rusqlite::Row<'_>, idx: usize, field: &'static str) -> Result<i64, IndexError> {
    match row.get_ref(idx) {
        Ok(ValueRef::Integer(i)) => Ok(i),
        Ok(_) => Err(corrupt(field)),
        Err(e) => Err(IndexError::sqlite("read token")(e)),
    }
}

fn revoked_col(row: &rusqlite::Row<'_>, idx: usize) -> Result<bool, IndexError> {
    match int_col(row, idx, "revoked")? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(corrupt("revoked")),
    }
}

fn time_col(
    row: &rusqlite::Row<'_>,
    idx: usize,
    field: &'static str,
) -> Result<UnixMs, IndexError> {
    UnixMs::new(int_col(row, idx, field)?).map_err(|_| corrupt(field))
}

fn text_col<'r>(
    row: &'r rusqlite::Row<'_>,
    idx: usize,
    field: &'static str,
) -> Result<&'r str, IndexError> {
    match row.get_ref(idx) {
        Ok(ValueRef::Text(t)) => std::str::from_utf8(t).map_err(|_| corrupt(field)),
        Ok(_) => Err(corrupt(field)),
        Err(e) => Err(IndexError::sqlite("read token")(e)),
    }
}

fn count(db: &sql::Db, stmt: sql::ReadSql, id: Option<&str>) -> Result<i64, IndexError> {
    let r = match id {
        Some(id) => sql::query_row(db, stmt, [id], |r| r.get(0)),
        None => sql::query_row(db, stmt, [], |r| r.get(0)),
    };
    r.map_err(IndexError::sqlite("count tokens"))
}

impl Index {
    /// Stores `token` (active, never used) in one write transaction.
    ///
    /// # Errors
    /// - [`IndexError::TokenIdTaken`]: a row with this id exists, revoked or not. Nothing was
    ///   written; the caller generates another token.
    /// - [`IndexError::TooManyTokens`]: [`MAX_TOKENS`] rows exist.
    /// - [`IndexError::Constraint`], [`IndexError::Busy`], [`IndexError::Sqlite`].
    pub fn insert_token(&mut self, token: &NewToken) -> Result<(), IndexError> {
        let id = token.id.as_str();
        sql::write_tx(&mut self.conn, "insert token", |w| {
            if count(w.read_conn(), sql::TOKEN_EXISTS, Some(id))? > 0 {
                return Err(IndexError::TokenIdTaken);
            }
            if usize::try_from(count(w.read_conn(), sql::TOKEN_COUNT, None)?)
                .map_or(true, |n| n >= MAX_TOKENS)
            {
                return Err(IndexError::TooManyTokens { max: MAX_TOKENS });
            }
            w.write(
                sql::INSERT_TOKEN,
                rusqlite::params![
                    id,
                    token.digest.as_slice(),
                    token.name.as_str(),
                    token.created_at.as_i64()
                ],
            )
            .map_err(|e| match e.sqlite_error_code() {
                Some(rusqlite::ErrorCode::ConstraintViolation) => {
                    IndexError::Constraint { op: "insert token" }
                }
                _ => IndexError::sqlite("insert token")(e),
            })?;
            Ok(())
        })
    }

    /// What is stored for `id`: the digest and whether it is revoked; `None` for an unknown id.
    ///
    /// # Errors
    /// [`IndexError::CorruptTokenRow`] (a column is out of bounds), [`IndexError::Busy`],
    /// [`IndexError::Sqlite`].
    pub fn find_token(&self, id: &TokenId) -> Result<Option<TokenRecord>, IndexError> {
        let mut stmt =
            sql::prepare(&self.conn, sql::FIND_TOKEN).map_err(IndexError::sqlite("find token"))?;
        let mut rows = stmt
            .query([id.as_str()])
            .map_err(IndexError::sqlite("find token"))?;
        let Some(row) = rows.next().map_err(IndexError::sqlite("find token"))? else {
            return Ok(None);
        };
        let digest = match row.get_ref(0) {
            Ok(ValueRef::Blob(b)) => <[u8; 32]>::try_from(b).map_err(|_| corrupt("digest"))?,
            Ok(_) => return Err(corrupt("digest")),
            Err(e) => return Err(IndexError::sqlite("find token")(e)),
        };
        Ok(Some(TokenRecord {
            digest,
            revoked: revoked_col(row, 1)?,
        }))
    }

    /// Every token, oldest first, at most [`MAX_TOKENS`]. No digest is read.
    ///
    /// # Errors
    /// [`IndexError::CorruptTokenRow`] (an id, name or time out of bounds), [`IndexError::Busy`],
    /// [`IndexError::Sqlite`].
    pub fn list_tokens(&self) -> Result<Vec<TokenSummary>, IndexError> {
        let limit = i64::try_from(MAX_TOKENS).unwrap_or(i64::MAX);
        let mut stmt = sql::prepare(&self.conn, sql::LIST_TOKENS)
            .map_err(IndexError::sqlite("list tokens"))?;
        let mut rows = stmt
            .query([limit])
            .map_err(IndexError::sqlite("list tokens"))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(IndexError::sqlite("list tokens"))? {
            let last_used_at = match row.get_ref(3) {
                Ok(ValueRef::Null) => None,
                Ok(_) => Some(time_col(row, 3, "last_used_at_ms")?),
                Err(e) => return Err(IndexError::sqlite("list tokens")(e)),
            };
            out.push(TokenSummary {
                id: TokenId::parse(text_col(row, 0, "id")?).map_err(|_| corrupt("id"))?,
                name: TokenName::new(text_col(row, 1, "name")?).map_err(|_| corrupt("name"))?,
                created_at: time_col(row, 2, "created_at_ms")?,
                last_used_at,
                revoked: revoked_col(row, 4)?,
            });
        }
        Ok(out)
    }

    /// Marks the token revoked; the row stays. An already revoked or unknown id writes nothing.
    ///
    /// # Errors
    /// [`IndexError::Busy`], [`IndexError::Sqlite`].
    pub fn revoke_token(&mut self, id: &TokenId) -> Result<RevokeOutcome, IndexError> {
        let mut outcome = RevokeOutcome::NotFound;
        sql::write_tx_opt(&mut self.conn, "revoke token", |w| {
            let changed = w
                .write(sql::REVOKE_TOKEN, [id.as_str()])
                .map_err(IndexError::sqlite("revoke token"))?;
            if changed > 0 {
                outcome = RevokeOutcome::Revoked;
                return Ok(Some(()));
            }
            if count(w.read_conn(), sql::TOKEN_EXISTS, Some(id.as_str()))? > 0 {
                outcome = RevokeOutcome::AlreadyRevoked;
            }
            Ok(None)
        })?;
        Ok(outcome)
    }

    /// Records a use of the token at `now`, at most once per [`TOUCH_INTERVAL_MS`] per token (see
    /// the module docs). Returns whether a write happened. An unknown id writes nothing.
    ///
    /// # Errors
    /// [`IndexError::Busy`], [`IndexError::Sqlite`].
    pub fn touch_token(&mut self, id: &TokenId, now: UnixMs) -> Result<bool, IndexError> {
        let due = now.as_i64().saturating_sub(TOUCH_INTERVAL_MS);
        // A token used within the interval takes no write lock.
        if touch_due(&self.conn, id.as_str(), due)? == 0 {
            return Ok(false);
        }
        let written = sql::write_tx_opt(&mut self.conn, "touch token", |w| {
            let n = w
                .write(
                    sql::TOUCH_TOKEN,
                    rusqlite::params![id.as_str(), now.as_i64(), due],
                )
                .map_err(IndexError::sqlite("touch token"))?;
            Ok((n > 0).then_some(()))
        })?;
        Ok(written.is_some())
    }
}

fn touch_due(db: &sql::Db, id: &str, due: i64) -> Result<i64, IndexError> {
    sql::query_row(db, sql::TOKEN_TOUCH_DUE, rusqlite::params![id, due], |r| {
        r.get(0)
    })
    .map_err(IndexError::sqlite("touch token"))
}

/// An [`Index`] as a core [`TokenStore`] and [`TokenAdmin`]. The connection is behind a `Mutex`, so the store is
/// `Send + Sync`; a poisoned lock is a store failure, never a panic. Store errors reach callers
/// without detail ([`TokenStoreError`]); use the [`Index`] methods for typed ones.
pub struct TokenIndex {
    index: Mutex<Index>,
}

impl std::fmt::Debug for TokenIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenIndex { .. }")
    }
}

impl TokenIndex {
    /// Wraps an open index.
    #[must_use]
    pub fn new(index: Index) -> Self {
        Self {
            index: Mutex::new(index),
        }
    }

    pub(crate) fn with<T>(
        &self,
        f: impl FnOnce(&mut Index) -> Result<T, IndexError>,
    ) -> Result<T, IndexError> {
        let mut guard = self.index.lock().map_err(|_| IndexError::Sqlite {
            op: "token store lock",
            code: None,
        })?;
        f(&mut guard)
    }
}

impl TokenStore for TokenIndex {
    fn find(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<Option<TokenRecord>, TokenStoreError>> + Send {
        std::future::ready(self.with(|i| i.find_token(id)).map_err(|_| TokenStoreError))
    }
}

impl TokenAdmin for TokenIndex {
    fn insert(&self, token: &NewToken) -> impl Future<Output = Result<(), InsertError>> + Send {
        std::future::ready(self.with(|i| i.insert_token(token)).map_err(|e| match e {
            IndexError::TokenIdTaken => InsertError::IdTaken,
            IndexError::TooManyTokens { .. } => InsertError::Full,
            _ => InsertError::Store(TokenStoreError),
        }))
    }

    fn list(&self) -> impl Future<Output = Result<Vec<TokenSummary>, TokenStoreError>> + Send {
        std::future::ready(self.with(|i| i.list_tokens()).map_err(|_| TokenStoreError))
    }

    fn revoke(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<RevokeOutcome, TokenStoreError>> + Send {
        std::future::ready(
            self.with(|i| i.revoke_token(id))
                .map_err(|_| TokenStoreError),
        )
    }

    fn touch_last_used(
        &self,
        id: &TokenId,
        now: UnixMs,
    ) -> impl Future<Output = Result<bool, TokenStoreError>> + Send {
        std::future::ready(
            self.with(|i| i.touch_token(id, now))
                .map_err(|_| TokenStoreError),
        )
    }
}
