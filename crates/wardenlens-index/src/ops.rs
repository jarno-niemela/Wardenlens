//! [`SegmentIndex`] on SQLite.

use rusqlite::{ErrorCode, params};
use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{
    IndexedSegment, MAX_LIST_LIMIT, MAX_OLDEST, SegmentCursor, SegmentId, SegmentIndex,
    SegmentPage, StoredSegment, Tier, TierTotals, TierUsage,
};
use wardenlens_core::time::{Timestamp, UnixMs};

use crate::cursor::{self, Position};
use crate::error::IndexError;
use crate::rows::{
    MAX_DURATION_MS, MAX_ENDED_MS, MIN_ENDED_MS, decode_segment, integer, other_tier, row_id,
    tier_code, tier_from_code,
};
use crate::{Index, sql};

fn raw_id(id: SegmentId) -> Option<i64> {
    i64::try_from(id.as_u64()).ok()
}

fn invalid(field: &'static str) -> IndexError {
    IndexError::InvalidRecord { field }
}

fn check_limit(limit: usize, max: usize) -> Result<i64, IndexError> {
    if limit == 0 || limit > max {
        return Err(IndexError::InvalidLimit { limit, max });
    }
    i64::try_from(limit).map_err(|_| IndexError::InvalidLimit { limit, max })
}

fn map_insert(e: rusqlite::Error) -> IndexError {
    if let rusqlite::Error::SqliteFailure(f, _) = &e {
        if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            || f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
        {
            return IndexError::Duplicate;
        }
        if f.code == ErrorCode::ConstraintViolation {
            return IndexError::Constraint { op: "insert" };
        }
    }
    IndexError::sqlite("insert")(e)
}

impl SegmentIndex for Index {
    type Error = IndexError;

    fn insert(&mut self, record: &SegmentRecord, tier: Tier) -> Result<SegmentId, IndexError> {
        let started = record.started_at_ms.as_i64();
        let duration = i64::try_from(record.duration_ms)
            .ok()
            .filter(|d| (1..=MAX_DURATION_MS).contains(d))
            .ok_or(invalid("duration_ms"))?;
        let ended = started
            .checked_add(duration)
            .ok_or(invalid("ended_at_ms"))?;
        let bytes = i64::try_from(record.bytes)
            .ok()
            .filter(|b| *b > 0)
            .ok_or(invalid("bytes"))?;
        let frames = i64::try_from(record.frame_count)
            .ok()
            .filter(|f| *f > 0)
            .ok_or(invalid("frame_count"))?;
        self.conn
            .execute(
                sql::INSERT,
                params![
                    record.camera.as_str(),
                    started,
                    duration,
                    ended,
                    bytes,
                    frames,
                    tier_code(tier)?
                ],
            )
            .map_err(map_insert)?;
        let raw = self.conn.last_insert_rowid();
        u64::try_from(raw)
            .map(SegmentId::new)
            .map_err(|_| IndexError::CorruptRow {
                id: raw,
                field: "id",
            })
    }

    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, IndexError> {
        let Some(raw) = raw_id(id) else {
            return Ok(None); // no row can have an id above i64::MAX
        };
        let mut stmt = self
            .conn
            .prepare(sql::GET)
            .map_err(IndexError::sqlite("get"))?;
        let mut rows = stmt.query([raw]).map_err(IndexError::sqlite("get"))?;
        match rows.next().map_err(IndexError::sqlite("get"))? {
            Some(row) => decode_segment(row).map(Some),
            None => Ok(None),
        }
    }

    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, IndexError> {
        let limit_i = check_limit(limit, MAX_LIST_LIMIT)?;
        let after = match cursor {
            Some(c) => cursor::decode(camera, c)?,
            None => Position {
                started_at_ms: i64::MIN,
                id: 0,
            },
        };
        let (from, to) = (from.as_unix_millis(), to.as_unix_millis());
        if from >= to {
            return Ok(SegmentPage::new(Vec::new(), None));
        }
        let mut stmt = self
            .conn
            .prepare(sql::LIST)
            .map_err(IndexError::sqlite("list"))?;
        // One row more than asked tells whether another page follows.
        let mut rows = stmt
            .query(params![
                camera.as_str(),
                from.saturating_sub(MAX_DURATION_MS),
                to,
                from,
                after.started_at_ms,
                after.id,
                limit_i.saturating_add(1)
            ])
            .map_err(IndexError::sqlite("list"))?;
        let mut items = Vec::new();
        while let Some(row) = rows.next().map_err(IndexError::sqlite("list"))? {
            items.push(decode_segment(row)?);
        }
        let more = items.len() > limit;
        items.truncate(limit);
        let next = match (more, items.last()) {
            (true, Some(last)) => {
                let id = raw_id(last.id).ok_or(IndexError::CorruptRow { id: 0, field: "id" })?;
                Some(cursor::encode(
                    camera,
                    Position {
                        started_at_ms: last.record.started_at_ms.as_i64(),
                        id,
                    },
                ))
            }
            _ => None,
        };
        Ok(SegmentPage::new(items, next))
    }

    fn set_tier(&mut self, id: SegmentId, tier: Tier) -> Result<(), IndexError> {
        let Some(raw) = raw_id(id) else {
            return Err(IndexError::NotFound(id.as_u64()));
        };
        let changed = self
            .conn
            .execute(
                sql::SET_TIER,
                params![raw, tier_code(tier)?, tier_code(other_tier(tier)?)?],
            )
            .map_err(IndexError::sqlite("set tier"))?;
        if changed == 1 {
            return Ok(());
        }
        let mut stmt = self
            .conn
            .prepare(sql::TIER_OF)
            .map_err(IndexError::sqlite("set tier"))?;
        let mut rows = stmt.query([raw]).map_err(IndexError::sqlite("set tier"))?;
        match rows.next().map_err(IndexError::sqlite("set tier"))? {
            None => Err(IndexError::NotFound(id.as_u64())),
            Some(_) => Err(IndexError::AlreadyOnTier(id.as_u64())),
        }
    }

    fn delete(&mut self, id: SegmentId) -> Result<(), IndexError> {
        let Some(raw) = raw_id(id) else {
            return Err(IndexError::NotFound(id.as_u64()));
        };
        let changed = self
            .conn
            .execute(sql::DELETE, [raw])
            .map_err(IndexError::sqlite("delete"))?;
        if changed == 1 {
            Ok(())
        } else {
            Err(IndexError::NotFound(id.as_u64()))
        }
    }

    fn oldest(&self, tier: Tier, n: usize) -> Result<Vec<StoredSegment>, IndexError> {
        let n_i = check_limit(n, MAX_OLDEST)?;
        let mut stmt = self
            .conn
            .prepare(sql::OLDEST)
            .map_err(IndexError::sqlite("oldest"))?;
        let mut rows = stmt
            .query(params![tier_code(tier)?, n_i])
            .map_err(IndexError::sqlite("oldest"))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(IndexError::sqlite("oldest"))? {
            let (raw, id) = row_id(row)?;
            let stored_tier = tier_from_code(integer(row, 1, raw, "tier")?, raw)?;
            let bytes = u64::try_from(integer(row, 2, raw, "bytes")?)
                .ok()
                .filter(|b| *b > 0)
                .ok_or(IndexError::CorruptRow {
                    id: raw,
                    field: "bytes",
                })?;
            let ended = integer(row, 3, raw, "ended_at_ms")?;
            if !(MIN_ENDED_MS..=MAX_ENDED_MS).contains(&ended) {
                return Err(IndexError::CorruptRow {
                    id: raw,
                    field: "ended_at_ms",
                });
            }
            out.push(StoredSegment {
                id,
                tier: stored_tier,
                bytes,
                ended_at: Timestamp::from_unix_millis(ended),
            });
        }
        Ok(out)
    }

    fn bytes_by_tier(&self) -> Result<TierTotals, IndexError> {
        let mut stmt = self
            .conn
            .prepare(sql::BYTES_BY_TIER)
            .map_err(IndexError::sqlite("bytes by tier"))?;
        let mut rows = stmt
            .query([])
            .map_err(IndexError::sqlite("bytes by tier"))?;
        let mut totals = TierTotals::default();
        while let Some(row) = rows.next().map_err(IndexError::sqlite("bytes by tier"))? {
            let tier = tier_from_code(integer(row, 0, 0, "tier")?, 0)?;
            let usage = TierUsage {
                bytes: u64::try_from(integer(row, 1, 0, "bytes")?).map_err(|_| {
                    IndexError::CorruptRow {
                        id: 0,
                        field: "bytes",
                    }
                })?,
                segments: u64::try_from(integer(row, 2, 0, "count")?).map_err(|_| {
                    IndexError::CorruptRow {
                        id: 0,
                        field: "count",
                    }
                })?,
            };
            match tier {
                Tier::Hot => totals.hot = usage,
                Tier::Archive => totals.archive = usage,
                _ => {
                    return Err(IndexError::CorruptRow {
                        id: 0,
                        field: "tier",
                    });
                }
            }
        }
        Ok(totals)
    }

    fn latest_started_at(&self, camera: &CameraId) -> Result<Option<UnixMs>, IndexError> {
        let value: Option<i64> = self
            .conn
            .query_row(sql::LATEST_START, [camera.as_str()], |r| r.get(0))
            .map_err(IndexError::sqlite("latest start"))?;
        value
            .map(|ms| {
                UnixMs::new(ms).map_err(|_| IndexError::CorruptRow {
                    id: 0,
                    field: "started_at_ms",
                })
            })
            .transpose()
    }
}
