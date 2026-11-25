//! [`SegmentIndex`] on SQLite.

use rusqlite::types::ValueRef;
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
    segment_bytes, tier_code, tier_from_code,
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
            .filter(|b| segment_bytes(*b).is_some())
            .ok_or(invalid("bytes"))?;
        let frames = i64::try_from(record.frame_count)
            .ok()
            .filter(|f| *f > 0)
            .ok_or(invalid("frame_count"))?;
        let code = tier_code(tier)?;
        let camera = record.camera.as_str();
        sql::write_tx(&mut self.conn, "insert", |w| {
            w.execute(
                sql::INSERT,
                params![camera, started, duration, ended, bytes, frames, code],
            )
            .map_err(map_insert)?;
            let raw = w.conn().last_insert_rowid();
            u64::try_from(raw)
                .map(SegmentId::new)
                .map_err(|_| IndexError::CorruptRow {
                    id: raw,
                    field: "id",
                })
        })
    }

    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, IndexError> {
        let Some(raw) = raw_id(id) else {
            return Ok(None); // no row can have an id above i64::MAX
        };
        let mut stmt = sql::prepare(&self.conn, sql::GET).map_err(IndexError::sqlite("get"))?;
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
        let mut stmt = sql::prepare(&self.conn, sql::LIST).map_err(IndexError::sqlite("list"))?;
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
        let (new_code, old_code) = (tier_code(tier)?, tier_code(other_tier(tier)?)?);
        sql::write_tx(&mut self.conn, "set tier", |w| {
            let changed = w
                .execute(sql::SET_TIER, params![raw, new_code, old_code])
                .map_err(IndexError::sqlite("set tier"))?;
            if changed == 1 {
                return Ok(());
            }
            // Nothing changed: say why. The error rolls the transaction back (no bump).
            let mut stmt =
                sql::prepare(w.conn(), sql::TIER_OF).map_err(IndexError::sqlite("set tier"))?;
            let mut rows = stmt.query([raw]).map_err(IndexError::sqlite("set tier"))?;
            match rows.next().map_err(IndexError::sqlite("set tier"))? {
                None => Err(IndexError::NotFound(id.as_u64())),
                Some(_) => Err(IndexError::AlreadyOnTier(id.as_u64())),
            }
        })
    }

    fn delete(&mut self, id: SegmentId) -> Result<(), IndexError> {
        let Some(raw) = raw_id(id) else {
            return Err(IndexError::NotFound(id.as_u64()));
        };
        sql::write_tx(&mut self.conn, "delete", |w| {
            let changed = w
                .execute(sql::DELETE, [raw])
                .map_err(IndexError::sqlite("delete"))?;
            if changed == 1 {
                Ok(())
            } else {
                Err(IndexError::NotFound(id.as_u64()))
            }
        })
    }

    fn oldest(
        &self,
        tier: Tier,
        after: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, IndexError> {
        let n_i = check_limit(n, MAX_OLDEST)?;
        // The key of the row to continue after; `(MIN, 0)` is before every row.
        let (after_end, after_id) = match after {
            None => (i64::MIN, 0),
            // An id above i64::MAX names no row, so it sorts after every row that ends at `ended`:
            // clamping it to i64::MAX gives the same keyset.
            Some((ended, id)) => (ended.as_unix_millis(), raw_id(id).unwrap_or(i64::MAX)),
        };
        let mut stmt =
            sql::prepare(&self.conn, sql::OLDEST).map_err(IndexError::sqlite("oldest"))?;
        let mut rows = stmt
            .query(params![tier_code(tier)?, after_end, after_id, n_i])
            .map_err(IndexError::sqlite("oldest"))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(IndexError::sqlite("oldest"))? {
            let (raw, id) = row_id(row)?;
            let stored_tier = tier_from_code(integer(row, 1, raw, "tier")?, raw)?;
            let bytes =
                segment_bytes(integer(row, 2, raw, "bytes")?).ok_or(IndexError::CorruptRow {
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
        let mut stmt = sql::prepare(&self.conn, sql::BYTES_BY_TIER)
            .map_err(IndexError::sqlite("bytes by tier"))?;
        let mut rows = stmt
            .query([])
            .map_err(IndexError::sqlite("bytes by tier"))?;
        let mut totals = TierTotals::default();
        while let Some(row) = rows.next().map_err(IndexError::sqlite("bytes by tier"))? {
            let tier = tier_from_code(integer(row, 0, 0, "tier")?, 0)?;
            let corrupt = |field| IndexError::CorruptRow { id: 0, field };
            let sum = u64::try_from(integer(row, 1, 0, "bytes")?).map_err(|_| corrupt("bytes"))?;
            let segments =
                u64::try_from(integer(row, 2, 0, "count")?).map_err(|_| corrupt("count"))?;
            // The smallest and largest row must each be a valid size: a stored zero, a negative
            // or an oversized value hides inside a sum that still looks plausible.
            let smallest = integer(row, 3, 0, "bytes")?;
            let largest = integer(row, 4, 0, "bytes")?;
            if segment_bytes(smallest).is_none() || segment_bytes(largest).is_none() {
                return Err(corrupt("bytes"));
            }
            let usage = TierUsage {
                bytes: sum,
                segments,
            };
            match tier {
                Tier::Hot => totals.hot = usage,
                Tier::Archive => totals.archive = usage,
                _ => return Err(corrupt("tier")),
            }
        }
        Ok(totals)
    }

    fn latest_started_at(&self, camera: &CameraId) -> Result<Option<UnixMs>, IndexError> {
        let corrupt = IndexError::CorruptRow {
            id: 0,
            field: "started_at_ms",
        };
        // The storage class is checked by hand: a wrong type is a corrupt row, not a driver error.
        let value = sql::query_row(&self.conn, sql::LATEST_START, [camera.as_str()], |r| {
            Ok(match r.get_ref(0)? {
                ValueRef::Null => Some(None),
                ValueRef::Integer(i) => Some(Some(i)),
                _ => None,
            })
        })
        .map_err(IndexError::sqlite("latest start"))?;
        match value {
            Some(None) => Ok(None),
            Some(Some(ms)) => UnixMs::new(ms).map(Some).map_err(|_| corrupt),
            None => Err(corrupt),
        }
    }
}
