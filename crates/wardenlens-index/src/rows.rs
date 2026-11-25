//! Reading rows back. The schema's `CHECK`s do not protect a file that was edited outside SQLite,
//! so every column is range-checked again and a violation is a typed error, never a panic, a wrap
//! or a lossy cast.

use rusqlite::Row;
use rusqlite::types::ValueRef;
use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{IndexedSegment, SegmentId, Tier};
use wardenlens_core::time::UnixMs;

use crate::error::IndexError;

/// The schema's bound on `duration_ms` (the real maximum is 120 s; 600 s is the `CHECK`).
pub(crate) const MAX_DURATION_MS: i64 = 600_000;

/// The smallest and largest `ended_at_ms` the schema allows: the start bounds plus one
/// millisecond of duration, and plus the longest duration.
pub(crate) const MIN_ENDED_MS: i64 = 946_684_800_001;
pub(crate) const MAX_ENDED_MS: i64 = 4_102_444_799_999 + MAX_DURATION_MS;

pub(crate) fn tier_code(tier: Tier) -> Result<i64, IndexError> {
    match tier {
        Tier::Hot => Ok(0),
        Tier::Archive => Ok(1),
        _ => Err(IndexError::InvalidRecord { field: "tier" }),
    }
}

pub(crate) fn tier_from_code(code: i64, id: i64) -> Result<Tier, IndexError> {
    match code {
        0 => Ok(Tier::Hot),
        1 => Ok(Tier::Archive),
        _ => Err(IndexError::CorruptRow { id, field: "tier" }),
    }
}

/// The opposite tier (the one a move starts from).
pub(crate) fn other_tier(tier: Tier) -> Result<Tier, IndexError> {
    match tier {
        Tier::Hot => Ok(Tier::Archive),
        Tier::Archive => Ok(Tier::Hot),
        _ => Err(IndexError::InvalidRecord { field: "tier" }),
    }
}

/// An INTEGER column; any other storage class is a corrupt row.
pub(crate) fn integer(
    row: &Row<'_>,
    idx: usize,
    id: i64,
    field: &'static str,
) -> Result<i64, IndexError> {
    match row.get_ref(idx) {
        Ok(ValueRef::Integer(i)) => Ok(i),
        Ok(_) => Err(IndexError::CorruptRow { id, field }),
        Err(e) => Err(IndexError::sqlite("read row")(e)),
    }
}

fn positive(row: &Row<'_>, idx: usize, id: i64, field: &'static str) -> Result<u64, IndexError> {
    u64::try_from(integer(row, idx, id, field)?)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(IndexError::CorruptRow { id, field })
}

/// The row id (column 0); a non-positive id is corrupt.
pub(crate) fn row_id(row: &Row<'_>) -> Result<(i64, SegmentId), IndexError> {
    let raw = integer(row, 0, 0, "id")?;
    let id = u64::try_from(raw)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(IndexError::CorruptRow {
            id: raw,
            field: "id",
        })?;
    Ok((raw, SegmentId::new(id)))
}

/// Decodes the full column list of `sql::GET` and `sql::LIST`.
pub(crate) fn decode_segment(row: &Row<'_>) -> Result<IndexedSegment, IndexError> {
    let (raw, id) = row_id(row)?;
    let camera = match row.get_ref(1) {
        Ok(ValueRef::Text(t)) => std::str::from_utf8(t)
            .ok()
            .and_then(|s| CameraId::new(s).ok()),
        Ok(_) => None,
        Err(e) => return Err(IndexError::sqlite("read row")(e)),
    }
    .ok_or(IndexError::CorruptRow {
        id: raw,
        field: "camera_id",
    })?;
    let started_raw = integer(row, 2, raw, "started_at_ms")?;
    let started = UnixMs::new(started_raw).map_err(|_| IndexError::CorruptRow {
        id: raw,
        field: "started_at_ms",
    })?;
    let duration = integer(row, 3, raw, "duration_ms")?;
    if !(1..=MAX_DURATION_MS).contains(&duration) {
        return Err(IndexError::CorruptRow {
            id: raw,
            field: "duration_ms",
        });
    }
    let ended = integer(row, 4, raw, "ended_at_ms")?;
    if started_raw.checked_add(duration) != Some(ended) {
        return Err(IndexError::CorruptRow {
            id: raw,
            field: "ended_at_ms",
        });
    }
    let bytes = positive(row, 5, raw, "bytes")?;
    let frames = positive(row, 6, raw, "frame_count")?;
    let tier = tier_from_code(integer(row, 7, raw, "tier")?, raw)?;
    let duration = u64::try_from(duration).map_err(|_| IndexError::CorruptRow {
        id: raw,
        field: "duration_ms",
    })?;
    Ok(IndexedSegment::new(
        id,
        tier,
        SegmentRecord::new(camera, started, duration, bytes, frames),
    ))
}
