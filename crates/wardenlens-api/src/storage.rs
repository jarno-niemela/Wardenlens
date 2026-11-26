//! Read-only storage status (ADR 0004, ADR 0005 section 6): `GET /api/v1/storage`.
//!
//! The handler takes the core [`StorageStatus`] port as a generic (never `dyn`). The response
//! types are the whole wire format and are built field by field from the core snapshot. Tiers are
//! `hot` and `archive`; there is no filesystem path, mount point, device id or error text, only
//! closed enums. Free-space numbers are `null` while a volume cannot be measured.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;
use wardenlens_core::storage::{
    ArchiveCondition, ArchiveUnavailableCause, StorageSnapshot, StorageStatus, TickErrorKind,
    TierStatus,
};

use wardenlens_core::time::Timestamp;

use crate::error::ErrorBody;

/// One tier. The space fields, except `min_free_percent`, are `null` when the volume could not be measured.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TierDto {
    /// Capacity as the floor arithmetic sees it: `(f_blocks - f_bfree + f_bavail) * f_frsize`.
    total_bytes: Option<u64>,
    /// Space available to the service: `f_bavail * f_frsize`.
    free_bytes: Option<u64>,
    /// `free_bytes * 100 / total_bytes`, rounded down.
    free_percent: Option<u8>,
    /// The configured floor, in percent; present whenever a tick has run, even while the volume
    /// is not measured.
    min_free_percent: Option<u8>,
    /// Free space is under the floor.
    below_floor: Option<bool>,
    /// Segment rows on this tier.
    segments: u64,
    /// End time of the oldest segment, in UTC Unix milliseconds; `null` for an empty tier.
    oldest_segment: Option<i64>,
    /// End time of the newest segment, in UTC Unix milliseconds; `null` for an empty tier.
    newest_segment: Option<i64>,
}

/// State of the archive.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArchiveStateDto {
    /// Available and taking moves.
    Available,
    /// Available but unable to absorb the moves even after evicting everything
    /// (`archive_full`); it behaves like unavailable.
    Full,
    /// `archive_unavailable`; see `unavailable_cause`.
    Unavailable,
}

/// Class of the cause of an unavailable archive. Never a path.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnavailableCauseDto {
    /// The root is missing, not a directory, a symlink, or cannot be opened.
    Missing,
    /// Same filesystem as the hot root (an unmounted disk).
    SameFilesystem,
    /// Mounted read-only.
    ReadOnly,
    /// The marker file is missing.
    NoMarker,
    /// Consecutive archive-side move failures.
    MoveFailures,
    /// Zero capacity or overflowing arithmetic.
    Unusable,
    /// The probe's own calls failed.
    ProbeFailed,
    /// Anything else.
    Other,
}

/// The archive tier and its state.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ArchiveDto {
    #[serde(flatten)]
    tier: TierDto,
    /// `available`, `full` (`archive_full`) or `unavailable` (`archive_unavailable`).
    state: ArchiveStateDto,
    /// Present exactly when `state` is `unavailable`.
    unavailable_cause: Option<UnavailableCauseDto>,
}

/// Why the latest storage tick failed.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TickErrorDto {
    /// The hot volume could not be probed or is unusable.
    HotVolume,
    /// The index could not be read.
    Index,
    /// The planner refused its input.
    Plan,
    /// Anything else.
    Other,
}

/// Storage status.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct StorageDto {
    hot: TierDto,
    archive: ArchiveDto,
    /// Event counter: times, since start, a segment was left alone because nothing could be
    /// concluded about it (the same segment can count again on a later tick).
    unverified_total: u64,
    /// Event counter: files moved into a quarantine since start, whatever the reason.
    quarantined_total: u64,
    /// When the latest tick ran, in UTC Unix milliseconds; `null` before the first tick.
    last_tick: Option<i64>,
    /// Kind of the latest tick's failure; `null` when it succeeded. Never error text.
    last_error: Option<TickErrorDto>,
    /// Ticks since start, per volume, that found it under its floor.
    floor_breaches_total: u64,
}

fn tier_dto(t: &TierStatus) -> TierDto {
    TierDto {
        total_bytes: t.volume.map(|v| v.total_bytes()),
        free_bytes: t.volume.map(|v| v.free_bytes()),
        free_percent: t.volume.map(|v| v.free_percent()),
        min_free_percent: t.min_free_percent,
        below_floor: t.volume.map(|v| v.below_floor()),
        segments: t.segments,
        oldest_segment: t.oldest.map(Timestamp::as_unix_millis),
        newest_segment: t.newest.map(Timestamp::as_unix_millis),
    }
}

fn cause_dto(c: ArchiveUnavailableCause) -> UnavailableCauseDto {
    match c {
        ArchiveUnavailableCause::Missing => UnavailableCauseDto::Missing,
        ArchiveUnavailableCause::SameFilesystem => UnavailableCauseDto::SameFilesystem,
        ArchiveUnavailableCause::ReadOnly => UnavailableCauseDto::ReadOnly,
        ArchiveUnavailableCause::NoMarker => UnavailableCauseDto::NoMarker,
        ArchiveUnavailableCause::MoveFailures => UnavailableCauseDto::MoveFailures,
        ArchiveUnavailableCause::Unusable => UnavailableCauseDto::Unusable,
        ArchiveUnavailableCause::ProbeFailed => UnavailableCauseDto::ProbeFailed,
        // Non-exhaustive: a cause added later is reported as `other`.
        _ => UnavailableCauseDto::Other,
    }
}

fn archive_dto(s: &StorageSnapshot) -> ArchiveDto {
    let (state, unavailable_cause) = match s.archive_condition {
        ArchiveCondition::Available => (ArchiveStateDto::Available, None),
        ArchiveCondition::Full => (ArchiveStateDto::Full, None),
        ArchiveCondition::Unavailable(c) => (ArchiveStateDto::Unavailable, Some(cause_dto(c))),
        // Non-exhaustive: a state added later is reported as unavailable, the safe reading.
        _ => (
            ArchiveStateDto::Unavailable,
            Some(UnavailableCauseDto::Other),
        ),
    };
    ArchiveDto {
        tier: tier_dto(&s.archive),
        state,
        unavailable_cause,
    }
}

fn error_dto(k: TickErrorKind) -> TickErrorDto {
    match k {
        TickErrorKind::HotVolume => TickErrorDto::HotVolume,
        TickErrorKind::Index => TickErrorDto::Index,
        TickErrorKind::Plan => TickErrorDto::Plan,
        // Non-exhaustive: a kind added later is reported as `other`.
        _ => TickErrorDto::Other,
    }
}

pub(crate) fn storage_dto(s: &StorageSnapshot) -> StorageDto {
    StorageDto {
        hot: tier_dto(&s.hot),
        archive: archive_dto(s),
        unverified_total: s.unverified_total,
        quarantined_total: s.quarantined_total,
        last_tick: s.last_tick.map(Timestamp::as_unix_millis),
        last_error: s.last_error.map(error_dto),
        floor_breaches_total: s.floor_breaches_total,
    }
}

/// Per-tier usage against the floor, segment counts and the latest storage tick.
#[utoipa::path(
    get,
    path = "/api/v1/storage",
    responses(
        (status = 200, description = "Storage status", body = StorageDto),
        (status = 401, description = "Missing or invalid bearer token", body = ErrorBody),
        (status = 500, description = "The storage status is unavailable", body = ErrorBody)
    )
)]
pub(crate) async fn get_storage<T>(
    State(status): State<Arc<T>>,
) -> Result<Json<StorageDto>, StatusCode>
where
    T: StorageStatus + Send + Sync + 'static,
{
    let snapshot = status
        .snapshot()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(storage_dto(&snapshot)))
}
