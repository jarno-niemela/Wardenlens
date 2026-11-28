//! Read-only camera routes (ADR 0004): `GET /api/v1/cameras` and `GET /api/v1/cameras/{id}`.
//!
//! The handlers take the two core read ports as generics (never `dyn`). The response types
//! below are the whole wire format: they have no credential field, not even a placeholder, and
//! they are built field by field from the core view, so adding a field to `Camera` cannot leak
//! it by accident. Remote error text never reaches this layer; only a failure kind does.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;
use wardenlens_core::camera::{
    Camera, CameraDirectory, CameraId, CameraStatus, LinkState, LinkStatus, RtspPath,
};
use wardenlens_core::connection::FailureKind;

use crate::error::ErrorBody;

/// The ports the camera routes read from.
pub(crate) struct CameraPorts<D, C> {
    pub(crate) directory: D,
    pub(crate) status: C,
}

/// Connection state of a camera.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ConnectionStateDto {
    /// Connected and receiving.
    Streaming,
    /// A connection attempt is in flight.
    Connecting,
    /// Waiting to retry after a failure.
    Backoff,
    /// The retry budget is spent; retries continue in the background.
    Degraded,
}

/// Live connection state with the time it was entered.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ConnectionDto {
    state: ConnectionStateDto,
    /// When the camera entered `state`, in UTC Unix milliseconds.
    since: i64,
    /// Kind of the most recent failure; present only while `state` is `degraded`. Never
    /// remote error text.
    #[serde(skip_serializing_if = "Option::is_none")]
    error_kind: Option<FailureKindDto>,
    /// The most recent failed connection attempt, kept after the camera recovers; absent until
    /// one fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_failure: Option<LastFailureDto>,
    /// Failures since the connection was last stable; zero while it streams stably.
    attempts: u32,
}

/// Kind and time of a failed connection attempt. Never remote error text.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct LastFailureDto {
    kind: FailureKindDto,
    /// When the failure was handled, in UTC Unix milliseconds.
    at: i64,
}

/// Why the last connection attempt failed.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FailureKindDto {
    /// Connect or read timed out.
    Timeout,
    /// The peer refused or reset the connection.
    Refused,
    /// Credentials were rejected.
    Auth,
    /// The peer spoke something unexpected.
    Protocol,
    /// Anything else.
    Other,
}

/// Catalogue model of a camera.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ModelDto {
    vendor: String,
    model: String,
}

/// RTSP paths, structurally redacted, whatever a parameter is called. In the query (after
/// the first `?`) every `name=value` is cut at the next `&` and the value replaced by `***`;
/// in the path part, the rest of any `/` segment after an `=` is replaced by `***`. Names and
/// plain segments are kept; the real path stays inside the server.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct StreamsDto {
    main: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
}

/// One camera. Carries no credential of any kind. `Debug` hides the host, name and paths.
#[derive(Serialize, ToSchema)]
pub(crate) struct CameraDto {
    id: String,
    display_name: String,
    model: ModelDto,
    host: String,
    streams: StreamsDto,
    /// `null` when no connection is supervised for the camera yet.
    connection: Option<ConnectionDto>,
}

impl std::fmt::Debug for CameraDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CameraDto")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Response of the list endpoint.
#[derive(Serialize, ToSchema)]
pub(crate) struct CameraList {
    cameras: Vec<CameraDto>,
}

impl std::fmt::Debug for CameraList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CameraList")
            .field("cameras", &self.cameras.len())
            .finish()
    }
}

fn failure_kind_dto(kind: FailureKind) -> FailureKindDto {
    match kind {
        FailureKind::Timeout => FailureKindDto::Timeout,
        FailureKind::Refused => FailureKindDto::Refused,
        FailureKind::Auth => FailureKindDto::Auth,
        FailureKind::Protocol => FailureKindDto::Protocol,
        // `FailureKind` is non-exhaustive: a kind added later is reported as `other`.
        _ => FailureKindDto::Other,
    }
}

fn connection_dto(status: LinkStatus) -> ConnectionDto {
    let (state, error_kind) = match status.state {
        LinkState::Streaming => (ConnectionStateDto::Streaming, None),
        LinkState::Connecting => (ConnectionStateDto::Connecting, None),
        LinkState::Backoff => (ConnectionStateDto::Backoff, None),
        LinkState::Degraded(kind) => (ConnectionStateDto::Degraded, Some(failure_kind_dto(kind))),
    };
    ConnectionDto {
        state,
        since: status.since.as_unix_millis(),
        error_kind,
        last_failure: status.last_failure.map(|f| LastFailureDto {
            kind: failure_kind_dto(f.kind),
            at: f.at.as_unix_millis(),
        }),
        attempts: status.attempts,
    }
}

pub(crate) fn camera_dto(camera: &Camera, status: Option<LinkStatus>) -> CameraDto {
    CameraDto {
        id: camera.id().as_str().to_owned(),
        display_name: camera.name().expose().to_owned(),
        model: ModelDto {
            vendor: camera.model().vendor().to_owned(),
            model: camera.model().model().to_owned(),
        },
        host: camera.host().expose(),
        streams: StreamsDto {
            main: camera.streams().main.redacted_for_display(),
            sub: camera
                .streams()
                .sub
                .as_ref()
                .map(RtspPath::redacted_for_display),
        },
        connection: status.map(connection_dto),
    }
}

/// Lists every camera with its live connection state.
#[utoipa::path(
    get,
    path = "/api/v1/cameras",
    responses(
        (status = 200, description = "All cameras", body = CameraList),
        (status = 401, description = "Missing or invalid bearer token", body = ErrorBody),
        (status = 500, description = "The camera directory is unavailable", body = ErrorBody)
    )
)]
pub(crate) async fn list_cameras<D, C>(
    State(ports): State<Arc<CameraPorts<D, C>>>,
) -> Result<Json<CameraList>, StatusCode>
where
    D: CameraDirectory + Send + Sync + 'static,
    C: CameraStatus + Send + Sync + 'static,
{
    let cameras = ports
        .directory
        .list()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::with_capacity(cameras.len());
    for camera in &cameras {
        let status = ports.status.status(camera.id()).await;
        out.push(camera_dto(camera, status));
    }
    Ok(Json(CameraList { cameras: out }))
}

/// One camera with its live connection state.
#[utoipa::path(
    get,
    path = "/api/v1/cameras/{id}",
    params(("id" = String, Path, description = "Camera id: a lowercase slug of at most 32 characters")),
    responses(
        (status = 200, description = "The camera", body = CameraDto),
        (status = 400, description = "The id is not a valid camera id", body = ErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ErrorBody),
        (status = 404, description = "No such camera", body = ErrorBody),
        (status = 500, description = "The camera directory is unavailable", body = ErrorBody)
    )
)]
pub(crate) async fn get_camera<D, C>(
    State(ports): State<Arc<CameraPorts<D, C>>>,
    Path(id): Path<String>,
) -> Result<Json<CameraDto>, StatusCode>
where
    D: CameraDirectory + Send + Sync + 'static,
    C: CameraStatus + Send + Sync + 'static,
{
    let id = CameraId::new(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let camera = ports
        .directory
        .get(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let status = ports.status.status(camera.id()).await;
    Ok(Json(camera_dto(&camera, status)))
}
