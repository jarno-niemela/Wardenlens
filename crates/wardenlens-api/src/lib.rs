//! HTTP API for Wardenlens: the axum router, bearer-token authentication and the
//! generated `OpenAPI` document (ADR 0004).
//!
//! This crate builds a [`axum::Router`] and does not bind sockets or serve it; the
//! composition root does that. It talks to storage only through the
//! [`TokenStore`], [`CameraDirectory`], [`CameraStatus`], [`StorageStatus`], [`SegmentLister`] and
//! [`SegmentFiles`] traits from `wardenlens-core`,
//! taken as generics.
//!
//! # Middleware order
//!
//! Outermost first:
//!
//! The layers wrap the whole router as **one service**, so the concurrency cap is global
//! (one semaphore for every route, method and unknown path), not per route.
//!
//! 1. `SetSensitiveRequestHeadersLayer` marks `Authorization`, `Cookie` and
//!    `Proxy-Authorization` sensitive before anything can log them, so it must wrap the
//!    trace layer.
//! 2. `TraceLayer` logs requests and responses (headers redacted by 1). The span records
//!    the method and the path, never the query string; a path segment containing `wl_`
//!    (the token prefix) is redacted and the path is length-capped. The headers are logged
//!    once, in the request event, capped in count and size (see the `trace` module), so the
//!    response and failure events carry no header values. A `5xx` logs one fixed-size
//!    `response failed` line.
//! 3. JSON error mapping turns bodyless error responses into `{"error": code}`.
//! 4. `ConcurrencyLimitLayer` caps in-flight requests. It takes its permit in `poll_ready`.
//! 5. `TimeoutLayer` answers `408` when a handler runs too long. Its timer starts at
//!    `call`, which comes after `poll_ready` has returned, so time spent waiting for a
//!    slot is not charged to the deadline whichever of 4 and 5 is outer. Only waiting
//!    that happens after `call` (inside a handler) counts against it.
//! 6. `RequestBodyLimitLayer` rejects bodies over 64 KiB with `413`.
//!
//! Neither limit covers a streamed response body: the recordings download has its own idle
//! timeout and download cap (see the `recordings` module). The connection cap and header
//! read timeout belong to the server, not to this router.

mod auth;
mod cameras;
mod error;
mod recordings;
mod rfc3339;
mod routes;
mod storage;
pub mod token;
mod trace;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Extension, Request};
use axum::http::StatusCode;
use axum::http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, PROXY_AUTHORIZATION,
};
use axum::middleware::{self, Next};
use axum::response::Response;
use tokio::sync::Semaphore;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use wardenlens_core::camera::{CameraDirectory, CameraStatus};
use wardenlens_core::storage::{SegmentFiles, SegmentLister, StorageStatus};
use wardenlens_core::token_store::TokenStore;

use crate::auth::{AuthState, require_token};
use crate::cameras::CameraPorts;
use crate::error::error_response;
use crate::recordings::{DOWNLOAD_IDLE, MAX_DOWNLOADS, RecordingPorts};

/// Largest accepted request body: 64 KiB (Phase 1 has no upload routes).
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Requests allowed in flight at once.
const MAX_IN_FLIGHT: usize = 64;
/// Deadline for a handler to produce its response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Name of the bearer security scheme in the `OpenAPI` document.
const BEARER_SCHEME: &str = "bearer";

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            BEARER_SCHEME,
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "Wardenlens API", description = "Read-only API of the Wardenlens NVR."),
    modifiers(&SecurityAddon),
    security(("bearer" = []))
)]
struct ApiDoc;

/// Request-level limits; a struct so tests can shrink them.
#[derive(Clone, Copy)]
struct Limits {
    max_body_bytes: usize,
    max_in_flight: usize,
    timeout: Duration,
    /// How long a streamed chunk may wait for the client before the download is cut.
    download_idle: Duration,
    /// Downloads streaming at once.
    max_downloads: usize,
}

const LIMITS: Limits = Limits {
    max_body_bytes: MAX_BODY_BYTES,
    max_in_flight: MAX_IN_FLIGHT,
    timeout: REQUEST_TIMEOUT,
    download_idle: DOWNLOAD_IDLE,
    max_downloads: MAX_DOWNLOADS,
};

/// Replaces non-JSON error responses (from the limit layers, `404`, `405`) with the
/// JSON error body, keeping the status and every header (multi-valued ones included)
/// except `Content-Type` and `Content-Length`.
async fn json_errors(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let status = resp.status();
    let is_json = resp
        .headers()
        .get(CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"application/json"));
    if (status.is_client_error() || status.is_server_error()) && !is_json {
        let mut headers = std::mem::take(resp.headers_mut());
        headers.remove(CONTENT_TYPE);
        headers.remove(CONTENT_LENGTH);
        let mut replacement = error_response(status);
        for (name, value) in replacement.headers() {
            headers.insert(name.clone(), value.clone());
        }
        *replacement.headers_mut() = headers;
        return replacement;
    }
    resp
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Wraps `router` in the documented middleware stack.
///
/// The layers are applied to the finished router as one service, not with
/// `Router::layer`: that would wrap every route and the fallback separately, each with
/// its own concurrency semaphore, and the cap would be per route instead of global.
fn with_layers(router: Router, limits: Limits) -> Router {
    let service = ServiceBuilder::new()
        .layer(SetSensitiveRequestHeadersLayer::new([
            AUTHORIZATION,
            COOKIE,
            PROXY_AUTHORIZATION,
        ]))
        .layer(trace::layer())
        .layer(middleware::from_fn(json_errors))
        .layer(ConcurrencyLimitLayer::new(limits.max_in_flight))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits.timeout,
        ))
        .layer(RequestBodyLimitLayer::new(limits.max_body_bytes))
        .service(router);
    Router::new().fallback_service(service)
}

fn build<S, D, C, T, R, F>(
    store: Arc<S>,
    directory: D,
    status: C,
    storage: T,
    recordings: R,
    files: F,
    limits: Limits,
) -> Router
where
    S: TokenStore + Send + Sync + 'static,
    D: CameraDirectory + Send + Sync + 'static,
    C: CameraStatus + Send + Sync + 'static,
    T: StorageStatus + Send + Sync + 'static,
    R: SegmentLister + Send + Sync + 'static,
    F: SegmentFiles + Send + Sync + 'static,
    F::Handle: 'static,
{
    let ports = Arc::new(CameraPorts { directory, status });
    let auth = Arc::new(AuthState::new(store));
    // Everything except health, unknown paths included, requires a token, so a
    // caller without one learns nothing about which routes exist.
    // `build` takes only `OpenApiRouter` fragments (`routes!` with `#[utoipa::path]`), so
    // every route is documented by construction.
    // The handlers are generic over the ports, which `routes!` cannot spell with a turbofish,
    // so the ports are the router state and the handler types are inferred from it.
    let cameras = OpenApiRouter::<Arc<CameraPorts<D, C>>>::new()
        .routes(routes!(cameras::list_cameras))
        .routes(routes!(cameras::get_camera))
        .with_state(ports);
    let storage = OpenApiRouter::<Arc<T>>::new()
        .routes(routes!(storage::get_storage))
        .with_state(Arc::new(storage));
    let recordings = OpenApiRouter::<Arc<RecordingPorts<R, F>>>::new()
        .routes(routes!(recordings::list_recordings))
        .routes(routes!(recordings::download_segment))
        .with_state(Arc::new(RecordingPorts {
            lister: recordings,
            files: Arc::new(files),
            downloads: Arc::new(Semaphore::new(limits.max_downloads)),
            idle: limits.download_idle,
        }));
    let protected = OpenApiRouter::new()
        .merge(cameras)
        .merge(storage)
        .merge(recordings)
        .routes(routes!(routes::openapi_json))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(auth, require_token::<S>));
    let public = OpenApiRouter::with_openapi(ApiDoc::openapi()).routes(routes!(routes::health));
    let (router, doc) = public.merge(protected).split_for_parts();
    // Known limitation: the openapi handler needs the final document, which only exists
    // after the split, hence the extension layer.
    with_layers(router.layer(Extension(Arc::new(doc))), limits)
}

/// Builds the API router with authentication and request limits applied.
///
/// `GET /api/v1/health` is open; every other route, and any unknown path, needs
/// `Authorization: Bearer <token>` checked against `store`. The camera routes read
/// `directory` and `status`, the storage route reads `storage`, the recordings list reads
/// `recordings` and the download opens segments through `files` only; the API never sees a
/// credential, a vault, a path or a volume root.
pub fn router<S, D, C, T, R, F>(
    store: Arc<S>,
    directory: D,
    status: C,
    storage: T,
    recordings: R,
    files: F,
) -> Router
where
    S: TokenStore + Send + Sync + 'static,
    D: CameraDirectory + Send + Sync + 'static,
    C: CameraStatus + Send + Sync + 'static,
    T: StorageStatus + Send + Sync + 'static,
    R: SegmentLister + Send + Sync + 'static,
    F: SegmentFiles + Send + Sync + 'static,
    F::Handle: 'static,
{
    build(store, directory, status, storage, recordings, files, LIMITS)
}

#[cfg(test)]
mod tests;
