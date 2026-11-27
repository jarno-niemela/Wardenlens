//! JSON error responses: `{"error": "<code>"}` and nothing else (no internal messages).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// Body of every error response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ErrorBody {
    /// Machine-readable error code.
    error: &'static str,
}

/// The stable error code for a status. Deliberately coarse: no detail about causes.
pub(crate) fn code_for(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        StatusCode::REQUEST_TIMEOUT => "request_timeout",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::RANGE_NOT_SATISFIABLE => "range_not_satisfiable",
        StatusCode::SERVICE_UNAVAILABLE => "unavailable",
        s if s.is_server_error() => "internal_error",
        _ => "bad_request",
    }
}

/// A JSON error response with the given status.
pub(crate) fn error_response(status: StatusCode) -> Response {
    (
        status,
        Json(ErrorBody {
            error: code_for(status),
        }),
    )
        .into_response()
}
