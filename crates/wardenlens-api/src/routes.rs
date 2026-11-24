//! Route handlers. Each handler carries its `#[utoipa::path]`, so the `OpenAPI` document
//! is derived from the same definitions that serve requests.

use std::sync::Arc;

use axum::Json;
use axum::extract::Extension;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa::openapi::OpenApi;

/// Response body of the health endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Health {
    /// Always `ok` when the service answers.
    status: &'static str,
}

/// Liveness probe. Unauthenticated; carries no version, build or camera data.
#[utoipa::path(
    get,
    path = "/api/v1/health",
    responses((status = 200, description = "Service is up", body = Health)),
    security(())
)]
pub(crate) async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

/// The `OpenAPI` document of this API. Requires a bearer token.
#[utoipa::path(
    get,
    path = "/api/v1/openapi.json",
    responses(
        (status = 200, description = "OpenAPI 3 document"),
        (status = 401, description = "Missing or invalid bearer token", body = crate::error::ErrorBody)
    )
)]
pub(crate) async fn openapi_json(Extension(doc): Extension<Arc<OpenApi>>) -> Json<OpenApi> {
    Json(OpenApi::clone(&doc))
}
