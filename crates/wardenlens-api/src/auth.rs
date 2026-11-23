//! Bearer-token authentication middleware.
//!
//! Every failure (missing, malformed, unknown, revoked, wrong secret) yields the same
//! `401` with `WWW-Authenticate: Bearer` and the same body. Only the `Authorization`
//! header is consulted; a token in the query string is never read.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use wardenlens_core::token_store::TokenStore;

use crate::error::error_response;
use crate::token::{MAX_TOKEN_LEN, Token};

/// Longest `Authorization` header value looked at, in bytes (SEC-2, ADR 0004).
const MAX_HEADER_LEN: usize = MAX_TOKEN_LEN;
/// One in this many authentication failures is logged, so a flood cannot fill the log.
const LOG_FAILURE_EVERY: u64 = 64;

/// Shared state of the middleware.
pub(crate) struct AuthState<S> {
    store: Arc<S>,
    failures: AtomicU64,
}

impl<S> AuthState<S> {
    pub(crate) fn new(store: Arc<S>) -> Self {
        Self {
            store,
            failures: AtomicU64::new(0),
        }
    }
}

/// Extracts the single bearer token from the headers; the scheme is case-insensitive.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() || value.len() > MAX_HEADER_LEN {
        return None;
    }
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

enum Failure {
    /// The caller is not authenticated.
    Unauthorized,
    /// The token store failed; reported as an internal error without detail.
    Store,
}

async fn check<S: TokenStore>(
    store: &S,
    headers: &HeaderMap,
    parsed_id: &mut Option<String>,
) -> Result<(), Failure> {
    let token = bearer_token(headers)
        .and_then(|t| Token::parse(t).ok())
        .ok_or(Failure::Unauthorized)?;
    *parsed_id = Some(token.id().to_string());
    let record = store.find(token.id()).await.map_err(|_| Failure::Store)?;
    if token.verify(record.as_ref()) {
        Ok(())
    } else {
        Err(Failure::Unauthorized)
    }
}

/// Rejects the request unless it carries a valid bearer token.
pub(crate) async fn require_token<S>(
    State(state): State<Arc<AuthState<S>>>,
    req: Request,
    next: Next,
) -> Response
where
    S: TokenStore + Send + Sync + 'static,
{
    let mut token_id = None;
    match check(state.store.as_ref(), req.headers(), &mut token_id).await {
        Ok(()) => next.run(req).await,
        Err(failure) => {
            let n = state.failures.fetch_add(1, Ordering::Relaxed);
            if n.checked_rem(LOG_FAILURE_EVERY) == Some(0) {
                let peer = req
                    .extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|c| c.0);
                tracing::warn!(?peer, ?token_id, "authentication failed (sampled)");
            }
            match failure {
                Failure::Unauthorized => {
                    let mut resp = error_response(StatusCode::UNAUTHORIZED);
                    resp.headers_mut()
                        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                    resp
                }
                Failure::Store => error_response(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }
}
