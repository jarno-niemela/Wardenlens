//! Request tracing: a bounded, redacted span and one fixed-size line per failure.
//!
//! Everything a client controls that reaches a log line is capped here: the path, the number
//! of headers and the length of each header name and value. A path segment that looks like
//! it carries a token (it contains `wl_`, also when percent-encoded) is replaced.

use std::fmt;
use std::time::Duration;

use axum::extract::Request;
use axum::http::HeaderMap;
use tower_http::LatencyUnit;
use tower_http::classify::{ServerErrorsAsFailures, ServerErrorsFailureClass, SharedClassifier};
use tower_http::trace::{DefaultOnBodyChunk, DefaultOnEos, DefaultOnResponse, TraceLayer};
use tracing::Span;

/// Longest path written to a log line, in bytes.
const MAX_PATH_BYTES: usize = 256;
/// Most headers written to a log line.
const MAX_HEADERS: usize = 32;
/// Longest header name written to a log line, in bytes.
const MAX_NAME_BYTES: usize = 64;
/// Longest header value written to a log line, in bytes.
const MAX_VALUE_BYTES: usize = 128;
/// What replaces a path segment that may carry a token.
const REDACTED_SEGMENT: &str = "<redacted>";

type OnRequest = fn(&Request, &Span);
type OnFailure = fn(ServerErrorsFailureClass, Duration, &Span);

type MakeSpan = fn(&Request) -> Span;
type Layer = TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    MakeSpan,
    OnRequest,
    DefaultOnResponse,
    DefaultOnBodyChunk,
    DefaultOnEos,
    OnFailure,
>;

/// The trace layer: span with method and redacted path, headers in the request event.
pub(crate) fn layer() -> Layer {
    let make_span: MakeSpan = make_span;
    let on_request: OnRequest = on_request;
    let on_failure: OnFailure = on_failure;
    TraceLayer::new_for_http()
        .make_span_with(make_span)
        .on_request(on_request)
        .on_response(DefaultOnResponse::new().latency_unit(LatencyUnit::Millis))
        .on_failure(on_failure)
}

fn make_span(req: &Request) -> Span {
    // Path only: a query string may carry a token someone put there by mistake.
    tracing::info_span!(
        "request",
        method = %req.method(),
        path = %redact_path(req.uri().path()),
    )
}

fn on_request(req: &Request, _span: &Span) {
    tracing::debug!(headers = ?HeaderSummary(req.headers()), "started processing request");
}

/// One fixed-size line per `5xx`: the span adds the method and the capped, redacted path.
/// No header value is logged here.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the signature is fixed by tower_http's OnFailure"
)]
fn on_failure(class: ServerErrorsFailureClass, latency: Duration, _span: &Span) {
    tracing::error!(%class, latency_ms = latency.as_millis(), "response failed");
}

/// `path` with token-looking segments replaced and the length capped.
pub(crate) fn redact_path(path: &str) -> String {
    let mut out = String::new();
    for (i, segment) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if looks_like_token(segment) {
            out.push_str(REDACTED_SEGMENT);
        } else {
            out.push_str(segment);
        }
        if out.len() > MAX_PATH_BYTES {
            break;
        }
    }
    truncate(&mut out, MAX_PATH_BYTES);
    out
}

/// Whether `segment`, percent-decoded, contains the token prefix `wl_` in any case.
fn looks_like_token(segment: &str) -> bool {
    let decoded = percent_decode(segment);
    decoded.windows(3).any(|w| w.eq_ignore_ascii_case(b"wl_"))
}

/// Lenient percent decoding: a malformed escape stays as it is.
fn percent_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut rest = s.as_bytes();
    while let Some((&b, tail)) = rest.split_first() {
        let escaped = match (b, tail) {
            (b'%', [h, l, after @ ..]) => hex(*h).zip(hex(*l)).map(|(h, l)| (h << 4 | l, after)),
            _ => None,
        };
        if let Some((byte, after)) = escaped {
            out.push(byte);
            rest = after;
        } else {
            out.push(b);
            rest = tail;
        }
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Cuts `s` to at most `max` bytes on a character boundary.
fn truncate(s: &mut String, max: usize) {
    if s.len() > max {
        s.truncate(s.floor_char_boundary(max));
    }
}

fn capped(bytes: &[u8], max: usize) -> String {
    let mut s = String::from_utf8_lossy(bytes.get(..max).unwrap_or(bytes)).into_owned();
    if bytes.len() > max {
        s.push_str("...");
    }
    s
}

/// `Debug` view of a header map: at most [`MAX_HEADERS`] entries, names and values cut to
/// fixed lengths, sensitive values shown as `Sensitive`.
pub(crate) struct HeaderSummary<'a>(pub(crate) &'a HeaderMap);

impl fmt::Debug for HeaderSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (name, value) in self.0.iter().take(MAX_HEADERS) {
            let name = capped(name.as_str().as_bytes(), MAX_NAME_BYTES);
            if value.is_sensitive() {
                map.entry(&name, &format_args!("Sensitive"));
            } else {
                map.entry(&name, &capped(value.as_bytes(), MAX_VALUE_BYTES));
            }
        }
        let more = self.0.len().saturating_sub(MAX_HEADERS);
        if more > 0 {
            map.entry(&"...", &format_args!("{more} more"));
        }
        map.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_segments_are_redacted_and_others_kept() {
        assert_eq!(redact_path("/api/v1/health"), "/api/v1/health");
        assert_eq!(
            redact_path("/api/v1/wl_abcdefgh_SECRET/x"),
            "/api/v1/<redacted>/x"
        );
    }

    #[test]
    fn redaction_table() {
        for (input, leaked) in [
            ("/wl_abcdefgh_s", "abcdefgh"),
            ("/WL_abcdefgh_s", "abcdefgh"),
            ("/%77l_abcdefgh_s", "abcdefgh"),
            ("/%57%4c%5f1234abcd", "1234abcd"),
            ("/Bearer%20wl_abcdefgh_s", "abcdefgh"),
            ("/x/wl_abcdefgh_s/y", "abcdefgh"),
            ("/a=wl_abcdefgh_s", "abcdefgh"),
        ] {
            let out = redact_path(input);
            assert!(!out.contains(leaked), "{input} -> {out}");
            assert!(out.contains(REDACTED_SEGMENT), "{input} -> {out}");
        }
    }

    #[test]
    fn path_is_length_capped_on_a_char_boundary() {
        let long = format!("/{}", "é".repeat(5000));
        assert!(redact_path(&long).len() <= MAX_PATH_BYTES);
        let many = "/a".repeat(50_000);
        assert!(redact_path(&many).len() <= MAX_PATH_BYTES);
    }

    #[test]
    fn header_summary_is_bounded() {
        let mut h = HeaderMap::new();
        for i in 0..1000 {
            h.append(
                axum::http::HeaderName::from_bytes(format!("x-h{i}").as_bytes()).unwrap(),
                "v".repeat(10_000).parse().unwrap(),
            );
        }
        let out = format!("{:?}", HeaderSummary(&h));
        assert!(
            out.len() < MAX_HEADERS * (MAX_NAME_BYTES + MAX_VALUE_BYTES + 32) + 64,
            "{}",
            out.len()
        );
        assert!(out.contains("968 more"), "{out}");
    }
}
