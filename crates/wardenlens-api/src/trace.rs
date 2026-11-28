//! Request tracing: a bounded, redacted span and one fixed-size line per failure.
//!
//! Everything a client controls that reaches a log line is capped here, in rendered bytes:
//! the method (a standard one, else `OTHER`), the path (256), the number of headers (32)
//! and each header name (64) and value (128, escapes included). A path segment or a header
//! value that looks like it carries a token (it contains `wl_`, case-insensitive, also
//! when percent-encoded) is replaced by a fixed word, whatever the header is called. The
//! error text of a failed response is never logged.

use std::fmt;
use std::time::Duration;

use axum::extract::Request;
use axum::http::{HeaderMap, Method};
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
const OTHER_METHOD: &str = "OTHER";
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
        method = method_label(req.method()),
        path = %redact_path(req.uri().path()),
    )
}

/// The method as logged: a standard one, else `OTHER` (extension methods are client-chosen
/// and unbounded).
fn method_label(method: &Method) -> &'static str {
    [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::HEAD,
        Method::OPTIONS,
        Method::CONNECT,
        Method::PATCH,
        Method::TRACE,
    ]
    .iter()
    .find(|m| *m == method)
    .map_or(OTHER_METHOD, Method::as_str)
}

fn on_request(req: &Request, _span: &Span) {
    tracing::debug!(headers = ?HeaderSummary(req.headers()), "started processing request");
}

/// One fixed-size line per `5xx`: the span adds the method and the capped, redacted path.
/// No header value and no error text is logged here.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the signature is fixed by tower_http's OnFailure"
)]
fn on_failure(class: ServerErrorsFailureClass, latency: Duration, _span: &Span) {
    let status = match class {
        ServerErrorsFailureClass::StatusCode(code) => code.as_u16(),
        ServerErrorsFailureClass::Error(_) => 0,
    };
    tracing::error!(status, latency_ms = latency.as_millis(), "response failed");
}

/// `path` with token-looking segments replaced and the length capped.
pub(crate) fn redact_path(path: &str) -> String {
    let mut out = String::new();
    for (i, segment) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if looks_like_token(segment.as_bytes()) {
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

/// Whether `text`, percent-decoded, contains the token prefix `wl_` in any case.
fn looks_like_token(text: &[u8]) -> bool {
    let decoded = percent_decode(text);
    decoded.windows(3).any(|w| w.eq_ignore_ascii_case(b"wl_"))
}

/// Lenient percent decoding: a malformed escape stays as it is.
fn percent_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut rest = s;
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

/// A header name cut to [`MAX_NAME_BYTES`] (names are ASCII by construction).
fn capped_name(name: &str) -> String {
    let mut s = name.to_owned();
    if s.len() > MAX_NAME_BYTES {
        truncate(&mut s, MAX_NAME_BYTES);
        s.push_str("...");
    }
    s
}

/// A header value rendered in at most [`MAX_VALUE_BYTES`] bytes (plus a `...` marker):
/// printable ASCII as is, everything else as `?`, `"` and `\` as `_`, so the output length
/// equals the input length and nothing needs escaping.
fn capped_value(value: &[u8]) -> String {
    let mut s: String = value
        .iter()
        .take(MAX_VALUE_BYTES)
        .map(|&b| match b {
            b'"' | b'\\' => '_',
            0x20..=0x7e => char::from(b),
            _ => '?',
        })
        .collect();
    if value.len() > MAX_VALUE_BYTES {
        s.push_str("...");
    }
    s
}

/// Prints its text as is, so a pre-rendered value is not quoted again.
struct Plain(String);

impl fmt::Debug for Plain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `Debug` view of a header map: at most [`MAX_HEADERS`] entries, names and values cut to
/// fixed lengths. A value is shown as `Sensitive` when the header is marked sensitive or
/// the value looks like it carries a token, whatever the header is called.
pub(crate) struct HeaderSummary<'a>(pub(crate) &'a HeaderMap);

impl fmt::Debug for HeaderSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (name, value) in self.0.iter().take(MAX_HEADERS) {
            let name = capped_name(name.as_str());
            if value.is_sensitive() || looks_like_token(value.as_bytes()) {
                map.entry(&name, &Plain("Sensitive".to_owned()));
            } else {
                map.entry(
                    &name,
                    &Plain(format!("\"{}\"", capped_value(value.as_bytes()))),
                );
            }
        }
        let more = self.0.len().saturating_sub(MAX_HEADERS);
        if more > 0 {
            map.entry(&"...", &Plain(format!("{more} more")));
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

    fn summary(h: &HeaderMap) -> String {
        format!("{:?}", HeaderSummary(h))
    }

    #[test]
    fn token_looking_values_are_hidden_in_any_header() {
        for (name, value) in [
            ("x-api-key", "wl_abcdefgh_SECRETSECRET"),
            ("x-auth-token", "Bearer wl_abcdefgh_SECRETSECRET"),
            (
                "referer",
                "https://h/ui?access_token=wl_abcdefgh_SECRETSECRET",
            ),
            ("x-a", "WL_abcdefgh_SECRETSECRET"),
            ("x-b", "%77l_abcdefgh_SECRETSECRET"),
            ("x-c", "a=1; k=w%6C%5Fabcdefgh_SECRETSECRET"),
            ("x-d", "https://h/?t%3Dwl%5Fabcdefgh_SECRETSECRET"),
        ] {
            let mut h = HeaderMap::new();
            h.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
            let out = summary(&h);
            assert!(
                !out.contains("SECRET") && !out.contains("abcdefgh"),
                "{name}: {out}"
            );
            assert!(out.contains("Sensitive"), "{name}: {out}");
        }
        let mut h = HeaderMap::new();
        h.insert("x-ok", "plain".parse().unwrap());
        assert!(summary(&h).contains("\"plain\""));
    }

    #[test]
    fn method_is_standard_or_other() {
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::PATCH), "PATCH");
        let long = Method::from_bytes("M".repeat(5000).as_bytes()).unwrap();
        assert_eq!(method_label(&long), "OTHER");
        assert_eq!(
            method_label(&Method::from_bytes(b"PROPFIND").unwrap()),
            "OTHER"
        );
    }

    fn one(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        h
    }

    #[test]
    fn boundary_rows() {
        // 128 / 129-byte values.
        assert!(
            summary(&one("x-a", &"v".repeat(128))).contains(&format!("\"{}\"", "v".repeat(128)))
        );
        let over = summary(&one("x-a", &"v".repeat(129)));
        assert!(
            over.contains(&format!("\"{}...\"", "v".repeat(128))),
            "{over}"
        );
        // 64 / 65-byte names.
        let n64 = "n".repeat(64);
        assert!(summary(&one(&n64, "v")).contains(&format!("\"{n64}\"")));
        let n65 = "n".repeat(65);
        assert!(summary(&one(&n65, "v")).contains(&format!("\"{n64}...\"")));
        // 32 / 33 headers.
        let many = |n: usize| {
            let mut h = HeaderMap::new();
            for i in 0..n {
                h.insert(
                    axum::http::HeaderName::from_bytes(format!("x-{i}").as_bytes()).unwrap(),
                    "v".parse().unwrap(),
                );
            }
            summary(&h)
        };
        assert!(!many(32).contains("more"));
        assert!(many(33).contains("1 more"));
        // 256 / 257-byte paths.
        let p = |n: usize| format!("/{}", "a".repeat(n - 1));
        assert_eq!(redact_path(&p(255)).len(), 255);
        assert_eq!(redact_path(&p(256)).len(), 256);
        assert_eq!(redact_path(&p(257)).len(), 256);
    }
}
