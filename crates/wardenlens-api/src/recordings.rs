//! Recordings routes (ADR 0004, ADR 0005 sections 5 and 7): `GET /api/v1/recordings` and
//! `GET /api/v1/recordings/{id}/file`.
//!
//! The listing goes through the core [`SegmentLister`] port and the download through the core
//! [`SegmentFiles`] port, both as generics (never `dyn`). The download calls
//! [`SegmentFiles::open_segment`] and nothing else: this module holds no path, root, directory
//! handle or `openat2`, derives no path, and never learns where the file is. The re-read after
//! `ENOENT` and the choice of tier live in the storage implementation.
//!
//! # Listing
//!
//! Query: `camera` (required, a camera id), `from` and `to` (RFC 3339, optional; both default to
//! an open end), `limit` (default 100; **0 or more than 1000 is a `400`**, never clamped), `cursor`
//! (opaque, from the previous page's `next_cursor`). `from > to` is `400`; `from == to` is an empty
//! page. A `+` in an RFC 3339 offset must be sent as `%2B` (a bare `+` is a space in a query).
//! A cursor longer than 256 bytes, or one the port refuses, is `400`. Times in the response are
//! UTC Unix milliseconds, like the other routes. The range selects segments that overlap it (see
//! [`wardenlens_core::storage::SegmentIndex::list`]).
//!
//! # Download
//!
//! `200` with `video/mp4`, `Content-Length` and `Accept-Ranges: bytes`, or, for a single satisfiable
//! `Range` (`a-b`, `a-` or `-n`), `206` with `Content-Range`. Rules:
//!
//! - An unsatisfiable range (start past the end, `-0`, any range on an empty file) is `416` with
//!   `Content-Range: bytes */len`. Digits past `u64` saturate, so they are unsatisfiable (or, as a
//!   suffix, the whole file).
//! - A **multi-range** request (a comma), a unit other than `bytes`, more than one `Range`
//!   header, or a syntactically invalid spec (`5-3`, `abc`, `-`) is **ignored**: the answer is the
//!   full `200` (RFC 9110 section 14.2 lets a server do this).
//! - The id is a canonical decimal (digits only, no sign, no leading zero, at most `i64::MAX`);
//!   anything else is `400`.
//! - Errors from the port: not found `404`, archive unavailable `503`, I/O `500`. At the download
//!   cap, `503` with `Retry-After`. Error bodies are the bare JSON error, with no path or OS text.
//!
//! # Streaming and limits (ADR 0004 section 9)
//!
//! The file is read in 64 KiB chunks on the blocking pool (`spawn_blocking`), never held in
//! memory. A pump task sends the chunks through a one-slot channel, so at most two chunks wait.
//! **A chunk that the client does not take within the idle timeout ends the download** (the pump
//! drops the handle and the body fails, so the client sees a truncated body, never a clean end).
//! That is the write timeout: the time the *client* leaves the response unread. A read that hangs
//! in the kernel cannot be interrupted and is not covered. At most [`MAX_DOWNLOADS`] downloads
//! run at once; each holds its permit until the pump ends. The open handle survives a move of the
//! segment to the other tier (POSIX semantics).

use std::io::{self, Read, Seek, SeekFrom};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE, RETRY_AFTER,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use http_body::{Body as HttpBody, Frame, SizeHint};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use utoipa::ToSchema;
use wardenlens_core::camera::CameraId;
use wardenlens_core::storage::{
    IndexedSegment, MAX_LIST_LIMIT, SegmentCursor, SegmentFiles, SegmentId, SegmentListError,
    SegmentLister, SegmentOpenError, Tier,
};
use wardenlens_core::time::Timestamp;

use crate::error::ErrorBody;
use crate::rfc3339;

/// Page size when `limit` is absent.
const DEFAULT_LIMIT: usize = 100;
/// Longest cursor accepted; the index issues far shorter ones (SEC-2).
const MAX_CURSOR_LEN: usize = 256;
/// Bytes read and sent at a time.
const CHUNK_BYTES: usize = 64 * 1024;
/// Downloads streaming at once.
pub(crate) const MAX_DOWNLOADS: usize = 8;
/// How long a finished chunk may wait for the client before the download is cut.
pub(crate) const DOWNLOAD_IDLE: Duration = Duration::from_secs(30);

/// What the recordings routes read from, and their download limits.
pub(crate) struct RecordingPorts<L, F> {
    pub(crate) lister: L,
    pub(crate) files: Arc<F>,
    pub(crate) downloads: Arc<Semaphore>,
    pub(crate) idle: Duration,
}

/// Query of the listing. Every field is text so that a bad value is a `400` of ours and not a
/// framework rejection; an unknown parameter is ignored and a repeated one is a `400`.
#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    camera: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
}

/// Tier of a segment.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TierDto {
    /// The fast volume.
    Hot,
    /// The archive volume.
    Archive,
    /// A tier this API version does not know.
    Other,
}

/// One recorded segment.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SegmentDto {
    /// The segment id; the file is at `/api/v1/recordings/{id}/file`.
    id: u64,
    camera: String,
    /// Start, in UTC Unix milliseconds.
    started_at: i64,
    /// End (`started_at + duration`), in UTC Unix milliseconds.
    ended_at: i64,
    /// Media duration in milliseconds.
    duration: u64,
    /// File size in bytes.
    bytes: u64,
    tier: TierDto,
}

/// One page of segments.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SegmentList {
    /// Ordered by start time, then id.
    segments: Vec<SegmentDto>,
    /// Pass it back as `cursor` for the next page; `null` on the last page.
    next_cursor: Option<String>,
}

fn segment_dto(s: &IndexedSegment) -> SegmentDto {
    SegmentDto {
        id: s.id.as_u64(),
        camera: s.record.camera.as_str().to_owned(),
        started_at: Timestamp::from(s.record.started_at_ms).as_unix_millis(),
        ended_at: s.record.ended_at_ms().as_unix_millis(),
        duration: s.record.duration_ms,
        bytes: s.record.bytes,
        tier: match s.tier {
            Tier::Hot => TierDto::Hot,
            Tier::Archive => TierDto::Archive,
            // Non-exhaustive: a tier added later is reported as `other`.
            _ => TierDto::Other,
        },
    }
}

/// `limit` as text: digits only, 1 to the page maximum.
fn parse_limit(text: Option<&str>) -> Option<usize> {
    let Some(text) = text else {
        return Some(DEFAULT_LIMIT);
    };
    if text.is_empty() || text.len() > 6 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: usize = text.parse().ok()?;
    (1..=MAX_LIST_LIMIT).contains(&n).then_some(n)
}

/// Lists recorded segments of a camera, optionally within a time range.
#[utoipa::path(
    get,
    path = "/api/v1/recordings",
    params(
        ("camera" = String, Query, description = "Camera id."),
        ("from" = Option<String>, Query, description = "RFC 3339 start of the range (inclusive); encode `+` as `%2B`."),
        ("to" = Option<String>, Query, description = "RFC 3339 end of the range (exclusive); not before `from`."),
        ("limit" = Option<u32>, Query, description = "Page size, 1 to 1000, default 100; anything else is 400."),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from a previous page.")
    ),
    responses(
        (status = 200, description = "A page of segments", body = SegmentList),
        (status = 400, description = "A malformed parameter", body = ErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ErrorBody),
        (status = 500, description = "The listing failed", body = ErrorBody)
    )
)]
pub(crate) async fn list_recordings<L, F>(
    State(ports): State<Arc<RecordingPorts<L, F>>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<SegmentList>, StatusCode>
where
    L: SegmentLister + Send + Sync + 'static,
    F: Send + Sync + 'static,
{
    let bad = StatusCode::BAD_REQUEST;
    let camera = CameraId::new(q.camera.as_deref().ok_or(bad)?).map_err(|_| bad)?;
    let from = match q.from.as_deref() {
        Some(t) => rfc3339::parse(t).ok_or(bad)?,
        None => Timestamp::from_unix_millis(i64::MIN),
    };
    let to = match q.to.as_deref() {
        Some(t) => rfc3339::parse(t).ok_or(bad)?,
        None => Timestamp::from_unix_millis(i64::MAX),
    };
    if from > to {
        return Err(bad);
    }
    let limit = parse_limit(q.limit.as_deref()).ok_or(bad)?;
    let cursor = match q.cursor {
        Some(c) if c.is_empty() || c.len() > MAX_CURSOR_LEN => return Err(bad),
        Some(c) => Some(SegmentCursor::from_token(c)),
        None => None,
    };
    let page = ports
        .lister
        .list(&camera, from, to, limit, cursor.as_ref())
        .await
        .map_err(|e| match e {
            SegmentListError::InvalidCursor => bad,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;
    Ok(Json(SegmentList {
        segments: page.items.iter().map(segment_dto).collect(),
        next_cursor: page.next.map(|c| c.as_token().to_owned()),
    }))
}

/// The segment id of the path: canonical decimal up to `i64::MAX`.
fn parse_id(text: &str) -> Option<SegmentId> {
    let canonical = !text.is_empty()
        && text.len() <= 19
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    let n: u64 = text.parse().ok().filter(|_| canonical)?;
    (n <= i64::MAX.unsigned_abs()).then_some(SegmentId::new(n))
}

/// What a `Range` header asks for, against a file of known length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RangeChoice {
    /// The whole file (no range, or one that is ignored).
    Full,
    /// Bytes `start..=end`, both inside the file.
    Slice { start: u64, end: u64 },
    /// A valid range that selects no byte.
    Unsatisfiable,
}

/// One side of a range spec.
enum Side {
    /// Nothing between the `=` or `-` and the next delimiter.
    Open,
    /// Digits, saturating at `u64::MAX`.
    At(u64),
}

/// `None` for anything that is neither empty nor all digits.
fn side(text: &str) -> Option<Side> {
    if text.is_empty() {
        return Some(Side::Open);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(Side::At(text.bytes().fold(0u64, |n, b| {
        n.saturating_mul(10)
            .saturating_add(u64::from(b.saturating_sub(b'0')))
    })))
}

/// Chooses the byte range for `len` from the request headers (rules in the module docs).
pub(crate) fn choose_range(headers: &HeaderMap, len: u64) -> RangeChoice {
    let mut values = headers.get_all(RANGE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return RangeChoice::Full;
    };
    let Ok(text) = value.to_str() else {
        return RangeChoice::Full;
    };
    let (Some(unit), Some(spec)) = (text.get(..6), text.get(6..)) else {
        return RangeChoice::Full;
    };
    if !unit.eq_ignore_ascii_case("bytes=") || spec.contains(',') {
        return RangeChoice::Full;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return RangeChoice::Full;
    };
    let (Some(first), Some(last)) = (side(first), side(last)) else {
        return RangeChoice::Full;
    };
    let last_byte = len.saturating_sub(1);
    match (first, last) {
        (Side::At(a), Side::At(b)) if a > b => RangeChoice::Full,
        (Side::At(a), _) if a >= len => RangeChoice::Unsatisfiable,
        (Side::At(start), Side::At(b)) => RangeChoice::Slice {
            start,
            end: b.min(last_byte),
        },
        (Side::At(start), Side::Open) => RangeChoice::Slice {
            start,
            end: last_byte,
        },
        (Side::Open, Side::At(0)) => RangeChoice::Unsatisfiable,
        (Side::Open, Side::At(_)) if len == 0 => RangeChoice::Unsatisfiable,
        (Side::Open, Side::At(n)) => RangeChoice::Slice {
            start: len.saturating_sub(n),
            end: last_byte,
        },
        (Side::Open, Side::Open) => RangeChoice::Full,
    }
}

/// A response body fed by the pump task. It knows how many bytes it must deliver: a channel that
/// closes early is an error, so a cut download is never mistaken for a complete one.
struct PumpBody {
    rx: mpsc::Receiver<Bytes>,
    remaining: u64,
}

impl HttpBody for PumpBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(chunk)) => {
                let n = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                self.remaining = self.remaining.saturating_sub(n);
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Poll::Ready(None) => {
                self.remaining = 0;
                Poll::Ready(Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

/// Reads up to `want` bytes; empty at end of file.
fn read_chunk<H: Read>(handle: &mut H, want: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        let Some(rest) = buf.get_mut(filled..) else {
            break;
        };
        match handle.read(rest) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Reads `len` bytes from `start` and feeds them to `tx`. Ends, dropping the handle and the
/// permit, when the bytes are sent, the client goes away, a chunk waits longer than `idle`, or a
/// read fails or comes up short. The body notices the early end by its byte count.
async fn pump<H>(
    mut handle: H,
    start: u64,
    len: u64,
    tx: mpsc::Sender<Bytes>,
    idle: Duration,
    _permit: OwnedSemaphorePermit,
) where
    H: Read + Seek + Send + 'static,
{
    let mut remaining = len;
    let mut position = Some(start).filter(|s| *s > 0);
    while remaining > 0 {
        let want = usize::try_from(remaining).map_or(CHUNK_BYTES, |r| r.min(CHUNK_BYTES));
        let seek = position.take();
        let read = tokio::task::spawn_blocking(move || {
            let result = match seek {
                Some(at) => handle.seek(SeekFrom::Start(at)).map(drop),
                None => Ok(()),
            }
            .and_then(|()| read_chunk(&mut handle, want));
            (handle, result)
        })
        .await;
        let Ok((h, Ok(chunk))) = read else { return };
        handle = h;
        let Ok(n) = u64::try_from(chunk.len()) else {
            return;
        };
        if n == 0 || n > remaining {
            return;
        }
        remaining = remaining.saturating_sub(n);
        match tokio::time::timeout(idle, tx.send(Bytes::from(chunk))).await {
            Ok(Ok(())) => {}
            _ => return,
        }
    }
}

fn header_value(n: u64) -> Option<HeaderValue> {
    HeaderValue::from_str(&n.to_string()).ok()
}

/// Streams a recorded segment (`video/mp4`), whole or as one byte range.
#[utoipa::path(
    get,
    path = "/api/v1/recordings/{id}/file",
    params(("id" = u64, Path, description = "Segment id.")),
    responses(
        (status = 200, description = "The whole segment", content_type = "video/mp4", body = Vec<u8>),
        (status = 206, description = "One byte range", content_type = "video/mp4", body = Vec<u8>),
        (status = 400, description = "A malformed id", body = ErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ErrorBody),
        (status = 404, description = "No such segment", body = ErrorBody),
        (status = 416, description = "The range selects no byte", body = ErrorBody),
        (status = 500, description = "The segment could not be read", body = ErrorBody),
        (status = 503, description = "The archive is unavailable, or too many downloads are running", body = ErrorBody)
    )
)]
pub(crate) async fn download_segment<L, F>(
    State(ports): State<Arc<RecordingPorts<L, F>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    L: Send + Sync + 'static,
    F: SegmentFiles + Send + Sync + 'static,
    F::Handle: 'static,
{
    let Some(id) = parse_id(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(permit) = Arc::clone(&ports.downloads).try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, [(RETRY_AFTER, "1")]).into_response();
    };
    // `open_segment` does file-system calls, so it runs on the blocking pool.
    let files = Arc::clone(&ports.files);
    let opened = match tokio::task::spawn_blocking(move || files.open_segment(id)).await {
        Ok(Ok(opened)) => opened,
        Ok(Err(SegmentOpenError::NotFound)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(SegmentOpenError::ArchiveUnavailable)) => {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        // `Io`, a variant added later, or a panicked task: the same bare 500, no detail.
        Ok(Err(_)) | Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let len = opened.len();
    let (status, start, count, content_range) = match choose_range(&headers, len) {
        RangeChoice::Full => (StatusCode::OK, 0, len, None),
        RangeChoice::Slice { start, end } => (
            StatusCode::PARTIAL_CONTENT,
            start,
            end.saturating_sub(start).saturating_add(1),
            HeaderValue::from_str(&format!("bytes {start}-{end}/{len}")).ok(),
        ),
        RangeChoice::Unsatisfiable => {
            return match HeaderValue::from_str(&format!("bytes */{len}")) {
                Ok(v) => (StatusCode::RANGE_NOT_SATISFIABLE, [(CONTENT_RANGE, v)]).into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
        }
    };
    let Some(length) = header_value(count) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let body = if count == 0 {
        Body::empty()
    } else {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(pump(
            opened.into_handle(),
            start,
            count,
            tx,
            ports.idle,
            permit,
        ));
        Body::new(PumpBody {
            rx,
            remaining: count,
        })
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("video/mp4"));
    h.insert(CONTENT_LENGTH, length);
    h.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if let Some(v) = content_range {
        h.insert(CONTENT_RANGE, v);
    }
    resp
}
