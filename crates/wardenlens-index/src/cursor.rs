//! The opaque listing cursor: lower-case hex of `v1:<started_at_ms>:<id>:<camera>`.
//!
//! Decoding is a pass-list: the text must be exactly what [`encode`] produces for the values it
//! contains (canonical hex, canonical numbers, a valid camera id), so a hand-edited or foreign
//! cursor is refused rather than interpreted. The camera is part of the cursor and must equal the
//! camera being listed, so a cursor can never move a listing to another camera.

use std::fmt::Write as _;

use wardenlens_core::camera::CameraId;
use wardenlens_core::storage::SegmentCursor;
use wardenlens_core::time::UnixMs;

use crate::error::{CursorFault, IndexError};

/// Longest cursor text accepted: 2 hex digits for every byte of the longest payload
/// (`v1:` + 20 + `:` + 20 + `:` + 32) with room to spare.
const MAX_TOKEN_LEN: usize = 192;

/// Where a listing resumes: after the row `(started_at_ms, id)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Position {
    pub(crate) started_at_ms: i64,
    pub(crate) id: i64,
}

pub(crate) fn encode(camera: &CameraId, position: Position) -> SegmentCursor {
    let payload = format!(
        "v1:{}:{}:{}",
        position.started_at_ms,
        position.id,
        camera.as_str()
    );
    let mut token = String::with_capacity(payload.len().saturating_mul(2));
    for b in payload.bytes() {
        // ERR-4: writing to a `String` cannot fail.
        let _ = write!(token, "{b:02x}");
    }
    SegmentCursor::from_token(token)
}

fn unhex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.saturating_sub(b'0')),
        b'a'..=b'f' => Some(c.saturating_sub(b'a').saturating_add(10)),
        _ => None,
    }
}

fn malformed() -> IndexError {
    IndexError::InvalidCursor(CursorFault::Malformed)
}

/// Decodes `cursor` for a listing of `camera`.
pub(crate) fn decode(camera: &CameraId, cursor: &SegmentCursor) -> Result<Position, IndexError> {
    let token = cursor.as_token().as_bytes();
    if token.len() > MAX_TOKEN_LEN {
        return Err(IndexError::InvalidCursor(CursorFault::TooLong));
    }
    if !token.len().is_multiple_of(2) {
        return Err(malformed());
    }
    let mut payload = Vec::with_capacity(token.len() / 2);
    for pair in token.as_chunks::<2>().0 {
        let (Some(hi), Some(lo)) = (
            pair.first().and_then(|c| unhex(*c)),
            pair.get(1).and_then(|c| unhex(*c)),
        ) else {
            return Err(malformed());
        };
        payload.push(hi << 4 | lo);
    }
    let text = std::str::from_utf8(&payload).map_err(|_| malformed())?;
    let mut parts = text.splitn(4, ':');
    let (Some("v1"), Some(started), Some(id), Some(cursor_camera)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed());
    };
    let started: i64 = started.parse().map_err(|_| malformed())?;
    let id: i64 = id.parse().map_err(|_| malformed())?;
    if UnixMs::new(started).is_err() || id < 1 {
        return Err(malformed());
    }
    if CameraId::new(cursor_camera).is_err() {
        return Err(malformed());
    }
    let position = Position {
        started_at_ms: started,
        id,
    };
    // Canonical form: re-encoding gives back the same text (rejects `+5`, leading zeros, upper
    // case hex, anything else that parses to the same numbers).
    let parsed_camera = CameraId::new(cursor_camera).map_err(|_| malformed())?;
    if encode(&parsed_camera, position).as_token().as_bytes() != token {
        return Err(malformed());
    }
    if parsed_camera != *camera {
        return Err(IndexError::InvalidCursor(CursorFault::WrongCamera));
    }
    Ok(position)
}
