//! In-memory child iteration over a capped payload, and fixed-path lookup.

use super::error::Mp4BoxError;
use super::header::{BoxHeader, HEADER_LEN, parse_header};
use super::walk::MAX_DEPTH;

/// One child box inside a payload.
pub(super) struct Child<'a> {
    pub(super) header: BoxHeader,
    pub(super) body: &'a [u8],
}

/// Walks the direct children of a payload, validating each against the parent.
pub(super) struct Children<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Children<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(super) fn next_child(&mut self) -> Result<Option<Child<'a>>, Mp4BoxError> {
        let rest = self.data.get(self.pos..).unwrap_or_default();
        if rest.is_empty() {
            return Ok(None);
        }
        if u64::try_from(rest.len()).map_err(|_| Mp4BoxError::Overflow)? < HEADER_LEN {
            return Err(Mp4BoxError::TrailingPartialBox);
        }
        let remaining = u64::try_from(rest.len()).map_err(|_| Mp4BoxError::Overflow)?;
        let header = parse_header(rest, remaining)?;
        let size = usize::try_from(header.size).map_err(|_| Mp4BoxError::Overflow)?;
        let head = usize::try_from(header.header_len).map_err(|_| Mp4BoxError::Overflow)?;
        let body = rest.get(head..size).ok_or(Mp4BoxError::TruncatedHeader)?;
        self.pos = self.pos.checked_add(size).ok_or(Mp4BoxError::Overflow)?;
        Ok(Some(Child { header, body }))
    }
}

/// Find the first box reachable along the fixed `path`, returning its payload.
///
/// Recursion depth is at most `path.len()`, and `path` is a compile-time constant at every
/// call site; `MAX_DEPTH` is a backstop.
pub(super) fn find_path<'a>(
    payload: &'a [u8],
    path: &[[u8; 4]],
    depth: usize,
) -> Result<Option<&'a [u8]>, Mp4BoxError> {
    if depth >= MAX_DEPTH {
        return Err(Mp4BoxError::DepthExceeded);
    }
    let Some((first, rest)) = path.split_first() else {
        return Ok(None);
    };
    let mut children = Children::new(payload);
    while let Some(child) = children.next_child()? {
        if child.header.fourcc != *first {
            continue;
        }
        if rest.is_empty() {
            return Ok(Some(child.body));
        }
        let next_depth = depth.checked_add(1).ok_or(Mp4BoxError::Overflow)?;
        if let Some(found) = find_path(child.body, rest, next_depth)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Big-endian reader over a byte slice with checked bounds.
pub(super) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(super) fn new(data: &'a [u8], what: &'static str) -> Self {
        Self { data, pos: 0, what }
    }

    pub(super) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub(super) fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or_default()
    }

    pub(super) fn skip(&mut self, n: usize) -> Result<(), Mp4BoxError> {
        self.take(n).map(|_| ())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Mp4BoxError> {
        let end = self.pos.checked_add(n).ok_or(Mp4BoxError::Overflow)?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(Mp4BoxError::TruncatedBox(self.what))?;
        self.pos = end;
        Ok(s)
    }

    pub(super) fn u32(&mut self) -> Result<u32, Mp4BoxError> {
        let &[a, b, c, d] = self
            .take(4)?
            .first_chunk::<4>()
            .ok_or(Mp4BoxError::TruncatedBox(self.what))?;
        Ok(u32::from_be_bytes([a, b, c, d]))
    }
}

/// Decode a big-endian `u32` at `offset` of `data`.
pub(super) fn u32_at(data: &[u8], offset: usize, what: &'static str) -> Result<u32, Mp4BoxError> {
    let mut r = Reader::new(data, what);
    r.skip(offset)?;
    r.u32()
}
