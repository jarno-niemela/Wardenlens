//! The adoption parser: a file without a row is untrusted input (ADR 0005 section 9).
//!
//! The box walk is `core::mp4box::summarize`: one box header at a time, `mdat` skipped by
//! seeking, `moov` and `moof` read only when at most 1 MiB, never a whole-file slice. It rejects a
//! box size of 0 or below 8, a `largesize`, a child that does not lie inside its parent, a
//! trailing partial box, `sample_count * entry_size` beyond the payload, more than 100,000
//! fragments or 1 GiB, and sums checked `u64`s. Storage does the reads, over the descriptor that
//! was opened with `O_NONBLOCK` and `fstat`ed.

use wardenlens_core::mp4box::{ByteSource, Mp4BoxError, Mp4Summary, summarize};
use wardenlens_core::storage::MAX_SEGMENT_BYTES;

use crate::files::ReadSeekSource;
use crate::fs::Opened;

/// The column's `CHECK` on `duration_ms` (ADR 0005 section 5).
const MAX_DURATION_MS: u64 = 600_000;

/// What the parser concluded about one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Parsed {
    /// A well-formed segment: the duration (ms, rounded up, at least 1) and the sample count.
    Valid(Mp4Summary),
    /// Not a segment we can adopt (malformed, out of the column bounds, ...): to be quarantined.
    Invalid,
    /// The file could not be read: no conclusion (never quarantined on an I/O error).
    Unreadable,
}

/// Parse `file`. The length is the one `fstat` reported for this very descriptor.
pub(super) fn parse(file: &mut Opened) -> Parsed {
    let len = file.len;
    if len == 0 || len > MAX_SEGMENT_BYTES {
        return Parsed::Invalid;
    }
    let Ok(mut source) = ReadSeekSource::new(&mut file.file) else {
        return Parsed::Unreadable;
    };
    if source.byte_len() != len {
        // The file changed between `fstat` and the walk: no conclusion.
        return Parsed::Unreadable;
    }
    match summarize(&mut source) {
        Ok(s) if (1..=MAX_DURATION_MS).contains(&s.duration_ms) && s.frame_count > 0 => {
            Parsed::Valid(s)
        }
        Err(Mp4BoxError::Source(_)) => Parsed::Unreadable,
        // Out of the column bounds, or any structural refusal of the walk.
        Ok(_) | Err(_) => Parsed::Invalid,
    }
}
