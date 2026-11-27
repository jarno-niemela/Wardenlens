//! Bounded, header-at-a-time fMP4 box parser (ADR 0005 section 9, "Adoption parser").
//!
//! Every input is untrusted (SEC-2): a planted file on a recordings volume. This module
//! performs no I/O. The caller supplies a [`ByteSource`]; the walk reads one box header at
//! a time, skips `mdat` payloads by offset and reads a `moov` or `moof` payload only when
//! it is at most [`MAX_PAYLOAD_LEN`] bytes. It descends only along fixed paths
//! (`moov/trak/mdia/mdhd`, `moof/traf/{tfhd,trun}`), so nesting depth cannot grow the stack.
//!
//! ```
//! use wardenlens_core::mp4box::{parse_header, BoxHeader};
//!
//! let bytes = [0, 0, 0, 16, b'f', b't', b'y', b'p', 0, 0, 0, 0, 0, 0, 0, 0];
//! let header: BoxHeader = parse_header(&bytes, 16).unwrap();
//! assert_eq!(&header.fourcc(), b"ftyp");
//! assert_eq!(header.size(), 16);
//! ```

mod error;
mod header;
mod moof;
mod source;
mod tree;
mod walk;

#[cfg(test)]
mod tests;

pub use error::{Mp4BoxError, SourceError};
pub use header::{BoxHeader, HEADER_LEN, parse_header};
pub use source::{ByteSource, SliceSource};
pub use walk::{
    MAX_FILE_LEN, MAX_FRAGMENTS, MAX_PAYLOAD_LEN, MAX_SAMPLES_PER_FRAGMENT, Mp4Summary, summarize,
};
