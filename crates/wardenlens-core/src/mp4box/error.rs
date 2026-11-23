//! Typed errors for the box parser (ERR-1: no panics, no stringly errors).

use std::fmt;

/// A read failure reported by a [`ByteSource`](super::ByteSource).
///
/// It deliberately carries no detail: callers log the I/O error themselves and reports must
/// never contain file names (ADR 0005 section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceError;

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("source read failed")
    }
}

impl std::error::Error for SourceError {}

/// Why a file was rejected by the box parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mp4BoxError {
    /// Fewer than 8 bytes were available for a box header.
    TruncatedHeader,
    /// The size field is 0 (box extends to end of file) or below 8.
    InvalidSize(u32),
    /// The size field is 1 (64-bit `largesize`), which our writer never produces.
    LargeSize,
    /// The box does not fit in its parent or in the rest of the file.
    ExceedsParent {
        /// Declared box size.
        size: u64,
        /// Bytes left in the parent.
        remaining: u64,
    },
    /// Between 1 and 7 bytes are left, too few for another box header.
    TrailingPartialBox,
    /// A `moov` or `moof` payload is larger than the cap.
    PayloadTooLarge {
        /// Declared payload length.
        len: u64,
    },
    /// The file is larger than the cap.
    FileTooLarge {
        /// File length.
        len: u64,
    },
    /// More fragments than the cap.
    TooManyFragments,
    /// More top-level boxes than any valid file within the caps can hold.
    TooManyBoxes,
    /// The depth backstop was hit.
    DepthExceeded,
    /// A required box is absent.
    MissingBox(&'static str),
    /// A box that must appear once appears again.
    DuplicateBox(&'static str),
    /// A box appears where it is not allowed (for example an `mdat` with no `moof` before it).
    MisplacedBox(&'static str),
    /// The file holds no samples at all.
    NoSamples,
    /// A `moof` is not directly followed by an `mdat`, or the file ends after a `moof`.
    IncompleteFragment,
    /// A `moof` appears before the `moov`, so the timescale is unknown.
    FragmentBeforeMoov,
    /// A box payload is shorter than its fixed fields require.
    TruncatedBox(&'static str),
    /// A field has a value that is not allowed (for example a zero timescale).
    InvalidField(&'static str),
    /// `sample_count * entry_size` exceeds the `trun` payload.
    SampleTableTooLarge,
    /// A `trun` has samples but neither per-sample durations nor a `tfhd` default duration.
    MissingSampleDuration,
    /// A checked arithmetic operation overflowed.
    Overflow,
    /// The byte source failed.
    Source(SourceError),
}

impl fmt::Display for Mp4BoxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("truncated box header"),
            Self::InvalidSize(s) => write!(f, "invalid box size {s}"),
            Self::LargeSize => f.write_str("largesize boxes are not accepted"),
            Self::ExceedsParent { size, remaining } => {
                write!(f, "box size {size} exceeds the {remaining} bytes remaining")
            }
            Self::TrailingPartialBox => f.write_str("trailing partial box"),
            Self::PayloadTooLarge { len } => write!(f, "payload of {len} bytes exceeds the cap"),
            Self::FileTooLarge { len } => write!(f, "file of {len} bytes exceeds the cap"),
            Self::TooManyFragments => f.write_str("too many fragments"),
            Self::TooManyBoxes => f.write_str("too many top-level boxes"),
            Self::DepthExceeded => f.write_str("box nesting depth exceeded"),
            Self::MissingBox(b) => write!(f, "missing required box {b}"),
            Self::DuplicateBox(b) => write!(f, "duplicate box {b}"),
            Self::MisplacedBox(b) => write!(f, "misplaced box {b}"),
            Self::NoSamples => f.write_str("file holds no samples"),
            Self::IncompleteFragment => f.write_str("moof without a following mdat"),
            Self::FragmentBeforeMoov => f.write_str("moof before moov"),
            Self::TruncatedBox(b) => write!(f, "truncated {b} box"),
            Self::InvalidField(b) => write!(f, "invalid field in {b}"),
            Self::SampleTableTooLarge => f.write_str("sample table larger than its box"),
            Self::MissingSampleDuration => f.write_str("samples without a duration"),
            Self::Overflow => f.write_str("arithmetic overflow"),
            Self::Source(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Mp4BoxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SourceError> for Mp4BoxError {
    fn from(e: SourceError) -> Self {
        Self::Source(e)
    }
}
