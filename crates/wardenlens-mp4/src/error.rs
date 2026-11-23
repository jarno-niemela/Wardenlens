//! The crate's error type.

/// Everything that can go wrong while building or writing an fMP4 file.
///
/// Messages never include payload bytes (ERR-5).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Mp4Error {
    /// The SPS is empty or larger than the bound.
    #[error("sps length {len} is outside 1..={max}")]
    SpsLength {
        /// Offending length.
        len: usize,
        /// Largest accepted length.
        max: usize,
    },
    /// The PPS is empty or larger than the bound.
    #[error("pps length {len} is outside 1..={max}")]
    PpsLength {
        /// Offending length.
        len: usize,
        /// Largest accepted length.
        max: usize,
    },
    /// The first byte of the SPS is not an SPS NAL header.
    #[error("sps does not start with an sps nal header")]
    NotAnSps,
    /// The first byte of the PPS is not a PPS NAL header.
    #[error("pps does not start with a pps nal header")]
    NotAPps,
    /// The SPS ended before all required fields were read.
    #[error("sps is truncated")]
    SpsTruncated,
    /// The SPS holds a value that is out of range or unsupported.
    #[error("sps is invalid: {0}")]
    SpsInvalid(&'static str),
    /// A fragment was requested with no samples.
    #[error("a fragment needs at least one sample")]
    NoSamples,
    /// A fragment holds more samples than the bound.
    #[error("fragment has {count} samples, more than {max}")]
    TooManySamples {
        /// Number of samples given.
        count: usize,
        /// Largest accepted count.
        max: usize,
    },
    /// A sample is empty.
    #[error("a sample must not be empty")]
    EmptySample,
    /// A sample is larger than the single-frame bound.
    #[error("sample of {len} bytes exceeds {max}")]
    SampleTooLarge {
        /// Offending length.
        len: usize,
        /// Largest accepted length.
        max: usize,
    },
    /// Sample data is not a sequence of exactly tiling 4-byte length-prefixed NAL units.
    #[error("sample is not valid avcc (4-byte length prefixed nal units)")]
    InvalidAvcc,
    /// Annex-B data contains no start code, or non-zero bytes before the first one.
    #[error("annex-b data has no leading start code")]
    NoStartCode,
    /// A box does not fit the 32-bit size field, or another length overflowed.
    #[error("box or length does not fit in 32 bits")]
    BoxTooLarge,
    /// A total duration does not fit the 32-bit `mvhd` field.
    #[error("duration of {ticks} ticks does not fit the 32-bit mvhd field")]
    DurationTooLarge {
        /// The duration that was requested.
        ticks: u64,
    },
    /// The underlying writer failed.
    #[error("write failed")]
    Io(#[from] std::io::Error),
}
