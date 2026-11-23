//! Single box header parsing.

use super::error::Mp4BoxError;

/// Length of a plain box header: 4 bytes size and 4 bytes fourcc.
pub const HEADER_LEN: u64 = 8;

/// A validated box header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxHeader {
    /// The four-character box type.
    pub fourcc: [u8; 4],
    /// Header length in bytes (always 8: `largesize` is rejected).
    pub header_len: u64,
    /// Total box size including the header; at least 8 and within the parent.
    pub size: u64,
}

impl BoxHeader {
    /// Payload length (total size minus header).
    #[must_use]
    pub fn payload_len(&self) -> u64 {
        self.size.saturating_sub(self.header_len)
    }
}

/// Parse and validate one box header from the start of `bytes`.
///
/// `remaining_in_parent` is the number of bytes from the start of this box to the end of
/// its parent (or of the file for a top-level box).
///
/// # Errors
/// [`Mp4BoxError::TruncatedHeader`] if fewer than 8 bytes are given,
/// [`Mp4BoxError::InvalidSize`] for a size of 0 or below 8, [`Mp4BoxError::LargeSize`] for a
/// size field of 1 and [`Mp4BoxError::ExceedsParent`] if the box is larger than
/// `remaining_in_parent`.
pub fn parse_header(bytes: &[u8], remaining_in_parent: u64) -> Result<BoxHeader, Mp4BoxError> {
    let Some(&[s0, s1, s2, s3, t0, t1, t2, t3]) = bytes.first_chunk::<8>() else {
        return Err(Mp4BoxError::TruncatedHeader);
    };
    let size32 = u32::from_be_bytes([s0, s1, s2, s3]);
    match size32 {
        1 => return Err(Mp4BoxError::LargeSize),
        0..=7 => return Err(Mp4BoxError::InvalidSize(size32)),
        _ => {}
    }
    let size = u64::from(size32);
    if size > remaining_in_parent {
        return Err(Mp4BoxError::ExceedsParent {
            size,
            remaining: remaining_in_parent,
        });
    }
    Ok(BoxHeader {
        fourcc: [t0, t1, t2, t3],
        header_len: HEADER_LEN,
        size,
    })
}
