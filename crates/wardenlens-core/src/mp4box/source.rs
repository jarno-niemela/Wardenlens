//! The caller-supplied byte source. Core does no I/O; storage implements this over a file.

use super::error::SourceError;

/// Random-access read access to a file's bytes.
///
/// Implementors must keep [`byte_len`](Self::byte_len) constant for the whole walk, and it
/// must come from `fstat` on the same handle that
/// [`read_exact_at`](Self::read_exact_at) reads (never from a path lookup), so a file that is
/// swapped or grown mid-walk cannot make the parser trust a stale length.
pub trait ByteSource {
    /// Total length in bytes.
    fn byte_len(&self) -> u64;

    /// Fill `buf` with the bytes at `offset..offset + buf.len()`.
    ///
    /// # Errors
    /// [`SourceError`] if the range cannot be read in full.
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError>;
}

/// A [`ByteSource`] over an in-memory slice (tests, small buffers).
#[derive(Debug, Clone, Copy)]
pub struct SliceSource<'a>(pub &'a [u8]);

impl ByteSource for SliceSource<'_> {
    fn byte_len(&self) -> u64 {
        u64::try_from(self.0.len()).unwrap_or(u64::MAX)
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let start = usize::try_from(offset).map_err(|_| SourceError)?;
        let end = start.checked_add(buf.len()).ok_or(SourceError)?;
        let src = self.0.get(start..end).ok_or(SourceError)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}
