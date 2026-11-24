//! Minimal box serialisation helpers. Every size goes through `u32::try_from` (ADR 0005 section 3).

use crate::error::Mp4Error;

pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_zeros(out: &mut Vec<u8>, n: usize) {
    out.resize(out.len().saturating_add(n), 0);
}

/// Current length of `out` as a file offset.
pub(crate) fn offset(out: &[u8]) -> Result<u64, Mp4Error> {
    u64::try_from(out.len()).map_err(|_| Mp4Error::BoxTooLarge)
}

/// Overwrite four bytes at `at` with `v` (used for sizes and offsets known only later).
pub(crate) fn patch_u32(out: &mut [u8], at: usize, v: u32) -> Result<(), Mp4Error> {
    let end = at.checked_add(4).ok_or(Mp4Error::BoxTooLarge)?;
    out.get_mut(at..end)
        .ok_or(Mp4Error::BoxTooLarge)?
        .copy_from_slice(&v.to_be_bytes());
    Ok(())
}

/// Append a box: an 8-byte header whose size is patched once `body` has run.
pub(crate) fn write_box<F>(out: &mut Vec<u8>, fourcc: [u8; 4], body: F) -> Result<(), Mp4Error>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), Mp4Error>,
{
    let start = out.len();
    put_u32(out, 0);
    out.extend_from_slice(&fourcc);
    body(out)?;
    let size = out.len().checked_sub(start).ok_or(Mp4Error::BoxTooLarge)?;
    patch_u32(
        out,
        start,
        u32::try_from(size).map_err(|_| Mp4Error::BoxTooLarge)?,
    )
}

/// Append a box that starts with a version byte and 24 bits of flags.
pub(crate) fn write_full_box<F>(
    out: &mut Vec<u8>,
    fourcc: [u8; 4],
    version: u8,
    flags: u32,
    body: F,
) -> Result<(), Mp4Error>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), Mp4Error>,
{
    write_box(out, fourcc, |o| {
        put_u32(o, (u32::from(version) << 24) | (flags & 0x00ff_ffff));
        body(o)
    })
}
