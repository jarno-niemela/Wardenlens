//! The top-level walk driver.

use super::error::Mp4BoxError;
use super::header::{BoxHeader, HEADER_LEN, parse_header};
use super::moof::parse_moof;
use super::source::ByteSource;
use super::tree::{Children, Reader, find_path};

/// Largest `moov` or `moof` payload that is read (1 MiB).
pub const MAX_PAYLOAD_LEN: u64 = 1024 * 1024;
/// Largest file that is accepted (1 GiB).
pub const MAX_FILE_LEN: u64 = 1024 * 1024 * 1024;
/// Most fragments (`moof` boxes) a file may hold.
pub const MAX_FRAGMENTS: u64 = 100_000;
/// Backstop on nesting depth for fixed-path descent.
pub(crate) const MAX_DEPTH: usize = 8;

/// Slack for `ftyp`, `moov` and any `free` boxes on top of two boxes per fragment.
pub(super) const MAX_TOP_LEVEL_BOXES: u64 = MAX_FRAGMENTS * 2 + 16;

/// What the adoption walk learns about a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mp4Summary {
    /// Sum of all `trun` sample durations in ms, rounded up, at least 1. Not range-checked.
    pub duration_ms: u64,
    /// Total number of samples across all fragments.
    pub frame_count: u64,
}

#[derive(Default)]
struct Walk {
    seen_any: bool,
    seen_ftyp: bool,
    timescale: Option<u32>,
    pending_moof: bool,
    fragments: u64,
    moofs_seen: u64,
    frames: u64,
    ticks: u64,
    pending_frames: u64,
    pending_ticks: u64,
}

/// Walk the top-level boxes of an fMP4 file and summarise it.
///
/// The file must start with exactly one `ftyp`, then one `moov` with exactly one `trak`
/// (our writer emits a single video track; files with more are rejected), then `moof`/`mdat`
/// pairs, with at least one sample overall.
///
/// The result is **not** range-checked: `frame_count` and `duration_ms` can be huge (a
/// `trun` may declare billions of samples via a default duration). Callers must range-check
/// both before trusting them.
///
/// Reads one 8-byte header at a time, skips `mdat` by offset and reads `moov`/`moof`
/// payloads only when at most [`MAX_PAYLOAD_LEN`] bytes.
///
/// # Errors
/// A typed [`Mp4BoxError`] for any malformed, oversized or incomplete file, or a source
/// failure. Never panics.
pub fn summarize<S: ByteSource>(source: &mut S) -> Result<Mp4Summary, Mp4BoxError> {
    let len = source.byte_len();
    if len > MAX_FILE_LEN {
        return Err(Mp4BoxError::FileTooLarge { len });
    }
    let mut walk = Walk::default();
    let mut offset = 0u64;
    let mut boxes = 0u64;
    while offset < len {
        boxes = boxes.checked_add(1).ok_or(Mp4BoxError::Overflow)?;
        if boxes > MAX_TOP_LEVEL_BOXES {
            return Err(Mp4BoxError::TooManyBoxes);
        }
        let remaining = len.checked_sub(offset).ok_or(Mp4BoxError::Overflow)?;
        if remaining < HEADER_LEN {
            return Err(Mp4BoxError::TrailingPartialBox);
        }
        let mut head = [0u8; 8];
        source.read_exact_at(offset, &mut head)?;
        let header = parse_header(&head, remaining)?;
        walk.visit(source, offset, &header)?;
        offset = offset
            .checked_add(header.size())
            .ok_or(Mp4BoxError::Overflow)?;
    }
    walk.finish()
}

impl Walk {
    fn visit<S: ByteSource>(
        &mut self,
        source: &mut S,
        offset: u64,
        header: &BoxHeader,
    ) -> Result<(), Mp4BoxError> {
        let is_mdat = &header.fourcc() == b"mdat";
        if self.pending_moof {
            if !is_mdat {
                return Err(Mp4BoxError::IncompleteFragment);
            }
            self.complete_fragment()?;
        } else if is_mdat {
            return Err(Mp4BoxError::MisplacedBox("mdat"));
        }
        let is_ftyp = &header.fourcc() == b"ftyp";
        if !self.seen_any {
            // Only the very first box may (and must) be the `ftyp`.
            if !is_ftyp {
                return Err(Mp4BoxError::MissingBox("ftyp"));
            }
        } else if is_ftyp {
            return Err(Mp4BoxError::DuplicateBox("ftyp"));
        }
        self.seen_any = true;
        match &header.fourcc() {
            b"ftyp" => self.seen_ftyp = true,
            b"moov" => self.visit_moov(source, offset, header)?,
            b"moof" => self.visit_moof(source, offset, header)?,
            _ => {} // mdat and everything else: skipped by offset
        }
        Ok(())
    }

    fn visit_moov<S: ByteSource>(
        &mut self,
        source: &mut S,
        offset: u64,
        header: &BoxHeader,
    ) -> Result<(), Mp4BoxError> {
        if self.timescale.is_some() {
            return Err(Mp4BoxError::DuplicateBox("moov"));
        }
        let payload = read_payload(source, offset, header)?;
        // Header-validate every `moov` child, including those after the `trak`.
        let mut mdhd = None;
        let mut seen_trak = false;
        let mut children = Children::new(&payload);
        while let Some(child) = children.next_child()? {
            if &child.header.fourcc() != b"trak" {
                continue;
            }
            if seen_trak {
                return Err(Mp4BoxError::DuplicateBox("trak"));
            }
            seen_trak = true;
            mdhd = find_path(child.body, &[*b"mdia", *b"mdhd"], 2)?;
        }
        let mdhd = mdhd.ok_or(Mp4BoxError::MissingBox("mdhd"))?;
        self.timescale = Some(parse_mdhd_timescale(mdhd)?);
        Ok(())
    }

    fn visit_moof<S: ByteSource>(
        &mut self,
        source: &mut S,
        offset: u64,
        header: &BoxHeader,
    ) -> Result<(), Mp4BoxError> {
        if self.timescale.is_none() {
            return Err(Mp4BoxError::FragmentBeforeMoov);
        }
        self.moofs_seen = self
            .moofs_seen
            .checked_add(1)
            .ok_or(Mp4BoxError::Overflow)?;
        if self.moofs_seen > MAX_FRAGMENTS {
            return Err(Mp4BoxError::TooManyFragments);
        }
        let payload = read_payload(source, offset, header)?;
        let stats = parse_moof(&payload)?;
        self.pending_frames = stats.frames;
        self.pending_ticks = stats.ticks;
        self.pending_moof = true;
        Ok(())
    }

    fn complete_fragment(&mut self) -> Result<(), Mp4BoxError> {
        self.frames = self
            .frames
            .checked_add(self.pending_frames)
            .ok_or(Mp4BoxError::Overflow)?;
        self.ticks = self
            .ticks
            .checked_add(self.pending_ticks)
            .ok_or(Mp4BoxError::Overflow)?;
        self.fragments = self.fragments.checked_add(1).ok_or(Mp4BoxError::Overflow)?;
        self.pending_moof = false;
        Ok(())
    }

    fn finish(self) -> Result<Mp4Summary, Mp4BoxError> {
        if self.pending_moof {
            return Err(Mp4BoxError::IncompleteFragment);
        }
        if !self.seen_ftyp {
            return Err(Mp4BoxError::MissingBox("ftyp"));
        }
        let timescale = self.timescale.ok_or(Mp4BoxError::MissingBox("moov"))?;
        if self.fragments == 0 {
            return Err(Mp4BoxError::MissingBox("moof+mdat"));
        }
        if self.frames == 0 {
            return Err(Mp4BoxError::NoSamples);
        }
        Ok(Mp4Summary {
            duration_ms: ticks_to_ms_ceil(self.ticks, timescale)?,
            frame_count: self.frames,
        })
    }
}

/// Convert ticks to milliseconds, rounding up, minimum 1.
fn ticks_to_ms_ceil(ticks: u64, timescale: u32) -> Result<u64, Mp4BoxError> {
    let scale = u128::from(timescale);
    if scale == 0 {
        return Err(Mp4BoxError::InvalidField("mdhd"));
    }
    // ticks < 2^64, so ticks * 1000 < 2^74 always fits in u128.
    let ms = u128::from(ticks)
        .checked_mul(1000)
        .ok_or(Mp4BoxError::Overflow)?
        .div_ceil(scale);
    Ok(u64::try_from(ms).map_err(|_| Mp4BoxError::Overflow)?.max(1))
}

/// Read a capped payload (after the 8-byte header) into memory.
fn read_payload<S: ByteSource>(
    source: &mut S,
    offset: u64,
    header: &BoxHeader,
) -> Result<Vec<u8>, Mp4BoxError> {
    let len = header.payload_len();
    if len > MAX_PAYLOAD_LEN {
        return Err(Mp4BoxError::PayloadTooLarge { len });
    }
    let mut buf = vec![0u8; usize::try_from(len).map_err(|_| Mp4BoxError::Overflow)?];
    let start = offset
        .checked_add(header.header_len())
        .ok_or(Mp4BoxError::Overflow)?;
    source.read_exact_at(start, &mut buf)?;
    Ok(buf)
}

/// `mdhd` version 0: 4 creation, 4 modification, then timescale; version 1 uses 8-byte times.
fn parse_mdhd_timescale(payload: &[u8]) -> Result<u32, Mp4BoxError> {
    let mut r = Reader::new(payload, "mdhd");
    let version = r.u32()? >> 24;
    match version {
        0 => r.skip(8)?,
        1 => r.skip(16)?,
        _ => return Err(Mp4BoxError::InvalidField("mdhd")),
    }
    let timescale = r.u32()?;
    if timescale == 0 {
        return Err(Mp4BoxError::InvalidField("mdhd"));
    }
    Ok(timescale)
}
