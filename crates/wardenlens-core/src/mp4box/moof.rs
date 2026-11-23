//! `moof` payload parsing: `moof/traf/{tfhd,trun}`.

use super::error::Mp4BoxError;
use super::tree::{Children, Reader, find_path, u32_at};

const TFHD_DEFAULT_DURATION: u32 = 0x08;
const TFHD_BASE_DATA_OFFSET: u32 = 0x01;
const TFHD_SAMPLE_DESC_INDEX: u32 = 0x02;

const TRUN_DATA_OFFSET: u32 = 0x001;
const TRUN_FIRST_SAMPLE_FLAGS: u32 = 0x004;
const TRUN_SAMPLE_DURATION: u32 = 0x100;
const TRUN_SAMPLE_SIZE: u32 = 0x200;
const TRUN_SAMPLE_FLAGS: u32 = 0x400;
const TRUN_SAMPLE_CTO: u32 = 0x800;

/// Frames and duration ticks of one fragment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct FragmentStats {
    pub(super) frames: u64,
    pub(super) ticks: u64,
}

fn add(a: u64, b: u64) -> Result<u64, Mp4BoxError> {
    a.checked_add(b).ok_or(Mp4BoxError::Overflow)
}

/// Sum the sample counts and durations of every `traf/trun` in a `moof` payload.
pub(super) fn parse_moof(payload: &[u8]) -> Result<FragmentStats, Mp4BoxError> {
    let mut total = FragmentStats::default();
    let mut children = Children::new(payload);
    while let Some(child) = children.next_child()? {
        if &child.header.fourcc != b"traf" {
            continue;
        }
        let t = parse_traf(child.body)?;
        total.frames = add(total.frames, t.frames)?;
        total.ticks = add(total.ticks, t.ticks)?;
    }
    Ok(total)
}

fn parse_traf(payload: &[u8]) -> Result<FragmentStats, Mp4BoxError> {
    let default_duration = match find_path(payload, &[*b"tfhd"], 2)? {
        Some(tfhd) => parse_tfhd(tfhd)?,
        None => None,
    };
    let mut total = FragmentStats::default();
    let mut children = Children::new(payload);
    while let Some(child) = children.next_child()? {
        if &child.header.fourcc != b"trun" {
            continue;
        }
        let t = parse_trun(child.body, default_duration)?;
        total.frames = add(total.frames, t.frames)?;
        total.ticks = add(total.ticks, t.ticks)?;
    }
    Ok(total)
}

/// Returns the default sample duration, if the `tfhd` carries one.
fn parse_tfhd(payload: &[u8]) -> Result<Option<u32>, Mp4BoxError> {
    let mut r = Reader::new(payload, "tfhd");
    let flags = r.u32()? & 0x00ff_ffff;
    r.skip(4)?; // track_id
    if flags & TFHD_BASE_DATA_OFFSET != 0 {
        r.skip(8)?;
    }
    if flags & TFHD_SAMPLE_DESC_INDEX != 0 {
        r.skip(4)?;
    }
    if flags & TFHD_DEFAULT_DURATION != 0 {
        return Ok(Some(r.u32()?));
    }
    Ok(None)
}

fn parse_trun(payload: &[u8], default_duration: Option<u32>) -> Result<FragmentStats, Mp4BoxError> {
    let mut r = Reader::new(payload, "trun");
    let flags = r.u32()? & 0x00ff_ffff;
    let sample_count = u64::from(r.u32()?);
    if flags & TRUN_DATA_OFFSET != 0 {
        r.skip(4)?;
    }
    if flags & TRUN_FIRST_SAMPLE_FLAGS != 0 {
        r.skip(4)?;
    }
    let present = [
        TRUN_SAMPLE_DURATION,
        TRUN_SAMPLE_SIZE,
        TRUN_SAMPLE_FLAGS,
        TRUN_SAMPLE_CTO,
    ]
    .iter()
    .filter(|f| flags & **f != 0)
    .count();
    let entry_size = present.checked_mul(4).ok_or(Mp4BoxError::Overflow)?;
    // Checked before any allocation or iteration (SEC-2).
    let needed = sample_count
        .checked_mul(u64::try_from(entry_size).map_err(|_| Mp4BoxError::Overflow)?)
        .ok_or(Mp4BoxError::Overflow)?;
    let available = u64::try_from(r.remaining()).map_err(|_| Mp4BoxError::Overflow)?;
    if needed > available {
        return Err(Mp4BoxError::SampleTableTooLarge);
    }
    let ticks = if sample_count == 0 {
        0
    } else if flags & TRUN_SAMPLE_DURATION != 0 {
        sum_entry_durations(r.rest(), entry_size, sample_count)?
    } else {
        let d = default_duration.ok_or(Mp4BoxError::MissingSampleDuration)?;
        sample_count
            .checked_mul(u64::from(d))
            .ok_or(Mp4BoxError::Overflow)?
    };
    Ok(FragmentStats {
        frames: sample_count,
        ticks,
    })
}

/// Sum the per-sample durations. The duration is the first field of each entry, and the
/// caller has verified that `sample_count * entry_size` fits in `entries`.
fn sum_entry_durations(
    entries: &[u8],
    entry_size: usize,
    sample_count: u64,
) -> Result<u64, Mp4BoxError> {
    let mut sum = 0u64;
    let mut seen = 0u64;
    for entry in entries.chunks_exact(entry_size) {
        if seen >= sample_count {
            break;
        }
        sum = add(sum, u64::from(u32_at(entry, 0, "trun")?))?;
        seen = add(seen, 1)?;
    }
    Ok(sum)
}
