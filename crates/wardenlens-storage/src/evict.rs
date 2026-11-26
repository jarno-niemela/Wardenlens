//! Quarantined files, evicted first (ADR 0005 section 6, "Eviction order", item 1).
//!
//! They are not in the index and not in the pure plan, so the executor deletes them before it
//! runs the plan whenever a volume is below its floor. Only names that match the section 3
//! quarantine pattern are ours; anything else under `_quarantine` is left alone.

use std::str::FromStr;

use wardenlens_core::camera::CameraId;
use wardenlens_core::storage::{Tier, VolumeSpace};
use wardenlens_fsutil::{DirEntry, FileKind, QUARANTINE_DIR};

use crate::fs::Fs;

/// Most directory entries one scan visits (SEC-2); a larger quarantine is evicted in several
/// ticks, oldest first.
pub const MAX_QUARANTINE_ENTRIES: usize = 100_000;

/// One quarantined file, ordered oldest first by the time in its name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Candidate {
    day: String,
    time: String,
    camera: String,
    suffix: u32,
    pub(crate) name: String,
}

impl Candidate {
    /// The directory components of this file below the root.
    pub(crate) fn dir(&self) -> [&str; 3] {
        [QUARANTINE_DIR, &self.camera, &self.day]
    }

    fn comps(&self) -> [&str; 4] {
        [QUARANTINE_DIR, &self.camera, &self.day, &self.name]
    }
}

/// The files to delete, oldest first, and the free space they must restore.
#[derive(Debug)]
pub(crate) struct Selection {
    pub(crate) files: Vec<Candidate>,
    /// Free bytes at which the eviction stops: floor plus headroom when the quarantine can reach
    /// it, else the floor.
    pub(crate) goal: u64,
}

/// Choose what to delete from the quarantine of `tier`, or nothing. Quarantine goes first, as an
/// order (section 6): reachability is judged on the combined goal, free space plus the whole
/// quarantine plus the `deletable_bytes` of the tier's indexed segments (which the plan deletes
/// after). Nothing is selected only when even that total cannot reach the floor (P2: deleting
/// evidence that cannot restore the goal loses it for nothing). Otherwise the selection is the
/// shortest oldest-first prefix that reaches the goal, or the whole quarantine when it does not.
pub(crate) fn select<F: Fs>(
    fs: &F,
    tier: Tier,
    space: &VolumeSpace,
    floor_percent: u8,
    deletable_bytes: u64,
) -> Option<Selection> {
    let floor = percent_of(space.capacity_bytes, u64::from(floor_percent))?;
    let target = percent_of(
        space.capacity_bytes,
        u64::from(floor_percent).saturating_add(1),
    )?;
    let mut sized: Vec<(Candidate, u64)> = Vec::new();
    let mut total = 0_u64;
    for c in scan(fs, tier) {
        // The length of the same descriptor that was opened (never a path lookup).
        let Ok(o) = fs.open_read(tier, &c.comps()) else {
            continue;
        };
        total = total.saturating_add(o.len);
        sized.push((c, o.len));
    }
    let reachable = space
        .free_bytes
        .saturating_add(total)
        .saturating_add(deletable_bytes);
    if reachable < floor {
        return None;
    }
    let goal = if reachable >= target { target } else { floor };
    let need = goal.saturating_sub(space.free_bytes);
    let mut freed = 0_u64;
    let mut files = Vec::new();
    for (c, len) in sized {
        if freed >= need {
            break;
        }
        freed = freed.saturating_add(len);
        files.push(c);
    }
    if files.is_empty() {
        None
    } else {
        Some(Selection { files, goal })
    }
}

/// `capacity * percent / 100`, rounded down, checked (a floor is never a wrapped number).
pub(crate) fn percent_of(capacity: u64, percent: u64) -> Option<u64> {
    let scaled = u128::from(capacity).checked_mul(u128::from(percent))?;
    u64::try_from(scaled.checked_div(100)?).ok()
}

/// Whether `space` is below its floor of `floor_percent`.
pub(crate) fn below_floor(space: &VolumeSpace, floor_percent: u8) -> bool {
    percent_of(space.capacity_bytes, u64::from(floor_percent))
        .is_some_and(|floor| space.free_bytes < floor)
}

fn digits(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_day(s: &str) -> bool {
    let mut it = s.split('-');
    matches!(
        (it.next(), it.next(), it.next(), it.next()),
        (Some(y), Some(m), Some(d), None) if digits(y, 4) && digits(m, 2) && digits(d, 2)
    )
}

/// `HHMMSS-mmm.mp4` or `HHMMSS-mmm.mp4.<n>`: the time part and the suffix.
fn parse_name(name: &str) -> Option<(String, u32)> {
    let (time, rest) = name.split_at_checked(10)?;
    let (h, ms) = time.split_at_checked(6)?;
    let ms = ms.strip_prefix('-')?;
    if !digits(h, 6) || !digits(ms, 3) {
        return None;
    }
    let suffix = match rest.strip_prefix(".mp4")? {
        "" => 0,
        n => {
            let n = n.strip_prefix('.')?;
            if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            n.parse::<u32>().ok()?
        }
    };
    Some((time.to_owned(), suffix))
}

/// Scan `<root>/_quarantine/<camera>/<day>/<file>` (depth 3), oldest first. A missing directory
/// (`ENOENT`) is an empty quarantine; any other listing failure ends the scan with what was seen.
pub(crate) fn scan<F: Fs>(fs: &F, tier: Tier) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut budget = MAX_QUARANTINE_ENTRIES;
    let cameras = list(fs, tier, &[QUARANTINE_DIR], &mut budget);
    for cam in cameras
        .iter()
        .filter(|e| matches!(e.kind, FileKind::Directory | FileKind::Other))
    {
        if CameraId::from_str(&cam.name).is_err() {
            continue;
        }
        let days = list(fs, tier, &[QUARANTINE_DIR, &cam.name], &mut budget);
        for day in days
            .iter()
            .filter(|e| matches!(e.kind, FileKind::Directory | FileKind::Other) && is_day(&e.name))
        {
            let files = list(
                fs,
                tier,
                &[QUARANTINE_DIR, &cam.name, &day.name],
                &mut budget,
            );
            // `DT_UNKNOWN` (kind `Other`) is not a verdict: the sizing step opens the file and
            // `fstat`s the descriptor, which refuses anything that is not regular.
            for f in files
                .iter()
                .filter(|e| matches!(e.kind, FileKind::Regular | FileKind::Other))
            {
                if let Some((time, suffix)) = parse_name(&f.name) {
                    out.push(Candidate {
                        day: day.name.clone(),
                        time,
                        camera: cam.name.clone(),
                        suffix,
                        name: f.name.clone(),
                    });
                }
            }
        }
    }
    out.sort();
    out
}

fn list<F: Fs>(fs: &F, tier: Tier, dir: &[&str], budget: &mut usize) -> Vec<DirEntry> {
    if *budget == 0 {
        return Vec::new();
    }
    match fs.list_dir(tier, dir, *budget) {
        Ok(v) => {
            *budget = budget.saturating_sub(v.len());
            v
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_quarantine_pattern_only() {
        assert_eq!(parse_name("000102-003.mp4"), Some(("000102-003".into(), 0)));
        assert_eq!(
            parse_name("000102-003.mp4.12"),
            Some(("000102-003".into(), 12))
        );
        for bad in [
            "000102-003.mp4.",
            "000102-003.mp4.x",
            "000102-003.mp4.part",
            "00010-0003.mp4",
            "000102-003.mov",
            "x.mp4",
            "",
            "000102-003.mp4.99999999999",
            "ééééééééé.mp4",
        ] {
            assert_eq!(parse_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn floor_arithmetic_is_checked() {
        let v = VolumeSpace {
            capacity_bytes: u64::MAX,
            free_bytes: 0,
        };
        assert!(below_floor(&v, 90));
        let zero = VolumeSpace {
            capacity_bytes: 0,
            free_bytes: 0,
        };
        assert!(
            !below_floor(&zero, 25),
            "capacity 0 is unusable, not below a floor"
        );
    }
}
