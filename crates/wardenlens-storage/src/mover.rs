//! The crash-safe move M1-M9 and the delete (ADR 0005 section 7), with the section 9 cell rules
//! for a bad hot file at M1.
//!
//! The hot copy stays authoritative until the index says archive (M8), and it is unlinked last
//! (M9): at every crash point one complete copy exists and the row names a tier that has one.
//! The mover never retries a failed segment itself; the loop does not either, within a tick.

use std::io::{ErrorKind, Read};

use rustix::io::Errno;
use wardenlens_core::storage::{IndexedSegment, SegmentId, SegmentIndex, Tier};
use wardenlens_fsutil::{FsError, QuarantineOutcome};

use crate::fs::{Fs, Opened, same_bytes};
use crate::index::{Rel, SharedIndex};

/// Copy chunk of M4.
pub(crate) const COPY_CHUNK: usize = 1 << 20;

/// The archive-side step that failed. Only these count toward the three move failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Stage {
    /// M2: creating a directory on the archive, or the fsync of its parent.
    M2,
    /// M3: removing a stale `.part` or creating the new one.
    M3,
    /// M4, the write half: a `write`, `ENOSPC` or `EIO` on the archive file.
    M4Write,
    /// M5: `fsync` of the `.part`.
    M5,
    /// M6: `renameat2`.
    M6,
    /// M7: directory `fsync` on the archive (and the roll-forward `fsync`s).
    M7,
}

/// Why a row was dropped (the section 9 cells for a bad hot file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Dropped {
    /// Hot file missing and no usable archive copy (`missing`).
    Missing,
    /// Hot file of the wrong size, quarantined (`size_mismatch`).
    SizeMismatch,
}

/// Why a segment was skipped without any action or blame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Skip {
    /// The row is gone (a stale plan).
    NoRow,
    /// The row is not on the tier the action expects (a stale plan).
    WrongTier,
    /// The archive became unavailable after the plan was made.
    ArchiveUnavailable,
    /// No path could be derived from the row.
    BadRow,
}

/// What happened to one segment. Every variant that is not a success is final for the tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Outcome {
    /// M1-M9 completed.
    Moved,
    /// The row says archive (M8 committed) but the hot file could not be unlinked: the section 9
    /// cell (archive, valid, valid) removes it later.
    MovedHotLeft,
    /// The M1 cell found a valid archive copy for a bad or missing hot file and made it the row's.
    RolledForward,
    /// The M1 cell dropped the row.
    RowDropped(Dropped),
    /// A read error on the hot source: the hot segment was quarantined and its row dropped.
    SourceQuarantined,
    /// No conclusion was possible (a non-ENOENT error, a non-regular file, an exhausted
    /// quarantine bound, ...): files and row stay as they are.
    Unverified,
    /// An archive-side failure; counts toward the three.
    ArchiveFailure(Stage),
    /// An index call failed: skipped this tick, not the archive's fault.
    IndexError,
    /// Deleted (files unlinked, directories fsynced, row removed).
    Deleted,
    /// As `Deleted`, but a non-regular twin (symlink, FIFO, ...) on the other tier was left alone.
    DeletedTwinLeft,
    /// A delete could not unlink or fsync a file; the row is kept.
    DeleteFailed,
    /// Skipped, see [`Skip`].
    Skipped(Skip),
}

impl Outcome {
    /// Whether this outcome counts toward the three archive-side failures.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn blames_archive(self) -> bool {
        matches!(self, Self::ArchiveFailure(_))
    }

    /// Whether the segment's row left the hot tier (moved, rolled forward to the archive,
    /// dropped or deleted): its bytes no longer count as hot video.
    #[must_use]
    pub(crate) const fn removed_hot_copy(self) -> bool {
        matches!(
            self,
            Self::Moved
                | Self::MovedHotLeft
                | Self::Deleted
                | Self::DeletedTwinLeft
                | Self::SourceQuarantined
                | Self::RolledForward
                | Self::RowDropped(_)
        )
    }

    /// Whether the action took effect (the loop does not exclude the id from the rest of the tick
    /// on success; every other outcome is never retried within the tick).
    #[must_use]
    pub(crate) const fn succeeded(self) -> bool {
        matches!(
            self,
            Self::Moved
                | Self::MovedHotLeft
                | Self::RolledForward
                | Self::RowDropped(_)
                | Self::SourceQuarantined
                | Self::Deleted
                | Self::DeletedTwinLeft
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BadHot {
    Missing,
    WrongSize,
}

enum ArchiveCopy {
    None,
    Valid(Opened),
    Invalid,
    Unverified,
}

/// Runs one action against the file system and the index.
pub(crate) struct Mover<'a, F, I> {
    pub(crate) fs: &'a F,
    pub(crate) index: &'a SharedIndex<I>,
}

impl<F: Fs, I: SegmentIndex> Mover<'_, F, I> {
    /// Move segment `id` from hot to archive (M1-M9). `archive_available` is the state of the
    /// latest probe.
    pub(crate) fn move_segment(&self, id: SegmentId, archive_available: bool) -> Outcome {
        let row = match self.index.get(id) {
            Err(_) => return Outcome::IndexError,
            Ok(None) => return Outcome::Skipped(Skip::NoRow),
            Ok(Some(r)) => r,
        };
        if row.tier != Tier::Hot {
            return Outcome::Skipped(Skip::WrongTier);
        }
        let Some(rel) = Rel::of(&row) else {
            return Outcome::Skipped(Skip::BadRow);
        };
        let bytes = row.record.bytes;
        // M1: open H/R once; the descriptor that is checked is the one M4 copies from.
        let src = match self.fs.open_read(Tier::Hot, &rel.comps()) {
            Ok(o) if o.len == bytes => o,
            Ok(_) => return self.bad_hot(&row, &rel, BadHot::WrongSize, archive_available),
            Err(FsError::NotRegular) => return Outcome::Unverified,
            Err(e) if e.is_not_found() => {
                return self.bad_hot(&row, &rel, BadHot::Missing, archive_available);
            }
            Err(_) => return Outcome::Unverified,
        };
        if !archive_available {
            return Outcome::Skipped(Skip::ArchiveUnavailable);
        }
        if let Err(outcome) = self.copy_to_archive(&row, &rel, src) {
            return outcome;
        }
        // M8: the commit point.
        if self.index.set_tier(row.id, Tier::Archive).is_err() {
            return Outcome::IndexError;
        }
        // M9: the hot copy goes last.
        match self.fs.unlink(Tier::Hot, &rel.dir(), &rel.name) {
            Ok(()) => {}
            Err(e) if e.is_not_found() => {}
            Err(_) => return Outcome::MovedHotLeft,
        }
        // Best effort: correctness does not depend on it.
        let _ = self.fs.sync_dir(Tier::Hot, &rel.dir());
        Outcome::Moved
    }

    /// M2-M7 for a valid hot source. `Err` carries the final outcome.
    fn copy_to_archive(
        &self,
        row: &IndexedSegment,
        rel: &Rel,
        mut src: Opened,
    ) -> Result<(), Outcome> {
        let fail = |stage| Outcome::ArchiveFailure(stage);
        let dir = rel.dir();
        let part = rel.part_name();
        // M2: the directory chain; fsync the parent of every directory this step created.
        self.ensure_dir(&[], &rel.camera)
            .map_err(|()| fail(Stage::M2))?;
        self.ensure_dir(&[rel.camera.as_str()], &rel.day)
            .map_err(|()| fail(Stage::M2))?;
        // M3: a stale `.part` is ours (only the mover writes archive `.part` files).
        match self.fs.unlink(Tier::Archive, &dir, &part) {
            Ok(()) => {}
            Err(e) if e.is_not_found() => {}
            Err(_) => return Err(fail(Stage::M3)),
        }
        let mut out = self
            .fs
            .create_part(Tier::Archive, &dir, &part)
            .map_err(|_| fail(Stage::M3))?;
        // M4: copy in chunks from the M1 descriptor.
        let mut buf = vec![0_u8; COPY_CHUNK];
        let mut remaining = row.record.bytes;
        while remaining > 0 {
            let want = usize::try_from(remaining).map_or(COPY_CHUNK, |r| r.min(COPY_CHUNK));
            let Some(window) = buf.get_mut(..want) else {
                return Err(Outcome::Unverified);
            };
            let n = match src.file.read(window) {
                Ok(0) => {
                    // The file ended before the length `fstat` reported: a source problem.
                    self.drop_part(&dir, &part);
                    return Err(self.quarantine_source(row, rel));
                }
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.drop_part(&dir, &part);
                    return Err(self.quarantine_source(row, rel));
                }
            };
            let Some(chunk) = buf.get(..n) else {
                return Err(Outcome::Unverified);
            };
            if out.write_all(chunk).is_err() {
                self.drop_part(&dir, &part);
                return Err(fail(Stage::M4Write));
            }
            remaining = remaining.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
        }
        // M5.
        if out.sync().is_err() {
            drop(out);
            self.drop_part(&dir, &part);
            return Err(fail(Stage::M5));
        }
        drop(out);
        // M6: never replace an existing A/R.
        match self
            .fs
            .rename_noreplace(Tier::Archive, &dir, &part, &rel.name)
        {
            Ok(()) => {}
            Err(e) if e.errno() == Some(Errno::EXIST) => {
                if self.settle_existing(row, rel, &part)? {
                    // Rolled forward: the stale copy and its directory are already fsynced.
                    return Ok(());
                }
            }
            Err(_) => {
                self.drop_part(&dir, &part);
                return Err(fail(Stage::M6));
            }
        }
        // M7.
        if self.fs.sync_dir(Tier::Archive, &dir).is_err() {
            return Err(fail(Stage::M7));
        }
        Ok(())
    }

    /// `EEXIST` at M6. Returns `Ok(true)` when a complete stale `A/R` was rolled forward,
    /// `Ok(false)` when the stale file was quarantined and the retried rename succeeded.
    fn settle_existing(
        &self,
        row: &IndexedSegment,
        rel: &Rel,
        part: &str,
    ) -> Result<bool, Outcome> {
        let dir = rel.dir();
        let fail = |stage| Outcome::ArchiveFailure(stage);
        let Ok(stale) = self.fs.open_read(Tier::Archive, &rel.comps()) else {
            // Not a regular file, vanished, or unreadable: no conclusion about it.
            self.drop_part(&dir, part);
            return Err(Outcome::Unverified);
        };
        let mut stale = stale;
        if stale.len == row.record.bytes {
            // A stale complete copy of an earlier attempt, but only if it is the very bytes this
            // move wrote: a name is not an identity (#195). Same size and other bytes is another
            // recording and is quarantined below, never trusted as this row's copy.
            let Ok(mut fresh) = self.fs.open_read(Tier::Archive, &[dir[0], dir[1], part]) else {
                self.drop_part(&dir, part);
                return Err(Outcome::Unverified);
            };
            match same_bytes(&mut stale, &mut fresh) {
                Some(true) => {
                    // Fsync it and its directory, delete the `.part`, and go on with M8.
                    if stale.file.sync().is_err() || self.fs.sync_dir(Tier::Archive, &dir).is_err()
                    {
                        self.drop_part(&dir, part);
                        return Err(fail(Stage::M7));
                    }
                    self.drop_part(&dir, part);
                    return Ok(true);
                }
                Some(false) => {}
                None => {
                    self.drop_part(&dir, part);
                    return Err(Outcome::Unverified);
                }
            }
        }
        drop(stale);
        match self.fs.quarantine(Tier::Archive, &rel.comps()) {
            Ok(QuarantineOutcome::Moved { .. }) => {}
            Ok(_) => {
                // The 1,000 bound is used up: the file stays in place, counted `unverified`. An
                // EEXIST at M6 is never the archive's fault (section 7).
                self.drop_part(&dir, part);
                return Err(Outcome::Unverified);
            }
            Err(_) => {
                // The quarantine rename itself failed on the archive (a `renameat2` error, M6).
                self.drop_part(&dir, part);
                return Err(fail(Stage::M6));
            }
        }
        if self
            .fs
            .rename_noreplace(Tier::Archive, &dir, part, &rel.name)
            .is_err()
        {
            self.drop_part(&dir, part);
            return Err(fail(Stage::M6));
        }
        Ok(false)
    }

    /// `mkdirat`, then `fsync` of the parent. `EEXIST` is fine, but the parent is fsynced anyway:
    /// an earlier attempt may have created the directory and failed its own fsync, and the move
    /// must not commit (M8) and unlink the hot copy (M9) before the entry is durable.
    fn ensure_dir(&self, parent: &[&str], name: &str) -> Result<(), ()> {
        match self.fs.mkdir(Tier::Archive, parent, name) {
            Ok(()) => {}
            Err(e) if e.errno() == Some(Errno::EXIST) => {}
            Err(_) => return Err(()),
        }
        self.fs.sync_dir(Tier::Archive, parent).map_err(|_| ())
    }

    fn drop_part(&self, dir: &[&str; 2], part: &str) {
        // Best effort: the next M3 removes a leftover.
        let _ = self.fs.unlink(Tier::Archive, dir, part);
    }

    /// A read error on the hot source: quarantine the hot segment and drop its row, as in M1.
    fn quarantine_source(&self, row: &IndexedSegment, rel: &Rel) -> Outcome {
        if !self.quarantined(Tier::Hot, rel) {
            return Outcome::Unverified;
        }
        self.drop_row(row.id, Outcome::SourceQuarantined)
    }

    fn quarantined(&self, tier: Tier, rel: &Rel) -> bool {
        matches!(
            self.fs.quarantine(tier, &rel.comps()),
            Ok(QuarantineOutcome::Moved { .. })
        )
    }

    fn drop_row(&self, id: SegmentId, done: Outcome) -> Outcome {
        match self.index.delete(id) {
            Ok(()) => done,
            Err(_) => Outcome::IndexError,
        }
    }

    /// `H/R` is missing or has the wrong size: act as the section 9 cell for row = hot.
    fn bad_hot(
        &self,
        row: &IndexedSegment,
        rel: &Rel,
        kind: BadHot,
        archive_available: bool,
    ) -> Outcome {
        let drop_reason = match kind {
            BadHot::Missing => Dropped::Missing,
            BadHot::WrongSize => Dropped::SizeMismatch,
        };
        if !archive_available {
            // The archive is not observable: nothing is concluded from an absent archive file.
            if kind == BadHot::WrongSize {
                let _ = self.quarantined(Tier::Hot, rel);
            }
            return Outcome::Unverified;
        }
        let dropped = Outcome::RowDropped(drop_reason);
        match (kind, self.archive_copy(row, rel)) {
            (_, ArchiveCopy::Unverified) => Outcome::Unverified,
            (BadHot::Missing, ArchiveCopy::None) => self.drop_row(row.id, dropped),
            (BadHot::Missing, ArchiveCopy::Valid(a)) => self.promote(row, rel, a),
            (BadHot::Missing, ArchiveCopy::Invalid) => {
                if self.quarantined(Tier::Archive, rel) {
                    self.drop_row(row.id, dropped)
                } else {
                    Outcome::Unverified
                }
            }
            (BadHot::WrongSize, ArchiveCopy::None) => {
                if self.quarantined(Tier::Hot, rel) {
                    self.drop_row(row.id, dropped)
                } else {
                    Outcome::Unverified
                }
            }
            (BadHot::WrongSize, ArchiveCopy::Valid(a)) => {
                let out = self.promote(row, rel, a);
                if out == Outcome::RolledForward {
                    // The archive copy is now the row's; H is quarantined, never deleted.
                    let _ = self.quarantined(Tier::Hot, rel);
                }
                out
            }
            (BadHot::WrongSize, ArchiveCopy::Invalid) => {
                if self.quarantined(Tier::Hot, rel) && self.quarantined(Tier::Archive, rel) {
                    self.drop_row(row.id, dropped)
                } else {
                    Outcome::Unverified
                }
            }
        }
    }

    /// Evaluate `A/R` with the same `O_NONBLOCK` open. "None" is ENOENT and nothing else.
    fn archive_copy(&self, row: &IndexedSegment, rel: &Rel) -> ArchiveCopy {
        match self.fs.open_read(Tier::Archive, &rel.comps()) {
            Ok(o) if o.len == row.record.bytes => ArchiveCopy::Valid(o),
            Ok(_) => ArchiveCopy::Invalid,
            Err(e) if e.is_not_found() => ArchiveCopy::None,
            Err(_) => ArchiveCopy::Unverified,
        }
    }

    /// Make a valid archive copy the row's tier: fsync the file and its directory first
    /// (durability before the only copy), then `set_tier`.
    fn promote(&self, row: &IndexedSegment, rel: &Rel, mut a: Opened) -> Outcome {
        if a.file.sync().is_err() || self.fs.sync_dir(Tier::Archive, &rel.dir()).is_err() {
            return Outcome::Unverified;
        }
        match self.index.set_tier(row.id, Tier::Archive) {
            Ok(()) => Outcome::RolledForward,
            Err(_) => Outcome::IndexError,
        }
    }

    /// Delete segment `id`: unlink the hot copy, then the archive copy (when the archive is
    /// available), fsync each parent directory, then remove the row.
    ///
    /// **The twin check runs first**, before anything is unlinked, so an error there never
    /// leaves an unlinked file behind a kept row. The twin is the file of the same row on the
    /// other tier (when that tier is in play): a missing one is nothing to delete; one of the
    /// wrong size is quarantined and left alone (a failure to quarantine is `DeleteFailed`); a
    /// non-regular object (`NotRegular`), a symlink (`ELOOP`) or a regular file planted where a
    /// directory of the twin's path should be (`ENOTDIR`) is not a segment: it is left alone,
    /// counted as [`Outcome::DeletedTwinLeft`], and never pins the row. Any other error is
    /// `DeleteFailed` and nothing was unlinked.
    pub(crate) fn delete_segment(&self, id: SegmentId, archive_available: bool) -> Outcome {
        let row = match self.index.get(id) {
            Err(_) => return Outcome::IndexError,
            Ok(None) => return Outcome::Skipped(Skip::NoRow),
            Ok(Some(r)) => r,
        };
        let Some(rel) = Rel::of(&row) else {
            return Outcome::Skipped(Skip::BadRow);
        };
        if row.tier == Tier::Archive && !archive_available {
            // Archive rows and files are not touched while the archive is unavailable.
            return Outcome::Skipped(Skip::ArchiveUnavailable);
        }
        let tiers: &[Tier] = if archive_available {
            &[Tier::Hot, Tier::Archive]
        } else {
            &[Tier::Hot]
        };
        // First look at the twin on the other tier, before anything is unlinked: an error there
        // must never leave an unlinked file behind a kept row.
        let other = if row.tier == Tier::Hot {
            Tier::Archive
        } else {
            Tier::Hot
        };
        let mut twin_left = false;
        let mut skip_other = false;
        if tiers.contains(&other) {
            match self.fs.open_read(other, &rel.comps()) {
                Ok(o) if o.len == row.record.bytes => drop(o),
                Ok(o) => {
                    // A wrong-size twin is an invalid file: quarantined, never deleted (section 9).
                    drop(o);
                    if !self.quarantined(other, &rel) {
                        return Outcome::DeleteFailed;
                    }
                    skip_other = true;
                }
                Err(e) if e.is_not_found() => {}
                // A symlink (ELOOP) or another non-regular object is not a segment and cannot be
                // quarantined: it is left where it is, counted, and never pins the row.
                Err(FsError::NotRegular) => {
                    twin_left = true;
                    skip_other = true;
                }
                // A regular file where a directory of the twin's path should be (ENOTDIR) is the
                // same: a planted object, not a segment.
                Err(e) if matches!(e.errno(), Some(Errno::LOOP | Errno::NOTDIR)) => {
                    twin_left = true;
                    skip_other = true;
                }
                Err(_) => return Outcome::DeleteFailed,
            }
        }
        for &tier in tiers {
            if tier == other && skip_other {
                continue;
            }
            // ENOENT or ENOTDIR (a planted file where a directory should be): no file can exist.
            match self.fs.unlink(tier, &rel.dir(), &rel.name) {
                Ok(()) => {}
                Err(e) if gone(&e) => {}
                Err(_) => return Outcome::DeleteFailed,
            }
            // Before the row goes, so a power cut cannot bring the file back after the DELETE.
            match self.fs.sync_dir(tier, &rel.dir()) {
                Ok(()) => {}
                Err(e) if gone(&e) => {}
                Err(_) => return Outcome::DeleteFailed,
            }
        }
        match self.index.delete(id) {
            Ok(()) if twin_left => Outcome::DeletedTwinLeft,
            Ok(()) => Outcome::Deleted,
            Err(_) => Outcome::IndexError,
        }
    }
}

/// The file cannot exist: `ENOENT`, or `ENOTDIR` (a regular file planted where one of its
/// directories should be), so a planted object never pins a row.
fn gone(e: &FsError) -> bool {
    e.is_not_found() || e.errno() == Some(Errno::NOTDIR)
}
