//! The per-key decision tables of ADR 0005 section 9: one match arm per cell.
//!
//! A key is `(camera, started_at)`. Its hot file `H`, archive file `A` and row `R` are looked at
//! together and exactly one cell applies. Every step that can fail leaves the key as it was found
//! and counts it `unverified`; no step deletes an invalid file.

use rustix::io::Errno;
use wardenlens_core::mp4box::Mp4Summary;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{IndexedSegment, SegmentIndex, Tier};
use wardenlens_fsutil::{FsError, QuarantineOutcome};

use super::adopt::{Parsed, parse};
use super::{Mode, Reconciler, bump};
use crate::fs::{Fs, Opened, same_bytes};
use crate::index::Rel;

/// Insert attempts before an adoption gives up and quarantines the file. The port's error does
/// not say whether it was transient, so every failure gets the same bounded retries (section 3:
/// never an unbounded loop).
pub(crate) const ADOPT_INSERT_ATTEMPTS: u32 = 3;

/// A file that was looked at and is a regular file the key can rely on.
struct Valid {
    file: Opened,
    /// Present for a file without a row: what the adoption parser found.
    summary: Option<Mp4Summary>,
}

/// What one copy (H or A) of a key is.
enum Seen {
    /// `ENOENT` and nothing else.
    Absent,
    Valid(Valid),
    /// A regular file that is not valid.
    Invalid,
    /// No conclusion (an error other than `ENOENT`, a non-regular object, an unreadable file).
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Absent,
    Valid,
    Invalid,
}

impl Seen {
    const fn kind(&self) -> Option<Kind> {
        match self {
            Self::Absent => Some(Kind::Absent),
            Self::Valid(_) => Some(Kind::Valid),
            Self::Invalid => Some(Kind::Invalid),
            Self::Blocked => None,
        }
    }

    fn valid(self) -> Option<Valid> {
        match self {
            Self::Valid(v) => Some(v),
            _ => None,
        }
    }
}

impl<F: Fs, I: SegmentIndex> Reconciler<'_, F, I> {
    /// Look at one copy. With a row it is valid when its size is the row's `bytes`; without one
    /// when the adoption parser accepts it.
    fn see(&mut self, tier: Tier, rel: &Rel, row: Option<&IndexedSegment>) -> Seen {
        match self.fs.open_read(tier, &rel.comps()) {
            Ok(mut file) => match row {
                Some(r) if file.len == r.record.bytes => Seen::Valid(Valid {
                    file,
                    summary: None,
                }),
                Some(_) => {
                    bump(&mut self.report.size_mismatch);
                    Seen::Invalid
                }
                None => match parse(&mut file) {
                    Parsed::Valid(s) => Seen::Valid(Valid {
                        file,
                        summary: Some(s),
                    }),
                    Parsed::Invalid => Seen::Invalid,
                    Parsed::Unreadable => Seen::Blocked,
                },
            },
            Err(e) if e.is_not_found() => Seen::Absent,
            Err(FsError::NotRegular) => {
                bump(&mut self.report.unknown_left);
                Seen::Blocked
            }
            // A symlink at the segment name: not a segment, never followed.
            Err(e) if e.errno() == Some(Errno::LOOP) => {
                bump(&mut self.report.unknown_left);
                Seen::Blocked
            }
            Err(_) => Seen::Blocked,
        }
    }

    /// Decide one key. `hot_gate` is set by the "archive returned" pass for a `tier = hot` row
    /// that has no archive file: it is evaluated only when its hot file is missing.
    pub(crate) fn key(&mut self, rel: &Rel, row: Option<&IndexedSegment>, hot_gate: bool) {
        let returned = self.mode == Mode::Returned;
        // The returned pass never looks at H for a key without a row: the recorder may be in
        // the window between its rename and its insert.
        let h = if hot_gate {
            // Out of scope unless the hot file is missing (ENOENT and nothing else). Looking at
            // it counts nothing: not a size mismatch, not `unknown_left`, not `unverified`.
            match self.fs.open_read(Tier::Hot, &rel.comps()) {
                Err(e) if e.is_not_found() => Some(Seen::Absent),
                _ => return,
            }
        } else if returned && row.is_none() {
            None
        } else {
            Some(self.see(Tier::Hot, rel, row))
        };
        let a = self.archive.then(|| self.see(Tier::Archive, rel, row));
        let observed = |s: &Option<Seen>| s.as_ref().is_none_or(|s| s.kind().is_some());
        if !(observed(&h) && observed(&a)) {
            bump(&mut self.report.unverified);
            return;
        }
        match (h, a, row) {
            (Some(h), Some(a), Some(r)) => self.rowed(rel, r, h, a),
            (Some(h), Some(a), None) => self.unrowed(rel, h, a),
            (Some(h), None, row) => self.unavailable(rel, row, h),
            (None, Some(a), None) => self.returned_orphan(rel, a),
            (None, _, _) => {}
        }
    }

    // ---- the steps ----------------------------------------------------------------------------

    /// Quarantine the file of `tier`. `false` when it could not be moved (an exhausted bound or
    /// an error): it stays in place and the key is `unverified`.
    fn quarantine(&mut self, tier: Tier, rel: &Rel) -> bool {
        // An exhausted bound leaves the file in place (nothing is overwritten), and so does an
        // error: the key is `unverified`.
        if let Ok(QuarantineOutcome::Moved { .. }) = self.fs.quarantine(tier, &rel.comps()) {
            bump(&mut self.report.quarantined);
            true
        } else {
            bump(&mut self.report.unverified);
            false
        }
    }

    /// The row goes. `false` on an index failure.
    fn drop_row(&mut self, row: &IndexedSegment) -> bool {
        if self.index.delete(row.id).is_ok() {
            true
        } else {
            self.index_failed();
            false
        }
    }

    pub(super) fn index_failed(&mut self) {
        bump(&mut self.report.index_errors);
        bump(&mut self.report.unverified);
    }

    /// Make a surviving copy durable (the file and its directory) before an index write turns it
    /// into the only copy or a twin is deleted.
    fn durable(&mut self, tier: Tier, rel: &Rel, file: &mut Opened) -> bool {
        if file.file.sync().is_ok() && self.fs.sync_dir(tier, &rel.dir()).is_ok() {
            true
        } else {
            bump(&mut self.report.unverified);
            false
        }
    }

    /// The copy of `tier` is the truth: make it durable, then point the row at it.
    fn point_row(&mut self, row: &IndexedSegment, tier: Tier, rel: &Rel, mut copy: Valid) -> bool {
        if !self.durable(tier, rel, &mut copy.file) {
            return false;
        }
        if self.index.set_tier(row.id, tier).is_ok() {
            true
        } else {
            self.index_failed();
            false
        }
    }

    /// Delete a valid twin (never an invalid file). The directory is synced afterwards, best
    /// effort: correctness does not depend on it.
    fn delete_twin(&mut self, tier: Tier, rel: &Rel) {
        match self.fs.unlink(tier, &rel.dir(), &rel.name) {
            Ok(()) => {
                let _ = self.fs.sync_dir(tier, &rel.dir());
                bump(&mut self.report.duplicates_deleted);
            }
            Err(e) if e.is_not_found() => {}
            Err(_) => bump(&mut self.report.unverified),
        }
    }

    /// The hot copy `H` of a key whose archive copy `A` is valid. Both have the size the row (or
    /// the adoption) gives, but a name is not an identity: a file at the same key may be a
    /// different recording (the recorder bumped its key onto a name another row held, #195). So
    /// `H` is deleted only when it is a byte-identical copy of `A`; a file that is not is
    /// quarantined (never deleted) and counted `foreign_twins`, a health error. When the bytes
    /// could not be compared nothing is deleted and the key is `unverified`.
    fn settle_hot_twin(&mut self, rel: &Rel, h: &mut Opened, a: &mut Opened) {
        match same_bytes(h, a) {
            Some(true) => self.delete_twin(Tier::Hot, rel),
            Some(false) => {
                bump(&mut self.report.foreign_twins);
                self.quarantine(Tier::Hot, rel);
            }
            None => bump(&mut self.report.unverified),
        }
    }

    /// Adopt a valid file of `tier` that has no row: fsync it and its directory, then insert the
    /// row. Any insert failure (after the bounded attempts) quarantines the file. `false` when
    /// no row was added.
    fn adopt(&mut self, tier: Tier, rel: &Rel, mut copy: Valid) -> bool {
        let Some(summary) = copy.summary else {
            bump(&mut self.report.unverified);
            return false;
        };
        if !self.durable(tier, rel, &mut copy.file) {
            return false;
        }
        let record = SegmentRecord::new(
            rel.camera_id.clone(),
            rel.started,
            summary.duration_ms,
            copy.file.len,
            summary.frame_count,
        );
        for _ in 0..ADOPT_INSERT_ATTEMPTS {
            if self.index.insert(&record, tier).is_ok() {
                bump(&mut self.report.adopted);
                return true;
            }
        }
        // A constraint violation or a permanent error: the file is kept, out of the index.
        bump(&mut self.report.index_errors);
        self.quarantine(tier, rel);
        false
    }

    // ---- the cells ------------------------------------------------------------------------------

    /// A key without a row, archive observable (the "row none" cells of the 27).
    fn unrowed(&mut self, rel: &Rel, h: Seen, a: Seen) {
        let (hk, ak) = (h.kind(), a.kind());
        let (Some(hk), Some(ak)) = (hk, ak) else {
            return;
        };
        match (hk, ak) {
            (Kind::Absent, Kind::Absent) => {}
            (Kind::Absent, Kind::Valid) => {
                if let Some(a) = a.valid() {
                    self.adopt(Tier::Archive, rel, a);
                }
            }
            (Kind::Absent, Kind::Invalid) => {
                self.quarantine(Tier::Archive, rel);
            }
            (Kind::Valid, Kind::Absent) => {
                if let Some(h) = h.valid() {
                    self.adopt(Tier::Hot, rel, h);
                }
            }
            (Kind::Valid, Kind::Valid) => {
                // Adopt A; H goes only when the two sizes are equal, otherwise it is quarantined.
                if let (Some(mut h), Some(mut a)) = (h.valid(), a.valid()) {
                    // Equal sizes are only a hint: the bytes decide (see `settle_hot_twin`).
                    let sizes = h.file.len == a.file.len;
                    let same = if sizes {
                        same_bytes(&mut h.file, &mut a.file)
                    } else {
                        Some(false)
                    };
                    if self.adopt(Tier::Archive, rel, a) {
                        match same {
                            Some(true) => self.delete_twin(Tier::Hot, rel),
                            Some(false) => {
                                if sizes {
                                    bump(&mut self.report.foreign_twins);
                                }
                                self.quarantine(Tier::Hot, rel);
                            }
                            None => bump(&mut self.report.unverified),
                        }
                    }
                }
            }
            (Kind::Valid, Kind::Invalid) => {
                if let Some(h) = h.valid() {
                    self.adopt(Tier::Hot, rel, h);
                }
                self.quarantine(Tier::Archive, rel);
            }
            (Kind::Invalid, Kind::Absent) => {
                self.quarantine(Tier::Hot, rel);
            }
            (Kind::Invalid, Kind::Valid) => {
                if let Some(a) = a.valid() {
                    self.adopt(Tier::Archive, rel, a);
                }
                self.quarantine(Tier::Hot, rel);
            }
            (Kind::Invalid, Kind::Invalid) => {
                self.quarantine(Tier::Hot, rel);
                self.quarantine(Tier::Archive, rel);
            }
        }
    }

    /// A key with a row, archive observable (the "row hot" and "row archive" cells).
    fn rowed(&mut self, rel: &Rel, row: &IndexedSegment, h: Seen, a: Seen) {
        let (Some(hk), Some(ak)) = (h.kind(), a.kind()) else {
            return;
        };
        match row.tier {
            Tier::Hot => self.row_hot(rel, row, (hk, ak), (h, a)),
            Tier::Archive => self.row_archive(rel, row, (hk, ak), (h, a)),
            // `Tier` is non-exhaustive: a tier this code does not know is no conclusion.
            _ => bump(&mut self.report.unverified),
        }
    }

    fn row_hot(
        &mut self,
        rel: &Rel,
        row: &IndexedSegment,
        kinds: (Kind, Kind),
        (h, a): (Seen, Seen),
    ) {
        match kinds {
            (Kind::Absent, Kind::Absent) => {
                if self.drop_row(row) {
                    bump(&mut self.report.missing);
                }
            }
            (Kind::Absent, Kind::Valid) => {
                if let Some(a) = a.valid()
                    && self.point_row(row, Tier::Archive, rel, a)
                {
                    bump(&mut self.report.rolled_forward);
                }
            }
            (Kind::Absent, Kind::Invalid) => {
                if self.quarantine(Tier::Archive, rel) {
                    self.drop_row(row);
                }
            }
            (Kind::Valid, Kind::Absent) => {}
            (Kind::Valid, Kind::Valid) => {
                // Roll forward (a crash after M6, M7 or before M8): the row first, H last. Only
                // onto an archive copy that is byte-identical to H: the row says the segment is
                // H, so a different A is not this row's recording (#195). Then the row stays on
                // its hot file and A is quarantined, never trusted.
                if let (Some(mut h), Some(mut a)) = (h.valid(), a.valid()) {
                    match same_bytes(&mut h.file, &mut a.file) {
                        Some(true) => {
                            if self.point_row(row, Tier::Archive, rel, a) {
                                bump(&mut self.report.rolled_forward);
                                self.delete_twin(Tier::Hot, rel);
                            }
                        }
                        Some(false) => {
                            bump(&mut self.report.foreign_twins);
                            self.quarantine(Tier::Archive, rel);
                        }
                        None => bump(&mut self.report.unverified),
                    }
                }
            }
            (Kind::Valid, Kind::Invalid) => {
                self.quarantine(Tier::Archive, rel);
            }
            (Kind::Invalid, Kind::Absent) => {
                if self.quarantine(Tier::Hot, rel) {
                    self.drop_row(row);
                }
            }
            (Kind::Invalid, Kind::Valid) => {
                if let Some(a) = a.valid()
                    && self.point_row(row, Tier::Archive, rel, a)
                {
                    bump(&mut self.report.rolled_forward);
                    self.quarantine(Tier::Hot, rel);
                }
            }
            (Kind::Invalid, Kind::Invalid) => {
                let (qh, qa) = (
                    self.quarantine(Tier::Hot, rel),
                    self.quarantine(Tier::Archive, rel),
                );
                if qh && qa {
                    self.drop_row(row);
                }
            }
        }
    }

    fn row_archive(
        &mut self,
        rel: &Rel,
        row: &IndexedSegment,
        kinds: (Kind, Kind),
        (h, a): (Seen, Seen),
    ) {
        match kinds {
            (Kind::Absent, Kind::Absent) => {
                if self.drop_row(row) {
                    bump(&mut self.report.missing);
                }
            }
            (Kind::Absent, Kind::Valid) => {}
            (Kind::Absent, Kind::Invalid) => {
                if self.quarantine(Tier::Archive, rel) {
                    self.drop_row(row);
                }
            }
            (Kind::Valid, Kind::Absent) => {
                // The hot file is the truth: roll the row back to hot.
                if let Some(h) = h.valid()
                    && self.point_row(row, Tier::Hot, rel, h)
                {
                    bump(&mut self.report.rolled_back);
                }
            }
            (Kind::Valid, Kind::Valid) => {
                // A crash after M8, before M9: H goes, after A is durable.
                if let (Some(mut h), Some(mut a)) = (h.valid(), a.valid())
                    && self.durable(Tier::Archive, rel, &mut a.file)
                {
                    self.settle_hot_twin(rel, &mut h.file, &mut a.file);
                }
            }
            (Kind::Valid, Kind::Invalid) => {
                if let Some(h) = h.valid()
                    && self.point_row(row, Tier::Hot, rel, h)
                {
                    bump(&mut self.report.rolled_back);
                    self.quarantine(Tier::Archive, rel);
                }
            }
            (Kind::Invalid, Kind::Absent) => {
                if self.quarantine(Tier::Hot, rel) {
                    self.drop_row(row);
                }
            }
            (Kind::Invalid, Kind::Valid) => {
                self.quarantine(Tier::Hot, rel);
            }
            (Kind::Invalid, Kind::Invalid) => {
                let (qh, qa) = (
                    self.quarantine(Tier::Hot, rel),
                    self.quarantine(Tier::Archive, rel),
                );
                if qh && qa {
                    self.drop_row(row);
                }
            }
        }
    }

    /// The archive cannot be observed: `A` is unknown, not none (the 9 cells). Every archive row
    /// is kept and no archive file is touched.
    fn unavailable(&mut self, rel: &Rel, row: Option<&IndexedSegment>, h: Seen) {
        let Some(hk) = h.kind() else {
            return;
        };
        match (row.map(|r| r.tier), hk) {
            (None, Kind::Absent) | (Some(Tier::Hot | Tier::Archive), Kind::Valid) => {}
            (None, Kind::Valid) => {
                if let Some(h) = h.valid() {
                    self.adopt(Tier::Hot, rel, h);
                }
            }
            (None, Kind::Invalid) => {
                self.quarantine(Tier::Hot, rel);
            }
            (Some(Tier::Hot | Tier::Archive), Kind::Absent) => {
                bump(&mut self.report.unverified);
            }
            (Some(Tier::Hot | Tier::Archive), Kind::Invalid) => {
                self.quarantine(Tier::Hot, rel);
                bump(&mut self.report.unverified);
            }
            (Some(_), _) => bump(&mut self.report.unverified),
        }
    }

    /// The "archive returned" pass, a key without a row: only the archive file is looked at.
    /// A valid one is adopted, an invalid one quarantined; H is never touched (it may be in the
    /// recorder's rename-to-insert window).
    fn returned_orphan(&mut self, rel: &Rel, a: Seen) {
        match a {
            Seen::Valid(v) => {
                self.adopt(Tier::Archive, rel, v);
            }
            Seen::Invalid => {
                self.quarantine(Tier::Archive, rel);
            }
            Seen::Absent | Seen::Blocked => {}
        }
    }
}
