//! Closing a segment: the sequence of ADR 0005 section 3.

use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier, TransientFault};

use crate::probe::find_row;
use crate::recorder::Recorder;
use crate::store::SegmentStore;

/// The index's answer for one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadBack {
    /// A row with the same key, size, duration and frames.
    Match,
    /// No row at the key.
    NoRow,
    /// A row at the key that is another segment.
    Differs,
    /// The index could not say.
    Unknown,
}

impl<S: SegmentStore, I: SegmentIndex> Recorder<S, I>
where
    I::Error: TransientFault + std::error::Error + Send + Sync + 'static,
{
    /// Closes the open segment whose record the segmenter gave:
    /// (1) the last fragment, (2) the duration patched into `mvhd` and `mehd` with `pwrite`,
    /// (3) fsync of the file, (4) rename `.part` to `.mp4` without replacing, (5) fsync of the
    /// directory, (6) only then `Index::insert`. A failure in steps 1 to 4 removes the `.part`;
    /// it never leaves a visible `.mp4` that is incomplete. A failure of step 5 keeps the
    /// finished file but does not index it (it may not survive a crash).
    pub(crate) fn finalize(&mut self, record: &SegmentRecord) {
        let Some(mut open) = self.open.take() else {
            return;
        };
        if let Err(e) = self.flush(&mut open, None) {
            self.abort_for(open, &e);
            return;
        }
        let Ok(patch) = open.init.duration_patch(open.written_ticks) else {
            // A segment is at most 580 s, far below the 32-bit field: not reachable.
            self.health.stream_errors = self.health.stream_errors.saturating_add(1);
            self.abort_segment(open);
            return;
        };
        let bytes = open.bytes_written;
        let open_key = open.key;
        match self.store.commit(open.writer, &patch) {
            Ok(sealed) => {
                self.keys.note(sealed.key);
                self.full_failures = 0;
                if !sealed.durable {
                    self.health.segments_unindexed =
                        self.health.segments_unindexed.saturating_add(1);
                    return;
                }
                // The row carries the key actually used (after any 1 ms bump) and the size of the
                // file, which reconciliation compares (ADR 0005 section 9).
                let row = SegmentRecord::new(
                    self.camera.clone(),
                    sealed.key,
                    record.duration_ms,
                    sealed.len,
                    record.frame_count,
                );
                self.index_segment(&row, sealed.key != open_key);
            }
            Err(e) => {
                self.health.segments_aborted = self.health.segments_aborted.saturating_add(1);
                self.note_store_error(&e, bytes);
            }
        }
    }

    /// What the index says about this segment's key. `Unknown` means the question could not be
    /// answered (a read error, too many overlapping rows): it is never read as "no row".
    fn read_back(&self, row: &SegmentRecord) -> ReadBack {
        match find_row(&self.index, &self.camera, row.started_at_ms) {
            Err(_) => ReadBack::Unknown,
            Ok(None) => ReadBack::NoRow,
            Ok(Some(f)) => {
                let r = &f.record;
                if r.bytes == row.bytes
                    && r.duration_ms == row.duration_ms
                    && r.frame_count == row.frame_count
                {
                    ReadBack::Match
                } else {
                    ReadBack::Differs
                }
            }
        }
    }

    /// Moves the file to quarantine; left in place (and counted unindexed) when that fails or
    /// every name is taken.
    fn quarantine(&mut self, row: &SegmentRecord) {
        match self.store.quarantine(row.started_at_ms) {
            Ok(()) => {
                self.health.segments_quarantined =
                    self.health.segments_quarantined.saturating_add(1);
            }
            Err(_) => self.count_unindexed(),
        }
    }

    fn count_unindexed(&mut self) {
        self.health.segments_unindexed = self.health.segments_unindexed.saturating_add(1);
    }

    fn count_indexed(&mut self) {
        self.health.segments_indexed = self.health.segments_indexed.saturating_add(1);
    }

    /// `Index::insert`. A transient error (busy, I/O) is retried up to `insert_retries` times
    /// with a growing pause; the file is quarantined only on a constraint or permanent error.
    ///
    /// A transient error can follow a commit (SQLite's checkpoint inside `COMMIT` may fail
    /// after the row is durable), so the retry then meets its own row as a duplicate. After any
    /// transient failure the row is therefore read back, and a matching row counts as indexed;
    /// the file is quarantined only when no such row exists. When the retries run out the
    /// finished file stays where it is (reconciliation adopts a `.mp4` without a row, ADR 0005
    /// section 9), unless the read-back finds the row.
    fn index_segment(&mut self, row: &SegmentRecord, bumped: bool) {
        let mut attempt = 0u32;
        loop {
            match self.index.insert(row, Tier::Hot) {
                Ok(_) => return self.count_indexed(),
                Err(e) if e.is_transient() => {
                    if attempt >= self.config.insert_retries {
                        if self.read_back(row) == ReadBack::Match {
                            self.count_indexed();
                        } else {
                            self.count_unindexed();
                        }
                        return;
                    }
                    attempt = attempt.saturating_add(1);
                    let pause = self.config.retry_backoff.saturating_mul(attempt);
                    if !pause.is_zero() {
                        std::thread::sleep(pause);
                    }
                }
                Err(_) => {
                    // A transient failure may have followed the commit, and a bumped key may
                    // be held by another row: ask the index before judging the file.
                    let seen = if attempt > 0 || bumped {
                        self.read_back(row)
                    } else {
                        ReadBack::NoRow
                    };
                    match seen {
                        ReadBack::Match => self.count_indexed(),
                        // Never quarantine on an answer that was not given.
                        ReadBack::Unknown => self.count_unindexed(),
                        // The key belongs to another row: this good file is left for
                        // reconciliation, not moved.
                        ReadBack::Differs if bumped => self.count_unindexed(),
                        ReadBack::Differs | ReadBack::NoRow => self.quarantine(row),
                    }
                    return;
                }
            }
        }
    }
}
