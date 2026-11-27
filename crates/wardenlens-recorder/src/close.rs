//! Closing a segment: the sequence of ADR 0005 section 3.

use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier, TransientFault};

use crate::probe::find_row;
use crate::recorder::Recorder;
use crate::store::SegmentStore;

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
                self.index_segment(&row);
            }
            Err(e) => {
                self.health.segments_aborted = self.health.segments_aborted.saturating_add(1);
                self.note_store_error(&e, bytes);
            }
        }
    }

    /// Whether the index holds exactly this segment: same key, size, duration and frames.
    fn row_matches(&self, row: &SegmentRecord) -> bool {
        find_row(&self.index, &self.camera, row.started_at_ms)
            .ok()
            .flatten()
            .is_some_and(|f| {
                let r = &f.record;
                r.bytes == row.bytes
                    && r.duration_ms == row.duration_ms
                    && r.frame_count == row.frame_count
            })
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
    fn index_segment(&mut self, row: &SegmentRecord) {
        let mut attempt = 0u32;
        loop {
            match self.index.insert(row, Tier::Hot) {
                Ok(_) => return self.count_indexed(),
                Err(e) if e.is_transient() => {
                    if attempt >= self.config.insert_retries {
                        if self.row_matches(row) {
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
                    if attempt > 0 && self.row_matches(row) {
                        return self.count_indexed();
                    }
                    match self.store.quarantine(row.started_at_ms) {
                        Ok(()) => {
                            self.health.segments_quarantined =
                                self.health.segments_quarantined.saturating_add(1);
                        }
                        // Left in place (every name taken, or the move failed): the next
                        // start's reconciliation judges it.
                        Err(_) => self.count_unindexed(),
                    }
                    return;
                }
            }
        }
    }
}
