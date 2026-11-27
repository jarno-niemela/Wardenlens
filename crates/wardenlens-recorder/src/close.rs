//! Closing a segment: the sequence of ADR 0005 section 3.

use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};

use crate::fault::IndexFault;
use crate::health::RecorderState;
use crate::recorder::Recorder;
use crate::store::SegmentStore;

impl<S: SegmentStore, I: SegmentIndex> Recorder<S, I>
where
    I::Error: IndexFault,
{
    /// Closes the open segment whose record the segmenter gave:
    /// (1) the last fragment, (2) the duration patched into `mvhd` and `mehd` with `pwrite`,
    /// (3) fsync of the file, (4) rename `.part` to `.mp4` without replacing, (5) fsync of the
    /// directory, (6) only then `Index::insert`. A failure in steps 1 to 5 removes the `.part`;
    /// it never leaves a visible `.mp4` that is incomplete.
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
            self.health.state = RecorderState::Waiting;
            return;
        };
        let key = open.key;
        match self.store.commit(open.writer, &patch) {
            Ok(len) => {
                // The row carries the key actually used (after any 1 ms bump) and the size of the
                // file, which reconciliation compares (ADR 0005 section 9).
                let row = SegmentRecord::new(
                    self.camera.clone(),
                    key,
                    record.duration_ms,
                    len,
                    record.frame_count,
                );
                self.index_segment(&row);
            }
            Err(e) => {
                self.health.segments_aborted = self.health.segments_aborted.saturating_add(1);
                self.note_full(&e);
                self.set_hold(Self::hold_for(&e));
            }
        }
    }

    /// `Index::insert`. A transient error (busy, I/O) is retried up to `insert_retries` times
    /// with a growing pause; the file is quarantined only on a constraint or permanent error.
    /// When the retries run out the finished file stays where it is: reconciliation adopts a
    /// `.mp4` without a row (ADR 0005 section 9).
    fn index_segment(&mut self, row: &SegmentRecord) {
        let mut attempt = 0u32;
        loop {
            match self.index.insert(row, Tier::Hot) {
                Ok(_) => {
                    self.health.segments_indexed = self.health.segments_indexed.saturating_add(1);
                    return;
                }
                Err(e) if e.is_transient() => {
                    if attempt >= self.config.insert_retries {
                        self.health.segments_unindexed =
                            self.health.segments_unindexed.saturating_add(1);
                        return;
                    }
                    attempt = attempt.saturating_add(1);
                    let pause = self.config.retry_backoff.saturating_mul(attempt);
                    if !pause.is_zero() {
                        std::thread::sleep(pause);
                    }
                }
                Err(_) => {
                    match self.store.quarantine(row.started_at_ms) {
                        Ok(()) => {
                            self.health.segments_quarantined =
                                self.health.segments_quarantined.saturating_add(1);
                        }
                        Err(_) => {
                            // Left in place: the next start's reconciliation judges it.
                            self.health.segments_unindexed =
                                self.health.segments_unindexed.saturating_add(1);
                        }
                    }
                    return;
                }
            }
        }
    }
}
