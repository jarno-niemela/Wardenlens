//! Starting a segment and writing its fragments.

use wardenlens_core::recording::Pushed;
use wardenlens_core::storage::{SegmentIndex, TransientFault};
use wardenlens_core::time::UnixMs;
use wardenlens_core::video::Frame;
use wardenlens_mp4::Mp4Error;

use crate::keys::KeyError;
use crate::pending::Pending;
use crate::probe::{Unknown, key_taken};
use crate::recorder::{Open, Recorder};
use crate::state::FullHold;
use crate::store::{SegmentStore, StoreError};

/// How often `create` is retried with the next key when its name turned out to be taken.
const CREATE_TRIES: u32 = 8;

/// Why a fragment could not be written.
pub(crate) enum FlushError {
    Store(StoreError),
    /// The muxer refused the samples: a malformed frame, not a file problem.
    Mp4,
}

impl From<StoreError> for FlushError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<Mp4Error> for FlushError {
    fn from(_: Mp4Error) -> Self {
        Self::Mp4
    }
}

impl<S: SegmentStore, I: SegmentIndex> Recorder<S, I>
where
    I::Error: TransientFault + std::error::Error + Send + Sync + 'static,
{
    /// The frame starts a new segment (a keyframe, the previous segment is already closed).
    pub(crate) fn begin(&mut self, frame: Frame, arrival: UnixMs) {
        let Some(init) = self.params.as_ref().map(|a| a.init.clone()) else {
            self.cond.params = true;
            self.fail_start();
            return;
        };
        if !self.volume_ready() {
            self.hold_start();
            return;
        }
        let mut from = arrival;
        for _ in 0..CREATE_TRIES {
            let (camera, store, index) = (&self.camera, &mut self.store, &self.index);
            let picked = self.keys.pick(from, |k| key_taken(store, index, camera, k));
            let picked = match picked {
                Ok(p) => p,
                Err(KeyError::OutOfRange) => {
                    self.cond.clock = true;
                    self.fail_start();
                    return;
                }
                Err(KeyError::Probe(who)) => {
                    match who {
                        Unknown::Store => self.cond.write = true,
                        Unknown::Index => self.cond.index = true,
                    }
                    self.fail_start();
                    return;
                }
                Err(KeyError::Exhausted) => {
                    self.cond.write = true;
                    self.fail_start();
                    return;
                }
            };
            match self.store.create(picked.key, init.bytes()) {
                Ok(writer) => {
                    if picked.stepped_back {
                        self.health.clock_stepped_back =
                            self.health.clock_stepped_back.saturating_add(1);
                    }
                    let mut pending = Pending::default();
                    pending.push(frame.data, 0, frame.is_keyframe);
                    self.cond.full = None;
                    self.cond.write = false;
                    self.cond.index = false;
                    self.open = Some(Open {
                        writer,
                        bytes_written: u64::try_from(init.bytes().len()).unwrap_or(u64::MAX),
                        init,
                        key: picked.key,
                        pending,
                        sequence: 1,
                        written_ticks: 0,
                        last_dts: 0,
                        last_step: 1,
                    });
                    return;
                }
                Err(StoreError::NameTaken) => {
                    // Lost a race for the name: the next key.
                    let next = picked.key.as_i64().checked_add(1).map(UnixMs::new);
                    let Some(Ok(next)) = next else {
                        self.cond.clock = true;
                        self.fail_start();
                        return;
                    };
                    from = next;
                }
                Err(e) => {
                    self.note_store_error(&e, 0);
                    self.fail_start();
                    return;
                }
            }
        }
        self.cond.write = true;
        self.fail_start();
    }

    /// After a full volume a segment is only tried again when the back-off is over and the
    /// volume has the space (see [`FullHold`]).
    fn volume_ready(&mut self) -> bool {
        let Some(mut hold) = self.cond.full else {
            return true;
        };
        let available = self.store.available_bytes().ok();
        let ready = hold.may_try(available);
        self.cond.full = Some(hold);
        ready
    }

    /// A segment could not be started: the segmenter forgets it (the next keyframe tries
    /// again), and the frame is not written.
    fn fail_start(&mut self) {
        self.health.segments_aborted = self.health.segments_aborted.saturating_add(1);
        self.hold_start();
    }

    /// As [`Self::fail_start`] for a start that was put off, not attempted: nothing is aborted.
    fn hold_start(&mut self) {
        self.segmenter.finish();
        self.drop_frame();
    }

    /// Records a failed file operation as a condition. A full volume starts (or lengthens) the
    /// back-off and remembers how much the aborted segment had written.
    pub(crate) fn note_store_error(&mut self, e: &StoreError, aborted_bytes: u64) {
        if matches!(e, StoreError::NoSpace) {
            self.full_failures = self.full_failures.saturating_add(1);
            self.cond.full = Some(FullHold::new(
                self.full_failures,
                aborted_bytes,
                self.config.resume_free_bytes,
            ));
        } else {
            self.cond.write = true;
        }
    }

    /// Appends a frame to the open segment, writing the open fragment first when the segmenter
    /// says so (a keyframe or the fragment cap) or the sample table is full.
    pub(crate) fn append(&mut self, frame: Frame, pushed: &Pushed) {
        let Some(mut open) = self.open.take() else {
            // The segmenter and the recorder disagree: forget the stream.
            self.segmenter.finish();
            self.drop_frame();
            return;
        };
        let Some(dts) = pushed.dts else {
            self.segmenter.finish();
            self.abort_segment(open);
            self.drop_frame();
            return;
        };
        if (pushed.flush_fragment || open.pending.is_full())
            && let Err(e) = self.flush(&mut open, Some(dts))
        {
            self.segmenter.finish();
            self.abort_for(open, &e);
            return;
        }
        open.last_step = dts.saturating_sub(open.last_dts).max(1);
        open.last_dts = dts;
        open.pending.push(frame.data, dts, frame.is_keyframe);
        self.open = Some(open);
    }

    /// Writes the open fragment. `next_dts` is the first sample of the next fragment, `None`
    /// when the segment ends.
    pub(crate) fn flush(
        &mut self,
        open: &mut Open<S::Writer>,
        next_dts: Option<u64>,
    ) -> Result<(), FlushError> {
        if open.pending.is_empty() {
            return Ok(());
        }
        let ticks = open.pending.encode(
            open.sequence,
            open.written_ticks,
            next_dts,
            open.last_step,
            &mut self.scratch,
        )?;
        self.store.append(&mut open.writer, &self.scratch)?;
        open.bytes_written = open
            .bytes_written
            .saturating_add(u64::try_from(self.scratch.len()).unwrap_or(u64::MAX));
        open.written_ticks = open.written_ticks.saturating_add(ticks);
        open.sequence = open.sequence.saturating_add(1);
        Ok(())
    }

    /// Throws the open segment away after a failed write (the caller has made the segmenter
    /// forget the stream) and records why.
    pub(crate) fn abort_for(&mut self, open: Open<S::Writer>, e: &FlushError) {
        match e {
            FlushError::Store(s) => self.note_store_error(s, open.bytes_written),
            FlushError::Mp4 => {
                self.health.stream_errors = self.health.stream_errors.saturating_add(1);
            }
        }
        self.abort_segment(open);
    }

    /// Removes the `.part` and counts the segment as aborted.
    pub(crate) fn abort_segment(&mut self, open: Open<S::Writer>) {
        self.store.abort(open.writer);
        self.health.segments_aborted = self.health.segments_aborted.saturating_add(1);
    }
}
