//! Starting a segment and writing its fragments.

use wardenlens_core::recording::Pushed;
use wardenlens_core::storage::{MAX_LIST_LIMIT, SegmentIndex};
use wardenlens_core::time::{DurationMs, Timestamp, UnixMs};
use wardenlens_ingest::Frame;
use wardenlens_mp4::Mp4Error;

use crate::fault::IndexFault;
use crate::health::{HoldReason, RecorderState};
use crate::keys::KeyError;
use crate::pending::Pending;
use crate::recorder::{Open, Recorder};
use crate::store::{SegmentStore, StoreError};

/// How often `create` is retried with the next key when its name turned out to be taken.
const CREATE_TRIES: u32 = 8;
/// Pages of overlapping rows read when probing a key; more than this and the key counts as taken.
const PROBE_PAGES: usize = 4;

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

/// A probe that could not answer: the key is never assumed free.
struct ProbeFailed;

/// Whether a segment of `camera` with this `started_at_ms` exists: a file on the hot volume or a
/// row. A row starting at `key` overlaps `[key, key + 1)`, so the listing finds it.
fn key_taken<S: SegmentStore, I: SegmentIndex>(
    store: &mut S,
    index: &I,
    camera: &wardenlens_core::camera::CameraId,
    key: UnixMs,
) -> Result<bool, ProbeFailed> {
    if store.key_taken(key).map_err(|_| ProbeFailed)? {
        return Ok(true);
    }
    let from = Timestamp::from(key);
    let to = from.saturating_add(DurationMs::from_millis(1));
    let mut cursor = None;
    for _ in 0..PROBE_PAGES {
        let page = index
            .list(camera, from, to, MAX_LIST_LIMIT, cursor.as_ref())
            .map_err(|_| ProbeFailed)?;
        if page.items.iter().any(|s| s.record.started_at_ms == key) {
            return Ok(true);
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => return Ok(false),
        }
    }
    Ok(true)
}

impl<S: SegmentStore, I: SegmentIndex> Recorder<S, I>
where
    I::Error: IndexFault,
{
    /// The frame starts a new segment (a keyframe, the previous segment is already closed).
    pub(crate) fn begin(&mut self, frame: Frame, arrival: UnixMs) {
        let Some(init) = self.params.as_ref().map(|a| a.init.clone()) else {
            self.fail_start(HoldReason::BadParameters);
            return;
        };
        if self.awaiting_space && !self.space_returned() {
            self.hold_start(HoldReason::StorageFull);
            return;
        }
        let mut from = arrival;
        for _ in 0..CREATE_TRIES {
            let (camera, store, index) = (&self.camera, &mut self.store, &self.index);
            let picked = self.keys.pick(from, |k| key_taken(store, index, camera, k));
            let picked = match picked {
                Ok(p) => p,
                Err(KeyError::OutOfRange) => {
                    self.fail_start(HoldReason::ClockOutOfRange);
                    return;
                }
                Err(KeyError::Probe(_) | KeyError::Exhausted) => {
                    self.fail_start(HoldReason::WriteFailed);
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
                    self.awaiting_space = false;
                    self.health.state = RecorderState::Recording;
                    self.open = Some(Open {
                        writer,
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
                        self.fail_start(HoldReason::ClockOutOfRange);
                        return;
                    };
                    from = next;
                }
                Err(e) => {
                    self.fail_start(Self::hold_for(&e));
                    self.note_full(&e);
                    return;
                }
            }
        }
        self.fail_start(HoldReason::WriteFailed);
    }

    /// A segment could not be started: the segmenter forgets it (the next keyframe tries again),
    /// the state says why, and the frame is not written.
    fn fail_start(&mut self, reason: HoldReason) {
        self.health.segments_aborted = self.health.segments_aborted.saturating_add(1);
        self.hold_start(reason);
    }

    /// As [`Self::fail_start`] for a start that was put off, not attempted: nothing is aborted.
    fn hold_start(&mut self, reason: HoldReason) {
        self.segmenter.finish();
        self.health.frames_dropped = self.health.frames_dropped.saturating_add(1);
        self.set_hold(reason);
    }

    /// Whether the volume has room again. A volume that cannot be queried is tried anyway.
    fn space_returned(&mut self) -> bool {
        self.store
            .available_bytes()
            .map_or(true, |n| n >= self.config.resume_free_bytes)
    }

    pub(crate) fn hold_for(e: &StoreError) -> HoldReason {
        match e {
            StoreError::NoSpace => HoldReason::StorageFull,
            _ => HoldReason::WriteFailed,
        }
    }

    pub(crate) fn note_full(&mut self, e: &StoreError) {
        if matches!(e, StoreError::NoSpace) {
            self.awaiting_space = true;
        }
    }

    /// Appends a frame to the open segment, writing the open fragment first when the segmenter
    /// says so (a keyframe or the fragment cap) or the sample table is full.
    pub(crate) fn append(&mut self, frame: Frame, pushed: &Pushed) {
        let (Some(dts), Some(mut open)) = (pushed.dts, self.open.take()) else {
            // The segmenter and the recorder disagree: forget the stream, keep nothing unverified.
            self.close_open();
            self.health.frames_dropped = self.health.frames_dropped.saturating_add(1);
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
        open.written_ticks = open.written_ticks.saturating_add(ticks);
        open.sequence = open.sequence.saturating_add(1);
        Ok(())
    }

    /// Throws the open segment away after a failed write (the caller has made the segmenter
    /// forget the stream) and records why.
    pub(crate) fn abort_for(&mut self, open: Open<S::Writer>, e: &FlushError) {
        match e {
            FlushError::Store(s) => {
                self.note_full(s);
                self.set_hold(Self::hold_for(s));
            }
            FlushError::Mp4 => {
                self.health.stream_errors = self.health.stream_errors.saturating_add(1);
                self.health.state = RecorderState::Waiting;
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
