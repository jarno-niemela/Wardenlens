//! [`Recorder`]: one camera's frames in, segments on the hot tier and rows in the index out.

use tokio::sync::watch;
use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::{Decision, FrameMeta, Pushed, Segmenter};
use wardenlens_core::storage::{SegmentIndex, TransientFault};
use wardenlens_core::time::UnixMs;
use wardenlens_core::video::{self, Frame};
use wardenlens_mp4::{H264Params, InitSegment, init_segment};

use crate::config::RecorderConfig;
use crate::health::RecorderHealth;
use crate::keys::KeyAlloc;
use crate::pending::Pending;
use crate::source::FrameSource;
use crate::state::Conditions;
use crate::store::SegmentStore;

/// Why a recorder could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecorderError {
    /// The newest `started_at_ms` of the camera could not be read from the index (the seed of
    /// the unique-key rule).
    #[error("could not read the newest segment of the camera from the index: {0}")]
    Seed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// The parameter sets of the stream and the init segment built from them.
pub(crate) struct Active {
    raw: video::H264Params,
    pub(crate) init: InitSegment,
}

/// The segment being written.
pub(crate) struct Open<W> {
    pub(crate) writer: W,
    pub(crate) init: InitSegment,
    pub(crate) pending: Pending,
    /// Next `mfhd` sequence number.
    pub(crate) sequence: u32,
    /// Sum of the durations of the fragments written so far, in ticks.
    pub(crate) written_ticks: u64,
    /// Bytes written to the `.part` so far (the init segment and the fragments).
    pub(crate) bytes_written: u64,
    /// Media time of the latest sample, ticks since the segment start.
    pub(crate) last_dts: u64,
    /// Step before the latest sample (the last sample of a segment reuses it).
    pub(crate) last_step: u64,
}

/// Turns the frames of one camera into segments (ADR 0005 sections 2 and 3).
///
/// Build it with [`Recorder::new`] and run it on a blocking thread with [`Recorder::run`]:
/// every file and database call blocks (ADR 0005 section 4), so wrap the call in
/// `tokio::task::spawn_blocking`. Ending the source stops it gracefully.
///
/// Frame handling, in this order:
/// 1. A B slice closes the segment and holds recording off for good ([`crate::HoldReason::BFramesDetected`]).
/// 2. A wall clock outside 2000..=2099 closes the segment and holds off while it lasts.
/// 3. A discontinuity, or parameter sets that differ from the current ones, closes the segment.
/// 4. The core `Segmenter` decides: append, start a segment at a keyframe, or drop.
/// 5. Closing a segment is the sequence of ADR 0005 section 3: last fragment, duration patch,
///    fsync, rename, fsync of the directory, then `Index::insert`.
pub struct Recorder<S: SegmentStore, I: SegmentIndex> {
    pub(crate) camera: CameraId,
    pub(crate) config: RecorderConfig,
    pub(crate) segmenter: Segmenter,
    pub(crate) store: S,
    pub(crate) index: I,
    pub(crate) keys: KeyAlloc,
    pub(crate) params: Option<Active>,
    pub(crate) open: Option<Open<S::Writer>>,
    pub(crate) health: RecorderHealth,
    pub(crate) cond: Conditions,
    /// Full-volume failures since the last segment that closed: the back-off exponent.
    pub(crate) full_failures: u32,
    pub(crate) scratch: Vec<u8>,
    tx: watch::Sender<RecorderHealth>,
}

impl<S: SegmentStore, I: SegmentIndex> Recorder<S, I>
where
    I::Error: TransientFault + std::error::Error + Send + Sync + 'static,
{
    /// A recorder for `camera`.
    ///
    /// The unique-key rule is seeded from the index (`MAX(started_at_ms)` of the camera) and from
    /// `walk_max`, the largest key of any file of the camera that the reconciliation walk found
    /// (orphans that were quarantined or left are not in the index). Returns the receiver of the
    /// recorder's health.
    ///
    /// # Errors
    /// [`RecorderError::Seed`] when the index cannot be read.
    pub fn new(
        camera: CameraId,
        config: RecorderConfig,
        store: S,
        index: I,
        walk_max: Option<UnixMs>,
    ) -> Result<(Self, watch::Receiver<RecorderHealth>), RecorderError> {
        let indexed = index
            .latest_started_at(&camera)
            .map_err(|e| RecorderError::Seed(Box::new(e)))?;
        let health = RecorderHealth::new();
        let (tx, rx) = watch::channel(health);
        let recorder = Self {
            segmenter: Segmenter::new(camera.clone(), config.segment),
            camera,
            config,
            store,
            index,
            keys: KeyAlloc::seeded(indexed, walk_max),
            params: None,
            open: None,
            health,
            cond: Conditions::default(),
            full_failures: 0,
            scratch: Vec::new(),
            tx,
        };
        Ok((recorder, rx))
    }

    /// Records until the source ends, then flushes and indexes the open segment (graceful stop)
    /// and returns the final health.
    pub fn run(mut self, mut source: impl FrameSource) -> RecorderHealth {
        while let Some(frame) = source.next_frame() {
            self.push_frame(frame);
        }
        self.finish()
    }

    /// Handles one frame.
    pub fn push_frame(&mut self, frame: Frame) {
        self.handle(frame);
        self.publish();
    }

    /// Graceful stop: closes the open segment through the full close sequence and returns the
    /// final health.
    pub fn finish(mut self) -> RecorderHealth {
        self.close_open();
        self.publish();
        self.health
    }

    fn publish(&mut self) {
        self.health.state = self.cond.state(self.open.is_some());
        let now = self.health;
        self.tx.send_if_modified(|h| {
            let changed = *h != now;
            *h = now;
            changed
        });
    }

    pub(crate) fn drop_frame(&mut self) {
        self.health.frames_dropped = self.health.frames_dropped.saturating_add(1);
    }

    /// Closes the open segment, if any, and forgets the stream: the next segment starts at a
    /// keyframe with media time 0. Used for a discontinuity, a hold and a stop.
    pub(crate) fn close_open(&mut self) {
        if let Some(record) = self.segmenter.finish() {
            self.finalize(&record);
        } else if let Some(open) = self.open.take() {
            // Cannot happen: the segmenter and the recorder open and close together. If it ever
            // does, the file is not trusted.
            self.abort_segment(open);
        }
    }

    fn handle(&mut self, frame: Frame) {
        if self.cond.b_frames {
            self.drop_frame();
            return;
        }
        // Parameter sets are taken from every frame, also from one that is dropped below: ingest
        // sends them once per session, and a frame lost to a hold must not lose them.
        self.update_params(&frame);
        match video::contains_b_slice(&frame.data) {
            Ok(false) => {}
            Ok(true) => {
                self.close_open();
                self.cond.b_frames = true;
                self.drop_frame();
                return;
            }
            Err(_) => {
                self.health.stream_errors = self.health.stream_errors.saturating_add(1);
                self.close_open();
                self.drop_frame();
                return;
            }
        }
        let Ok(arrival) = UnixMs::try_from(frame.arrival) else {
            self.close_open();
            self.cond.clock = true;
            self.drop_frame();
            return;
        };
        self.cond.clock = false;
        if self.params.is_none() {
            self.drop_frame();
            return;
        }
        let meta = FrameMeta::new(
            frame.is_keyframe,
            frame.rtp_ts_90k,
            arrival,
            u64::try_from(frame.data.len()).unwrap_or(u64::MAX),
        );
        let pushed = self.segmenter.push(meta);
        self.apply(frame, arrival, pushed);
    }

    /// A discontinuity or a change of parameter sets closes the segment; new parameter sets are
    /// validated and turned into the init segment once.
    fn update_params(&mut self, frame: &Frame) {
        let changed = frame
            .params
            .as_ref()
            .is_some_and(|p| self.params.as_ref().is_none_or(|a| a.raw != *p));
        if frame.discontinuity || changed {
            self.close_open();
        }
        let Some(raw) = frame.params.as_ref().filter(|_| changed) else {
            return;
        };
        let built = H264Params::new(&raw.sps, &raw.pps)
            .and_then(|p| init_segment(&p))
            .ok();
        if let Some(init) = built {
            self.params = Some(Active {
                raw: raw.clone(),
                init,
            });
            self.cond.params = false;
        } else {
            self.params = None;
            self.cond.params = true;
        }
    }

    fn apply(&mut self, frame: Frame, arrival: UnixMs, mut pushed: Pushed) {
        if pushed.error.is_some() {
            self.health.stream_errors = self.health.stream_errors.saturating_add(1);
        }
        if let Some(record) = pushed.closed.take() {
            self.finalize(&record);
        }
        match pushed.decision {
            Decision::StartNew => self.begin(frame, arrival),
            Decision::Append => self.append(frame, &pushed),
            _ => self.drop_frame(),
        }
    }
}
