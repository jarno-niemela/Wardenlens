//! `Segmenter`: decides where segments start and end (ADR 0005 section 2).

use super::clock::{MediaClock, TICKS_PER_SECOND};
use super::path::RecordingError;
use crate::camera::CameraId;
use crate::time::{DurationMs, Timestamp, UnixMs};

/// Largest accepted frame, 8 MiB (ADR 0005 section 2). A larger frame is a
/// stream error ([`PushError::FrameTooLarge`]).
pub const MAX_FRAME_BYTES: u64 = 8 << 20;

/// Largest fragment (one GOP of the fMP4 muxer), 16 MiB: when appending a frame
/// would take the open fragment past this, [`Pushed::flush_fragment`] is set.
pub const MAX_FRAGMENT_BYTES: u64 = 16 << 20;

/// Metadata of one encoded frame, as the recorder sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrameMeta {
    /// Whether the frame is a keyframe (IDR).
    pub is_keyframe: bool,
    /// The 32-bit RTP timestamp, 90 kHz.
    pub media_ts_90k: u32,
    /// Wall-clock arrival time of the frame.
    pub arrival: UnixMs,
    /// Encoded size of the frame in bytes.
    pub bytes: u64,
}

impl FrameMeta {
    /// Describes one frame.
    #[must_use]
    pub fn new(is_keyframe: bool, media_ts_90k: u32, arrival: UnixMs, bytes: u64) -> Self {
        Self {
            is_keyframe,
            media_ts_90k,
            arrival,
            bytes,
        }
    }
}

/// A frame the segmenter refuses: a stream error.
///
/// The open segment is closed (its record is in [`Pushed::closed`]) and frames
/// are dropped until the next keyframe. The recorder (#57) treats this as a
/// discontinuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushError {
    /// The frame is larger than [`MAX_FRAME_BYTES`].
    FrameTooLarge,
    /// The frame has no bytes.
    EmptyFrame,
}

/// What to do with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// Add the frame to the open segment.
    Append,
    /// Close the open segment (if any) and start a new one with this frame.
    StartNew,
    /// Discard the frame: no segment is open and it is not a keyframe.
    Drop,
}

/// The result of [`Segmenter::push`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pushed {
    /// What to do with the frame.
    pub decision: Decision,
    /// Media time of the frame in ticks since the start of its segment
    /// (0 for `StartNew`); `None` when dropped.
    pub dts: Option<u64>,
    /// The segment this frame closed, if any. Present on `StartNew` (the
    /// previous segment) and on a `Drop` that hit the hard maximum or byte cap.
    pub closed: Option<SegmentRecord>,
    /// Flush the open fragment before this frame: set at each keyframe (a
    /// fragment is one GOP) and when appending the frame would take the open
    /// fragment past [`MAX_FRAGMENT_BYTES`]. Never set on a dropped frame.
    pub flush_fragment: bool,
    /// Set when the frame was refused; the decision is then `Drop`.
    pub error: Option<PushError>,
}

impl Pushed {
    fn dropped(closed: Option<SegmentRecord>, error: Option<PushError>) -> Self {
        Self {
            decision: Decision::Drop,
            dts: None,
            closed,
            flush_fragment: false,
            error,
        }
    }
}

/// An index row for a finished segment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SegmentRecord {
    /// The camera that produced the segment.
    pub camera: CameraId,
    /// Arrival time of the first frame (before the recorder's collision bump).
    pub started_at_ms: UnixMs,
    /// Media duration in ms, ticks rounded up, at least 1.
    pub duration_ms: u64,
    /// Sum of the encoded frame sizes.
    pub bytes: u64,
    /// Number of frames in the segment.
    pub frame_count: u64,
}

impl SegmentRecord {
    /// Builds a record. The segmenter is the usual source; adapters (the index) use this to read
    /// stored rows back. No bound is checked here: the consumer validates what it stores.
    #[must_use]
    pub fn new(
        camera: CameraId,
        started_at_ms: UnixMs,
        duration_ms: u64,
        bytes: u64,
        frame_count: u64,
    ) -> Self {
        Self {
            camera,
            started_at_ms,
            duration_ms,
            bytes,
            frame_count,
        }
    }

    /// `started_at_ms + duration_ms`; saturates instead of overflowing.
    #[must_use]
    pub fn ended_at_ms(&self) -> Timestamp {
        Timestamp::from(self.started_at_ms)
            .saturating_add(DurationMs::from_millis(self.duration_ms))
    }
}

/// Converts 90 kHz ticks to milliseconds, rounding up, minimum 1.
#[must_use]
pub(crate) fn ticks_to_ms_ceil(ticks: u64) -> u64 {
    let ms = ticks
        .saturating_mul(1000)
        .saturating_add(TICKS_PER_SECOND.saturating_sub(1))
        .checked_div(TICKS_PER_SECOND)
        .unwrap_or(1);
    ms.max(1)
}

/// Validated segmenter settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentConfig {
    target_ticks: u64,
    max_ticks: u64,
    max_segment_bytes: u64,
}

impl SegmentConfig {
    /// Shortest target, seconds.
    pub const MIN_TARGET_SECS: u32 = 10;
    /// Longest target, seconds: twice this stays under the 600 s index `CHECK`.
    pub const MAX_TARGET_SECS: u32 = 290;

    /// Builds a config; the hard maximum is twice the target.
    ///
    /// # Errors
    /// [`RecordingError::TargetOutOfRange`] unless `target_secs` is 10-290;
    /// [`RecordingError::ZeroByteCap`] if `max_segment_bytes` is 0.
    pub fn new(target_secs: u32, max_segment_bytes: u64) -> Result<Self, RecordingError> {
        if !(Self::MIN_TARGET_SECS..=Self::MAX_TARGET_SECS).contains(&target_secs) {
            return Err(RecordingError::TargetOutOfRange);
        }
        if max_segment_bytes == 0 {
            return Err(RecordingError::ZeroByteCap);
        }
        let target_ticks = u64::from(target_secs).saturating_mul(TICKS_PER_SECOND);
        Ok(Self {
            target_ticks,
            max_ticks: target_ticks.saturating_mul(2),
            max_segment_bytes,
        })
    }
}

impl Default for SegmentConfig {
    /// 60 s target, 120 s hard maximum, 1 GiB byte cap.
    fn default() -> Self {
        Self {
            target_ticks: 60 * TICKS_PER_SECOND,
            max_ticks: 120 * TICKS_PER_SECOND,
            max_segment_bytes: 1 << 30,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Open {
    started_at: UnixMs,
    /// Stream media time of the first frame.
    start_dts: u64,
    /// Stream media time of the latest frame.
    last_dts: u64,
    /// Step before the latest frame; the last sample reuses it (at least 1).
    last_step: u64,
    bytes: u64,
    /// Bytes in the open fragment.
    fragment_bytes: u64,
    frames: u64,
}

/// Cuts a frame stream into segments and keeps media time monotonic.
///
/// Rules: frames before the first keyframe are dropped; a segment is cut at
/// the first keyframe at or after the target; at the hard maximum (2x target)
/// or the byte cap the segment closes at that frame unless it is a keyframe,
/// and frames are dropped until the next keyframe. A frame of 0 bytes or more
/// than 8 MiB is a stream error: the open segment closes and frames are dropped
/// until the next keyframe.
#[derive(Debug, Clone)]
pub struct Segmenter {
    camera: CameraId,
    config: SegmentConfig,
    clock: MediaClock,
    open: Option<Open>,
}

impl Segmenter {
    /// A segmenter for `camera` waiting for its first keyframe.
    #[must_use]
    pub fn new(camera: CameraId, config: SegmentConfig) -> Self {
        Self {
            camera,
            config,
            clock: MediaClock::default(),
            open: None,
        }
    }

    fn record(&self, o: &Open) -> SegmentRecord {
        let ticks = o
            .last_dts
            .saturating_sub(o.start_dts)
            .saturating_add(o.last_step.max(1));
        SegmentRecord {
            camera: self.camera.clone(),
            started_at_ms: o.started_at,
            duration_ms: ticks_to_ms_ceil(ticks),
            bytes: o.bytes,
            frame_count: o.frames,
        }
    }

    fn start(&mut self, f: &FrameMeta, dts: u64) -> Pushed {
        self.open = Some(Open {
            started_at: f.arrival,
            start_dts: dts,
            last_dts: dts,
            last_step: 1,
            bytes: f.bytes,
            fragment_bytes: f.bytes,
            frames: 1,
        });
        Pushed {
            decision: Decision::StartNew,
            dts: Some(0),
            closed: None,
            flush_fragment: true,
            error: None,
        }
    }

    /// Feeds the next frame and says what to do with it.
    pub fn push(&mut self, f: FrameMeta) -> Pushed {
        // The clock sees every frame so its RTP line stays continuous while dropping.
        let dts = self.clock.push(f.media_ts_90k);
        let invalid = if f.bytes == 0 {
            Some(PushError::EmptyFrame)
        } else if f.bytes > MAX_FRAME_BYTES {
            Some(PushError::FrameTooLarge)
        } else {
            None
        };
        if invalid.is_some() {
            let closed = self.open.take().map(|o| self.record(&o));
            return Pushed::dropped(closed, invalid);
        }
        let Some(mut o) = self.open else {
            return if f.is_keyframe {
                self.start(&f, dts)
            } else {
                Pushed::dropped(None, None)
            };
        };
        let elapsed = dts.saturating_sub(o.start_dts);
        let over_bytes = o.bytes.saturating_add(f.bytes) > self.config.max_segment_bytes;
        let forced = elapsed >= self.config.max_ticks || over_bytes;
        if f.is_keyframe && (elapsed >= self.config.target_ticks || forced) {
            let closed = self.record(&o);
            let mut next = self.start(&f, dts);
            next.closed = Some(closed);
            return next;
        }
        if forced {
            self.open = None;
            return Pushed::dropped(Some(self.record(&o)), None);
        }
        o.last_step = dts.saturating_sub(o.last_dts).max(1);
        o.last_dts = dts;
        o.bytes = o.bytes.saturating_add(f.bytes);
        o.frames = o.frames.saturating_add(1);
        let flush_fragment =
            if f.is_keyframe || o.fragment_bytes.saturating_add(f.bytes) > MAX_FRAGMENT_BYTES {
                o.fragment_bytes = f.bytes;
                true
            } else {
                o.fragment_bytes = o.fragment_bytes.saturating_add(f.bytes);
                false
            };
        self.open = Some(o);
        Pushed {
            decision: Decision::Append,
            dts: Some(elapsed),
            closed: None,
            flush_fragment,
            error: None,
        }
    }

    /// Closes the open segment, if any, and forgets the stream: the next
    /// segment starts at the next keyframe with media time 0. Call it on a
    /// discontinuity or at shutdown.
    pub fn finish(&mut self) -> Option<SegmentRecord> {
        self.clock.reset();
        self.open.take().map(|o| self.record(&o))
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic on small bounded literals"
    )]

    use super::*;

    const T0: i64 = 1_700_000_000_000;

    fn seg(target: u32) -> Segmenter {
        Segmenter::new(
            "cam".parse().unwrap(),
            SegmentConfig::new(target, 1 << 30).unwrap(),
        )
    }

    fn frame(key: bool, rtp: u32, at: i64, bytes: u64) -> FrameMeta {
        FrameMeta::new(key, rtp, UnixMs::new(at).unwrap(), bytes)
    }

    /// 1 fps frames, keyframe every `gop` frames.
    fn feed(s: &mut Segmenter, n: u32, gop: u32) -> Vec<Pushed> {
        (0..n)
            .map(|i| {
                s.push(frame(
                    i % gop == 0,
                    i * 90_000,
                    T0 + i64::from(i) * 1000,
                    100,
                ))
            })
            .collect()
    }

    fn records(p: &[Pushed]) -> Vec<&SegmentRecord> {
        p.iter().filter_map(|p| p.closed.as_ref()).collect()
    }

    #[test]
    fn drops_until_first_keyframe() {
        let mut s = seg(10);
        assert_eq!(s.push(frame(false, 0, T0, 1)).decision, Decision::Drop);
        assert_eq!(
            s.push(frame(false, 90_000, T0 + 1000, 1)).decision,
            Decision::Drop
        );
        let k = s.push(frame(true, 180_000, T0 + 2000, 1));
        assert_eq!(k.decision, Decision::StartNew);
        assert_eq!(k.dts, Some(0));
        assert_eq!(k.closed, None);
    }

    #[test]
    fn no_keyframe_ever_drops_everything_and_yields_no_record() {
        let mut s = seg(10);
        for i in 0..500u32 {
            let p = s.push(frame(false, i * 90_000, T0, 1));
            assert_eq!((p.decision, p.closed), (Decision::Drop, None));
        }
        assert_eq!(s.finish(), None);
    }

    #[test]
    fn cuts_at_first_keyframe_at_or_after_target() {
        let mut s = seg(10);
        // keyframes at 0, 4, 8, 12, 16 s; target 10 s -> cut at 12 s
        let out: Vec<Pushed> = (0..14u32)
            .map(|i| s.push(frame(i % 4 == 0, i * 90_000, T0 + i64::from(i) * 1000, 10)))
            .collect();
        let starts: Vec<usize> = out
            .iter()
            .enumerate()
            .filter(|(_, p)| p.decision == Decision::StartNew)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(starts, [0, 12]);
        let r = out[12].closed.as_ref().unwrap();
        assert_eq!(r.frame_count, 12);
        assert_eq!(r.bytes, 120);
        assert_eq!(r.started_at_ms.as_i64(), T0);
        assert_eq!(r.duration_ms, 12_000);
        assert_eq!(r.ended_at_ms(), Timestamp::from_unix_millis(T0 + 12_000));
        assert_eq!(out[12].dts, Some(0));
        assert_eq!(out[13].dts, Some(90_000));
    }

    #[test]
    fn exact_target_keyframe_cuts() {
        let mut s = seg(10);
        let out = feed(&mut s, 11, 10); // keyframes at 0 and 10 s
        assert_eq!(out[10].decision, Decision::StartNew);
    }

    #[test]
    fn keyframe_just_before_target_does_not_cut() {
        let mut s = seg(10);
        let mut out = feed(&mut s, 10, 100);
        out.push(s.push(frame(true, 9 * 90_000 + 89_999, T0 + 20_000, 1)));
        assert_eq!(out[10].decision, Decision::Append);
    }

    #[test]
    fn hard_maximum_closes_on_the_frame_and_drops_until_keyframe() {
        let mut s = seg(10); // max 20 s
        let out = feed(&mut s, 30, 100); // no keyframe after frame 0
        assert_eq!(out[19].decision, Decision::Append);
        let cut = &out[20];
        assert_eq!(cut.decision, Decision::Drop);
        let r = cut.closed.as_ref().unwrap();
        assert_eq!((r.frame_count, r.duration_ms), (20, 20_000));
        assert!(
            out[21..]
                .iter()
                .all(|p| p.decision == Decision::Drop && p.closed.is_none())
        );
        let k = s.push(frame(true, 40 * 90_000, T0 + 40_000, 1));
        assert_eq!((k.decision, k.closed), (Decision::StartNew, None));
    }

    #[test]
    fn keyframe_at_hard_maximum_starts_new_instead_of_dropping() {
        let mut s = seg(10);
        let out = feed(&mut s, 21, 20);
        assert_eq!(out[20].decision, Decision::StartNew);
        assert!(out[20].closed.is_some());
    }

    #[test]
    fn byte_cap_closes_the_segment() {
        let cfg = SegmentConfig::new(10, 250).unwrap();
        let mut s = Segmenter::new("cam".parse().unwrap(), cfg);
        let out = feed(&mut s, 5, 100); // 100 bytes each: frame 2 would reach 300
        assert_eq!(out[2].decision, Decision::Drop);
        let r = out[2].closed.as_ref().unwrap();
        assert_eq!((r.frame_count, r.bytes), (2, 200));
    }

    #[test]
    fn keyframe_on_every_frame_cuts_at_target_only() {
        let mut s = seg(10);
        let out = feed(&mut s, 25, 1);
        let starts = out
            .iter()
            .filter(|p| p.decision == Decision::StartNew)
            .count();
        assert_eq!(starts, 3); // frames 0, 10, 20
        assert!(records(&out).iter().all(|r| r.frame_count == 10));
    }

    #[test]
    fn single_frame_segment_has_minimum_duration() {
        let mut s = seg(10);
        s.push(frame(true, 0, T0, 7));
        let r = s.finish().unwrap();
        assert_eq!((r.frame_count, r.bytes, r.duration_ms), (1, 7, 1));
    }

    #[test]
    fn finish_with_nothing_open_is_none_and_resets_the_stream() {
        let mut s = seg(10);
        assert_eq!(s.finish(), None);
        s.push(frame(true, 5, T0, 1));
        s.finish().unwrap();
        assert_eq!(s.push(frame(false, 90_005, T0, 1)).decision, Decision::Drop);
        assert_eq!(s.push(frame(true, 180_005, T0, 1)).dts, Some(0));
    }

    #[test]
    fn survives_a_32_bit_rtp_wrap_inside_a_segment() {
        let mut s = seg(10);
        let base = u32::MAX - 4 * 90_000;
        let out: Vec<Pushed> = (0..8u32)
            .map(|i| {
                s.push(frame(
                    i == 0,
                    base.wrapping_add(i * 90_000),
                    T0 + i64::from(i) * 1000,
                    1,
                ))
            })
            .collect();
        let dts: Vec<u64> = out.iter().map(|p| p.dts.unwrap()).collect();
        assert_eq!(
            dts,
            [
                0, 90_000, 180_000, 270_000, 360_000, 450_000, 540_000, 630_000
            ]
        );
        assert_eq!(s.finish().unwrap().duration_ms, 8000);
    }

    #[test]
    fn jittery_duplicate_timestamps_still_give_positive_steps() {
        let mut s = seg(10);
        let rtps = [0u32, 3600, 3600, 3600, 7200, 7000, 10_800];
        let dts: Vec<u64> = rtps
            .iter()
            .enumerate()
            .map(|(i, &r)| s.push(frame(i == 0, r, T0, 1)).dts.unwrap())
            .collect();
        assert!(dts.windows(2).all(|w| w[1] > w[0]));
    }

    /// Frames 10 s apart (the largest non-rebase step) from 0 up to `last_ms`, ending with `tail_ms`.
    fn sparse(s: &mut Segmenter, last_ms: u64, tail_ms: &[u64]) -> Vec<Pushed> {
        let mut at: Vec<u64> = (0..last_ms).step_by(10_000).collect();
        at.extend_from_slice(tail_ms);
        at.iter()
            .enumerate()
            .map(|(i, &ms)| {
                let rtp = u32::try_from(ms * 90).unwrap();
                s.push(frame(i == 0, rtp, T0 + i64::try_from(ms).unwrap(), 1))
            })
            .collect()
    }

    #[test]
    fn duration_stays_within_the_600s_check_at_the_boundary() {
        // target 290 s, hard max 580 s: frame at 579.99 s, then a 10 s (non-rebase) gap
        let mut s = seg(290);
        let out = sparse(&mut s, 570_000, &[569_990, 579_990, 589_990]);
        let last = out.last().unwrap();
        assert_eq!(last.decision, Decision::Drop);
        let r = last.closed.as_ref().unwrap();
        assert_eq!(r.duration_ms, 579_990 + 10_000);
        assert!(r.duration_ms <= 600_000);
    }

    #[test]
    fn worst_case_last_sample_is_still_within_600s() {
        // Last appended frame at 579.99 s after a 10 s step: the last sample reuses 10 s.
        let mut s = seg(290);
        sparse(&mut s, 570_000, &[569_990, 579_990]);
        let r = s.finish().unwrap();
        assert_eq!(r.duration_ms, 579_990 + 10_000);
        assert!(r.duration_ms <= 600_000);
    }

    const MIB: u64 = 1 << 20;

    /// A keyframe of `first` bytes, then P-frames of the given sizes; returns the flush flags.
    fn flushes(first: u64, rest: &[u64]) -> Vec<bool> {
        let mut s = seg(290);
        let mut out = vec![s.push(frame(true, 0, T0, first)).flush_fragment];
        for (i, &b) in rest.iter().enumerate() {
            let rtp = u32::try_from(i + 1).unwrap() * 3600;
            let p = s.push(frame(false, rtp, T0, b));
            assert_eq!(p.decision, Decision::Append);
            out.push(p.flush_fragment);
        }
        out
    }

    #[test]
    fn fragment_flush_at_keyframes() {
        let mut s = seg(290);
        let k = s.push(frame(true, 0, T0, 10));
        assert!(k.flush_fragment);
        assert!(!s.push(frame(false, 3600, T0, 10)).flush_fragment);
        let k2 = s.push(frame(true, 7200, T0, 10));
        assert_eq!(k2.decision, Decision::Append);
        assert!(k2.flush_fragment);
        assert!(!s.push(frame(false, 10_800, T0, 10)).flush_fragment);
    }

    #[test]
    fn fragment_cap_boundaries() {
        // 8 MiB keyframe + 8 MiB - 1 = 16 MiB - 1: no flush.
        assert_eq!(flushes(8 * MIB, &[8 * MIB - 1]), [true, false]);
        // exactly 16 MiB: no flush.
        assert_eq!(flushes(8 * MIB, &[8 * MIB]), [true, false]);
        // 16 MiB + 1: flush before the frame.
        assert_eq!(flushes(8 * MIB, &[8 * MIB - 1, 2]), [true, false, true]);
        // the new fragment starts with the flushed frame.
        assert_eq!(
            flushes(8 * MIB, &[8 * MIB, 1, 8 * MIB, 8 * MIB]),
            [true, false, true, false, true]
        );
    }

    #[test]
    fn frame_of_8_mib_is_accepted_and_one_more_byte_is_an_error() {
        let mut s = seg(10);
        let ok = s.push(frame(true, 0, T0, 8 * MIB));
        assert_eq!((ok.decision, ok.error), (Decision::StartNew, None));
        let bad = s.push(frame(false, 3600, T0, 8 * MIB + 1));
        assert_eq!(bad.decision, Decision::Drop);
        assert_eq!(bad.error, Some(PushError::FrameTooLarge));
        let r = bad.closed.unwrap();
        assert_eq!((r.frame_count, r.bytes), (1, 8 * MIB));
        // dropped until the next keyframe
        let d = s.push(frame(false, 7200, T0, 1));
        assert_eq!(
            (d.decision, d.error, d.closed),
            (Decision::Drop, None, None)
        );
        let k = s.push(frame(true, 10_800, T0, 1));
        assert_eq!((k.decision, k.dts), (Decision::StartNew, Some(0)));
    }

    #[test]
    fn oversized_keyframe_never_opens_a_segment() {
        let mut s = seg(10);
        let p = s.push(frame(true, 0, T0, u64::MAX));
        assert_eq!(
            (p.decision, p.error, p.closed),
            (Decision::Drop, Some(PushError::FrameTooLarge), None)
        );
        assert_eq!(s.finish(), None);
    }

    #[test]
    fn zero_byte_frame_is_a_stream_error_and_no_record_has_zero_bytes() {
        let mut s = seg(10);
        assert_eq!(
            s.push(frame(true, 0, T0, 0)).error,
            Some(PushError::EmptyFrame)
        );
        s.push(frame(true, 3600, T0, 5));
        let p = s.push(frame(false, 7200, T0, 0));
        assert_eq!(p.error, Some(PushError::EmptyFrame));
        let r = p.closed.unwrap();
        assert_eq!((r.bytes, r.frame_count), (5, 1));
        assert_eq!(s.finish(), None);
    }

    #[test]
    fn config_bounds() {
        assert!(SegmentConfig::new(9, 1).is_err());
        assert!(SegmentConfig::new(10, 1).is_ok());
        assert!(SegmentConfig::new(290, 1).is_ok());
        assert!(SegmentConfig::new(291, 1).is_err());
        assert_eq!(SegmentConfig::new(60, 0), Err(RecordingError::ZeroByteCap));
        assert_eq!(
            SegmentConfig::new(60, 1 << 30).unwrap(),
            SegmentConfig::default()
        );
    }

    #[test]
    fn ticks_round_up_with_minimum_one() {
        assert_eq!(ticks_to_ms_ceil(0), 1);
        assert_eq!(ticks_to_ms_ceil(1), 1);
        assert_eq!(ticks_to_ms_ceil(90), 1);
        assert_eq!(ticks_to_ms_ceil(91), 2);
        assert_eq!(ticks_to_ms_ceil(90_000), 1000);
        assert_eq!(ticks_to_ms_ceil(u64::MAX), u64::MAX / 90_000);
    }

    proptest::proptest! {
        #[test]
        fn records_are_positive_bounded_and_cover_the_media_time(
            frames in proptest::collection::vec((proptest::bool::ANY, proptest::num::u32::ANY, 1u64..5000), 1..300),
        ) {
            let mut s = seg(10);
            let mut records = Vec::new();
            let mut summed_frames = 0u64;
            let mut appended = 0u64;
            // Pushed.dts of the frames of the open segment.
            let mut cur: Vec<u64> = Vec::new();
            let mut closed_dts: Vec<Vec<u64>> = Vec::new();
            for (key, rtp, bytes) in frames {
                let p = s.push(frame(key, rtp, T0, bytes));
                if let Some(r) = p.closed {
                    records.push(r);
                    closed_dts.push(std::mem::take(&mut cur));
                }
                match p.decision {
                    Decision::StartNew => cur = vec![0],
                    Decision::Append => cur.extend(p.dts),
                    _ => {}
                }
                if p.decision != Decision::Drop { appended += 1; }
            }
            if let Some(r) = s.finish() {
                records.push(r);
                closed_dts.push(cur);
            }
            for (r, dts) in records.iter().zip(&closed_dts) {
                // Media span = last dts + the last step (the last sample reuses it).
                let last = dts.last().copied().unwrap();
                let step = match dts.len() {
                    1 => 1,
                    n => last - dts[n - 2],
                };
                proptest::prop_assert_eq!(ticks_to_ms_ceil(last + step), r.duration_ms);
                proptest::prop_assert_eq!(u64::try_from(dts.len()).unwrap(), r.frame_count);
            }
            for r in &records {
                proptest::prop_assert!(r.duration_ms >= 1);
                proptest::prop_assert!(r.duration_ms <= 600_000);
                proptest::prop_assert!(r.frame_count >= 1);
                proptest::prop_assert_eq!(
                    r.ended_at_ms().as_unix_millis(),
                    r.started_at_ms.as_i64() + i64::try_from(r.duration_ms).unwrap()
                );
                summed_frames += r.frame_count;
            }
            proptest::prop_assert_eq!(summed_frames, appended);
        }

        #[test]
        fn regular_stream_duration_equals_frame_span(n in 2u32..200, step in 1u32..20_000) {
            let mut s = seg(290);
            for i in 0..n {
                s.push(frame(i == 0, i * step, T0, 1));
            }
            let r = s.finish().unwrap();
            let ticks = u64::from(n) * u64::from(step);
            proptest::prop_assert_eq!(r.duration_ms, ticks_to_ms_ceil(ticks));
        }
    }
}
