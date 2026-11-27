//! What the recorder reports about itself: one state and a few counters, no paths, no camera
//! data (SEC-6).

/// Why recording is held off. Each reason names its cause (P6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HoldReason {
    /// A B slice was seen. Segments carry no composition offsets (PTS = DTS), so a stream with
    /// frame reordering would be written with wrong timestamps (ADR 0005 section 2, #157). The
    /// open segment was closed; nothing more is written until the recorder is restarted.
    BFramesDetected,
    /// The wall clock is before the year 2000 or after 2099 (ADR 0005 section 2). Ends when the
    /// clock is back in range.
    ClockOutOfRange,
    /// The hot volume is full (`ENOSPC`, or a quota). The segment was aborted and its `.part`
    /// removed. Recording resumes at a keyframe once the volume has room again.
    StorageFull,
    /// A file operation other than "volume full" failed. The segment was aborted; recording
    /// retries at the next keyframe.
    WriteFailed,
    /// The camera's SPS or PPS did not validate, so no segment can be written. Ends when valid
    /// parameter sets arrive.
    BadParameters,
    /// The index could not be asked whether a key is free, or no free key was found, so no
    /// segment can be started safely. Retried at the next keyframe.
    IndexUnavailable,
}

/// The recorder's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecorderState {
    /// No segment is open: waiting for parameter sets or for a keyframe.
    Waiting,
    /// A segment is open.
    Recording,
    /// Recording is held off.
    Held(HoldReason),
}

/// A snapshot of the recorder's state and counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecorderHealth {
    /// The current state.
    pub state: RecorderState,
    /// Segments that are on disk and in the index.
    pub segments_indexed: u64,
    /// Segments thrown away because a write failed (the `.part` was removed).
    pub segments_aborted: u64,
    /// Finished files moved to quarantine because the index refused them permanently.
    pub segments_quarantined: u64,
    /// Finished files left in place without a row: the index stayed busy through every retry,
    /// the directory fsync failed, or every quarantine name was taken. The reconciliation pass at
    /// the next start judges them (ADR 0005 section 9).
    pub segments_unindexed: u64,
    /// Frames that were not written.
    pub frames_dropped: u64,
    /// Segments whose arrival time was earlier than the previous segment's (the wall clock
    /// stepped back; ADR 0005 section 2 health warning).
    pub clock_stepped_back: u64,
    /// Frames refused as a stream error (empty, too large, or a cut-off slice header).
    pub stream_errors: u64,
}

impl RecorderHealth {
    pub(crate) fn new() -> Self {
        Self {
            state: RecorderState::Waiting,
            segments_indexed: 0,
            segments_aborted: 0,
            segments_quarantined: 0,
            segments_unindexed: 0,
            frames_dropped: 0,
            clock_stepped_back: 0,
            stream_errors: 0,
        }
    }
}
