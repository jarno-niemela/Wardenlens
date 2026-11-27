//! Recorder settings.

use std::time::Duration;

use wardenlens_core::recording::SegmentConfig;

/// Settings of one recorder.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RecorderConfig {
    /// The segment rule (target, hard maximum, byte cap).
    pub segment: SegmentConfig,
    /// How many times a transient index error (busy, I/O) is retried after the first attempt
    /// (ADR 0005 section 3, default 5). Never unbounded.
    pub insert_retries: u32,
    /// Pause before the first retry; it grows linearly with the attempt number.
    pub retry_backoff: Duration,
    /// After the volume was full, keyframes are skipped until at least this many bytes are
    /// available to the recorder. Default 32 MiB, twice the fragment cap. 0 retries at every
    /// keyframe.
    pub resume_free_bytes: u64,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            segment: SegmentConfig::default(),
            insert_retries: 5,
            retry_backoff: Duration::from_millis(50),
            resume_free_bytes: 32 << 20,
        }
    }
}

impl RecorderConfig {
    /// The defaults with a different segment rule.
    #[must_use]
    pub fn with_segment(mut self, segment: SegmentConfig) -> Self {
        self.segment = segment;
        self
    }

    /// Sets the number of index retries and the pause before the first.
    #[must_use]
    pub fn with_insert_retries(mut self, retries: u32, backoff: Duration) -> Self {
        self.insert_retries = retries;
        self.retry_backoff = backoff;
        self
    }

    /// Sets the free space needed to resume after a full volume.
    #[must_use]
    pub fn with_resume_free_bytes(mut self, bytes: u64) -> Self {
        self.resume_free_bytes = bytes;
        self
    }
}
