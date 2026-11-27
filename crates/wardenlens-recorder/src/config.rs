//! Recorder settings.

use std::time::Duration;

use wardenlens_core::mp4box::{MAX_FILE_LEN, MAX_FRAGMENTS};
use wardenlens_core::recording::SegmentConfig;

/// Largest finished segment file the recorder writes, in bytes: the adoption parser's limit
/// ([`MAX_FILE_LEN`]) less a margin of 16 MiB (two largest frames), so a file that is finished is
/// a file reconciliation can adopt (#195). The segmenter's own byte cap counts frame bytes only;
/// this limit counts the file, container overhead included.
pub(crate) const MAX_FILE_BYTES: u64 = MAX_FILE_LEN - (16 << 20);

/// Most fragments the recorder writes into one segment: the adoption parser's limit
/// ([`MAX_FRAGMENTS`]) less a margin of 1,000.
pub(crate) const MAX_FRAGMENTS_PER_SEGMENT: u64 = MAX_FRAGMENTS - 1_000;

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
    /// The segment is closed before it would pass this many bytes on disk, container overhead
    /// included. Never above the adoption parser's limit less a margin.
    pub max_file_bytes: u64,
    /// The segment is closed before it would pass this many fragments. Never above the adoption
    /// parser's limit less a margin.
    pub max_fragments: u64,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            segment: SegmentConfig::default(),
            insert_retries: 5,
            retry_backoff: Duration::from_millis(50),
            resume_free_bytes: 32 << 20,
            max_file_bytes: MAX_FILE_BYTES,
            max_fragments: MAX_FRAGMENTS_PER_SEGMENT,
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

impl RecorderConfig {
    /// Lowers the file-size and fragment-count limits of a segment (they can never be raised
    /// above the adoption parser's, so a finished file is always adoptable).
    #[must_use]
    pub fn with_file_limits(mut self, max_file_bytes: u64, max_fragments: u64) -> Self {
        self.max_file_bytes = max_file_bytes.min(MAX_FILE_BYTES);
        self.max_fragments = max_fragments.min(MAX_FRAGMENTS_PER_SEGMENT);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_leave_a_margin_under_the_adoption_parser() {
        const {
            // One largest frame (8 MiB) fits the margin.
            assert!(MAX_FILE_BYTES + (8 << 20) <= MAX_FILE_LEN);
            assert!(MAX_FRAGMENTS_PER_SEGMENT < MAX_FRAGMENTS);
        }
        let d = RecorderConfig::default();
        assert_eq!(
            (d.max_file_bytes, d.max_fragments),
            (MAX_FILE_BYTES, MAX_FRAGMENTS_PER_SEGMENT)
        );
    }

    #[test]
    fn the_limits_can_be_lowered_never_raised() {
        let c = RecorderConfig::default().with_file_limits(u64::MAX, u64::MAX);
        assert_eq!(
            (c.max_file_bytes, c.max_fragments),
            (MAX_FILE_BYTES, MAX_FRAGMENTS_PER_SEGMENT)
        );
        let c = RecorderConfig::default().with_file_limits(1000, 3);
        assert_eq!((c.max_file_bytes, c.max_fragments), (1000, 3));
    }
}
