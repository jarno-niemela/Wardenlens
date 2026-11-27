//! The conditions that hold recording off, and the state derived from them.
//!
//! The reported [`RecorderState`] is computed from these facts and from whether a segment is
//! open, never set by hand at each place that notices something, so it cannot disagree with
//! what the recorder does.

use crate::health::{HoldReason, RecorderState};

/// Frames at a keyframe are skipped at most this many times between two attempts after a full
/// volume (about a minute with 2 s GOPs).
const MAX_SKIP_KEYFRAMES: u32 = 32;

/// Keyframes skipped between two probe segments while the index is not writable (about a minute
/// with 2 s GOPs; the same bound as the full-volume back-off).
pub(crate) const READ_ONLY_SKIP_KEYFRAMES: u32 = MAX_SKIP_KEYFRAMES;

/// A full volume (`ENOSPC` or `EDQUOT`): when to try again.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FullHold {
    /// Keyframes still to skip: the back-off. It doubles with every failed attempt, which also
    /// covers a quota that `statvfs` cannot see.
    skip: u32,
    /// Free bytes needed before an attempt: the margin plus what the aborted segment had written
    /// (removing it freed that much, so seeing it again proves nothing).
    need_bytes: u64,
}

impl FullHold {
    pub(crate) fn new(failures: u32, aborted_bytes: u64, margin: u64) -> Self {
        let doublings = failures.saturating_sub(1).min(5);
        Self {
            skip: 1_u32
                .checked_shl(doublings)
                .unwrap_or(1)
                .min(MAX_SKIP_KEYFRAMES),
            need_bytes: margin.saturating_add(aborted_bytes),
        }
    }

    /// Called at each keyframe that would start a segment, with the free bytes if they could be
    /// read. Skips while the back-off lasts; then waits for the space (a volume that cannot be
    /// queried is tried).
    pub(crate) fn may_try(&mut self, available: Option<u64>) -> bool {
        if self.skip > 0 {
            self.skip = self.skip.saturating_sub(1);
            return false;
        }
        available.is_none_or(|n| n >= self.need_bytes)
    }
}

/// Everything that can hold recording off.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts; the reported state is derived from them"
)]
pub(crate) struct Conditions {
    /// A B slice was seen. Never cleared.
    pub(crate) b_frames: bool,
    /// The wall clock is outside 2000..=2099.
    pub(crate) clock: bool,
    /// The parameter sets did not validate.
    pub(crate) params: bool,
    /// The last file operation failed (not a full volume).
    pub(crate) write: bool,
    /// The index could not answer, or no free key was found.
    pub(crate) index: bool,
    /// The index cannot be written (read-only volume): the keyframes still to skip before the
    /// next probe segment. `None` when the index takes writes.
    pub(crate) index_read_only: Option<u32>,
    pub(crate) full: Option<FullHold>,
}

impl Conditions {
    /// The state: the most specific reason first, then whether a segment is open.
    pub(crate) fn state(&self, open: bool) -> RecorderState {
        let reason = if self.b_frames {
            Some(HoldReason::BFramesDetected)
        } else if self.clock {
            Some(HoldReason::ClockOutOfRange)
        } else if self.params {
            Some(HoldReason::BadParameters)
        } else if self.full.is_some() {
            Some(HoldReason::StorageFull)
        } else if self.index_read_only.is_some() {
            Some(HoldReason::IndexReadOnly)
        } else if self.write {
            Some(HoldReason::WriteFailed)
        } else if self.index {
            Some(HoldReason::IndexUnavailable)
        } else {
            None
        };
        match (reason, open) {
            (Some(r), _) => RecorderState::Held(r),
            (None, true) => RecorderState::Recording,
            (None, false) => RecorderState::Waiting,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_condition_has_its_own_reason_in_priority_order() {
        let mut c = Conditions::default();
        assert_eq!(c.state(false), RecorderState::Waiting);
        assert_eq!(c.state(true), RecorderState::Recording);
        c.index = true;
        assert_eq!(
            c.state(true),
            RecorderState::Held(HoldReason::IndexUnavailable)
        );
        c.write = true;
        assert_eq!(c.state(false), RecorderState::Held(HoldReason::WriteFailed));
        c.index_read_only = Some(0);
        assert_eq!(
            c.state(false),
            RecorderState::Held(HoldReason::IndexReadOnly)
        );
        c.full = Some(FullHold::new(1, 0, 0));
        assert_eq!(c.state(false), RecorderState::Held(HoldReason::StorageFull));
        c.params = true;
        assert_eq!(
            c.state(false),
            RecorderState::Held(HoldReason::BadParameters)
        );
        c.clock = true;
        assert_eq!(
            c.state(false),
            RecorderState::Held(HoldReason::ClockOutOfRange)
        );
        c.b_frames = true;
        assert_eq!(
            c.state(true),
            RecorderState::Held(HoldReason::BFramesDetected)
        );
    }

    #[test]
    fn the_back_off_doubles_up_to_its_cap_and_the_space_margin_is_exact() {
        let skips: Vec<u32> = (1..=9).map(|f| FullHold::new(f, 0, 0).skip).collect();
        assert_eq!(skips, [1, 2, 4, 8, 16, 32, 32, 32, 32]);
        let mut h = FullHold::new(1, 500, 1_000);
        assert!(!h.may_try(Some(u64::MAX))); // the skipped keyframe
        assert!(!h.may_try(Some(1_499)));
        assert!(h.may_try(Some(1_500)));
        assert!(h.may_try(None));
    }
}
