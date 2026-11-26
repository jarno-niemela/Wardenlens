//! Configuration of the storage loop. The values come from the service configuration (#47):
//! no root, floor or size is built in.

use std::path::PathBuf;

use wardenlens_core::storage::Policy;

/// The default for `max_actions_per_tick`.
const DEFAULT_MAX_ACTIONS: usize = 64;

/// What the loop needs to know.
///
/// Build it with [`StorageConfig::new`] and the `with_*` setters (the struct is
/// `#[non_exhaustive]`, so a field added later does not break a caller).
///
/// **Segment row cap.** The loop holds at most [`MAX_SEGMENTS`](crate::MAX_SEGMENTS) (1,000,000)
/// segment rows in total, hot and archive together (ADR 0005 section 6). Above it, each tick
/// first evicts the oldest archive segments (the oldest hot ones when the archive is unavailable
/// or holds no rows) with the normal delete protocol, at most `max_actions_per_tick` of them.
/// The cap is a fixed, generic bound on memory (SEC-2), not a per-site setting; so normal
/// operation never plans from a truncated prefix.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StorageConfig {
    /// The hot root (absolute). A missing or unusable one refuses to start.
    pub hot_root: PathBuf,
    /// The archive root (absolute). A missing or unusable one is the `unavailable` state.
    pub archive_root: PathBuf,
    /// Floors, headroom age and the emergency reserve.
    pub policy: Policy,
    /// Most actions one tick executes (default 64 in the service config), so a tick cannot starve
    /// the recorder.
    pub max_actions_per_tick: usize,
    /// Accept an archive on the same filesystem as the hot root. **Tests only**: in production
    /// this is the "unmounted disk" case that would fill the SSD, so the field exists only with
    /// the `test-support` feature.
    #[cfg(feature = "test-support")]
    pub allow_same_filesystem: bool,
}

impl StorageConfig {
    /// A configuration with `max_actions_per_tick` of 64.
    #[must_use]
    pub const fn new(hot_root: PathBuf, archive_root: PathBuf, policy: Policy) -> Self {
        Self {
            hot_root,
            archive_root,
            policy,
            max_actions_per_tick: DEFAULT_MAX_ACTIONS,
            #[cfg(feature = "test-support")]
            allow_same_filesystem: false,
        }
    }

    /// Set the most actions one tick executes.
    #[must_use]
    pub const fn with_max_actions_per_tick(mut self, n: usize) -> Self {
        self.max_actions_per_tick = n;
        self
    }

    /// Accept an archive on the same filesystem as the hot root. **Tests only.**
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn with_allow_same_filesystem(mut self, allow: bool) -> Self {
        self.allow_same_filesystem = allow;
        self
    }
}
