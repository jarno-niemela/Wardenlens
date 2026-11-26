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
/// segment rows (ADR 0005 section 6). It is retention, not safety: it runs after the plan's
/// actions of a tick, each tier pass with a bound of its own (`max_actions_per_tick` again). A
/// row whose delete fails is skipped and reported, and a paging cursor carried across ticks lets
/// the cap continue past it. With the archive available the rows of both tiers together are
/// capped: the oldest deletable archive rows go first, and what the archive cannot supply comes
/// from the oldest hot rows. With the archive unavailable only the hot tier's own excess is
/// evicted: hot video is never deleted because of archive rows. The cap is a fixed, generic
/// bound, not a per-site setting.
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
