//! Configuration of the storage loop. The values come from the service configuration (#47):
//! no root, floor or size is built in.

use std::path::PathBuf;

use wardenlens_core::storage::Policy;

/// What the loop needs to know.
#[derive(Debug, Clone)]
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
    /// this is the "unmounted disk" case that would fill the SSD.
    pub allow_same_filesystem: bool,
}
