//! Error and outcome types. None carries a path, a camera id or a time (SEC-6).

use wardenlens_core::storage::PlanError;
use wardenlens_fsutil::FsError;

/// Why the loop could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The hot root is missing or unusable: the only volume problem that refuses to start
    /// (ADR 0005 section 8).
    #[error("hot root cannot be opened: {0}")]
    HotRoot(FsError),
    /// `max_actions_per_tick` was zero.
    #[error("max_actions_per_tick must be at least 1")]
    NoActions,
}

/// The reason a volume report cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// `capacity == 0` or the checked arithmetic overflowed (ADR 0005 section 6): never a division.
    #[error("volume is unusable (zero capacity or overflow)")]
    Unusable,
    /// A system call failed (the errno, when the failure had one).
    #[error("volume probe failed")]
    Io(Option<rustix::io::Errno>),
}

/// A failed tick. State, not a crash: the caller logs it and ticks again.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TickError {
    /// The hot volume could not be probed or is unusable.
    #[error("hot volume: {0}")]
    HotVolume(ProbeError),
    /// The index could not be read.
    #[error("the index could not be read")]
    Index,
    /// The planner refused its input.
    #[error("planner: {0}")]
    Plan(PlanError),
}
