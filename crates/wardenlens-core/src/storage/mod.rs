//! Tiered storage policy: a pure planner that keeps both volumes above their
//! free-space floor (ADR 0005 section 6).
//!
//! The planner performs no I/O. The storage adapter probes the volumes, calls
//! [`plan`], and executes the returned actions.

mod files;
mod index;
mod plan;
mod types;

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on small bounded values"
)]
mod proptests;
#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on small bounded values"
)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub use files::{MemoryHandle, MemorySegmentFiles};
pub use files::{OpenedSegment, SegmentFiles, SegmentOpenError};
pub use index::{
    IndexedSegment, MAX_LIST_LIMIT, MAX_OLDEST, SegmentCursor, SegmentIndex, SegmentPage,
    TierTotals, TierUsage,
};
pub use plan::{
    Action, ArchiveStatus, HotState, OverflowQuantity, Plan, PlanError, PlanInput, plan,
};
pub use types::{
    ArchiveState, DEFAULT_EMERGENCY_RESERVE_BYTES, MinFreePercent, MinFreePercentError, Policy,
    SegmentId, StoredSegment, Tier, VolumeSpace,
};
