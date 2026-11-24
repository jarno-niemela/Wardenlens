//! Tiered storage policy: a pure planner that keeps both volumes above their
//! free-space floor (ADR 0005 section 6).
//!
//! The planner performs no I/O. The storage adapter probes the volumes, calls
//! [`plan`], and executes the returned actions.

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

pub use plan::{
    Action, ArchiveStatus, HotState, OverflowQuantity, Plan, PlanError, PlanInput, plan,
};
pub use types::{
    ArchiveState, MinFreePercent, MinFreePercentError, Policy, SegmentId, StoredSegment, Tier,
    VolumeSpace,
};
