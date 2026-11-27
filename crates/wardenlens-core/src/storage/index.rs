//! The `SegmentIndex` port: the segment table as the recorder, the storage loop and the
//! recordings API see it (ADR 0005 section 5).
//!
//! Core defines the contract and the value types; the `wardenlens-index` crate implements it on
//! SQLite (ARCH-3). The port carries no path: a segment's path is a pure function of its camera
//! and start time ([`crate::recording::RelPath`]).
//!
//! # Time ranges
//!
//! [`SegmentIndex::list`] takes a half-open range `[from, to)`. A segment occupies
//! `[started_at, ended_at)` and is listed when it **overlaps** the range:
//! `started_at < to && ended_at > from`. So a segment that starts exactly at `from` is listed, one
//! that ends exactly at `from` is not, and one that starts exactly at `to` is not. A range with
//! `from >= to` is empty and lists nothing; it is not an error.

use crate::camera::CameraId;
use crate::recording::SegmentRecord;
use crate::time::{Timestamp, UnixMs};

use super::types::{SegmentId, StoredSegment, Tier};

/// Most rows one [`SegmentIndex::list`] page may hold.
pub const MAX_LIST_LIMIT: usize = 1000;

/// Most rows one [`SegmentIndex::oldest`] call may return. A memory bound (SEC-2): a
/// [`StoredSegment`] is a few dozen bytes, so one call holds well under a megabyte. Callers that
/// need more page through the tier with the `after` key.
pub const MAX_OLDEST: usize = 10_000;

/// Largest segment the index accepts, in bytes (64 GiB, far above the recorder's 1 GiB default cap
/// and still about 850 Mbit/s for the longest accepted segment). With it, the sum of all `bytes`
/// stays inside `i64` for up to 2^27 rows, so [`SegmentIndex::bytes_by_tier`] cannot overflow on
/// rows that `insert` accepted.
pub const MAX_SEGMENT_BYTES: u64 = 1 << 36;

/// The schema's `CHECK` on `duration_ms` (600 s; the recorder's real maximum is 120 s). One value
/// for the index's row validation and the adoption parser's bound.
pub const MAX_DURATION_MS: u64 = 600_000;

/// An opaque position in a listing.
///
/// A client gets it from [`SegmentPage::next`] and hands it back unchanged. Treat the text as
/// untrusted when it comes from a client: [`SegmentCursor::from_token`] does not validate, the
/// implementation of [`SegmentIndex::list`] does, and refuses a cursor that is malformed or that
/// was issued for another camera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentCursor(String);

impl SegmentCursor {
    /// Wraps a token without validating it.
    #[must_use]
    pub fn from_token(token: String) -> Self {
        Self(token)
    }

    /// The token text.
    #[must_use]
    pub fn as_token(&self) -> &str {
        &self.0
    }
}

/// A row of the index: a segment record with its id and tier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IndexedSegment {
    /// The id the API exposes; never reused after a delete.
    pub id: SegmentId,
    /// The tier the segment is on.
    pub tier: Tier,
    /// The recorded segment.
    pub record: SegmentRecord,
}

impl IndexedSegment {
    /// Builds a row.
    #[must_use]
    pub fn new(id: SegmentId, tier: Tier, record: SegmentRecord) -> Self {
        Self { id, tier, record }
    }
}

/// One page of a listing, ordered by `(started_at, id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SegmentPage {
    /// The rows of this page, at most the requested limit.
    pub items: Vec<IndexedSegment>,
    /// Where the next page starts; `None` when there is no further row.
    pub next: Option<SegmentCursor>,
}

impl SegmentPage {
    /// Builds a page.
    #[must_use]
    pub fn new(items: Vec<IndexedSegment>, next: Option<SegmentCursor>) -> Self {
        Self { items, next }
    }
}

/// Bytes and segment count of one tier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TierUsage {
    /// Sum of the segment sizes.
    pub bytes: u64,
    /// Number of segments.
    pub segments: u64,
}

/// [`TierUsage`] of both tiers; an empty tier is zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TierTotals {
    /// The hot tier.
    pub hot: TierUsage,
    /// The archive tier.
    pub archive: TierUsage,
}

/// Whether a failed index call may succeed when retried.
///
/// The recorder retries a transient failure of `insert` a bounded number of times and treats any
/// other (a constraint, a duplicate, a bad record, a permanent failure) as final (ADR 0005
/// section 3). The index adapter implements it for its error type.
pub trait TransientFault {
    /// True when the same call may succeed later: the database was busy or an I/O error occurred.
    fn is_transient(&self) -> bool;
}

/// The segment index.
///
/// Every method that names a segment by id reports an unknown id as an error of the
/// implementation, never as a silent success.
pub trait SegmentIndex {
    /// The implementation's error type.
    type Error: std::error::Error;

    /// Adds a segment on `tier` and returns its new id. A second segment with the same camera
    /// and start time is an error.
    ///
    /// # Errors
    /// An invalid record, a duplicate `(camera, started_at)` or a storage failure.
    fn insert(&mut self, record: &SegmentRecord, tier: Tier) -> Result<SegmentId, Self::Error>;

    /// The row with `id`, if any.
    ///
    /// # Errors
    /// A storage failure or a row that violates the schema's bounds.
    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, Self::Error>;

    /// Lists the segments of `camera` that overlap `[from, to)` (see the module docs), ordered
    /// by `(started_at, id)`, at most `limit` (1 to [`MAX_LIST_LIMIT`]) rows after `cursor`.
    ///
    /// # Errors
    /// A limit outside the range, a cursor that is malformed or belongs to another camera, or a
    /// storage failure.
    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, Self::Error>;

    /// Moves the row of `id` to `tier`. The row must exist and be on the other tier.
    ///
    /// # Errors
    /// An unknown id, a row already on `tier`, or a storage failure.
    fn set_tier(&mut self, id: SegmentId, tier: Tier) -> Result<(), Self::Error>;

    /// Deletes the row of `id`.
    ///
    /// # Errors
    /// An unknown id or a storage failure.
    fn delete(&mut self, id: SegmentId) -> Result<(), Self::Error>;

    /// Up to `n` segments of `tier` (1 to [`MAX_OLDEST`]) in the order `(ended_at, id)`, starting
    /// after the key `after` (`None` starts at the oldest).
    ///
    /// One call is bounded, so a caller that needs the whole tier **pages through it**: pass the
    /// `(ended_at, id)` of the last row of the previous page as `after` until a page comes back
    /// shorter than `n`. The key is stable under inserts and deletes between calls.
    ///
    /// # Errors
    /// An `n` outside the range, or a storage failure.
    fn oldest(
        &self,
        tier: Tier,
        after: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, Self::Error>;

    /// The newest segment of `tier` by `(ended_at, id)`, the last of what [`oldest`](Self::oldest)
    /// would list; `None` for an empty tier. For the status endpoint (ticket #63).
    ///
    /// # Errors
    /// The adapter's error.
    fn newest(&self, tier: Tier) -> Result<Option<StoredSegment>, Self::Error>;

    /// Bytes and segment counts per tier.
    ///
    /// # Errors
    /// A storage failure.
    fn bytes_by_tier(&self) -> Result<TierTotals, Self::Error>;

    /// The latest `started_at` of `camera`, for the recorder's seed.
    ///
    /// # Errors
    /// A storage failure or a row that violates the schema's bounds.
    fn latest_started_at(&self, camera: &CameraId) -> Result<Option<UnixMs>, Self::Error>;
}
