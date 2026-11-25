//! An in-memory model of the index, as a second implementation of the core port. The tests run
//! the same operations on it and on SQLite and require identical outcomes.

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{
    IndexedSegment, MAX_LIST_LIMIT, MAX_OLDEST, SegmentCursor, SegmentId, SegmentIndex,
    SegmentPage, StoredSegment, Tier, TierTotals, TierUsage,
};
use wardenlens_core::time::{Timestamp, UnixMs};

use crate::error::IndexError;

/// The error classes both implementations must agree on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Duplicate,
    NotFound,
    AlreadyOnTier,
    InvalidLimit,
    InvalidRecord,
    InvalidCursor,
}

pub(crate) trait HasKind {
    fn kind(&self) -> Kind;
}

impl HasKind for IndexError {
    fn kind(&self) -> Kind {
        match self {
            Self::Duplicate => Kind::Duplicate,
            Self::NotFound(_) => Kind::NotFound,
            Self::AlreadyOnTier(_) => Kind::AlreadyOnTier,
            Self::InvalidLimit { .. } => Kind::InvalidLimit,
            Self::InvalidRecord { .. } => Kind::InvalidRecord,
            Self::InvalidCursor(_) => Kind::InvalidCursor,
            other => panic!("unexpected error class: {other:?}"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ModelError(pub(crate) Kind);

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
impl std::error::Error for ModelError {}
impl HasKind for ModelError {
    fn kind(&self) -> Kind {
        self.0
    }
}

#[derive(Debug, Default)]
pub(crate) struct Model {
    pub(crate) rows: Vec<IndexedSegment>,
    next_id: u64,
}

fn err<T>(k: Kind) -> Result<T, ModelError> {
    Err(ModelError(k))
}

impl Model {
    pub(crate) fn new() -> Self {
        Self {
            rows: Vec::new(),
            next_id: 1,
        }
    }
}

fn ended(r: &SegmentRecord) -> i64 {
    r.started_at_ms.as_i64() + i64::try_from(r.duration_ms).unwrap()
}

impl SegmentIndex for Model {
    type Error = ModelError;

    fn insert(&mut self, record: &SegmentRecord, tier: Tier) -> Result<SegmentId, ModelError> {
        let ok = (1..=600_000).contains(&record.duration_ms)
            && (1..=i64::MAX as u64).contains(&record.bytes)
            && (1..=i64::MAX as u64).contains(&record.frame_count);
        if !ok {
            return err(Kind::InvalidRecord);
        }
        if self.rows.iter().any(|r| {
            r.record.camera == record.camera && r.record.started_at_ms == record.started_at_ms
        }) {
            return err(Kind::Duplicate);
        }
        let id = SegmentId::new(self.next_id);
        self.next_id += 1;
        self.rows
            .push(IndexedSegment::new(id, tier, record.clone()));
        Ok(id)
    }

    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, ModelError> {
        Ok(self.rows.iter().find(|r| r.id == id).cloned())
    }

    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, ModelError> {
        if limit == 0 || limit > MAX_LIST_LIMIT {
            return err(Kind::InvalidLimit);
        }
        let after = match cursor {
            None => None,
            Some(c) => {
                let mut it = c.as_token().splitn(3, ':');
                let (Some(s), Some(i), Some(cam)) = (it.next(), it.next(), it.next()) else {
                    return err(Kind::InvalidCursor);
                };
                if cam != camera.as_str() {
                    return err(Kind::InvalidCursor);
                }
                Some((s.parse::<i64>().unwrap(), i.parse::<u64>().unwrap()))
            }
        };
        let (from, to) = (from.as_unix_millis(), to.as_unix_millis());
        let mut hits: Vec<&IndexedSegment> = if from >= to {
            Vec::new()
        } else {
            self.rows
                .iter()
                .filter(|r| &r.record.camera == camera)
                .filter(|r| r.record.started_at_ms.as_i64() < to && ended(&r.record) > from)
                .collect()
        };
        hits.sort_by_key(|r| (r.record.started_at_ms.as_i64(), r.id));
        let hits: Vec<IndexedSegment> = hits
            .into_iter()
            .filter(|r| after.is_none_or(|a| (r.record.started_at_ms.as_i64(), r.id.as_u64()) > a))
            .cloned()
            .collect();
        let more = hits.len() > limit;
        let items: Vec<IndexedSegment> = hits.into_iter().take(limit).collect();
        let next = match (more, items.last()) {
            (true, Some(l)) => Some(SegmentCursor::from_token(format!(
                "{}:{}:{}",
                l.record.started_at_ms.as_i64(),
                l.id.as_u64(),
                camera.as_str()
            ))),
            _ => None,
        };
        Ok(SegmentPage::new(items, next))
    }

    fn set_tier(&mut self, id: SegmentId, tier: Tier) -> Result<(), ModelError> {
        match self.rows.iter_mut().find(|r| r.id == id) {
            None => err(Kind::NotFound),
            Some(r) if r.tier == tier => err(Kind::AlreadyOnTier),
            Some(r) => {
                r.tier = tier;
                Ok(())
            }
        }
    }

    fn delete(&mut self, id: SegmentId) -> Result<(), ModelError> {
        match self.rows.iter().position(|r| r.id == id) {
            None => err(Kind::NotFound),
            Some(i) => {
                self.rows.remove(i);
                Ok(())
            }
        }
    }

    fn oldest(&self, tier: Tier, n: usize) -> Result<Vec<StoredSegment>, ModelError> {
        if n == 0 || n > MAX_OLDEST {
            return err(Kind::InvalidLimit);
        }
        let mut v: Vec<&IndexedSegment> = self.rows.iter().filter(|r| r.tier == tier).collect();
        v.sort_by_key(|r| (ended(&r.record), r.id));
        Ok(v.into_iter()
            .take(n)
            .map(|r| StoredSegment {
                id: r.id,
                tier: r.tier,
                bytes: r.record.bytes,
                ended_at: Timestamp::from_unix_millis(ended(&r.record)),
            })
            .collect())
    }

    fn bytes_by_tier(&self) -> Result<TierTotals, ModelError> {
        let mut t = TierTotals::default();
        for r in &self.rows {
            let u: &mut TierUsage = if r.tier == Tier::Hot {
                &mut t.hot
            } else {
                &mut t.archive
            };
            u.bytes += r.record.bytes;
            u.segments += 1;
        }
        Ok(t)
    }

    fn latest_started_at(&self, camera: &CameraId) -> Result<Option<UnixMs>, ModelError> {
        Ok(self
            .rows
            .iter()
            .filter(|r| &r.record.camera == camera)
            .map(|r| r.record.started_at_ms)
            .max())
    }
}
