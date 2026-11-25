//! Invariants 2 and 3: segment operations against the model, and the cursor walk.

use proptest::prelude::*;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{
    IndexedSegment, MAX_LIST_LIMIT, MAX_OLDEST, SegmentCursor, SegmentId, SegmentIndex,
    SegmentPage, StoredSegment, Tier, TierTotals,
};
use wardenlens_core::time::UnixMs;

use super::model::{HasKind, Kind, Model};
use super::*;
use crate::error::IndexError;

const CAMS: [&str; 3] = ["cam1", "cam2", "a"];
const DURS: [u64; 6] = [1, 5_000, 10_000, 10_001, 120_000, 600_000];

#[derive(Debug, Clone)]
enum Op {
    Insert {
        cam: usize,
        start: i64,
        dur: u64,
        bytes: u64,
        frames: u64,
        tier: bool,
    },
    Get(u64),
    List {
        cam: usize,
        from: i64,
        to: i64,
        limit: usize,
    },
    Walk {
        cam: usize,
        from: i64,
        to: i64,
        limit: usize,
        between: Vec<Op>,
    },
    SetTier(u64, bool),
    Delete(u64),
    Oldest(bool, usize),
    OldestWalk {
        tier: bool,
        n: usize,
        between: Vec<Op>,
    },
    Bytes,
    Latest(usize),
}

fn tier(b: bool) -> Tier {
    if b { Tier::Archive } else { Tier::Hot }
}

#[derive(Debug, PartialEq)]
enum Out {
    Inserted(u64),
    Got(Option<IndexedSegment>),
    Page(Vec<IndexedSegment>, bool),
    Walked(Vec<Vec<IndexedSegment>>),
    Unit,
    Oldest(Vec<StoredSegment>),
    OldestPages(Vec<Vec<StoredSegment>>),
    Totals(TierTotals),
    Latest(Option<UnixMs>),
    Err(Kind),
}

fn time() -> impl Strategy<Value = i64> {
    prop_oneof![
        8 => (-3_i64..60).prop_map(|j| BASE + j * 5_000),
        1 => Just(i64::MIN), 1 => Just(i64::MAX), 1 => Just(0_i64),
    ]
}

fn limit() -> impl Strategy<Value = usize> {
    prop_oneof![
        4 => 1_usize..5,
        1 => Just(0_usize), 1 => Just(1000_usize), 1 => Just(1001_usize), 1 => Just(usize::MAX),
    ]
}

fn simple_op() -> impl Strategy<Value = Op> {
    let id = prop_oneof![8 => 0_u64..14, 1 => Just(u64::MAX), 1 => Just(i64::MAX as u64 + 1), 1 => Just(i64::MAX as u64)];
    prop_oneof![
        6 => (0..3_usize, 0_i64..10, 0..6_usize, prop_oneof![9 => 1_u64..1_000_000, 1 => Just(0_u64), 1 => Just(u64::MAX), 1 => Just(1_u64 << 36), 1 => Just((1_u64 << 36) + 1)], prop_oneof![9 => 1_u64..100, 1 => Just(0_u64)], any::<bool>())
            .prop_map(|(cam, k, d, bytes, frames, t)| Op::Insert {
                cam, start: BASE + k * 10_000, dur: DURS[d], bytes, frames, tier: t }),
        // Out-of-range duration.
        1 => (0..3_usize, 0_i64..10).prop_map(|(cam, k)| Op::Insert { cam, start: BASE + k * 10_000, dur: 600_001, bytes: 1, frames: 1, tier: false }),
        1 => (0..3_usize).prop_map(|cam| Op::Insert { cam, start: BASE, dur: 0, bytes: 1, frames: 1, tier: false }),
        2 => id.clone().prop_map(Op::Get),
        3 => (id.clone(), any::<bool>()).prop_map(|(i, t)| Op::SetTier(i, t)),
        3 => id.prop_map(Op::Delete),
        2 => (any::<bool>(), prop_oneof![2 => 1_usize..6, 1 => Just(0), 1 => Just(MAX_OLDEST), 1 => Just(MAX_OLDEST + 1)]).prop_map(|(t, n)| Op::Oldest(t, n)),
        1 => Just(Op::Bytes),
        1 => (0..3_usize).prop_map(Op::Latest),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => simple_op(),
        3 => (0..3_usize, time(), time(), limit()).prop_map(|(cam, from, to, limit)| Op::List { cam, from, to, limit }),
        2 => (any::<bool>(), 1_usize..4, prop::collection::vec(simple_op(), 0..3))
            .prop_map(|(tier, n, between)| Op::OldestWalk { tier, n, between }),
        2 => (0..3_usize, time(), time(), 1_usize..4, prop::collection::vec(simple_op(), 0..3))
            .prop_map(|(cam, from, to, limit, between)| Op::Walk { cam, from, to, limit, between }),
    ]
}

fn run<I: SegmentIndex>(i: &mut I, op: &Op) -> Out
where
    I::Error: HasKind,
{
    match op {
        Op::Insert {
            cam,
            start,
            dur,
            bytes,
            frames,
            tier: t,
        } => {
            let r = SegmentRecord::new(
                super::cam(CAMS[*cam]),
                UnixMs::new(*start).unwrap(),
                *dur,
                *bytes,
                *frames,
            );
            match i.insert(&r, tier(*t)) {
                Ok(id) => Out::Inserted(id.as_u64()),
                Err(e) => Out::Err(e.kind()),
            }
        }
        Op::Get(id) => i
            .get(SegmentId::new(*id))
            .map_or_else(|e| Out::Err(e.kind()), Out::Got),
        Op::List {
            cam,
            from,
            to,
            limit,
        } => match i.list(&super::cam(CAMS[*cam]), ts(*from), ts(*to), *limit, None) {
            Ok(p) => Out::Page(p.items.clone(), p.next.is_some()),
            Err(e) => Out::Err(e.kind()),
        },
        Op::Walk {
            cam,
            from,
            to,
            limit,
            between,
        } => {
            let camera = super::cam(CAMS[*cam]);
            let mut pages = Vec::new();
            let mut cursor: Option<SegmentCursor> = None;
            let mut pending = between.iter();
            loop {
                let page: SegmentPage =
                    match i.list(&camera, ts(*from), ts(*to), *limit, cursor.as_ref()) {
                        Ok(p) => p,
                        Err(e) => return Out::Err(e.kind()),
                    };
                pages.push(page.items.clone());
                match page.next {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
                if let Some(m) = pending.next() {
                    let _ = run(i, m);
                }
            }
            Out::Walked(pages)
        }
        Op::SetTier(id, t) => i
            .set_tier(SegmentId::new(*id), tier(*t))
            .map_or_else(|e| Out::Err(e.kind()), |()| Out::Unit),
        Op::Delete(id) => i
            .delete(SegmentId::new(*id))
            .map_or_else(|e| Out::Err(e.kind()), |()| Out::Unit),
        Op::Oldest(t, n) => i
            .oldest(tier(*t), None, *n)
            .map_or_else(|e| Out::Err(e.kind()), Out::Oldest),
        Op::OldestWalk {
            tier: t,
            n,
            between,
        } => {
            let mut pages = Vec::new();
            let mut after = None;
            let mut pending = between.iter();
            loop {
                let page = match i.oldest(tier(*t), after, *n) {
                    Ok(p) => p,
                    Err(e) => return Out::Err(e.kind()),
                };
                let full = page.len() == *n;
                after = page.last().map(|s| (s.ended_at, s.id));
                pages.push(page);
                if !full {
                    break;
                }
                if let Some(m) = pending.next() {
                    let _ = run(i, m);
                }
            }
            Out::OldestPages(pages)
        }
        Op::Bytes => i
            .bytes_by_tier()
            .map_or_else(|e| Out::Err(e.kind()), Out::Totals),
        Op::Latest(c) => i
            .latest_started_at(&super::cam(CAMS[*c]))
            .map_or_else(|e| Out::Err(e.kind()), Out::Latest),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// The model and the database agree after any sequence of operations, results included.
    #[test]
    fn index_agrees_with_the_model(ops in prop::collection::vec(op(), 1..40)) {
        let (_f, mut idx) = open_new();
        let mut model = Model::new();
        for o in &ops {
            let want = run(&mut model, o);
            let got = run(&mut idx, o);
            prop_assert_eq!(&got, &want, "op {:?}", o);
        }
        // Final state: every row, through the unbounded-by-time list of each camera.
        for c in CAMS {
            let camera = super::cam(c);
            let a = model.list(&camera, ts(i64::MIN), ts(i64::MAX), 1000, None).unwrap();
            let b = idx.list(&camera, ts(i64::MIN), ts(i64::MAX), 1000, None).unwrap();
            prop_assert_eq!(a.items, b.items);
        }
    }
}

/// Mutation check of the generator: the properties above reach duplicates, not-found and
/// multi-page walks (counted over a fixed seed sweep, not by timing).
#[test]
fn generator_reaches_the_interesting_branches() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let strat = prop::collection::vec(op(), 20..40);
    let (mut dup, mut nf, mut multi, mut already) = (0, 0, 0, 0);
    for _ in 0..60 {
        let ops = strat.new_tree(&mut runner).unwrap().current();
        let (_f, mut idx) = open_new();
        for o in &ops {
            match run(&mut idx, o) {
                Out::Err(Kind::Duplicate) => dup += 1,
                Out::Err(Kind::NotFound) => nf += 1,
                Out::Err(Kind::AlreadyOnTier) => already += 1,
                Out::Walked(p) if p.len() > 1 => multi += 1,
                _ => {}
            }
        }
    }
    assert!(
        dup > 0 && nf > 0 && multi > 0 && already > 0,
        "{dup} {nf} {multi} {already}"
    );
}

fn ins(idx: &mut Index, c: &str, start: i64, dur: u64) -> SegmentId {
    idx.insert(&rec(c, start, dur, 100, 3), Tier::Hot).unwrap()
}

fn starts(p: &SegmentPage) -> Vec<i64> {
    p.items
        .iter()
        .map(|s| s.record.started_at_ms.as_i64())
        .collect()
}

#[test]
fn insert_get_roundtrip_returns_every_field() {
    let (_f, mut idx) = open_new();
    let r = rec("cam1", BASE, 1234, 5678, 9);
    let id = idx.insert(&r, Tier::Archive).unwrap();
    let got = idx.get(id).unwrap().unwrap();
    assert_eq!(got.id, id);
    assert_eq!(got.tier, Tier::Archive);
    assert_eq!(got.record, r);
}

#[test]
fn ids_are_never_reused_after_deleting_the_newest_row() {
    let (_f, mut idx) = open_new();
    let a = ins(&mut idx, "cam1", BASE, 10);
    idx.delete(a).unwrap();
    let b = ins(&mut idx, "cam1", BASE, 10);
    assert!(b.as_u64() > a.as_u64());
}

#[test]
fn duplicate_camera_and_start_is_typed_and_burns_no_id() {
    let (_f, mut idx) = open_new();
    let a = ins(&mut idx, "cam1", BASE, 10);
    let e = idx
        .insert(&rec("cam1", BASE, 99, 1, 1), Tier::Hot)
        .unwrap_err();
    assert!(matches!(e, IndexError::Duplicate));
    assert_eq!(ins(&mut idx, "cam2", BASE, 10).as_u64(), a.as_u64() + 1);
}

#[test]
fn insert_bounds_each_field_exactly() {
    let (_f, mut idx) = open_new();
    let bad = |idx: &mut Index, r: SegmentRecord, field: &str| {
        let e = idx.insert(&r, Tier::Hot).unwrap_err();
        assert!(
            matches!(e, IndexError::InvalidRecord { field: f } if f == field),
            "{e:?}"
        );
    };
    bad(&mut idx, rec("cam1", BASE, 0, 1, 1), "duration_ms");
    bad(&mut idx, rec("cam1", BASE, 600_001, 1, 1), "duration_ms");
    bad(&mut idx, rec("cam1", BASE, 1, 0, 1), "bytes");
    bad(&mut idx, rec("cam1", BASE, 1, u64::MAX, 1), "bytes");
    bad(&mut idx, rec("cam1", BASE, 1, (1 << 36) + 1, 1), "bytes");
    bad(&mut idx, rec("cam1", BASE, 1, 1, 0), "frame_count");
    bad(&mut idx, rec("cam1", BASE, 1, 1, u64::MAX), "frame_count");
    idx.insert(
        &rec("cam1", BASE, 600_000, 1 << 36, i64::MAX as u64),
        Tier::Hot,
    )
    .unwrap();
    idx.insert(&rec("cam1", BASE + 1, 1, 1, 1), Tier::Hot)
        .unwrap();
    // The ends of the wall-clock window are accepted.
    idx.insert(&rec("cam1", 946_684_800_000, 1, 1, 1), Tier::Hot)
        .unwrap();
    idx.insert(&rec("cam1", 4_102_444_799_999, 600_000, 1, 1), Tier::Hot)
        .unwrap();
}

#[test]
fn limits_are_validated_before_anything_else() {
    let (_f, idx) = open_new();
    let c = cam("cam1");
    for (limit, ok) in [
        (0, false),
        (1, true),
        (1000, true),
        (1001, false),
        (usize::MAX, false),
    ] {
        let r = idx.list(&c, ts(0), ts(10), limit, None);
        assert_eq!(r.is_ok(), ok, "list limit {limit}");
        if !ok {
            assert!(matches!(
                r.unwrap_err(),
                IndexError::InvalidLimit { max: 1000, .. }
            ));
        }
    }
    for (n, ok) in [
        (0, false),
        (1, true),
        (MAX_OLDEST, true),
        (MAX_OLDEST + 1, false),
    ] {
        assert_eq!(idx.oldest(Tier::Hot, None, n).is_ok(), ok, "oldest n {n}");
    }
    assert_eq!(MAX_LIST_LIMIT, 1000);
}

#[test]
fn page_of_1000_and_a_next_cursor_after_1001_rows() {
    let (_f, mut idx) = open_new();
    for k in 0..1001 {
        ins(&mut idx, "cam1", BASE + k * 1000, 500);
    }
    let c = cam("cam1");
    let p1 = idx.list(&c, ts(0), ts(i64::MAX), 1000, None).unwrap();
    assert_eq!(p1.items.len(), 1000);
    let p2 = idx
        .list(&c, ts(0), ts(i64::MAX), 1000, p1.next.as_ref())
        .unwrap();
    assert_eq!(p2.items.len(), 1);
    assert!(p2.next.is_none());
    // Exactly one page of rows: no cursor to an empty page.
    let exact = idx
        .list(&c, ts(0), ts(BASE + 1000 * 1000), 1000, None)
        .unwrap();
    assert_eq!(exact.items.len(), 1000);
    assert!(exact.next.is_none());
}

/// Boundary table: segment [BASE, BASE+1000). Half-open range [from, to).
#[test]
fn range_boundaries_are_half_open_and_overlap_based() {
    let (_f, mut idx) = open_new();
    ins(&mut idx, "cam1", BASE, 1000);
    let c = cam("cam1");
    let hit = |idx: &Index, from: i64, to: i64| {
        !idx.list(&c, ts(from), ts(to), 10, None)
            .unwrap()
            .items
            .is_empty()
    };
    let table = [
        (
            BASE - 1000,
            BASE,
            false,
            "range ends exactly where the segment starts",
        ),
        (
            BASE - 1000,
            BASE + 1,
            true,
            "range reaches one ms into the segment",
        ),
        (BASE, BASE + 1, true, "from equals the start: included"),
        (
            BASE + 999,
            BASE + 2000,
            true,
            "from is the last ms of the segment",
        ),
        (
            BASE + 1000,
            BASE + 2000,
            false,
            "from equals the end: excluded",
        ),
        (BASE + 1, BASE + 2, true, "range inside the segment"),
        (i64::MIN, i64::MAX, true, "everything"),
        (BASE, BASE, false, "empty range"),
        (BASE + 10, BASE, false, "inverted range"),
        (
            BASE + 500,
            BASE + 100,
            false,
            "inverted range inside the segment",
        ),
        (i64::MAX, i64::MIN, false, "inverted extremes"),
    ];
    for (from, to, want, why) in table {
        assert_eq!(hit(&idx, from, to), want, "{why}");
    }
}

#[test]
fn long_segment_starting_far_before_from_is_found_exactly() {
    let (_f, mut idx) = open_new();
    ins(&mut idx, "cam1", BASE, 600_000);
    let c = cam("cam1");
    let n = |from: i64, to: i64| {
        idx.list(&c, ts(from), ts(to), 10, None)
            .unwrap()
            .items
            .len()
    };
    assert_eq!(n(BASE + 599_999, BASE + 700_000), 1);
    assert_eq!(n(BASE + 600_000, BASE + 700_000), 0);
}

#[test]
fn list_never_returns_another_camera() {
    let (_f, mut idx) = open_new();
    ins(&mut idx, "cam1", BASE, 10);
    ins(&mut idx, "cam2", BASE, 10);
    let p = idx
        .list(&cam("cam2"), ts(0), ts(i64::MAX), 10, None)
        .unwrap();
    assert_eq!(p.items.len(), 1);
    assert_eq!(p.items[0].record.camera.as_str(), "cam2");
}

#[test]
fn set_tier_table() {
    let (_f, mut idx) = open_new();
    let id = ins(&mut idx, "cam1", BASE, 10);
    assert!(
        matches!(idx.set_tier(id, Tier::Hot), Err(IndexError::AlreadyOnTier(n)) if n == id.as_u64())
    );
    idx.set_tier(id, Tier::Archive).unwrap();
    assert_eq!(idx.get(id).unwrap().unwrap().tier, Tier::Archive);
    assert!(matches!(
        idx.set_tier(id, Tier::Archive),
        Err(IndexError::AlreadyOnTier(_))
    ));
    idx.set_tier(id, Tier::Hot).unwrap();
    for unknown in [
        0,
        id.as_u64() + 1,
        i64::MAX as u64,
        i64::MAX as u64 + 1,
        u64::MAX,
    ] {
        let e = idx
            .set_tier(SegmentId::new(unknown), Tier::Archive)
            .unwrap_err();
        assert!(
            matches!(e, IndexError::NotFound(n) if n == unknown),
            "{unknown}: {e:?}"
        );
    }
}

#[test]
fn delete_table() {
    let (_f, mut idx) = open_new();
    let id = ins(&mut idx, "cam1", BASE, 10);
    idx.delete(id).unwrap();
    assert!(idx.get(id).unwrap().is_none());
    for unknown in [id.as_u64(), 0, u64::MAX, i64::MAX as u64 + 1] {
        assert!(
            matches!(idx.delete(SegmentId::new(unknown)), Err(IndexError::NotFound(n)) if n == unknown)
        );
    }
}

#[test]
fn oldest_orders_by_end_then_id_and_filters_tier() {
    let (_f, mut idx) = open_new();
    let a = ins(&mut idx, "cam1", BASE + 100, 50); // ends 150
    let b = ins(&mut idx, "cam2", BASE, 150); // ends 150, larger id
    let c = ins(&mut idx, "cam1", BASE, 10); // ends 10
    let d = idx
        .insert(&rec("cam1", BASE + 5000, 10, 7, 1), Tier::Archive)
        .unwrap();
    let ids: Vec<_> = idx
        .oldest(Tier::Hot, None, 10)
        .unwrap()
        .iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(ids, [c, a, b]);
    assert_eq!(idx.oldest(Tier::Hot, None, 2).unwrap().len(), 2);
    let arch = idx.oldest(Tier::Archive, None, 10).unwrap();
    assert_eq!((arch[0].id, arch[0].bytes), (d, 7));
    assert_eq!(arch[0].ended_at, ts(BASE + 5010));
}

#[test]
fn bytes_by_tier_sums_and_zero_fills() {
    let (_f, mut idx) = open_new();
    assert_eq!(idx.bytes_by_tier().unwrap(), TierTotals::default());
    idx.insert(&rec("cam1", BASE, 10, 100, 1), Tier::Hot)
        .unwrap();
    idx.insert(&rec("cam1", BASE + 1, 10, 50, 1), Tier::Hot)
        .unwrap();
    let t = idx.bytes_by_tier().unwrap();
    assert_eq!(
        (
            t.hot.bytes,
            t.hot.segments,
            t.archive.bytes,
            t.archive.segments
        ),
        (150, 2, 0, 0)
    );
}

#[test]
fn latest_started_at_is_per_camera() {
    let (_f, mut idx) = open_new();
    assert_eq!(idx.latest_started_at(&cam("cam1")).unwrap(), None);
    ins(&mut idx, "cam1", BASE, 10);
    ins(&mut idx, "cam1", BASE + 5000, 10);
    ins(&mut idx, "cam2", BASE + 9000, 10);
    assert_eq!(
        idx.latest_started_at(&cam("cam1")).unwrap(),
        Some(UnixMs::new(BASE + 5000).unwrap())
    );
}

/// Walk with inserts and deletes between pages: each row present throughout appears exactly once,
/// in order; a row inserted ahead of the cursor appears; one behind it does not.
#[test]
fn cursor_walk_is_exactly_once_under_concurrent_inserts_and_deletes() {
    let (_f, mut idx) = open_new();
    let ids: Vec<_> = (0..10)
        .map(|k| ins(&mut idx, "cam1", BASE + k * 1000, 500))
        .collect();
    let c = cam("cam1");
    let mut seen = Vec::new();
    let p1 = idx.list(&c, ts(0), ts(i64::MAX), 3, None).unwrap();
    seen.extend(starts(&p1));
    // Behind the cursor: an insert (must not appear) and a delete (already seen anyway).
    ins(&mut idx, "cam1", BASE + 500, 10);
    idx.delete(ids[0]).unwrap();
    // Ahead of the cursor: a delete (must vanish) and an insert (must appear).
    idx.delete(ids[4]).unwrap();
    ins(&mut idx, "cam1", BASE + 4500, 10);
    let mut cursor = p1.next;
    while let Some(cur) = cursor {
        let p = idx.list(&c, ts(0), ts(i64::MAX), 3, Some(&cur)).unwrap();
        seen.extend(starts(&p));
        cursor = p.next;
    }
    let want: Vec<i64> = [0, 1, 2, 3, 5, 6, 7, 8, 9]
        .iter()
        .map(|k| BASE + k * 1000)
        .collect();
    let mut want = want;
    want.insert(4, BASE + 4500);
    assert_eq!(seen, want);
    assert!(
        seen.windows(2).all(|w| w[0] < w[1]),
        "strictly increasing: no duplicates"
    );
}

/// A cursor is issued only when a row follows the page: exactly `limit` rows leave none,
/// `limit + 1` rows leave one, and following it returns the last row.
#[test]
fn cursor_exists_exactly_when_one_more_row_follows() {
    let (_f, mut idx) = open_new();
    let c = cam("cam1");
    for k in 0..4 {
        ins(&mut idx, "cam1", BASE + k * 1000, 500);
        let rows = usize::try_from(k + 1).unwrap();
        let page = idx.list(&c, ts(0), ts(i64::MAX), 3, None).unwrap();
        assert_eq!(page.items.len(), rows.min(3));
        assert_eq!(page.next.is_some(), rows > 3, "{rows} rows, limit 3");
        if let Some(next) = page.next {
            let rest = idx.list(&c, ts(0), ts(i64::MAX), 3, Some(&next)).unwrap();
            assert_eq!(rest.items.len(), 1);
            assert!(rest.next.is_none());
        }
    }
}

/// Keyset walk of `oldest`: pages of 2 over 5 rows, ordered by `(ended_at, id)`, with the key
/// of the last row continuing; a row inserted behind the key does not reappear.
#[test]
fn oldest_pages_by_keyset_exactly_once() {
    let (_f, mut idx) = open_new();
    let ids: Vec<_> = (0..5)
        .map(|k| ins(&mut idx, "cam1", BASE + k * 1000, 100))
        .collect();
    let p1 = idx.oldest(Tier::Hot, None, 2).unwrap();
    assert_eq!(p1.iter().map(|s| s.id).collect::<Vec<_>>(), ids[..2]);
    ins(&mut idx, "cam1", BASE - 5000, 100); // ends before the key: not seen again
    idx.delete(ids[3]).unwrap();
    let last = p1.last().unwrap();
    let p2 = idx
        .oldest(Tier::Hot, Some((last.ended_at, last.id)), 2)
        .unwrap();
    assert_eq!(
        p2.iter().map(|s| s.id).collect::<Vec<_>>(),
        [ids[2], ids[4]]
    );
    let last = p2.last().unwrap();
    assert_eq!(
        idx.oldest(Tier::Hot, Some((last.ended_at, last.id)), 2)
            .unwrap(),
        []
    );
    // Equal end times are broken by id: both rows end at BASE + 10_000.
    let a = ins(&mut idx, "cam2", BASE + 9_000, 1_000);
    let b = ins(&mut idx, "cam3", BASE + 8_000, 2_000);
    let all = idx
        .oldest(Tier::Hot, Some((ts(BASE + 9_999), SegmentId::new(0))), 10)
        .unwrap();
    assert_eq!(all.iter().map(|s| s.id).collect::<Vec<_>>(), [a, b]);
    let after_a = idx
        .oldest(Tier::Hot, Some((ts(BASE + 10_000), a)), 10)
        .unwrap();
    assert_eq!(after_a.iter().map(|s| s.id).collect::<Vec<_>>(), [b]);
    // A key above any id names no row and sorts before nothing.
    assert_eq!(
        idx.oldest(Tier::Hot, Some((ts(0), SegmentId::new(u64::MAX))), 10)
            .unwrap(),
        []
    );
}
