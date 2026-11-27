//! `started_at_ms` allocation: unique per camera, seeded at start-up (ADR 0005 section 2).

use wardenlens_core::time::UnixMs;

/// Most 1 ms steps tried before giving up. A segment lasts at least 10 s, so a long run of taken
/// keys means the index or the volume is not what it claims to be.
pub(crate) const MAX_BUMPS: u32 = 1_000;

/// Why no key could be chosen.
#[derive(Debug)]
pub(crate) enum KeyError<E> {
    /// The probe failed; the key is never assumed free.
    Probe(E),
    /// [`MAX_BUMPS`] consecutive keys were taken.
    Exhausted,
    /// The next key would be after the year 2099.
    OutOfRange,
}

/// The largest key known so far: the seed (index maximum and reconciliation walk maximum) and
/// every key chosen since.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyAlloc {
    max_seen: Option<UnixMs>,
}

/// A chosen key and whether the clock went back to get it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Picked {
    pub(crate) key: UnixMs,
    /// `arrival` is earlier than a key already used (the wall clock stepped back).
    pub(crate) stepped_back: bool,
}

impl KeyAlloc {
    pub(crate) fn seeded(a: Option<UnixMs>, b: Option<UnixMs>) -> Self {
        Self {
            max_seen: a.into_iter().chain(b).max(),
        }
    }

    /// `arrival`, plus 1 ms repeated until `taken` says the key is free (no row and no file has
    /// it). Every candidate is probed, so a file that is not in the index (an orphan or a stale
    /// `.part`) is found whatever the seed says, and a forward step of the clock does not
    /// compress the index. The largest key seen counts as taken without a probe: its file may
    /// have been quarantined, and a name is not handed out twice by one run.
    pub(crate) fn pick<E>(
        &mut self,
        arrival: UnixMs,
        mut taken: impl FnMut(UnixMs) -> Result<bool, E>,
    ) -> Result<Picked, KeyError<E>> {
        let stepped_back = self.max_seen.is_some_and(|m| arrival < m);
        let mut key = arrival;
        let mut bumps = 0u32;
        loop {
            if self.max_seen != Some(key) && !taken(key).map_err(KeyError::Probe)? {
                break;
            }
            bumps = bumps.saturating_add(1);
            if bumps > MAX_BUMPS {
                return Err(KeyError::Exhausted);
            }
            key = key
                .as_i64()
                .checked_add(1)
                .and_then(|ms| UnixMs::new(ms).ok())
                .ok_or(KeyError::OutOfRange)?;
        }
        self.max_seen = Some(self.max_seen.map_or(key, |m| m.max(key)));
        Ok(Picked { key, stepped_back })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ms(v: i64) -> UnixMs {
        UnixMs::new(v).unwrap()
    }

    const A: i64 = 1_700_000_000_000;

    type Row = (Option<i64>, i64, &'static [i64], i64, bool);

    fn pick(seed: Option<i64>, arrival: i64, taken: &[i64]) -> Result<(i64, bool), KeyError<()>> {
        let set: HashSet<i64> = taken.iter().copied().collect();
        let mut k = KeyAlloc::seeded(seed.map(ms), None);
        k.pick(ms(arrival), |c| Ok(set.contains(&c.as_i64())))
            .map(|p| (p.key.as_i64(), p.stepped_back))
    }

    #[test]
    fn keys_follow_the_adr_rule() {
        // (seed, arrival, taken, key, stepped back)
        let rows: [Row; 9] = [
            (None, A, &[], A, false),
            (Some(A), A, &[A], A + 1, false),
            (Some(A), A + 1, &[], A + 1, false),
            (Some(A), A + 5_000_000, &[], A + 5_000_000, false),
            (Some(A), A - 1, &[], A - 1, true),
            (Some(A + 10), A, &[A, A + 1], A + 2, true),
            (Some(A + 2), A, &[A, A + 1], A + 3, true),
            // A file or row at the arrival itself, with nothing above it.
            (None, A, &[A, A + 1, A + 2], A + 3, false),
            // The largest key is skipped even when the probe says it is free.
            (Some(A + 3), A + 3, &[], A + 4, false),
        ];
        for (seed, arrival, taken, key, back) in rows {
            let got = pick(seed, arrival, taken).unwrap();
            assert_eq!(
                got,
                (key, back),
                "seed {seed:?} arrival {arrival} taken {taken:?}"
            );
        }
    }

    #[test]
    fn the_seed_is_the_larger_of_the_index_and_the_walk() {
        for (a, b) in [
            (Some(A), Some(A + 9)),
            (Some(A + 9), Some(A)),
            (None, Some(A + 9)),
            (Some(A + 9), None),
        ] {
            let mut k = KeyAlloc::seeded(a.map(ms), b.map(ms));
            let p = k.pick(ms(A + 9), |_| Ok::<_, ()>(false)).unwrap();
            assert_eq!(p.key, ms(A + 10));
        }
    }

    #[test]
    fn a_long_run_of_taken_keys_gives_up() {
        let mut k = KeyAlloc::seeded(None, None);
        let r = k.pick(ms(A), |_| Ok::<_, ()>(true));
        assert!(matches!(r, Err(KeyError::Exhausted)));
        // The bound is exact: MAX_BUMPS taken keys are skipped, one more is too many.
        let mut k = KeyAlloc::seeded(None, None);
        let n = i64::from(MAX_BUMPS);
        let p = k.pick(ms(A), |c| Ok::<_, ()>(c.as_i64() < A + n)).unwrap();
        assert_eq!(p.key, ms(A + n));
        let mut k = KeyAlloc::seeded(None, None);
        let r = k.pick(ms(A), |c| Ok::<_, ()>(c.as_i64() <= A + n));
        assert!(matches!(r, Err(KeyError::Exhausted)));
    }

    #[test]
    fn the_end_of_2099_is_out_of_range_not_a_wrap() {
        let end = 4_102_444_799_999;
        let r = pick(Some(end), end, &[]);
        assert!(matches!(r, Err(KeyError::OutOfRange)));
        let r = pick(None, end, &[end]);
        assert!(matches!(r, Err(KeyError::OutOfRange)));
    }

    #[test]
    fn a_failed_probe_is_an_error_never_a_free_key() {
        let mut k = KeyAlloc::seeded(None, None);
        let r = k.pick(ms(A), |_| Err::<bool, _>("io"));
        assert!(matches!(r, Err(KeyError::Probe("io"))));
    }
}
