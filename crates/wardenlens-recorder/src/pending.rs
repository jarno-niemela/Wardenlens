//! The open fragment: one GOP of samples waiting for the duration of the last one.

use wardenlens_mp4::{Fragment, MAX_SAMPLES_PER_FRAGMENT, Mp4Error, Sample};

/// A sample duration is clamped to 1..=900,000 ticks (ADR 0005 section 2).
const MAX_DURATION_TICKS: u64 = 900_000;

#[derive(Debug)]
struct PendingSample {
    data: Vec<u8>,
    dts: u64,
    is_sync: bool,
}

/// Samples of the open fragment, in decode order.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    samples: Vec<PendingSample>,
    /// Sum of the sample sizes.
    payload: u64,
}

/// Bytes a fragment adds besides its samples: `moof` with `mfhd`, `traf`, `tfhd`, `tfdt` and the
/// `trun` header (80 bytes, with slack to 128, the bound the adoption parser also uses) and the
/// `mdat` header.
const FRAGMENT_OVERHEAD: u64 = 128 + 8;
/// Bytes a sample adds to the `trun` table (duration, size, flags).
const SAMPLE_OVERHEAD: u64 = 12;

/// An upper bound of the bytes of a fragment of `samples` samples holding `payload` bytes.
pub(crate) fn fragment_bound(samples: u64, payload: u64) -> u64 {
    payload
        .saturating_add(samples.saturating_mul(SAMPLE_OVERHEAD))
        .saturating_add(FRAGMENT_OVERHEAD)
}

fn clamp_duration(ticks: u64) -> u32 {
    u32::try_from(ticks.clamp(1, MAX_DURATION_TICKS)).unwrap_or(u32::MAX)
}

impl Pending {
    pub(crate) fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// An upper bound of the bytes this fragment will take on disk when it is written.
    pub(crate) fn bound(&self) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        fragment_bound(
            u64::try_from(self.samples.len()).unwrap_or(u64::MAX),
            self.payload,
        )
    }

    /// Whether one more sample would pass the `trun` table bound.
    pub(crate) fn is_full(&self) -> bool {
        self.samples.len() >= MAX_SAMPLES_PER_FRAGMENT
    }

    pub(crate) fn push(&mut self, data: Vec<u8>, dts: u64, is_sync: bool) {
        self.payload = self
            .payload
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        self.samples.push(PendingSample { data, dts, is_sync });
    }

    /// Writes the fragment into `out` and empties it; returns its duration in ticks.
    ///
    /// Each sample lasts until the next one starts. The last lasts until `next_dts` (the first
    /// sample of the next fragment) or, when the segment ends, `last_step` (the previous step,
    /// at least 1; ADR 0005 section 2). `sequence` is the `mfhd` number and `base` the decode
    /// time of the first sample (the sum of the durations written before).
    pub(crate) fn encode(
        &mut self,
        sequence: u32,
        base: u64,
        next_dts: Option<u64>,
        last_step: u64,
        out: &mut Vec<u8>,
    ) -> Result<u64, Mp4Error> {
        let mut durations = Vec::with_capacity(self.samples.len());
        for (cur, next) in self.samples.iter().zip(self.samples.iter().skip(1)) {
            durations.push(clamp_duration(next.dts.saturating_sub(cur.dts)));
        }
        let last = self.samples.last();
        let tail = match (last, next_dts) {
            (Some(l), Some(n)) => n.saturating_sub(l.dts),
            _ => last_step,
        };
        durations.push(clamp_duration(tail));
        let samples: Vec<Sample<'_>> = self
            .samples
            .iter()
            .zip(&durations)
            .map(|(s, d)| Sample {
                data: &s.data,
                duration: *d,
                is_sync: s.is_sync,
            })
            .collect();
        out.clear();
        Fragment::write(sequence, base, &samples, out)?;
        self.samples.clear();
        self.payload = 0;
        Ok(durations.iter().map(|d| u64::from(*d)).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AU: [u8; 6] = [0, 0, 0, 2, 0x41, 0xaa];

    fn filled(dts: &[u64]) -> Pending {
        let mut p = Pending::default();
        for (i, d) in dts.iter().enumerate() {
            p.push(AU.to_vec(), *d, i == 0);
        }
        p
    }

    #[test]
    fn durations_are_the_gaps_and_the_tail_rule() {
        // (dts, next fragment's first dts, last step, total ticks)
        let rows: [(&[u64], Option<u64>, u64, u64); 8] = [
            (&[0, 3000, 6000], Some(9000), 1, 9000),
            (&[0, 3000, 6000], None, 3000, 9000),
            (&[0, 3000, 6000], None, 0, 6001),
            (&[0], None, 1, 1),
            (&[0], Some(0), 7, 1),
            (&[0, 5_000_000], None, 7, 900_007),
            (&[0, 5_000_000], Some(9_000_000), 7, 1_800_000),
            (&[10, 11, 12], Some(13), 1, 3),
        ];
        for (dts, next, step, want) in rows {
            let mut out = Vec::new();
            let got = filled(dts).encode(1, 0, next, step, &mut out).unwrap();
            assert_eq!(got, want, "{dts:?} {next:?} {step}");
            assert_ne!(out.len(), 0);
        }
    }

    #[test]
    fn encoding_empties_the_fragment_and_an_empty_one_is_an_error() {
        let mut p = filled(&[0, 1]);
        let mut out = Vec::new();
        p.encode(1, 0, None, 1, &mut out).unwrap();
        assert!(p.is_empty());
        assert!(p.encode(2, 2, None, 1, &mut out).is_err());
    }

    /// The bound is never below the real size of the fragment (the adoption limit rests on it).
    #[test]
    fn the_fragment_bound_covers_the_encoded_size() {
        for n in [1_usize, 2, 3, 50, 1000] {
            let mut p = Pending::default();
            for i in 0..n {
                p.push(AU.to_vec(), u64::try_from(i).unwrap(), i == 0);
            }
            let bound = p.bound();
            let mut out = Vec::new();
            p.encode(1, 0, None, 1, &mut out).unwrap();
            assert!(u64::try_from(out.len()).unwrap() <= bound, "{n} samples");
            assert_eq!(p.bound(), 0, "emptied");
        }
    }

    #[test]
    fn the_sample_table_bound_is_exact() {
        let mut p = Pending::default();
        for i in 0..MAX_SAMPLES_PER_FRAGMENT {
            assert!(!p.is_full(), "{i}");
            p.push(AU.to_vec(), u64::try_from(i).unwrap(), false);
        }
        assert!(p.is_full());
    }
}
