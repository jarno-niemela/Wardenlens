//! AVCC framing and the B-slice check.

use super::bits::{Bits, unescape};

/// Why AVCC data is not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("frame is not valid AVCC data")]
pub struct AvccError;

/// The NAL units of AVCC data (4 byte big-endian lengths). Yields an error and then stops when a
/// length is zero, or runs past the end. No allocation.
pub fn nal_units(data: &[u8]) -> impl Iterator<Item = Result<&[u8], AvccError>> {
    let mut rest = data;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let parsed = rest
            .split_first_chunk::<4>()
            .and_then(|(len, tail)| {
                let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
                (len > 0 && len <= tail.len()).then(|| tail.split_at(len))
            })
            .ok_or(AvccError);
        match parsed {
            Ok((nal, tail)) => {
                rest = tail;
                Some(Ok(nal))
            }
            Err(e) => {
                rest = &[];
                Some(Err(e))
            }
        }
    })
}

/// Whether any slice in this AVCC frame is a B slice (`slice_type` 1 or 6, spec table 7-6).
///
/// Where `SpsSummary::reordering` (wardenlens-ingest) says `Undetermined`, a B
/// slice is the evidence that the stream reorders; a long run of frames without one is the
/// evidence that it does not. Only the first two syntax elements of each slice are read.
///
/// # Errors
/// [`AvccError`] when the data is not AVCC, a slice header is cut off or a
/// `slice_type` is above 9.
pub fn contains_b_slice(avcc: &[u8]) -> Result<bool, AvccError> {
    for nal in nal_units(avcc) {
        let nal = nal.map_err(|_| AvccError)?;
        let Some((&header, payload)) = nal.split_first() else {
            return Err(AvccError);
        };
        // Slice NAL unit types: 1 (non-IDR) and 5 (IDR). Partitioned slices (2 to 4) are
        // Extended profile only and also start with the same two elements, but have no B-slice
        // relevance for the cameras this serves, so they are not scanned.
        if !matches!(header & 0x1f, 1 | 5) {
            continue;
        }
        // The first bytes can hold an emulation prevention byte; 16 bytes cover two ue(v) values.
        let head = unescape(payload.get(..payload.len().min(16)).unwrap_or_default());
        let mut r = Bits::new(&head);
        r.ue().map_err(|_| AvccError)?; // first_mb_in_slice
        let slice_type = r.ue().map_err(|_| AvccError)?;
        if slice_type > 9 {
            return Err(AvccError); // table 7-6 allows 0 to 9
        }
        if matches!(slice_type, 1 | 6) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "test writer on small values"
)]
mod tests {
    use super::*;

    /// One slice NAL unit (`0x41`) whose header is `first_mb_in_slice = 0` and `slice_type`.
    fn slice(slice_type: u32) -> Vec<u8> {
        let x = u64::from(slice_type) + 1;
        let len = 64 - x.leading_zeros();
        let mut bits = vec![true];
        bits.extend(std::iter::repeat_n(
            false,
            usize::try_from(len - 1).unwrap(),
        ));
        bits.extend((0..len).rev().map(|i| (x >> i) & 1 == 1));
        while bits.len() % 8 != 0 {
            bits.push(false);
        }
        let mut nal = vec![0x41];
        nal.extend(
            bits.chunks(8)
                .map(|b| b.iter().fold(0u8, |a, v| a << 1 | u8::from(*v))),
        );
        let mut out = u32::try_from(nal.len()).unwrap().to_be_bytes().to_vec();
        out.extend(nal);
        out
    }

    #[test]
    fn slice_types_one_and_six_are_b_slices_and_above_nine_is_malformed() {
        for t in 0..=9 {
            assert_eq!(contains_b_slice(&slice(t)), Ok(t == 1 || t == 6), "{t}");
        }
        for t in [10, 11, 255] {
            assert_eq!(contains_b_slice(&slice(t)), Err(AvccError), "{t}");
        }
    }

    #[test]
    fn framing_errors_and_the_empty_frame() {
        assert_eq!(contains_b_slice(&[]), Ok(false));
        for bad in [
            &[0u8, 0, 0][..],
            &[0, 0, 0, 0],
            &[0, 0, 0, 5, 0x41],
            &[0, 0, 0, 1, 0x41],
        ] {
            assert_eq!(contains_b_slice(bad), Err(AvccError), "{bad:?}");
        }
    }

    #[test]
    fn a_b_slice_behind_a_p_slice_is_found() {
        let mut au = slice(0);
        au.extend(slice(1));
        assert_eq!(contains_b_slice(&au), Ok(true));
    }
}
