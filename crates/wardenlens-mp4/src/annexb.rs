//! Annex-B (start code) to AVCC (4-byte length prefix) conversion.

use crate::boxes::put_u32;
use crate::error::Mp4Error;
use crate::fragment::MAX_SAMPLE_LEN;

const NAL_SPS: u8 = 7;
const NAL_PPS: u8 = 8;

/// Convert one Annex-B access unit to an AVCC sample.
///
/// Start codes (`00 00 01` or `00 00 00 01`) become 4-byte big-endian NAL lengths. Trailing
/// zero bytes of a NAL (`trailing_zero_8bits`, or the leading zero of the next 4-byte start
/// code) are removed, empty NAL units are skipped, and SPS and PPS NAL units are dropped:
/// they live only in `avcC` (ADR 0005 section 3). The result can be empty if the access unit
/// held nothing else.
///
/// # Errors
/// [`Mp4Error::NoStartCode`] if there is no start code or non-zero bytes precede the first
/// one; [`Mp4Error::SampleTooLarge`] if input or output exceeds the 8 MiB single-frame limit.
pub fn annexb_to_avcc(data: &[u8]) -> Result<Vec<u8>, Mp4Error> {
    if data.len() > MAX_SAMPLE_LEN {
        return Err(Mp4Error::SampleTooLarge {
            len: data.len(),
            max: MAX_SAMPLE_LEN,
        });
    }
    // Index of the first byte of each `00 00 01`.
    let starts: Vec<usize> = data
        .windows(3)
        .enumerate()
        .filter(|(_, w)| *w == [0, 0, 1])
        .map(|(i, _)| i)
        .collect();
    let first = *starts.first().ok_or(Mp4Error::NoStartCode)?;
    if data
        .get(..first)
        .is_none_or(|lead| lead.iter().any(|b| *b != 0))
    {
        return Err(Mp4Error::NoStartCode);
    }
    let mut out = Vec::with_capacity(data.len());
    for (k, &start) in starts.iter().enumerate() {
        let begin = start.saturating_add(3);
        let end = starts
            .get(k.saturating_add(1))
            .copied()
            .unwrap_or(data.len());
        let nal = data.get(begin..end).unwrap_or_default();
        let trimmed_len = nal
            .iter()
            .rposition(|b| *b != 0)
            .map_or(0, |p| p.saturating_add(1));
        let Some(nal) = nal.get(..trimmed_len).filter(|n| !n.is_empty()) else {
            continue;
        };
        if matches!(nal.first().map(|h| h & 0x1f), Some(NAL_SPS | NAL_PPS)) {
            continue;
        }
        let len = u32::try_from(nal.len()).map_err(|_| Mp4Error::BoxTooLarge)?;
        put_u32(&mut out, len);
        out.extend_from_slice(nal);
    }
    if out.len() > MAX_SAMPLE_LEN {
        return Err(Mp4Error::SampleTooLarge {
            len: out.len(),
            max: MAX_SAMPLE_LEN,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_three_and_four_byte_start_codes() {
        let data = [0, 0, 0, 1, 0x65, 1, 2, 0, 0, 1, 0x06, 9];
        let avcc = annexb_to_avcc(&data).unwrap();
        assert_eq!(avcc, [0, 0, 0, 3, 0x65, 1, 2, 0, 0, 0, 2, 0x06, 9]);
    }

    #[test]
    fn drops_sps_and_pps() {
        let data = [0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2, 0, 0, 1, 0x41, 7];
        assert_eq!(annexb_to_avcc(&data).unwrap(), [0, 0, 0, 2, 0x41, 7]);
    }

    #[test]
    fn strips_trailing_zero_bytes() {
        let data = [0, 0, 1, 0x41, 5, 0, 0, 0, 0, 0, 1, 0x41, 6, 0, 0];
        assert_eq!(
            annexb_to_avcc(&data).unwrap(),
            [0, 0, 0, 2, 0x41, 5, 0, 0, 0, 2, 0x41, 6]
        );
    }

    #[test]
    fn keeps_emulation_prevention_bytes_inside_a_nal() {
        let data = [0, 0, 1, 0x41, 0, 0, 3, 1, 0xff];
        assert_eq!(
            annexb_to_avcc(&data).unwrap(),
            [0, 0, 0, 6, 0x41, 0, 0, 3, 1, 0xff]
        );
    }

    #[test]
    fn rejects_data_without_start_code() {
        assert!(matches!(annexb_to_avcc(&[]), Err(Mp4Error::NoStartCode)));
        assert!(matches!(
            annexb_to_avcc(&[1, 2, 3, 4]),
            Err(Mp4Error::NoStartCode)
        ));
    }

    #[test]
    fn rejects_garbage_before_first_start_code() {
        assert!(matches!(
            annexb_to_avcc(&[9, 0, 0, 1, 0x41, 1]),
            Err(Mp4Error::NoStartCode)
        ));
    }

    #[test]
    fn empty_nal_units_yield_empty_sample() {
        assert_eq!(
            annexb_to_avcc(&[0, 0, 1, 0, 0, 1]).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn rejects_input_over_the_sample_limit() {
        let data = vec![0u8; MAX_SAMPLE_LEN + 1];
        assert!(matches!(
            annexb_to_avcc(&data),
            Err(Mp4Error::SampleTooLarge { .. })
        ));
    }
}
