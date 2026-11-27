//! [`Frame`] and the pure mapping from a depacketized retina frame to it.
//!
//! [`FrameMapper::map`] takes plain values, not retina types, so every branch is unit tested with
//! synthetic input. The retina adapter in `session` only copies fields into [`RawVideoFrame`].

use wardenlens_core::time::Timestamp;
use wardenlens_core::video::{self, nal_units};
pub use wardenlens_core::video::{Frame, H264Params};

use crate::sps::{ReorderVerdict, SpsError, sps_reordering};

/// Reordering verdict of a parameter set pair (ADR 0005 open risk 1). `H264Params` lives in core,
/// so the SPS reader of this crate extends it through a trait; import it to call `reordering`.
pub trait H264ParamsExt {
    /// Whether this SPS allows frame reordering.
    ///
    /// # Errors
    /// [`SpsError`] when the SPS cannot be read; the stream is still delivered.
    fn reordering(&self) -> Result<ReorderVerdict, SpsError>;
}

impl H264ParamsExt for H264Params {
    fn reordering(&self) -> Result<ReorderVerdict, SpsError> {
        sps_reordering(&self.sps)
    }
}

/// Largest accepted frame (AVCC bytes). A bigger frame is dropped and counted (ADR 0005 section 2).
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Longest accepted SPS or PPS NAL unit. Real ones are under 1 KiB; the bound keeps a hostile
/// camera from making every parameter change allocate without limit.
pub const MAX_PARAM_SET_BYTES: usize = 4096;

/// The RTP clock rate of H.264 video (RFC 6184 section 8.2.1).
pub const H264_CLOCK_RATE_HZ: u32 = 90_000;

/// The parameter sets as retina reports them, before the size check.
#[derive(Clone, PartialEq, Eq)]
pub struct RawParams {
    /// The SPS NAL unit.
    pub sps: Vec<u8>,
    /// The PPS NAL unit.
    pub pps: Vec<u8>,
}

/// What the retina adapter copies out of a retina `VideoFrame`.
pub struct RawVideoFrame {
    /// AVCC data (retina's `FrameFormat::MP4`).
    pub data: Vec<u8>,
    /// Retina's `is_random_access_point`.
    pub is_random_access_point: bool,
    /// Retina's unwrapped RTP timestamp (`i64`, may be negative before the stream start).
    pub rtp_timestamp: i64,
    /// The stream's RTP clock rate in Hz.
    pub clock_rate: u32,
    /// RTP packets lost before this frame.
    pub loss: u16,
    /// The stream's parameter sets, present when they are new or still wanted
    /// ([`FrameMapper::wants_params`]).
    pub params: Option<RawParams>,
}

/// Why a frame could not be mapped. The stream is ended; the frame is not delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MapError {
    /// The RTP clock rate is not 90 kHz, so `rtp_ts_90k` would be wrong.
    #[error("video RTP clock rate is not 90 kHz")]
    UnsupportedClockRate,
    /// The data is not a sequence of length-prefixed NAL units.
    #[error("frame is not valid AVCC data")]
    MalformedFrame,
    /// An SPS or PPS is empty or longer than [`MAX_PARAM_SET_BYTES`].
    #[error("parameter set is empty or longer than the limit")]
    BadParameterSet,
}

/// Maps frames and keeps the three facts that outlive one frame: whether the next frame follows a
/// gap, which parameter sets have not been delivered yet, and how many frames were dropped.
#[derive(Debug)]
pub struct FrameMapper {
    pending_discontinuity: bool,
    pending_params: Option<H264Params>,
    params_delivered: bool,
    dropped_oversize: u64,
}

impl Default for FrameMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameMapper {
    /// A mapper for a new session: its first frame is a discontinuity and carries the parameters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_discontinuity: true,
            pending_params: None,
            params_delivered: false,
            dropped_oversize: 0,
        }
    }

    /// Frames dropped because they were larger than [`MAX_FRAME_BYTES`].
    #[must_use]
    pub fn dropped_oversize(&self) -> u64 {
        self.dropped_oversize
    }

    /// Whether the adapter should pass the stream's current parameters with the next frame even if
    /// retina does not say they changed: no frame has delivered them yet.
    #[must_use]
    pub fn wants_params(&self) -> bool {
        !self.params_delivered && self.pending_params.is_none()
    }

    /// Maps one frame. `Ok(None)` means the frame was dropped (oversize) and counted; the next
    /// delivered frame has `discontinuity` set and carries any parameters the dropped one changed.
    ///
    /// # Errors
    /// [`MapError`] for a clock rate other than 90 kHz, data that is not AVCC, or a parameter set
    /// that is empty or too long. Nothing in the error depends on the input bytes.
    pub fn map(
        &mut self,
        raw: RawVideoFrame,
        arrival: Timestamp,
    ) -> Result<Option<Frame>, MapError> {
        if raw.clock_rate != H264_CLOCK_RATE_HZ {
            return Err(MapError::UnsupportedClockRate);
        }
        let params = raw.params.map(convert_params).transpose()?;
        if raw.data.len() > MAX_FRAME_BYTES {
            self.dropped_oversize = self.dropped_oversize.saturating_add(1);
            self.pending_discontinuity = true;
            if params.is_some() {
                self.pending_params = params;
            }
            return Ok(None);
        }
        check_avcc(&raw.data)?;
        // Always consume the held value: a newer change must not leave a stale one behind.
        let held = self.pending_params.take();
        let params = params.or(held);
        self.params_delivered |= params.is_some();
        let discontinuity = self.pending_discontinuity || raw.loss > 0;
        self.pending_discontinuity = false;
        Ok(Some(Frame::new(
            raw.data,
            raw.is_random_access_point,
            rtp_low_32(raw.rtp_timestamp),
            arrival,
            params,
            discontinuity,
        )))
    }
}

fn convert_params(raw: RawParams) -> Result<H264Params, MapError> {
    let ok = |n: &[u8]| !n.is_empty() && n.len() <= MAX_PARAM_SET_BYTES;
    if ok(&raw.sps) && ok(&raw.pps) {
        Ok(H264Params::new(raw.sps, raw.pps))
    } else {
        Err(MapError::BadParameterSet)
    }
}

/// The 32 bits an RTP header carries.
fn rtp_low_32(unwrapped: i64) -> u32 {
    u32::try_from(unwrapped.rem_euclid(1_i64 << 32)).unwrap_or(0)
}

fn check_avcc(data: &[u8]) -> Result<(), MapError> {
    if data.is_empty() {
        return Err(MapError::MalformedFrame);
    }
    for nal in nal_units(data) {
        nal.map_err(|_| MapError::MalformedFrame)?;
    }
    Ok(())
}

/// Whether any slice in this AVCC frame is a B slice (`slice_type` 1 or 6, spec table 7-6): the
/// evidence that a stream reorders frames where the SPS says `Undetermined`. The scan lives in
/// core (the recorder runs it on every frame); this maps its error to [`MapError`].
///
/// # Errors
/// [`MapError::MalformedFrame`] when the data is not AVCC, a slice header is cut off or a
/// `slice_type` is above 9.
pub fn contains_b_slice(avcc: &[u8]) -> Result<bool, MapError> {
    video::contains_b_slice(avcc).map_err(|_| MapError::MalformedFrame)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::arithmetic_side_effects,
        clippy::many_single_char_names,
        reason = "test arithmetic on small values; short names in tables"
    )]
    use super::*;
    use crate::testsupport::{avcc, slice_nal};
    use proptest::prelude::*;

    const T0: Timestamp = Timestamp::from_unix_millis(1_700_000_000_000);

    fn nal(len: usize) -> Vec<u8> {
        let mut n = vec![0x41];
        n.resize(len, 0xaa);
        n
    }

    fn data() -> Vec<u8> {
        avcc(&[nal(5), nal(9)])
    }

    fn params() -> RawParams {
        RawParams {
            sps: vec![0x67, 1, 2],
            pps: vec![0x68, 3],
        }
    }

    fn raw(data: Vec<u8>) -> RawVideoFrame {
        RawVideoFrame {
            data,
            is_random_access_point: false,
            rtp_timestamp: 1000,
            clock_rate: H264_CLOCK_RATE_HZ,
            loss: 0,
            params: None,
        }
    }

    fn avcc_of_len(total: usize) -> Vec<u8> {
        // One NAL unit with a 4 byte prefix, `total` bytes in all.
        avcc(&[nal(total - 4)])
    }

    #[test]
    fn maps_every_field() {
        let mut m = FrameMapper::new();
        let r = RawVideoFrame {
            is_random_access_point: true,
            rtp_timestamp: 123_456,
            params: Some(params()),
            ..raw(data())
        };
        let f = m.map(r, T0).unwrap().unwrap();
        assert_eq!(f.data, data());
        assert!(f.is_keyframe);
        assert_eq!(f.rtp_ts_90k, 123_456);
        assert_eq!(f.arrival, T0);
        let p = f.params.unwrap();
        assert_eq!((p.sps, p.pps), (vec![0x67, 1, 2], vec![0x68, 3]));
        let g = m
            .map(raw(data()), Timestamp::from_unix_millis(5))
            .unwrap()
            .unwrap();
        assert!(!g.is_keyframe);
        assert_eq!(g.arrival, Timestamp::from_unix_millis(5));
    }

    #[test]
    fn discontinuity_sequence() {
        let mut m = FrameMapper::new();
        let mut next = |loss: u16| {
            m.map(
                RawVideoFrame {
                    loss,
                    ..raw(data())
                },
                T0,
            )
            .unwrap()
            .unwrap()
            .discontinuity
        };
        assert!(next(0), "first frame of a session");
        assert!(!next(0));
        assert!(next(1), "one lost packet");
        assert!(!next(0), "the flag does not stick");
        assert!(next(u16::MAX));
    }

    #[test]
    fn params_are_signalled_once_and_on_change() {
        let mut m = FrameMapper::new();
        assert!(m.wants_params());
        // First frame arrives before retina has parameters: still wanted next time.
        assert!(m.map(raw(data()), T0).unwrap().unwrap().params.is_none());
        assert!(m.wants_params());
        let with = |p: Option<RawParams>| RawVideoFrame {
            params: p,
            ..raw(data())
        };
        assert!(
            m.map(with(Some(params())), T0)
                .unwrap()
                .unwrap()
                .params
                .is_some()
        );
        assert!(!m.wants_params());
        assert!(m.map(with(None), T0).unwrap().unwrap().params.is_none());
        let changed = RawParams {
            sps: vec![0x67, 9],
            pps: vec![0x68, 9],
        };
        let f = m.map(with(Some(changed.clone())), T0).unwrap().unwrap();
        assert_eq!(f.params.unwrap().sps, changed.sps);
        assert!(!m.wants_params());
    }

    #[test]
    fn size_cap_boundaries() {
        for (len, delivered) in [
            (MAX_FRAME_BYTES - 1, true),
            (MAX_FRAME_BYTES, true),
            (MAX_FRAME_BYTES + 1, false),
        ] {
            let mut m = FrameMapper::new();
            let out = m.map(raw(avcc_of_len(len)), T0).unwrap();
            assert_eq!(out.is_some(), delivered, "len {len}");
            assert_eq!(m.dropped_oversize(), u64::from(!delivered), "len {len}");
        }
    }

    #[test]
    fn dropped_frame_is_counted_and_marks_the_next_one() {
        let mut m = FrameMapper::new();
        assert!(m.map(raw(data()), T0).unwrap().unwrap().discontinuity);
        assert!(!m.map(raw(data()), T0).unwrap().unwrap().discontinuity);
        // Oversize frame that also changes the parameters.
        let big = RawVideoFrame {
            params: Some(params()),
            ..raw(vec![0; MAX_FRAME_BYTES + 1])
        };
        assert_eq!(m.map(big, T0).unwrap(), None);
        assert_eq!(m.dropped_oversize(), 1);
        assert!(!m.wants_params(), "params are held back, not lost");
        let f = m.map(raw(data()), T0).unwrap().unwrap();
        assert!(f.discontinuity);
        assert_eq!(
            f.params.unwrap().sps,
            params().sps,
            "the dropped frame's change is delivered"
        );
        assert!(!m.map(raw(data()), T0).unwrap().unwrap().discontinuity);
        for _ in 0..3 {
            let _ = m.map(raw(vec![0; MAX_FRAME_BYTES + 1]), T0);
        }
        assert_eq!(m.dropped_oversize(), 4);
    }

    fn tagged(tag: u8) -> RawParams {
        RawParams {
            sps: vec![0x67, tag],
            pps: vec![0x68, tag],
        }
    }

    /// Regression (round 1): A on a normal frame, A again on an oversize frame, B on a normal
    /// frame, then none. The last frame must not get the stale A.
    #[test]
    fn stale_held_back_params_are_not_redelivered() {
        let mut m = FrameMapper::new();
        let with = |p: Option<RawParams>| RawVideoFrame {
            params: p,
            ..raw(data())
        };
        let big = |p: Option<RawParams>| RawVideoFrame {
            params: p,
            ..raw(vec![0; MAX_FRAME_BYTES + 1])
        };
        assert_eq!(
            m.map(with(Some(tagged(1))), T0)
                .unwrap()
                .unwrap()
                .params
                .unwrap()
                .sps[1],
            1
        );
        assert_eq!(m.map(big(Some(tagged(1))), T0).unwrap(), None);
        assert_eq!(
            m.map(with(Some(tagged(2))), T0)
                .unwrap()
                .unwrap()
                .params
                .unwrap()
                .sps[1],
            2
        );
        assert_eq!(m.map(with(None), T0).unwrap().unwrap().params, None);
    }

    #[test]
    fn invalid_slice_type_is_malformed() {
        for t in [10, 11, 255, u32::MAX - 1] {
            assert_eq!(
                contains_b_slice(&avcc(&[slice_nal(false, 0, t)])),
                Err(MapError::MalformedFrame),
                "{t}"
            );
        }
        assert_eq!(
            contains_b_slice(&avcc(&[slice_nal(false, 0, 9)])),
            Ok(false)
        );
    }

    #[test]
    fn oversize_with_bad_params_is_an_error_not_a_drop() {
        let mut m = FrameMapper::new();
        let r = RawVideoFrame {
            params: Some(RawParams {
                sps: vec![],
                pps: vec![1],
            }),
            ..raw(vec![0; MAX_FRAME_BYTES + 1])
        };
        assert_eq!(m.map(r, T0), Err(MapError::BadParameterSet));
        assert_eq!(m.dropped_oversize(), 0);
    }

    #[test]
    fn clock_rate_must_be_90k() {
        for rate in [0, 1, 8000, 44_100, 89_999, 90_001, u32::MAX] {
            let mut m = FrameMapper::new();
            let r = RawVideoFrame {
                clock_rate: rate,
                ..raw(data())
            };
            assert_eq!(m.map(r, T0), Err(MapError::UnsupportedClockRate), "{rate}");
        }
    }

    #[test]
    fn malformed_avcc_table() {
        let good = data();
        let mut trailing = good.clone();
        trailing.push(0);
        let rows: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("1 byte", vec![0]),
            ("3 bytes", vec![0, 0, 0]),
            ("zero length", vec![0, 0, 0, 0]),
            (
                "zero length after good",
                [good.clone(), vec![0, 0, 0, 0]].concat(),
            ),
            ("length past end", vec![0, 0, 0, 5, 1, 2, 3, 4]),
            ("huge length", vec![0xff, 0xff, 0xff, 0xff, 1]),
            ("prefix only", vec![0, 0, 0, 1]),
            ("trailing byte", trailing),
            ("trailing prefix", [good.clone(), vec![0, 0, 0]].concat()),
            ("annex b", vec![0, 0, 0, 1, 0x65, 1, 2, 3]),
        ];
        for (name, bytes) in rows {
            let mut m = FrameMapper::new();
            assert_eq!(
                m.map(raw(bytes), T0),
                Err(MapError::MalformedFrame),
                "{name}"
            );
        }
        assert!(FrameMapper::new().map(raw(good), T0).unwrap().is_some());
        // A one byte NAL unit is the smallest valid one.
        assert!(
            FrameMapper::new()
                .map(raw(vec![0, 0, 0, 1, 0x65]), T0)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn param_set_size_boundaries() {
        let sized = |sps: usize, pps: usize| RawParams {
            sps: vec![7; sps],
            pps: vec![8; pps],
        };
        let cases = [
            (sized(1, 1), true),
            (sized(MAX_PARAM_SET_BYTES, MAX_PARAM_SET_BYTES), true),
            (sized(MAX_PARAM_SET_BYTES + 1, 1), false),
            (sized(1, MAX_PARAM_SET_BYTES + 1), false),
            (sized(0, 1), false),
            (sized(1, 0), false),
        ];
        for (p, ok) in cases {
            let r = RawVideoFrame {
                params: Some(p),
                ..raw(data())
            };
            let out = FrameMapper::new().map(r, T0);
            if ok {
                assert!(out.unwrap().is_some());
            } else {
                assert_eq!(out, Err(MapError::BadParameterSet));
            }
        }
    }

    #[test]
    fn rtp_timestamp_low_32_bits() {
        let rows: [(i64, u32); 9] = [
            (0, 0),
            (1, 1),
            (4_294_967_295, u32::MAX),
            (4_294_967_296, 0),
            (4_294_967_297, 1),
            (-1, u32::MAX),
            (-4_294_967_296, 0),
            (i64::MAX, u32::MAX),
            (i64::MIN, 0),
        ];
        for (ts, want) in rows {
            let f = FrameMapper::new()
                .map(
                    RawVideoFrame {
                        rtp_timestamp: ts,
                        ..raw(data())
                    },
                    T0,
                )
                .unwrap()
                .unwrap();
            assert_eq!(f.rtp_ts_90k, want, "{ts}");
        }
    }

    #[test]
    fn debug_never_prints_video_bytes() {
        let f = FrameMapper::new()
            .map(
                RawVideoFrame {
                    params: Some(params()),
                    ..raw(vec![0, 0, 0, 2, 0x65, 0xcd])
                },
                T0,
            )
            .unwrap()
            .unwrap();
        let text = format!("{f:?}");
        assert!(text.contains("len: 6"), "{text}");
        for needle in ["205", "0xcd", "cd", "[0, 0"] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }

    #[test]
    fn b_slice_detection_table() {
        let sps = vec![0x67, 0x42, 0, 10];
        let rows: Vec<(&str, Vec<Vec<u8>>, bool)> = vec![
            ("P", vec![slice_nal(false, 0, 0)], false),
            ("B", vec![slice_nal(false, 0, 1)], true),
            ("I", vec![slice_nal(false, 0, 2)], false),
            ("SP", vec![slice_nal(false, 0, 3)], false),
            ("SI", vec![slice_nal(false, 0, 4)], false),
            ("all-P (5)", vec![slice_nal(false, 0, 5)], false),
            ("all-B (6)", vec![slice_nal(false, 0, 6)], true),
            ("all-I (7)", vec![slice_nal(true, 0, 7)], false),
            (
                "all-SP, SI (8, 9)",
                vec![slice_nal(false, 0, 8), slice_nal(false, 0, 9)],
                false,
            ),
            (
                "B after P in one frame",
                vec![slice_nal(false, 0, 0), slice_nal(false, 5, 1)],
                true,
            ),
            ("B inside IDR type", vec![slice_nal(true, 0, 1)], true),
            ("parameter set is skipped", vec![sps.clone()], false),
            ("sps then B", vec![sps, slice_nal(false, 0, 1)], true),
            // first_mb_in_slice needs an emulation prevention byte (a 23 bit Exp-Golomb prefix).
            (
                "escaped header, B",
                vec![slice_nal(false, 1 << 23, 1)],
                true,
            ),
            (
                "escaped header, P",
                vec![slice_nal(false, 1 << 23, 0)],
                false,
            ),
        ];
        for (name, nals, want) in rows {
            assert_eq!(contains_b_slice(&avcc(&nals)), Ok(want), "{name}");
        }
        let escaped = slice_nal(false, 1 << 23, 1);
        assert!(
            escaped.windows(3).any(|w| w == [0, 0, 3]),
            "the escape case must contain one"
        );
    }

    #[test]
    fn b_slice_scan_errors() {
        assert_eq!(contains_b_slice(&[0, 0, 0]), Err(MapError::MalformedFrame));
        assert_eq!(
            contains_b_slice(&[0, 0, 0, 0]),
            Err(MapError::MalformedFrame)
        );
        // A slice NAL cut right after its header.
        assert_eq!(
            contains_b_slice(&[0, 0, 0, 1, 0x41]),
            Err(MapError::MalformedFrame)
        );
        assert_eq!(contains_b_slice(&[]), Ok(false));
    }

    proptest! {
        /// Over random sequences of (oversize?, params?) frames, the parameters a delivered frame
        /// carries are exactly the newest change not yet delivered, and none is ever repeated.
        #[test]
        fn params_delivered_are_the_latest_undelivered_change(
            steps in prop::collection::vec((any::<bool>(), prop::option::of(0..4_u8)), 0..40)
        ) {
            let mut m = FrameMapper::new();
            let mut newest_undelivered: Option<u8> = None;
            for (oversize, tag) in steps {
                if let Some(t) = tag { newest_undelivered = Some(t); }
                let data = if oversize { vec![0; MAX_FRAME_BYTES + 1] } else { data() };
                let r = RawVideoFrame { params: tag.map(tagged), ..raw(data) };
                let out = m.map(r, T0).unwrap();
                if oversize {
                    prop_assert!(out.is_none());
                } else {
                    let got = out.unwrap().params.map(|p| p.sps[1]);
                    prop_assert_eq!(got, newest_undelivered);
                    newest_undelivered = None;
                }
            }
        }

        /// Whatever bytes arrive, mapping never panics; a delivered frame is valid AVCC within
        /// the cap and equals the input; a refusal is typed.
        #[test]
        fn arbitrary_input_is_total(
            data in prop::collection::vec(any::<u8>(), 0..64),
            ts in any::<i64>(),
            rate in prop_oneof![Just(H264_CLOCK_RATE_HZ), any::<u32>()],
            loss in any::<u16>(),
            sps in prop::option::of(prop::collection::vec(any::<u8>(), 0..8)),
        ) {
            let r = RawVideoFrame {
                data: data.clone(), is_random_access_point: false, rtp_timestamp: ts,
                clock_rate: rate, loss,
                params: sps.map(|s| RawParams { sps: s, pps: vec![1] }),
            };
            if let Ok(Some(f)) = FrameMapper::new().map(r, T0) {
                prop_assert_eq!(&f.data, &data);
                prop_assert!(f.data.len() <= MAX_FRAME_BYTES);
                prop_assert!(nal_units(&f.data).all(|n| n.is_ok()));
                prop_assert_eq!(i64::from(f.rtp_ts_90k), ts.rem_euclid(1 << 32));
            }
            let _ = contains_b_slice(&data);
        }

        /// Well-formed AVCC (valid prefixes) with hostile NAL contents is always delivered
        /// whole and never trips the B-slice scan.
        #[test]
        fn well_formed_avcc_with_hostile_contents(
            nals in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..40), 1..6)
        ) {
            let bytes = avcc(&nals);
            let f = FrameMapper::new().map(raw(bytes.clone()), T0).unwrap().unwrap();
            prop_assert_eq!(f.data, bytes.clone());
            let _ = contains_b_slice(&bytes);
        }

        /// Every proper prefix of valid AVCC with at least one NAL is refused.
        #[test]
        fn avcc_truncation_sweep(nals in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..20), 1..4)) {
            let bytes = avcc(&nals);
            let mut ends = vec![0];
            let mut at = 0;
            for n in &nals { at += 4 + n.len(); ends.push(at); }
            for cut in 0..bytes.len() {
                let ok = FrameMapper::new().map(raw(bytes[..cut].to_vec()), T0);
                // A cut on a NAL boundary is valid AVCC (with fewer NAL units), except empty.
                let boundary = cut > 0 && ends.contains(&cut);
                prop_assert_eq!(ok.is_ok(), boundary, "cut {}", cut);
            }
        }
    }
}
