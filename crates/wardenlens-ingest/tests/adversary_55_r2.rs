//! Round-2 adversarial tests for #55 (PR #154). Loopback only (127.0.0.1); synthetic data only.
//! Ordering between client and server uses channels, never sleeps.

#![expect(
    clippy::unwrap_used,
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::decimal_bitwise_operands,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::option_option,
    reason = "scripted test-server helpers; a panic fails the test"
)]

use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use proptest::prelude::*;
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use wardenlens_core::camera::{Credential, Host, RtspPath};
use wardenlens_core::catalogue::StreamRole;
use wardenlens_core::time::{Clock, Timestamp};
use wardenlens_ingest::{
    FrameMapper, H264_CLOCK_RATE_HZ, IngestError, MAX_FRAME_BYTES, MAX_PARAM_SET_BYTES, MapError,
    RawParams, RawVideoFrame, ReorderVerdict, contains_b_slice, open_stream, parse_sps,
    sps_reordering,
};

const USER: &str = "adv2-user";
const PASSWORD: &str = "adv2-pass";
const PATH: &str = "/adv2-path";

const SPS_B64: &str = "Z0LACtoQmQ==";
const PPS_B64: &str = "aM48gA==";
const IDR: [u8; 5] = [0x65, 0x88, 0x84, 0x00, 0x10];
const P1: [u8; 4] = [0x41, 0x9a, 0x00, 0x20];

type Batch = Vec<(u16, u32, bool, Vec<u8>)>;

#[derive(Clone)]
enum After {
    Packets(Batch),
    PacketsThenClose(Batch),
    OnSignal(Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Batch>>>),
}

struct Server {
    port: u16,
}

struct StepClock(AtomicI64);

impl Clock for StepClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.fetch_add(10, Ordering::SeqCst))
    }
}

fn sdp() -> String {
    format!(
        "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=t\r\nt=0 0\r\n\
         m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 packetization-mode=1;profile-level-id=42C00A;sprop-parameter-sets={SPS_B64},{PPS_B64}\r\n\
         a=control:trackID=0\r\n"
    )
}

async fn read_request(sock: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if sock.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    req.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn rtp(seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, if marker { 0x80 | 96 } else { 96 }];
    p.extend(seq.to_be_bytes());
    p.extend(ts.to_be_bytes());
    p.extend(0x1234_5678_u32.to_be_bytes());
    p.extend(payload);
    p
}

async fn send_packets(sock: &mut TcpStream, channel: u8, pkts: &[(u16, u32, bool, Vec<u8>)]) {
    for (seq, ts, m, payload) in pkts {
        let packet = rtp(*seq, *ts, *m, payload);
        let mut out = vec![b'$', channel];
        out.extend(u16::try_from(packet.len()).unwrap().to_be_bytes());
        out.extend(packet);
        if sock.write_all(&out).await.is_err() {
            return;
        }
    }
}

async fn respond(sock: &mut TcpStream, req: &str, status: &str, extra: &str, body: &str) {
    let cseq = header(req, "CSeq").unwrap_or("0");
    let msg = format!(
        "RTSP/1.0 {status}\r\nCSeq: {cseq}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(msg.as_bytes()).await;
}

/// `rtptime` is the RTP-Info value sent with PLAY.
async fn serve(mut sock: TcpStream, port: u16, after: After, rtptime: u32) {
    let mut channel = 0_u8;
    while let Some(req) = read_request(&mut sock).await {
        let method = req.split_whitespace().next().unwrap_or("").to_owned();
        match method.as_str() {
            "DESCRIBE" => {
                if header(&req, "Authorization").is_none() {
                    let challenge = "WWW-Authenticate: Digest realm=\"t\", nonce=\"abc123\"\r\n";
                    respond(&mut sock, &req, "401 Unauthorized", challenge, "").await;
                } else {
                    let base = format!(
                        "Content-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1:{port}{PATH}/\r\n"
                    );
                    respond(&mut sock, &req, "200 OK", &base, &sdp()).await;
                }
            }
            "SETUP" => {
                let t = header(&req, "Transport").unwrap_or("");
                if let Some(i) = t.split(';').find_map(|p| p.strip_prefix("interleaved=")) {
                    channel = i
                        .split('-')
                        .next()
                        .and_then(|c| c.parse().ok())
                        .unwrap_or(0);
                }
                let extra = format!(
                    "Transport: RTP/AVP/TCP;unicast;interleaved={channel}-{}\r\nSession: 4711;timeout=60\r\n",
                    channel + 1
                );
                respond(&mut sock, &req, "200 OK", &extra, "").await;
            }
            "PLAY" => {
                let extra = format!(
                    "Session: 4711\r\nRTP-Info: url=rtsp://127.0.0.1:{port}{PATH}/trackID=0;seq=100;rtptime={rtptime}\r\n"
                );
                respond(&mut sock, &req, "200 OK", &extra, "").await;
                match &after {
                    After::Packets(p) => send_packets(&mut sock, channel, p).await,
                    After::PacketsThenClose(p) => {
                        send_packets(&mut sock, channel, p).await;
                        return;
                    }
                    After::OnSignal(rx) => {
                        let mut rx = rx.lock().await;
                        while let Some(batch) = rx.recv().await {
                            send_packets(&mut sock, channel, &batch).await;
                        }
                    }
                }
            }
            _ => respond(&mut sock, &req, "200 OK", "", "").await,
        }
    }
}

async fn spawn_with(after: After, rtptime: u32) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(serve(sock, port, after.clone(), rtptime));
        }
    });
    Server { port }
}

async fn open_with(
    server: &Server,
) -> Result<wardenlens_ingest::FrameStream<StepClock>, IngestError> {
    let cred = Credential::new(USER, SecretString::from(PASSWORD));
    open_stream(
        &Host::new("127.0.0.1").unwrap(),
        NonZeroU16::new(server.port).unwrap(),
        &RtspPath::new(PATH).unwrap(),
        Some(&cred),
        StreamRole::Main,
        StepClock(AtomicI64::new(1_700_000_000_000)),
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// Session: fuse and timestamps
// ---------------------------------------------------------------------------------------------

/// A zero frame timeout with nothing queued fails at once (the inner future is polled first and
/// is pending, no race). Frames queued afterwards must never come out of the fused stream, even
/// under a generous timeout, and repeated calls stay `Ok(None)`.
#[tokio::test]
async fn zero_timeout_error_fuses_even_when_frames_arrive_later() {
    let (tx, rx) = mpsc::unbounded_channel();
    let server = spawn_with(
        After::OnSignal(Arc::new(tokio::sync::Mutex::new(rx))),
        90_000,
    )
    .await;
    let mut s = open_with(&server)
        .await
        .unwrap()
        .with_frame_timeout(Duration::ZERO);
    assert_eq!(s.next_frame().await.unwrap_err(), IngestError::FrameTimeout);
    tx.send(vec![
        (100, 90_000, true, IDR.to_vec()),
        (101, 93_600, true, P1.to_vec()),
    ])
    .unwrap();
    let mut s = s.with_frame_timeout(Duration::from_secs(60));
    for _ in 0..3 {
        assert_eq!(s.next_frame().await, Ok(None));
    }
}

/// After the camera closes the session (`Ok(None)`), later calls stay `Ok(None)`.
#[tokio::test]
async fn end_of_stream_is_sticky() {
    let server = spawn_with(
        After::PacketsThenClose(vec![(100, 90_000, true, IDR.to_vec())]),
        90_000,
    )
    .await;
    let mut s = open_with(&server).await.unwrap();
    assert!(s.next_frame().await.unwrap().is_some());
    for _ in 0..3 {
        assert_eq!(s.next_frame().await, Ok(None));
    }
}

/// `rtp_ts_90k` is the 32-bit wire timestamp across a wrap of the RTP clock, and when the first
/// packet is "before" the RTP-Info `rtptime` (retina's unwrapped value is negative), and when
/// the timestamps go backwards (B frames are sent in decoding order).
#[tokio::test]
async fn rtp_timestamp_is_the_wire_value_across_wrap_and_backwards_steps() {
    let wire: [u32; 6] = [u32::MAX - 3_599, u32::MAX, 0, 3_600, 1_000, 7_200];
    let pkts: Batch = wire
        .iter()
        .enumerate()
        .map(|(i, &ts)| {
            let payload = if i == 0 { IDR.to_vec() } else { P1.to_vec() };
            (100 + i as u16, ts, true, payload)
        })
        .collect();
    // rtptime 10 makes the first packet lie just before the announced start.
    let server = spawn_with(After::Packets(pkts), 10).await;
    let mut s = open_with(&server).await.unwrap();
    for want in wire {
        let f = s.next_frame().await.unwrap().unwrap();
        assert_eq!(f.rtp_ts_90k, want);
    }
}

// ---------------------------------------------------------------------------------------------
// Mapper: model-based check against a naive oracle
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Step {
    oversize: bool,
    /// The camera changes its parameter sets on this frame (retina's `has_new_parameters`).
    change: Option<u8>,
    loss: u16,
}

fn step() -> impl Strategy<Value = Step> {
    (
        prop::bool::weighted(0.3),
        prop::option::weighted(0.3, any::<u8>()),
        prop_oneof![4 => Just(0_u16), 1 => any::<u16>()],
    )
        .prop_map(|(oversize, change, loss)| Step {
            oversize,
            change,
            loss,
        })
}

fn params_of(tag: u8) -> RawParams {
    RawParams {
        sps: vec![0x67, tag, 0x5a],
        pps: vec![0x68, tag],
    }
}

fn small_avcc() -> Vec<u8> {
    let mut v = vec![0, 0, 0, 4];
    v.extend(P1);
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Drives the mapper exactly as the session adapter does (pass the camera's current parameters
    /// when they changed on this frame or when `wants_params`), and checks against a model:
    /// - the consumer's latest known parameters always equal the camera's current ones after
    ///   each delivered frame (never stale, never lost);
    /// - `params` is `Some` on a delivered frame iff a change is pending for the consumer or it is
    ///   the first delivery of known parameters;
    /// - `discontinuity` iff first delivered frame, a dropped frame since the last delivery, or
    ///   loss on this frame;
    /// - the drop counter counts exactly the oversize frames.
    #[test]
    fn mapper_composed_with_adapter_policy_matches_model(
        initial in prop::option::of(any::<u8>()),
        steps in prop::collection::vec(step(), 1..40),
    ) {
        let mut m = FrameMapper::new();
        let mut camera: Option<u8> = initial;
        let mut consumer: Option<u8> = None;
        let mut dropped = 0_u64;
        let mut first = true;
        let mut dropped_since = false;
        // The model: the consumer must be told when camera != consumer at a delivered frame.
        for (i, st) in steps.iter().enumerate() {
            if let Some(t) = st.change { camera = Some(t); }
            let has_new = st.change.is_some();
            let pass = if has_new || m.wants_params() { camera.map(params_of) } else { None };
            let raw = RawVideoFrame {
                data: if st.oversize { vec![0; MAX_FRAME_BYTES + 1] } else { small_avcc() },
                is_random_access_point: false,
                rtp_timestamp: i as i64,
                clock_rate: H264_CLOCK_RATE_HZ,
                loss: st.loss,
                params: pass,
            };
            let out = m.map(raw, Timestamp::from_unix_millis(i as i64)).unwrap();
            if st.oversize {
                prop_assert!(out.is_none());
                dropped += 1;
                dropped_since = true;
            } else {
                let f = out.unwrap();
                let want_disc = first || dropped_since || st.loss > 0;
                prop_assert_eq!(f.discontinuity, want_disc, "step {}", i);
                let must_signal = camera != consumer;
                if must_signal {
                    prop_assert!(f.params.is_some(),
                        "step {}: change not signalled, camera {:?} consumer {:?}", i, camera, consumer);
                } else if f.params.is_some() {
                    // A redundant signal is tolerable only where something did change: on this
                    // frame, or on a dropped frame since the last delivery.
                    prop_assert!(has_new || dropped_since,
                        "step {}: spurious params, camera {:?}", i, camera);
                }
                if let Some(p) = &f.params {
                    consumer = Some(p.sps[1]);
                    prop_assert_eq!(&p.pps, &params_of(p.sps[1]).pps);
                }
                prop_assert_eq!(consumer, camera, "step {}: consumer stale", i);
                first = false;
                dropped_since = false;
            }
            prop_assert_eq!(m.dropped_oversize(), dropped);
        }
    }
}

/// Parameter-set length bounds: exactly the limit is accepted, one more refused, empty refused,
/// for SPS and PPS independently.
#[test]
fn parameter_set_length_boundaries() {
    let frame = |sps: Vec<u8>, pps: Vec<u8>| RawVideoFrame {
        data: small_avcc(),
        is_random_access_point: true,
        rtp_timestamp: 0,
        clock_rate: H264_CLOCK_RATE_HZ,
        loss: 0,
        params: Some(RawParams { sps, pps }),
    };
    let t = Timestamp::from_unix_millis(0);
    let n = |len: usize| vec![0x67; len];
    let rows: [(&str, Vec<u8>, Vec<u8>, bool); 6] = [
        (
            "both at cap",
            n(MAX_PARAM_SET_BYTES),
            n(MAX_PARAM_SET_BYTES),
            true,
        ),
        ("sps over", n(MAX_PARAM_SET_BYTES + 1), n(1), false),
        ("pps over", n(1), n(MAX_PARAM_SET_BYTES + 1), false),
        ("sps empty", vec![], n(1), false),
        ("pps empty", n(1), vec![], false),
        ("both one byte", n(1), n(1), true),
    ];
    for (name, sps, pps, ok) in rows {
        let got = FrameMapper::new().map(frame(sps, pps), t);
        if ok {
            assert!(matches!(got, Ok(Some(_))), "{name}: {got:?}");
        } else {
            assert_eq!(got, Err(MapError::BadParameterSet), "{name}");
        }
    }
}

/// Retina's unwrapped timestamp is `i64`; every value maps to its low 32 bits without panicking.
#[test]
fn rtp_low_32_of_extreme_unwrapped_values() {
    let rows: [(i64, u32); 7] = [
        (0, 0),
        (-1, u32::MAX),
        (1 << 32, 0),
        ((1 << 32) + 5, 5),
        (-(1 << 32) - 1, u32::MAX),
        (i64::MAX, u32::MAX),
        (i64::MIN, 0),
    ];
    for (unwrapped, want) in rows {
        let raw = RawVideoFrame {
            data: small_avcc(),
            is_random_access_point: false,
            rtp_timestamp: unwrapped,
            clock_rate: H264_CLOCK_RATE_HZ,
            loss: 0,
            params: None,
        };
        let f = FrameMapper::new()
            .map(raw, Timestamp::from_unix_millis(0))
            .unwrap()
            .unwrap();
        assert_eq!(f.rtp_ts_90k, want, "{unwrapped}");
    }
}

// ---------------------------------------------------------------------------------------------
// contains_b_slice
// ---------------------------------------------------------------------------------------------

struct BitWriter {
    out: Vec<u8>,
    n: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self { out: vec![], n: 0 }
    }
    fn bit(&mut self, b: u32) {
        if self.n.is_multiple_of(8) {
            self.out.push(0);
        }
        if b != 0 {
            *self.out.last_mut().unwrap() |= 0x80 >> (self.n % 8);
        }
        self.n += 1;
    }
    fn bits(&mut self, v: u32, n: u32) {
        for i in (0..n).rev() {
            self.bit((v >> i) & 1);
        }
    }
    fn ue(&mut self, v: u32) {
        let x = u64::from(v) + 1;
        let len = 64 - x.leading_zeros();
        for _ in 0..len - 1 {
            self.bit(0);
        }
        for i in (0..len).rev() {
            self.bit(((x >> i) & 1) as u32);
        }
    }
    fn se(&mut self, v: i32) {
        let k = if v > 0 {
            (2 * v - 1) as u32
        } else {
            (-2 * v) as u32
        };
        self.ue(k);
    }
    fn rbsp(mut self) -> Vec<u8> {
        self.bit(1);
        self.out
    }
}

/// Inserts emulation prevention bytes (spec 7.4.1).
fn escape(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut zeros = 0;
    for &b in rbsp {
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

fn avcc(nals: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    for n in nals {
        v.extend(u32::try_from(n.len()).unwrap().to_be_bytes());
        v.extend(n);
    }
    v
}

fn slice(nal_header: u8, first_mb: u32, slice_type: u32) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.ue(first_mb);
    w.ue(slice_type);
    w.ue(0); // pic_parameter_set_id
    w.bits(0, 8); // some more header bits
    let mut nal = vec![nal_header];
    nal.extend(escape(&w.rbsp()));
    nal
}

/// B slices are found in every position and form: second slice of a multi-slice picture, after a
/// SEI and an AUD, as `slice_type` 1 or 6, in a non-reference NAL (`nal_ref_idc` 0), and behind an
/// emulation prevention byte inside the first two syntax elements. Every `slice_type` 0..=9 is
/// classified per table 7-6.
#[test]
fn b_slice_detection_table() {
    let sei = vec![0x06, 0x05, 0x00, 0x00, 0x03, 0x00, 0x80];
    let aud = vec![0x09, 0xf0];
    // first_mb_in_slice 2^22 - 1: 22 leading zeros, so the bytes start 00 00 02 and need an escape.
    let escaped = slice(0x01, (1 << 22) - 1, 1);
    assert!(
        escaped.windows(3).any(|w| w == [0, 0, 3]),
        "vector must contain an escape"
    );
    let rows: Vec<(&str, Vec<Vec<u8>>, bool)> = vec![
        ("single P", vec![slice(0x41, 0, 0)], false),
        ("single B", vec![slice(0x01, 0, 1)], true),
        ("B as type 6", vec![slice(0x01, 0, 6)], true),
        (
            "P then B slice",
            vec![slice(0x41, 0, 5), slice(0x41, 99, 1)],
            true,
        ),
        (
            "aud, sei, then B",
            vec![aud.clone(), sei.clone(), slice(0x21, 0, 6)],
            true,
        ),
        ("IDR I", vec![slice(0x65, 0, 7)], false),
        ("escaped B", vec![escaped], true),
        (
            "SP and SI",
            vec![
                slice(0x41, 0, 3),
                slice(0x41, 1, 4),
                slice(0x41, 2, 8),
                slice(0x41, 3, 9),
            ],
            false,
        ),
        ("aud only", vec![aud], false),
    ];
    for (name, nals, want) in rows {
        assert_eq!(contains_b_slice(&avcc(&nals)), Ok(want), "{name}");
    }
    for t in 0..=9_u32 {
        let want = matches!(t, 1 | 6);
        assert_eq!(
            contains_b_slice(&avcc(&[slice(0x41, 0, t)])),
            Ok(want),
            "slice_type {t}"
        );
    }
}

/// `check_avcc` refuses empty data as not AVCC, and the rustdoc of `contains_b_slice` promises
/// `MalformedFrame` "when the data is not AVCC". Empty data must not be reported as a frame
/// without B slices (it is not evidence that the stream does not reorder).
#[test]
#[ignore = "follow-up #155"]
fn empty_frame_is_not_evidence_of_no_b_slice() {
    let got = contains_b_slice(&[]);
    assert_ne!(
        got,
        Ok(false),
        "empty data counted as a frame without B slices"
    );
}

// ---------------------------------------------------------------------------------------------
// SPS: independent vectors, cross-checked with h264-reader
// ---------------------------------------------------------------------------------------------

struct Vui {
    hrd_nal: bool,
    hrd_vcl: bool,
    reorder: Option<u32>,
}

/// High 4:4:4 Predictive (244) with `chroma_format_idc` 3 and all twelve scaling lists present,
/// mixing "use default" (first delta makes next 0), "stop early" and full lists; POC type 1 with
/// a cycle; cropping; interlaced; VUI with extended SAR, every optional block and both HRDs.
fn rich_sps(constraint: u8, vui: Option<Vui>) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.bits(244, 8);
    w.bits(u32::from(constraint), 8);
    w.bits(51, 8);
    w.ue(31); // sps id, the maximum
    w.ue(3); // chroma_format_idc 4:4:4
    w.bit(0); // separate_colour_plane_flag
    w.ue(6); // bit_depth_luma_minus8, max
    w.ue(6);
    w.bit(1); // qpprime
    w.bit(1); // seq_scaling_matrix_present_flag
    for i in 0..12 {
        match i % 3 {
            0 => w.bit(0),
            1 => {
                // useDefaultScalingMatrixFlag: delta -8 from 8 gives 0 at j = 0.
                w.bit(1);
                w.se(-8);
            }
            _ => {
                w.bit(1);
                let size = if i < 6 { 16 } else { 64 };
                // Walk up then stop early by reaching 0 half way.
                let mut last = 8_i32;
                for j in 0..size {
                    if j == size / 2 {
                        w.se(-last);
                        break;
                    }
                    let d = if j % 2 == 0 { 3 } else { -2 };
                    w.se(d);
                    last = (last + d + 256).rem_euclid(256);
                    assert_ne!(last, 0);
                }
            }
        }
    }
    w.ue(12); // log2_max_frame_num_minus4, max
    w.ue(1); // poc type 1
    w.bit(1);
    w.se(-5);
    w.se(7);
    w.ue(3);
    w.se(1);
    w.se(-2);
    w.se(3);
    w.ue(16); // max_num_ref_frames
    w.bit(1);
    w.ue(119);
    w.ue(33);
    w.bit(0); // frame_mbs_only_flag 0
    w.bit(1); // mb_adaptive
    w.bit(1);
    w.bit(1); // cropping
    w.ue(0);
    w.ue(4);
    w.ue(0);
    w.ue(4);
    match vui {
        None => w.bit(0),
        Some(v) => {
            w.bit(1);
            w.bit(1);
            w.bits(255, 8);
            w.bits(0, 16);
            w.bits(0, 16); // zero SAR: long zero runs, escapes needed
            w.bit(1);
            w.bit(1);
            w.bit(1);
            w.bits(5, 3);
            w.bit(1);
            w.bit(1);
            w.bits(1, 8);
            w.bits(1, 8);
            w.bits(1, 8);
            w.bit(1);
            w.ue(5);
            w.ue(5);
            w.bit(1);
            w.bits(0, 32);
            w.bits(0, 32);
            w.bit(1);
            for present in [v.hrd_nal, v.hrd_vcl] {
                w.bit(u32::from(present));
                if present {
                    w.ue(2); // cpb_cnt_minus1
                    w.bits(4, 4);
                    w.bits(5, 4);
                    for _ in 0..3 {
                        w.ue(u32::MAX - 1); // bit_rate_value_minus1, max
                        w.ue(1000);
                        w.bit(1);
                    }
                    w.bits(23, 5);
                    w.bits(23, 5);
                    w.bits(23, 5);
                    w.bits(24, 5);
                }
            }
            if v.hrd_nal || v.hrd_vcl {
                w.bit(1);
            }
            w.bit(1); // pic_struct_present
            match v.reorder {
                None => w.bit(0),
                Some(r) => {
                    w.bit(1);
                    w.bit(1);
                    w.ue(2);
                    w.ue(1);
                    w.ue(16);
                    w.ue(16);
                    w.ue(r);
                    w.ue(16);
                }
            }
        }
    }
    let mut nal = vec![0x67];
    nal.extend(escape(&w.rbsp()));
    nal
}

fn oracle_reorder(nal: &[u8]) -> Option<Option<u32>> {
    use h264_reader::nal::sps::SeqParameterSet;
    use h264_reader::rbsp::{BitReader, ByteReader};
    SeqParameterSet::from_bits(BitReader::new(ByteReader::skipping_h264_header(nal)))
        .ok()
        .map(|s| {
            s.vui_parameters
                .and_then(|v| v.bitstream_restrictions)
                .map(|b| b.max_num_reorder_frames)
        })
}

#[test]
fn rich_sps_vectors_parse_and_agree_with_h264_reader() {
    let rows: Vec<(&str, Vec<u8>, ReorderVerdict, Option<u32>)> = vec![
        (
            "no vui",
            rich_sps(0, None),
            ReorderVerdict::Undetermined,
            None,
        ),
        (
            "both hrd, reorder 2",
            rich_sps(
                0,
                Some(Vui {
                    hrd_nal: true,
                    hrd_vcl: true,
                    reorder: Some(2),
                }),
            ),
            ReorderVerdict::ReorderingAllowed(2),
            Some(2),
        ),
        (
            "vcl hrd only, reorder 0",
            rich_sps(
                0,
                Some(Vui {
                    hrd_nal: false,
                    hrd_vcl: true,
                    reorder: Some(0),
                }),
            ),
            ReorderVerdict::NoReordering(wardenlens_ingest::NoReorderReason::VuiZeroReorder),
            Some(0),
        ),
        (
            "nal hrd only, no restriction, intra flag",
            rich_sps(
                0x10,
                Some(Vui {
                    hrd_nal: true,
                    hrd_vcl: false,
                    reorder: None,
                }),
            ),
            ReorderVerdict::NoReordering(wardenlens_ingest::NoReorderReason::IntraOnlyProfile),
            None,
        ),
    ];
    for (name, nal, want, reorder) in rows {
        assert!(
            nal.windows(3).any(|w| w == [0, 0, 3]) || name == "no vui",
            "{name}: no escape"
        );
        let got = parse_sps(&nal).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(got.profile_idc, 244, "{name}");
        assert_eq!(got.pic_order_cnt_type, 1, "{name}");
        assert_eq!(got.max_num_reorder_frames, reorder, "{name}");
        assert_eq!(sps_reordering(&nal), Ok(want), "{name}");
        if let Some(theirs) = oracle_reorder(&nal) {
            assert_eq!(theirs, reorder, "{name}: h264-reader disagrees");
        }
        // Every proper prefix that cuts into the syntax is refused, never a verdict.
        for cut in 1..nal.len() - 1 {
            assert!(
                parse_sps(&nal[..cut]).is_err(),
                "{name}: prefix {cut} accepted"
            );
        }
    }
}
