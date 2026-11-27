//! Adversarial tests for #55 (PR #154): a scripted RTSP server on 127.0.0.1 only.
//!
//! The server is driven by a per-test `Script`: which challenge to send and which interleaved RTP
//! packets to emit after PLAY. Where a test needs ordering between client and server it uses a
//! channel, never a sleep.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::decimal_bitwise_operands,
    clippy::cast_possible_truncation,
    reason = "scripted test-server helpers; a panic fails the test"
)]

use std::num::NonZeroU16;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use wardenlens_core::camera::{Credential, Host, RtspPath};
use wardenlens_core::catalogue::StreamRole;
use wardenlens_core::time::{Clock, Timestamp};
use wardenlens_ingest::{
    IngestError, MAX_FRAME_BYTES, MapError, NoReorderReason, OpenOptions, ReorderVerdict,
    RetinaSource, SpsError, StreamSource, contains_b_slice, open_stream, open_stream_with,
    parse_sps, sps_reordering,
};

const USER: &str = "adv-user-q7";
const PASSWORD: &str = "adv-pass-q7";
const PATH: &str = "/adv-path-q7";

/// Baseline 64x64, POC type 2 (same as the PR's loopback test).
const SPS: [u8; 7] = [0x67, 0x42, 0xc0, 0x0a, 0xda, 0x10, 0x99];
const SPS_B64: &str = "Z0LACtoQmQ==";
/// The same SPS with `level_idc` 11 instead of 10: a parameter change.
const SPS2: [u8; 7] = [0x67, 0x42, 0xc0, 0x0b, 0xda, 0x10, 0x99];
const PPS: [u8; 4] = [0x68, 0xce, 0x3c, 0x80];
const PPS_B64: &str = "aM48gA==";

const IDR: [u8; 5] = [0x65, 0x88, 0x84, 0x00, 0x10];
const P1: [u8; 4] = [0x41, 0x9a, 0x00, 0x20];

#[derive(Clone)]
enum Challenge {
    Digest,
    Basic,
    /// Basic listed first, Digest second, in one header: the client must pick Digest.
    BasicThenDigest,
}

/// What the server sends after PLAY.
/// RTP packets as (seq, ts, marker, payload).
type Batch = Vec<(u16, u32, bool, Vec<u8>)>;

#[derive(Clone)]
enum After {
    /// These RTP payloads, as (seq, ts, marker, payload), then keep the socket open.
    Packets(Vec<(u16, u32, bool, Vec<u8>)>),
    /// Nothing until the test sends a batch over the channel; each batch is sent in order.
    OnSignal(Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Batch>>>),
}

#[derive(Clone)]
struct Script {
    challenge: Challenge,
    after: After,
}

struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

struct StepClock(AtomicI64);

impl Clock for StepClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.fetch_add(10, Ordering::SeqCst))
    }
}

#[derive(Clone)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(1_700_000_000_000)
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

async fn serve(mut sock: TcpStream, port: u16, script: Script, log: Arc<Mutex<Vec<String>>>) {
    let mut channel = 0_u8;
    while let Some(req) = read_request(&mut sock).await {
        log.lock().unwrap().push(req.clone());
        let method = req.split_whitespace().next().unwrap_or("").to_owned();
        match method.as_str() {
            "DESCRIBE" => {
                if header(&req, "Authorization").is_none() {
                    let challenge = match script.challenge {
                        Challenge::Digest => {
                            "WWW-Authenticate: Digest realm=\"t\", nonce=\"abc123\"\r\n"
                        }
                        Challenge::Basic => "WWW-Authenticate: Basic realm=\"t\"\r\n",
                        Challenge::BasicThenDigest => {
                            "WWW-Authenticate: Basic realm=\"t\", Digest realm=\"t\", nonce=\"abc123\"\r\n"
                        }
                    };
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
                    "Session: 4711\r\nRTP-Info: url=rtsp://127.0.0.1:{port}{PATH}/trackID=0;seq=100;rtptime=90000\r\n"
                );
                respond(&mut sock, &req, "200 OK", &extra, "").await;
                match &script.after {
                    After::Packets(p) => send_packets(&mut sock, channel, p).await,
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

async fn spawn(script: Script) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(serve(sock, port, script.clone(), Arc::clone(&log)));
        }
    });
    Server { port, requests }
}

async fn open_with(
    server: &Server,
    cred: &Credential,
) -> Result<wardenlens_ingest::FrameStream<StepClock>, IngestError> {
    open_stream(
        &Host::new("127.0.0.1").unwrap(),
        NonZeroU16::new(server.port).unwrap(),
        &RtspPath::new(PATH).unwrap(),
        Some(cred),
        StreamRole::Main,
        StepClock(AtomicI64::new(1_700_000_000_000)),
    )
    .await
}

fn cred() -> Credential {
    Credential::new(USER, SecretString::from(PASSWORD))
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn stap_a(nals: &[&[u8]]) -> Vec<u8> {
    let mut p = vec![0x78]; // NRI 3, type 24
    for n in nals {
        p.extend(u16::try_from(n.len()).unwrap().to_be_bytes());
        p.extend(*n);
    }
    p
}

/// FU-A packets for one NAL unit (`hdr` plus `body`), at most `chunk` body bytes per packet.
fn fu_a(seq0: u16, ts: u32, hdr: u8, body: &[u8], chunk: usize) -> Vec<(u16, u32, bool, Vec<u8>)> {
    let pieces: Vec<&[u8]> = body.chunks(chunk).collect();
    let last = pieces.len() - 1;
    pieces
        .iter()
        .enumerate()
        .map(|(i, piece)| {
            let mut fu_header = hdr & 0x1f;
            if i == 0 {
                fu_header |= 0x80;
            }
            if i == last {
                fu_header |= 0x40;
            }
            let mut p = vec![(hdr & 0xe0) | 28, fu_header];
            p.extend(*piece);
            (seq0.wrapping_add(i as u16), ts, i == last, p)
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

/// A camera (or anything answering on its address) that asks for Basic gets `user:password` in
/// base64, i.e. in the clear. The rustdoc of `open_stream` says Basic is used when asked; this
/// test documents that the password is then on the wire.
#[tokio::test]
async fn basic_challenge_never_receives_the_password_in_clear() {
    let server = spawn(Script {
        challenge: Challenge::Basic,
        after: After::Packets(vec![]),
    })
    .await;
    let out = open_with(&server, &cred()).await;
    assert_eq!(out.err(), Some(IngestError::BasicAuthRefused));
    let leaked = base64(format!("{USER}:{PASSWORD}").as_bytes());
    let reqs = server.requests.lock().unwrap();
    assert!(!reqs.is_empty());
    for r in reqs.iter() {
        assert!(
            !r.contains(&leaked) && header(r, "Authorization").is_none(),
            "credentials sent to a Basic-only camera: {}",
            r.lines()
                .find(|l| l.starts_with("Authorization"))
                .unwrap_or("")
        );
    }
}

/// The per-camera opt-in: with it, a Basic-only camera gets Basic credentials (and the stream
/// opens). Without it (the test above) nothing is sent.
#[tokio::test]
async fn basic_challenge_with_the_opt_in_is_answered_with_basic() {
    let server = spawn(Script {
        challenge: Challenge::Basic,
        after: After::Packets(vec![(100, 90_000, true, IDR.to_vec())]),
    })
    .await;
    let mut s = open_stream_with(
        &Host::new("127.0.0.1").unwrap(),
        NonZeroU16::new(server.port).unwrap(),
        &RtspPath::new(PATH).unwrap(),
        Some(&cred()),
        StreamRole::Main,
        StepClock(AtomicI64::new(1_700_000_000_000)),
        OpenOptions::default().allow_basic_auth(true),
    )
    .await
    .unwrap();
    assert!(s.next_frame().await.unwrap().is_some());
    let want = format!("Basic {}", base64(format!("{USER}:{PASSWORD}").as_bytes()));
    let reqs = server.requests.lock().unwrap();
    assert!(
        reqs.iter()
            .any(|r| header(r, "Authorization") == Some(want.as_str()))
    );
}

/// The supervisor's source carries the opt-in: refused by default, answered when set.
#[tokio::test]
async fn retina_source_honours_the_basic_opt_in() {
    for (allow, want_ok) in [(false, false), (true, true)] {
        let server = spawn(Script {
            challenge: Challenge::Basic,
            after: After::Packets(vec![(100, 90_000, true, IDR.to_vec())]),
        })
        .await;
        let mut source = RetinaSource::new(
            Host::new("127.0.0.1").unwrap(),
            NonZeroU16::new(server.port).unwrap(),
            RtspPath::new(PATH).unwrap(),
            Some(cred()),
            StreamRole::Main,
            FixedClock,
        );
        if allow {
            source = source.with_open_options(OpenOptions::default().allow_basic_auth(true));
        }
        let out = source.open(Duration::from_secs(5)).await;
        assert_eq!(out.is_ok(), want_ok, "allow={allow}");
        if !want_ok {
            assert_eq!(out.err(), Some(IngestError::BasicAuthRefused));
        }
    }
}

/// A challenge that offers Digest as well as Basic is answered with Digest, never refused and
/// never answered with Basic, whatever the order.
#[tokio::test]
async fn basic_and_digest_challenge_is_answered_with_digest() {
    let server = spawn(Script {
        challenge: Challenge::BasicThenDigest,
        after: After::Packets(vec![(100, 90_000, true, IDR.to_vec())]),
    })
    .await;
    let mut s = open_with(&server, &cred()).await.unwrap();
    assert!(s.next_frame().await.unwrap().is_some());
    let reqs = server.requests.lock().unwrap();
    let auth: Vec<&str> = reqs
        .iter()
        .filter_map(|r| header(r, "Authorization"))
        .collect();
    assert_ne!(auth.len(), 0);
    assert!(auth.iter().all(|a| a.starts_with("Digest ")), "{auth:?}");
}

/// The hostile camera of #155: one access unit that never ends. retina must stop buffering it,
/// so the session fails at once (`StreamFailed`) instead of reading until the frame timeout
/// (`FrameTimeout`) with everything it was sent still in memory.
#[tokio::test]
async fn endless_access_unit_fails_the_session_instead_of_growing() {
    // 40 MiB of FU-A fragments of one NAL with no end bit and no marker, then silence.
    let body = vec![0x5a_u8; 40 * 1024 * 1024];
    let mut pkts = vec![(100, 90_000, true, IDR.to_vec())];
    let mut frag = fu_a(101, 93_600, 0x65, &body, 60_000);
    // Take the end bit and the marker off the last fragment: the access unit never completes.
    if let Some(last) = frag.last_mut() {
        last.2 = false;
        last.3[1] &= !0x40;
    }
    pkts.extend(frag);
    let server = spawn(Script {
        challenge: Challenge::Digest,
        after: After::Packets(pkts),
    })
    .await;
    let mut s = open_with(&server, &cred())
        .await
        .unwrap()
        .with_frame_timeout(Duration::from_secs(20));
    assert!(s.next_frame().await.unwrap().is_some());
    assert_eq!(s.next_frame().await, Err(IngestError::StreamFailed));
}

/// A user name with CR LF (allowed by `Credential::new` and `Credential::check`) must not split
/// the request into injected headers, and must not panic inside retina's `HeaderValue` unwrap.
#[tokio::test]
async fn crlf_in_user_name_cannot_inject_rtsp_headers() {
    for challenge in [Challenge::Digest, Challenge::Basic] {
        let server = spawn(Script {
            challenge,
            after: After::Packets(vec![]),
        })
        .await;
        let c = Credential::new(
            "u\r\nX-Injected: yes\r\nx",
            SecretString::from("p\r\nX-Injected2: yes"),
        );
        let handle = tokio::spawn(async move {
            let s = open_with(&server, &c).await.map(|_| ());
            (s, server.requests.lock().unwrap().clone())
        });
        let (_, reqs) = handle.await.expect("open_stream must not panic");
        for r in &reqs {
            assert!(header(r, "X-Injected").is_none(), "injected header in {r}");
            assert!(header(r, "X-Injected2").is_none(), "injected header in {r}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------------------------

/// `with_frame_timeout(Duration::MAX)` is the natural way to say "no idle limit". It must deliver
/// the frame that is waiting, not fail at once because the deadline overflowed.
#[tokio::test]
async fn huge_frame_timeout_still_delivers_frames() {
    let server = spawn(Script {
        challenge: Challenge::Digest,
        after: After::Packets(vec![(100, 90_000, true, IDR.to_vec())]),
    })
    .await;
    let mut s = open_with(&server, &cred())
        .await
        .unwrap()
        .with_frame_timeout(Duration::MAX);
    let got = s.next_frame().await;
    assert!(matches!(got, Ok(Some(_))), "expected a frame, got {got:?}");
}

/// A parameter change carried inline (STAP-A with a new SPS) is signalled on that frame, the new
/// SPS is the one delivered, and the parameter sets are not inline in `data`.
#[tokio::test]
async fn inline_parameter_change_is_signalled_on_its_frame() {
    let server = spawn(Script {
        challenge: Challenge::Digest,
        after: After::Packets(vec![
            (100, 90_000, true, IDR.to_vec()),
            (101, 93_600, true, P1.to_vec()),
            (102, 97_200, true, stap_a(&[&SPS2, &PPS, &IDR])),
            (103, 100_800, true, P1.to_vec()),
        ]),
    })
    .await;
    let mut s = open_with(&server, &cred()).await.unwrap();
    let f1 = s.next_frame().await.unwrap().unwrap();
    assert_eq!(f1.params.as_ref().unwrap().sps, SPS);
    let f2 = s.next_frame().await.unwrap().unwrap();
    assert!(f2.params.is_none());
    let f3 = s.next_frame().await.unwrap().unwrap();
    assert!(f3.is_keyframe);
    assert_eq!(f3.params.as_ref().expect("change signalled").sps, SPS2);
    assert_eq!(
        f3.data,
        [&[0, 0, 0, 5][..], &IDR].concat(),
        "no inline SPS/PPS"
    );
    assert!(!f3.discontinuity, "a parameter change is not a loss");
    let f4 = s.next_frame().await.unwrap().unwrap();
    assert!(f4.params.is_none());
}

/// An oversize frame over the wire (FU-A) that also changes the SPS is dropped and counted; the
/// next frame is a discontinuity and carries the new parameters.
#[tokio::test]
async fn oversize_frame_with_parameter_change_over_the_wire() {
    // AVCC size = 4 + 1 + body; one byte over the cap.
    let body = vec![0x5a_u8; MAX_FRAME_BYTES - 4];
    let mut pkts = vec![(100, 90_000, true, IDR.to_vec())];
    // SPS2 + PPS in their own STAP-A at the start of the big access unit, then the slice.
    pkts.push((101, 93_600, false, stap_a(&[&SPS2, &PPS])));
    pkts.extend(fu_a(102, 93_600, 0x65, &body, 60_000));
    let next_seq = 102 + u16::try_from(body.len().div_ceil(60_000)).unwrap();
    pkts.push((next_seq, 97_200, true, P1.to_vec()));
    let server = spawn(Script {
        challenge: Challenge::Digest,
        after: After::Packets(pkts),
    })
    .await;
    let mut s = open_with(&server, &cred()).await.unwrap();
    let f1 = s.next_frame().await.unwrap().unwrap();
    assert_eq!(f1.params.as_ref().unwrap().sps, SPS);
    let f2 = s.next_frame().await.unwrap().unwrap();
    assert_eq!(s.dropped_oversize(), 1);
    assert_eq!(f2.rtp_ts_90k, 97_200);
    assert!(f2.discontinuity);
    assert_eq!(
        f2.params.as_ref().expect("held-back change").sps,
        SPS2,
        "the dropped frame's parameter change must reach the next frame"
    );
}

/// The largest frame that fits (exactly `MAX_FRAME_BYTES` of AVCC) is delivered over the wire.
#[tokio::test]
async fn frame_at_exactly_the_cap_is_delivered_over_the_wire() {
    let body = vec![0x5a_u8; MAX_FRAME_BYTES - 5];
    let mut pkts = vec![(100, 90_000, true, IDR.to_vec())];
    pkts.extend(fu_a(101, 93_600, 0x65, &body, 60_000));
    let server = spawn(Script {
        challenge: Challenge::Digest,
        after: After::Packets(pkts),
    })
    .await;
    let mut s = open_with(&server, &cred()).await.unwrap();
    s.next_frame().await.unwrap().unwrap();
    let f2 = s.next_frame().await.unwrap().unwrap();
    assert_eq!(f2.data.len(), MAX_FRAME_BYTES);
    assert_eq!(s.dropped_oversize(), 0);
    assert!(!f2.discontinuity);
}

/// Corrupt media after PLAY (a NAL header with the forbidden bit) ends the stream with a typed
/// error that carries no camera data; `StreamFailed` is reachable.
#[tokio::test]
async fn corrupt_media_after_play_is_stream_failed() {
    let server = spawn(Script {
        challenge: Challenge::Digest,
        after: After::Packets(vec![
            (100, 90_000, true, IDR.to_vec()),
            (101, 93_600, true, vec![0xe5, 0x00]),
            (102, 97_200, true, P1.to_vec()),
        ]),
    })
    .await;
    let mut s = open_with(&server, &cred()).await.unwrap();
    s.next_frame().await.unwrap().unwrap();
    let mut outcome = None;
    for _ in 0..3 {
        match s.next_frame().await {
            Ok(Some(_)) => {}
            other => {
                outcome = Some(other);
                break;
            }
        }
    }
    let e = outcome.expect("corrupt media must not be delivered silently");
    assert_eq!(e.as_ref().err(), Some(&IngestError::StreamFailed), "{e:?}");
    let text = format!("{e:?}");
    for needle in [USER, PASSWORD, PATH, "127.0.0.1", "rtsp://"] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }
}

/// The rustdoc of `next_frame` says "After an error the stream is finished". After a
/// `FrameTimeout`, the stream must not hand out further frames as if nothing happened.
#[tokio::test]
async fn after_an_error_the_stream_is_finished() {
    let (tx, rx) = mpsc::unbounded_channel();
    let server = spawn(Script {
        challenge: Challenge::Digest,
        after: After::OnSignal(Arc::new(tokio::sync::Mutex::new(rx))),
    })
    .await;
    // The server sends nothing until signalled, so the short limit is the only thing that can end
    // the first call (the code's own bounded timeout; no race).
    let mut s = open_with(&server, &cred())
        .await
        .unwrap()
        .with_frame_timeout(Duration::from_millis(50));
    assert_eq!(s.next_frame().await.unwrap_err(), IngestError::FrameTimeout);
    tx.send(vec![(100, 90_000, true, IDR.to_vec())]).unwrap();
    let mut s = s.with_frame_timeout(Duration::from_secs(60));
    let after = s.next_frame().await;
    assert!(
        !matches!(after, Ok(Some(_))),
        "a frame was delivered after the stream reported an error: {after:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// SPS
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
    fn finish(mut self) -> Vec<u8> {
        self.bit(1);
        self.out
    }
}

/// A minimal SPS: given profile and constraint byte, POC type 0, no VUI.
fn sps_poc0(profile: u8, constraint: u8) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.bits(u32::from(profile), 8);
    w.bits(u32::from(constraint), 8);
    w.bits(40, 8);
    w.ue(0); // sps id
    if matches!(
        profile,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        w.ue(1); // chroma_format_idc
        w.ue(0);
        w.ue(0);
        w.bit(0);
        w.bit(0);
    }
    w.ue(0); // log2_max_frame_num_minus4
    w.ue(0); // poc type 0
    w.ue(0); // log2_max_poc_lsb_minus4
    w.ue(1); // max_num_ref_frames
    w.bit(0);
    w.ue(0);
    w.ue(0);
    w.bit(1); // frame_mbs_only
    w.bit(1); // direct_8x8
    w.bit(0); // cropping
    w.bit(0); // vui
    let mut nal = vec![0x67];
    nal.extend(w.finish());
    nal
}

/// Spec 7.4.2.1.1 / annex A: `constraint_set3_flag` marks an intra profile only for `profile_idc`
/// 110, 122 and 244 (and 44 is intra by itself; 86 for Scalable High Intra). There is no "High
/// Intra" profile: for `profile_idc` 100 the flag is reserved, decoders ignore it. A High SPS with
/// POC type 0 and no VUI must stay `Undetermined`, not be cleared as intra-only.
#[test]
fn high_profile_with_constraint_set3_is_not_intra_only() {
    let sps = sps_poc0(100, 0x10);
    assert_eq!(parse_sps(&sps).unwrap().profile_idc, 100);
    assert_eq!(sps_reordering(&sps), Ok(ReorderVerdict::Undetermined));
}

/// The genuine intra profiles are still recognised (control rows for the test above).
#[test]
fn genuine_intra_profiles_are_recognised() {
    for profile in [110_u8, 122, 244] {
        assert_eq!(
            sps_reordering(&sps_poc0(profile, 0x10)),
            Ok(ReorderVerdict::NoReordering(
                NoReorderReason::IntraOnlyProfile
            )),
            "{profile}"
        );
        assert_eq!(
            sps_reordering(&sps_poc0(profile, 0)),
            Ok(ReorderVerdict::Undetermined),
            "{profile} without set3"
        );
    }
    assert_eq!(
        sps_reordering(&sps_poc0(44, 0)),
        Ok(ReorderVerdict::NoReordering(
            NoReorderReason::IntraOnlyProfile
        ))
    );
    // Main with set3 (level 1b marker for 66/77/88) is not intra either.
    assert_eq!(
        sps_reordering(&sps_poc0(77, 0x10)),
        Ok(ReorderVerdict::Undetermined)
    );
}

/// Exp-Golomb with 32 leading zeros overflows `u32`; it must be a typed error, not a panic or a
/// silent wrap. Also a NAL header with `nal_ref_idc` 1 is still an SPS.
#[test]
fn sps_exp_golomb_and_header_bounds() {
    // profile 66, constraint 0, level 10, then 32 zero bits and a one: seq_parameter_set_id.
    let mut nal = vec![0x67, 66, 0, 10, 0, 0, 0, 0, 0x80];
    assert_eq!(parse_sps(&nal), Err(SpsError::OutOfRange));
    nal[0] = 0x27;
    assert_eq!(parse_sps(&nal), Err(SpsError::OutOfRange));
    assert_eq!(parse_sps(&[0x67]), Err(SpsError::Truncated));
    assert_eq!(parse_sps(&[0xe7, 66]), Err(SpsError::NotSps));
    assert_eq!(parse_sps(&[0x68, 66]), Err(SpsError::NotSps));
    assert_eq!(parse_sps(&[]), Err(SpsError::Truncated));
    let mut long = sps_poc0(66, 0);
    long.resize(4097, 0);
    assert_eq!(parse_sps(&long), Err(SpsError::TooLong));
    let mut at_cap = sps_poc0(66, 0);
    at_cap.resize(4096, 0);
    assert!(parse_sps(&at_cap).is_ok());
}

/// Every prefix of a valid SPS that cuts into the read syntax is `Truncated`, never a verdict.
#[test]
fn sps_truncation_sweep_never_guesses() {
    let full = sps_poc0(100, 0);
    assert!(parse_sps(&full).is_ok());
    // The last byte holds the vui flag and stop bit, so every shorter prefix must fail.
    for cut in 0..full.len() - 1 {
        assert_eq!(
            parse_sps(&full[..cut]),
            Err(SpsError::Truncated),
            "cut {cut}"
        );
    }
}

/// `slice_type` is 0..=9 (spec 7.4.3). A larger value is not "evidence of no B slice": the scan
/// must refuse it as malformed instead of reporting `false`.
#[test]
fn b_slice_scan_refuses_out_of_range_slice_type() {
    let mut w = BitWriter::new();
    w.ue(0); // first_mb_in_slice
    w.ue(10); // slice_type out of range
    let mut nal = vec![0x41];
    nal.extend(w.finish());
    let avcc = [&u32::try_from(nal.len()).unwrap().to_be_bytes()[..], &nal].concat();
    assert_eq!(contains_b_slice(&avcc), Err(MapError::MalformedFrame));
}
