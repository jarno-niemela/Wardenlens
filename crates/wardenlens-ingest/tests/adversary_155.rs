//! Adversarial tests for #155 (PR #221): Basic-auth refusal at every challenge site, and the
//! read-buffer bound. A scripted RTSP server on 127.0.0.1 only; ordering between client and
//! server goes through the request log and the frames the server sends, never a sleep.

#![expect(
    clippy::unwrap_used,
    clippy::as_conversions,
    clippy::decimal_bitwise_operands,
    clippy::cast_sign_loss,
    clippy::type_complexity,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "scripted test-server helpers; a panic fails the test"
)]

use std::num::NonZeroU16;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wardenlens_core::camera::{Credential, Host, RtspPath};
use wardenlens_core::catalogue::StreamRole;
use wardenlens_core::time::{Clock, Timestamp};
use wardenlens_ingest::{FrameStream, IngestError, OpenOptions, open_stream_with};

const USER: &str = "adv155-user";
const PASSWORD: &str = "adv155-pass";
const PATH: &str = "/adv155";
const SPS_B64: &str = "Z0LACtoQmQ==";
const PPS_B64: &str = "aM48gA==";
const IDR: [u8; 5] = [0x65, 0x88, 0x84, 0x00, 0x10];
const DIGEST: &str = "WWW-Authenticate: Digest realm=\"t\", nonce=\"abc123\"\r\n";
const BASIC: &str = "WWW-Authenticate: Basic realm=\"t\"\r\n";

struct StepClock(AtomicI64);

impl Clock for StepClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.fetch_add(10, Ordering::SeqCst))
    }
}

#[derive(Clone)]
struct Script {
    /// Challenge header(s) for an unauthenticated DESCRIBE; `None` answers 200 at once.
    describe: Option<&'static str>,
    /// Challenge header(s) for an unauthenticated SETUP; `None` answers 200.
    setup: Option<&'static str>,
    /// Challenge for every keepalive (any other method); `None` answers 200. After each
    /// keepalive response the server sends one IDR frame, so the client's `next_frame` returns
    /// once per keepalive.
    keepalive: Option<&'static str>,
    /// `Session: ...;timeout=` seconds; retina keeps alive every `timeout / 2`.
    timeout_s: u32,
    /// RTP packets (seq, ts, marker, payload) sent after the first frame that follows PLAY.
    flood: Option<fn() -> Vec<(u16, u32, bool, Vec<u8>)>>,
}

struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
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
        // Skip interleaved RTCP the client may send ($ ch len16 payload).
        if buf.is_empty() && byte[0] == b'$' {
            let mut hdr = [0_u8; 3];
            sock.read_exact(&mut hdr).await.ok()?;
            let len = usize::from(u16::from_be_bytes([hdr[1], hdr[2]]));
            let mut skip = vec![0_u8; len];
            sock.read_exact(&mut skip).await.ok()?;
            continue;
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

async fn respond(sock: &mut TcpStream, req: &str, status: &str, extra: &str, body: &str) {
    let cseq = header(req, "CSeq").unwrap_or("0");
    let msg = format!(
        "RTSP/1.0 {status}\r\nCSeq: {cseq}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(msg.as_bytes()).await;
}

async fn send_idr(sock: &mut TcpStream, channel: u8, n: u32) {
    let mut p = vec![0x80, 0x80 | 96];
    p.extend((100_u16.wrapping_add(n as u16)).to_be_bytes());
    p.extend((90_000 + n * 3000).to_be_bytes());
    p.extend(0x1234_5678_u32.to_be_bytes());
    p.extend(IDR);
    let mut out = vec![b'$', channel];
    out.extend(u16::try_from(p.len()).unwrap().to_be_bytes());
    out.extend(p);
    let _ = sock.write_all(&out).await;
}

async fn send_packets(sock: &mut TcpStream, channel: u8, pkts: &[(u16, u32, bool, Vec<u8>)]) {
    let mut out = Vec::new();
    for (seq, ts, m, payload) in pkts {
        let mut p = vec![0x80, if *m { 0x80 | 96 } else { 96 }];
        p.extend(seq.to_be_bytes());
        p.extend(ts.to_be_bytes());
        p.extend(0x1234_5678_u32.to_be_bytes());
        p.extend(payload);
        out.extend([b'$', channel]);
        out.extend(u16::try_from(p.len()).unwrap().to_be_bytes());
        out.extend(p);
        if out.len() > 1 << 20 {
            if sock.write_all(&out).await.is_err() {
                return;
            }
            out.clear();
        }
    }
    let _ = sock.write_all(&out).await;
}

async fn serve(mut sock: TcpStream, port: u16, script: Script, log: Arc<Mutex<Vec<String>>>) {
    let mut channel = 0_u8;
    let mut sent = 0_u32;
    while let Some(req) = read_request(&mut sock).await {
        log.lock().unwrap().push(req.clone());
        let method = req.split_whitespace().next().unwrap_or("").to_owned();
        let authed = header(&req, "Authorization").is_some();
        match method.as_str() {
            "DESCRIBE" => match script.describe {
                Some(c) if !authed => respond(&mut sock, &req, "401 Unauthorized", c, "").await,
                _ => {
                    let base = format!(
                        "Content-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1:{port}{PATH}/\r\n"
                    );
                    respond(&mut sock, &req, "200 OK", &base, &sdp()).await;
                }
            },
            "SETUP" => match script.setup {
                Some(c) if !authed => respond(&mut sock, &req, "401 Unauthorized", c, "").await,
                _ => {
                    let t = header(&req, "Transport").unwrap_or("");
                    if let Some(i) = t.split(';').find_map(|p| p.strip_prefix("interleaved=")) {
                        channel = i
                            .split('-')
                            .next()
                            .and_then(|c| c.parse().ok())
                            .unwrap_or(0);
                    }
                    let extra = format!(
                        "Transport: RTP/AVP/TCP;unicast;interleaved={channel}-{}\r\nSession: 4711;timeout={}\r\n",
                        channel + 1,
                        script.timeout_s
                    );
                    respond(&mut sock, &req, "200 OK", &extra, "").await;
                }
            },
            "PLAY" => {
                let extra = format!(
                    "Session: 4711\r\nRTP-Info: url=rtsp://127.0.0.1:{port}{PATH}/trackID=0;seq=100;rtptime=90000\r\n"
                );
                respond(&mut sock, &req, "200 OK", &extra, "").await;
                send_idr(&mut sock, channel, sent).await;
                sent += 1;
                if let Some(f) = script.flood {
                    send_packets(&mut sock, channel, &f()).await;
                }
            }
            "TEARDOWN" => respond(&mut sock, &req, "200 OK", "", "").await,
            _ => {
                match script.keepalive {
                    Some(c) => {
                        respond(&mut sock, &req, "401 Unauthorized", c, "").await;
                    }
                    None => respond(&mut sock, &req, "200 OK", "Session: 4711\r\n", "").await,
                }
                send_idr(&mut sock, channel, sent).await;
                sent += 1;
            }
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

async fn open(
    server: &Server,
    options: OpenOptions,
) -> Result<FrameStream<StepClock>, IngestError> {
    open_stream_with(
        &Host::new("127.0.0.1").unwrap(),
        NonZeroU16::new(server.port).unwrap(),
        &RtspPath::new(PATH).unwrap(),
        Some(&Credential::new(USER, SecretString::from(PASSWORD))),
        StreamRole::Main,
        StepClock(AtomicI64::new(1_700_000_000_000)),
        options,
    )
    .await
}

fn basic_auth_sent(server: &Server) -> Vec<String> {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter_map(|r| header(r, "Authorization"))
        .filter(|a| a.to_ascii_lowercase().starts_with("basic"))
        .map(str::to_owned)
        .collect()
}

fn keepalives(server: &Server) -> usize {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| {
            let m = r.split_whitespace().next().unwrap_or("");
            !matches!(m, "DESCRIBE" | "SETUP" | "PLAY" | "TEARDOWN")
        })
        .count()
}

/// DESCRIBE needs no authentication; SETUP then asks for Basic only. The second challenge site
/// of the first `send` loop must refuse too.
#[tokio::test]
async fn basic_challenge_on_setup_is_refused() {
    let server = spawn(Script {
        describe: None,
        setup: Some(BASIC),
        keepalive: None,
        timeout_s: 60,
        flood: None,
    })
    .await;
    let out = open(&server, OpenOptions::default()).await;
    assert_eq!(out.err(), Some(IngestError::BasicAuthRefused));
    assert_eq!(basic_auth_sent(&server), Vec::<String>::new());
}

/// Spellings and combinations of a challenge list; whatever http-auth picks, Basic is never
/// answered without the opt-in.
#[tokio::test]
async fn no_challenge_spelling_gets_basic_credentials_without_the_opt_in() {
    let rows: [&'static str; 9] = [
        "WWW-Authenticate: basic realm=\"t\"\r\n",
        "WWW-Authenticate: BASIC realm=\"t\"\r\n",
        "WWW-Authenticate: Bearer realm=\"x\", Basic realm=\"t\"\r\n",
        "WWW-Authenticate: Digest realm=\"t\", nonce=\"n\", algorithm=FOO-9, Basic realm=\"t\"\r\n",
        "WWW-Authenticate: Digest realm=\"t\"\r\nWWW-Authenticate: Basic realm=\"t\"\r\n",
        "WWW-Authenticate: Basic realm=\"t\"\r\nWWW-Authenticate: Digest realm=\"t\", nonce=\"n\"\r\n",
        "WWW-Authenticate: Basic realm=\"t\", Basic realm=\"u\"\r\n",
        "WWW-Authenticate: Basic\r\n",
        "WWW-Authenticate: Basic realm=\"t\", charset=\"UTF-8\"\r\n",
    ];
    for c in rows {
        let server = spawn(Script {
            describe: Some(c),
            setup: None,
            keepalive: None,
            timeout_s: 60,
            flood: None,
        })
        .await;
        let _ = open(&server, OpenOptions::default()).await;
        assert!(
            basic_auth_sent(&server).is_empty(),
            "{c:?}: {:?}",
            basic_auth_sent(&server)
        );
    }
}

/// Runs a session that authenticates with Digest at DESCRIBE, then answers every keepalive with
/// `keepalive` and one frame. Returns after `n` keepalives.
async fn run_keepalives(keepalive: &'static str, options: OpenOptions, n: usize) -> Server {
    let server = spawn(Script {
        describe: Some(DIGEST),
        setup: None,
        keepalive: Some(keepalive),
        timeout_s: 2,
        flood: None,
    })
    .await;
    let mut s = open(&server, options).await.unwrap();
    while keepalives(&server) < n {
        // One frame per keepalive response (plus the one after PLAY); retina's own keepalive
        // timer paces this, the test does not sleep.
        assert!(s.next_frame().await.unwrap().is_some());
    }
    drop(s);
    server
}

/// The mid-session keepalive re-challenge (the second adoption site): a camera that switches to
/// Basic after a Digest handshake must not get the password, on the retry or later keepalives.
#[tokio::test]
async fn keepalive_basic_rechallenge_after_digest_never_gets_the_password() {
    let server = run_keepalives(BASIC, OpenOptions::default(), 3).await;
    assert!(
        basic_auth_sent(&server).is_empty(),
        "{:?}",
        basic_auth_sent(&server)
    );
}

/// Control for the test above: with the opt-in the same camera does get Basic credentials on a
/// later keepalive, so the harness can see a downgrade when one happens.
#[tokio::test]
async fn keepalive_basic_rechallenge_with_the_opt_in_is_answered_with_basic() {
    let server = run_keepalives(BASIC, OpenOptions::default().allow_basic_auth(true), 3).await;
    assert_ne!(basic_auth_sent(&server), Vec::<String>::new());
}

/// 40 MiB of one access unit as separate single-NAL packets (no FU-A), all with one timestamp
/// and no marker: retina keeps adding NALs to the same access unit.
fn endless_single_nals() -> Vec<(u16, u32, bool, Vec<u8>)> {
    let mut nal = vec![0x41_u8];
    nal.extend(std::iter::repeat_n(0x5a_u8, 1399));
    (0..30_000_u32)
        .map(|i| (101_u16.wrapping_add(i as u16), 93_000, false, nal.clone()))
        .collect()
}

/// One FU-A NAL that never ends, in 1-byte fragments: the most packets (and the most RTP
/// overhead) per byte of access unit.
fn endless_tiny_fragments() -> Vec<(u16, u32, bool, Vec<u8>)> {
    (0..1_500_000_u32)
        .map(|i| {
            let fu_header = if i == 0 { 0x80 | 5 } else { 5 };
            (
                101_u16.wrapping_add(i as u16),
                93_000,
                false,
                vec![0x7c, fu_header, 0x5a],
            )
        })
        .collect()
}

/// A completed 12 MiB access unit: over the frame cap, under the buffer limit. Dropped and
/// counted, the session goes on.
fn oversize_then_frame() -> Vec<(u16, u32, bool, Vec<u8>)> {
    let body = 12 * 1024 * 1024 / 1400;
    let mut v: Vec<(u16, u32, bool, Vec<u8>)> = (0..body)
        .map(|i| {
            let mut fu_header = 5_u8;
            if i == 0 {
                fu_header |= 0x80;
            }
            if i == body - 1 {
                fu_header |= 0x40;
            }
            let mut p = vec![0x7c, fu_header];
            p.extend(std::iter::repeat_n(0x5a_u8, 1400));
            (101_u16.wrapping_add(i as u16), 93_000, i == body - 1, p)
        })
        .collect();
    v.push((
        101_u16.wrapping_add(body as u16),
        96_000,
        true,
        IDR.to_vec(),
    ));
    v
}

async fn flood_session(flood: fn() -> Vec<(u16, u32, bool, Vec<u8>)>) -> FrameStream<StepClock> {
    let server = spawn(Script {
        describe: Some(DIGEST),
        setup: None,
        keepalive: None,
        timeout_s: 60,
        flood: Some(flood),
    })
    .await;
    let mut s = open(&server, OpenOptions::default())
        .await
        .unwrap()
        .with_frame_timeout(std::time::Duration::from_secs(30));
    assert!(s.next_frame().await.unwrap().is_some());
    s
}

#[tokio::test]
async fn endless_access_unit_of_single_nals_fails_the_session() {
    let mut s = flood_session(endless_single_nals).await;
    assert_eq!(s.next_frame().await, Err(IngestError::StreamFailed));
}

#[tokio::test]
async fn endless_access_unit_of_one_byte_fragments_fails_the_session() {
    let mut s = flood_session(endless_tiny_fragments).await;
    assert_eq!(s.next_frame().await, Err(IngestError::StreamFailed));
}

#[tokio::test]
async fn oversize_access_unit_under_the_buffer_limit_is_dropped_not_fatal() {
    let mut s = flood_session(oversize_then_frame).await;
    let f = s.next_frame().await.unwrap().unwrap();
    assert!(f.discontinuity);
    assert_eq!(s.dropped_oversize(), 1);
}

/// One SPS NAL (header 0x67) for `profile`, with the High family chroma fields written when
/// `chroma` is set: 4:2:0, 8-bit, no scaling, POC type `poc` (0 or 2), 40x30 MBs, no VUI.
fn sps_nal(profile: u8, chroma: bool, poc: u32) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::new();
    let put = |bits: &mut Vec<bool>, v: u32, n: u32| {
        for i in (0..n).rev() {
            bits.push((v >> i) & 1 == 1);
        }
    };
    let ue = |bits: &mut Vec<bool>, v: u32| {
        let x = v + 1;
        let len = 32 - x.leading_zeros();
        put(bits, x, 2 * len - 1);
    };
    put(&mut bits, u32::from(profile), 8);
    put(&mut bits, 0, 8);
    put(&mut bits, 30, 8);
    ue(&mut bits, 0); // sps id
    if chroma {
        ue(&mut bits, 1); // chroma_format_idc 4:2:0
        ue(&mut bits, 0); // bit_depth_luma_minus8
        ue(&mut bits, 0); // bit_depth_chroma_minus8
        put(&mut bits, 0, 1); // qpprime
        put(&mut bits, 0, 1); // no scaling matrix
    }
    ue(&mut bits, 0); // log2_max_frame_num_minus4
    ue(&mut bits, poc);
    if poc == 0 {
        ue(&mut bits, 0);
    }
    ue(&mut bits, 1); // max_num_ref_frames
    put(&mut bits, 0, 1); // gaps
    ue(&mut bits, 39);
    ue(&mut bits, 29);
    put(&mut bits, 1, 1); // frame_mbs_only
    put(&mut bits, 1, 1); // direct_8x8
    put(&mut bits, 0, 1); // crop
    put(&mut bits, 0, 1); // vui
    bits.push(true); // rbsp stop bit
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }
    let mut out = vec![0x67];
    for c in bits.chunks(8) {
        out.push(c.iter().fold(0_u8, |a, &b| (a << 1) | u8::from(b)));
    }
    out
}

/// The ingest SPS parser reads profile 144 like the other High family profiles (#54/#100 class):
/// the same SPS body parses to the same POC type under 100 and 144.
#[test]
fn ingest_reads_profile_144_chroma_fields_like_high() {
    for poc in [0, 2] {
        let high = wardenlens_ingest::parse_sps(&sps_nal(100, true, poc)).unwrap();
        let p144 = wardenlens_ingest::parse_sps(&sps_nal(144, true, poc)).unwrap();
        assert_eq!(
            high.pic_order_cnt_type, p144.pic_order_cnt_type,
            "poc {poc}"
        );
        assert_eq!(u32::from(p144.pic_order_cnt_type), poc);
        let main = wardenlens_ingest::parse_sps(&sps_nal(77, false, poc)).unwrap();
        assert_eq!(u32::from(main.pic_order_cnt_type), poc);
    }
}
