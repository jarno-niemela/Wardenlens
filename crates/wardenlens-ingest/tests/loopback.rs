//! End-to-end tests of `open_stream` against a scripted RTSP server on 127.0.0.1.
//!
//! The server is a few dozen lines of test code, not a camera: it answers DESCRIBE, SETUP and
//! PLAY with canned messages and sends interleaved RTP. Nothing here leaves the machine.
//!
//! The Digest "check" only compares the user name: it exists to see what the client puts on the
//! wire (no credentials in the URL, no password in the clear), not to test retina's hashing.

#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::decimal_bitwise_operands,
    reason = "scripted test-server helpers outside #[test] fns; a panic fails the test"
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
use wardenlens_ingest::{
    FRAME_TIMEOUT, H264ParamsExt, IngestError, NoReorderReason, OPEN_TIMEOUT, ReorderVerdict,
    contains_b_slice, open_stream,
};

const USER: &str = "alice-xyz";
const PASSWORD: &str = "hunter2-xyz";
const PATH: &str = "/s3cr3t-path-zzz";

/// Baseline 64x64, `pic_order_cnt_type` 2, hand assembled from the syntax table.
const SPS: [u8; 7] = [0x67, 0x42, 0xc0, 0x0a, 0xda, 0x10, 0x99];
const SPS_B64: &str = "Z0LACtoQmQ==";
const PPS: [u8; 4] = [0x68, 0xce, 0x3c, 0x80];
const PPS_B64: &str = "aM48gA==";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Digest challenge, then accept any request that names the user; send frames and stay open.
    Frames,
    /// As `Frames`, then close the connection.
    FramesThenClose,
    /// As `Frames` but never send a frame.
    NoFrames,
    /// As `Frames` but send only RTCP sender reports, one every 50 ms, and never a frame.
    RtcpOnly,
    /// Answer 401 to every DESCRIBE, whatever it carries.
    Reject401,
    /// As `Frames`, but the second frame is a NAL unit with the forbidden bit set.
    CorruptMedia,
    /// Answer 403 to DESCRIBE.
    Forbidden,
    /// Answer 404 to DESCRIBE.
    NotFound,
    /// Accept the connection and never answer.
    Silent,
}

#[derive(Clone, Copy)]
enum Sdp {
    H264,
    H264WithAudioFirst,
    H265,
    AudioOnly,
}

struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

struct StepClock(AtomicI64);

impl Clock for StepClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.fetch_add(10, Ordering::SeqCst))
    }
}

fn clock() -> StepClock {
    StepClock(AtomicI64::new(1_700_000_000_000))
}

fn sdp(kind: Sdp) -> String {
    let audio = "m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=control:trackID=1\r\n";
    let h264 = format!(
        "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 packetization-mode=1;profile-level-id=42C00A;sprop-parameter-sets={SPS_B64},{PPS_B64}\r\n\
         a=control:trackID=0\r\n"
    );
    let h265 = "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\na=control:trackID=0\r\n";
    let head = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=test\r\nt=0 0\r\n";
    match kind {
        Sdp::H264 => format!("{head}{h264}"),
        Sdp::H264WithAudioFirst => format!("{head}{audio}{h264}"),
        Sdp::H265 => format!("{head}{h265}"),
        Sdp::AudioOnly => format!("{head}{audio}"),
    }
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
    String::from_utf8(buf).ok()
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

async fn send_interleaved(sock: &mut TcpStream, channel: u8, packet: &[u8]) {
    let mut out = vec![b'$', channel];
    out.extend(u16::try_from(packet.len()).unwrap().to_be_bytes());
    out.extend(packet);
    sock.write_all(&out).await.unwrap();
}

async fn respond(sock: &mut TcpStream, req: &str, status: &str, extra: &str, body: &str) {
    let cseq = header(req, "CSeq").unwrap_or("0");
    let msg = format!(
        "RTSP/1.0 {status}\r\nCSeq: {cseq}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(msg.as_bytes()).await.unwrap();
}

/// One unfinished frame (no marker bit) teaches the client the SSRC; without it retina drops RTCP
/// of an unknown source. Then a sender report every 50 ms until the client goes away.
async fn rtcp_forever(sock: &mut TcpStream, channel: u8) {
    let start = rtp(100, 90_000, false, &[0x65, 0x88, 0x84, 0x00, 0x10]);
    send_interleaved(sock, channel, &start).await;
    // Sender report: version 2, no reports, 6 words after the header word.
    let mut sr = vec![0x80, 200, 0, 6];
    sr.extend([0x12, 0x34, 0x56, 0x78]);
    sr.extend([0_u8; 20]);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut out = vec![b'$', channel + 1];
        out.extend(u16::try_from(sr.len()).unwrap().to_be_bytes());
        out.extend(&sr);
        if sock.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// An IDR, a P, then a P after a lost packet (seq 102 is never sent).
async fn send_frames(sock: &mut TcpStream, channel: u8) {
    let frames: [(u16, u32, &[u8]); 3] = [
        (100, 90_000, &[0x65, 0x88, 0x84, 0x00, 0x10]),
        (101, 93_600, &[0x41, 0x9a, 0x00, 0x20]),
        (103, 97_200, &[0x41, 0x9a, 0x00, 0x21]),
    ];
    for (seq, ts, payload) in frames {
        send_interleaved(sock, channel, &rtp(seq, ts, true, payload)).await;
    }
}

async fn serve(
    mut sock: TcpStream,
    port: u16,
    kind: Sdp,
    mode: Mode,
    log: Arc<Mutex<Vec<String>>>,
) {
    let mut channel = 0_u8;
    while let Some(req) = read_request(&mut sock).await {
        log.lock().unwrap().push(req.clone());
        let method = req.split_whitespace().next().unwrap_or("").to_owned();
        match method.as_str() {
            "DESCRIBE" if mode == Mode::Forbidden => {
                respond(&mut sock, &req, "403 Forbidden", "", "").await;
            }
            "DESCRIBE" if mode == Mode::NotFound => {
                respond(&mut sock, &req, "404 Not Found", "", "").await;
            }
            "DESCRIBE" => {
                let authed = header(&req, "Authorization").is_some_and(|a| {
                    a.starts_with("Digest") && a.contains(&format!("username=\"{USER}\""))
                });
                if mode == Mode::Reject401 || !authed {
                    let challenge = "WWW-Authenticate: Digest realm=\"test\", \
                        nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n";
                    respond(&mut sock, &req, "401 Unauthorized", challenge, "").await;
                } else {
                    let base = format!(
                        "Content-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1:{port}{PATH}/\r\n"
                    );
                    respond(&mut sock, &req, "200 OK", &base, &sdp(kind)).await;
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
                if mode == Mode::NoFrames {
                    continue;
                }
                if mode == Mode::RtcpOnly {
                    rtcp_forever(&mut sock, channel).await;
                    return;
                }
                if mode == Mode::CorruptMedia {
                    send_interleaved(
                        &mut sock,
                        channel,
                        &rtp(100, 90_000, true, &[0x65, 0x88, 0x84, 0x00, 0x10]),
                    )
                    .await;
                    send_interleaved(&mut sock, channel, &rtp(101, 93_600, true, &[0xe5, 0x00]))
                        .await;
                    continue;
                }
                send_frames(&mut sock, channel).await;
                if mode == Mode::FramesThenClose {
                    return;
                }
            }
            _ => respond(&mut sock, &req, "200 OK", "", "").await,
        }
    }
}

async fn spawn(kind: Sdp, mode: Mode) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let log = Arc::clone(&log);
            if mode == Mode::Silent {
                // Hold the socket open without ever answering.
                tokio::spawn(async move {
                    let _sock = sock;
                    std::future::pending::<()>().await;
                });
            } else {
                tokio::spawn(serve(sock, port, kind, mode, log));
            }
        }
    });
    Server { port, requests }
}

fn credential() -> Credential {
    Credential::new(USER, SecretString::from(PASSWORD))
}

async fn open(
    server: &Server,
    cred: Option<&Credential>,
) -> Result<wardenlens_ingest::FrameStream<StepClock>, IngestError> {
    open_stream(
        &Host::new("127.0.0.1").unwrap(),
        NonZeroU16::new(server.port).unwrap(),
        &RtspPath::new(PATH).unwrap(),
        cred,
        StreamRole::Main,
        clock(),
    )
    .await
}

fn assert_no_camera_data(text: &str, server: &Server) {
    for needle in [
        USER,
        PASSWORD,
        PATH,
        "127.0.0.1",
        &server.port.to_string(),
        "rtsp://",
    ] {
        assert!(!text.contains(needle), "{needle} leaked in {text}");
    }
}

#[tokio::test]
async fn plays_h264_with_digest_credentials_off_the_url() {
    for sdp_kind in [Sdp::H264, Sdp::H264WithAudioFirst] {
        let server = spawn(sdp_kind, Mode::Frames).await;
        let cred = credential();
        let mut stream = open(&server, Some(&cred)).await.unwrap();
        assert_eq!(stream.role(), StreamRole::Main);

        let f1 = stream.next_frame().await.unwrap().unwrap();
        assert!(f1.is_keyframe);
        assert_eq!(f1.rtp_ts_90k, 90_000);
        assert!(f1.discontinuity, "first frame of a session");
        let p = f1.params.as_ref().expect("parameters on the first frame");
        assert_eq!(
            (p.sps.as_slice(), p.pps.as_slice()),
            (SPS.as_slice(), PPS.as_slice())
        );
        assert_eq!(
            p.reordering(),
            Ok(ReorderVerdict::NoReordering(NoReorderReason::PocType2))
        );
        // AVCC: one 4 byte length, then the IDR NAL unit.
        assert_eq!(f1.data, [0, 0, 0, 5, 0x65, 0x88, 0x84, 0x00, 0x10]);
        assert_eq!(contains_b_slice(&f1.data), Ok(false));

        let f2 = stream.next_frame().await.unwrap().unwrap();
        assert!(!f2.is_keyframe);
        assert_eq!(f2.rtp_ts_90k, 93_600);
        assert!(f2.params.is_none());
        assert!(!f2.discontinuity);

        let f3 = stream.next_frame().await.unwrap().unwrap();
        assert_eq!(f3.rtp_ts_90k, 97_200);
        assert!(f3.discontinuity, "a lost RTP packet before this frame");

        // Arrival comes from the injected clock, once per delivered frame, in order.
        let base = 1_700_000_000_000;
        let arrivals = [f1.arrival, f2.arrival, f3.arrival].map(Timestamp::as_unix_millis);
        assert_eq!(arrivals, [base, base + 10, base + 20]);
        assert_eq!(stream.dropped_oversize(), 0);

        // What went over the wire.
        let reqs = server.requests();
        let first = reqs.first().unwrap();
        assert!(first.starts_with("DESCRIBE "));
        assert!(
            header(first, "Authorization").is_none(),
            "no credentials before a challenge"
        );
        for r in &reqs {
            let line = r.lines().next().unwrap();
            assert!(!line.contains('@'), "user info in {line}");
            assert!(!r.contains(PASSWORD), "password in the clear");
        }
        assert!(
            reqs.iter()
                .any(|r| header(r, "Authorization").is_some_and(|a| a.contains(USER))),
            "credentials answer the challenge through the Authorization header"
        );
        let setup = reqs.iter().find(|r| r.starts_with("SETUP ")).unwrap();
        let transport = header(setup, "Transport").unwrap();
        assert!(transport.starts_with("RTP/AVP/TCP;"), "{transport}");
        assert!(transport.contains("interleaved="), "{transport}");
        assert!(!transport.contains("client_port"), "{transport}");
        assert_eq!(
            reqs.iter().filter(|r| r.starts_with("SETUP ")).count(),
            1,
            "one stream set up"
        );
    }
}

#[tokio::test]
async fn wrong_credentials_are_auth_rejected_without_leaking() {
    let server = spawn(Sdp::H264, Mode::Reject401).await;
    let cred = credential();
    let Err(e) = open(&server, Some(&cred)).await else {
        panic!("must not open");
    };
    assert_eq!(e, IngestError::AuthRejected);
    assert_no_camera_data(&format!("{e} {e:?}"), &server);
}

#[tokio::test]
async fn forbidden_is_auth_rejected_too() {
    let server = spawn(Sdp::H264, Mode::Forbidden).await;
    let cred = credential();
    let Err(e) = open(&server, Some(&cred)).await else {
        panic!("must not open");
    };
    assert_eq!(e, IngestError::AuthRejected);
}

#[tokio::test]
async fn missing_credentials_are_reported_as_rejected() {
    let server = spawn(Sdp::H264, Mode::Frames).await;
    let Err(e) = open(&server, None).await else {
        panic!("must not open");
    };
    assert_eq!(e, IngestError::AuthRejected);
}

#[tokio::test]
async fn wrong_path_is_rejected_with_its_status() {
    let server = spawn(Sdp::H264, Mode::NotFound).await;
    let Err(e) = open(&server, None).await else {
        panic!("must not open");
    };
    assert_eq!(e, IngestError::Rejected(404));
    assert_no_camera_data(&format!("{e} {e:?}"), &server);
}

#[tokio::test]
async fn h265_is_an_unsupported_codec() {
    let server = spawn(Sdp::H265, Mode::Frames).await;
    let cred = credential();
    let Err(e) = open(&server, Some(&cred)).await else {
        panic!("must not open");
    };
    assert_eq!(e, IngestError::UnsupportedCodec);
    // Refused before SETUP: no media flows for a codec we cannot use.
    assert!(!server.requests().iter().any(|r| r.starts_with("SETUP ")));
}

#[tokio::test]
async fn audio_only_has_no_video_stream() {
    let server = spawn(Sdp::AudioOnly, Mode::Frames).await;
    let cred = credential();
    let Err(e) = open(&server, Some(&cred)).await else {
        panic!("must not open");
    };
    assert_eq!(e, IngestError::NoVideoStream);
}

#[tokio::test]
async fn refused_connection_is_open_failed_without_leaking() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let server = Server {
        port,
        requests: Arc::default(),
    };
    let cred = credential();
    let Err(e) = open(&server, Some(&cred)).await else {
        panic!("must not open");
    };
    assert_eq!(e, IngestError::OpenFailed);
    assert_no_camera_data(&format!("{e} {e:?}"), &server);
}

#[tokio::test(start_paused = true)]
async fn a_silent_camera_times_out_on_open() {
    let server = spawn(Sdp::H264, Mode::Silent).await;
    let cred = credential();
    let started = tokio::time::Instant::now();
    let Err(e) = open(&server, Some(&cred)).await else {
        panic!("must not open");
    };
    assert_eq!(e, IngestError::OpenTimeout);
    assert!(started.elapsed() >= OPEN_TIMEOUT);
    assert!(started.elapsed() < OPEN_TIMEOUT * 2);
}

#[tokio::test(start_paused = true)]
async fn a_camera_that_stops_sending_times_out_on_frames() {
    let server = spawn(Sdp::H264, Mode::NoFrames).await;
    let cred = credential();
    let mut stream = open(&server, Some(&cred)).await.unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(
        stream.next_frame().await.unwrap_err(),
        IngestError::FrameTimeout
    );
    assert!(started.elapsed() >= FRAME_TIMEOUT);
    assert!(started.elapsed() < FRAME_TIMEOUT * 2);
}

/// Keep-alive traffic must not extend the wait: the deadline is per call, not per item. Real
/// time, not paused time: with the clock paused the scripted RTCP never reaches the client before
/// the timer jumps, and the per-item mutant then survives (checked in round 2). The camera sends
/// a report every 50 ms, far more often than the 300 ms limit, so a timer that restarted per item
/// would never fire and the outer guard would fail the test.
#[tokio::test]
async fn rtcp_traffic_does_not_defer_the_frame_timeout() {
    let server = spawn(Sdp::H264, Mode::RtcpOnly).await;
    let cred = credential();
    let limit = std::time::Duration::from_millis(300);
    let mut stream = open(&server, Some(&cred))
        .await
        .unwrap()
        .with_frame_timeout(limit);
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), stream.next_frame())
        .await
        .expect("the frame timeout must fire while RTCP keeps arriving");
    assert_eq!(result.unwrap_err(), IngestError::FrameTimeout);
    assert!(started.elapsed() >= limit);
}

/// A session error is typed without camera data, and the stream is fused afterwards.
#[tokio::test]
async fn corrupt_media_is_stream_failed_without_leaking_and_fuses() {
    let server = spawn(Sdp::H264, Mode::CorruptMedia).await;
    let cred = credential();
    let mut stream = open(&server, Some(&cred)).await.unwrap();
    assert!(stream.next_frame().await.unwrap().is_some());
    let e = stream.next_frame().await.unwrap_err();
    assert_eq!(e, IngestError::StreamFailed);
    assert_no_camera_data(&format!("{e} {e:?}"), &server);
    assert!(stream.next_frame().await.unwrap().is_none());
    assert!(stream.next_frame().await.unwrap().is_none());
}

#[tokio::test]
async fn a_closed_session_ends_the_stream_after_its_frames() {
    let server = spawn(Sdp::H264, Mode::FramesThenClose).await;
    let cred = credential();
    let mut stream = open(&server, Some(&cred)).await.unwrap();
    for _ in 0..3 {
        assert!(stream.next_frame().await.unwrap().is_some());
    }
    assert!(
        stream.next_frame().await.unwrap().is_none(),
        "the camera closed the session"
    );
}
