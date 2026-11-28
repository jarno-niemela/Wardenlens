//! Adversarial tests for #155 (PR #221) round 2: the memory a hostile camera can make one session
//! hold before the read-buffer bound (`max_buffered_bytes`, 16 MiB - 64 KiB) fails it. The bound
//! is on ring bytes; the depacketizer's per-NAL metadata (`pieces`, 16 bytes per piece, and `nals`,
//! 12 bytes per NAL) grows with the NAL count, not the byte count. A STAP-A of 2-byte NALs costs 4
//! ring bytes and 28 metadata bytes per NAL.
//!
//! A scripted RTSP server on 127.0.0.1 only; packets are generated lazily so the server does not
//! add to the measured peak. Peak memory is the process's `VmHWM` (Linux), so this file holds a
//! single test.

#![expect(
    clippy::unwrap_used,
    clippy::decimal_bitwise_operands,
    clippy::arithmetic_side_effects,
    reason = "scripted test-server helpers; a panic fails the test"
)]

use std::num::NonZeroU16;
use std::sync::atomic::{AtomicI64, Ordering};

use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wardenlens_core::camera::{Credential, Host, RtspPath};
use wardenlens_core::catalogue::StreamRole;
use wardenlens_core::time::{Clock, Timestamp};
use wardenlens_ingest::{IngestError, OpenOptions, open_stream_with};

const PATH: &str = "/adv155r2";
const IDR: [u8; 5] = [0x65, 0x88, 0x84, 0x00, 0x10];

struct StepClock(AtomicI64);

impl Clock for StepClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.fetch_add(10, Ordering::SeqCst))
    }
}

fn sdp() -> String {
    "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=t\r\nt=0 0\r\n\
     m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
     a=fmtp:96 packetization-mode=1;profile-level-id=42C00A;sprop-parameter-sets=Z0LACtoQmQ==,aM48gA==\r\n\
     a=control:trackID=0\r\n"
        .to_owned()
}

async fn read_request(sock: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if sock.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        if buf.is_empty() && byte[0] == b'$' {
            let mut hdr = [0_u8; 3];
            sock.read_exact(&mut hdr).await.ok()?;
            let mut skip = vec![0_u8; usize::from(u16::from_be_bytes([hdr[1], hdr[2]]))];
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

fn rtp(channel: u8, seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, if marker { 0x80 | 96 } else { 96 }];
    p.extend(seq.to_be_bytes());
    p.extend(ts.to_be_bytes());
    p.extend(0x1234_5678_u32.to_be_bytes());
    p.extend(payload);
    let mut out = vec![b'$', channel];
    out.extend(u16::try_from(p.len()).unwrap().to_be_bytes());
    out.extend(p);
    out
}

/// One STAP-A (type 24) as large as an interleaved packet allows, of 2-byte NALs (a header and
/// one body byte): each NAL is one `Nal` and one `BufRange` piece in retina's depacketizer.
fn stap_a_of_tiny_nals() -> Vec<u8> {
    let mut p = vec![0x78_u8];
    // 65535 - 12 (RTP header) - 1 (STAP-A header), in 4-byte entries.
    for _ in 0..(65_535 - 13) / 4 {
        p.extend([0x00, 0x02, 0x41, 0x9a]);
    }
    p
}

async fn serve(mut sock: TcpStream, port: u16) {
    let mut channel = 0_u8;
    while let Some(req) = read_request(&mut sock).await {
        let method = req.split_whitespace().next().unwrap_or("").to_owned();
        match method.as_str() {
            "DESCRIBE" => {
                let base = format!(
                    "Content-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1:{port}{PATH}/\r\n"
                );
                respond(&mut sock, &req, "200 OK", &base, &sdp()).await;
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
                let _ = sock.write_all(&rtp(channel, 100, 90_000, true, &IDR)).await;
                // 32 MiB of one access unit (same timestamp, no marker): twice the bound.
                let stap = stap_a_of_tiny_nals();
                for i in 0..512_u16 {
                    let pkt = rtp(channel, 101_u16.wrapping_add(i), 93_000, false, &stap);
                    if sock.write_all(&pkt).await.is_err() {
                        return;
                    }
                }
            }
            _ => respond(&mut sock, &req, "200 OK", "Session: 4711\r\n", "").await,
        }
    }
}

/// Peak resident set of this process in KiB (`VmHWM`).
fn peak_rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

/// ADR 0002 item 12: "the peak is about twice that (up to about 32 MiB), plus the depacketizer's
/// piece metadata". With 2-byte NALs the metadata is seven times the ring data, so the session
/// holds about 112 MiB of metadata (Vec capacities 64 MiB + 48 MiB, plus a realloc transient)
/// before the 16 MiB bound fails it. Expect the peak growth to stay within 64 MiB (the stated
/// 32 MiB with as much again of slack).
#[tokio::test]
async fn adv_tiny_nal_flood_peak_memory_stays_near_the_stated_bound() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(serve(sock, port));
        }
    });
    let mut s = open_stream_with(
        &Host::new("127.0.0.1").unwrap(),
        NonZeroU16::new(port).unwrap(),
        &RtspPath::new(PATH).unwrap(),
        Some(&Credential::new(
            "adv-user",
            SecretString::from("adv-pass".to_owned()),
        )),
        StreamRole::Main,
        StepClock(AtomicI64::new(1_700_000_000_000)),
        OpenOptions::default(),
    )
    .await
    .unwrap()
    .with_frame_timeout(std::time::Duration::from_secs(60));
    assert!(s.next_frame().await.unwrap().is_some());
    let before = peak_rss_kib();
    assert_eq!(s.next_frame().await, Err(IngestError::StreamFailed));
    let grown_mib = (peak_rss_kib() - before) / 1024;
    assert!(
        grown_mib <= 64,
        "one session grew peak RSS by {grown_mib} MiB before the 16 MiB buffer bound failed it"
    );
}
