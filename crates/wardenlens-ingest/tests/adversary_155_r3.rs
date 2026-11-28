//! Adversarial tests for #155 (PR #221) round 3: the per-access-unit NAL and piece bound
//! (`SetupOptions::max_nals_per_access_unit`, `MAX_NALS_PER_ACCESS_UNIT`). Attacks: false positives
//! on realistic large or multi-slice frames, the counter's reset between access units and after
//! loss, the bound split across packets, and the exact `16 * n` piece boundary.
//!
//! A scripted RTSP server on 127.0.0.1 only. Each test sends a fixed packet list after PLAY.

#![expect(
    clippy::unwrap_used,
    clippy::decimal_bitwise_operands,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "scripted test-server helpers; a panic fails the test"
)]

use std::num::NonZeroU16;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wardenlens_core::camera::{Credential, Host, RtspPath};
use wardenlens_core::catalogue::StreamRole;
use wardenlens_core::time::{Clock, Timestamp};
use wardenlens_ingest::{
    FrameStream, IngestError, MAX_NALS_PER_ACCESS_UNIT, OpenOptions, open_stream_with,
};

const PATH: &str = "/adv155r3";
const IDR: [u8; 5] = [0x65, 0x88, 0x84, 0x00, 0x10];

/// RTP payloads as (seq, ts, marker, payload).
type Pkts = Vec<(u16, u32, bool, Vec<u8>)>;

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

async fn serve(mut sock: TcpStream, port: u16, pkts: std::sync::Arc<Pkts>) {
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
                let mut out = Vec::new();
                for (seq, ts, m, payload) in pkts.iter() {
                    out.extend(rtp(channel, *seq, *ts, *m, payload));
                    if out.len() > 1 << 20 {
                        if sock.write_all(&out).await.is_err() {
                            return;
                        }
                        out.clear();
                    }
                }
                let _ = sock.write_all(&out).await;
            }
            _ => respond(&mut sock, &req, "200 OK", "Session: 4711\r\n", "").await,
        }
    }
}

async fn open(pkts: Pkts) -> FrameStream<StepClock> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let pkts = std::sync::Arc::new(pkts);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(serve(sock, port, std::sync::Arc::clone(&pkts)));
        }
    });
    open_stream_with(
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
    .with_frame_timeout(Duration::from_secs(30))
}

fn stap_a(count: usize) -> Vec<u8> {
    let mut p = vec![0x78_u8];
    for _ in 0..count {
        p.extend([0x00, 0x02, 0x41, 0x9a]);
    }
    p
}

/// FU-A packets for one NAL (`hdr` + `body`), `chunk` body bytes per packet; marker on the last
/// only if `marker_last`.
fn fu_a(seq0: u16, ts: u32, hdr: u8, body: &[u8], chunk: usize, marker_last: bool) -> Pkts {
    let parts: Vec<&[u8]> = body.chunks(chunk).collect();
    let last = parts.len() - 1;
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let mut fu = hdr & 0x1f;
            if i == 0 {
                fu |= 0x80;
            }
            if i == last {
                fu |= 0x40;
            }
            let mut p = vec![(hdr & 0xe0) | 28, fu];
            p.extend(*part);
            (seq0.wrapping_add(i as u16), ts, marker_last && i == last, p)
        })
        .collect()
}

/// A slice body of `len` bytes that starts and ends every `chunk`-byte fragment with a zero byte
/// (the scanner's worst case for pieces per fragment) and never forms 00 00 00..03.
fn zero_edged_body(len: usize, chunk: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let k = i % chunk;
            if k == 0 || k == chunk - 1 { 0x00 } else { 0x5a }
        })
        .collect()
}

/// A realistic large keyframe: one IDR NAL just under the 8 MiB frame cap, in FU-A fragments of
/// 1400 bytes with zeros at every fragment edge. About 6000 fragments: must be delivered, not
/// refused by the 65536-piece bound.
#[tokio::test]
async fn large_idr_in_mtu_sized_fu_a_with_zero_edges_is_delivered() {
    let body = zero_edged_body(8 * 1024 * 1024 - 4096, 1400);
    let mut pkts = vec![(100, 90_000, true, IDR.to_vec())];
    pkts.extend(fu_a(101, 93_600, 0x65, &body, 1400, true));
    let mut s = open(pkts).await;
    assert!(s.next_frame().await.unwrap().is_some());
    let f = s.next_frame().await;
    assert!(matches!(f, Ok(Some(_))), "{f:?}");
}

/// A high-resolution multi-slice frame: 4000 slices (below the 4096 NAL bound) of 1800 bytes,
/// each in two FU-A fragments. 8000 pieces: must be delivered.
#[tokio::test]
async fn many_fragmented_slices_below_the_nal_bound_are_delivered() {
    let mut pkts = vec![(100, 90_000, true, IDR.to_vec())];
    let body = zero_edged_body(1800, 1000);
    let mut seq = 101_u16;
    for i in 0..4000 {
        let frags = fu_a(seq, 93_600, 0x65, &body, 1000, i == 3999);
        seq = seq.wrapping_add(frags.len() as u16);
        pkts.extend(frags);
    }
    let mut s = open(pkts).await;
    assert!(s.next_frame().await.unwrap().is_some());
    let f = s.next_frame().await;
    assert!(matches!(f, Ok(Some(_))), "{f:?}");
}

/// The NAL count is per access unit: several consecutive access units of exactly the bound are
/// all delivered (the counter resets at each frame).
#[tokio::test]
async fn consecutive_access_units_at_the_bound_are_all_delivered() {
    let mut pkts = vec![(100, 90_000, true, IDR.to_vec())];
    for i in 0..6_u16 {
        pkts.push((
            101 + i,
            93_600 + u32::from(i) * 3600,
            true,
            stap_a(MAX_NALS_PER_ACCESS_UNIT),
        ));
    }
    let mut s = open(pkts).await;
    for n in 0..7 {
        let f = s.next_frame().await;
        assert!(matches!(f, Ok(Some(_))), "frame {n}: {f:?}");
    }
}

/// Access units delimited only by timestamp changes (no marker bits): the counter resets too.
#[tokio::test]
async fn markerless_access_units_at_the_bound_are_all_delivered() {
    let mut pkts = vec![(100, 90_000, true, IDR.to_vec())];
    for i in 0..4_u16 {
        pkts.push((
            101 + i,
            93_600 + u32::from(i) * 3600,
            false,
            stap_a(MAX_NALS_PER_ACCESS_UNIT),
        ));
    }
    // One more packet with a new timestamp ends the last one.
    pkts.push((105, 93_600 + 4 * 3600, true, IDR.to_vec()));
    let mut s = open(pkts).await;
    for n in 0..5 {
        let f = s.next_frame().await;
        assert!(matches!(f, Ok(Some(_))), "frame {n}: {f:?}");
    }
}

/// The bound counts the whole access unit, not one packet: 2048 + 2048 NALs in two packets of one
/// access unit pass, 2048 + 2049 fail.
#[tokio::test]
async fn bound_counts_across_packets_of_one_access_unit() {
    let half = MAX_NALS_PER_ACCESS_UNIT / 2;
    for (second, ok) in [(half, true), (half + 1, false)] {
        let pkts = vec![
            (100, 90_000, true, IDR.to_vec()),
            (101, 93_600, false, stap_a(half)),
            (102, 93_600, true, stap_a(second)),
        ];
        let mut s = open(pkts).await;
        assert!(s.next_frame().await.unwrap().is_some());
        let f = s.next_frame().await;
        if ok {
            assert!(matches!(f, Ok(Some(_))), "{half}+{second}: {f:?}");
        } else {
            assert_eq!(f, Err(IngestError::StreamFailed), "{half}+{second}");
        }
    }
}

/// After packet loss discards a half-built access unit, the next one starts from zero: 4000 NALs
/// lost mid-unit, then a full access unit of exactly the bound, is delivered.
#[tokio::test]
async fn counter_resets_after_loss_discards_an_access_unit() {
    let pkts = vec![
        (100, 90_000, true, IDR.to_vec()),
        (101, 93_600, false, stap_a(4000)),
        // seq 102 lost; same timestamp: retina discards the unit until the mark.
        (103, 93_600, true, stap_a(10)),
        (104, 97_200, true, stap_a(MAX_NALS_PER_ACCESS_UNIT)),
        // seq 105 lost; new timestamp.
        (106, 100_800, false, stap_a(4000)),
        (108, 104_400, true, stap_a(MAX_NALS_PER_ACCESS_UNIT)),
    ];
    let mut s = open(pkts).await;
    for n in 0..3 {
        let f = s.next_frame().await;
        assert!(matches!(f, Ok(Some(_))), "frame {n}: {f:?}");
    }
}

/// The piece bound is exactly `16 * n`: one NAL in 65536 one-byte FU-A fragments passes,
/// 65537 fails.
#[tokio::test]
async fn piece_bound_is_exactly_sixteen_times_the_nal_bound() {
    let limit = MAX_NALS_PER_ACCESS_UNIT * 16;
    for (count, ok) in [(limit, true), (limit + 1, false)] {
        let body = vec![0x5a_u8; count];
        let mut pkts = vec![(100, 90_000, true, IDR.to_vec())];
        pkts.extend(fu_a(101, 93_600, 0x65, &body, 1, true));
        let mut s = open(pkts).await;
        assert!(s.next_frame().await.unwrap().is_some());
        let f = s.next_frame().await;
        if ok {
            assert!(matches!(f, Ok(Some(_))), "{count} pieces: {f:?}");
        } else {
            assert_eq!(f, Err(IngestError::StreamFailed), "{count} pieces");
        }
    }
}
