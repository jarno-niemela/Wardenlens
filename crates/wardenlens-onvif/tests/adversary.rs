//! Adversarial tests for PR #150 (ticket #52): a loopback-only fake camera that sends raw,
//! hand-written HTTP, plus parser and stream-URI attacks on the public API.
#![expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "test code: small bounded counters and readable string building"
)]

use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use proptest::prelude::*;
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wardenlens_core::camera::{Credential, Host};
use wardenlens_core::connection::Backoff;
use wardenlens_core::time::DurationMs;
use wardenlens_onvif::{
    ClientConfig, MAX_BODY_BYTES, OnvifClient, OnvifError, parse_profiles, reduce_stream_uri,
};

const PASSWORD: &str = "PW-ADV-SENTINEL-77";

const NS: &str = r#"xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema""#;

fn env(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><env:Envelope {NS}><env:Body>{body}</env:Body></env:Envelope>"#
    )
}

fn device_info() -> String {
    env(
        "<tds:GetDeviceInformationResponse><tds:Manufacturer>Acme</tds:Manufacturer>\
         <tds:Model>Cam-1</tds:Model><tds:FirmwareVersion>1</tds:FirmwareVersion>\
         <tds:SerialNumber>S</tds:SerialNumber><tds:HardwareId>H</tds:HardwareId>\
         </tds:GetDeviceInformationResponse>",
    )
}

fn video_profile(token: &str, w: u32, h: u32) -> String {
    format!(
        r#"<trt:Profiles token="{token}"><tt:Name>n</tt:Name><tt:VideoEncoderConfiguration token="ve"><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>{w}</tt:Width><tt:Height>{h}</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>"#
    )
}

fn profiles(list: &[String]) -> String {
    env(&format!(
        "<trt:GetProfilesResponse>{}</trt:GetProfilesResponse>",
        list.concat()
    ))
}

/// What the raw fake does after reading one full request.
#[derive(Clone)]
enum Script {
    /// Writes these bytes, then closes.
    Raw(Vec<u8>),
    /// Writes `head`, then repeats `block` until the client hangs up.
    Repeat { head: Vec<u8>, block: Vec<u8> },
    /// Writes these bytes, then holds the connection open until the client hangs up.
    RawThenHold(Vec<u8>),
}

struct Fake {
    port: u16,
    accepted: Arc<AtomicUsize>,
}

async fn read_request(stream: &mut TcpStream) -> Option<()> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text[..end]
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return Some(());
            }
        }
    }
}

async fn serve(mut stream: TcpStream, script: Script) {
    if read_request(&mut stream).await.is_none() {
        return;
    }
    match script {
        Script::Raw(bytes) => {
            let _ = stream.write_all(&bytes).await;
            let _ = stream.shutdown().await;
        }
        Script::Repeat { head, block } => {
            let _ = stream.write_all(&head).await;
            while stream.write_all(&block).await.is_ok() {}
        }
        Script::RawThenHold(bytes) => {
            let _ = stream.write_all(&bytes).await;
            // Hold until the client closes: a read returns 0 or an error.
            let mut sink = [0_u8; 64];
            while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
        }
    }
}

async fn spawn_on(bind: &str, script: Script) -> Fake {
    let listener = TcpListener::bind(bind).await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let acc = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            acc.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve(stream, script.clone()));
        }
    });
    Fake { port, accepted }
}

async fn spawn(script: Script) -> Fake {
    spawn_on("127.0.0.1:0", script).await
}

fn cfg() -> ClientConfig {
    let mut c = ClientConfig::default();
    c.connect_timeout = Duration::from_secs(5);
    c.request_timeout = Duration::from_secs(30);
    c.backoff = Backoff::new(DurationMs::from_millis(1), DurationMs::from_millis(1));
    c
}

fn client_for(host: &str, port: u16) -> OnvifClient {
    OnvifClient::new(
        Host::new(host).expect("host"),
        NonZeroU16::new(port).expect("port"),
        Some(Credential::new("u", SecretString::from(PASSWORD))),
    )
    .with_config(cfg())
}

fn http200(body: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

fn chunked200(body: &[u8], chunk: usize) -> Vec<u8> {
    let mut v =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for c in body.chunks(chunk) {
        v.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        v.extend_from_slice(c);
        v.extend_from_slice(b"\r\n");
    }
    v.extend_from_slice(b"0\r\n\r\n");
    v
}

fn padded_info(len: usize) -> Vec<u8> {
    let mut b = device_info().into_bytes();
    b.resize(len, b' ');
    b
}

fn assert_no_leak(e: &OnvifError) {
    for s in [format!("{e}"), format!("{e:?}")] {
        assert!(!s.contains(PASSWORD), "{s}");
        assert!(!s.contains("127.0.0.1"), "{s}");
    }
}

// ---- the transport: shapes of a hostile reply ----

#[tokio::test]
async fn ipv6_loopback_host_connects_and_answers() {
    let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
        return; // no IPv6 loopback on this machine
    };
    drop(listener);
    let fake = spawn_on("[::1]:0", Script::Raw(http200(device_info().as_bytes()))).await;
    let r = client_for("::1", fake.port).get_device_information().await;
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(fake.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn chunked_body_up_to_the_cap_is_accepted_and_one_over_is_refused() {
    for (len, ok) in [(MAX_BODY_BYTES, true), (MAX_BODY_BYTES + 1, false)] {
        let fake = spawn(Script::Raw(chunked200(&padded_info(len), 7919))).await;
        let r = client_for("127.0.0.1", fake.port)
            .get_device_information()
            .await;
        if ok {
            assert!(r.is_ok(), "{len}: {r:?}");
        } else {
            assert_eq!(r.err(), Some(OnvifError::BodyTooLarge), "{len}");
        }
        assert_eq!(fake.accepted.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn endless_chunked_body_stops_at_the_cap() {
    let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let mut block = b"1000\r\n".to_vec();
    block.extend_from_slice(&[b' '; 0x1000]);
    block.extend_from_slice(b"\r\n");
    let fake = spawn(Script::Repeat { head, block }).await;
    let r = client_for("127.0.0.1", fake.port)
        .get_device_information()
        .await;
    assert_eq!(r.err(), Some(OnvifError::BodyTooLarge));
    assert_eq!(fake.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn endless_chunk_extension_ends_with_a_typed_final_error() {
    let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;".to_vec();
    let fake = spawn(Script::Repeat {
        head,
        block: vec![b'a'; 4096],
    })
    .await;
    let r = client_for("127.0.0.1", fake.port)
        .get_device_information()
        .await;
    let e = r.expect_err("must fail");
    assert_eq!(e, OnvifError::Transport, "{e:?}");
    assert_eq!(fake.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn endless_trailers_end_with_a_typed_final_error() {
    let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
    let fake = spawn(Script::Repeat {
        head,
        block: b"X-T: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n".to_vec(),
    })
    .await;
    let r = client_for("127.0.0.1", fake.port)
        .get_device_information()
        .await;
    assert_eq!(r.err(), Some(OnvifError::Transport));
    assert_eq!(fake.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn endless_header_is_bounded_and_retried_then_unreachable() {
    let head = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
    let fake = spawn(Script::Repeat {
        head,
        block: vec![b'a'; 8192],
    })
    .await;
    let r = client_for("127.0.0.1", fake.port)
        .get_device_information()
        .await;
    assert_eq!(r.err(), Some(OnvifError::Unreachable { attempts: 6 }));
    assert_eq!(fake.accepted.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn non_http_garbage_is_a_typed_error() {
    let fake = spawn(Script::Raw(b"\x00\x01SSH-2.0-nope\r\n\r\n".to_vec())).await;
    let r = client_for("127.0.0.1", fake.port)
        .get_device_information()
        .await;
    let e = r.expect_err("must fail");
    assert_no_leak(&e);
    assert_eq!(e, OnvifError::Unreachable { attempts: 6 });
}

#[tokio::test]
#[ignore = "follow-up #151"]
async fn content_length_over_the_cap_is_refused_without_waiting_for_the_body() {
    // The camera announces 2 MiB and then stays silent. The cap must not wait for the timeout:
    // with request_timeout at 30 s the test would take 30 s and report Timeout.
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        2 * MAX_BODY_BYTES
    )
    .into_bytes();
    let fake = spawn(Script::RawThenHold(head)).await;
    let mut c = cfg();
    c.request_timeout = Duration::from_secs(2);
    let r = OnvifClient::new(
        Host::new("127.0.0.1").expect("host"),
        NonZeroU16::new(fake.port).expect("port"),
        None,
    )
    .with_config(c)
    .get_device_information()
    .await;
    assert_eq!(r.err(), Some(OnvifError::BodyTooLarge));
}

#[tokio::test]
async fn conflicting_content_lengths_are_never_parsed_as_a_reply() {
    let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\n".to_vec();
    raw.extend_from_slice(device_info().as_bytes());
    let fake = spawn(Script::Raw(raw)).await;
    let r = client_for("127.0.0.1", fake.port)
        .get_device_information()
        .await;
    assert!(r.is_err(), "{r:?}");
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let raw = b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.99/onvif/device_service\r\nContent-Length: 0\r\n\r\n".to_vec();
    let fake = spawn(Script::Raw(raw)).await;
    let r = client_for("127.0.0.1", fake.port)
        .get_device_information()
        .await;
    assert_eq!(r.err(), Some(OnvifError::HttpStatus { status: 302 }));
    assert_eq!(fake.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn many_informational_heads_then_a_reply() {
    let mut raw = Vec::new();
    for _ in 0..50 {
        raw.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    raw.extend_from_slice(&http200(device_info().as_bytes()));
    let fake = spawn(Script::Raw(raw)).await;
    let r = client_for("127.0.0.1", fake.port)
        .get_device_information()
        .await;
    assert!(r.is_ok(), "{r:?}");
}

// ---- the parser ----

#[test]
#[ignore = "follow-up #151"]
fn an_audio_only_profile_with_an_unusual_token_does_not_hide_the_video_profiles() {
    // The audio-only profile is documented as "left out"; its token is never sent back, so its
    // spelling must not decide whether the video profiles can be read.
    let audio = r#"<trt:Profiles token="Audio Profile #1"><tt:Name>A</tt:Name></trt:Profiles>"#;
    let r =
        parse_profiles(profiles(&[audio.to_owned(), video_profile("main", 1920, 1080)]).as_bytes());
    let list = r.expect("the video profile is readable");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].token.as_str(), "main");
}

#[test]
#[ignore = "follow-up #151"]
fn an_audio_only_profile_without_a_token_does_not_hide_the_video_profiles() {
    let audio = r"<trt:Profiles><tt:Name>A</tt:Name></trt:Profiles>";
    let r =
        parse_profiles(profiles(&[video_profile("main", 1920, 1080), audio.to_owned()]).as_bytes());
    assert_eq!(r.map(|l| l.len()), Ok(1));
}

#[test]
#[ignore = "follow-up #151"]
fn a_token_is_never_altered_before_it_is_sent_back() {
    // " main" (leading space via a character reference) is a different token from "main";
    // trimming it would make GetStreamUri ask for a profile the camera does not have.
    let r = parse_profiles(profiles(&[video_profile("&#32;main", 10, 10)]).as_bytes());
    if let Ok(list) = r {
        assert_ne!(
            list.first().map(|p| p.token.as_str()),
            Some("main"),
            "token silently trimmed"
        );
    }
}

#[test]
fn huge_attribute_count_is_parsed_quickly_or_refused() {
    // 100k distinct attributes on one element, under 1 MiB: duplicate checks must not be
    // quadratic. A result (either way) is all that is asserted; a hang fails the test run.
    let mut attrs = String::new();
    for i in 0..100_000 {
        attrs.push_str(" a");
        attrs.push_str(&i.to_string());
        attrs.push_str("=\"\"");
    }
    let doc = env(&format!(
        "<trt:GetProfilesResponse{attrs}></trt:GetProfilesResponse>"
    ));
    assert!(doc.len() < MAX_BODY_BYTES);
    let _ = parse_profiles(doc.as_bytes());
}

// ---- the stream URI: a password echoed raw, in any spelling ----

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn echoed_raw_password_never_reaches_the_endpoint(
        pw in "[ -~]{1,24}",
        path in prop::sample::select(vec!["/stream1", "/11", "/h264Preview_01_main", "/cam/realmonitor?channel=1&subtype=0"]),
        port in prop::option::of(1_u16..=65535),
    ) {
        let port_text = port.map_or_else(String::new, |p| format!(":{p}"));
        let uri = format!("rtsp://admin:{pw}@192.0.2.10{port_text}{path}");
        if let Ok(ep) = reduce_stream_uri(&uri) {
            prop_assert_eq!(ep.path.as_str(), path, "uri {}", uri);
            prop_assert_eq!(ep.port.get(), port.unwrap_or(554));
        }
    }

    #[test]
    fn host_in_the_reply_never_changes_the_endpoint(
        host in prop::sample::select(vec!["192.0.2.10", "[2001:db8::1]", "evil.example.invalid", "a", "[::]"]),
        user in prop::option::of("[a-z]{1,8}"),
    ) {
        let ui = user.map_or_else(String::new, |u| format!("{u}@"));
        let ep = reduce_stream_uri(&format!("rtsp://{ui}{host}:8554/s")).expect("ok");
        prop_assert_eq!(ep.path.as_str(), "/s");
        prop_assert_eq!(ep.port.get(), 8554);
    }
}
