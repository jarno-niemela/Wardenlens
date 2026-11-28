//! Adversarial tests for PR #239 (ticket #151): per-attempt envelope, the Content-Length cap,
//! the split head/body timeouts, the Cf refusal, the token rules and the codec-aware stream
//! choice. Loopback-only fakes that speak raw HTTP.
#![expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "test code: small bounded counters and readable string building"
)]

use std::num::NonZeroU16;
use std::time::Duration;

use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wardenlens_core::camera::{Credential, Host};
use wardenlens_core::connection::Backoff;
use wardenlens_core::time::DurationMs;
use wardenlens_onvif::{
    ClientConfig, MAX_BODY_BYTES, OnvifClient, OnvifError, Profile, VideoEncoding,
    parse_device_information, parse_profiles, pick_streams,
};

const NS: &str = r#"xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema""#;

fn env(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><env:Envelope {NS}><env:Body>{body}</env:Body></env:Envelope>"#
    )
}

fn device_info_with(fields: [&str; 5]) -> String {
    env(&format!(
        "<tds:GetDeviceInformationResponse><tds:Manufacturer>{}</tds:Manufacturer>\
         <tds:Model>{}</tds:Model><tds:FirmwareVersion>{}</tds:FirmwareVersion>\
         <tds:SerialNumber>{}</tds:SerialNumber><tds:HardwareId>{}</tds:HardwareId>\
         </tds:GetDeviceInformationResponse>",
        fields[0], fields[1], fields[2], fields[3], fields[4]
    ))
}

fn video(token: &str, name: &str, w: u32, h: u32, enc: Option<&str>) -> String {
    let enc = enc.map_or(String::new(), |e| format!("<tt:Encoding>{e}</tt:Encoding>"));
    format!(
        r#"<trt:Profiles token="{token}"><tt:Name>{name}</tt:Name><tt:VideoEncoderConfiguration token="ve">{enc}<tt:Resolution><tt:Width>{w}</tt:Width><tt:Height>{h}</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>"#
    )
}

fn profiles(list: &[String]) -> String {
    env(&format!(
        "<trt:GetProfilesResponse>{}</trt:GetProfilesResponse>",
        list.concat()
    ))
}

// ---- a raw loopback fake ----

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

#[derive(Clone)]
enum Script {
    /// Writes the bytes, then holds the connection until the client hangs up.
    Hold(Vec<u8>),
    /// Writes `head`, then repeats `block` until the client hangs up.
    Repeat { head: Vec<u8>, block: Vec<u8> },
}

async fn serve(mut stream: TcpStream, script: Script) {
    if read_request(&mut stream).await.is_none() {
        return;
    }
    match script {
        Script::Hold(bytes) => {
            let _ = stream.write_all(&bytes).await;
            let mut sink = [0_u8; 64];
            while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
        }
        Script::Repeat { head, block } => {
            let _ = stream.write_all(&head).await;
            while stream.write_all(&block).await.is_ok() {}
        }
    }
}

async fn spawn(script: Script) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(serve(s, script.clone()));
        }
    });
    port
}

fn cfg(head: Duration, body: Duration) -> ClientConfig {
    let mut c = ClientConfig::default();
    c.connect_timeout = Duration::from_secs(5);
    c.request_timeout = head;
    c.body_timeout = body;
    c.backoff = Backoff::new(DurationMs::from_millis(1), DurationMs::from_millis(1));
    c
}

fn client(port: u16, cred: Option<Credential>, c: ClientConfig) -> OnvifClient {
    OnvifClient::new(
        Host::new("127.0.0.1").expect("host"),
        NonZeroU16::new(port).expect("port"),
        cred,
    )
    .with_config(c)
}

/// Runs `fut` under a generous outer guard: hitting the guard means the client hung.
async fn bounded<T>(secs: u64, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(secs), fut)
        .await
        .expect("the client hung past its own timeouts")
}

// ---- the per-attempt envelope: a request that cannot be built ----

#[tokio::test]
async fn an_unbuildable_request_is_reported_as_such_even_when_the_camera_is_down() {
    // A port with nothing listening: every connect is refused at once.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        l.local_addr().expect("addr").port()
    };
    let bad_user = Credential::new("a\u{1}b", SecretString::from("pw"));
    let r = bounded(
        60,
        client(
            port,
            Some(bad_user),
            cfg(Duration::from_secs(5), Duration::from_secs(5)),
        )
        .get_device_information(),
    )
    .await;
    // The user name can never be sent; "camera unreachable" would send the operator to the
    // network instead of the credential.
    assert_eq!(r.err(), Some(OnvifError::UserNotXmlSafe));
}

#[tokio::test]
async fn an_unbuildable_request_never_opens_a_connection() {
    // Deterministic, unlike a counter in the fake's accept task: the kernel queues every
    // completed connect, so after the call the test connects once itself and accepts. If the
    // first accepted peer is not the test's own socket, the client connected.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let bad_user = Credential::new("a\u{1}b", SecretString::from("pw"));
    let r = client(
        port,
        Some(bad_user),
        cfg(Duration::from_secs(5), Duration::from_secs(5)),
    )
    .get_device_information()
    .await;
    assert_eq!(r.err(), Some(OnvifError::UserNotXmlSafe));
    let probe = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("probe");
    let mine = probe.local_addr().expect("probe addr");
    let (_s, first_peer) = listener.accept().await.expect("accept");
    assert_eq!(
        first_peer, mine,
        "the client connected to the camera for a request it could not build"
    );
}

// ---- the Content-Length cap and the body timeout ----

fn head_with_length(n: u64) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn content_length_one_over_the_cap_is_refused_at_once() {
    let over = u64::try_from(MAX_BODY_BYTES).expect("fits") + 1;
    let port = spawn(Script::Hold(head_with_length(over))).await;
    // Both timeouts are far beyond the outer guard: only the size check can answer in time.
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(20, client(port, None, c).get_device_information()).await;
    assert_eq!(r.err(), Some(OnvifError::BodyTooLarge));
}

#[tokio::test]
async fn content_length_of_u64_max_is_refused_without_waiting() {
    let port = spawn(Script::Hold(head_with_length(u64::MAX))).await;
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(20, client(port, None, c).get_device_information()).await;
    assert!(
        matches!(
            r.as_ref().err(),
            Some(OnvifError::BodyTooLarge | OnvifError::Unreachable { .. })
        ),
        "{r:?}"
    );
}

#[tokio::test]
async fn content_length_exactly_at_the_cap_is_not_refused_by_the_size_check() {
    // At the cap the body is read; the camera holds, so the body timeout answers.
    let at = u64::try_from(MAX_BODY_BYTES).expect("fits");
    let port = spawn(Script::Hold(head_with_length(at))).await;
    let c = cfg(Duration::from_secs(120), Duration::from_millis(200));
    let r = bounded(20, client(port, None, c).get_device_information()).await;
    assert_eq!(r.err(), Some(OnvifError::Timeout));
}

#[tokio::test]
async fn a_huge_declared_chunk_that_never_arrives_ends_at_the_body_timeout() {
    let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n200000\r\nabc".to_vec();
    let port = spawn(Script::Hold(head)).await;
    let c = cfg(Duration::from_secs(120), Duration::from_millis(200));
    let r = bounded(20, client(port, None, c).get_device_information()).await;
    assert_eq!(r.err(), Some(OnvifError::Timeout));
}

#[tokio::test]
async fn an_endless_chunked_body_stops_at_the_cap() {
    let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let mut block = b"1000\r\n".to_vec();
    block.extend(std::iter::repeat_n(b'x', 0x1000));
    block.extend_from_slice(b"\r\n");
    let port = spawn(Script::Repeat { head, block }).await;
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(30, client(port, None, c).get_device_information()).await;
    assert_eq!(r.err(), Some(OnvifError::BodyTooLarge));
}

#[tokio::test]
async fn an_endless_close_delimited_body_stops_at_the_cap() {
    let head = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    let block = vec![b'x'; 8192];
    let port = spawn(Script::Repeat { head, block }).await;
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(30, client(port, None, c).get_device_information()).await;
    assert_eq!(r.err(), Some(OnvifError::BodyTooLarge));
}

#[tokio::test]
async fn endless_header_lines_are_bounded_by_the_head_limit() {
    // The head never ends; hyper's 64 KiB head buffer must refuse it long before the head
    // timeout, on every attempt.
    let head = b"HTTP/1.1 200 OK\r\n".to_vec();
    let block = b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n".to_vec();
    let port = spawn(Script::Repeat { head, block }).await;
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(60, client(port, None, c).get_device_information()).await;
    assert_eq!(r.err(), Some(OnvifError::Unreachable { attempts: 6 }));
}

#[tokio::test]
async fn unauthorized_with_a_huge_length_is_still_unauthorized() {
    let head = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 99999999\r\n\r\n".to_vec();
    let port = spawn(Script::Hold(head)).await;
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(20, client(port, None, c).get_device_information()).await;
    assert_eq!(r.err(), Some(OnvifError::Unauthorized));
}

#[tokio::test]
async fn the_head_timeout_does_not_cut_a_body_that_arrives_within_the_body_timeout() {
    // The body is complete at once; a tiny head timeout must not be applied to the body read.
    let body = device_info_with(["Acme", "M", "1", "S", "H"]);
    let mut raw = head_with_length(u64::try_from(body.len()).expect("fits"));
    raw.extend_from_slice(body.as_bytes());
    let port = spawn(Script::Hold(raw)).await;
    let c = cfg(Duration::from_secs(5), Duration::from_secs(5));
    let r = bounded(20, client(port, None, c).get_device_information()).await;
    assert!(r.is_ok(), "{r:?}");
}

// ---- untrusted text: every Unicode 16 Cf code point, and other invisibles ----

/// General category Cf in Unicode 16.0, from Python's `unicodedata` (an independent source).
const CF_RANGES: &[(u32, u32)] = &[
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

const FIELDS: [&str; 5] = [
    "Manufacturer",
    "Model",
    "FirmwareVersion",
    "SerialNumber",
    "HardwareId",
];

#[test]
fn every_cf_code_point_is_refused_in_every_device_field_and_position() {
    let mut checked = 0_usize;
    for &(lo, hi) in CF_RANGES {
        for cp in lo..=hi {
            let c = char::from_u32(cp).expect("scalar");
            for (i, field) in FIELDS.iter().enumerate() {
                for text in [format!("{c}Acme"), format!("Ac{c}me"), format!("Acme{c}")] {
                    let mut f = ["a", "b", "c", "d", "e"];
                    f[i] = &text;
                    let r = parse_device_information(device_info_with(f).as_bytes());
                    assert_eq!(
                        r,
                        Err(OnvifError::InvalidField { field }),
                        "U+{cp:04X} in {field}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 2000);
}

#[test]
fn every_cf_code_point_is_refused_in_a_profile_name() {
    for &(lo, hi) in CF_RANGES {
        for cp in lo..=hi {
            let c = char::from_u32(cp).expect("scalar");
            let r = parse_profiles(
                profiles(&[video("main", &format!("n{c}"), 10, 10, Some("H264"))]).as_bytes(),
            );
            assert_eq!(
                r.err(),
                Some(OnvifError::InvalidField { field: "Name" }),
                "U+{cp:04X}"
            );
        }
    }
}

#[test]
fn cf_given_as_a_character_reference_is_refused_too() {
    for reference in ["&#x202E;", "&#8238;", "&#xFEFF;", "&#xE0041;"] {
        let r = parse_device_information(
            device_info_with([&format!("Acme{reference}"), "b", "c", "d", "e"]).as_bytes(),
        );
        assert_eq!(
            r,
            Err(OnvifError::InvalidField {
                field: "Manufacturer"
            }),
            "{reference}"
        );
    }
}

#[test]
fn line_and_paragraph_separators_inside_a_field_are_refused() {
    // U+2028 / U+2029 (Zl / Zp) are neither Cc nor Cf, yet they break a log line in most
    // viewers. Inside the text they are not trimmed away.
    for sep in ['\u{2028}', '\u{2029}'] {
        let r = parse_device_information(
            device_info_with([&format!("Acme{sep}Fake log line"), "b", "c", "d", "e"]).as_bytes(),
        );
        assert_eq!(
            r,
            Err(OnvifError::InvalidField {
                field: "Manufacturer"
            }),
            "U+{:04X}",
            u32::from(sep)
        );
    }
}

#[test]
fn ordinary_text_with_marks_and_scripts_stays_valid() {
    for ok in [
        "Caf\u{e9}",
        "Cafe\u{301}",
        "\u{05E9}\u{05DC}\u{05D5}\u{05DD}",
        "\u{0627}\u{0644}\u{0639}\u{0631}\u{0628}\u{064A}\u{0629}",
        "\u{65E5}\u{672C}",
        "a b",
    ] {
        let r = parse_device_information(device_info_with([ok, "b", "c", "d", "e"]).as_bytes());
        assert!(r.is_ok(), "{ok:?}: {r:?}");
    }
}

// ---- tokens ----

#[test]
fn tokens_with_invisible_or_whitespace_characters_are_refused_untrimmed() {
    for token in [
        "main&#x200B;",
        "&#x202E;main",
        "main&#9;",
        "main&#10;",
        "main&#13;",
        "&#xA0;main",
        "main ",
    ] {
        let r = parse_profiles(profiles(&[video(token, "n", 10, 10, Some("H264"))]).as_bytes());
        assert_eq!(
            r.err(),
            Some(OnvifError::InvalidField { field: "token" }),
            "{token:?}"
        );
    }
}

#[test]
fn a_token_at_the_length_limit_is_kept_and_one_more_is_refused() {
    let at = "a".repeat(64);
    let r = parse_profiles(profiles(&[video(&at, "n", 10, 10, Some("H264"))]).as_bytes());
    assert_eq!(r.map(|l| l[0].token.as_str().to_owned()), Ok(at));
    let over = "a".repeat(65);
    let r = parse_profiles(profiles(&[video(&over, "n", 10, 10, Some("H264"))]).as_bytes());
    assert_eq!(r.err(), Some(OnvifError::InvalidField { field: "token" }));
}

#[test]
fn a_bad_video_token_after_a_good_one_is_still_refused() {
    let r = parse_profiles(
        profiles(&[
            video("main", "n", 1920, 1080, Some("H264")),
            video("bad token", "n", 640, 360, Some("H264")),
        ])
        .as_bytes(),
    );
    assert_eq!(r.err(), Some(OnvifError::InvalidField { field: "token" }));
}

#[test]
fn a_video_profile_without_a_token_is_refused() {
    let p = r"<trt:Profiles><tt:VideoEncoderConfiguration><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>10</tt:Width><tt:Height>10</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>";
    let r = parse_profiles(profiles(&[p.to_owned()]).as_bytes());
    assert_eq!(r.err(), Some(OnvifError::InvalidField { field: "token" }));
}

#[test]
fn non_video_profiles_with_odd_tokens_and_names_are_left_out() {
    // Hostile spelling everywhere on the audio and metadata profiles: none of it matters.
    let audio = r#"<trt:Profiles token="a b &lt;"><tt:Name>x&#x202E;y</tt:Name><tt:AudioEncoderConfiguration/></trt:Profiles>"#;
    let meta = r#"<trt:Profiles token="main"><tt:MetadataConfiguration/></trt:Profiles>"#;
    let r = parse_profiles(
        profiles(&[
            audio.to_owned(),
            meta.to_owned(),
            video("main", "n", 1920, 1080, Some("H264")),
        ])
        .as_bytes(),
    );
    let list = r.expect("video profiles readable");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].token.as_str(), "main");
}

// ---- the stream choice ----

fn ps(spec: &[(&str, u32, u32, Option<&str>)]) -> Vec<Profile> {
    let list: Vec<String> = spec
        .iter()
        .map(|(t, w, h, e)| video(t, "n", *w, *h, *e))
        .collect();
    parse_profiles(profiles(&list).as_bytes()).expect("profiles")
}

/// The expected (main, sub) tokens.
type Want<'a> = Option<(&'a str, Option<&'a str>)>;

fn pick(p: &[Profile]) -> Option<(String, Option<String>)> {
    pick_streams(p).map(|c| {
        (
            c.main.token.as_str().to_owned(),
            c.sub.map(|s| s.token.as_str().to_owned()),
        )
    })
}

/// An independent oracle: filter to H.264/H.265 when any exists, then max / min by pixels,
/// ties to the first listed, sub only when strictly smaller.
fn oracle(p: &[Profile]) -> Option<(String, Option<String>)> {
    let modern: Vec<&Profile> = p
        .iter()
        .filter(|x| matches!(x.encoding, VideoEncoding::H264 | VideoEncoding::H265))
        .collect();
    let pool: Vec<&Profile> = if modern.is_empty() {
        p.iter().collect()
    } else {
        modern
    };
    let mut main = *pool.first()?;
    for x in &pool {
        if x.pixels() > main.pixels() {
            main = x;
        }
    }
    let mut sub: Option<&Profile> = None;
    for x in &pool {
        if x.pixels() < main.pixels() && sub.is_none_or(|s| x.pixels() < s.pixels()) {
            sub = Some(x);
        }
    }
    Some((
        main.token.as_str().to_owned(),
        sub.map(|s| s.token.as_str().to_owned()),
    ))
}

#[test]
fn stream_choice_table() {
    let cases: Vec<(Vec<Profile>, Want<'_>)> = vec![
        (Vec::new(), None),
        (ps(&[("j", 160, 120, Some("JPEG"))]), Some(("j", None))),
        // An MJPEG between main and sub in size is never chosen.
        (
            ps(&[
                ("m", 1920, 1080, Some("H264")),
                ("j", 1280, 720, Some("JPEG")),
                ("s", 640, 360, Some("H264")),
            ]),
            Some(("m", Some("s"))),
        ),
        // Lower-case and padded spellings still count as H.264 / H.265.
        (
            ps(&[
                ("j", 3840, 2160, Some("JPEG")),
                ("m", 1920, 1080, Some(" h264 ")),
                ("s", 640, 360, Some("h265")),
            ]),
            Some(("m", Some("s"))),
        ),
        // A missing encoding is Other: ranks below a modern codec.
        (
            ps(&[("x", 3840, 2160, None), ("m", 640, 480, Some("H264"))]),
            Some(("m", None)),
        ),
        // Only one modern profile, many small MJPEG ones: no sub.
        (
            ps(&[
                ("j1", 320, 240, Some("JPEG")),
                ("m", 1920, 1080, Some("H265")),
                ("j2", 160, 120, Some("JPEG")),
            ]),
            Some(("m", None)),
        ),
        // Ties: the first listed wins both ways.
        (
            ps(&[
                ("a", 1920, 1080, Some("H264")),
                ("b", 1920, 1080, Some("H265")),
                ("c", 640, 360, Some("H264")),
                ("d", 640, 360, Some("H265")),
            ]),
            Some(("a", Some("c"))),
        ),
        // A rotated portrait main stream: pixels, not width, decide.
        (
            ps(&[
                ("s", 1280, 720, Some("H264")),
                ("m", 1080, 1920, Some("H264")),
            ]),
            Some(("m", Some("s"))),
        ),
    ];
    for (i, (profiles, want)) in cases.iter().enumerate() {
        let want = want.map(|(m, s)| (m.to_owned(), s.map(str::to_owned)));
        assert_eq!(pick(profiles), want, "case {i}");
        assert_eq!(
            oracle(profiles),
            want,
            "oracle disagrees with the table, case {i}"
        );
    }
}

#[test]
fn stream_choice_matches_the_oracle_over_generated_mixes() {
    // A small deterministic LCG: no dev-dependency needed, every mix of codecs and sizes.
    let encs = [
        Some("H264"),
        Some("H265"),
        Some("JPEG"),
        Some("MPEG4"),
        None,
    ];
    let sizes = [
        (160, 120),
        (640, 360),
        (1280, 720),
        (1920, 1080),
        (3840, 2160),
    ];
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = |n: usize| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(seed >> 33).expect("fits") % n
    };
    for _ in 0..2000 {
        let count = 1 + next(6);
        let tokens: Vec<String> = (0..count).map(|i| format!("p{i}")).collect();
        let spec: Vec<(&str, u32, u32, Option<&str>)> = tokens
            .iter()
            .map(|t| {
                let (w, h) = sizes[next(sizes.len())];
                (t.as_str(), w, h, encs[next(encs.len())])
            })
            .collect();
        let p = ps(&spec);
        assert_eq!(pick(&p), oracle(&p), "{spec:?}");
    }
}
