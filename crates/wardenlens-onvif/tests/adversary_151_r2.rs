//! Round-2 adversarial tests for PR #239 (ticket #151): per-attempt WS-Security digests, every
//! service path that validates is sendable (no connection for a request that cannot be built),
//! duplicated lengths, trimming around invisibles. Loopback-only raw fakes.
#![expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "test code: small bounded counters and readable string building"
)]

use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use secrecy::SecretString;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wardenlens_core::camera::{Credential, Host};
use wardenlens_core::connection::Backoff;
use wardenlens_core::time::DurationMs;
use wardenlens_onvif::{
    ClientConfig, MAX_BODY_BYTES, MAX_SERVICE_PATH_LEN, OnvifClient, OnvifError,
    parse_device_information,
};

const NS: &str = r#"xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl""#;

fn device_info_with(fields: [&str; 5]) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><env:Envelope {NS}><env:Body><tds:GetDeviceInformationResponse><tds:Manufacturer>{}</tds:Manufacturer><tds:Model>{}</tds:Model><tds:FirmwareVersion>{}</tds:FirmwareVersion><tds:SerialNumber>{}</tds:SerialNumber><tds:HardwareId>{}</tds:HardwareId></tds:GetDeviceInformationResponse></env:Body></env:Envelope>"#,
        fields[0], fields[1], fields[2], fields[3], fields[4]
    )
}

fn ok_reply() -> Vec<u8> {
    let body = device_info_with(["Acme", "M", "1", "S", "H"]);
    let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    raw.extend_from_slice(body.as_bytes());
    raw
}

/// Reads one full request (head and `Content-Length` body) and returns it as text.
async fn read_request(stream: &mut TcpStream) -> Option<String> {
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
                return Some(text);
            }
        }
    }
}

/// A fake that records every request; connection `i` (from 0) is closed unanswered while
/// `i < close_first`, after that it gets `reply` and is held until the client hangs up.
async fn spawn(close_first: usize, reply: Vec<u8>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut i = 0_usize;
        while let Ok((mut s, _)) = listener.accept().await {
            // Sequential on purpose: the client never has two connections open at once.
            let Some(req) = read_request(&mut s).await else {
                i += 1;
                continue;
            };
            log.lock().expect("lock").push(req);
            if i >= close_first {
                let _ = s.write_all(&reply).await;
                let mut sink = [0_u8; 64];
                while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
            }
            i += 1;
        }
    });
    (port, seen)
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

async fn bounded<T>(secs: u64, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(secs), fut)
        .await
        .expect("the client hung past its own timeouts")
}

fn between<'a>(text: &'a str, from: &str, to: &str) -> &'a str {
    let start = text.find(from).expect("start marker") + from.len();
    let rest = &text[start..];
    &rest[..rest.find(to).expect("end marker")]
}

// ---- per-attempt envelope: every retry is a self-consistent UsernameToken ----

#[tokio::test]
async fn every_retry_digest_matches_its_own_nonce_and_created() {
    // Five unanswered attempts, then an answer. A camera that caches nonces, or one that checks
    // the digest, must accept the sixth request on its own: its digest has to be computed from
    // the nonce and Created that this very request carries.
    let (port, seen) = spawn(5, ok_reply()).await;
    let password = "p&ss<wörd>";
    let cred = Credential::new("admin", SecretString::from(password));
    let r = bounded(
        60,
        client(
            port,
            Some(cred),
            cfg(Duration::from_secs(5), Duration::from_secs(5)),
        )
        .get_device_information(),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests.len(), 6);
    let mut nonces = Vec::new();
    let mut last_created = String::new();
    for req in &requests {
        let nonce_b64 = between(req, "#Base64Binary\">", "<");
        let created = between(req, "<wsu:Created>", "<");
        let sent_digest = between(req, "#PasswordDigest\">", "<");
        let nonce = STANDARD.decode(nonce_b64).expect("nonce is base64");
        assert_eq!(nonce.len(), 16, "nonce length");
        let mut h = Sha1::new();
        h.update(&nonce);
        h.update(created.as_bytes());
        h.update(password.as_bytes());
        let want = STANDARD.encode(h.finalize());
        assert_eq!(
            sent_digest, want,
            "digest does not match its own nonce/created"
        );
        // Created is fixed-width UTC, so text order is time order: never goes backwards.
        assert!(created >= last_created.as_str(), "Created went backwards");
        last_created = created.to_owned();
        nonces.push(nonce);
    }
    nonces.sort();
    nonces.dedup();
    assert_eq!(nonces.len(), 6, "a nonce repeated across attempts");
}

#[tokio::test]
async fn a_retry_without_credentials_sends_the_same_body_and_succeeds() {
    let (port, seen) = spawn(3, ok_reply()).await;
    let r = bounded(
        60,
        client(
            port,
            None,
            cfg(Duration::from_secs(5), Duration::from_secs(5)),
        )
        .get_device_information(),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests.len(), 4);
    let bodies: Vec<&str> = requests
        .iter()
        .map(|r| &r[r.find("\r\n\r\n").expect("head end")..])
        .collect();
    assert!(bodies.iter().all(|b| *b == bodies[0]));
    assert!(!bodies[0].contains("Security"));
}

// ---- no connection for a request hyper cannot build: every valid service path is sendable ----

/// The bytes `ServicePath` admits besides ASCII alphanumerics (crate source, client.rs).
const PATH_PUNCT: &[u8] = b"/-._~:!$&'()*+,;=";

#[tokio::test]
async fn every_service_path_the_client_accepts_can_actually_be_sent() {
    // If a path passes `with_device_path` but `http` refuses it as a URI, the client connects
    // first and then reports InvalidServicePath: a connection for a request that cannot be sent.
    let mut paths: Vec<String> = Vec::new();
    for &b in PATH_PUNCT {
        let c = char::from(b);
        paths.push(format!("/{c}"));
        paths.push(format!("/a{c}b"));
        paths.push(format!("/a/{c}{c}/b{c}"));
    }
    paths.push(format!("/{}", "a".repeat(MAX_SERVICE_PATH_LEN - 1)));
    paths.push(format!(
        "/{}",
        ":=;/".repeat((MAX_SERVICE_PATH_LEN - 1) / 4)
    ));
    paths.push("/onvif/device_service:8080".to_owned());
    paths.push("/:".to_owned());
    paths.push("/a//b".to_owned());
    let mut sent = 0_usize;
    let mut refused: Vec<String> = Vec::new();
    for path in paths {
        let Ok(c) = client(
            1, // only the path validation runs
            None,
            cfg(Duration::from_secs(5), Duration::from_secs(5)),
        )
        .with_device_path(&path) else {
            refused.push(path);
            continue; // refused up front: nothing to prove
        };
        drop(c);
        let (port, seen) = spawn(0, ok_reply()).await;
        let r = bounded(
            20,
            client(
                port,
                None,
                cfg(Duration::from_secs(5), Duration::from_secs(5)),
            )
            .with_device_path(&path)
            .expect("validated above")
            .get_device_information(),
        )
        .await;
        assert!(
            r.is_ok(),
            "path {path:?} validated but was not sendable: {r:?}"
        );
        let requests = seen.lock().expect("lock").clone();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with(&format!("POST {path} HTTP/1.1\r\n")),
            "path altered on the wire: {path:?} -> {:?}",
            requests[0].lines().next()
        );
        sent += 1;
    }
    // Refused up front, by design: the "//" prefix and the "." / ".." segments.
    assert_eq!(
        refused,
        ["//", "/.", "/a/../b."],
        "an ordinary path was refused up front ({sent} sent)"
    );
}

// ---- Content-Length: duplicated and non-200 forms ----

/// A fake that writes `head` after the request and holds the connection.
async fn spawn_head(head: &'static [u8]) -> (u16, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let count = Arc::new(Mutex::new(0_usize));
    let c = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            *c.lock().expect("lock") += 1;
            tokio::spawn(async move {
                if read_request(&mut s).await.is_none() {
                    return;
                }
                let _ = s.write_all(head).await;
                let mut sink = [0_u8; 64];
                while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
            });
        }
    });
    (port, count)
}

#[tokio::test]
async fn a_repeated_identical_content_length_over_the_cap_is_refused_at_once() {
    let (port, count) = spawn_head(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\nContent-Length: 2000000\r\n\r\n",
    )
    .await;
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(20, client(port, None, c).get_device_information()).await;
    assert_eq!(r.err(), Some(OnvifError::BodyTooLarge));
    assert_eq!(*count.lock().expect("lock"), 1, "a final error was retried");
}

#[tokio::test]
async fn a_comma_list_content_length_over_the_cap_is_not_waited_for() {
    // `2000000, 2000000` is a legal folded duplicate for hyper; either refusal is fine, a wait for
    // the 120 s body timeout is not.
    let (port, _) =
        spawn_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2000000, 2000000\r\n\r\n").await;
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(30, client(port, None, c).get_device_information()).await;
    assert!(
        matches!(
            r.as_ref().err(),
            Some(OnvifError::BodyTooLarge | OnvifError::Unreachable { .. })
        ),
        "{r:?}"
    );
}

#[tokio::test]
async fn a_server_error_with_a_length_over_the_cap_is_refused_without_waiting() {
    let (port, _) = spawn_head(b"HTTP/1.1 500 Internal\r\nContent-Length: 1048577\r\n\r\n").await;
    let c = cfg(Duration::from_secs(120), Duration::from_secs(120));
    let r = bounded(20, client(port, None, c).get_device_information()).await;
    assert!(
        matches!(
            r.as_ref().err(),
            Some(OnvifError::BodyTooLarge | OnvifError::HttpStatus { .. })
        ),
        "{r:?}"
    );
}

#[tokio::test]
async fn content_length_one_under_the_cap_with_a_full_body_is_read() {
    // A body of exactly MAX_BODY_BYTES that is a valid reply (padded with a comment).
    let base = device_info_with(["Acme", "M", "1", "S", "H"]);
    let pad = MAX_BODY_BYTES - base.len() - "<!---->".len();
    let body = format!("{base}<!--{}-->", "x".repeat(pad));
    assert_eq!(body.len(), MAX_BODY_BYTES);
    let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    raw.extend_from_slice(body.as_bytes());
    let (port, _) = spawn(0, raw).await;
    let c = cfg(Duration::from_secs(10), Duration::from_secs(10));
    let r = bounded(30, client(port, None, c).get_device_information()).await;
    assert!(r.is_ok(), "{r:?}");
}

// ---- trimming and the invisible check ----

/// Every code point that is a control or core-invisible.
fn bad_chars() -> Vec<char> {
    (0_u32..=0x10_FFFF)
        .filter_map(char::from_u32)
        .filter(|c| c.is_control() || wardenlens_core::text::is_invisible(*c))
        .collect()
}

#[test]
fn no_accepted_device_field_ever_contains_a_control_or_invisible_character() {
    // Whatever trimming does at the edges, the value handed out must be clean. Placements cover
    // the edge (trimmed when white space), behind white space, and inside.
    for c in bad_chars() {
        if !wardenlens_core::text::is_invisible(c) && !c.is_control() {
            continue;
        }
        // XML 1.0 cannot carry most C0 controls: skip those the parser refuses as malformed.
        for placed in [
            format!("{c}Acme"),
            format!("Acme{c}"),
            format!(" {c} Acme"),
            format!("Acme \u{2028}{c}"),
            format!("Ac{c}me"),
            format!("\u{2029}{c}\u{2029}"),
        ] {
            let xml = device_info_with([&placed, "M", "1", "S", "H"]);
            if let Ok(info) = parse_device_information(xml.as_bytes()) {
                assert!(
                    !info
                        .manufacturer
                        .chars()
                        .any(|x| x.is_control() || wardenlens_core::text::is_invisible(x)),
                    "U+{:04X} in {placed:?} came out as {:?}",
                    u32::from(c),
                    info.manufacturer
                );
            }
        }
    }
}

#[test]
fn a_separator_at_a_field_edge_is_trimmed_away_and_one_inside_is_refused() {
    for sep in ['\u{2028}', '\u{2029}', '\u{85}'] {
        let edge = device_info_with([&format!("{sep}Acme{sep}"), "M", "1", "S", "H"]);
        let info = parse_device_information(edge.as_bytes()).expect("edge separators trim");
        assert_eq!(info.manufacturer, "Acme");
        let inside = device_info_with([&format!("Ac{sep}me"), "M", "1", "S", "H"]);
        assert_eq!(
            parse_device_information(inside.as_bytes()).err(),
            Some(OnvifError::InvalidField {
                field: "Manufacturer"
            })
        );
    }
}

#[test]
fn a_separator_given_as_a_character_reference_inside_a_field_is_refused() {
    for r in ["&#x2028;", "&#8233;", "&#x202E;", "&#x85;", "&#xFEFF;"] {
        let xml = device_info_with([&format!("Ac{r}me"), "M", "1", "S", "H"]);
        assert!(
            parse_device_information(xml.as_bytes()).is_err(),
            "{r} inside a field was accepted"
        );
    }
}

#[test]
fn a_bidi_override_split_across_cdata_and_text_is_refused() {
    let xml = device_info_with(["Ac<![CDATA[\u{202E}]]>me", "M", "1", "S", "H"]);
    assert!(parse_device_information(xml.as_bytes()).is_err());
}
