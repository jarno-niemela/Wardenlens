//! The client against a loopback fake camera: auth on the wire, the retry contract, the body
//! cap on the socket, and every way the exchange can end.

use std::num::NonZeroU16;
use std::time::Duration;

use base64::Engine as _;
use secrecy::SecretString;
use sha1::{Digest, Sha1};
use wardenlens_core::camera::{Credential, Host};
use wardenlens_core::connection::{Backoff, JitterSource};
use wardenlens_core::time::DurationMs;

use super::fixtures::*;
use super::server::{Fake, Reply, ok, spawn};
use crate::transport::retry_delay;
use crate::{ClientConfig, MAX_ATTEMPTS, MAX_BODY_BYTES, OnvifClient, OnvifError, ProfileToken};

pub(crate) const PASSWORD: &str = "PW-SENTINEL-0451";
pub(crate) const USER: &str = "USER-SENTINEL";

pub(crate) fn fast() -> ClientConfig {
    ClientConfig {
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
        body_timeout: Duration::from_secs(5),
        backoff: Backoff::new(DurationMs::from_millis(1), DurationMs::from_millis(1)),
    }
}

pub(crate) fn cred() -> Credential {
    Credential::new(USER, SecretString::from(PASSWORD))
}

pub(crate) fn client(fake: &Fake, cred: Option<Credential>, cfg: ClientConfig) -> OnvifClient {
    OnvifClient::new(
        Host::new("127.0.0.1").expect("host"),
        NonZeroU16::new(fake.port()).expect("port"),
        cred,
    )
    .with_config(cfg)
}

fn between(text: &str, open: &str, close: &str) -> String {
    let from = text.find(open).map(|i| i + open.len()).expect(open);
    let rest = &text[from..];
    rest[..rest.find(close).expect(close)].to_owned()
}

#[tokio::test]
async fn device_information_with_a_verifiable_digest() {
    let fake = spawn(0, ok(&good_device_info())).await;
    let info = client(&fake, Some(cred()), fast())
        .get_device_information()
        .await
        .expect("info");
    assert_eq!(info.model, "Cam-1");

    let req = fake.last_request();
    assert!(
        req.starts_with("POST /onvif/device_service HTTP/1.1\r\n"),
        "{req}"
    );
    assert!(
        req.contains(&format!("host: 127.0.0.1:{}\r\n", fake.port()))
            || req.contains(&format!("Host: 127.0.0.1:{}\r\n", fake.port()))
    );
    assert!(req.contains("/ver10/device/wsdl/GetDeviceInformation\""));
    assert!(req.contains("GetDeviceInformation xmlns"));
    // The server recomputes the digest from the request's own nonce and created, independently.
    let user = between(&req, "<wsse:Username>", "</wsse:Username>");
    let digest = between(&req, "#PasswordDigest\">", "</wsse:Password>");
    let nonce_b64 = between(&req, "#Base64Binary\">", "</wsse:Nonce>");
    let created = between(&req, "<wsu:Created>", "</wsu:Created>");
    assert_eq!(user, USER);
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(&nonce_b64)
        .expect("b64");
    assert_eq!(nonce.len(), 16);
    let mut h = Sha1::new();
    h.update(&nonce);
    h.update(created.as_bytes());
    h.update(PASSWORD.as_bytes());
    assert_eq!(
        digest,
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    );
    assert_eq!(created.len(), 20);
    assert!(created.starts_with("20") && created.ends_with('Z'));
    // The password itself is nowhere on the wire.
    assert!(!req.contains(PASSWORD));
}

#[tokio::test]
async fn two_calls_use_two_nonces() {
    let fake = spawn(0, ok(&good_device_info())).await;
    let c = client(&fake, Some(cred()), fast());
    c.get_device_information().await.expect("1");
    let first = between(&fake.last_request(), "#Base64Binary\">", "</wsse:Nonce>");
    c.get_device_information().await.expect("2");
    let second = between(&fake.last_request(), "#Base64Binary\">", "</wsse:Nonce>");
    assert_ne!(first, second);
}

#[tokio::test]
async fn anonymous_calls_send_no_security_header() {
    let fake = spawn(0, ok(&good_device_info())).await;
    client(&fake, None, fast())
        .get_device_information()
        .await
        .expect("info");
    assert!(!fake.last_request().contains("Security"));
}

#[tokio::test]
async fn profiles_use_the_media_path_and_stream_uri_sends_the_token() {
    let fake = spawn(0, ok(&good_profiles())).await;
    let c = client(&fake, Some(cred()), fast())
        .with_media_path("/onvif/media_service")
        .expect("path");
    let profiles = c.get_profiles().await.expect("profiles");
    assert_eq!(profiles.len(), 2);
    assert!(
        fake.last_request()
            .starts_with("POST /onvif/media_service HTTP/1.1")
    );
    assert!(fake.last_request().contains("GetProfiles xmlns"));

    let fake = spawn(
        0,
        ok(&stream_uri(
            "rtsp://admin:USERINFO-SENTINEL@198.51.100.7:8554/stream1",
        )),
    )
    .await;
    let c = client(&fake, Some(cred()), fast());
    let token = ProfileToken::new("main_tok").expect("token");
    let ep = c.get_stream_uri(&token).await.expect("uri");
    assert_eq!((ep.path.as_str(), ep.port.get()), ("/stream1", 8554));
    let req = fake.last_request();
    assert!(req.starts_with("POST /onvif/device_service HTTP/1.1"));
    assert!(req.contains("<trt:ProfileToken>main_tok</trt:ProfileToken>"));
    assert!(req.contains("<tt:Protocol>RTSP</tt:Protocol>"));
    assert!(req.contains("/ver10/media/wsdl/GetStreamUri\""));
    // The client connected only to the configured host: one connection, to the fake.
    assert_eq!(fake.accepted(), 1);
    assert!(!format!("{ep:?}").contains("SENTINEL"));
}

#[tokio::test]
async fn retries_until_the_first_n_dropped_connections_are_past() {
    for dropped in 0..usize::from(MAX_ATTEMPTS) {
        let fake = spawn(dropped, ok(&good_device_info())).await;
        let info = client(&fake, Some(cred()), fast())
            .get_device_information()
            .await;
        assert!(info.is_ok(), "dropped {dropped}: {info:?}");
        assert_eq!(fake.accepted(), dropped + 1, "dropped {dropped}");
    }
}

#[tokio::test]
async fn gives_up_after_six_attempts_with_unreachable() {
    assert_eq!(MAX_ATTEMPTS, 6);
    for dropped in [6, 7, 1000] {
        let fake = spawn(dropped, ok(&good_device_info())).await;
        let r = client(&fake, Some(cred()), fast())
            .get_device_information()
            .await;
        assert_eq!(r.err(), Some(OnvifError::Unreachable { attempts: 6 }));
        assert_eq!(
            fake.accepted(),
            6,
            "exactly six attempts, dropped {dropped}"
        );
    }
}

#[tokio::test]
async fn a_silent_camera_is_retried_per_attempt_then_unreachable() {
    let fake = spawn(0, Reply::Silent).await;
    let cfg = ClientConfig {
        request_timeout: Duration::from_millis(40),
        ..fast()
    };
    let r = client(&fake, Some(cred()), cfg)
        .get_device_information()
        .await;
    assert_eq!(r.err(), Some(OnvifError::Unreachable { attempts: 6 }));
    assert_eq!(fake.accepted(), 6);
}

#[tokio::test(start_paused = true)]
async fn waits_between_attempts_with_the_configured_backoff() {
    // Virtual time: the five waits of 10 s each pass instantly but are counted.
    let fake = spawn(1000, ok("")).await;
    let cfg = ClientConfig {
        backoff: Backoff::new(DurationMs::from_secs(10), DurationMs::from_secs(10)),
        ..fast()
    };
    let start = tokio::time::Instant::now();
    let r = client(&fake, None, cfg).get_device_information().await;
    assert_eq!(r.err(), Some(OnvifError::Unreachable { attempts: 6 }));
    assert!(
        start.elapsed() >= Duration::from_secs(50),
        "{:?}",
        start.elapsed()
    );
}

struct Fixed(u64);
impl JitterSource for Fixed {
    fn next_u64(&mut self) -> u64 {
        self.0
    }
}

#[test]
fn retry_delay_is_the_core_backoff_by_retry_number() {
    let b = Backoff::DEFAULT;
    for attempt in 1..MAX_ATTEMPTS {
        for jitter in [0, 123, u64::MAX] {
            let want = b
                .delay(u32::from(attempt) - 1, &mut Fixed(jitter))
                .as_millis();
            assert_eq!(
                retry_delay(&b, attempt, &mut Fixed(jitter)).as_millis(),
                u128::from(want)
            );
        }
    }
    // Within 2 s .. 5 s for the default contract, and growing at the start.
    assert_eq!(
        retry_delay(&b, 1, &mut Fixed(0)),
        Duration::from_millis(2000)
    );
    assert_eq!(
        retry_delay(&b, 2, &mut Fixed(0)),
        Duration::from_millis(3000)
    );
    assert!(retry_delay(&b, 5, &mut Fixed(u64::MAX)) <= Duration::from_secs(5));
}

#[test]
fn defaults_match_the_ticket() {
    let c = ClientConfig::default();
    assert_eq!(c.connect_timeout, Duration::from_secs(3));
    assert_eq!(c.backoff, Backoff::DEFAULT);
}

#[tokio::test]
async fn body_cap_on_the_socket() {
    let big = |n: usize| {
        let mut b = good_device_info().into_bytes();
        b.resize(n, b' ');
        Reply::Http {
            status: 200,
            body: b,
        }
    };
    for (len, want_ok) in [
        (MAX_BODY_BYTES - 1, true),
        (MAX_BODY_BYTES, true),
        (MAX_BODY_BYTES + 1, false),
    ] {
        let fake = spawn(0, big(len)).await;
        let r = client(&fake, None, fast()).get_device_information().await;
        if want_ok {
            assert!(r.is_ok(), "{len}: {r:?}");
        } else {
            assert_eq!(r.err(), Some(OnvifError::BodyTooLarge), "{len}");
        }
    }
    // A body with no length that never ends: the read stops at the cap and the call ends.
    let fake = spawn(0, Reply::Endless).await;
    let r = client(&fake, None, fast()).get_device_information().await;
    assert_eq!(r.err(), Some(OnvifError::BodyTooLarge));
    assert_eq!(fake.accepted(), 1);
}

#[tokio::test]
async fn failures_after_the_head_are_final_not_retried() {
    let fake = spawn(
        0,
        Reply::Truncated {
            promised: 500,
            sent: 10,
        },
    )
    .await;
    let r = client(&fake, None, fast()).get_device_information().await;
    assert_eq!(r.err(), Some(OnvifError::Transport));
    assert_eq!(fake.accepted(), 1);

    // The head arrives at once and the body stalls: only the body timeout is short, so a slow
    // CI machine cannot turn the head wait into a retry.
    let fake = spawn(0, Reply::StalledBody).await;
    let cfg = ClientConfig {
        body_timeout: Duration::from_millis(40),
        ..fast()
    };
    let r = client(&fake, None, cfg).get_device_information().await;
    assert_eq!(r.err(), Some(OnvifError::Timeout));
    assert_eq!(fake.accepted(), 1);
}

#[tokio::test]
async fn http_and_soap_outcomes() {
    let http = |status: u16, body: String| Reply::Http {
        status,
        body: body.into_bytes(),
    };
    let rows: Vec<(&str, Reply, OnvifError)> = vec![
        ("401", http(401, String::new()), OnvifError::Unauthorized),
        (
            "401 with fault body",
            http(401, fault("ter:NotAuthorized", "x")),
            OnvifError::Unauthorized,
        ),
        (
            "400 not authorized",
            http(400, fault("ter:NotAuthorized", "x")),
            OnvifError::NotAuthorized,
        ),
        (
            "500 fault",
            http(500, fault("ter:Action", "x")),
            OnvifError::SoapFault,
        ),
        (
            "200 fault",
            http(200, fault("ter:Action", "x")),
            OnvifError::SoapFault,
        ),
        (
            "503 junk",
            http(503, "<html>busy</html>".to_owned()),
            OnvifError::HttpStatus { status: 503 },
        ),
        (
            "503 empty",
            http(503, String::new()),
            OnvifError::HttpStatus { status: 503 },
        ),
        (
            "302",
            http(302, String::new()),
            OnvifError::HttpStatus { status: 302 },
        ),
        (
            "404 well-formed response body",
            http(404, good_device_info()),
            OnvifError::HttpStatus { status: 404 },
        ),
        (
            "200 empty",
            http(200, String::new()),
            OnvifError::EmptyReply,
        ),
        (
            "200 malformed",
            http(200, "<a>".to_owned()),
            OnvifError::Malformed { position: 3 },
        ),
        (
            "200 doctype",
            http(200, "<!DOCTYPE a><a/>".to_owned()),
            OnvifError::DocType,
        ),
    ];
    for (label, reply, want) in rows {
        let fake = spawn(0, reply).await;
        let r = client(&fake, Some(cred()), fast())
            .get_device_information()
            .await;
        match (r.err(), want) {
            (Some(OnvifError::Malformed { .. }), OnvifError::Malformed { .. }) => {}
            (got, want) => assert_eq!(got, Some(want), "{label}"),
        }
        assert_eq!(fake.accepted(), 1, "{label}: no retry once a head arrived");
    }
}

#[tokio::test]
async fn requests_that_cannot_be_built_never_touch_the_network() {
    let fake = spawn(0, ok(&good_device_info())).await;
    let bad_user = Credential::new("a\u{1}b", SecretString::from("pw"));
    let r = client(&fake, Some(bad_user), fast())
        .get_device_information()
        .await;
    assert_eq!(r.err(), Some(OnvifError::UserNotXmlSafe));
    assert_eq!(fake.accepted(), 0);
}

#[test]
fn service_path_table() {
    let base = OnvifClient::new(
        Host::new("192.0.2.1").expect("h"),
        NonZeroU16::new(80).expect("p"),
        None,
    );
    let long = format!("/{}", "a".repeat(256));
    let exact = format!("/{}", "a".repeat(255));
    let rows: [(&str, bool); 14] = [
        ("/onvif/device_service", true),
        ("/", true),
        ("/onvif/service", true),
        (&exact, true),
        (&long, false),
        ("", false),
        ("onvif", false),
        ("//x", false),
        ("/a?b", false),
        ("/a#b", false),
        ("/a b", false),
        ("/a%20b", false),
        ("/../x", false),
        ("/a\u{e9}", false),
    ];
    for (path, valid) in rows {
        assert_eq!(
            base.clone().with_device_path(path).is_ok(),
            valid,
            "{path:?}"
        );
        assert_eq!(
            base.clone().with_media_path(path).is_ok(),
            valid,
            "{path:?}"
        );
        if !valid {
            assert_eq!(
                base.clone().with_device_path(path).err(),
                Some(OnvifError::InvalidServicePath)
            );
        }
    }
}

#[test]
fn futures_are_send() {
    fn is_send<T: Send>(_: &T) {}
    let c = OnvifClient::new(
        Host::new("192.0.2.1").expect("h"),
        NonZeroU16::new(80).expect("p"),
        None,
    );
    is_send(&c.get_device_information());
    is_send(&c.get_profiles());
    is_send(&c.get_stream_uri(&ProfileToken::new("a").expect("t")));
}

/// The transport's own cap, below the parser's: `post` itself refuses one byte over, so the read
/// (not only the later parse) is what is bounded.
#[tokio::test]
async fn the_transport_caps_the_read_itself() {
    use crate::transport::{Request1, post};
    let host = Host::new("127.0.0.1").expect("host");
    for (len, want_ok) in [(MAX_BODY_BYTES, true), (MAX_BODY_BYTES + 1, false)] {
        let fake = spawn(
            0,
            Reply::Http {
                status: 200,
                body: vec![b' '; len],
            },
        )
        .await;
        let req = Request1 {
            host: &host,
            port: fake.port(),
            path: "/x",
            action: "a",
            body: &|| Ok(bytes::Bytes::new()),
        };
        let r = post(&req, &fast()).await;
        if want_ok {
            assert_eq!(r.map(|(s, b)| (s, b.len())), Ok((200, len)));
        } else {
            assert_eq!(r.err(), Some(OnvifError::BodyTooLarge));
        }
    }
}

/// The `Nonce` and `Created` values of a recorded request.
fn nonce_and_created(request: &str) -> (String, String) {
    let between = |from: &str, to: &str| {
        let start = request.find(from).map_or(0, |i| i + from.len());
        request[start..]
            .split(to)
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    (
        between("#Base64Binary\">", "<"),
        between("<wsu:Created>", "<"),
    )
}

#[tokio::test]
async fn every_attempt_carries_its_own_nonce() {
    // A camera that caches nonces would refuse a retry that repeats one. The camera closes
    // without answering, so all six attempts are made.
    let fake = spawn(0, Reply::Close).await;
    let r = client(&fake, Some(cred()), fast())
        .get_device_information()
        .await;
    assert_eq!(r.err(), Some(OnvifError::Unreachable { attempts: 6 }));
    let requests = fake.requests.lock().expect("lock").clone();
    assert_eq!(requests.len(), 6);
    let mut nonces: Vec<String> = requests.iter().map(|r| nonce_and_created(r).0).collect();
    assert!(nonces.iter().all(|n| !n.is_empty()));
    nonces.sort();
    nonces.dedup();
    assert_eq!(nonces.len(), 6, "a nonce was reused across attempts");
}
