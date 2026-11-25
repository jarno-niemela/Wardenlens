//! No error path, `Debug` or `Display`, shows the password, the user name, the digest, the nonce,
//! the host or any reply text (SEC-6). Every variant a call can return is driven over the wire.

use std::collections::BTreeSet;
use std::time::Duration;

use super::client::{PASSWORD, USER, client, cred, fast};
use super::fixtures::*;
use super::server::{Fake, Reply, ok, spawn};
use crate::{ClientConfig, MAX_BODY_BYTES, OnvifError, ProfileToken};

const RESP: &str = "RESP-SENTINEL";

/// Exhaustive on purpose: adding a variant breaks this until the tests below name it.
fn label(e: &OnvifError) -> &'static str {
    match e {
        OnvifError::EmptyReply => "EmptyReply",
        OnvifError::BodyTooLarge => "BodyTooLarge",
        OnvifError::NotUtf8 => "NotUtf8",
        OnvifError::UnsupportedEncoding => "UnsupportedEncoding",
        OnvifError::DocType => "DocType",
        OnvifError::Malformed { .. } => "Malformed",
        OnvifError::TooDeep => "TooDeep",
        OnvifError::TooManyElements => "TooManyElements",
        OnvifError::SoapFault => "SoapFault",
        OnvifError::NotAuthorized => "NotAuthorized",
        OnvifError::MissingElement { .. } => "MissingElement",
        OnvifError::InvalidField { .. } => "InvalidField",
        OnvifError::TooManyProfiles => "TooManyProfiles",
        OnvifError::StreamUriScheme => "StreamUriScheme",
        OnvifError::StreamUriAuthority => "StreamUriAuthority",
        OnvifError::StreamUriPort => "StreamUriPort",
        OnvifError::StreamUriPath(_) => "StreamUriPath",
        OnvifError::UserNotXmlSafe => "UserNotXmlSafe",
        OnvifError::InvalidServicePath => "InvalidServicePath",
        OnvifError::InvalidToken => "InvalidToken",
        OnvifError::Random => "Random",
        OnvifError::Clock => "Clock",
        OnvifError::Unreachable { .. } => "Unreachable",
        OnvifError::Unauthorized => "Unauthorized",
        OnvifError::HttpStatus { .. } => "HttpStatus",
        OnvifError::Transport => "Transport",
        OnvifError::Timeout => "Timeout",
    }
}

/// Variants that cannot be provoked from a test: the operating system's RNG or clock failing.
const UNDRIVABLE: [&str; 2] = ["Random", "Clock"];
const ALL: [&str; 27] = [
    "EmptyReply",
    "BodyTooLarge",
    "NotUtf8",
    "UnsupportedEncoding",
    "DocType",
    "Malformed",
    "TooDeep",
    "TooManyElements",
    "SoapFault",
    "NotAuthorized",
    "MissingElement",
    "InvalidField",
    "TooManyProfiles",
    "StreamUriScheme",
    "StreamUriAuthority",
    "StreamUriPort",
    "StreamUriPath",
    "UserNotXmlSafe",
    "InvalidServicePath",
    "InvalidToken",
    "Random",
    "Clock",
    "Unreachable",
    "Unauthorized",
    "HttpStatus",
    "Transport",
    "Timeout",
];

fn check(seen: &mut BTreeSet<&'static str>, fake: Option<&Fake>, e: &OnvifError, what: &str) {
    seen.insert(label(e));
    let mut forbidden: Vec<String> = vec![
        PASSWORD.into(),
        USER.into(),
        RESP.into(),
        "127.0.0.1".into(),
        "USERINFO-SENTINEL".into(),
    ];
    if let Some(f) = fake {
        let req = f.last_request();
        for (open, close) in [
            ("#PasswordDigest\">", "</wsse:Password>"),
            ("#Base64Binary\">", "</wsse:Nonce>"),
            ("<wsu:Created>", "</wsu:Created>"),
        ] {
            if let Some(i) = req.find(open) {
                let rest = &req[i + open.len()..];
                if let Some(j) = rest.find(close) {
                    forbidden.push(rest[..j].to_owned());
                }
            }
        }
    }
    for text in [format!("{e}"), format!("{e:?}")] {
        for bad in &forbidden {
            assert!(
                !text.contains(bad.as_str()),
                "{what}: {text:?} contains {bad:?}"
            );
        }
    }
}

fn http(status: u16, body: &str) -> Reply {
    Reply::Http {
        status,
        body: body.as_bytes().to_vec(),
    }
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "a data table of cases")]
async fn every_error_variant_is_provoked_and_leaks_nothing() {
    let mut seen = BTreeSet::new();
    let deep = env(&format!(
        "<x>{}{RESP}{}</x>",
        "<x>".repeat(70),
        "</x>".repeat(70)
    ));
    let many = env(&format!("<x>{}</x>", format!("<y>{RESP}</y>").repeat(4100)));
    let too_long = device_info(&format!("{RESP}{}", "m".repeat(300)), "m", "m", "m", "m");
    let mut latin = good_device_info().into_bytes();
    latin.extend_from_slice(RESP.as_bytes());
    latin.push(0xFF);
    let big = {
        let mut b = good_device_info().into_bytes();
        b.extend_from_slice(RESP.as_bytes());
        b.resize(MAX_BODY_BYTES + 1, b' ');
        b
    };

    // Calls to `get_device_information`.
    let device_rows: Vec<(&str, Reply)> = vec![
        ("empty", http(200, "")),
        ("fault", http(500, &fault("ter:Boom", RESP))),
        (
            "not authorized",
            http(400, &fault("ter:NotAuthorized", RESP)),
        ),
        ("malformed", http(200, &format!("<a>{RESP}"))),
        (
            "doctype",
            http(
                200,
                &format!("<!DOCTYPE a [<!ENTITY x \"{RESP}\">]><a>&x;</a>"),
            ),
        ),
        (
            "encoding",
            http(
                200,
                &format!("<?xml version=\"1.0\" encoding=\"UTF-16\"?><a>{RESP}</a>"),
            ),
        ),
        (
            "not utf8",
            Reply::Http {
                status: 200,
                body: latin,
            },
        ),
        ("too deep", http(200, &deep)),
        ("too many", http(200, &many)),
        (
            "missing",
            http(200, &env(&format!("<tds:Other>{RESP}</tds:Other>"))),
        ),
        ("invalid field", http(200, &too_long)),
        ("401", http(401, RESP)),
        ("503", http(503, RESP)),
        (
            "too large",
            Reply::Http {
                status: 200,
                body: big,
            },
        ),
        (
            "transport",
            Reply::Truncated {
                promised: 100,
                sent: 5,
            },
        ),
    ];
    for (what, reply) in device_rows {
        let fake = spawn(0, reply).await;
        let e = client(&fake, Some(cred()), fast())
            .get_device_information()
            .await
            .expect_err(what);
        check(&mut seen, Some(&fake), &e, what);
    }

    // Unreachable and timeout.
    let fake = spawn(100, ok(&good_device_info())).await;
    let e = client(&fake, Some(cred()), fast())
        .get_device_information()
        .await
        .expect_err("unreachable");
    check(&mut seen, Some(&fake), &e, "unreachable");
    let fake = spawn(0, Reply::StalledBody).await;
    let cfg = ClientConfig {
        request_timeout: Duration::from_millis(40),
        ..fast()
    };
    let e = client(&fake, Some(cred()), cfg)
        .get_device_information()
        .await
        .expect_err("timeout");
    check(&mut seen, Some(&fake), &e, "timeout");

    // Profiles.
    let many_profiles = profiles(
        &(0..33)
            .map(|i| profile(&format!("p{i}"), RESP, "10", "10", "H264"))
            .collect::<Vec<_>>(),
    );
    let fake = spawn(0, http(200, &many_profiles)).await;
    let e = client(&fake, Some(cred()), fast())
        .get_profiles()
        .await
        .expect_err("profiles");
    check(&mut seen, Some(&fake), &e, "too many profiles");

    // Stream URI.
    let token = ProfileToken::new("t").expect("token");
    let uri_rows = [
        "http://RESP-SENTINEL/p",
        "rtsp://USERINFO-SENTINEL@/p",
        "rtsp://USERINFO-SENTINEL@h:99999/p",
        "rtsp://USERINFO-SENTINEL@h/p?password=RESP-SENTINEL",
    ];
    for uri in uri_rows {
        let fake = spawn(0, http(200, &stream_uri(uri))).await;
        let e = client(&fake, Some(cred()), fast())
            .get_stream_uri(&token)
            .await
            .expect_err(uri);
        check(&mut seen, Some(&fake), &e, uri);
    }

    // Request-side errors, no network.
    let fake = spawn(0, ok("")).await;
    let bad_user = wardenlens_core::camera::Credential::new(
        format!("{USER}\u{1}"),
        secrecy::SecretString::from(PASSWORD),
    );
    let e = client(&fake, Some(bad_user), fast())
        .get_device_information()
        .await
        .expect_err("user");
    check(&mut seen, None, &e, "user not xml safe");
    let e = client(&fake, None, fast())
        .with_device_path(&format!("/{RESP} ?"))
        .expect_err("path");
    check(&mut seen, None, &e, "service path");
    let e = ProfileToken::new(&format!("{RESP} {PASSWORD}")).expect_err("token");
    check(&mut seen, None, &e, "token");

    let want: BTreeSet<&str> = ALL
        .iter()
        .copied()
        .filter(|l| !UNDRIVABLE.contains(l))
        .collect();
    let missing: Vec<_> = want
        .difference(&seen.iter().copied().collect())
        .copied()
        .collect();
    assert!(missing.is_empty(), "variants never provoked: {missing:?}");
    assert_eq!(ALL.len(), 27);
}

#[tokio::test]
async fn debug_of_the_client_and_config_leaks_nothing() {
    let fake = spawn(0, ok("")).await;
    let c = client(&fake, Some(cred()), fast());
    let shown = format!("{c:?} {:?}", ClientConfig::default());
    for bad in [PASSWORD, USER, "127.0.0.1"] {
        assert!(!shown.contains(bad), "{shown}");
    }
}

#[tokio::test]
async fn a_successful_call_leaves_the_password_only_in_the_digest() {
    let fake = spawn(0, ok(&good_device_info())).await;
    let info = client(&fake, Some(cred()), fast())
        .get_device_information()
        .await
        .expect("info");
    assert!(!format!("{info:?}").contains(PASSWORD));
    assert!(!fake.last_request().contains(PASSWORD));
}
