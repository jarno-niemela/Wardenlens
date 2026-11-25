//! Invariant 2 and 3: the source URL split and the skips, one row per input form (TEST-9).
//!
//! Enumeration of the surface, by URL part:
//! scheme (rtsp in any case, other schemes, none, local device names, one slash);
//! userinfo (none, user only, password only, both, both empty, `@` / `:` / `%40` / `%3A` / `/` /
//! `?` / `#` / `%` forms, non-ASCII, control characters, invalid UTF-8);
//! host (IPv4, bracketed IPv6, bare IPv6, name, upper case, empty, over-long, percent-encoded,
//! non-ASCII, mapped IPv6, all-digit last label);
//! port (absent, empty, default, explicit, 0, 65535, 65536, huge, signed, text);
//! path and query (absent, `/`, query only, plain, Dahua query, credential forms, `%`, `#`, dot
//! segments, `//`, over 512 bytes);
//! whole-string forms (empty, blank, surrounding white space, inner control characters).

use crate::SkipReason as S;

use super::fixtures::{cred, one};

enum Want {
    Ok {
        host: String,
        port: u16,
        path: String,
        cred: Option<(String, String)>,
    },
    Skip(S),
}

fn ok(host: &str, port: u16, path: &str, cred: Option<(&str, &str)>) -> Want {
    Want::Ok {
        host: host.to_owned(),
        port,
        path: path.to_owned(),
        cred: cred.map(|(u, p)| (u.to_owned(), p.to_owned())),
    }
}

#[expect(clippy::too_many_lines, reason = "a data table of cases")]
fn rows() -> Vec<(String, Want)> {
    let long_path = format!("rtsp://192.0.2.10/{}", "a".repeat(600));
    let long_host = format!("rtsp://{}/s", "a".repeat(260));
    let ok_path_512 = format!("rtsp://192.0.2.10/{}", "a".repeat(511));
    let mut v: Vec<(String, Want)> = vec![
        // host forms
        (
            "rtsp://192.0.2.10/stream1".into(),
            ok("192.0.2.10", 554, "/stream1", None),
        ),
        (
            "rtsp://[2001:db8::1]/s".into(),
            ok("2001:db8::1", 554, "/s", None),
        ),
        (
            "rtsp://[2001:db8::1]:8554/s".into(),
            ok("2001:db8::1", 8554, "/s", None),
        ),
        (
            "rtsp://[2001:DB8:0:0:0:0:0:1]/s".into(),
            ok("2001:db8::1", 554, "/s", None),
        ),
        (
            "rtsp://cam.example/s".into(),
            ok("cam.example", 554, "/s", None),
        ),
        (
            "rtsp://CAM.Example:8554/s".into(),
            ok("cam.example", 8554, "/s", None),
        ),
        ("rtsp://cam_1/s".into(), ok("cam_1", 554, "/s", None)),
        // scheme case
        (
            "RTSP://192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", None),
        ),
        (
            "RtSp://192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", None),
        ),
        // ports
        (
            "rtsp://192.0.2.10:554/s".into(),
            ok("192.0.2.10", 554, "/s", None),
        ),
        (
            "rtsp://192.0.2.10:8554/s".into(),
            ok("192.0.2.10", 8554, "/s", None),
        ),
        (
            "rtsp://192.0.2.10:1/s".into(),
            ok("192.0.2.10", 1, "/s", None),
        ),
        (
            "rtsp://192.0.2.10:65535/s".into(),
            ok("192.0.2.10", 65535, "/s", None),
        ),
        (
            "rtsp://192.0.2.10:08554/s".into(),
            ok("192.0.2.10", 8554, "/s", None),
        ),
        (
            "rtsp://192.0.2.10:/s".into(),
            ok("192.0.2.10", 554, "/s", None),
        ),
        ("rtsp://[::1]:/s".into(), ok("::1", 554, "/s", None)),
        ("rtsp://192.0.2.10:0/s".into(), Want::Skip(S::InvalidPort)),
        (
            "rtsp://192.0.2.10:65536/s".into(),
            Want::Skip(S::InvalidPort),
        ),
        (
            "rtsp://192.0.2.10:99999999999999999999/s".into(),
            Want::Skip(S::InvalidPort),
        ),
        ("rtsp://192.0.2.10:-1/s".into(), Want::Skip(S::InvalidPort)),
        ("rtsp://192.0.2.10:+80/s".into(), Want::Skip(S::InvalidPort)),
        ("rtsp://192.0.2.10:80a/s".into(), Want::Skip(S::InvalidPort)),
        ("rtsp://192.0.2.10:abc/s".into(), Want::Skip(S::InvalidPort)),
        ("rtsp://192.0.2.10: 80/s".into(), Want::Skip(S::InvalidPort)),
        ("rtsp://192.0.2.10:8:9/s".into(), Want::Skip(S::InvalidHost)),
        (
            "rtsp://u:p/w@192.0.2.10/s".into(),
            Want::Skip(S::InvalidPort),
        ),
        // path and query
        ("rtsp://192.0.2.10".into(), ok("192.0.2.10", 554, "/", None)),
        (
            "rtsp://192.0.2.10/".into(),
            ok("192.0.2.10", 554, "/", None),
        ),
        (
            "rtsp://192.0.2.10?x=1".into(),
            ok("192.0.2.10", 554, "/?x=1", None),
        ),
        (
            "rtsp://192.0.2.10:8554?x=1".into(),
            ok("192.0.2.10", 8554, "/?x=1", None),
        ),
        (
            "rtsp://192.0.2.10/cam/realmonitor?channel=1&subtype=0".into(),
            ok(
                "192.0.2.10",
                554,
                "/cam/realmonitor?channel=1&subtype=0",
                None,
            ),
        ),
        (
            "rtsp://192.0.2.10/h264Preview_01_main".into(),
            ok("192.0.2.10", 554, "/h264Preview_01_main", None),
        ),
        (
            "rtsp://192.0.2.10/s?".into(),
            ok("192.0.2.10", 554, "/s?", None),
        ),
        (
            ok_path_512,
            ok("192.0.2.10", 554, &format!("/{}", "a".repeat(511)), None),
        ),
        (long_path, Want::Skip(S::InvalidPath)),
        ("rtsp://192.0.2.10/a%20b".into(), Want::Skip(S::InvalidPath)),
        ("rtsp://192.0.2.10/a b".into(), Want::Skip(S::InvalidPath)),
        (
            "rtsp://192.0.2.10/a#frag".into(),
            Want::Skip(S::InvalidPath),
        ),
        ("rtsp://192.0.2.10//x".into(), Want::Skip(S::InvalidPath)),
        ("rtsp://192.0.2.10/../x".into(), Want::Skip(S::InvalidPath)),
        ("rtsp://192.0.2.10/a/./b".into(), Want::Skip(S::InvalidPath)),
        (
            "rtsp://192.0.2.10/\u{e9}".into(),
            Want::Skip(S::InvalidPath),
        ),
        ("rtsp://192.0.2.10/s@x".into(), Want::Skip(S::InvalidPath)),
        ("rtsp://192.0.2.10/s\\x".into(), Want::Skip(S::InvalidPath)),
        // credentials in the path or query (Xiongmai and friends)
        (
            "rtsp://192.0.2.10/user=admin&password=x&channel=1&stream=0.sdp".into(),
            Want::Skip(S::CredentialInPath),
        ),
        (
            "rtsp://192.0.2.10/s?pass=1".into(),
            Want::Skip(S::CredentialInPath),
        ),
        (
            "rtsp://192.0.2.10/s?token=abc".into(),
            Want::Skip(S::CredentialInPath),
        ),
        (
            "rtsp://192.0.2.10/s;password=x".into(),
            Want::Skip(S::CredentialInPath),
        ),
        (
            "rtsp://192.0.2.10/s?a=1?user=x".into(),
            Want::Skip(S::CredentialInPath),
        ),
        (
            "rtsp://192.0.2.10/s?Password=x".into(),
            Want::Skip(S::CredentialInPath),
        ),
        // userinfo
        (
            "rtsp://user:secret@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("user", "secret"))),
        ),
        (
            "rtsp://user:secret@192.0.2.10:8554/s?channel=1".into(),
            ok("192.0.2.10", 8554, "/s?channel=1", Some(("user", "secret"))),
        ),
        (
            "rtsp://user:secret@[2001:db8::1]:8554/s".into(),
            ok("2001:db8::1", 8554, "/s", Some(("user", "secret"))),
        ),
        (
            "rtsp://user:secret@cam.example".into(),
            ok("cam.example", 554, "/", Some(("user", "secret"))),
        ),
        (
            "rtsp://user@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("user", ""))),
        ),
        (
            "rtsp://user:@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("user", ""))),
        ),
        (
            "rtsp://:secret@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("", "secret"))),
        ),
        (
            "rtsp://:@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", None),
        ),
        (
            "rtsp://@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", None),
        ),
        (
            "rtsp://user:p@ss@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("user", "p@ss"))),
        ),
        (
            "rtsp://user:p@@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("user", "p@"))),
        ),
        (
            "rtsp://user:p%40ss@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("user", "p@ss"))),
        ),
        (
            "rtsp://user:p%40@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("user", "p@"))),
        ),
        (
            "rtsp://us%40er:secret@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("us@er", "secret"))),
        ),
        (
            "rtsp://a%3Ab:secret@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("a:b", "secret"))),
        ),
        (
            "rtsp://a:b:c@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("a", "b:c"))),
        ),
        (
            "rtsp://u:p%2Fw%3F%23x@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("u", "p/w?#x"))),
        ),
        (
            "rtsp://u:100%@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("u", "100%"))),
        ),
        (
            "rtsp://u:p%zz@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("u", "p%zz"))),
        ),
        (
            "rtsp://u:p%4@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("u", "p%4"))),
        ),
        (
            "rtsp://u:caf%C3%A9@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("u", "caf\u{e9}"))),
        ),
        (
            "rtsp://u:caf\u{e9}@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("u", "caf\u{e9}"))),
        ),
        (
            "rtsp://u:p w@192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", Some(("u", "p w"))),
        ),
        (
            "rtsp://u:%00@192.0.2.10/s".into(),
            Want::Skip(S::InvalidCredential),
        ),
        (
            "rtsp://u:a%0d%0ab@192.0.2.10/s".into(),
            Want::Skip(S::InvalidCredential),
        ),
        (
            "rtsp://u%0a:p@192.0.2.10/s".into(),
            Want::Skip(S::InvalidCredential),
        ),
        (
            "rtsp://u:%7f@192.0.2.10/s".into(),
            Want::Skip(S::InvalidCredential),
        ),
        (
            "rtsp://u:%FF@192.0.2.10/s".into(),
            Want::Skip(S::InvalidCredential),
        ),
        (
            "rtsp://u:%C3@192.0.2.10/s".into(),
            Want::Skip(S::InvalidCredential),
        ),
        // userinfo does not rescue a bad host or path
        ("rtsp://u:p@/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://u:p@host name/s".into(), Want::Skip(S::InvalidHost)),
        (
            "rtsp://u:p@192.0.2.10/user=a&password=b".into(),
            Want::Skip(S::CredentialInPath),
        ),
        // host refusals
        ("rtsp:///s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://:554/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://[2001:db8::1/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://[2001:db8::1]x/s".into(), Want::Skip(S::InvalidHost)),
        (
            "rtsp://[2001:db8::1]8554/s".into(),
            Want::Skip(S::InvalidHost),
        ),
        ("rtsp://[]/s".into(), Want::Skip(S::InvalidHost)),
        (
            "rtsp://[::ffff:192.0.2.1]/s".into(),
            Want::Skip(S::InvalidHost),
        ),
        (
            "rtsp://[fe80::1%25eth0]/s".into(),
            Want::Skip(S::InvalidHost),
        ),
        ("rtsp://2001:db8::1/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://300.1.1.1/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://192.0.2/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://0x7f.1/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://cam%41/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://ca m/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://-cam/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://cam..example/s".into(), Want::Skip(S::InvalidHost)),
        ("rtsp://c\u{e4}m/s".into(), Want::Skip(S::InvalidHost)),
        (long_host, Want::Skip(S::InvalidHost)),
        // schemes and non-URLs
        (
            "http://192.0.2.10/video.mjpg".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "https://192.0.2.10/".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "HTTP://192.0.2.10/".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "mjpeg://192.0.2.10/".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "file:///var/video/x.mp4".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "onvif://192.0.2.10/".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "rtsps://192.0.2.10/s".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "rtmp://192.0.2.10/s".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "rtspx://192.0.2.10/s".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        (
            "xrtsp://192.0.2.10/s".into(),
            Want::Skip(S::UnsupportedScheme),
        ),
        ("://192.0.2.10/s".into(), Want::Skip(S::UnsupportedScheme)),
        ("rtsp:/192.0.2.10/s".into(), Want::Skip(S::NotAUrl)),
        ("rtsp:192.0.2.10/s".into(), Want::Skip(S::NotAUrl)),
        ("rtsp".into(), Want::Skip(S::NotAUrl)),
        ("192.0.2.10/s".into(), Want::Skip(S::NotAUrl)),
        ("Integrated Camera".into(), Want::Skip(S::NotAUrl)),
        ("/dev/video0".into(), Want::Skip(S::NotAUrl)),
        ("0".into(), Want::Skip(S::NotAUrl)),
        // whole-string forms
        (String::new(), Want::Skip(S::NoSource)),
        (" ".into(), Want::Skip(S::NoSource)),
        ("\n\t ".into(), Want::Skip(S::NoSource)),
        (
            "  rtsp://192.0.2.10/s \n".into(),
            ok("192.0.2.10", 554, "/s", None),
        ),
        (
            "\trtsp://192.0.2.10/s".into(),
            ok("192.0.2.10", 554, "/s", None),
        ),
        ("rtsp://192.0.2.10/a\tb".into(), Want::Skip(S::InvalidUrl)),
        ("rtsp://192.0.2.10/a\nb".into(), Want::Skip(S::InvalidUrl)),
        ("rtsp://192.0.2.10/a\rb".into(), Want::Skip(S::InvalidUrl)),
        (
            "rtsp://192.0.2.10/a\u{7f}b".into(),
            Want::Skip(S::InvalidUrl),
        ),
        (
            "rtsp://u:p\tw@192.0.2.10/s".into(),
            Want::Skip(S::InvalidUrl),
        ),
        ("rtsp://192.0.2.10\u{1}/s".into(), Want::Skip(S::InvalidUrl)),
    ];
    v.push((
        format!("rtsp://192.0.2.10/{}", "a".repeat(512)),
        Want::Skip(S::InvalidPath),
    ));
    v
}

#[test]
fn every_source_form_is_imported_or_skipped_as_listed() {
    let mut seen = std::collections::BTreeSet::new();
    for (src, want) in rows() {
        let got = one(&src);
        match (&want, got) {
            (Want::Skip(reason), Err(got)) => {
                assert_eq!(*reason, got, "source {src:?}");
                seen.insert(got);
            }
            (
                Want::Ok {
                    host,
                    port,
                    path,
                    cred: want_cred,
                },
                Ok(d),
            ) => {
                assert_eq!(d.host.expose(), *host, "{src:?}");
                assert_eq!(d.port.get(), *port, "{src:?}");
                assert_eq!(d.path.as_str(), *path, "{src:?}");
                assert_eq!(cred(&d), *want_cred, "{src:?}");
            }
            (_, got) => panic!("source {src:?}: unexpected {:?}", got.map(|d| d.id)),
        }
    }
    // Every skip reason a source can cause has a row.
    for reason in [
        S::NoSource,
        S::NotAUrl,
        S::UnsupportedScheme,
        S::InvalidUrl,
        S::InvalidHost,
        S::InvalidPort,
        S::InvalidPath,
        S::CredentialInPath,
        S::InvalidCredential,
    ] {
        assert!(seen.contains(&reason), "no source row for {reason:?}");
    }
}

#[test]
fn the_imported_path_never_holds_userinfo_or_the_split_text() {
    let d = one("rtsp://user:secret@192.0.2.10:8554/live/ch1?x=1").expect("imports");
    let path = d.path.as_str();
    assert_eq!(path, "/live/ch1?x=1");
    assert!(!path.contains("user") && !path.contains("secret") && !path.contains('@'));
}

#[test]
fn a_host_with_a_port_never_keeps_the_port_in_the_host() {
    let d = one("rtsp://192.0.2.10:8554/s").expect("imports");
    assert_eq!(d.host.expose(), "192.0.2.10");
}
