//! Adversary tests for #51 round 2 (PR #144): public API only.

#![expect(
    clippy::expect_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]
#![expect(
    clippy::format_push_string,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::needless_borrow,
    reason = "kept adversary table tests, committed verbatim; style only"
)]

use secrecy::ExposeSecret;
use wardenlens_agentdvr::{ImportError, SkipReason, parse};

fn doc(cameras: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><objects><cameras>{cameras}</cameras></objects>"
    )
}

fn cam(id: &str, name: &str, settings: &str) -> String {
    format!("<camera id=\"{id}\" name=\"{name}\"><settings>{settings}</settings></camera>")
}

fn one(settings: &str) -> Result<Option<(String, String)>, SkipReason> {
    let d = doc(&cam("1", "Porch", settings));
    let i = parse(d.as_bytes()).expect("parses");
    if let Some(s) = i.skipped.first() {
        assert!(i.cameras.is_empty());
        return Err(s.reason);
    }
    let c = i.cameras.first().expect("one camera");
    Ok(c.credential
        .as_ref()
        .map(|c| (c.user.clone(), c.password.expose_secret().to_owned())))
}

fn fields(src: &str, login: Option<&str>, pw: Option<&str>) -> String {
    let mut s = format!("<videosourcestring>{src}</videosourcestring>");
    if let Some(l) = login {
        s.push_str(&format!("<login>{l}</login>"));
    }
    if let Some(p) = pw {
        s.push_str(&format!("<password>{p}</password>"));
    }
    s
}

fn pair(u: &str, p: &str) -> Result<Option<(String, String)>, SkipReason> {
    Ok(Some((u.to_owned(), p.to_owned())))
}

#[test]
fn precedence_table() {
    use SkipReason::*;
    let h = "192.0.2.10/s";
    let cases: Vec<(
        String,
        Option<&str>,
        Option<&str>,
        Result<Option<(String, String)>, SkipReason>,
    )> = vec![
        (format!("rtsp://{h}"), None, None, Ok(None)),
        (format!("rtsp://{h}"), Some(""), Some(""), Ok(None)),
        (format!("rtsp://{h}"), Some("   "), Some(""), Ok(None)),
        (
            format!("rtsp://{h}"),
            Some("admin"),
            None,
            pair("admin", ""),
        ),
        (
            format!("rtsp://{h}"),
            Some("admin"),
            Some("pw"),
            pair("admin", "pw"),
        ),
        (
            format!("rtsp://{h}"),
            None,
            Some("pw"),
            Err(CredentialWithoutUser),
        ),
        (
            format!("rtsp://{h}"),
            Some(" \t "),
            Some("pw"),
            Err(CredentialWithoutUser),
        ),
        (
            format!("rtsp://admin:pw@{h}"),
            None,
            None,
            pair("admin", "pw"),
        ),
        (
            format!("rtsp://admin:pw@{h}"),
            Some(" "),
            None,
            pair("admin", "pw"),
        ),
        (
            format!("rtsp://admin:pw@{h}"),
            Some("admin"),
            Some("pw"),
            pair("admin", "pw"),
        ),
        (
            format!("rtsp://admin:p%77@{h}"),
            Some("admin"),
            Some("pw"),
            pair("admin", "pw"),
        ),
        (
            format!("rtsp://admin:pw@{h}"),
            Some("admin"),
            None,
            Err(ConflictingCredential),
        ),
        (
            format!("rtsp://admin:pw@{h}"),
            Some("admin"),
            Some("other"),
            Err(ConflictingCredential),
        ),
        (
            format!("rtsp://admin:pw@{h}"),
            Some("root"),
            Some("pw"),
            Err(ConflictingCredential),
        ),
        (
            format!("rtsp://admin:pw@{h}"),
            None,
            Some("pw"),
            Err(ConflictingCredential),
        ),
        (
            format!("rtsp://:pw@{h}"),
            None,
            None,
            Err(CredentialWithoutUser),
        ),
        (format!("rtsp://:@{h}"), None, None, Ok(None)),
        (format!("rtsp://@{h}"), None, None, Ok(None)),
        (
            format!("rtsp://a%3Ab:pw@{h}"),
            None,
            None,
            Err(InvalidCredential),
        ),
        (
            format!("rtsp://ab:p%0Aw@{h}"),
            None,
            None,
            Err(InvalidCredential),
        ),
        (
            format!("rtsp://ab:p%00w@{h}"),
            None,
            None,
            Err(InvalidCredential),
        ),
        (
            format!("rtsp://ab:p%FFw@{h}"),
            None,
            None,
            Err(InvalidCredential),
        ),
        (
            format!("rtsp://ab:p%zzw@{h}"),
            None,
            None,
            pair("ab", "p%zzw"),
        ),
        (format!("rtsp://a:b:c@{h}"), None, None, pair("a", "b:c")),
        (format!("rtsp://a:b@c@{h}"), None, None, pair("a", "b@c")),
        (
            format!("rtsp://{h}"),
            Some("a:b"),
            Some("pw"),
            Err(InvalidCredential),
        ),
    ];
    for (src, login, pw, want) in cases {
        let got = one(&fields(&src, login, pw));
        assert_eq!(got, want, "src={src} login={login:?} pw={pw:?}");
    }
}

/// A password containing `/` or `?` unencoded must never import the user name as the host.
#[test]
fn unencoded_slash_or_query_in_password_never_imports_user_as_host() {
    for src in [
        "rtsp://camuser:1234/x@192.0.2.10/s",
        "rtsp://camuser:1234?x@192.0.2.10/s",
        "rtsp://camuser:1234/@192.0.2.10",
        "rtsp://camuser:1234?@192.0.2.10",
        "rtsp://camuser:1234/x?y@192.0.2.10",
        "rtsp://camuser:1234/%40192.0.2.10",
    ] {
        let d = doc(&cam("1", "Porch", &fields(src, None, None)));
        let i = parse(d.as_bytes()).expect("parses");
        for c in &i.cameras {
            assert_ne!(c.host.expose(), "camuser", "{src}: user imported as host");
        }
    }
}

#[test]
fn port_edges() {
    use SkipReason::*;
    let cases = [
        ("rtsp://192.0.2.10:/s", Ok(554)),
        ("rtsp://192.0.2.10:1/s", Ok(1)),
        ("rtsp://192.0.2.10:65535/s", Ok(65535)),
        ("rtsp://192.0.2.10:65536/s", Err(InvalidPort)),
        ("rtsp://192.0.2.10:0/s", Err(InvalidPort)),
        ("rtsp://192.0.2.10:+554/s", Err(InvalidPort)),
        ("rtsp://192.0.2.10:-1/s", Err(InvalidPort)),
        ("rtsp://192.0.2.10: 554/s", Err(InvalidPort)),
        ("rtsp://192.0.2.10:99999999999999999999/s", Err(InvalidPort)),
        ("rtsp://[2001:db8::1]/s", Ok(554)),
        ("rtsp://[2001:db8::1]:/s", Ok(554)),
        ("rtsp://[2001:db8::1]:8554/s", Ok(8554)),
        ("rtsp://[2001:db8::1]x/s", Err(InvalidHost)),
        ("rtsp://[2001:db8::1/s", Err(InvalidHost)),
        ("rtsp://2001:db8::1/s", Err(InvalidHost)),
        ("rtsp://:554/s", Err(InvalidHost)),
        ("rtsp:///s", Err(InvalidHost)),
    ];
    for (src, want) in cases {
        let d = doc(&cam("1", "Porch", &fields(src, None, None)));
        let i = parse(d.as_bytes()).expect("parses");
        let got = match (i.cameras.first(), i.skipped.first()) {
            (Some(c), None) => Ok(c.port.get()),
            (None, Some(s)) => Err(s.reason),
            _ => panic!("{src}: not exactly one outcome"),
        };
        assert_eq!(got, want, "{src}");
    }
}

#[test]
fn every_strict_prefix_of_a_document_is_an_error_and_never_panics() {
    let d = doc(&format!(
        "{}{}",
        cam(
            "1",
            "Porch &amp; Yard",
            &fields("rtsp://u:p@192.0.2.10/s?a=1", Some("u"), Some("p"))
        ),
        cam("2", "Gate", "<![CDATA[x]]><!-- c --><?pi x?>")
    ));
    assert!(parse(d.as_bytes()).is_ok());
    let bytes = d.as_bytes();
    for n in 0..bytes.len() {
        assert!(parse(&bytes[..n]).is_err(), "prefix of {n} bytes parsed Ok");
    }
}

#[test]
fn names_equal_after_normalisation_refuse_the_import_with_positions() {
    let d = doc(&format!(
        "{}{}{}",
        cam(
            "1",
            "Front  Door",
            &fields("rtsp://192.0.2.10/s", None, None)
        ),
        cam("2", "Other", &fields("http://192.0.2.11/s", None, None)),
        cam(
            "3",
            " Front&#9;Door\u{200b} ",
            &fields("rtsp://192.0.2.12/s", None, None)
        ),
    ));
    assert_eq!(
        parse(d.as_bytes()).unwrap_err(),
        ImportError::DuplicateName {
            first: 0,
            second: 2
        }
    );
}

#[test]
fn a_skipped_camera_does_not_reserve_its_name_or_its_id() {
    let d = doc(&format!(
        "{}{}",
        cam("5", "Porch", &fields("http://192.0.2.10/s", None, None)),
        cam("5", "Porch", &fields("rtsp://192.0.2.10/s", None, None)),
    ));
    let i = parse(d.as_bytes()).expect("parses");
    assert_eq!(i.cameras.len(), 1);
    assert_eq!(i.cameras[0].id.as_str(), "agentdvr-5");
}

#[test]
fn ids_are_unique_and_never_derived_from_the_name() {
    let names = [
        "agentdvr-1",
        "agentdvr-pos-0",
        "Zzsentinelzz",
        "agentdvr-pos-2",
    ];
    let ids = ["1", "", "+1", "01", "x", "4294967296", "-1", " 1"];
    let mut cams = String::new();
    let mut n = 0;
    for id in ids {
        for name in names {
            cams.push_str(&cam(
                id,
                &format!("{name} {n}"),
                &fields("rtsp://192.0.2.10/s", None, None),
            ));
            n += 1;
        }
    }
    let i = parse(doc(&cams).as_bytes()).expect("parses");
    assert_eq!(i.cameras.len(), n);
    let mut seen = std::collections::BTreeSet::new();
    for c in &i.cameras {
        assert!(
            seen.insert(c.id.as_str().to_owned()),
            "duplicate id {}",
            c.id.as_str()
        );
        assert!(!c.id.as_str().to_lowercase().contains("zzsentinel"));
    }
}

#[test]
fn no_sentinel_in_any_output_for_every_skip_reason() {
    let s = ["Zqname", "Zquser", "Zqpass", "zqhost"];
    let cams = [
        cam(
            "1",
            "Zqname a",
            &fields("rtsp://Zquser:Zqpass@zqhost.example/s", None, None),
        ),
        cam(
            "2",
            "Zqname b",
            &fields(
                "rtsp://Zquser:Zqpass@zqhost.example/s",
                Some("Zquser"),
                Some("Zqpassx"),
            ),
        ),
        cam(
            "3",
            "Zqname c",
            &fields("rtsp://:Zqpass@zqhost.example/s", None, None),
        ),
        cam(
            "4",
            "Zqname d",
            &fields("rtsp://Zquser:Zqpass@zqhost.example:0/s", None, None),
        ),
        cam(
            "5",
            "Zqname e",
            &fields("rtsp://Zquser:Zqpass@zqhost.example/Zqpass%", None, None),
        ),
        cam(
            "6",
            "Zqname f",
            &fields(
                "rtsp://Zquser:Zqpass@zqhost.example/user=Zquser&amp;password=Zqpass",
                None,
                None,
            ),
        ),
        cam(
            "7",
            "Zqname g",
            &fields("rtsp://Zq%3Auser:Zqpass@zqhost.example/s", None, None),
        ),
        cam(
            "8",
            "Zqname h",
            &fields(
                "rtsp://Zquser:Zqpass@zqhost.example/s",
                Some("Zq:user"),
                None,
            ),
        ),
        cam(
            "9",
            "Zqname i\u{0007}",
            &fields("rtsp://Zquser:Zqpass@zqhost.example/s", None, None),
        ),
        cam(
            "10",
            "Zqname j",
            &fields("rtsp://Zquser:Zqpass@zqhost.example/s&#9;", None, None),
        ),
        cam(
            "11",
            "Zqname k",
            &fields(
                "rtsp://Zquser:Zqpass@zqhost.example/s",
                Some("Zquser"),
                Some("Zqpass"),
            ),
        ),
    ];
    let d = doc(&cams.concat());
    let i = parse(d.as_bytes());
    let shown = match &i {
        Ok(i) => format!("{i:?} {i:#?}"),
        Err(e) => format!("{e:?} {e}"),
    };
    for s in s {
        assert!(!shown.contains(s), "{s} leaked: {shown}");
    }
    if let Ok(i) = i {
        for sk in &i.skipped {
            let t = format!("{} {:?}", sk.reason, sk);
            for s in ["Zqname", "Zquser", "Zqpass", "zqhost"] {
                assert!(!t.contains(s));
            }
        }
    }
}

#[test]
fn duplicate_name_error_text_has_no_name() {
    let d = doc(&format!(
        "{}{}",
        cam(
            "1",
            "Zqsecretname",
            &fields("rtsp://192.0.2.10/s", None, None)
        ),
        cam(
            "2",
            "Zqsecretname",
            &fields("rtsp://192.0.2.11/s", None, None)
        ),
    ));
    let e = parse(d.as_bytes()).unwrap_err();
    assert!(!format!("{e} {e:?}").contains("Zqsecret"));
}

#[test]
fn hostile_xml_is_refused_not_expanded() {
    let cases: [(&str, fn(&ImportError) -> bool); 8] = [
        ("<!DOCTYPE objects [<!ENTITY a \"b\">]><objects/>", |e| {
            *e == ImportError::DocType
        }),
        (
            "<objects><cameras><camera name=\"&a;\"/></cameras></objects>",
            |e| matches!(e, ImportError::Malformed { .. }),
        ),
        (
            "<objects><cameras><camera name=\"&#0;\"/></cameras></objects>",
            |e| matches!(e, ImportError::Malformed { .. }),
        ),
        (
            "<objects><cameras><camera name=\"&#xD800;\"/></cameras></objects>",
            |e| matches!(e, ImportError::Malformed { .. }),
        ),
        (
            "<objects><cameras><camera><settings><login>&#1;</login></settings></camera></cameras></objects>",
            |e| matches!(e, ImportError::Malformed { .. }),
        ),
        ("<objects></objects><objects></objects>", |e| {
            matches!(e, ImportError::Malformed { .. })
        }),
        ("<objects><a></b></objects>", |e| {
            matches!(e, ImportError::Malformed { .. })
        }),
        (
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><objects/>",
            |e| *e == ImportError::UnsupportedEncoding,
        ),
    ];
    for (x, ok) in cases {
        let e = parse(x.as_bytes()).expect_err(x);
        assert!(ok(&e), "{x}: {e:?}");
    }
    let deep = format!(
        "<objects>{}{}</objects>",
        "<a>".repeat(100),
        "</a>".repeat(100)
    );
    assert_eq!(parse(deep.as_bytes()).unwrap_err(), ImportError::TooDeep);
    let many = doc(&cam("1", "x", "").repeat(wardenlens_agentdvr::MAX_CAMERAS + 1));
    assert_eq!(
        parse(many.as_bytes()).unwrap_err(),
        ImportError::TooManyCameras
    );
}

/// A raw C0 control character in element text is not well-formed XML 1.0, same as its
/// character reference (which is Malformed). It must not be accepted as a value.
#[test]
#[ignore = "follow-up #146"]
fn raw_control_char_in_login_text_is_malformed_like_its_reference() {
    let d = doc(&cam(
        "1",
        "Porch",
        &fields("rtsp://192.0.2.10/s", Some("ad\u{1}min"), Some("pw")),
    ));
    assert!(
        matches!(parse(d.as_bytes()), Err(ImportError::Malformed { .. })),
        "{:?}",
        parse(d.as_bytes()).map(|i| i.skipped)
    );
}

/// The vault normaliser and the importer's must agree byte-for-byte (one normaliser).
#[test]
fn imported_name_is_core_normalised() {
    for (raw, want) in [
        ("  A\u{a0}\u{2003}B\u{200d} ", "A B"),
        ("a&#10;&#13;b", "a b"),
        ("a\u{2028}b", "a b"),
    ] {
        let d = doc(&cam("1", raw, &fields("rtsp://192.0.2.10/s", None, None)));
        let i = parse(d.as_bytes()).expect("parses");
        assert_eq!(i.cameras[0].name.expose(), want);
        assert_eq!(
            wardenlens_core::text::normalise_display_name(&i.cameras[0].name.expose()),
            want
        );
    }
}

#[test]
fn xml_declaration_only_first() {
    assert!(parse("\u{feff}<?xml version=\"1.0\"?><objects/>".as_bytes()).is_ok());
    for x in [
        "<!-- c --><?xml version=\"1.0\"?><objects/>",
        "<objects/><?xml version=\"1.0\"?>",
        "<?xml version=\"1.0\"?><?xml version=\"1.0\"?><objects/>",
        "<objects><?xml version=\"1.0\" encoding=\"latin1\"?></objects>",
    ] {
        assert!(
            matches!(parse(x.as_bytes()), Err(ImportError::Malformed { .. })),
            "{x}: {:?}",
            parse(x.as_bytes()).map(|_| ())
        );
    }
}
