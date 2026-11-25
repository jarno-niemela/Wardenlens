//! The element and attribute level: which fields are read, login fields versus userinfo,
//! and every per-camera skip (invariant 3). Each skip reason has a row.

use crate::{ImportError, SkipReason as S, parse};

use super::fixtures::{Cam, cam_xml, cred, doc, esc, one, parse_ok, wrap};

fn skip_of(c: &Cam) -> S {
    let i = parse_ok(std::slice::from_ref(c));
    assert!(i.cameras.is_empty(), "expected a skip");
    assert_eq!(i.skipped.len(), 1);
    i.skipped[0].reason
}

fn with(f: impl FnOnce(&mut Cam)) -> Cam {
    let mut c = Cam::new("Porch", "rtsp://192.0.2.10/s");
    f(&mut c);
    c
}

fn imported(c: &Cam) -> crate::CameraDraft {
    let i = parse_ok(std::slice::from_ref(c));
    assert!(i.skipped.is_empty(), "skipped: {:?}", i.skipped);
    i.cameras.into_iter().next().expect("one camera")
}

#[test]
fn login_fields_are_the_credential() {
    let d = imported(&Cam::new("A", "rtsp://192.0.2.10/s").login("user", "secret"));
    assert_eq!(cred(&d), Some(("user".into(), "secret".into())));
    assert_eq!(d.path.as_str(), "/s");
}

#[test]
fn login_fields_and_url_userinfo_that_agree_are_one_credential() {
    let d = imported(&Cam::new("A", "rtsp://user:secret@192.0.2.10/s").login("user", "secret"));
    assert_eq!(cred(&d), Some(("user".into(), "secret".into())));
    // The URL's side is compared after percent-decoding.
    let d = imported(&Cam::new("A", "rtsp://us%40er:p%40ss@192.0.2.10/s").login("us@er", "p@ss"));
    assert_eq!(cred(&d), Some(("us@er".into(), "p@ss".into())));
}

#[test]
fn login_fields_and_url_userinfo_that_differ_conflict_and_nothing_is_chosen() {
    let rows = [
        // (url userinfo, login field, password field)
        ("other:pw", "user", "secret"),
        ("user:pw", "user", "secret"),
        ("other:secret", "user", "secret"),
        // the login field has a user but no password; the URL has the password (dropping it
        // would import an empty one)
        ("user:secret", "user", ""),
        ("user", "user", "secret"),
        ("user:secret", "", "secret"),
        (":secret", "user", "secret"),
    ];
    for (ui, l, p) in rows {
        let c = Cam::new("A", &format!("rtsp://{ui}@192.0.2.10/s")).login(l, p);
        assert_eq!(skip_of(&c), S::ConflictingCredential, "{ui} / {l} / {p}");
    }
}

#[test]
fn only_one_source_present_is_used_whichever_it_is() {
    // Fields only, URL only; the other side empty in every spelling.
    for (l, p) in [
        (Some(""), Some("")),
        (None, None),
        (Some(""), None),
        (None, Some("")),
    ] {
        let c = with(|c| {
            c.source = Some("rtsp://user:secret@192.0.2.10/s".into());
            c.login = l.map(str::to_owned);
            c.password = p.map(str::to_owned);
        });
        assert_eq!(
            cred(&imported(&c)),
            Some(("user".into(), "secret".into())),
            "{l:?} {p:?}"
        );
    }
    let fields_only = Cam::new("A", "rtsp://192.0.2.10/s").login("user", "");
    assert_eq!(
        cred(&imported(&fields_only)),
        Some(("user".into(), String::new()))
    );
}

#[test]
fn a_whitespace_only_login_is_no_user() {
    // Treated as empty (not skipped): the URL userinfo is then the only credential.
    for blank in [" ", "\t", "  \n ", "\u{a0}"] {
        let c = with(|c| {
            c.source = Some("rtsp://user:secret@192.0.2.10/s".into());
            c.login = Some(blank.into());
            c.password = Some(String::new());
        });
        assert_eq!(
            cred(&imported(&c)),
            Some(("user".into(), "secret".into())),
            "{blank:?}"
        );
        // With a password field and no real user it is a password without a user.
        let c = Cam::new("A", "rtsp://192.0.2.10/s").login(blank, "secret");
        assert_eq!(skip_of(&c), S::CredentialWithoutUser, "{blank:?}");
    }
}

#[test]
fn a_password_without_a_user_is_never_emitted() {
    let rows = [
        // Cam with fields
        Cam::new("A", "rtsp://192.0.2.10/s").login("", "secret"),
        Cam::new("A", "rtsp://:secret@192.0.2.10/s"),
        Cam::new("A", "rtsp://%20:secret@192.0.2.10/s").login("", ""),
    ];
    for (n, c) in rows.iter().enumerate() {
        let i = parse_ok(std::slice::from_ref(c));
        // The third row is a user of one space: accepted by the vault rule (non-empty).
        if n == 2 {
            assert_eq!(i.cameras.len(), 1);
            continue;
        }
        assert_eq!(i.skipped[0].reason, S::CredentialWithoutUser, "row {n}");
    }
}

#[test]
fn a_colon_in_the_user_is_refused_from_every_source() {
    for c in [
        Cam::new("A", "rtsp://192.0.2.10/s").login("a:b", "secret"),
        Cam::new("A", "rtsp://a%3Ab:secret@192.0.2.10/s"),
    ] {
        assert_eq!(skip_of(&c), S::InvalidCredential);
    }
    // A colon in the password is fine.
    let c = Cam::new("A", "rtsp://192.0.2.10/s").login("user", "a:b");
    assert_eq!(cred(&imported(&c)), Some(("user".into(), "a:b".into())));
}

#[test]
fn every_emitted_credential_passes_the_vault_rule() {
    // Every spelling that reaches an emitted credential, through the one shared rule.
    let sources = [
        Cam::new("A", "rtsp://user:secret@192.0.2.10/s"),
        Cam::new("A", "rtsp://user@192.0.2.10/s"),
        Cam::new("A", "rtsp://user:@192.0.2.10/s"),
        Cam::new("A", "rtsp://:secret@192.0.2.10/s"),
        Cam::new("A", "rtsp://%00:secret@192.0.2.10/s"),
        Cam::new("A", "rtsp://user:p%00@192.0.2.10/s"),
        Cam::new("A", "rtsp://192.0.2.10/s").login("user", "secret"),
        Cam::new("A", "rtsp://192.0.2.10/s").login("", "secret"),
        Cam::new("A", "rtsp://192.0.2.10/s").login("user", ""),
        Cam::new("A", "rtsp://192.0.2.10/s").login("u\u{0}", "secret"),
        Cam::new("A", "rtsp://192.0.2.10/s").login(&"u".repeat(4096), &"p".repeat(4096)),
        Cam::new("A", &format!("rtsp://{}:p@192.0.2.10/s", "u".repeat(4000))),
    ];
    let mut emitted = 0;
    for c in sources {
        let i = parse(doc(&[c]).as_bytes());
        let Ok(i) = i else { continue };
        for d in i.cameras {
            if let Some((u, p)) = cred(&d) {
                assert_eq!(wardenlens_core::camera::Credential::check(&u, &p), Ok(()));
                emitted += 1;
            }
        }
    }
    assert!(emitted >= 5);
}

#[test]
fn no_login_anywhere_is_no_credential() {
    assert!(imported(&with(|_| {})).credential.is_none());
}

#[test]
fn login_fields_are_exact_text_not_url_decoded_or_trimmed() {
    let c = Cam::new("A", "rtsp://192.0.2.10/s").login(" us%40er@x ", " p%40ss@:/? ");
    assert_eq!(
        cred(&imported(&c)),
        Some((" us%40er@x ".into(), " p%40ss@:/? ".into()))
    );
}

#[test]
fn login_fields_with_control_characters_are_refused() {
    for bad in ["a\tb", "a\nb", "a\rb", "a\u{7f}b", "\u{85}x", "x\u{0}"] {
        let user_bad = Cam::new("A", "rtsp://192.0.2.10/s").login(bad, "secret");
        let pass_bad = Cam::new("A", "rtsp://192.0.2.10/s").login("user", bad);
        // A raw NUL or control char is not legal XML text: the whole document is refused, which
        // is also a refusal. Everything else is a skipped camera.
        for c in [user_bad, pass_bad] {
            match parse(doc(&[c]).as_bytes()) {
                Ok(i) => {
                    assert!(i.cameras.is_empty(), "{bad:?}");
                    assert_eq!(i.skipped[0].reason, S::InvalidCredential, "{bad:?}");
                }
                Err(e) => assert!(matches!(e, ImportError::Malformed { .. }), "{bad:?} {e}"),
            }
        }
    }
}

#[test]
fn deleted_flag_forms() {
    for (v, skipped) in [
        ("true", true),
        ("True", true),
        ("TRUE", true),
        ("1", true),
        ("false", false),
        ("False", false),
        ("0", false),
        ("", false),
        ("maybe", false),
    ] {
        let c = with(|c| c.deleted = Some(v));
        let i = parse_ok(&[c]);
        assert_eq!(i.skipped.len(), usize::from(skipped), "deleted={v:?}");
        if skipped {
            assert_eq!(i.skipped[0].reason, S::Deleted);
        }
    }
}

#[test]
fn name_forms() {
    let long_ok = "n".repeat(128);
    let long_bad = "n".repeat(129);
    let rows: Vec<(Option<String>, Option<S>)> = vec![
        (None, Some(S::MissingName)),
        (Some(String::new()), Some(S::NameRefused)),
        (Some("   ".into()), Some(S::NameRefused)),
        (Some("\u{a0}\u{200b}".into()), Some(S::NameRefused)),
        (Some("!!!".into()), Some(S::NameRefused)),
        (Some("\u{301}x".into()), Some(S::NameRefused)),
        (Some("\u{e000}".into()), Some(S::NameRefused)),
        (Some(long_bad), Some(S::NameRefused)),
        (Some(long_ok), None),
        (Some("Front Door".into()), None),
        (Some("  Front\u{a0}\u{a0}Door\u{200b} ".into()), None),
        (Some("Caf\u{e9} \u{4e2d}\u{6587}".into()), None),
    ];
    for (name, want) in rows {
        let c = with(|c| c.name.clone_from(&name));
        let i = parse_ok(&[c]);
        match want {
            Some(reason) => {
                assert!(i.cameras.is_empty(), "{name:?}");
                assert_eq!(i.skipped[0].reason, reason, "{name:?}");
            }
            None => assert_eq!(i.cameras.len(), 1, "{name:?}"),
        }
    }
}

#[test]
fn name_is_normalised_like_the_vault_stores_it() {
    let c = with(|c| c.name = Some("  Front\t\u{a0}Door\u{200b}\n Cam ".into()));
    assert_eq!(imported(&c).name.expose(), "Front Door Cam");
}

#[test]
fn missing_source_forms() {
    let none = with(|c| c.source = None);
    assert_eq!(skip_of(&none), S::NoSource);
    let empty = with(|c| c.source = Some(String::new()));
    assert_eq!(skip_of(&empty), S::NoSource);
    // No settings element at all, and settings without a source (ONVIF only entries).
    let bare = wrap("<camera id=\"1\" name=\"Porch\"/>");
    let i = parse(bare.as_bytes()).expect("parses");
    assert_eq!(i.skipped[0].reason, S::NoSource);
    let onvif = wrap(
        "<camera id=\"1\" name=\"Porch\"><settings><onvifident>x</onvifident><onvif><username>u</username></onvif></settings></camera>",
    );
    assert_eq!(
        parse(onvif.as_bytes()).expect("parses").skipped[0].reason,
        S::NoSource
    );
}

#[test]
fn repeated_elements_are_ambiguous_and_skipped() {
    let base = "<camera id=\"1\" name=\"Porch\">";
    let rows = [
        "<settings><videosourcestring>rtsp://192.0.2.10/a</videosourcestring></settings><settings><videosourcestring>rtsp://192.0.2.11/b</videosourcestring></settings>",
        "<settings><videosourcestring>rtsp://192.0.2.10/a</videosourcestring><videosourcestring>rtsp://192.0.2.11/b</videosourcestring></settings>",
        "<settings><videosourcestring>rtsp://192.0.2.10/a</videosourcestring><login>a</login><login>b</login></settings>",
        "<settings><videosourcestring>rtsp://192.0.2.10/a</videosourcestring><password>a</password><password>b</password></settings>",
    ];
    for r in rows {
        let d = wrap(&format!("{base}{r}</camera>"));
        let i = parse(d.as_bytes()).expect("parses");
        assert!(i.cameras.is_empty(), "{r}");
        assert_eq!(i.skipped[0].reason, S::RepeatedElement, "{r}");
    }
}

#[test]
fn field_length_boundaries() {
    // Login and password: exactly the limit is accepted, one more is refused.
    let at = "x".repeat(crate::MAX_FIELD_BYTES);
    let over = "x".repeat(crate::MAX_FIELD_BYTES + 1);
    let ok_user = Cam::new("A", "rtsp://192.0.2.10/s").login(&at, "p");
    assert_eq!(imported(&ok_user).credential.expect("cred").user, at);
    for c in [
        Cam::new("A", "rtsp://192.0.2.10/s").login(&over, "p"),
        Cam::new("A", "rtsp://192.0.2.10/s").login("u", &over),
        Cam::new("A", &format!("rtsp://192.0.2.10/{over}")),
    ] {
        assert_eq!(skip_of(&c), S::FieldTooLong);
    }
}

#[test]
fn position_and_agent_id_of_skips() {
    let cams = vec![
        Cam::new("One", "rtsp://192.0.2.10/s"),
        Cam::new("Two", "http://192.0.2.11/x"),
        Cam::new("Three", "rtsp://192.0.2.12/s"),
    ];
    let i = parse_ok(&cams);
    assert_eq!(i.cameras.len(), 2);
    assert_eq!(i.skipped.len(), 1);
    assert_eq!(i.skipped[0].position, 1);
    assert_eq!(i.skipped[0].agent_id, Some(1));
    // A non-numeric or out of range id is None.
    for id in ["x", "", "-1", "99999999999999999999", "1.5"] {
        let d = wrap(&format!("<camera id=\"{id}\" name=\"A\"/>"));
        assert_eq!(
            parse(d.as_bytes()).expect("ok").skipped[0].agent_id,
            None,
            "{id}"
        );
    }
}

#[test]
fn every_camera_is_in_exactly_one_list_in_document_order() {
    let cams: Vec<Cam> = (0..40)
        .map(|n| {
            if n % 3 == 0 {
                Cam::new(&format!("Cam {n}"), "http://192.0.2.1/x")
            } else {
                Cam::new(&format!("Cam {n}"), &format!("rtsp://192.0.2.{}/s", n + 1))
            }
        })
        .collect();
    let i = parse_ok(&cams);
    assert_eq!(i.cameras.len() + i.skipped.len(), 40);
    let hosts: Vec<String> = i.cameras.iter().map(|c| c.host.expose()).collect();
    let want: Vec<String> = (0..40)
        .filter(|n| n % 3 != 0)
        .map(|n| format!("192.0.2.{}", n + 1))
        .collect();
    assert_eq!(hosts, want);
    let positions: Vec<usize> = i.skipped.iter().map(|s| s.position).collect();
    assert_eq!(
        positions,
        (0..40).filter(|n| n % 3 == 0).collect::<Vec<_>>()
    );
}

#[test]
fn only_the_documented_paths_are_read() {
    // A source, login or camera in the wrong place is ignored, never half-used.
    let rows = [
        // fields directly under camera
        "<camera id=\"1\" name=\"A\"><videosourcestring>rtsp://192.0.2.10/s</videosourcestring></camera>",
        // settings nested under another element
        "<camera id=\"1\" name=\"A\"><x><settings><videosourcestring>rtsp://192.0.2.10/s</videosourcestring></settings></x></camera>",
        // wrong case
        "<camera id=\"1\" name=\"A\"><settings><VideoSourceString>rtsp://192.0.2.10/s</VideoSourceString></settings></camera>",
        // name as an element, not an attribute
    ];
    for r in rows {
        let i = parse(wrap(r).as_bytes()).expect("parses");
        assert!(i.cameras.is_empty(), "{r}");
        assert_eq!(i.skipped[0].reason, S::NoSource, "{r}");
    }
    // name as an element is not the name.
    let r = "<camera id=\"1\"><name>A</name><settings><videosourcestring>rtsp://192.0.2.10/s</videosourcestring></settings></camera>";
    assert_eq!(
        parse(wrap(r).as_bytes()).expect("ok").skipped[0].reason,
        S::MissingName
    );
    // A camera outside <cameras> is not a camera.
    let d = "<objects><camera id=\"1\" name=\"A\"><settings><videosourcestring>rtsp://192.0.2.10/s</videosourcestring></settings></camera></objects>";
    let i = parse(d.as_bytes()).expect("ok");
    assert!(i.cameras.is_empty() && i.skipped.is_empty());
    // A root other than <objects> is refused (see document tests); other sections are ignored.
    let d =
        "<objects><microphones><camera id=\"1\" name=\"A\"/></microphones><floorplans/></objects>";
    let i = parse(d.as_bytes()).expect("ok");
    assert!(i.cameras.is_empty() && i.skipped.is_empty());
}

#[test]
fn unknown_elements_attributes_and_nested_children_are_ignored() {
    let d = wrap(
        "<camera id=\"1\" name=\"Porch\" zzz=\"1\" xmlns:q=\"u\"><q:extra a=\"b\"><deep><deeper/></deep></q:extra>\
         <settings foo=\"bar\"><sourceindex>2</sourceindex><videosourcestring a=\"b\">rtsp://192.0.2.10/s<b>nested</b>tail</videosourcestring>\
         <onvif><password>not-this</password><login>not-this</login></onvif><ptzpassword>nope</ptzpassword></settings><ftp><password>nope</password></ftp></camera>",
    );
    let i = parse(d.as_bytes()).expect("parses");
    // Text of a nested child element is not part of the field; only the direct text is.
    assert_eq!(i.cameras.len(), 1);
    let c = &i.cameras[0];
    assert_eq!(c.host.expose(), "192.0.2.10");
    assert_eq!(c.path.as_str(), "/stail");
    assert!(c.credential.is_none());
}

#[test]
fn entities_cdata_comments_and_char_refs_in_fields() {
    let d = wrap(
        "<camera id=\"1\" name=\"A &amp; B &#67;\"><settings><videosourcestring><![CDATA[rtsp://192.0.2.10/s?channel=1&subtype=0]]></videosourcestring>\
         <login>us<!-- c -->er</login><password>p&amp;&lt;&gt;&quot;&apos;&#x40;<![CDATA[<x>]]></password></settings></camera>",
    );
    let c = parse(d.as_bytes()).expect("parses").cameras.remove(0);
    assert_eq!(c.name.expose(), "A & B C");
    assert_eq!(c.path.as_str(), "/s?channel=1&subtype=0");
    assert_eq!(cred(&c), Some(("user".into(), "p&<>\"'@<x>".into())));
}

#[test]
fn escaping_helper_round_trips_every_special_character() {
    let pw = "a&b<c>d\"e'f";
    let c = Cam::new("A", "rtsp://192.0.2.10/s").login("u", pw);
    assert_eq!(cred(&imported(&c)), Some(("u".into(), pw.into())));
    assert_eq!(esc("&<>\""), "&amp;&lt;&gt;&quot;");
    let _ = (cam_xml, one);
}

#[test]
fn empty_cameras_list_and_empty_root_are_empty_imports() {
    for d in [
        "<objects/>",
        "<objects></objects>",
        "<objects><cameras/></objects>",
        "<objects><cameras></cameras><cameras/></objects>",
    ] {
        let i = parse(d.as_bytes()).expect(d);
        assert!(i.cameras.is_empty() && i.skipped.is_empty(), "{d}");
    }
}

#[test]
fn several_cameras_lists_are_all_read_in_order() {
    let a = cam_xml(&Cam::new("A", "rtsp://192.0.2.10/s"), 0);
    let b = cam_xml(&Cam::new("B", "rtsp://192.0.2.11/s"), 1);
    let d = format!("<objects><cameras>{a}</cameras><cameras>{b}</cameras></objects>");
    let i = parse(d.as_bytes()).expect("ok");
    let names: Vec<&str> = i.cameras.iter().map(|c| c.name.expose()).collect();
    assert_eq!(names, ["A", "B"]);
}
