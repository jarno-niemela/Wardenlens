//! `objects.json` (#226): the JSON reader against the XML reader and its own limits.
//!
//! Enumeration (TEST-9): (1) every source form of the XML tests' shape, run through both formats
//! and compared field by field (drafts, skip reasons, logins); (2) every member type of the
//! three text members and of `id`, `name` and `deleted`; (3) structure (root kinds, missing and
//! repeated members, unknown members, BOM, trailing data, every truncated prefix); (4) limits
//! (depth at the limit and one over, strings that hold brackets and quotes, cameras at the limit
//! and one over, size); (5) no input text in any error.

use serde_json::{Value, json};

use crate::{
    Format, ImportError as E, MAX_CAMERAS, MAX_DEPTH, MAX_FIELD_BYTES, MAX_INPUT_BYTES, SkipReason,
    detect, parse, parse_as, parse_json,
};

use super::fixtures::{Cam, doc};

fn cam_json(c: &Cam, id: usize) -> Value {
    let mut settings = serde_json::Map::new();
    settings.insert("sourceindex".into(), json!(2));
    if let Some(s) = &c.source {
        settings.insert("videosourcestring".into(), json!(s));
    }
    if let Some(l) = &c.login {
        settings.insert("login".into(), json!(l));
    }
    if let Some(p) = &c.password {
        settings.insert("password".into(), json!(p));
    }
    let mut cam = json!({"id": id, "ptz": 0, "settings": settings});
    if let Some(n) = &c.name {
        cam["name"] = json!(n);
    }
    if let Some(d) = c.deleted {
        cam["deleted"] = json!(d);
    }
    cam
}

fn doc_json(cams: &[Cam]) -> String {
    let all: Vec<Value> = cams
        .iter()
        .enumerate()
        .map(|(i, c)| cam_json(c, i))
        .collect();
    json!({"cameras": all, "microphones": []}).to_string()
}

fn err(input: &str) -> E {
    match parse_json(input.as_bytes()) {
        Err(e) => e,
        Ok(i) => panic!("expected an error, got {} cameras", i.cameras.len()),
    }
}

/// A one-camera document around a `settings` value.
fn with_settings(settings: &str) -> String {
    format!(r#"{{"cameras":[{{"id":1,"name":"A","settings":{settings}}}]}}"#)
}

type Summary = (
    String,
    String,
    String,
    u16,
    String,
    Option<(String, String)>,
);

fn drafts(i: &crate::Import) -> Vec<Summary> {
    i.cameras
        .iter()
        .map(|d| {
            (
                d.id.as_str().to_owned(),
                d.name.expose().to_owned(),
                d.host.expose().clone(),
                d.port.get(),
                d.path.as_str().to_owned(),
                super::fixtures::cred(d),
            )
        })
        .collect()
}

fn sorted_logins(i: &crate::Import) -> Vec<String> {
    let mut v: Vec<String> = i.logins.iter().map(str::to_owned).collect();
    v.sort();
    v
}

#[test]
fn every_source_form_maps_as_in_xml() {
    let sources = [
        "rtsp://192.0.2.10/stream1",
        "rtsp://192.0.2.10:8554/a/b?channel=1&subtype=0",
        "RTSP://user:pw@192.0.2.10/s",
        "rtsp://user:p%40ss@192.0.2.10/s",
        "rtsp://us%3Aer:pw@192.0.2.10/s",
        "rtsp://[2001:db8::1]:554/s",
        "rtsp://192.0.2.10/user=admin&password=x",
        "rtsp://192.0.2.10/s?token=abc",
        "http://192.0.2.10/video.mjpg",
        "rtsps://192.0.2.10/s",
        "rtsp://192.0.2.10:0/s",
        "rtsp://192.0.2.10:99999/s",
        "rtsp://",
        "rtsp://192.0.2.10/s\u{1}",
        "/dev/video0",
        "",
        "  rtsp://192.0.2.10/s  ",
        "rtsp://192.0.2.10/s#frag",
        "rtsp://192.0.2.10/../s",
        "rtsp://:@192.0.2.10/s",
    ];
    let creds: [(Option<&str>, Option<&str>); 6] = [
        (None, None),
        (Some("user"), Some("pw")),
        (Some("user"), Some("")),
        (Some("  "), Some("pw")),
        (None, Some("pw")),
        (Some("other"), Some("pw2")),
    ];
    for source in sources {
        for (login, password) in creds {
            let mut c = Cam::new("Porch", source);
            c.login = login.map(str::to_owned);
            c.password = password.map(str::to_owned);
            let x = parse(doc(std::slice::from_ref(&c)).as_bytes()).unwrap();
            let j = parse_json(doc_json(std::slice::from_ref(&c)).as_bytes()).unwrap();
            let row = format!("{source:?} {login:?} {password:?}");
            assert_eq!(drafts(&x), drafts(&j), "{row}");
            let skips = |i: &crate::Import| -> Vec<_> {
                i.skipped
                    .iter()
                    .map(|s| (s.position, s.agent_id, s.reason))
                    .collect()
            };
            assert_eq!(skips(&x), skips(&j), "{row}");
            assert_eq!(sorted_logins(&x), sorted_logins(&j), "{row}");
        }
    }
}

#[test]
fn a_whole_document_matches_xml_including_deleted_and_names() {
    let mut deleted = Cam::new("Gone", "rtsp://192.0.2.11/s").login("u", "p");
    deleted.deleted = Some("true");
    let cams = [
        Cam::new("Porch", "rtsp://192.0.2.10/s").login("user", "secret"),
        deleted,
        Cam::new("Garage  Door", "rtsp://192.0.2.12/s"),
        Cam::new("Bad", "http://192.0.2.13/s"),
    ];
    let x = parse(doc(&cams).as_bytes()).unwrap();
    let j = parse_json(doc_json(&cams).as_bytes()).unwrap();
    assert_eq!(drafts(&x), drafts(&j));
    assert_eq!(x.skipped, j.skipped);
    assert_eq!(sorted_logins(&x), sorted_logins(&j));
    assert_eq!(drafts(&j).len(), 2);
    assert_eq!(drafts(&j)[1].1, "Garage Door");
}

#[test]
fn duplicate_names_are_refused_as_in_xml() {
    let cams = [
        Cam::new("Same", "rtsp://192.0.2.10/s"),
        Cam::new("Same", "rtsp://192.0.2.11/s"),
    ];
    assert_eq!(
        parse_json(doc_json(&cams).as_bytes()).unwrap_err(),
        E::DuplicateName {
            first: 0,
            second: 1
        }
    );
}

#[test]
fn id_forms() {
    // (id member as JSON text, expected camera id)
    let rows = [
        ("7", "agentdvr-7"),
        (r#""7""#, "agentdvr-7"),
        ("4294967295", "agentdvr-4294967295"),
        ("4294967296", "agentdvr-pos-0"),
        ("-1", "agentdvr-pos-0"),
        ("1.5", "agentdvr-pos-0"),
        (r#""x""#, "agentdvr-pos-0"),
        ("null", "agentdvr-pos-0"),
        ("[1]", "agentdvr-pos-0"),
        (r#"{"a":1}"#, "agentdvr-pos-0"),
        ("true", "agentdvr-pos-0"),
    ];
    for (id, want) in rows {
        let text = format!(
            r#"{{"cameras":[{{"id":{id},"name":"A","settings":{{"videosourcestring":"rtsp://192.0.2.10/s"}}}}]}}"#
        );
        let i = parse_json(text.as_bytes()).unwrap();
        assert_eq!(i.cameras[0].id.as_str(), want, "{id}");
    }
    // A repeated id falls back to the position, as in XML.
    let text = r#"{"cameras":[
        {"id":3,"name":"A","settings":{"videosourcestring":"rtsp://192.0.2.10/s"}},
        {"id":3,"name":"B","settings":{"videosourcestring":"rtsp://192.0.2.11/s"}}]}"#;
    let i = parse_json(text.as_bytes()).unwrap();
    assert_eq!(i.cameras[0].id.as_str(), "agentdvr-3");
    assert_eq!(i.cameras[1].id.as_str(), "agentdvr-pos-1");
}

#[test]
fn deleted_forms() {
    let rows = [
        ("true", true),
        (r#""true""#, true),
        (r#""TRUE""#, true),
        (r#""1""#, true),
        ("1", true),
        ("false", false),
        ("0", false),
        ("2", false),
        (r#""yes""#, false),
        ("null", false),
        ("[true]", false),
    ];
    for (d, deleted) in rows {
        let text = format!(
            r#"{{"cameras":[{{"id":1,"name":"A","deleted":{d},"settings":{{"videosourcestring":"rtsp://192.0.2.10/s"}}}}]}}"#
        );
        let i = parse_json(text.as_bytes()).unwrap();
        assert_eq!(i.cameras.is_empty(), deleted, "{d}");
        if deleted {
            assert_eq!(i.skipped[0].reason, SkipReason::Deleted);
        }
    }
}

#[test]
fn name_that_is_not_a_string_is_missing() {
    for name in ["1", "true", "null", "[]", r#"{"a":"b"}"#] {
        let text = format!(
            r#"{{"cameras":[{{"id":1,"name":{name},"settings":{{"videosourcestring":"rtsp://192.0.2.10/s"}}}}]}}"#
        );
        let i = parse_json(text.as_bytes()).unwrap();
        assert_eq!(i.skipped[0].reason, SkipReason::MissingName, "{name}");
    }
}

#[test]
fn a_member_that_is_not_text_refuses_the_whole_document() {
    // Every non-string type, for each of the three members.
    for member in ["videosourcestring", "login", "password"] {
        for value in [
            "1",
            "-1",
            "1.5",
            "true",
            "false",
            "[]",
            r#"["a"]"#,
            "{}",
            r#"{"a":"b"}"#,
        ] {
            let text = with_settings(&format!(r#"{{"{member}":{value}}}"#));
            assert_eq!(err(&text), E::FieldNotText, "{member} {value}");
        }
        // null is absent.
        let text = with_settings(&format!(r#"{{"{member}":null}}"#));
        assert!(parse_json(text.as_bytes()).is_ok(), "{member} null");
    }
}

#[test]
fn settings_that_is_not_an_object_is_refused_and_null_is_absent() {
    for s in ["1", r#""x""#, "[]", "true"] {
        assert_eq!(err(&with_settings(s)), E::WrongShape, "{s}");
    }
    let i = parse_json(with_settings("null").as_bytes()).unwrap();
    assert_eq!(i.skipped[0].reason, SkipReason::NoSource);
    let i = parse_json(br#"{"cameras":[{"id":1,"name":"A"}]}"#).unwrap();
    assert_eq!(i.skipped[0].reason, SkipReason::NoSource);
}

#[test]
fn camera_entries_that_are_not_objects_are_refused() {
    for entry in ["1", r#""x""#, "[]", "null", "true"] {
        let text = format!(r#"{{"cameras":[{entry}]}}"#);
        // `null` is a camera with nothing in it: skipped like any entry with no name.
        match parse_json(text.as_bytes()) {
            Ok(i) => assert_eq!((entry, i.skipped.len()), ("null", 1)),
            Err(e) => assert_eq!(e, E::WrongShape, "{entry}"),
        }
    }
}

#[test]
fn structure_rows() {
    let rows: [(&str, E); 12] = [
        ("", E::NotObjects),
        ("   ", E::NotObjects),
        ("[]", E::NotObjects),
        ("1", E::NotObjects),
        (r#""cameras""#, E::NotObjects),
        ("null", E::NotObjects),
        ("{}", E::NotObjects),
        (r#"{"cameras":null}"#, E::NotObjects),
        (r#"{"cameras":{}}"#, E::WrongShape),
        (
            r#"{"cameras":"wardenlens:too-many-cameras"}"#,
            E::WrongShape,
        ),
        (r#"{"cameras":[],"cameras":[]}"#, E::RepeatedMember),
        (r#"{"Cameras":[]}"#, E::NotObjects),
    ];
    for (text, want) in rows {
        assert_eq!(err(text), want, "{text}");
    }
    assert!(parse_json(br#"{"cameras":[]}"#).unwrap().cameras.is_empty());
}

#[test]
fn malformed_json_rows() {
    let rows = [
        r#"{"cameras":[}"#,
        r#"{"cameras":[],}"#,
        r#"{"cameras":[]} x"#,
        r#"{"cameras":[]}{"cameras":[]}"#,
        r#"{"cameras":[{"name":"A\x"}]}"#,
        r#"{"cameras":[{"name":"A\ud800"}]}"#,
        "{\"cameras\":[{\"name\":\"A\nB\"}]}",
        "{\"cameras\":[{\"name\":\"A\u{1}\"}]}",
        r"{'cameras':[]}",
        r#"{"cameras":[01]}"#,
        r#"{"cameras":[NaN]}"#,
        r#"{"cameras":[], // c
        }"#,
        r#"{"cameras":["#,
        r#"{"cameras":[{"name":"A"#,
    ];
    for text in rows {
        assert!(matches!(err(text), E::MalformedJson { .. }), "{text:?}");
    }
}

#[test]
fn every_prefix_of_a_valid_document_is_refused_without_panic() {
    let full = doc_json(&[
        Cam::new("Porch", "rtsp://u:p@192.0.2.10/s").login("u", "p"),
        Cam::new("Yard", "rtsp://192.0.2.11/s"),
    ]);
    for end in 0..full.len() {
        if !full.is_char_boundary(end) {
            continue;
        }
        let e = err(&full[..end]);
        assert!(
            matches!(e, E::MalformedJson { .. } | E::NotObjects),
            "{end}: {e:?}"
        );
    }
    assert!(parse_json(full.as_bytes()).is_ok());
}

#[test]
fn repeated_members_refuse_the_whole_document() {
    let rows = [
        r#"{"cameras":[{"id":1,"id":2,"name":"A"}]}"#,
        r#"{"cameras":[{"name":"A","name":"B"}]}"#,
        r#"{"cameras":[{"name":"A","settings":{},"settings":{}}]}"#,
        r#"{"cameras":[{"name":"A","settings":{"login":"a","login":"b"}}]}"#,
        r#"{"cameras":[{"name":"A","settings":{"videosourcestring":"a","videosourcestring":"b"}}]}"#,
        r#"{"cameras":[{"name":"A","settings":{"password":"a","password":"b"}}]}"#,
    ];
    for text in rows {
        assert_eq!(err(text), E::RepeatedMember, "{text}");
    }
}

#[test]
fn unknown_members_are_ignored_and_never_collected() {
    let text = r#"{"version":3,"cameras":[{"id":1,"name":"A","extra":{"login":"deep-user","password":"deep-pw"},
        "settings":{"videosourcestring":"rtsp://192.0.2.10/s","login":"user","password":"pw",
        "onvif":{"login":"o-user","password":"o-pw"},"Login":"Case","unknown":[1,2,{"x":"y"}]}}],
        "microphones":[{"settings":{"login":"mic-user","password":"mic-pw"}}]}"#;
    let i = parse_json(text.as_bytes()).unwrap();
    assert_eq!(i.cameras.len(), 1);
    let logins = sorted_logins(&i);
    assert_eq!(logins, ["pw", "user"]);
    // The member names are exact: `Login` is not `login`.
    assert!(super::fixtures::cred(&i.cameras[0]).is_some_and(|c| c.0 == "user"));
}

#[test]
fn a_bom_is_accepted_once() {
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend_from_slice(br#"{"cameras":[]}"#);
    assert!(parse_json(&bytes).is_ok());
    let mut twice = b"\xEF\xBB\xBF\xEF\xBB\xBF".to_vec();
    twice.extend_from_slice(br#"{"cameras":[]}"#);
    assert_eq!(parse_json(&twice).unwrap_err(), E::NotObjects);
}

#[test]
fn encodings() {
    assert_eq!(parse_json(b"{\"cameras\":[\xFF]}").unwrap_err(), E::NotUtf8);
    assert_eq!(parse_json(b"\xFF\xFE{\x00\"\x00").unwrap_err(), E::NotUtf8);
    // Escapes decode to the same text as the literal.
    let text = r#"{"cameras":[{"id":1,"name":"Café","settings":{"videosourcestring":"rtsp://192.0.2.10/s","login":"user","password":"p\"w"}}]}"#;
    let i = parse_json(text.as_bytes()).unwrap();
    assert_eq!(i.cameras[0].name.expose(), "Café");
    assert_eq!(
        super::fixtures::cred(&i.cameras[0]),
        Some(("user".into(), "p\"w".into()))
    );
}

fn nested(depth: usize) -> String {
    // A root object of depth 1 whose unknown member nests to `depth` in total.
    let mut s = String::from(r#"{"cameras":[],"x":"#);
    // Already inside depth 1; the array chain adds `depth - 1`.
    s.push_str(&"[".repeat(depth - 1));
    s.push_str(&"]".repeat(depth - 1));
    s.push('}');
    s
}

#[test]
fn depth_limit_at_and_over() {
    assert!(parse_json(nested(MAX_DEPTH).as_bytes()).is_ok());
    assert_eq!(err(&nested(MAX_DEPTH + 1)), E::TooDeep);
    assert_eq!(err(&nested(100_000)), E::TooDeep);
    // Depth through the camera path (cameras array 2, camera 3, settings 4, unknown below).
    let deep = format!(
        r#"{{"cameras":[{{"name":"A","settings":{{"x":{}1{}}}}}]}}"#,
        "[".repeat(MAX_DEPTH - 4),
        "]".repeat(MAX_DEPTH - 4)
    );
    assert!(parse_json(deep.as_bytes()).is_ok());
    let deeper = format!(
        r#"{{"cameras":[{{"name":"A","settings":{{"x":{}1{}}}}}]}}"#,
        "[".repeat(MAX_DEPTH - 3),
        "]".repeat(MAX_DEPTH - 3)
    );
    assert_eq!(err(&deeper), E::TooDeep);
    // Unbalanced openers beyond the limit are refused for depth before they are malformed.
    assert_eq!(err(&format!("{{{}", "[".repeat(MAX_DEPTH))), E::TooDeep);
}

#[test]
fn brackets_and_quotes_in_strings_do_not_count_as_depth() {
    let brackets = "[".repeat(MAX_DEPTH * 4);
    let text = format!(
        r#"{{"cameras":[{{"id":1,"name":"{brackets}","settings":{{"videosourcestring":"rtsp://192.0.2.10/s"}}}}]}}"#
    );
    assert!(parse_json(text.as_bytes()).is_ok());
    // An escaped quote does not end the string: the brackets after it are still text.
    let tricky = format!(
        r#"{{"cameras":[{{"id":1,"name":"a\"{brackets}","settings":{{"videosourcestring":"rtsp://192.0.2.10/s"}}}}]}}"#
    );
    assert!(parse_json(tricky.as_bytes()).is_ok());
    // An escaped backslash before the quote does end it.
    let ends = format!(
        r#"{{"cameras":[{{"name":"a\\","x":{}{}}}]}}"#,
        "[".repeat(MAX_DEPTH),
        "]".repeat(MAX_DEPTH)
    );
    assert_eq!(err(&ends), E::TooDeep);
}

fn many(n: usize) -> String {
    let one = r#"{"name":"A"}"#;
    format!(r#"{{"cameras":[{}]}}"#, vec![one; n].join(","))
}

#[test]
fn camera_count_limit_at_and_over() {
    assert_eq!(
        parse_json(many(MAX_CAMERAS).as_bytes())
            .unwrap()
            .skipped
            .len(),
        MAX_CAMERAS
    );
    assert_eq!(err(&many(MAX_CAMERAS + 1)), E::TooManyCameras);
    assert_eq!(err(&many(MAX_CAMERAS * 8)), E::TooManyCameras);
    // Entries that are not cameras at all still count.
    let nulls = format!(
        r#"{{"cameras":[{}]}}"#,
        vec!["null"; MAX_CAMERAS + 1].join(",")
    );
    assert_eq!(err(&nulls), E::TooManyCameras);
}

#[test]
fn size_limit_before_parsing() {
    let mut big = br#"{"cameras":[]"#.to_vec();
    big.resize(MAX_INPUT_BYTES + 1, b' ');
    assert_eq!(parse_json(&big).unwrap_err(), E::TooLarge);
    big.truncate(MAX_INPUT_BYTES - 1);
    big.push(b'}');
    assert_eq!(big.len(), MAX_INPUT_BYTES);
    assert!(parse_json(&big).unwrap().cameras.is_empty());
    // Over the limit and not JSON at all: the size is what is reported.
    assert_eq!(
        parse_json(&vec![b'x'; MAX_INPUT_BYTES + 1]).unwrap_err(),
        E::TooLarge
    );
}

#[test]
fn an_over_long_field_skips_the_camera_but_its_logins_are_still_collected() {
    let long = "p".repeat(MAX_FIELD_BYTES + 1);
    let text = with_settings(&format!(
        r#"{{"videosourcestring":"rtsp://192.0.2.10/s","login":"user","password":"{long}"}}"#
    ));
    let i = parse_json(text.as_bytes()).unwrap();
    assert_eq!(i.skipped[0].reason, SkipReason::FieldTooLong);
    assert!(i.logins.iter().any(|l| l == long));
    // At the limit it is kept.
    let ok = "p".repeat(MAX_FIELD_BYTES);
    let text = with_settings(&format!(
        r#"{{"videosourcestring":"rtsp://192.0.2.10/s","login":"user","password":"{ok}"}}"#
    ));
    assert_eq!(parse_json(text.as_bytes()).unwrap().cameras.len(), 1);
}

#[test]
fn logins_of_skipped_and_deleted_entries_are_collected() {
    let text = r#"{"cameras":[
        {"id":1,"name":"A","deleted":true,"settings":{"videosourcestring":"rtsp://x:y@192.0.2.10/s","login":"del-user","password":"del-pw"}},
        {"id":2,"settings":{"login":"nameless-user","password":"nameless-pw"}}]}"#;
    let i = parse_json(text.as_bytes()).unwrap();
    let l = sorted_logins(&i);
    for want in [
        "del-user",
        "del-pw",
        "nameless-user",
        "nameless-pw",
        "x",
        "y",
    ] {
        assert!(l.iter().any(|v| v == want), "{want}");
    }
}

#[test]
fn login_work_limit_refuses_the_document() {
    // Many distinct logins: past MAX_LOGINS the whole document is refused, as in XML.
    let cams: Vec<Value> = (0..MAX_CAMERAS)
        .map(|i| json!({"name": format!("C{i}"), "settings": {"login": format!("u{i}-a"), "password": format!("p{i}-b")}}))
        .collect();
    assert!(parse_json(json!({"cameras": cams}).to_string().as_bytes()).is_ok());
    let sources: Vec<String> = (0..MAX_CAMERAS)
        .map(|i| {
            let userinfo: Vec<String> = (0..40).map(|k| format!("a{i}x{k}:b{i}y{k}@")).collect();
            format!("rtsp://{}192.0.2.10/s", userinfo.join(""))
        })
        .collect();
    let cams: Vec<Value> = sources
        .iter()
        .enumerate()
        .map(|(i, s)| json!({"name": format!("C{i}"), "settings": {"videosourcestring": s}}))
        .collect();
    assert_eq!(
        parse_json(json!({"cameras": cams}).to_string().as_bytes()).unwrap_err(),
        E::TooManyLogins
    );
}

#[test]
fn no_error_carries_input_text() {
    let secret = "S3cr3t-Value";
    let inputs = [
        format!(r#"{{"cameras":[{{"name":"{secret}","settings":{{"login":{secret:?}x}}}}]}}"#),
        format!(r#"{{"cameras":"{secret}"}}"#),
        format!(r#"{{"cameras":[{{"settings":"{secret}"}}]}}"#),
        format!(r#"{{"cameras":[{{"settings":{{"password":["{secret}"]}}}}]}}"#),
        format!(r#"{{"{secret}":1"#),
        format!(r#"{{"cameras":[],"{secret}":}}"#),
        format!(r#"{{"cameras":[{{"{secret}":1,"{secret}":2,"id":"{secret}","id":1}}]}}"#),
        format!(r#"{{"cameras":[{{"settings":{{"login":"{secret}","login":"{secret}"}}}}]}}"#),
    ];
    for text in inputs {
        let e = err(&text);
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(secret), "{shown}");
    }
    // A payload that spells a sentinel of this module cannot forge its error.
    assert_eq!(
        err(r#"{"cameras":"wardenlens:too-many-cameras"}"#),
        E::WrongShape
    );
}

#[test]
fn debug_of_a_json_import_shows_no_secret() {
    let i =
        parse_json(doc_json(&[Cam::new("Porch", "rtsp://u:topsecret@192.0.2.10/s")]).as_bytes())
            .unwrap();
    assert!(!format!("{i:?}").contains("topsecret"));
}

#[test]
fn detect_rows() {
    let rows: [(&[u8], Format); 10] = [
        (b"{}", Format::Json),
        (b"  \n\t\r{\"cameras\":[]}", Format::Json),
        (b"\xEF\xBB\xBF{\"cameras\":[]}", Format::Json),
        (b"\xEF\xBB\xBF \n{", Format::Json),
        (b"<objects/>", Format::Xml),
        (b"<?xml version=\"1.0\"?><objects/>", Format::Xml),
        (b"\xEF\xBB\xBF<objects/>", Format::Xml),
        (b"", Format::Xml),
        (b"[]", Format::Xml),
        (b"garbage {", Format::Xml),
    ];
    for (bytes, want) in rows {
        assert_eq!(detect(bytes), want, "{bytes:?}");
    }
}

#[test]
fn parse_as_picks_the_reader_and_a_wrong_format_is_an_error() {
    let xml = doc(&[Cam::new("A", "rtsp://192.0.2.10/s")]);
    let js = doc_json(&[Cam::new("A", "rtsp://192.0.2.10/s")]);
    assert_eq!(
        parse_as(Format::Xml, xml.as_bytes()).unwrap().cameras.len(),
        1
    );
    assert_eq!(
        parse_as(Format::Json, js.as_bytes()).unwrap().cameras.len(),
        1
    );
    assert_eq!(
        parse_as(Format::Json, xml.as_bytes()).unwrap_err(),
        E::NotObjects
    );
    assert!(parse_as(Format::Xml, js.as_bytes()).is_err());
}
