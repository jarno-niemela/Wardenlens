//! Adversary tests for #226 (PR #230): `objects.json` against the XML reader as an oracle, and
//! the JSON reader's own limits. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration-test helpers outside #[test] fns"
)]

use std::fmt::Write as _;

use proptest::prelude::*;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use wardenlens_agentdvr::{
    Format, Import, ImportError as E, MAX_CAMERAS, MAX_DEPTH, MAX_INPUT_BYTES, detect, parse,
    parse_json,
};

/// One camera of a generated document; `None` is an absent member.
#[derive(Debug, Clone)]
struct Cam {
    id: Option<u32>,
    name: Option<String>,
    deleted: Option<bool>,
    source: Option<String>,
    login: Option<String>,
    password: Option<String>,
}

/// Every character as a numeric reference, so XML carries exactly the same text as JSON.
fn xml_text(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            write!(out, "&#{};", u32::from(c)).unwrap();
        }
    }
    out
}

fn xml_doc(cams: &[Cam]) -> String {
    let mut out = String::from("<objects><cameras>");
    for c in cams {
        out.push_str("<camera");
        if let Some(id) = c.id {
            write!(out, " id=\"{id}\"").unwrap();
        }
        if let Some(n) = &c.name {
            write!(out, " name=\"{}\"", xml_text(n)).unwrap();
        }
        if let Some(d) = c.deleted {
            write!(out, " deleted=\"{d}\"").unwrap();
        }
        out.push_str("><settings>");
        for (tag, v) in [
            ("videosourcestring", &c.source),
            ("login", &c.login),
            ("password", &c.password),
        ] {
            if let Some(v) = v {
                write!(out, "<{tag}>{}</{tag}>", xml_text(v)).unwrap();
            }
        }
        out.push_str("</settings></camera>");
    }
    out.push_str("</cameras></objects>");
    out
}

fn json_doc(cams: &[Cam]) -> String {
    let all: Vec<Value> = cams
        .iter()
        .map(|c| {
            let mut s = serde_json::Map::new();
            if let Some(v) = &c.source {
                s.insert("videosourcestring".into(), json!(v));
            }
            if let Some(v) = &c.login {
                s.insert("login".into(), json!(v));
            }
            if let Some(v) = &c.password {
                s.insert("password".into(), json!(v));
            }
            let mut o = serde_json::Map::new();
            if let Some(id) = c.id {
                o.insert("id".into(), json!(id));
            }
            if let Some(n) = &c.name {
                o.insert("name".into(), json!(n));
            }
            if let Some(d) = c.deleted {
                o.insert("deleted".into(), json!(d));
            }
            o.insert("settings".into(), Value::Object(s));
            Value::Object(o)
        })
        .collect();
    json!({ "cameras": all }).to_string()
}

type Summary = (
    Vec<(
        String,
        String,
        String,
        u16,
        String,
        Option<(String, String)>,
    )>,
    Vec<String>,
    Vec<String>,
);

fn summary(r: Result<Import, E>) -> Result<Summary, String> {
    let i = r.map_err(|e| format!("{e:?}"))?;
    let cams = i
        .cameras
        .iter()
        .map(|d| {
            (
                d.id.as_str().to_owned(),
                d.name.expose().to_owned(),
                d.host.expose().clone(),
                d.port.get(),
                d.path.as_str().to_owned(),
                d.credential
                    .as_ref()
                    .map(|c| (c.user.clone(), c.password.expose_secret().to_owned())),
            )
        })
        .collect();
    let skipped = i.skipped.iter().map(|s| format!("{s:?}")).collect();
    let mut logins: Vec<String> = i.logins.iter().map(str::to_owned).collect();
    logins.sort();
    Ok((cams, skipped, logins))
}

/// `%u` to the JSON `\\u` escape (kept out of the source so no tool decodes it).
fn esc(doc: &str) -> String {
    doc.replace("%u", "\\u")
}

fn json_err(input: &str) -> E {
    match parse_json(input.as_bytes()) {
        Err(e) => e,
        Ok(i) => panic!("expected an error, got {} cameras", i.cameras.len()),
    }
}

// ---------------------------------------------------------------------------------------------
// Parity: XML as the oracle.

fn piece() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just(" ".to_owned()),
        Just("admin".to_owned()),
        Just("pa:ss".to_owned()),
        Just("p@ss".to_owned()),
        Just("p%40ss".to_owned()),
        Just("é".to_owned()),
        Just("\u{a0}".to_owned()),
        Just("\"<&>\\".to_owned()),
        Just("\t".to_owned()),
        Just("\u{1F600}".to_owned()),
        Just("Cam".to_owned()),
        "[a-zA-Z0-9 ._~-]{0,6}",
    ]
}

fn source() -> impl Strategy<Value = String> {
    (
        prop_oneof![
            Just("rtsp://"),
            Just("RTSP://"),
            Just("http://"),
            Just("rtsps://")
        ],
        prop::option::of((piece(), prop::option::of(piece()))),
        prop_oneof![
            Just("192.0.2.1"),
            Just("cam.example"),
            Just("[2001:db8::1]"),
            Just("h")
        ],
        prop_oneof![
            Just(""),
            Just(":554"),
            Just(":0"),
            Just(":99999"),
            Just(":8554")
        ],
        prop_oneof![
            Just(""),
            Just("/"),
            Just("/live/ch0"),
            Just("/cam/realmonitor?channel=1&subtype=0"),
            Just("/x?user=admin&password=secret"),
            Just("/p%20q"),
        ],
    )
        .prop_map(|(scheme, ui, host, port, path)| {
            let ui = match ui {
                None => String::new(),
                Some((u, None)) => format!("{u}@"),
                Some((u, Some(p))) => format!("{u}:{p}@"),
            };
            format!("{scheme}{ui}{host}{port}{path}")
        })
}

fn cam() -> impl Strategy<Value = Cam> {
    (
        prop::option::of(0_u32..6),
        prop::option::of(prop_oneof![piece(), Just("Porch".to_owned())]),
        prop::option::of(any::<bool>()),
        prop::option::of(prop_oneof![source(), piece()]),
        prop::option::of(piece()),
        prop::option::of(piece()),
    )
        .prop_map(|(id, name, deleted, source, login, password)| Cam {
            id,
            name,
            deleted,
            source,
            login,
            password,
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, .. ProptestConfig::default() })]

    /// Every generated document gives the same drafts, skips, logins (or the same error) in both
    /// formats.
    #[test]
    fn json_and_xml_of_the_same_cameras_agree(cams in prop::collection::vec(cam(), 0..5)) {
        let x = summary(parse(xml_doc(&cams).as_bytes()));
        let j = summary(parse_json(json_doc(&cams).as_bytes()));
        prop_assert_eq!(j, x);
    }
}

/// Every UTF-16 unit of `s` as a JSON escape: the parser's unescaping path for every string.
fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for u in s.encode_utf16() {
        write!(out, "%u{u:04x}").unwrap();
    }
    out.push('"');
    esc(&out)
}

/// As `json_doc`, but keys and values fully escaped and members in reverse order.
fn json_doc_escaped(cams: &[Cam]) -> String {
    let mut out = format!("{{{}:[", jstr("cameras"));
    for (i, c) in cams.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut s = Vec::new();
        for (k, v) in [
            ("password", &c.password),
            ("login", &c.login),
            ("videosourcestring", &c.source),
        ] {
            if let Some(v) = v {
                s.push(format!("{}:{}", jstr(k), jstr(v)));
            }
        }
        let mut o = vec![format!("{}:{{{}}}", jstr("settings"), s.join(","))];
        if let Some(d) = c.deleted {
            o.push(format!("{}:{d}", jstr("deleted")));
        }
        if let Some(n) = &c.name {
            o.push(format!("{}:{}", jstr("name"), jstr(n)));
        }
        if let Some(id) = c.id {
            o.push(format!("{}:{}", jstr("id"), jstr(&id.to_string())));
        }
        write!(out, "{{{}}}", o.join(",")).unwrap();
    }
    out.push_str("]}");
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, .. ProptestConfig::default() })]

    /// Fully escaped JSON (keys too, ids as digit strings, reversed member order) still agrees
    /// with XML.
    #[test]
    fn fully_escaped_json_agrees_with_xml(cams in prop::collection::vec(cam(), 0..5)) {
        let x = summary(parse(xml_doc(&cams).as_bytes()));
        let j = summary(parse_json(json_doc_escaped(&cams).as_bytes()));
        prop_assert_eq!(j, x);
    }
}

/// The generator reaches imported cameras, credentials and skips (TEST-8: the parity proptest is
/// not vacuous).
#[test]
fn the_parity_generator_reaches_imports_credentials_and_skips() {
    let cams = vec![
        Cam {
            id: Some(1),
            name: Some("Porch".into()),
            deleted: None,
            source: Some("rtsp://admin:p@ss@192.0.2.1/live/ch0".into()),
            login: None,
            password: None,
        },
        Cam {
            id: Some(2),
            name: Some("\"<&>\\".into()),
            deleted: Some(false),
            source: Some("rtsp://cam.example/live".into()),
            login: Some("admin".into()),
            password: Some("é\u{1F600}".into()),
        },
        Cam {
            id: None,
            name: Some("Gone".into()),
            deleted: Some(true),
            source: Some("rtsp://h/".into()),
            login: None,
            password: None,
        },
    ];
    let x = summary(parse(xml_doc(&cams).as_bytes())).unwrap();
    let j = summary(parse_json(json_doc(&cams).as_bytes())).unwrap();
    assert_eq!(j, x);
    assert!(j.0.iter().any(|c| c.5.is_some()), "{:?}", j.0.len());
    assert_ne!(j.1.len(), 0);
}

// ---------------------------------------------------------------------------------------------
// Repeated members, also when spelled with escapes.

#[test]
fn a_key_repeated_through_an_escape_refuses_the_document() {
    for doc in [
        r#"{"cameras":[{"name":"A","settings":{"login":"a","log%u0069n":"b"}}]}"#,
        r#"{"cameras":[{"name":"A","settings":{"password":"a","p%u0061ssword":"b"}}]}"#,
        r#"{"cameras":[{"name":"A","n%u0061me":"B","settings":{}}]}"#,
        r#"{"cameras":[],"c%u0061meras":[{"name":"A"}]}"#,
        r#"{"cameras":[{"name":"A","settings":{},"s%u0065ttings":{"login":"x"}}]}"#,
    ] {
        let doc = &esc(doc);
        assert!(doc.contains("\\u00"));
        assert!(
            matches!(json_err(doc), E::RepeatedMember),
            "{doc}: {:?}",
            json_err(doc)
        );
    }
}

#[test]
fn an_escaped_key_is_the_same_key() {
    let doc = esc(
        r#"{"c%u0061meras":[{"n%u0061me":"Porch","settings":{"videosourcestring":"rtsp://192.0.2.1/live","p%u0061ssword":"s3cret","login":"admin"}}]}"#,
    );
    let i = parse_json(doc.as_bytes()).unwrap();
    assert_eq!(i.cameras.len(), 1);
    let c = i.cameras[0].credential.as_ref().unwrap();
    assert_eq!(c.user, "admin");
    assert_eq!(c.password.expose_secret(), "s3cret");
}

#[test]
fn an_escaped_password_is_collected_unescaped() {
    let doc = esc(
        r#"{"cameras":[{"name":"A","settings":{"videosourcestring":"rtsp://192.0.2.1/x","login":"u","password":"s%u0065cr\"et"}}]}"#,
    );
    let i = parse_json(doc.as_bytes()).unwrap();
    let got: Vec<&str> = i.logins.iter().collect();
    assert!(got.contains(&"secr\"et"), "{} logins", got.len());
}

// ---------------------------------------------------------------------------------------------
// The sentinel error text cannot be forged by input.

#[test]
fn input_that_spells_the_sentinel_is_not_too_many_cameras() {
    let s = "wardenlens:too-many-cameras";
    for doc in [
        format!(r#"{{"cameras":"{s}"}}"#),
        format!(r#"{{"cameras":["{s}"]}}"#),
        format!(r#"{{"cameras":[{{"name":"A","settings":"{s}"}}]}}"#),
        format!(r#"{{"{s}":1,"cameras":[{{"{s}":"{s}","settings":["{s}"]}}]}}"#),
    ] {
        let e = json_err(&doc);
        assert!(matches!(e, E::WrongShape), "{doc}: {e:?}");
    }
}

#[test]
fn camera_limit_counts_null_entries_and_is_exact() {
    let at = format!(r#"{{"cameras":[{}]}}"#, vec!["null"; MAX_CAMERAS].join(","));
    let i = parse_json(at.as_bytes()).unwrap();
    assert_eq!(i.skipped.len(), MAX_CAMERAS);
    let over = format!(
        r#"{{"cameras":[{}]}}"#,
        vec!["null"; MAX_CAMERAS + 1].join(",")
    );
    assert!(matches!(json_err(&over), E::TooManyCameras));
}

// ---------------------------------------------------------------------------------------------
// Depth: string-aware, exact.

fn deep_array(depth_inside: usize) -> String {
    // Root object (depth 1) + `depth_inside` arrays in an ignored member.
    format!(
        r#"{{"cameras":[],"x":{}{}}}"#,
        "[".repeat(depth_inside),
        "]".repeat(depth_inside)
    )
}

#[test]
fn depth_after_tricky_strings_is_still_counted() {
    for prefix in [
        r#""\\""#,
        r#""\"""#,
        r#""\\\"""#,
        r#""\\\\""#,
        r#""{[""#,
        r#""""#,
    ] {
        let ok = format!(
            r#"{{"a":{prefix},"cameras":[],"x":{}{}}}"#,
            "[".repeat(MAX_DEPTH - 1),
            "]".repeat(MAX_DEPTH - 1)
        );
        assert!(parse_json(ok.as_bytes()).is_ok(), "{prefix} at the limit");
        let over = format!(
            r#"{{"a":{prefix},"cameras":[],"x":{}{}}}"#,
            "[".repeat(MAX_DEPTH),
            "]".repeat(MAX_DEPTH)
        );
        assert!(
            matches!(json_err(&over), E::TooDeep),
            "{prefix} one over: {:?}",
            json_err(&over)
        );
    }
}

#[test]
fn depth_boundary_is_exact() {
    assert!(parse_json(deep_array(MAX_DEPTH - 1).as_bytes()).is_ok());
    assert!(matches!(json_err(&deep_array(MAX_DEPTH)), E::TooDeep));
}

#[test]
fn deep_nesting_to_the_input_cap_is_refused_quickly_without_overflow() {
    let n = MAX_INPUT_BYTES / 2 - 8;
    let doc = format!("{{\"x\":{}{}}}", "[".repeat(n), "]".repeat(n));
    assert!(matches!(json_err(&doc), E::TooDeep));
}

// ---------------------------------------------------------------------------------------------
// DoS: huge numbers, many keys, long strings, many escapes, all within the size cap.

fn timed(doc: &str) -> Result<Import, E> {
    assert!(doc.len() <= MAX_INPUT_BYTES, "{}", doc.len());
    parse_json(doc.as_bytes())
}

#[test]
fn a_huge_ignored_number_is_bounded() {
    let digits = "9".repeat(MAX_INPUT_BYTES - 64);
    let doc = format!(r#"{{"cameras":[],"n":{digits}}}"#);
    let _ = timed(&doc);
    let doc = format!(r#"{{"cameras":[],"n":0.{digits}e5}}"#);
    let _ = timed(&doc);
}

#[test]
fn a_huge_id_or_deleted_number_is_no_id_and_not_deleted() {
    // Past u64 (an f64 to serde) but finite.
    let digits = "9".repeat(300);
    let doc = format!(
        r#"{{"cameras":[{{"id":{digits},"deleted":{digits},"name":"A","settings":{{"videosourcestring":"rtsp://192.0.2.1/x"}}}}]}}"#
    );
    let i = timed(&doc).unwrap();
    assert_eq!(i.cameras.len(), 1);
}

#[test]
fn out_of_range_exponents_are_malformed_not_a_panic() {
    for n in ["1e400", "-1e400", "1e99999999999999999999"] {
        let doc = format!(r#"{{"cameras":[{{"id":{n},"name":"A"}}]}}"#);
        let e = json_err(&doc);
        assert!(matches!(e, E::MalformedJson { .. }), "{n}: {e:?}");
    }
}

#[test]
fn many_keys_and_many_escapes_are_bounded() {
    let mut doc = String::from(r#"{"cameras":[],"#);
    let mut k = 0_u64;
    while doc.len() < MAX_INPUT_BYTES - 64 {
        write!(doc, r#""k{k}":0,"#).unwrap();
        k += 1;
    }
    doc.push_str(r#""z":0}"#);
    timed(&doc).unwrap();

    // Six-byte `\\u00e9` escapes, built at run time, in an ignored member.
    let esc = format!("\\{}00e9", 'u').repeat((MAX_INPUT_BYTES - 200) / 6);
    let doc =
        format!(r#"{{"cameras":[{{"name":"A","x":"{esc}","settings":{{"password":"p"}}}}]}}"#);
    let i = timed(&doc).unwrap();
    assert_eq!(i.skipped.len(), 1);
}

#[test]
fn many_cameras_with_long_distinct_passwords_hit_the_login_cap_not_memory() {
    // 256 cameras, each with a ~30 KiB distinct password: 7.5 MiB, over MAX_LOGIN_BYTES.
    let mut cams = Vec::new();
    for i in 0..MAX_CAMERAS {
        let pw = format!("{i:04}{}", "p".repeat(30_000));
        cams.push(json!({"name": format!("C{i}"), "settings": {"password": pw}}));
    }
    let doc = json!({ "cameras": cams }).to_string();
    let e = match timed(&doc) {
        Err(e) => e,
        Ok(i) => panic!("accepted {} logins", i.logins.len()),
    };
    assert!(matches!(e, E::TooManyLogins), "{e:?}");
}

// ---------------------------------------------------------------------------------------------
// Encoding: characters JSON can carry that XML cannot.

#[test]
fn control_characters_xml_cannot_carry_are_refused_per_camera() {
    let src = "rtsp://192.0.2.1/x";
    for (name, source, login) in [
        ("A\\u0000", src, "u"),
        ("A\\u001b[2J", src, "u"),
        ("A\\u0007", src, "u"),
        ("A\\u007f", src, "u"),
        ("A", "rtsp://192.0.2.1/x\\u0000y", "u"),
        ("A", "rtsp://192.0.2.1/x\\u001b", "u"),
        ("A", src, "u\\u0000"),
        ("A", src, "u\\u001b"),
        ("A", src, "u\\r\\nX: y"),
    ] {
        let doc = format!(
            r#"{{"cameras":[{{"name":"{name}","settings":{{"videosourcestring":"{source}","login":"{login}","password":"p"}}}}]}}"#
        );
        let i = parse_json(doc.as_bytes()).unwrap();
        assert!(
            i.cameras.is_empty(),
            "{name} / {source} / {login}: imported"
        );
        assert_eq!(i.skipped.len(), 1);
    }
}

#[test]
fn surrogate_escapes() {
    let lone = &esc(r#"{"cameras":[{"name":"%ud800","settings":{}}]}"#);
    assert!(matches!(json_err(lone), E::MalformedJson { .. }));
    let lone_pw = &esc(r#"{"cameras":[{"name":"A","settings":{"password":"%udc00x"}}]}"#);
    assert!(matches!(json_err(lone_pw), E::MalformedJson { .. }));
    let pair = esc(
        r#"{"cameras":[{"name":"Cam %ud83d%ude00","settings":{"videosourcestring":"rtsp://192.0.2.1/x"}}]}"#,
    );
    let i = parse_json(pair.as_bytes()).unwrap();
    assert_eq!(i.cameras.len(), 1);
}

#[test]
fn raw_control_and_invalid_utf8_are_refused_without_echo() {
    let raw = "{\"cameras\":[{\"name\":\"A\",\"settings\":{\"password\":\"s3cr\u{1}t\"}}]}";
    let e = json_err(raw);
    assert!(matches!(e, E::MalformedJson { .. }), "{e:?}");
    assert!(!e.to_string().contains("s3cr"));
    let mut bad = br#"{"cameras":[{"name":"A","settings":{"password":"s3cr"#.to_vec();
    bad.extend_from_slice(b"\xff\"}}]}");
    assert!(matches!(parse_json(&bad), Err(E::NotUtf8)));
}

// ---------------------------------------------------------------------------------------------
// Detection.

#[test]
fn detection_rows() {
    let rows: [(&[u8], Format); 9] = [
        (b"\xEF\xBB\xBF{", Format::Json),
        (b"\xEF\xBB\xBF \r\n\t{", Format::Json),
        (b"\xEF\xBB\xBF\xEF\xBB\xBF{", Format::Xml),
        (b"\x0c{", Format::Xml),
        (b"\x00{", Format::Xml),
        (b" [", Format::Xml),
        (b"<objects/>{", Format::Xml),
        (b"\xEF\xBB", Format::Xml),
        (b"", Format::Xml),
    ];
    for (bytes, want) in rows {
        assert_eq!(detect(bytes), want, "{bytes:?}");
    }
}

#[test]
fn a_detected_json_with_bom_and_whitespace_parses() {
    let doc = b"\xEF\xBB\xBF \r\n{\"cameras\":[]}";
    assert_eq!(detect(doc), Format::Json);
    assert!(parse_json(doc).is_ok());
}

#[test]
fn a_bom_after_whitespace_is_not_skipped() {
    let doc = " \u{FEFF}{\"cameras\":[]}";
    assert!(parse_json(doc.as_bytes()).is_err());
}

// ---------------------------------------------------------------------------------------------
// Errors carry no input, for every refusal this reader can return.

#[test]
fn no_json_refusal_echoes_a_secret() {
    let s = "SeKr1tXyZ";
    let docs = [
        format!(
            r#"{{"cameras":[{{"name":"A","settings":{{"password":"{s}","password":"{s}"}}}}]}}"#
        ),
        format!(r#"{{"cameras":[{{"name":"A","settings":"rtsp://u:{s}@h/"}}]}}"#),
        format!(r#"{{"cameras":["rtsp://u:{s}@h/"]}}"#),
        format!(r#"{{"cameras":[{{"name":"A","settings":{{"password":["{s}"]}}}}]}}"#),
        format!(r#"{{"cameras":[{{"name":"A","settings":{{"password":"{s}"#),
        format!(r#"{{"cameras":[{{"name":"A","settings":{{"password":"{s}\q"}}}}]}}"#),
        format!(r#"{{"cameras":[]}} "{s}""#),
        format!(r#"{{"{s}"}}"#),
    ];
    for d in &docs {
        let e = json_err(d);
        assert!(!e.to_string().contains(s), "{e}");
        assert!(!format!("{e:?}").contains(s), "{e:?}");
    }
}
