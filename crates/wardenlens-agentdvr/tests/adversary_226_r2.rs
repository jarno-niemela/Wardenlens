//! Adversary round 2 for #226 (PR #230): the typed stop cell and the mapping of every serde
//! error path to its own variant. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns"
)]

use std::fmt::Write as _;
use std::sync::{Arc, Barrier};

use wardenlens_agentdvr::{ImportError as E, MAX_CAMERAS, parse, parse_json};

fn kind(doc: &str) -> String {
    match parse_json(doc.as_bytes()) {
        Ok(i) => format!("ok {} {}", i.cameras.len(), i.skipped.len()),
        Err(e) => {
            let d = format!("{e:?}");
            d.split([' ', '{', '(']).next().unwrap().to_owned()
        }
    }
}

const GOOD: &str = r#"{"cameras":[{"id":1,"name":"Porch","settings":{"videosourcestring":"rtsp://10.0.0.9/a","login":"u","password":"p"}}]}"#;

fn too_many() -> String {
    let items = vec!["null"; MAX_CAMERAS + 1].join(",");
    format!(r#"{{"cameras":[{items}]}}"#)
}

#[test]
fn every_wrong_structural_type_is_wrong_shape() {
    for bad in ["{}", "[]", "\"x\"", "1", "-1", "1.5", "true", "false"] {
        let rows = [
            (format!(r#"{{"cameras":{bad}}}"#), bad == "[]"),
            (format!(r#"{{"cameras":[{bad}]}}"#), bad == "{}"),
            (
                format!(r#"{{"cameras":[{{"settings":{bad}}}]}}"#),
                bad == "{}",
            ),
        ];
        for (doc, fine) in rows {
            let got = kind(&doc);
            if fine {
                assert!(got.starts_with("ok"), "{doc} -> {got}");
            } else {
                assert_eq!(got, "WrongShape", "{doc}");
            }
        }
    }
}

#[test]
fn every_watched_member_repeated_is_repeated_even_when_both_are_null() {
    let cases = [
        r#"{"cameras":null,"cameras":null}"#.to_owned(),
        r#"{"cameras":[],"cameras":[]}"#.to_owned(),
        r#"{"cameras":[{"id":null,"id":null}]}"#.to_owned(),
        r#"{"cameras":[{"name":"a","name":"a"}]}"#.to_owned(),
        r#"{"cameras":[{"deleted":false,"deleted":false}]}"#.to_owned(),
        r#"{"cameras":[{"settings":null,"settings":null}]}"#.to_owned(),
        r#"{"cameras":[{"settings":{"login":null,"login":null}}]}"#.to_owned(),
        r#"{"cameras":[{"settings":{"password":"p","password":"p"}}]}"#.to_owned(),
        r#"{"cameras":[{"settings":{"videosourcestring":"rtsp://h/","videosourcestring":"rtsp://h/"}}]}"#.to_owned(),
    ];
    for doc in cases {
        assert_eq!(kind(&doc), "RepeatedMember", "{doc}");
    }
}

#[test]
fn repeats_inside_ignored_subtrees_and_case_variants_are_not_refused() {
    for doc in [
        r#"{"x":{"a":1,"a":2},"x":3,"cameras":[]}"#,
        r#"{"cameras":[{"extra":{"login":"a","login":"b"},"extra":1,"name":"N"}]}"#,
        r#"{"cameras":[{"settings":{"login":"a","Login":"b","LOGIN":"c","z":{"password":1,"password":2}}}]}"#,
        r#"{"cameras":[{"name":"a","Name":"b"}]}"#,
    ] {
        assert!(kind(doc).starts_with("ok"), "{doc} -> {}", kind(doc));
    }
}

#[test]
fn each_parse_gets_its_own_stop_reason_in_any_order_on_one_thread() {
    let docs: Vec<(String, &str)> = vec![
        (
            r#"{"cameras":[{"id":1,"id":2}]}"#.to_owned(),
            "RepeatedMember",
        ),
        (r#"{"cameras":{}}"#.to_owned(), "WrongShape"),
        (too_many(), "TooManyCameras"),
        (r#"{"cameras":[}"#.to_owned(), "MalformedJson"),
        (r#"{"cameras":["#.to_owned(), "MalformedJson"),
        (r#"{"cameras":[]} x"#.to_owned(), "MalformedJson"),
        (
            r#"{"cameras":[{"settings":{"login":1}}]}"#.to_owned(),
            "FieldNotText",
        ),
        (r#"{"cameras":null}"#.to_owned(), "NotObjects"),
        (GOOD.to_owned(), "ok 1 0"),
    ];
    // Every ordered pair, so a reason left over from the first parse would show in the second.
    for (a, want_a) in &docs {
        for (b, want_b) in &docs {
            assert_eq!(kind(a), *want_a, "{a}");
            // An XML parse in between must not disturb the JSON state either.
            assert!(parse(b"<objects><cameras/></objects>").is_ok());
            assert_eq!(kind(b), *want_b, "{a} then {b}");
        }
    }
}

#[test]
fn concurrent_parses_do_not_share_a_stop_reason() {
    let docs: Vec<(String, &'static str)> = vec![
        (
            r#"{"cameras":[{"name":"a","name":"b"}]}"#.to_owned(),
            "RepeatedMember",
        ),
        (too_many(), "TooManyCameras"),
        (r#"{"cameras":[{"settings":[]}]}"#.to_owned(), "WrongShape"),
        (GOOD.to_owned(), "ok 1 0"),
    ];
    let rounds = 200;
    let barrier = Arc::new(Barrier::new(docs.len()));
    let handles: Vec<_> = docs
        .into_iter()
        .map(|(doc, want)| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                for _ in 0..rounds {
                    barrier.wait();
                    assert_eq!(kind(&doc), want);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn a_refusal_after_the_limit_is_reached_is_still_too_many_cameras() {
    // Element MAX+1 holds a repeat: the repeat is parsed first and wins (it comes first in the
    // text); element MAX+1 clean, then a repeat later in the root: too many wins.
    let mut items = vec!["null".to_owned(); MAX_CAMERAS];
    items.push(r#"{"id":1}"#.to_owned());
    let doc = format!(r#"{{"cameras":[{}],"cameras":[]}}"#, items.join(","));
    assert_eq!(kind(&doc), "TooManyCameras");
    items.pop();
    items.push(r#"{"id":1,"id":1}"#.to_owned());
    let doc = format!(r#"{{"cameras":[{}]}}"#, items.join(","));
    assert_eq!(kind(&doc), "RepeatedMember");
}

#[test]
fn no_new_error_variant_text_carries_input() {
    let marker = "Zq9SECRETzq9";
    let docs = [
        format!(r#"{{"cameras":[{{"settings":"{marker}"}}]}}"#),
        format!(r#"{{"cameras":"{marker}"}}"#),
        format!(r#"{{"cameras":["{marker}"]}}"#),
        format!(r#"{{"cameras":[{{"{marker}":1,"name":"{marker}","name":"{marker}"}}]}}"#),
        format!(
            r#"{{"cameras":[{{"settings":{{"password":"{marker}","password":"{marker}"}}}}]}}"#
        ),
        format!(r#"{{"cameras":[{{"settings":{{"login":["{marker}"]}}}}]}}"#),
        format!(r#"{{"cameras":[{{"settings":{{"login":"{marker}" "{marker}"}}}}]}}"#),
        format!(r#"{{"cameras":[{{"settings":{{"login":"{marker}\q"}}}}]}}"#),
        format!(r#"{{"{marker}":{marker}}}"#),
    ];
    for doc in docs {
        let e: E = parse_json(doc.as_bytes()).err().unwrap();
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(marker), "{doc} -> {shown}");
        assert!(!shown.contains("Zq9"), "{doc} -> {shown}");
    }
}

fn outcome(r: Result<wardenlens_agentdvr::Import, E>) -> String {
    match r {
        Err(e) => format!("err {e:?}"),
        Ok(i) => {
            let cams: Vec<String> = i
                .cameras
                .iter()
                .map(|d| format!("{}|{}", d.id.as_str(), d.path.as_str()))
                .collect();
            let skipped: Vec<String> = i.skipped.iter().map(|s| format!("{s:?}")).collect();
            format!("{cams:?} {skipped:?} {}", i.logins.iter().count())
        }
    }
}

#[test]
fn id_and_deleted_spellings_agree_with_xml() {
    // (JSON literal, XML attribute text) of the same value.
    let ids = [
        ("\"007\"", "007"),
        ("\"+5\"", "+5"),
        ("\" 5\"", " 5"),
        ("\"4294967295\"", "4294967295"),
        ("\"4294967296\"", "4294967296"),
        ("\"-0\"", "-0"),
        ("\"\"", ""),
    ];
    for (j, x) in ids {
        let json = format!(
            r#"{{"cameras":[{{"id":{j},"name":"A","settings":{{"videosourcestring":"rtsp://10.0.0.9/a"}}}}]}}"#
        );
        let xml = format!(
            r#"<objects><cameras><camera id="{x}" name="A"><settings><videosourcestring>rtsp://10.0.0.9/a</videosourcestring></settings></camera></cameras></objects>"#
        );
        assert_eq!(
            outcome(parse_json(json.as_bytes())),
            outcome(parse(xml.as_bytes())),
            "id {j}"
        );
    }
    let deleted = [
        ("\"TRUE\"", "TRUE"),
        ("\"1\"", "1"),
        ("\"yes\"", "yes"),
        ("\" true\"", " true"),
        ("\"0\"", "0"),
    ];
    for (j, x) in deleted {
        let json = format!(
            r#"{{"cameras":[{{"deleted":{j},"name":"A","settings":{{"videosourcestring":"rtsp://10.0.0.9/a"}}}}]}}"#
        );
        let xml = format!(
            r#"<objects><cameras><camera deleted="{x}" name="A"><settings><videosourcestring>rtsp://10.0.0.9/a</videosourcestring></settings></camera></cameras></objects>"#
        );
        assert_eq!(
            outcome(parse_json(json.as_bytes())),
            outcome(parse(xml.as_bytes())),
            "deleted {j}"
        );
    }
}

#[test]
fn over_long_fields_agree_with_xml() {
    for n in [4095_usize, 4096, 4097, 9000] {
        let long = "p".repeat(n);
        for field in ["videosourcestring", "login", "password"] {
            let mut s = vec![
                ("videosourcestring", "rtsp://10.0.0.9/a".to_owned()),
                ("login", "u".to_owned()),
            ];
            s.retain(|(k, _)| *k != field);
            let value = if field == "videosourcestring" {
                format!("rtsp://10.0.0.9/{long}")
            } else {
                long.clone()
            };
            s.push((field, value));
            let json_s: Vec<String> = s.iter().map(|(k, v)| format!(r#""{k}":"{v}""#)).collect();
            let xml_s: String = s.iter().fold(String::new(), |mut out, (k, v)| {
                write!(out, "<{k}>{v}</{k}>").unwrap();
                out
            });
            let json = format!(
                r#"{{"cameras":[{{"name":"A","settings":{{{}}}}}]}}"#,
                json_s.join(",")
            );
            let xml = format!(
                r#"<objects><cameras><camera name="A"><settings>{xml_s}</settings></camera></cameras></objects>"#
            );
            assert_eq!(
                outcome(parse_json(json.as_bytes())),
                outcome(parse(xml.as_bytes())),
                "{field} {n}"
            );
        }
    }
}
