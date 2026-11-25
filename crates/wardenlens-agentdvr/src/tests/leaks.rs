//! Invariant 1: no credential, host, path or name text in any error, skip reason, `Debug` or
//! `Display` output, whatever the input (SEC-6). Enumerated over every error variant, every skip
//! reason, every odd userinfo spelling and every downstream failure.

use crate::{ImportError, MAX_CAMERAS, MAX_DEPTH, MAX_INPUT_BYTES, SkipReason, parse};

use super::ALL_SKIPS;
use super::fixtures::{Cam, doc, esc, wrap};

const PW: &str = "Pw-S3ntinel-9x";
const USER: &str = "Us-S3ntinel-7q";
const HOST: &str = "host-s3ntinel.example";
const PATH: &str = "p-s3ntinel";
const NAME: &str = "Nm-S3ntinel-5z";

/// Every fragment that must never be printed: the sentinels, lower-cased, plus the encoded form.
fn needles() -> Vec<String> {
    let mut v = Vec::new();
    for s in [PW, USER, HOST, PATH, NAME] {
        v.push(s.to_ascii_lowercase());
        v.push("s3ntinel".to_owned());
    }
    v.push("p%40ss".into());
    v.sort();
    v.dedup();
    v
}

fn assert_clean(shown: &str, what: &str) {
    let lower = shown.to_ascii_lowercase();
    for n in needles() {
        assert!(!lower.contains(&n), "{what} leaks {n:?}: {shown}");
    }
}

/// All the renderings of a parse result: `Debug`, pretty `Debug`, and `Display` of the error and
/// of each skip reason.
fn render(r: &Result<crate::Import, ImportError>) -> String {
    let mut out = format!("{r:?}\n{r:#?}\n");
    match r {
        Err(e) => out.push_str(&format!("{e}\n{e:?}\n")),
        Ok(i) => {
            for s in &i.skipped {
                out.push_str(&format!("{} {:?} {:#?}\n", s.reason, s, s));
            }
            for c in &i.cameras {
                out.push_str(&format!("{c:?}\n{c:#?}\n"));
                // The credential is the one field with no Display.
                out.push_str(&format!("{:?}\n", c.credential));
            }
        }
    }
    out
}

/// A camera with a plain name (a camera id is derived from the name and is not sensitive) and
/// sentinel login fields.
fn sentinel_cam(source: &str) -> Cam {
    Cam::new("Camera", source).login(USER, PW)
}

fn url(userinfo: &str, host: &str, tail: &str) -> String {
    format!("rtsp://{userinfo}{host}{tail}")
}

#[test]
#[expect(clippy::too_many_lines, reason = "a data table of cases")]
fn every_import_error_variant_is_produced_and_clean() {
    let mut ok_cam = sentinel_cam(&url(&format!("{USER}:{PW}@"), HOST, &format!("/{PATH}")));
    ok_cam.name = Some(NAME.to_owned());
    let good = doc(&[ok_cam.clone()]);
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut too_large = good.clone().into_bytes();
    too_large.resize(MAX_INPUT_BYTES + 1, b' ');
    cases.push(("TooLarge", too_large));
    let mut bad_utf8 = good.clone().into_bytes();
    bad_utf8.push(0xFF);
    cases.push(("NotUtf8", bad_utf8));
    cases.push((
        "UnsupportedEncoding",
        format!("<?xml version=\"1.0\" encoding=\"{PW}\"?>{}", wrap("")).into_bytes(),
    ));
    cases.push((
        "DocType",
        format!("<!DOCTYPE {USER} [<!ENTITY {PW} \"{HOST}\">]><objects/>").into_bytes(),
    ));
    cases.push((
        "Malformed",
        good.replace("<login>", &format!("<login {USER}=\"1\" {USER}=\"{PW}\">"))
            .into_bytes(),
    ));
    cases.push((
        "Malformed",
        format!("<objects><{USER}></{PW}></objects>").into_bytes(),
    ));
    cases.push(("Malformed", good.as_bytes()[..good.len() / 2].to_vec()));
    cases.push((
        "Malformed",
        format!("<objects>&{PW};</objects>").into_bytes(),
    ));
    cases.push((
        "TooDeep",
        format!("<objects>{}", format!("<{USER}>").repeat(MAX_DEPTH + 1)).into_bytes(),
    ));
    cases.push((
        "TooManyCameras",
        doc(&vec![ok_cam.clone(); MAX_CAMERAS + 1]).into_bytes(),
    ));
    cases.push(("NotObjects", format!("<{USER} a=\"{PW}\"/>").into_bytes()));
    cases.push((
        "DuplicateName",
        doc(&[ok_cam.clone(), ok_cam.clone()]).into_bytes(),
    ));
    let mut seen = std::collections::HashSet::new();
    for (label, bytes) in cases {
        let r = parse(&bytes);
        let e = r.as_ref().err().unwrap_or_else(|| panic!("{label} parsed"));
        seen.insert(std::mem::discriminant(e));
        assert_clean(&render(&r), label);
    }
    // All nine variants were reached (the match forces a new variant to be listed).
    let variants = [
        ImportError::TooLarge,
        ImportError::NotUtf8,
        ImportError::UnsupportedEncoding,
        ImportError::DocType,
        ImportError::Malformed { position: 0 },
        ImportError::TooDeep,
        ImportError::TooManyCameras,
        ImportError::NotObjects,
        ImportError::DuplicateName,
    ];
    for v in variants {
        match v {
            ImportError::TooLarge
            | ImportError::NotUtf8
            | ImportError::UnsupportedEncoding
            | ImportError::DocType
            | ImportError::Malformed { .. }
            | ImportError::TooDeep
            | ImportError::TooManyCameras
            | ImportError::NotObjects
            | ImportError::DuplicateName => {}
        }
        assert!(
            seen.contains(&std::mem::discriminant(&v)),
            "{v:?} not produced"
        );
        assert_clean(&format!("{v} {v:?}"), "variant text");
    }
}

fn skip_case(reason: SkipReason) -> Cam {
    let good = url(&format!("{USER}:{PW}@"), HOST, &format!("/{PATH}"));
    let mut c = sentinel_cam(&good);
    match reason {
        SkipReason::Deleted => c.deleted = Some("true"),
        SkipReason::RepeatedElement => c.source = Some(good.clone()),
        SkipReason::FieldTooLong => c.source = Some(format!("{good}{}", "a".repeat(5000))),
        SkipReason::MissingName => c.name = None,
        SkipReason::NameRefused => c.name = Some("!!!".into()),
        SkipReason::NoSource => c.source = None,
        SkipReason::NotAUrl => c.source = Some(format!("{USER} {PW} {HOST}")),
        SkipReason::UnsupportedScheme => {
            c.source = Some(format!("http://{USER}:{PW}@{HOST}/{PATH}"));
        }
        SkipReason::InvalidUrl => c.source = Some(format!("{good}\u{1}")),
        SkipReason::InvalidHost => c.source = Some(url(&format!("{USER}:{PW}@"), "bad host", "/s")),
        SkipReason::InvalidPort => {
            c.source = Some(url(
                &format!("{USER}:{PW}@"),
                &format!("{HOST}:99999"),
                "/s",
            ));
        }
        SkipReason::InvalidPath => c.source = Some(format!("{good}%20{PW}")),
        SkipReason::CredentialInPath => {
            c.source = Some(url("", HOST, &format!("/user={USER}&password={PW}")));
        }
        SkipReason::InvalidCredential => c.password = Some(format!("{PW}\u{7f}")),
    }
    c
}

#[test]
fn every_skip_reason_is_produced_and_clean() {
    for reason in ALL_SKIPS {
        let cam = skip_case(reason);
        let r = if reason == SkipReason::RepeatedElement {
            let xml = doc(&[cam]).replace(
                "</settings>",
                &format!(
                    "<videosourcestring>rtsp://{USER}:{PW}@{HOST}/x</videosourcestring></settings>"
                ),
            );
            parse(xml.as_bytes())
        } else {
            parse(doc(&[cam]).as_bytes())
        };
        let import = r.as_ref().expect("document parses");
        assert!(import.cameras.is_empty(), "{reason:?}");
        assert_eq!(import.skipped.len(), 1, "{reason:?}");
        assert_eq!(import.skipped[0].reason, reason);
        assert_clean(&render(&r), &format!("{reason:?}"));
        assert_clean(&reason.to_string(), "skip display");
    }
}

/// Every userinfo spelling an attacker or an odd camera can write.
fn userinfos() -> Vec<String> {
    let u = USER;
    let p = PW;
    vec![
        format!("{u}:{p}@"),
        format!("{u}@"),
        format!(":{p}@"),
        format!("{u}:@"),
        format!("{u}:{p}@{p}@"),
        format!("{u}:p@ss{p}@"),
        format!("{u}:p%40ss{p}@"),
        format!("{u}%40x:{p}@"),
        format!("{u}%3Ax:{p}@"),
        format!("{u}:a:b:{p}@"),
        format!("{u}:{p}%00@"),
        format!("{u}:{p}%0d%0a@"),
        format!("{u}:{p}%FF@"),
        format!("{u}:{p}/x@"),
        format!("{u}:{p}?x@"),
        format!("{u}:{p}#x@"),
        format!("{u}:{p}%@"),
        format!("{u}:caf\u{e9}{p}@"),
        format!("{u}:{p}\u{7f}@"),
        format!("%{}:{p}@", &u[..2]),
    ]
}

/// Every way the rest of the URL can be good or bad.
fn tails() -> Vec<(String, String)> {
    let h = HOST.to_owned();
    vec![
        (h.clone(), format!("/{PATH}")),
        (h.clone(), format!("/{PATH}?q=1")),
        (h.clone(), String::new()),
        (format!("{h}:8554"), format!("/{PATH}")),
        (format!("{h}:99999"), "/s".into()),
        (format!("{h}:0"), "/s".into()),
        (format!("{h}:{PW}"), "/s".into()),
        ("[2001:db8::1]".into(), format!("/{PATH}")),
        ("[2001:db8::1".into(), "/s".into()),
        ("bad host".into(), "/s".into()),
        (String::new(), "/s".into()),
        (h.clone(), format!("/{PATH}%20")),
        (h.clone(), format!("/{PATH}#f")),
        (h.clone(), format!("/user={USER}&password={PW}")),
        (h.clone(), format!("/s?pass={PW}")),
        (h, format!("/{PATH}/../x")),
    ]
}

#[test]
fn no_userinfo_spelling_and_no_failure_leaks() {
    let mut combos = 0_usize;
    for ui in userinfos() {
        for (host, tail) in tails() {
            for scheme in ["rtsp", "RTSP", "http", "rtsps"] {
                let src = format!("{scheme}://{ui}{host}{tail}");
                // Login fields present as well: the URL userinfo is not used, the fields are.
                for fields in [false, true] {
                    let cam = if fields {
                        sentinel_cam(&src)
                    } else {
                        Cam::new("Cam", &src)
                    };
                    let r = parse(doc(&[cam]).as_bytes());
                    assert_clean(&render(&r), &src);
                    combos += 1;
                }
            }
        }
    }
    assert!(combos > 1000);
}

#[test]
fn draft_debug_shows_no_host_path_name_or_credential() {
    let cam = Cam::new(
        "Plain Name",
        &url(&format!("{USER}:{PW}@"), HOST, &format!("/{PATH}")),
    );
    let i = parse(doc(&[cam]).as_bytes()).expect("parses");
    assert_eq!(i.cameras.len(), 1);
    let shown = render(&Ok(i));
    assert_clean(&shown, "draft");
    assert!(!shown.contains("Plain Name"));
}

#[test]
fn xml_text_is_never_echoed_by_any_xml_error() {
    // Element names, attribute names, entity names and text are all attacker text.
    let rows = [
        format!("<objects><{USER}></{PW}></objects>"),
        format!("<objects {USER}=\"1\" {USER}=\"2\"/>"),
        format!("<objects>&{USER};</objects>"),
        format!("<objects {USER}=&{PW};/>"),
        format!("<objects a=\"{PW}\" b=\"{PW}/>"),
        format!("<objects><![CDATA[{PW}</objects>"),
        format!("<objects><!-- {PW}</objects>"),
        format!("<{USER}/><{PW}/>"),
        PW.to_owned(),
        format!("<objects/>{PW}"),
        format!(
            "<objects><camera name=\"{}\"/></objects>",
            esc(PW).repeat(3)
        ),
    ];
    for d in rows {
        let r = parse(d.as_bytes());
        assert_clean(&render(&r), &d);
    }
}
