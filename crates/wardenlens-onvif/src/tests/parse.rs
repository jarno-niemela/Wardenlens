//! The pure parsers on synthetic envelopes. Input spaces enumerated: the three reply failures
//! (empty, fault, malformed) for every parser; each mandatory element; each field boundary;
//! profile selection.

use super::fixtures::*;
use crate::{
    OnvifError, Profile, ProfileToken, VideoEncoding, parse_device_information, parse_profiles,
    parse_stream_uri, pick_streams,
};

type Parser = fn(&[u8]) -> Result<(), OnvifError>;

/// Every parser, reduced to its error, so one table covers them all.
fn all_parsers() -> [(&'static str, Parser); 3] {
    [
        ("device", |b| parse_device_information(b).map(|_| ())),
        ("profiles", |b| parse_profiles(b).map(|_| ())),
        ("stream", |b| parse_stream_uri(b).map(|_| ())),
    ]
}

#[test]
fn happy_paths() {
    let d = parse_device_information(good_device_info().as_bytes()).expect("device");
    assert_eq!(
        (
            d.manufacturer.as_str(),
            d.model.as_str(),
            d.firmware_version.as_str(),
            d.serial_number.as_str(),
            d.hardware_id.as_str()
        ),
        ("Acme", "Cam-1", "1.2.3", "SN0001", "HW-7")
    );
    let p = parse_profiles(good_profiles().as_bytes()).expect("profiles");
    assert_eq!(p.len(), 2);
    assert_eq!(p[0].token.as_str(), "main_tok");
    assert_eq!((p[0].width, p[0].height), (2560, 1440));
    assert_eq!(p[0].encoding, VideoEncoding::H264);
    assert_eq!(p[0].name.as_deref(), Some("Main"));
    let s = parse_stream_uri(good_stream_uri().as_bytes()).expect("uri");
    assert_eq!(s.path.as_str(), "/stream1");
    assert_eq!(s.port.get(), 554);
}

#[test]
fn empty_reply_is_typed_for_every_parser() {
    for (name, parse) in all_parsers() {
        for body in ["", " ", "\r\n\t  \n"] {
            assert_eq!(
                parse(body.as_bytes()),
                Err(OnvifError::EmptyReply),
                "{name} {body:?}"
            );
        }
    }
}

#[test]
fn soap_faults_are_typed_for_every_parser() {
    let faults = [
        (
            fault("ter:NotAuthorized", "Sender not authorized"),
            OnvifError::NotAuthorized,
        ),
        (fault("NotAuthorized", "x"), OnvifError::NotAuthorized),
        (fault("ter:InvalidArgVal", "bad"), OnvifError::SoapFault),
        (
            fault("ter:NotAuthorizedAtAll", "bad"),
            OnvifError::SoapFault,
        ),
        (fault("", ""), OnvifError::SoapFault),
        // SOAP 1.1 shape, no Value element at all
        (
            env(
                "<env:Fault><faultcode>env:Server</faultcode><faultstring>NotAuthorized</faultstring></env:Fault>",
            ),
            OnvifError::SoapFault,
        ),
    ];
    for (name, parse) in all_parsers() {
        for (body, want) in &faults {
            assert_eq!(parse(body.as_bytes()), Err(*want), "{name}");
        }
    }
}

#[test]
fn malformed_xml_is_typed_for_every_parser() {
    let good = good_device_info();
    let rows: Vec<(&str, String)> = vec![
        ("not xml", "hello".to_owned()),
        ("mismatched", "<a><b></a></b>".to_owned()),
        ("unclosed", "<a><b>".to_owned()),
        ("text outside root", format!("{good}trailing")),
        ("two roots", format!("{good}<a/>")),
        ("unknown entity", env("<a>&foo;</a>")),
        ("nul char ref", env("<a>&#0;</a>")),
        ("control char ref", env("<a>&#x1;</a>")),
        ("raw control char", env("<a>\u{1}</a>")),
        ("duplicate attribute", env("<a x=\"1\" x=\"2\"/>")),
        ("angle in attribute", env("<a x=\"<\"/>")),
        ("unterminated attribute", "<a x=\"1></a>".to_owned()),
        ("late declaration", "<a/><?xml version=\"1.0\"?>".to_owned()),
        (
            "double declaration",
            "<?xml version=\"1.0\"?><?xml version=\"1.0\"?><a/>".to_owned(),
        ),
        ("lone close", "</a>".to_owned()),
        ("only a comment", "<!-- x -->".to_owned()),
    ];
    for (name, parse) in all_parsers() {
        for (label, body) in &rows {
            assert!(
                matches!(parse(body.as_bytes()), Err(OnvifError::Malformed { .. })),
                "{name}: {label}: {:?}",
                parse(body.as_bytes())
            );
        }
    }
}

#[test]
fn doctype_and_entities_are_refused_for_every_parser() {
    let rows = [
        "<!DOCTYPE a><a/>",
        "<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>",
        "<!DOCTYPE a SYSTEM \"http://192.0.2.1/x.dtd\"><a/>",
        // billion laughs
        "<?xml version=\"1.0\"?><!DOCTYPE l [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;\">]><l>&b;&b;&b;&b;</l>",
    ];
    for (name, parse) in all_parsers() {
        for body in rows {
            assert_eq!(
                parse(body.as_bytes()),
                Err(OnvifError::DocType),
                "{name}: {body}"
            );
        }
    }
    // Inside a well-formed envelope, too.
    let inside =
        good_device_info().replace("<env:Envelope", "<!DOCTYPE env:Envelope><env:Envelope");
    assert_eq!(
        parse_device_information(inside.as_bytes()).err(),
        Some(OnvifError::DocType)
    );
}

#[test]
fn encoding_rows() {
    let utf16 = good_device_info().replace("UTF-8", "UTF-16");
    assert_eq!(
        parse_device_information(utf16.as_bytes()).err(),
        Some(OnvifError::UnsupportedEncoding)
    );
    let latin = good_device_info().replace("UTF-8", "ISO-8859-1");
    assert_eq!(
        parse_device_information(latin.as_bytes()).err(),
        Some(OnvifError::UnsupportedEncoding)
    );
    let mut bad = good_device_info().into_bytes();
    bad.extend_from_slice(&[0xFF, 0xFE]);
    assert_eq!(
        parse_device_information(&bad).err(),
        Some(OnvifError::NotUtf8)
    );
    // UTF-16 bytes with a BOM are not UTF-8.
    assert_eq!(
        parse_device_information(&[0xFF, 0xFE, b'<', 0]).err(),
        Some(OnvifError::NotUtf8)
    );
    // A UTF-8 BOM is fine; a lower-case encoding name too.
    let bom = format!("\u{FEFF}{}", good_device_info().replace("UTF-8", "utf-8"));
    assert!(parse_device_information(bom.as_bytes()).is_ok());
    // No declaration at all is fine.
    let bare = good_device_info().replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
    assert!(parse_device_information(bare.as_bytes()).is_ok());
}

#[test]
fn wrong_shape_names_the_missing_element() {
    let rows: [(&str, String, &str); 4] = [
        ("html", "<html><body/></html>".to_owned(), "Envelope"),
        ("no body", format!("<env:Envelope {NS}/>"), "Body"),
        ("empty body", env(""), "GetDeviceInformationResponse"),
        (
            "other response",
            env("<tds:Other/>"),
            "GetDeviceInformationResponse",
        ),
    ];
    for (label, body, element) in rows {
        assert_eq!(
            parse_device_information(body.as_bytes()),
            Err(OnvifError::MissingElement { element }),
            "{label}"
        );
    }
    assert_eq!(
        parse_profiles(env("<trt:GetStreamUriResponse/>").as_bytes()),
        Err(OnvifError::MissingElement {
            element: "GetProfilesResponse"
        })
    );
    assert_eq!(
        parse_stream_uri(env("<trt:GetStreamUriResponse/>").as_bytes()),
        Err(OnvifError::MissingElement { element: "Uri" })
    );
    assert_eq!(
        parse_stream_uri(
            env("<trt:GetStreamUriResponse><trt:MediaUri/></trt:GetStreamUriResponse>").as_bytes()
        ),
        Err(OnvifError::MissingElement { element: "Uri" })
    );
}

#[test]
fn every_device_field_is_mandatory() {
    for name in [
        "Manufacturer",
        "Model",
        "FirmwareVersion",
        "SerialNumber",
        "HardwareId",
    ] {
        let open = format!("<tds:{name}>");
        let close = format!("</tds:{name}>");
        let full = good_device_info();
        let from = full.find(&open).expect("open");
        let to = full.find(&close).expect("close") + close.len();
        let cut = format!("{}{}", &full[..from], &full[to..]);
        let want = OnvifError::MissingElement {
            element: [
                "Manufacturer",
                "Model",
                "FirmwareVersion",
                "SerialNumber",
                "HardwareId",
            ]
            .into_iter()
            .find(|n| *n == name)
            .expect("name"),
        };
        assert_eq!(
            parse_device_information(cut.as_bytes()),
            Err(want),
            "{name}"
        );
    }
}

#[test]
fn device_field_boundaries_and_content() {
    let exact = "m".repeat(256);
    let over = "m".repeat(257);
    assert!(parse_device_information(device_info(&exact, "x", "x", "x", "x").as_bytes()).is_ok());
    assert!(
        parse_device_information(device_info(&exact[..255], "x", "x", "x", "x").as_bytes()).is_ok()
    );
    assert_eq!(
        parse_device_information(device_info(&over, "x", "x", "x", "x").as_bytes()),
        Err(OnvifError::InvalidField {
            field: "Manufacturer"
        })
    );
    // 256 characters of 2 bytes is 512 bytes: bytes count, not chars.
    let wide = "\u{e9}".repeat(129);
    assert_eq!(
        parse_device_information(device_info("a", &wide, "x", "x", "x").as_bytes()),
        Err(OnvifError::InvalidField { field: "Model" })
    );
    // Control characters, however spelled.
    for bad in [
        "a&#9;b",
        "a&#10;b",
        "a&#x7F;b",
        "a&#x85;b",
        "a<![CDATA[\u{7}]]>b",
    ] {
        assert!(
            parse_device_information(device_info("a", "x", bad, "x", "x").as_bytes()).is_err(),
            "{bad}"
        );
    }
    // Trimmed; entities and CDATA decoded; multibyte kept.
    let d = parse_device_information(
        device_info("  A&amp;B \n", "<![CDATA[<c>]]>", "\u{1F600}", "x", "x").as_bytes(),
    )
    .expect("ok");
    assert_eq!(d.manufacturer, "A&B");
    assert_eq!(d.model, "<c>");
    assert_eq!(d.firmware_version, "\u{1F600}");
    // Empty is allowed (the element is present).
    assert_eq!(
        parse_device_information(device_info("", "x", "x", "x", "x").as_bytes())
            .expect("ok")
            .manufacturer,
        ""
    );
    // Text over the keep limit (4096) in a field is an error even when trimming would fit.
    let huge = format!("{}x", " ".repeat(4100));
    assert_eq!(
        parse_device_information(device_info(&huge, "x", "x", "x", "x").as_bytes()),
        Err(OnvifError::InvalidField {
            field: "Manufacturer"
        })
    );
}

#[test]
fn profile_dimension_table() {
    let rows: [(&str, Option<u32>); 14] = [
        ("1", Some(1)),
        ("65535", Some(65535)),
        ("65536", None),
        ("0", None),
        ("00", None),
        ("-1", None),
        ("+1", None),
        ("1e3", None),
        ("1.0", None),
        ("0x10", None),
        ("", None),
        ("abc", None),
        ("99999999999", None),
        ("1 0", None),
    ];
    for (text, want) in rows {
        for (w, h) in [(text, "10"), ("10", text)] {
            let r = parse_profiles(profiles(&[profile("t", "n", w, h, "H264")]).as_bytes());
            match want {
                Some(v) => {
                    let p = r.expect("ok");
                    assert_eq!(p[0].width.max(p[0].height), v.max(10), "{text}");
                }
                None => assert!(
                    matches!(
                        r,
                        Err(OnvifError::InvalidField {
                            field: "Width" | "Height"
                        })
                    ),
                    "{text:?}: {r:?}"
                ),
            }
        }
    }
}

#[test]
fn profile_token_table() {
    let long = "a".repeat(65);
    let exact = "a".repeat(64);
    let rows: [(&str, bool); 12] = [
        ("Profile_1", true),
        ("a.b:c-d_E9", true),
        (&exact, true),
        (&long, false),
        ("has space", false),
        ("a&lt;b", false),
        ("a&quot;b", false),
        ("caf\u{e9}", false),
        ("a/b", false),
        ("a%41", false),
        ("a&#10;b", false),
        ("", false),
    ];
    for (token, ok) in rows {
        let r = parse_profiles(profiles(&[profile(token, "n", "10", "10", "H264")]).as_bytes());
        assert_eq!(r.is_ok(), ok, "{token:?}: {r:?}");
        if !ok {
            assert_eq!(r.err(), Some(OnvifError::InvalidField { field: "token" }));
        }
    }
    // Missing token attribute; over-long attribute (cut and flagged).
    let missing = profiles(&[profile("t", "n", "10", "10", "H264").replace(" token=\"t\"", "")]);
    assert_eq!(
        parse_profiles(missing.as_bytes()).err(),
        Some(OnvifError::InvalidField { field: "token" })
    );
    let huge = "a".repeat(300);
    assert_eq!(
        parse_profiles(profiles(&[profile(&huge, "n", "10", "10", "H264")]).as_bytes()).err(),
        Some(OnvifError::InvalidField { field: "token" })
    );
}

#[test]
fn profiles_without_video_are_skipped_and_duplicates_refused() {
    let audio =
        r#"<trt:Profiles token="audio_only"><tt:Name>A</tt:Name></trt:Profiles>"#.to_owned();
    let r = parse_profiles(
        profiles(&[audio.clone(), profile("v", "V", "10", "10", "H264")]).as_bytes(),
    )
    .expect("ok");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].token.as_str(), "v");
    assert_eq!(
        parse_profiles(profiles(&[audio]).as_bytes()).expect("ok"),
        vec![]
    );
    assert_eq!(
        parse_profiles(profiles(&[]).as_bytes()).expect("ok"),
        vec![]
    );
    let dup = profiles(&[
        profile("same", "A", "10", "10", "H264"),
        profile("same", "B", "20", "20", "H264"),
    ]);
    assert_eq!(
        parse_profiles(dup.as_bytes()).err(),
        Some(OnvifError::InvalidField { field: "token" })
    );
    // Missing resolution under an encoder.
    let no_res = r#"<trt:Profiles token="t"><tt:VideoEncoderConfiguration><tt:Encoding>H264</tt:Encoding></tt:VideoEncoderConfiguration></trt:Profiles>"#;
    assert_eq!(
        parse_profiles(profiles(&[no_res.to_owned()]).as_bytes()).err(),
        Some(OnvifError::MissingElement {
            element: "Resolution"
        })
    );
    // A bad name is refused, not dropped.
    let bad_name = profile("t", "a&#9;b", "10", "10", "H264");
    assert_eq!(
        parse_profiles(profiles(&[bad_name]).as_bytes()).err(),
        Some(OnvifError::InvalidField { field: "Name" })
    );
}

#[test]
fn profile_count_boundary() {
    let many = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| profile(&format!("p{i}"), "n", "10", "10", "H264"))
            .collect()
    };
    assert_eq!(
        parse_profiles(profiles(&many(32)).as_bytes())
            .expect("ok")
            .len(),
        32
    );
    assert_eq!(
        parse_profiles(profiles(&many(33)).as_bytes()).err(),
        Some(OnvifError::TooManyProfiles)
    );
    assert_eq!(
        parse_profiles(profiles(&many(31)).as_bytes())
            .expect("ok")
            .len(),
        31
    );
}

#[test]
fn encoding_table() {
    let rows = [
        ("H264", VideoEncoding::H264),
        ("h264", VideoEncoding::H264),
        ("H265", VideoEncoding::H265),
        ("JPEG", VideoEncoding::Jpeg),
        ("MPEG4", VideoEncoding::Mpeg4),
        ("AV1", VideoEncoding::Other),
        ("", VideoEncoding::Other),
    ];
    for (text, want) in rows {
        let p = parse_profiles(profiles(&[profile("t", "n", "10", "10", text)]).as_bytes())
            .expect("ok");
        assert_eq!(p[0].encoding, want, "{text}");
    }
}

fn prof(token: &str, w: u32, h: u32) -> Profile {
    parse_profiles(
        profiles(&[profile(token, "n", &w.to_string(), &h.to_string(), "H264")]).as_bytes(),
    )
    .expect("profile")
    .remove(0)
}

#[test]
fn pick_streams_table() {
    assert!(pick_streams(&[]).is_none());
    let one = [prof("a", 1920, 1080)];
    let c = pick_streams(&one).expect("choice");
    assert_eq!(c.main.token.as_str(), "a");
    assert!(c.sub.is_none());

    let two = [prof("sub", 640, 360), prof("main", 2560, 1440)];
    let c = pick_streams(&two).expect("choice");
    assert_eq!(
        (c.main.token.as_str(), c.sub.map(|p| p.token.as_str())),
        ("main", Some("sub"))
    );

    // Equal resolution: one stream, no sub.
    let same = [prof("a", 1280, 720), prof("b", 1280, 720)];
    let c = pick_streams(&same).expect("choice");
    assert_eq!(c.main.token.as_str(), "a");
    assert!(c.sub.is_none());

    // Three: largest and smallest.
    let three = [
        prof("mid", 1920, 1080),
        prof("small", 320, 240),
        prof("big", 3840, 2160),
    ];
    let c = pick_streams(&three).expect("choice");
    assert_eq!(
        (c.main.token.as_str(), c.sub.map(|p| p.token.as_str())),
        ("big", Some("small"))
    );

    // Ordered by pixel count, not by width: 1080x1920 has the same pixels as 1920x1080.
    let rot = [
        prof("land", 1920, 1080),
        prof("port", 1080, 1920),
        prof("sub", 640, 480),
    ];
    let c = pick_streams(&rot).expect("choice");
    assert_eq!(
        (c.main.token.as_str(), c.sub.map(|p| p.token.as_str())),
        ("land", Some("sub"))
    );
    // Wide but short loses to taller with more pixels.
    let shape = [prof("wide", 4000, 100), prof("tall", 1000, 1000)];
    assert_eq!(
        pick_streams(&shape).expect("choice").main.token.as_str(),
        "tall"
    );

    // Input order does not change the answer when pixels are all different.
    let mut rev = three.to_vec();
    rev.reverse();
    let c = pick_streams(&rev).expect("choice");
    assert_eq!(
        (c.main.token.as_str(), c.sub.map(|p| p.token.as_str())),
        ("big", Some("small"))
    );
    // Max size does not overflow.
    let max = [prof("m", 65535, 65535), prof("s", 1, 1)];
    assert_eq!(
        pick_streams(&max).expect("choice").sub.map(Profile::pixels),
        Some(1)
    );
}

#[test]
fn profile_token_new_is_the_one_validator() {
    assert!(ProfileToken::new("ok-1").is_ok());
    assert_eq!(
        ProfileToken::new("a b").err(),
        Some(OnvifError::InvalidToken)
    );
    assert_eq!(ProfileToken::new("").err(), Some(OnvifError::InvalidToken));
}

#[test]
fn stream_uri_reply_bounds() {
    let long = format!("rtsp://192.0.2.1/{}", "a".repeat(4100));
    assert_eq!(
        parse_stream_uri(stream_uri(&long).as_bytes()).err(),
        Some(OnvifError::InvalidField { field: "Uri" })
    );
    // Whitespace around the URI is trimmed.
    assert!(parse_stream_uri(stream_uri("\n  rtsp://192.0.2.1/x \n").as_bytes()).is_ok());
}

#[test]
fn fault_text_never_reaches_the_error() {
    let body = fault("ter:Boom", "FAULT-TEXT-SENTINEL");
    for (_, parse) in all_parsers() {
        let e = parse(body.as_bytes()).expect_err("fault");
        assert!(!format!("{e} {e:?}").contains("SENTINEL"));
    }
}
