//! Invariant 5 and the limits: hostile and malformed XML, one row per form (TEST-9).
//!
//! Enumeration: DOCTYPE (internal subset, entity declarations, external SYSTEM and PUBLIC,
//! billion laughs, lower case, after the root); entity references (undefined, unterminated,
//! predefined, numeric, illegal numeric); nesting (at the limit, one over, absurdly deep);
//! truncation (every prefix); encodings (invalid UTF-8 forms, UTF-16 byte order marks, a UTF-8
//! BOM, declared encodings); size and count limits (-1, exact, +1); structure (wrong root, none,
//! two roots, text outside the root, mismatched tags, duplicate attributes, unquoted
//! attributes); constructs that must be accepted (comments, PIs, CDATA, unknown content).

use crate::{ImportError as E, MAX_CAMERAS, MAX_DEPTH, MAX_INPUT_BYTES, parse};

use super::fixtures::{Cam, doc, wrap};

fn err(input: &[u8]) -> E {
    match parse(input) {
        Err(e) => e,
        Ok(i) => panic!(
            "expected an error, got {} cameras and {} skipped for {:?}",
            i.cameras.len(),
            i.skipped.len(),
            String::from_utf8_lossy(&input[..input.len().min(200)])
        ),
    }
}

fn is_malformed(e: E) -> bool {
    matches!(e, E::Malformed { .. })
}

const LAUGHS: &str = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><objects><cameras><camera id=\"1\" name=\"&lol3;\"/></cameras></objects>";

#[test]
fn doctype_forms_are_refused() {
    let rows: Vec<String> = vec![
        LAUGHS.into(),
        "<!DOCTYPE objects><objects/>".into(),
        "<!doctype objects><objects/>".into(),
        "<!DOCTYPE objects SYSTEM \"file:///etc/passwd\"><objects/>".into(),
        "<!DOCTYPE objects PUBLIC \"-//x\" \"http://192.0.2.1/x.dtd\"><objects/>".into(),
        "<!DOCTYPE objects [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><objects><cameras><camera id=\"1\" name=\"&xxe;\"/></cameras></objects>".into(),
        "<!DOCTYPE objects [<!ENTITY % p SYSTEM \"http://192.0.2.1/e.dtd\"> %p;]><objects/>".into(),
        "<objects><!DOCTYPE objects></objects>".into(),
        "<objects/><!DOCTYPE objects>".into(),
        "<?xml version=\"1.0\"?>\n<!-- c -->\n<!DOCTYPE objects [ ]>\n<objects/>".into(),
    ];
    for d in rows {
        assert_eq!(err(d.as_bytes()), E::DocType, "{d}");
    }
}

#[test]
fn a_large_entity_expansion_never_happens() {
    // Without the DOCTYPE the entities are undefined: still refused, and nothing expands.
    let d = LAUGHS.replace("<!DOCTYPE", "<!-- ").replace("]>", " -->");
    assert!(is_malformed(err(d.as_bytes())));
}

#[test]
fn entity_references_table() {
    let bad: [&str; 11] = [
        "&foo;",
        "&amp",
        "&",
        "&;",
        "&#;",
        "&#x;",
        "&#0;",
        "&#x1;",
        "&#xD800;",
        "&#1114112;",
        "&#99999999999999999999;",
    ];
    for r in bad {
        let in_name = wrap(&format!("<camera id=\"1\" name=\"a{r}b\"/>"));
        let in_text = wrap(&format!(
            "<camera id=\"1\" name=\"a\"><settings><login>{r}</login></settings></camera>"
        ));
        let in_ignored = wrap(&format!("<camera id=\"1\" name=\"a\"><x>{r}</x></camera>"));
        let in_other_attr = wrap(&format!("<camera id=\"1\" name=\"a\" zzz=\"{r}\"/>"));
        let in_root_attr = format!("<objects q=\"{r}\"/>");
        for d in [in_name, in_text, in_ignored, in_other_attr, in_root_attr] {
            assert!(is_malformed(err(d.as_bytes())), "{r} in {d}");
        }
    }
    // Predefined and numeric references are fine, in attributes and text.
    let d = wrap("<camera id=\"1\" name=\"a&amp;&lt;&gt;&quot;&apos;&#65;&#x42;\"/>");
    assert_eq!(parse(d.as_bytes()).expect("ok").skipped.len(), 1); // no source, but parsed
}

#[test]
fn nesting_limit_boundaries() {
    let nest = |depth: usize| {
        let mut s = String::from("<objects>");
        for _ in 1..depth {
            s.push_str("<a>");
        }
        for _ in 1..depth {
            s.push_str("</a>");
        }
        s.push_str("</objects>");
        s
    };
    assert!(parse(nest(MAX_DEPTH).as_bytes()).is_ok());
    assert_eq!(err(nest(MAX_DEPTH + 1).as_bytes()), E::TooDeep);
    assert_eq!(err(nest(MAX_DEPTH + 2).as_bytes()), E::TooDeep);
    // Absurd depth, also unclosed: refused at the limit, no recursion, no allocation per level.
    let mut s = String::from("<objects>");
    s.push_str(&"<a>".repeat(1_000_000));
    assert_eq!(err(s.as_bytes()), E::TooDeep);
    // Depth is counted inside a camera too.
    let d = wrap(&format!(
        "<camera id=\"1\" name=\"a\">{}{}</camera>",
        "<x>".repeat(MAX_DEPTH),
        "</x>".repeat(MAX_DEPTH)
    ));
    assert_eq!(err(d.as_bytes()), E::TooDeep);
}

#[test]
fn every_proper_prefix_of_a_valid_document_is_refused() {
    let cams = [
        Cam::new(
            "Caf\u{e9} \u{4e2d}",
            "rtsp://user:secret@192.0.2.10/s?a=1&b=2",
        )
        .login("u", "p"),
        Cam::new("B", "rtsp://192.0.2.11/s"),
    ];
    let full = doc(&cams);
    let end = full.find("</objects>").expect("root end") + "</objects>".len();
    assert!(parse(full.as_bytes()).is_ok());
    for n in 0..end {
        let r = parse(&full.as_bytes()[..n]);
        assert!(r.is_err(), "prefix of {n} bytes was accepted");
    }
    // The trailing newline after the root may be cut.
    assert!(parse(&full.as_bytes()[..end]).is_ok());
}

#[test]
fn invalid_utf8_forms() {
    let good = doc(&[Cam::new("A", "rtsp://192.0.2.10/s")]);
    let at = good.find("name=\"A\"").expect("name") + "name=\"".len();
    for bad in [
        &[0xFF][..],
        &[0x80],
        &[0xC0, 0x80],
        &[0xC3],
        &[0xE2, 0x82],
        &[0xED, 0xA0, 0x80],
        &[0xF4, 0x90, 0x80, 0x80],
        &[0xF8, 0x88, 0x80, 0x80, 0x80],
    ] {
        let mut bytes = good.as_bytes()[..at].to_vec();
        bytes.extend_from_slice(bad);
        bytes.extend_from_slice(&good.as_bytes()[at..]);
        assert_eq!(err(&bytes), E::NotUtf8, "{bad:x?}");
    }
    // Invalid bytes in an ignored comment are refused too: the whole input is checked first.
    let mut bytes = b"<objects><!-- ".to_vec();
    bytes.push(0xFF);
    bytes.extend_from_slice(b" --></objects>");
    assert_eq!(err(&bytes), E::NotUtf8);
    // Invalid bytes at the very end.
    let mut bytes = good.into_bytes();
    bytes.push(0xFF);
    assert_eq!(err(&bytes), E::NotUtf8);
}

#[test]
fn utf16_documents_are_refused() {
    let text = "<objects/>";
    let mut le = vec![0xFF, 0xFE];
    le.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    let mut be = vec![0xFE, 0xFF];
    be.extend(text.encode_utf16().flat_map(u16::to_be_bytes));
    let no_bom: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    for b in [le, be, no_bom] {
        assert!(parse(&b).is_err());
    }
    assert_eq!(err(&[0xFF, 0xFE, b'<', 0, b'o', 0]), E::NotUtf8);
}

#[test]
fn utf8_bom_is_accepted_once() {
    let good = doc(&[Cam::new("A", "rtsp://192.0.2.10/s")]);
    let mut with_bom = vec![0xEF, 0xBB, 0xBF];
    with_bom.extend_from_slice(good.as_bytes());
    assert_eq!(parse(&with_bom).expect("ok").cameras.len(), 1);
    let mut two = vec![0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF];
    two.extend_from_slice(good.as_bytes());
    assert!(is_malformed(err(&two)));
    // A BOM alone, and a BOM with an empty document.
    assert_eq!(err(&[0xEF, 0xBB, 0xBF]), E::NotObjects);
}

#[test]
fn declared_encoding_table() {
    for (enc, ok) in [
        ("utf-8", true),
        ("UTF-8", true),
        ("Utf-8", true),
        ("iso-8859-1", false),
        ("utf-16", false),
        ("UTF-16LE", false),
        ("windows-1252", false),
        ("utf8", false),
        ("", false),
    ] {
        for q in ['"', '\''] {
            let d = format!("<?xml version={q}1.0{q} encoding={q}{enc}{q}?><objects/>");
            let r = parse(d.as_bytes());
            assert_eq!(r.is_ok(), ok, "{d}");
            if !ok {
                assert_eq!(r.err(), Some(E::UnsupportedEncoding), "{d}");
            }
        }
    }
    assert!(parse(b"<?xml version=\"1.0\"?><objects/>").is_ok());
    assert!(parse(b"<?xml version=\"1.0\" standalone=\"yes\"?><objects/>").is_ok());
}

#[test]
fn input_size_limit_boundaries() {
    let pad = |n: usize| {
        let base = "<objects/>";
        let mut s = base.to_owned();
        s.push_str(&" ".repeat(n - base.len()));
        s.into_bytes()
    };
    assert!(parse(&pad(MAX_INPUT_BYTES - 1)).is_ok());
    assert!(parse(&pad(MAX_INPUT_BYTES)).is_ok());
    assert_eq!(err(&pad(MAX_INPUT_BYTES + 1)), E::TooLarge);
    // The size check comes first: invalid UTF-8 of any size over the limit is TooLarge.
    assert_eq!(err(&vec![0xFF; MAX_INPUT_BYTES + 1]), E::TooLarge);
}

#[test]
fn huge_values_are_bounded_by_the_input_limit() {
    // 1 MiB name: refused as a name, not a crash; 1 MiB unknown attribute: ignored.
    let big = "n".repeat(1 << 20);
    let d = wrap(&format!(
        "<camera id=\"1\" name=\"{big}\" other=\"{big}\"><settings><videosourcestring>rtsp://192.0.2.10/s</videosourcestring></settings></camera>"
    ));
    let i = parse(d.as_bytes()).expect("ok");
    assert!(i.cameras.is_empty());
    assert_eq!(i.skipped[0].reason, crate::SkipReason::NameRefused);
    let d = wrap(&format!("<camera id=\"1\" name=\"a\" other=\"{big}\"/>"));
    assert!(parse(d.as_bytes()).is_ok());
}

#[test]
fn camera_count_limit_boundaries() {
    let many = |n: usize, skipped: bool| {
        let cams: Vec<Cam> = (0..n)
            .map(|i| {
                let src = if skipped {
                    "http://192.0.2.1/x"
                } else {
                    "rtsp://192.0.2.1/s"
                };
                Cam::new(&format!("Camera {i}"), src)
            })
            .collect();
        doc(&cams)
    };
    for skipped in [false, true] {
        let i = parse(many(MAX_CAMERAS, skipped).as_bytes()).expect("at the limit");
        assert_eq!(i.cameras.len() + i.skipped.len(), MAX_CAMERAS);
        assert_eq!(
            err(many(MAX_CAMERAS + 1, skipped).as_bytes()),
            E::TooManyCameras
        );
    }
    // Deleted and empty entries count, and so do cameras split over several lists.
    let a: String = (0..MAX_CAMERAS).map(|_| "<camera/>").collect();
    let d = format!("<objects><cameras>{a}</cameras><cameras><camera/></cameras></objects>");
    assert_eq!(err(d.as_bytes()), E::TooManyCameras);
    // Cameras outside <cameras> do not count and are not read.
    let a: String = (0..MAX_CAMERAS + 10).map(|_| "<camera/>").collect();
    assert!(parse(format!("<objects>{a}</objects>").as_bytes()).is_ok());
}

#[test]
fn root_and_structure_table() {
    let not_objects: [&[u8]; 9] = [
        b"",
        b"   \n",
        b"<?xml version=\"1.0\"?>",
        b"<!-- only a comment -->",
        b"<other/>",
        b"<Objects/>",
        b"<ns:objects/>",
        b"<cameras><camera/></cameras>",
        b"just text",
    ];
    for d in not_objects {
        let e = err(d);
        assert!(
            e == E::NotObjects || is_malformed(e),
            "{:?}: {e}",
            String::from_utf8_lossy(d)
        );
    }
    let malformed: [&str; 14] = [
        "<objects/><objects/>",
        "<objects/>trailing",
        "text<objects/>",
        "<objects></other>",
        "<objects><cameras></objects>",
        "<objects><cameras/>",
        "<objects",
        "<objects><camera id=\"1\" id=\"2\"/></objects>",
        "<objects><cameras><camera name=\"a\" name=\"b\"/></cameras></objects>",
        "<objects><x a=\"1\" a=\"2\"/></objects>",
        "<objects><camera id=1/></objects>",
        "<objects><camera id=\"<\"/></objects>",
        "<objects></objects></objects>",
        "<objects><![CDATA[x</objects>",
    ];
    for d in malformed {
        assert!(is_malformed(err(d.as_bytes())), "{d}");
    }
}

#[test]
fn accepted_constructs() {
    let rows = [
        "<objects><!-- c --></objects>",
        "<?xml version=\"1.0\"?><?pi data?><objects><?pi?></objects><!-- end -->",
        "<objects><![CDATA[ignored]]></objects>",
        "<objects>text between</objects>",
        "<objects><unknown a=\"1\"><x/></unknown><cameras/></objects>",
        "\n\t <objects/> \n",
        "<objects xmlns=\"urn:x\" xmlns:xsi=\"y\"><cameras/></objects>",
    ];
    for d in rows {
        assert!(parse(d.as_bytes()).is_ok(), "{d}");
    }
}

#[test]
fn many_attributes_do_not_take_quadratic_time() {
    // quick-xml's duplicate-attribute check compares each key with the earlier ones; an element
    // with a million attributes must be refused or read fast, not tie a core up for hours.
    let mut s = String::from("<objects");
    for n in 0..700_000_u32 {
        s.push_str(&format!(" a{n}=\"\""));
    }
    s.push_str("/>");
    assert!(s.len() > 7_000_000 && s.len() <= MAX_INPUT_BYTES);
    let start = std::time::Instant::now();
    let r = parse(s.as_bytes());
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert!(r.is_ok());
}

#[test]
fn xml_declaration_is_only_legal_first() {
    // White space before the declaration is tolerated; anything else before it, a second
    // declaration, or one inside the document is malformed (never an encoding error).
    let ok = ["  \n<?xml version=\"1.0\" encoding=\"utf-8\"?><objects/>"];
    for d in ok {
        assert!(parse(d.as_bytes()).is_ok(), "{d:?}");
    }
    let bad = [
        "<?xml version=\"1.0\"?><?xml version=\"1.0\"?><objects/>",
        "<?xml version=\"1.0\"?> <?xml version=\"1.0\" encoding=\"latin1\"?><objects/>",
        "<!-- c --><?xml version=\"1.0\"?><objects/>",
        "<objects/><?xml version=\"1.0\"?>",
        "<objects><?xml version=\"1.0\" encoding=\"utf-8\"?></objects>",
        "<objects><?xml version=\"1.0\" encoding=\"latin1\"?></objects>",
        "<?pi x?><?xml version=\"1.0\"?><objects/>",
    ];
    for d in bad {
        assert!(is_malformed(err(d.as_bytes())), "{d:?}");
    }
}
