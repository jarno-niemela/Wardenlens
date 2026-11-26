//! `Import::logins` holds the user and password texts of every entry, skipped ones included, and
//! shows none of them in `Debug`.

use super::ALL_SKIPS;
use super::fixtures::{Cam, cam_xml};
use crate::{SkipReason, parse};

fn camera(attrs: &str, source: &str, login: &str, password: &str) -> String {
    format!(
        "<camera {attrs}><settings><videosourcestring>{source}</videosourcestring>\
         <login>{login}</login><password>{password}</password></settings></camera>"
    )
}

fn logins_of(body: &str) -> Vec<String> {
    let xml = format!("<objects><cameras>{body}</cameras></objects>");
    let import = parse(xml.as_bytes()).unwrap();
    import.logins.iter().map(str::to_owned).collect()
}

const U: &str = "u-sntl";
const P: &str = "pw-sntl";

/// One document body for `reason` and the values `logins` must then hold. `None` for a reason that
/// cannot be produced. The match has no wildcard: a new `SkipReason` fails to compile until it has a
/// row here.
fn skip_row(reason: SkipReason) -> Option<(String, Vec<String>)> {
    let fields = |c: Cam| c.login(U, P);
    let both = vec![U.to_owned(), P.to_owned()];
    let cam = |source: &str| Cam::new("A", source);
    let row = |c: Cam, want: &[&str]| {
        Some((
            cam_xml(&c, 1),
            want.iter().map(|w| (*w).to_owned()).collect(),
        ))
    };
    match reason {
        SkipReason::Deleted => {
            let mut c = fields(cam("rtsp://192.0.2.1/s"));
            c.deleted = Some("true");
            Some((cam_xml(&c, 1), both))
        }
        SkipReason::RepeatedElement => Some((
            format!(
                "<camera id=\"1\" name=\"A\"><settings><login>{U}</login><password>{P}</password>\
                 <password>{P}-2</password></settings></camera>"
            ),
            vec![U.into(), P.into(), format!("{P}-2")],
        )),
        SkipReason::FieldTooLong => {
            let mut c = Cam::new("A", &format!("rtsp://192.0.2.1/{}", "a".repeat(5000)));
            c.login = Some(U.to_owned());
            row(c, &[U])
        }
        SkipReason::MissingName => {
            let mut c = fields(cam("rtsp://192.0.2.1/s"));
            c.name = None;
            Some((cam_xml(&c, 1), both))
        }
        SkipReason::NameRefused => Some((
            cam_xml(&fields(Cam::new("!!!", "rtsp://192.0.2.1/s")), 1),
            both,
        )),
        SkipReason::NoSource => {
            let mut c = fields(cam(""));
            c.source = None;
            Some((cam_xml(&c, 1), both))
        }
        // No scheme: the userinfo is still taken.
        SkipReason::NotAUrl => row(cam(&format!("{U}:{P}@host")), &[U, P]),
        SkipReason::UnsupportedScheme => row(cam(&format!("http://{U}:{P}@192.0.2.1/s")), &[U, P]),
        SkipReason::InvalidUrl => row(cam(&format!("rtsp://{U}:{P}@192.0.2.1/s\u{1}")), &[U, P]),
        SkipReason::InvalidHost => row(cam(&format!("rtsp://{U}:{P}@bad host/s")), &[U, P]),
        SkipReason::InvalidPort => row(cam(&format!("rtsp://{U}:{P}@192.0.2.1:99999/s")), &[U, P]),
        SkipReason::InvalidPath => row(cam(&format!("rtsp://{U}:{P}@192.0.2.1/s%20")), &[U, P]),
        SkipReason::CredentialInPath => Some((
            cam_xml(
                &fields(cam(&format!("rtsp://192.0.2.1/user={U}&password={P}"))),
                1,
            ),
            both,
        )),
        SkipReason::InvalidCredential => {
            let mut c = cam("rtsp://192.0.2.1/s");
            c.login = Some(U.to_owned());
            c.password = Some(format!("{P}\u{7f}"));
            row(c, &[U, &format!("{P}\u{7f}")])
        }
        SkipReason::CredentialWithoutUser => {
            let mut c = cam("rtsp://192.0.2.1/s");
            c.password = Some(P.to_owned());
            row(c, &[P])
        }
        // The field values and the (percent-encoded) userinfo values.
        SkipReason::ConflictingCredential => row(
            fields(cam(&format!("rtsp://{U}x:p%40{P}x@192.0.2.1/s"))),
            &[U, P, &format!("{U}x"), &format!("p@{P}x")],
        ),
        SkipReason::IdRefused => None,
    }
}

#[test]
fn every_skip_reason_still_contributes_its_logins() {
    for reason in ALL_SKIPS {
        let Some((body, want)) = skip_row(reason) else {
            assert_eq!(reason, SkipReason::IdRefused, "{reason:?} has no row");
            continue;
        };
        let xml = format!("<objects><cameras>{body}</cameras></objects>");
        let import = parse(xml.as_bytes()).unwrap();
        assert!(import.cameras.is_empty(), "{reason:?} was imported");
        assert_eq!(import.skipped.len(), 1, "{reason:?}");
        assert_eq!(import.skipped[0].reason, reason);
        let got: Vec<&str> = import.logins.iter().collect();
        for w in &want {
            assert!(got.contains(&w.as_str()), "{reason:?}: missing {w:?}");
        }
    }
}

/// Repeats, extra settings blocks, a schemeless source and a slash in the userinfo: occurrences
/// the slots would drop, and spellings the strict URL split would cut.
#[test]
fn every_occurrence_and_lenient_spelling_is_collected() {
    let rows: [(&str, &[&str]); 7] = [
        ("<login>a-1</login><login>a-2</login>", &["a-1", "a-2"]),
        (
            "<password>b-1</password><password>b-2</password>",
            &["b-1", "b-2"],
        ),
        (
            "<videosourcestring>rtsp://c1:d1@192.0.2.1/s</videosourcestring>\
             <videosourcestring>rtsp://c2:d2@192.0.2.1/s</videosourcestring>",
            &["c1", "d1", "c2", "d2"],
        ),
        (
            "<password>e-1</password></settings><settings><password>e-2</password>",
            &["e-1", "e-2"],
        ),
        (
            "<videosourcestring>f1:g1@host/x</videosourcestring>",
            &["f1", "g1"],
        ),
        (
            "<videosourcestring>rtsp://h1:i1/x@192.0.2.1/s</videosourcestring>",
            &["h1", "i1/x"],
        ),
        ("<password>  padded  </password>", &["  padded  ", "padded"]),
    ];
    for (settings, want) in rows {
        let xml = format!(
            "<objects><cameras><camera id=\"1\" name=\"A\"><settings>{settings}</settings>\
             </camera></cameras></objects>"
        );
        let import = parse(xml.as_bytes()).unwrap();
        let got: Vec<&str> = import.logins.iter().collect();
        for w in want {
            assert!(got.contains(w), "{settings}: missing {w:?}");
        }
    }
}

#[test]
fn empty_and_blank_values_are_left_out() {
    let got = logins_of(&camera(
        "id=\"1\" name=\"A\"",
        "rtsp://192.0.2.1/s",
        "   ",
        "",
    ));
    assert_eq!(got.len(), 0);
    // The fields and the userinfo pair are all collected (there is no per-entry count).
    let got = logins_of(&camera(
        "id=\"1\" name=\"A\"",
        "rtsp://a:b@192.0.2.1/s",
        "c",
        "d",
    ));
    for v in ["a", "b", "c", "d"] {
        assert!(got.iter().any(|g| g == v), "{v}");
    }
}

#[test]
fn debug_shows_only_a_count() {
    let xml = format!(
        "<objects><cameras>{}</cameras></objects>",
        camera(
            "id=\"1\" name=\"A\" deleted=\"true\"",
            "rtsp://192.0.2.1/s",
            "u-secret-x",
            "pw-secret-x"
        )
    );
    let import = parse(xml.as_bytes()).unwrap();
    for shown in [
        format!("{import:?}"),
        format!("{import:#?}"),
        format!("{:?}", import.logins),
    ] {
        assert!(!shown.contains("secret-x"), "{shown}");
    }
    assert!(format!("{:?}", import.logins).contains("redacted; 2"));
}
