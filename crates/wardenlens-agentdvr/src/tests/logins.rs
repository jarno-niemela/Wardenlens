//! `Import::logins` holds the user and password texts of every entry, skipped ones included, and
//! shows none of them in `Debug`.

use crate::parse;

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

#[test]
fn every_skip_reason_still_contributes_its_logins() {
    let body = [
        // Deleted.
        camera(
            "id=\"1\" name=\"A\" deleted=\"true\"",
            "rtsp://192.0.2.1/s",
            "u-del",
            "pw-del",
        ),
        // Unsupported scheme, with userinfo.
        camera(
            "id=\"2\" name=\"B\"",
            "http://u-http:pw-http@192.0.2.2/s",
            "",
            "",
        ),
        // Not a URL.
        camera("id=\"3\" name=\"C\"", "/dev/video0", "u-dev", "pw-dev"),
        // Password with no user.
        camera("id=\"4\" name=\"D\"", "rtsp://192.0.2.4/s", "", "pw-nouser"),
        // Conflicting: both the field and the percent-encoded userinfo values are kept.
        camera(
            "id=\"5\" name=\"E\"",
            "rtsp://u-url:p%40ss-url@192.0.2.5/s",
            "u-field",
            "pw-field",
        ),
        // Missing name.
        camera("id=\"6\"", "rtsp://192.0.2.6/s", "u-noname", "pw-noname"),
        // Entity-encoded text is taken after decoding.
        camera(
            "id=\"7\" name=\"G\"",
            "rtsp://192.0.2.7/s",
            "u&amp;g",
            "p&lt;w",
        ),
    ]
    .concat();
    let got = logins_of(&body);
    for want in [
        "u-del",
        "pw-del",
        "u-http",
        "pw-http",
        "u-dev",
        "pw-dev",
        "pw-nouser",
        "u-url",
        "p@ss-url",
        "u-field",
        "pw-field",
        "u-noname",
        "pw-noname",
        "u&g",
        "p<w",
    ] {
        assert!(
            got.iter().any(|g| g == want),
            "missing {want:?} in {} values",
            got.len()
        );
    }
}

#[test]
fn empty_and_blank_values_are_left_out_and_the_count_is_bounded() {
    let got = logins_of(&camera(
        "id=\"1\" name=\"A\"",
        "rtsp://192.0.2.1/s",
        "   ",
        "",
    ));
    assert_eq!(got.len(), 0);
    // At most four values per entry: two fields and the userinfo pair.
    let got = logins_of(&camera(
        "id=\"1\" name=\"A\"",
        "rtsp://a:b@192.0.2.1/s",
        "c",
        "d",
    ));
    assert_eq!(got.len(), 4);
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
