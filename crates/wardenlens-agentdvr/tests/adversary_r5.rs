//! Round-5 adversary tests (#66, PR #162): every login text present in the file must reach
//! `Import::logins`. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helper outside #[test] fns"
)]

use wardenlens_agentdvr::{MAX_FIELD_BYTES, parse};

fn logins_of(body: &str) -> Vec<String> {
    let xml = format!("<objects><cameras>{body}</cameras></objects>");
    let import = parse(xml.as_bytes()).unwrap();
    import.logins.iter().map(str::to_owned).collect()
}

fn assert_has(got: &[String], want: &str) {
    assert!(
        got.iter().any(|g| g == want),
        "login {want:?} missing; have {} values",
        got.len()
    );
}

fn cam(source: &str, extra: &str) -> String {
    format!(
        "<camera id=\"1\" name=\"A\"><settings>\
         <videosourcestring>{source}</videosourcestring>{extra}</settings></camera>"
    )
}

#[test]
fn an_overlong_source_still_contributes_its_userinfo() {
    let long = "a".repeat(MAX_FIELD_BYTES + 10);
    let got = logins_of(&cam(
        &format!("rtsp://u-long5:pw-long5@192.0.2.1/{long}"),
        "",
    ));
    assert_has(&got, "pw-long5");
    assert_has(&got, "u-long5");
}

#[test]
fn an_overlong_padded_password_still_contributes_its_trimmed_value() {
    let pad = " ".repeat(MAX_FIELD_BYTES + 10);
    let got = logins_of(&cam(
        "rtsp://192.0.2.1/s",
        &format!("<login>u5</login><password>{pad}pw-pad5</password>"),
    ));
    assert_has(&got, "pw-pad5");
}

#[test]
fn an_overlong_field_split_by_references_keeps_its_tail() {
    // Character references split the text into pieces; the tail piece is dropped once the
    // buffer is full.
    let refs = "&#32;".repeat(MAX_FIELD_BYTES + 10);
    let got = logins_of(&cam(
        "rtsp://192.0.2.1/s",
        &format!("<login>u5</login><password>{refs}pw-ref5</password>"),
    ));
    assert_has(&got, "pw-ref5");
}

#[test]
fn a_slash_password_is_collected_when_the_path_also_has_an_at_sign() {
    let got = logins_of(&cam("rtsp://u-sl5:pw/sl5@192.0.2.1/live@x", ""));
    assert_has(&got, "pw/sl5");
}

#[test]
fn a_slash_password_is_collected_when_the_query_has_an_at_sign() {
    let got = logins_of(&cam("rtsp://u-sl6:pw/sl6@192.0.2.1/live?to=a@b", ""));
    assert_has(&got, "pw/sl6");
}

#[test]
fn a_password_with_an_at_sign_and_a_slash_is_collected() {
    // Unencoded `@` and `/` both in the password, and an `@` in the path.
    let got = logins_of(&cam("rtsp://u-at7:p@w/at7@192.0.2.1/x@y", ""));
    assert_has(&got, "p@w/at7");
}

#[test]
fn entity_and_cdata_spellings_are_decoded_before_collection() {
    let got = logins_of(&cam(
        "rtsp://u-e8:p&#37;40w-e8@192.0.2.1/s",
        "<login><![CDATA[u&c8]]></login><password>p<!-- c -->w-c8</password>",
    ));
    assert_has(&got, "u&c8");
    assert_has(&got, "pw-c8");
    assert_has(&got, "p@w-e8");
}

#[test]
fn a_whitespace_padded_source_userinfo_is_collected_trimmed() {
    let got = logins_of(&cam("rtsp:// u-ws9 : pw-ws9 @192.0.2.1/s", ""));
    assert_has(&got, "pw-ws9");
    assert_has(&got, "u-ws9");
}
