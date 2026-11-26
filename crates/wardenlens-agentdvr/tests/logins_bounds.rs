//! #166: the login collection is bounded (distinct values and bytes), fails closed with a typed
//! error, and covers every `@`, credential parameters and nested text. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helper outside #[test] fns"
)]

use wardenlens_agentdvr::{ImportError, MAX_INPUT_BYTES, MAX_LOGIN_BYTES, MAX_LOGINS, parse};

fn xml(body: &str) -> String {
    format!("<objects><cameras>{body}</cameras></objects>")
}

fn cam(id: u32, source: &str, extra: &str) -> String {
    let source = source.replace('&', "&amp;");
    format!(
        "<camera id=\"{id}\" name=\"Cam {id}\"><settings>\
         <videosourcestring>{source}</videosourcestring>{extra}</settings></camera>"
    )
}

fn logins_of(body: &str) -> Vec<String> {
    let import = parse(xml(body).as_bytes()).unwrap();
    import.logins.iter().map(str::to_owned).collect()
}

fn has(got: &[String], want: &str) -> bool {
    got.iter().any(|g| g == want)
}

/// A source with exactly `n` distinct short credential-parameter values.
fn params_source(n: usize) -> String {
    let q: Vec<String> = (0..n).map(|i| format!("u=v{i:05}")).collect();
    format!("rtsp://192.0.2.1/s?{}", q.join("&"))
}

#[test]
fn the_cap_is_exact_at_the_distinct_count() {
    let at = parse(xml(&cam(1, &params_source(MAX_LOGINS), "")).as_bytes()).unwrap();
    assert_eq!(at.logins.len(), MAX_LOGINS);
    let over = parse(xml(&cam(1, &params_source(MAX_LOGINS + 1), "")).as_bytes());
    assert_eq!(over.unwrap_err(), ImportError::TooManyLogins);
}

#[test]
fn duplicates_count_once() {
    // 256 cameras with the same login, and the same source repeated: far past the cap if counted.
    let body: String = (0..255)
        .map(|i| cam(i, "rtsp://us-d:pw-d@192.0.2.1/s", "<login>us-d</login>"))
        .collect();
    let got = logins_of(&body);
    assert_eq!(got.len(), 2);
    let many_dups = format!("rtsp://192.0.2.1/s?{}", "u=same&".repeat(100_000));
    assert_eq!(logins_of(&cam(1, &many_dups, "")), vec!["same".to_owned()]);
}

#[test]
fn the_byte_budget_is_exact() {
    let at = "p".repeat(MAX_LOGIN_BYTES);
    let ok = logins_of(&cam(
        1,
        "rtsp://192.0.2.1/s",
        &format!("<password>{at}</password>"),
    ));
    assert_eq!(ok.len(), 1);
    let over = format!("<password>{at}p</password>");
    let r = parse(xml(&cam(1, "rtsp://192.0.2.1/s", &over)).as_bytes());
    assert_eq!(r.unwrap_err(), ImportError::TooManyLogins);
}

#[test]
fn nothing_is_dropped_silently_the_whole_document_is_refused() {
    // One good camera, one that pushes past the cap: the result is an error, not a partial import.
    let ats = "a@".repeat(MAX_LOGINS + 10);
    let body = format!(
        "{}{}",
        cam(1, "rtsp://192.0.2.1/ok", ""),
        cam(2, &format!("rtsp://u:{ats}192.0.2.9/s"), "")
    );
    assert_eq!(
        parse(xml(&body).as_bytes()).unwrap_err(),
        ImportError::TooManyLogins
    );
}

#[test]
fn the_worst_case_8_mib_document_fails_closed() {
    // The security auditor's shape: 255 cameras with long paths and one with a huge run of
    // `~ :~ @` sources, filling the file to the input limit.
    let path = "a".repeat(500);
    let mut body: String = (0..255)
        .map(|i| cam(i, &format!("rtsp://192.0.2.1/{path}"), ""))
        .collect();
    let head = body.len() + "<objects><cameras>".len() + "</cameras></objects>".len();
    let filler = "~ :~ @";
    let budget = MAX_INPUT_BYTES - head - 200;
    let src = format!("rtsp://{}h/s", filler.repeat(budget / filler.len()));
    body.push_str(&cam(300, &src, ""));
    let doc = xml(&body);
    assert!(doc.len() <= MAX_INPUT_BYTES && doc.len() > MAX_INPUT_BYTES - 1000);
    assert_eq!(
        parse(doc.as_bytes()).unwrap_err(),
        ImportError::TooManyLogins
    );
}

#[test]
fn a_dense_run_of_credential_parameters_is_bounded() {
    // `user=` with no `&`: every value is a longer suffix. Fails closed, quickly.
    let src = format!("rtsp://192.0.2.1/s?{}", "user=x".repeat(1_000_000));
    assert_eq!(
        parse(xml(&cam(1, &src, "")).as_bytes()).unwrap_err(),
        ImportError::TooManyLogins
    );
}

#[test]
fn an_equals_after_every_short_name_is_linear() {
    // Names that are not credential names, packed to the input limit: no candidates, no stall.
    let src = format!(
        "rtsp://192.0.2.1/s?{}",
        "a_a_a_a_a_a_a_a_a_a_a_a_a_a=1&".repeat(200_000)
    );
    assert!(src.len() < MAX_INPUT_BYTES);
    assert_eq!(logins_of(&cam(1, &src, "")), Vec::<String>::new());
}

#[test]
fn every_at_sign_yields_a_split() {
    let got = logins_of(&cam(1, "rtsp://us-m:a/b@c/d@192.0.2.1/x@y", ""));
    for want in ["us-m", "a/b", "a/b@c/d", "a/b@c/d@192.0.2.1/x"] {
        assert!(has(&got, want), "{want:?} missing");
    }
}

#[test]
fn a_user_before_an_at_sign_with_no_colon_is_collected() {
    let got = logins_of(&cam(1, "rtsp://us-n@192.0.2.1/s", ""));
    assert!(has(&got, "us-n"));
}

#[test]
fn credential_parameters_of_a_skipped_entry_are_collected() {
    // The path carries a credential, so the entry is skipped; its values are still known.
    let src = "rtsp://192.0.2.1/live?user=us-q&password=pw%2Fq&x_token=tk-q&monkey=notacred";
    let got = logins_of(&cam(1, src, ""));
    for want in ["us-q", "pw%2Fq", "pw/q", "tk-q"] {
        assert!(has(&got, want), "{want:?} missing");
    }
    assert!(!has(&got, "notacred"));
}

#[test]
fn a_credential_parameter_value_with_a_delimiter_is_collected_whole_and_cut() {
    let got = logins_of(&cam(1, "rtsp://192.0.2.1/s?pwd=ab/cd@ef;gh&k=1", ""));
    for want in ["ab/cd@ef;gh", "ab"] {
        assert!(has(&got, want), "{want:?} missing");
    }
}

#[test]
fn the_parameter_name_may_sit_anywhere_in_the_text() {
    // Not in a query: after a `;` in a path.
    let got = logins_of(&cam(1, "rtsp://192.0.2.1/a;pass=pw-r/b", ""));
    assert!(has(&got, "pw-r"));
}

#[test]
fn text_below_a_login_element_is_collected() {
    let got = logins_of(&cam(
        1,
        "rtsp://192.0.2.1/s",
        "<password><b>pw-nest</b></password><login>u<i>-nest</i></login>",
    ));
    assert!(has(&got, "pw-nest"));
    assert!(has(&got, "u-nest"));
    // The direct text alone (what the entry uses) is collected too.
    assert!(has(&got, "u"));
}

#[test]
fn direct_text_is_collected_for_password_login_and_source_shapes() {
    let got = logins_of(&cam(
        1,
        "rtsp://us-s:pw-s@192.0.2.1/<b>x</b>",
        "<login>us-l<i>-c</i>tail</login><password>pw-<b>c</b>direct</password>",
    ));
    for want in ["us-ltail", "us-l-ctail", "pw-direct", "pw-cdirect", "pw-s"] {
        assert!(has(&got, want), "{want:?} missing");
    }
}

#[test]
fn duplicate_heavy_fields_finish() {
    // A field of `pw=` x 800 repeated to fill the input, and a `u:` + `@` x 1400 source repeated.
    let pw = format!("<password>{}</password>", "pw=".repeat(800));
    let pws = pw.repeat(1500);
    let src = format!("rtsp://u:{}h/s", "@".repeat(1400));
    let srcs = format!("<videosourcestring>{src}</videosourcestring>").repeat(1500);
    let body = format!("<camera id=\"1\" name=\"A\"><settings>{pws}{srcs}</settings></camera>");
    let doc = xml(&body);
    assert!(doc.len() < MAX_INPUT_BYTES);
    let import = parse(doc.as_bytes()).unwrap();
    assert!(import.logins.len() > 1000);
}

#[test]
fn an_overlong_field_with_references_and_cdata_pieces_keeps_every_piece() {
    let pad = "&#32;".repeat(5000);
    let got = logins_of(&cam(
        1,
        "rtsp://192.0.2.1/s",
        &format!("<password>a{pad}<![CDATA[b]]>&amp;c</password>"),
    ));
    assert!(has(&got, &format!("a{}b&c", " ".repeat(5000))));
}
