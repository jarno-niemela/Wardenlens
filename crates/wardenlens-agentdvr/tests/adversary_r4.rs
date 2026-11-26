//! Round-4 adversary tests (#66, PR #162): every login text present in the file must reach
//! `Import::logins`, so the CLI can keep it out of every path it writes. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helper outside #[test] fns"
)]

use wardenlens_agentdvr::parse;

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

#[test]
fn a_repeated_password_element_keeps_both_values() {
    let got = logins_of(
        "<camera id=\"1\" name=\"A\"><settings>\
         <videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <login>u-rep</login><password>first-pw-rep</password>\
         <password>second-pw-rep</password></settings></camera>",
    );
    assert_has(&got, "second-pw-rep");
    assert_has(&got, "first-pw-rep");
}

#[test]
fn a_repeated_settings_block_keeps_the_first_blocks_login() {
    let got = logins_of(
        "<camera id=\"1\" name=\"A\"><settings>\
         <videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <login>u-one</login><password>pw-settings-one</password></settings>\
         <settings><login>u-two</login><password>pw-settings-two</password></settings></camera>",
    );
    assert_has(&got, "pw-settings-one");
    assert_has(&got, "pw-settings-two");
}

#[test]
fn a_repeated_source_keeps_the_first_userinfo() {
    let got = logins_of(
        "<camera id=\"1\" name=\"A\"><settings>\
         <videosourcestring>rtsp://u-src:pw-src-one@192.0.2.1/s</videosourcestring>\
         <videosourcestring>rtsp://192.0.2.1/s</videosourcestring></settings></camera>",
    );
    assert_has(&got, "pw-src-one");
}

#[test]
fn a_schemeless_source_with_userinfo_contributes_its_password() {
    // `NotAUrl`, but the userinfo is still a login that is present in the file.
    let got = logins_of(
        "<camera id=\"1\" name=\"A\"><settings>\
         <videosourcestring>u-nos:pw-noscheme@192.0.2.1/live</videosourcestring>\
         </settings></camera>",
    );
    assert_has(&got, "pw-noscheme");
}

#[test]
fn a_userinfo_password_with_a_slash_is_still_collected() {
    // The authority split at the first `/` hides the `@`; the entry is skipped (bad port).
    let got = logins_of(
        "<camera id=\"1\" name=\"A\"><settings>\
         <videosourcestring>rtsp://u-sl:pwslash/tail@192.0.2.1/live</videosourcestring>\
         </settings></camera>",
    );
    assert!(
        got.iter().any(|g| g.contains("pwslash")),
        "no login of the slash userinfo collected"
    );
}

#[test]
fn debug_of_the_import_and_a_clone_shows_no_login() {
    let xml = "<objects><cameras><camera id=\"1\" name=\"A\" deleted=\"true\"><settings>\
               <videosourcestring>rtsp://u-dbg:pw-dbg-xyz@192.0.2.1/s</videosourcestring>\
               <login>u-dbg</login><password>pw-dbg-xyz</password></settings></camera>\
               </cameras></objects>";
    let import = parse(xml.as_bytes()).unwrap();
    let cloned = import.clone();
    for shown in [
        format!("{import:?}"),
        format!("{:?}", cloned.logins),
        format!("{cloned:#?}"),
    ] {
        assert!(!shown.contains("pw-dbg-xyz"), "{shown}");
        assert!(!shown.contains("u-dbg"), "{shown}");
    }
    assert_eq!(cloned.logins.len(), import.logins.len());
}
