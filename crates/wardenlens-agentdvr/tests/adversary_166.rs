//! Adversary tests for #166 (PR #167): the login screen's completeness and bounds.
//! Synthetic data only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helper outside #[test] fns"
)]

use secrecy::ExposeSecret;
use wardenlens_agentdvr::{ImportError, MAX_FIELD_BYTES, MAX_LOGINS, parse};
use wardenlens_core::camera::ends_with_credential_param_name;

fn xml(body: &str) -> String {
    format!("<objects><cameras>{body}</cameras></objects>")
}

fn cam(id: u32, settings: &str) -> String {
    format!("<camera id=\"{id}\" name=\"Cam {id}\"><settings>{settings}</settings></camera>")
}

fn logins_of(doc: &str) -> Vec<String> {
    parse(doc.as_bytes())
        .unwrap()
        .logins
        .iter()
        .map(str::to_owned)
        .collect()
}

fn has(got: &[String], want: &str) -> bool {
    got.iter().any(|g| g == want)
}

/// The credential the parser hands to the vault for camera `position` (imported ones only).
fn credential_of(doc: &str, position: usize) -> (String, String) {
    let import = parse(doc.as_bytes()).unwrap();
    let c = import
        .cameras
        .get(position)
        .unwrap()
        .credential
        .clone()
        .unwrap();
    (c.user.clone(), c.password.expose_secret().to_owned())
}

// --- Completeness: every credential the import actually uses must be collected. ---

#[test]
fn the_login_used_by_an_entry_whose_login_has_a_child_element_is_collected() {
    // The entry's credential is built from the direct text only ("se" + "cret-u9"); the
    // collection concatenates the child's text too ("seQcret-u9"). The used user must be known.
    let doc = xml(&cam(
        1,
        "<videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <login>se<x>Q</x>cret-u9</login><password>pw-plain-1</password>",
    ));
    let (user, _) = credential_of(&doc, 0);
    assert!(
        has(&logins_of(&doc), &user),
        "the user the entry uses is not among the collected logins"
    );
}

#[test]
fn the_password_used_by_an_entry_whose_password_has_a_child_element_is_collected() {
    let doc = xml(&cam(
        1,
        "<videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <login>us-plain-2</login><password>Qv7<b>zz</b>synth-pw</password>",
    ));
    let (_, password) = credential_of(&doc, 0);
    assert!(
        has(&logins_of(&doc), &password),
        "the password the entry uses is not among the collected logins"
    );
}

#[test]
fn the_userinfo_used_by_an_entry_whose_source_has_a_child_element_is_collected() {
    // Entry source: rtsp://us-3:pass-3@192.0.2.1/s; collected text: rtsp://us-3:pa@ss-3@...
    let doc = xml(&cam(
        1,
        "<videosourcestring>rtsp://us-3:pa<i>@</i>ss-3@192.0.2.1/s</videosourcestring>",
    ));
    let (_, password) = credential_of(&doc, 0);
    assert_eq!(
        password, "pass-3",
        "fixture: the entry uses the direct text"
    );
    assert!(
        has(&logins_of(&doc), &password),
        "the URL password the entry uses is not among the collected logins"
    );
}

#[test]
fn an_overlong_field_still_contributes_its_logins() {
    let pw = format!("Qv7-{}", "y".repeat(MAX_FIELD_BYTES));
    let doc = xml(&cam(
        1,
        &format!(
            "<videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
             <login>us-4</login><password>{pw}</password>"
        ),
    ));
    let got = logins_of(&doc);
    assert!(has(&got, &pw));
    assert!(has(&got, "us-4"));
}

#[test]
fn an_overlong_source_still_contributes_its_userinfo() {
    let pad = "a".repeat(MAX_FIELD_BYTES);
    let doc = xml(&cam(
        1,
        &format!("<videosourcestring>rtsp://us-5:pw-5@192.0.2.1/{pad}</videosourcestring>"),
    ));
    let got = logins_of(&doc);
    assert!(has(&got, "us-5"));
    assert!(has(&got, "pw-5"));
}

#[test]
fn a_percent_encoded_url_password_is_collected_decoded() {
    let doc = xml(&cam(
        1,
        "<videosourcestring>rtsp://us-6:p%2Fw%40six@192.0.2.1/s</videosourcestring>",
    ));
    let (_, password) = credential_of(&doc, 0);
    assert!(has(&logins_of(&doc), &password));
}

#[test]
fn a_password_with_every_delimiter_is_found_for_every_at() {
    let doc = xml(&cam(
        1,
        "<videosourcestring>rtsp://us-7:a:b/c?d#e@f@192.0.2.1/x@y?z@w</videosourcestring>",
    ));
    let got = logins_of(&doc);
    for want in [
        "us-7",
        "a:b/c?d#e",
        "a:b/c?d#e@f",
        "a:b/c?d#e@f@192.0.2.1/x",
    ] {
        assert!(has(&got, want), "{want:?} missing");
    }
}

// --- Bounds: exact boundaries on the distinct count with raw + trimmed + decoded variants. ---

#[test]
fn a_trimmed_variant_counts_toward_the_cap() {
    // MAX_LOGINS - 1 distinct values, then one value whose raw and trimmed forms differ: that
    // is two more, so the document must be refused, never truncated.
    let q: Vec<String> = (0..MAX_LOGINS - 1).map(|i| format!("u=v{i:05}")).collect();
    let src = format!("rtsp://192.0.2.1/s?{}", q.join("&amp;"));
    let doc = xml(&cam(
        1,
        &format!("<videosourcestring>{src}</videosourcestring><password> pw-8 </password>"),
    ));
    assert_eq!(
        parse(doc.as_bytes()).unwrap_err(),
        ImportError::TooManyLogins
    );
}

#[test]
fn many_repeated_credential_params_with_long_identical_values_are_accepted() {
    // 2000 identical 400-byte values: one distinct, far under the byte budget.
    let v = "v".repeat(400);
    let src = format!(
        "rtsp://192.0.2.1/s?{}",
        format!("pwd={v}&amp;").repeat(2000)
    );
    let doc = xml(&cam(
        1,
        &format!("<videosourcestring>{src}</videosourcestring>"),
    ));
    let got = logins_of(&doc);
    assert!(has(&got, &v));
    assert!(got.len() <= 2);
}

// --- Core: the public name scan against a naive oracle on longer, random inputs. ---

const DENIED: [&str; 36] = [
    "pass",
    "passw",
    "passwd",
    "password",
    "passcode",
    "pw",
    "pwd",
    "p",
    "user",
    "usr",
    "u",
    "username",
    "user_name",
    "user-name",
    "userid",
    "user_id",
    "login",
    "loginuse",
    "loginpas",
    "token",
    "access_token",
    "auth",
    "key",
    "apikey",
    "api_key",
    "api-key",
    "secret",
    "pword",
    "account",
    "psw",
    "pswd",
    "passwort",
    "passphrase",
    "authcode",
    "authtoken",
    "credential",
];

fn oracle(before_eq: &str) -> bool {
    let squash = |n: &str| -> String {
        n.chars()
            .filter(|c| !matches!(c, '_' | '-'))
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };
    let start = before_eq
        .bytes()
        .rposition(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
        .map_or(0, |i| i.saturating_add(1));
    let run = before_eq.get(start..).unwrap();
    let pieces: Vec<&str> = run.split(['_', '-']).collect();
    (0..pieces.len()).any(|from| {
        let joined: String = pieces.get(from..).unwrap().concat();
        DENIED.iter().any(|d| squash(d) == squash(&joined))
    })
}

#[test]
fn the_public_name_scan_matches_the_oracle_on_random_long_names() {
    // Deterministic xorshift; pieces drawn from listed names, fragments and noise.
    let pieces = [
        "pass",
        "word",
        "user",
        "name",
        "api",
        "key",
        "access",
        "token",
        "auth",
        "code",
        "x",
        "PassPhrase",
        "credential",
        "ACCOUNT",
        "login",
        "use",
        "pas",
        "0",
        "é",
        "+",
        "",
        "aaaa",
        "abcdefghijklmnopq",
        "p",
        "u",
        "id",
    ];
    let seps = ["_", "-", "", "__", "-_", "+", "%"];
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let mut pick =
        |n: usize| -> usize { usize::try_from(next() % u64::try_from(n).unwrap()).unwrap() };
    for _ in 0..200_000 {
        let n = pick(7);
        let mut t = String::new();
        for _ in 0..n {
            t.push_str(pieces.get(pick(pieces.len())).unwrap());
            t.push_str(seps.get(pick(seps.len())).unwrap());
        }
        if pick(2) == 0 {
            t.push_str(pieces.get(pick(pieces.len())).unwrap());
        }
        assert_eq!(ends_with_credential_param_name(&t), oracle(&t), "{t:?}");
    }
}

#[test]
fn the_public_name_scan_on_names_around_sixteen_characters() {
    for t in [
        "access_token",
        "x_access_token",
        "accesstoken",
        "a_c_c_e_s_s_t_o_k_e_n",
        "passphrase",
        "xpassphrase",
        "x-passphrase",
        "credential",
        "abcdefghijklmnopq_user",
        "abcdefghijklmnopqr",
        "user_abcdefghijklmnopqrstuvw",
        "abcdefghijklmnop_access_token",
        "aaaaaaaaaaaaaaaa_pw",
        "API-KEY",
        "Api_Key",
    ] {
        assert_eq!(ends_with_credential_param_name(t), oracle(t), "{t:?}");
    }
}
