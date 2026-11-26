//! Adversary tests for #166 round 2 (PR #167): the seen-text sets and the worst-case parse time
//! for many distinct texts whose candidates are all duplicates. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns"
)]

use wardenlens_agentdvr::{ImportError, MAX_INPUT_BYTES, parse};

fn xml(body: &str) -> String {
    format!("<objects><cameras>{body}</cameras></objects>")
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

/// Many distinct sources, each with ~1400 `@`: every one is new to the seen set, but every
/// candidate after the first text is a duplicate, so the cap never stops the walk.
fn distinct_at_sources_doc() -> String {
    let ats = "@".repeat(1400);
    let mut fields = String::new();
    let mut i = 0_u32;
    let room = MAX_INPUT_BYTES - 200;
    loop {
        let f = format!("<videosourcestring>rtsp://u:{ats}h/s{i}</videosourcestring>");
        if fields.len().saturating_add(f.len()) > room {
            break;
        }
        fields.push_str(&f);
        i = u32::saturating_add(i, 1);
    }
    xml(&format!(
        "<camera id=\"1\" name=\"A\"><settings>{fields}</settings></camera>"
    ))
}

#[test]
fn many_distinct_sources_with_duplicate_candidates_are_refused_by_the_work_budget() {
    let doc = distinct_at_sources_doc();
    assert!(doc.len() <= MAX_INPUT_BYTES);
    let r = parse(doc.as_bytes());
    assert_eq!(r.unwrap_err(), ImportError::TooManyLogins);
}

fn param_doc(pw: &str) -> String {
    let mut fields = String::new();
    let mut i = 0_u32;
    let room = MAX_INPUT_BYTES - 200;
    loop {
        let f = format!("<videosourcestring>x{i}&amp;{pw}</videosourcestring>");
        if fields.len().saturating_add(f.len()) > room {
            break;
        }
        fields.push_str(&f);
        i = u32::saturating_add(i, 1);
    }
    xml(&format!(
        "<camera id=\"1\" name=\"A\"><settings>{fields}</settings></camera>"
    ))
}

#[test]
fn many_distinct_short_param_sources_are_refused_by_the_work_budget() {
    let doc = param_doc(&"p=".repeat(1000));
    let r = parse(doc.as_bytes());
    assert_eq!(r.unwrap_err(), ImportError::TooManyLogins);
}

#[test]
fn many_distinct_param_sources_with_duplicate_candidates_are_refused_by_the_work_budget() {
    let pw = "pw=".repeat(800);
    let mut fields = String::new();
    let mut i = 0_u32;
    let room = MAX_INPUT_BYTES - 200;
    loop {
        let f = format!("<videosourcestring>x{i}&amp;{pw}</videosourcestring>");
        if fields.len().saturating_add(f.len()) > room {
            break;
        }
        fields.push_str(&f);
        i = u32::saturating_add(i, 1);
    }
    let doc = xml(&format!(
        "<camera id=\"1\" name=\"A\"><settings>{fields}</settings></camera>"
    ));
    let r = parse(doc.as_bytes());
    assert_eq!(r.unwrap_err(), ImportError::TooManyLogins);
}

/// Whitespace-only distinct texts: blank, so never a candidate, but each is kept in the seen
/// set. Parse must still succeed (memory bounded by input).
#[test]
fn many_distinct_blank_logins_are_accepted() {
    let mut fields = String::new();
    'outer: for len in 1..=12_u32 {
        for bits in 0..(1_u32 << len) {
            let s: String = (0..len)
                .map(|b| if bits >> b & 1 == 1 { ' ' } else { '\t' })
                .collect();
            let f = format!("<login>{s}</login>");
            if fields.len() + f.len() > MAX_INPUT_BYTES - 200 {
                break 'outer;
            }
            fields.push_str(&f);
        }
    }
    let doc = xml(&format!(
        "<camera id=\"1\" name=\"A\"><settings>{fields}</settings></camera>"
    ));
    let import = parse(doc.as_bytes()).unwrap();
    assert!(import.logins.is_empty());
}

// --- Escapes: a login the entry uses must be collected. ---

fn cam(id: u32, settings: &str) -> String {
    format!("<camera id=\"{id}\" name=\"Cam {id}\"><settings>{settings}</settings></camera>")
}

#[test]
fn a_login_split_by_a_comment_is_collected_whole() {
    // A comment splits the text into two events, but both are direct text.
    let got = logins_of(&xml(&cam(
        1,
        "<videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <login>us<!-- c -->er9</login><password>Pw<!-- c -->9x</password>",
    )));
    assert!(has(&got, "user9"));
    assert!(has(&got, "Pw9x"));
}

#[test]
fn a_login_split_by_a_processing_instruction_and_cdata_is_collected_whole() {
    let got = logins_of(&xml(&cam(
        1,
        "<videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <login>us<?pi x?>e<![CDATA[r]]>&#57;</login><password>a<b/>b</password>",
    )));
    assert!(has(&got, "user9"));
    assert!(has(&got, "ab"));
}

#[test]
fn the_same_text_in_a_source_and_a_login_is_collected_both_ways() {
    // Separate seen sets: a source text equal to a login text must still yield both kinds.
    let t = "rtsp://u1:p@ss1@192.0.2.1/s";
    let got = logins_of(&xml(&cam(
        1,
        &format!("<login>{t}</login><videosourcestring>{t}</videosourcestring>"),
    )));
    assert!(has(&got, t));
    assert!(has(&got, "u1"));
    assert!(has(&got, "p@ss1"));
}

#[test]
fn a_text_seen_first_as_a_child_split_field_is_still_collected_later_direct() {
    // First field: direct "ab", all-depth "aXb". Second field: direct "aXb". Seen dedup must
    // not swallow "aXb" (already processed) nor "ab".
    let got = logins_of(&xml(&cam(
        1,
        "<videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <password>a<i>X</i>b</password><password>aXb</password><login>a<i>X</i>b</login>",
    )));
    assert!(has(&got, "ab"));
    assert!(has(&got, "aXb"));
}

#[test]
fn a_userinfo_with_a_child_element_inside_the_host_is_collected() {
    // The entry uses direct "rtsp://us:pw@192.0.2.1/s"; the all-depth text has extra '@'.
    let got = logins_of(&xml(&cam(
        1,
        "<videosourcestring>rtsp://us7:pw7<x>@evil:z</x>@192.0.2.1/s</videosourcestring>",
    )));
    assert!(has(&got, "us7"));
    assert!(has(&got, "pw7"));
}
