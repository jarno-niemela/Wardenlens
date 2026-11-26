//! Adversary tests (#61 round 3) for `RtspPath::redacted_for_display` against the corrected
//! ruling: in the query (after the first `?`) a value runs to the next `&`; in the path part,
//! the rest of a `/` segment after its first `=` is hidden. Synthetic data only.

use wardenlens_core::camera::RtspPath;

/// Independent oracle: a single left-to-right character scanner (no splitting), written from
/// the ruling text alone. Returns the expected output and, per input byte, whether it is a
/// value byte (one that must not appear in the output).
fn oracle(text: &str) -> (String, Vec<bool>) {
    let mut out = String::new();
    let mut is_value = Vec::new();
    let mut in_query = false;
    let mut skipping = false;
    for c in text.chars() {
        if !in_query && c == '?' {
            in_query = true;
            skipping = false;
            out.push('?');
            is_value.push(false);
            continue;
        }
        let boundary = if in_query { c == '&' } else { c == '/' };
        if boundary {
            skipping = false;
            out.push(c);
            is_value.push(false);
        } else if skipping {
            is_value.push(true);
        } else if c == '=' {
            skipping = true;
            out.push_str("=***");
            is_value.push(false);
        } else {
            out.push(c);
            is_value.push(false);
        }
    }
    (out, is_value)
}

#[test]
fn hand_rows_match_the_ruling() {
    for (input, want) in [
        ("/", "/"),
        ("/=", "/=***"),
        ("/a=", "/a=***"),
        ("/a==", "/a=***"),
        ("/=/=", "/=***/=***"),
        ("/a?", "/a?"),
        ("/a?&", "/a?&"),
        ("/a?&&=", "/a?&&=***"),
        ("/a?=", "/a?=***"),
        ("/a?==&==", "/a?=***&=***"),
        ("/a=b?c", "/a=***?c"),
        ("/a=b?c=d?e", "/a=***?c=***"),
        ("/a=b&c=d?e=f&g", "/a=***?e=***&g"),
        ("/a&b=c/d", "/a&b=***/d"),
        ("/a?b=c/d=e&f/g", "/a?b=***&f/g"),
        ("/a?b/c=d", "/a?b/c=***"),
        ("/a?b;c=d", "/a?b;c=***"),
        ("/a?b,c=d", "/a?b,c=***"),
        ("/a?b?c=d?e", "/a?b?c=***"),
        ("/x=***", "/x=***"),
        ("/a/b=c/", "/a/b=***/"),
        ("/a//b=c", "/a//b=***"),
    ] {
        let got = RtspPath::new(input)
            .expect("self-check: accepted")
            .redacted_for_display();
        assert_eq!(got, want, "{input}");
        assert_eq!(oracle(input).0, want, "oracle self-check {input}");
    }
}

/// The output never contains the full raw text when it holds any `=`.
#[test]
fn raw_path_never_returned_when_it_has_a_value() {
    for input in ["/a=b", "/a?b=c", "/a?=", "/a=?", "/a?b&c=d&e"] {
        let p = RtspPath::new(input).expect("accepted");
        assert_ne!(p.redacted_for_display(), p.as_str(), "{input}");
    }
}

/// Value of three or more distinct uppercase bytes: none of its contiguous runs survives,
/// whichever delimiter is placed inside it.
#[test]
fn delimiter_inside_value_does_not_expose_the_tail() {
    let secret = "QXZ";
    for d in [
        ";", ",", ":", "=", "!", "$", "'", "(", ")", "*", "+", "~", ".", "-", "_",
    ] {
        for template in [
            format!("/live?k={secret}{d}{secret}"),
            format!("/live?k={secret}{d}{secret}&n=1"),
            format!("/k={secret}{d}{secret}/n"),
            format!("/live/k={secret}{d}{secret}?n=1"),
        ] {
            let Ok(p) = RtspPath::new(&template) else {
                continue;
            };
            let s = p.redacted_for_display();
            assert!(!s.contains(secret), "{template} -> {s}");
        }
    }
    // `/` and `?` are value bytes in the query.
    for d in ["/", "?"] {
        let t = format!("/live?k={secret}{d}{secret}&n=1");
        let s = RtspPath::new(&t).expect("accepted").redacted_for_display();
        assert!(!s.contains(secret), "{t} -> {s}");
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 4096,
        failure_persistence: None,
        ..proptest::test_runner::Config::default()
    })]
    /// Any accepted path over the whole allowed alphabet (letters restricted so the
    /// credential list rarely rejects): output equals the independent scanner's, and no value
    /// byte position survives (checked by marking the value with a unique byte).
    #[test]
    fn redaction_equals_independent_scanner(s in "/[abcXYZ09=&;?/,:!$'()*+_~.-]{0,48}") {
        if let Ok(p) = RtspPath::new(&s) {
            let got = p.redacted_for_display();
            let (want, _) = oracle(&s);
            proptest::prop_assert_eq!(&got, &want, "{}", s);
        }
    }

    /// Mark every value byte with `Q` (not otherwise generated): no `Q` may appear.
    #[test]
    fn no_marked_value_byte_survives(s in "/[abcXYZ09=&;?/,:!$'()*+_~.-]{0,48}") {
        let (_, is_value) = oracle(&s);
        let marked: String = s
            .chars()
            .zip(&is_value)
            .map(|(c, v)| if *v { 'Q' } else { c })
            .collect();
        if let Ok(p) = RtspPath::new(&marked) {
            let got = p.redacted_for_display();
            proptest::prop_assert!(!got.contains('Q'), "{} -> {}", marked, got);
            // Idempotent, and the output is itself an accepted path.
            let again = RtspPath::new(&got).expect("output re-parses").redacted_for_display();
            proptest::prop_assert_eq!(&again, &got);
        }
    }
}

#[test]
fn generator_reaches_accepted_paths_with_values() {
    // Run the scanner proptest body over a fixed deterministic sweep, so the counter check
    // does not depend on test ordering.
    let alphabet: Vec<char> = "abX=&;?/,:".chars().collect();
    let mut accepted = 0_u32;
    let mut with_value = 0_u32;
    for n in 0..alphabet.len().pow(4) {
        let mut s = String::from("/");
        let mut k = n;
        for _ in 0..4 {
            s.push(alphabet[k % alphabet.len()]);
            k /= alphabet.len();
        }
        if let Ok(p) = RtspPath::new(&s) {
            accepted += 1;
            assert_eq!(p.redacted_for_display(), oracle(&s).0, "{s}");
            if s.contains('=') {
                with_value += 1;
            }
        }
    }
    assert!(
        accepted > 1000 && with_value > 500,
        "{accepted} {with_value}"
    );
}
