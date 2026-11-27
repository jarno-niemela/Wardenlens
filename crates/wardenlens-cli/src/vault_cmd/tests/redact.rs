//! `vault redact` through the command layer: a temporary vault and synthetic values only.

use super::*;

const PASS: &str = "Tr0ub4dor&3-synthetic";

fn store(h: &Home) {
    set_text(h, "tok:a", "secret", PASS);
    set_text(h, "cam:x:host", "host", "192.0.2.77");
    ok(
        h,
        &["set", "cam:x:login", "--kind", "credential"],
        Fake::pipe().with_stdin("admin\nsynthetic-cam-pass\n"),
    );
}

fn redact(h: &Home, input: &str, n: usize) -> Fake {
    let mut t = Fake::pipe().with_stream(input.as_bytes(), n);
    cmd(&h.env(), &["redact"], &mut t).unwrap();
    t
}

#[test]
fn redact_replaces_vault_values_across_chunk_boundaries() {
    let h = Home::new();
    h.init();
    store(&h);
    let input = format!("a {PASS} b rtsp://admin:synthetic-cam-pass@192.0.2.77:554/x c\n");
    // The userinfo and the host touch, so they are one marker.
    let want = "a [REDACTED] b rtsp://[REDACTED]:554/x c\n";
    for n in [1, 2, 3, 7, 4096] {
        let t = redact(&h, &input, n);
        assert_eq!(t.out(), want, "n={n}");
        assert!(t.err().is_empty(), "{}", t.err());
    }
}

#[test]
fn redact_with_an_empty_vault_copies_stdin() {
    let h = Home::new();
    h.init();
    let t = redact(&h, "plain text, no secrets\n", 5);
    assert_eq!(t.out(), "plain text, no secrets\n");
}

#[test]
fn redact_fails_closed_when_there_is_no_vault() {
    let h = Home::new();
    let mut t = Fake::pipe().with_stream(b"anything", 8);
    let e = cmd(&h.env(), &["redact"], &mut t).unwrap_err();
    assert!(matches!(e, CliError::CouldNotRedact(_)), "{e:?}");
    assert_eq!(e.exit_code(), 2);
    assert!(t.out.is_empty(), "nothing may be written");
}

#[test]
fn redact_fails_closed_with_the_wrong_key() {
    let h = Home::new();
    h.init();
    store(&h);
    let key = h.paths().key;
    std::fs::remove_file(&key).unwrap();
    KeyFile::generate(&key).unwrap();
    let mut t = Fake::pipe().with_stream(PASS.as_bytes(), 8);
    let e = cmd(&h.env(), &["redact"], &mut t).unwrap_err();
    assert_eq!(e.exit_code(), 2, "{e:?}");
    assert!(t.out.is_empty(), "nothing may be written");
}

#[test]
fn redact_refuses_the_key_variable_before_reading() {
    let h = Home::new();
    h.init();
    let mut env = h.env();
    env.key_var_set = true;
    let mut t = Fake::pipe().with_stream(b"x", 1);
    let e = run(parse(&["redact"]), &env, &mut t).unwrap_err();
    assert_eq!(e.exit_code(), 2, "{e:?}");
    assert!(t.out.is_empty(), "nothing may be written");
}

#[test]
fn a_broken_input_is_exit_one_and_names_no_value() {
    let h = Home::new();
    h.init();
    store(&h);
    let e = run(parse(&["redact"]), &h.env(), &mut Broken(Fails, Fails)).unwrap_err();
    assert!(matches!(e, CliError::Redact(_)), "{e:?}");
    assert_eq!(e.exit_code(), 1);
    assert!(!format!("{e:?}{e}").contains(PASS));
}

#[test]
fn an_unredactable_entry_is_listed_on_stderr_without_its_value() {
    let h = Home::new();
    h.init();
    set_text(&h, "tok:short", "secret", "abc12");
    let t = redact(&h, "abc12", 5);
    assert_eq!(t.out(), "abc12");
    assert!(t.err().contains("tok:short"), "{}", t.err());
    assert!(!t.err().contains("abc12"));
}

#[test]
fn redact_passes_binary_input_through() {
    let h = Home::new();
    h.init();
    store(&h);
    let mut input: Vec<u8> = vec![0, 1, 2, 0xff, 0xfe];
    input.extend_from_slice(PASS.as_bytes());
    input.extend_from_slice(&[0x80, 0]);
    let mut t = Fake::pipe().with_stream(&input, 3);
    cmd(&h.env(), &["redact"], &mut t).unwrap();
    let mut want = vec![0, 1, 2, 0xff, 0xfe];
    want.extend_from_slice(b"[REDACTED]");
    want.extend_from_slice(&[0x80, 0]);
    assert_eq!(t.out, want);
}
