//! Adversarial end-to-end checks of the real binary (#94 verification, round 3). Temporary HOME,
//! cleared environment, synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns"
)]

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const MARK: &str = "zqsyntheticmark7713";

/// Expected stored (username, password).
type Pair = (&'static [u8], &'static [u8]);

fn home() -> TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn run_os(h: &TempDir, args: &[OsString], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .env_clear()
        .env("HOME", h.path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

fn run(h: &TempDir, args: &[&str], stdin: &[u8]) -> Output {
    let a: Vec<OsString> = args.iter().map(OsString::from).collect();
    run_os(h, &a, stdin)
}

fn all_output(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn no_argv_mistake_ever_echoes_the_mistyped_value() {
    let h = home();
    let m = MARK;
    let eq_kind = format!("--kind={m}");
    let eq_field = format!("--field={m}");
    let long = format!("--{m}");
    let long_eq = format!("--{m}=x");
    let short = format!("-{m}");
    let cases: Vec<Vec<&str>> = vec![
        // missing required option, value in the positional slot
        vec!["vault", "set", m],
        vec!["vault", "set", "--kind", "host", "cam:a:host", m],
        vec!["vault", "set", "cam:a:host", "--kind", "host", "--kind", m],
        vec!["vault", "set", "cam:a:host", &eq_kind],
        vec!["vault", "get", "cam:a:host", &eq_field],
        vec![
            "vault",
            "get",
            "cam:a:host",
            "--field",
            "password",
            "--field",
            m,
        ],
        vec!["vault", "rm", "cam:a:host", m],
        vec!["vault", "check-key", "/nonexistent", m],
        vec!["vault", "init", m],
        vec!["vault", "rekey", m],
        vec!["vault", "key", "export", m],
        vec!["vault", "key", "import", m],
        vec!["vault", "import-legacy", m],
        vec!["vault", "import-legacy", "--secret-json"],
        vec!["vault", "set", "cam:a:host", "--kind", "host", &long],
        vec!["vault", "set", "cam:a:host", "--kind", "host", &long_eq],
        vec!["vault", "set", "cam:a:host", "--kind", "host", &short],
        vec!["vault", "help", m],
        vec!["help", "vault", m],
        vec!["help", m],
        vec![&long],
        vec![&short],
        vec!["vault", "set", "--", m],
        vec!["vault", "get", "--", m, m],
        vec!["--version", m],
        vec!["vault", "--help", m],
    ];
    for args in cases {
        let o = run(&h, &args, b"");
        let all = all_output(&o);
        assert!(!all.contains(m), "{args:?} echoed:\n{all}");
        // Only help/version may exit 0.
        if o.status.success() {
            assert!(!all.contains("error"), "{args:?}: {all}");
        }
    }
}

#[test]
fn non_utf8_argv_is_refused_without_echo() {
    let h = home();
    let mut bad = MARK.as_bytes().to_vec();
    bad.push(0xff);
    let args = vec![
        OsString::from("vault"),
        OsString::from("set"),
        OsString::from_vec(bad),
        OsString::from("--kind"),
        OsString::from("host"),
    ];
    let o = run_os(&h, &args, b"x\n");
    let all = all_output(&o);
    assert!(!o.status.success());
    assert!(!all.contains(MARK), "{all}");
}

#[test]
fn credential_piping_edge_cases() {
    let h = home();
    assert!(run(&h, &["vault", "init"], b"").status.success());
    // (input, expected Some((user, pass)) or None for refused)
    let cases: &[(&[u8], Option<Pair>)] = &[
        (b"", None),
        (b"\n", None),
        (b"\r\n", None),
        (b"qsvcq\n", None),
        (b"qsvcq\r\n", None),
        (b"qsvcq", None),
        (b"qsvcq\n\n", Some((b"qsvcq", b""))),
        (b"qsvcq\r\n\r\n", Some((b"qsvcq", b""))),
        (b"qsvcq\nqpwq", Some((b"qsvcq", b"qpwq"))),
        (b"qsvcq\nqpwq\n", Some((b"qsvcq", b"qpwq"))),
        (b"qsvcq\r\nqpwq\r\n", Some((b"qsvcq", b"qpwq"))),
        (b"qsvcq\nqpwq\n\n", Some((b"qsvcq", b"qpwq"))),
        (b"qsvcq\nqpwq\nqthirdq", None),
        (b"qsvcq\nqpwq\nqthirdq\n", None),
        (b"qsvcq\nqpwq\n\n\n", None),
        // An empty username is a vault rule refusal.
        (b"\nqpwq\n", None),
    ];
    for (i, (input, want)) in cases.iter().enumerate() {
        let id = format!("cam:c{i}:cred");
        let o = run(&h, &["vault", "set", &id, "--kind", "credential"], input);
        match want {
            None => {
                assert_eq!(o.status.code(), Some(1), "{input:?}: {}", all_output(&o));
                let all = all_output(&o);
                assert!(!all.contains("svc") && !all.contains("pw") && !all.contains("qthirdq"));
                assert_eq!(
                    run(&h, &["vault", "get", &id], b"").status.code(),
                    Some(1),
                    "refused input stored anyway: {input:?}"
                );
            }
            Some((u, p)) => {
                assert!(o.status.success(), "{input:?}: {}", all_output(&o));
                let gu = run(&h, &["vault", "get", &id, "--field", "username"], b"");
                let gp = run(&h, &["vault", "get", &id, "--field", "password"], b"");
                assert_eq!(gu.stdout, *u, "{input:?}");
                assert_eq!(gp.stdout, *p, "{input:?}");
            }
        }
    }
}

#[test]
fn set_overwrite_refused_credential_keeps_the_old_value() {
    let h = home();
    assert!(run(&h, &["vault", "init"], b"").status.success());
    let id = "cam:z:cred";
    assert!(
        run(
            &h,
            &["vault", "set", id, "--kind", "credential"],
            b"old\nopw\n"
        )
        .status
        .success()
    );
    let o = run(&h, &["vault", "set", id, "--kind", "credential"], b"new\n");
    assert_eq!(o.status.code(), Some(1));
    let gp = run(&h, &["vault", "get", id, "--field", "password"], b"");
    assert_eq!(gp.stdout, b"opw");
}

#[test]
fn reported_errors_keep_distinct_causes_and_are_one_line() {
    let h = home();
    // No vault yet: get must fail with a single line and exit 2 (not initialised).
    let o = run(&h, &["vault", "get", "cam:a:host"], b"");
    let err = String::from_utf8(o.stderr).unwrap();
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.starts_with("error: "), "{err}");
    assert!(!err.trim_end().ends_with(':'), "{err}");
    assert!(!err.contains(": :"), "{err}");
    // check-key on a missing path names the i/o cause rather than dropping it.
    let o = run(&h, &["vault", "check-key", "/nonexistent/zz"], b"");
    let err = String::from_utf8(o.stderr).unwrap();
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(!o.status.success());
}
