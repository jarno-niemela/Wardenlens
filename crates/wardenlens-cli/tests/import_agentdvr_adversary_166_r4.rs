//! Adversary tests for #166 round 4 (PR #167): the aho-corasick screen.
//!
//! Synthetic data only: documentation-range hosts, invented passwords, temporary directories,
//! a cleared environment.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

/// A deterministic xorshift stream.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Characters a password text may use in XML without escaping: printable ASCII except `<`, `&`
/// and `>`, plus Latin-1 / Latin Extended characters whose UTF-8 encodings cover many distinct
/// lead and continuation bytes.
fn alphabet() -> Vec<char> {
    let mut a: Vec<char> = (0x21_u8..=0x7e)
        .filter(|b| !matches!(b, b'<' | b'&' | b'>'))
        .map(char::from)
        .collect();
    // Two-byte UTF-8 (C2..DF lead, 80..BF continuation) and a few three-byte ones (E0..EF lead).
    for cp in (0x80_u32..0x800).step_by(17) {
        a.push(char::from_u32(cp).unwrap());
    }
    for cp in (0x800_u32..0xd000).step_by(997) {
        a.push(char::from_u32(cp).unwrap());
    }
    a
}

/// `n` distinct random passwords of about `each` bytes each.
fn random_passwords(n: usize, each: usize, seed: u64) -> Vec<String> {
    let a = alphabet();
    let mut rng = Rng(seed);
    (0..n)
        .map(|_| {
            let mut s = String::new();
            while s.len().saturating_add(4) <= each {
                let n = u64::try_from(a.len()).unwrap();
                let i = usize::try_from(rng.next().checked_rem(n).unwrap()).unwrap();
                s.push(*a.get(i).unwrap());
            }
            s
        })
        .collect()
}

/// One importable camera and a skipped carrier holding the passwords.
fn doc_with_passwords(pws: &[String]) -> String {
    let mut body = String::new();
    let _ = write!(
        body,
        "<camera id=\"1\" name=\"Cam 1\"><settings><videosourcestring>\
         rtsp://192.0.2.1/live/main</videosourcestring></settings></camera>"
    );
    let mut fields = String::new();
    for p in pws {
        let _ = write!(fields, "<password>{p}</password>");
    }
    let _ = write!(
        body,
        "<camera id=\"999\" name=\"Carrier\"><settings>\
         <videosourcestring>rtsp://192.0.2.9/s</videosourcestring>{fields}</settings></camera>"
    );
    format!("<objects><cameras>{body}</cameras></objects>")
}

/// Run `import agentdvr --dry-run` under an address-space limit of `limit_kib` KiB.
fn run_dry_limited(doc: &str, limit_kib: u64) -> Output {
    let dir = tempfile::tempdir().unwrap();
    for d in ["state", "keys", "in"] {
        let p = dir.path().join(d);
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let t = dir.path().display();
    let config = dir.path().join("wardenlens.toml");
    fs::write(
        &config,
        format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let file = dir.path().join("in/objects.xml");
    assert!(doc.len() < wardenlens_agentdvr::MAX_INPUT_BYTES);
    fs::write(&file, doc).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    Command::new("/bin/sh")
        .env_clear()
        .arg("-c")
        .arg("ulimit -v \"$1\" && exec \"$2\" --config \"$3\" import agentdvr \"$4\" --dry-run")
        .arg("sh")
        .arg(limit_kib.to_string())
        .arg(env!("CARGO_BIN_EXE_wardenlens"))
        .arg(&config)
        .arg(&file)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn assert_imports_one(out: &Output) {
    assert!(
        out.status.success(),
        "exit {:?} signal-killed {}, stderr {}",
        out.status.code(),
        out.status.code().is_none(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.matches("would import").count(), 1);
}

/// Control: 4096 random passwords (about 1 MiB in total) build the contiguous NFA, which fits in
/// a 512 MiB address space.
#[test]
fn a_full_mib_of_many_random_logins_screens_within_512_mib() {
    let pws = random_passwords(4096, 250, 7);
    let total: usize = pws.iter().map(String::len).sum();
    assert!(total <= wardenlens_agentdvr::MAX_LOGIN_BYTES);
    assert_imports_one(&run_dry_limited(&doc_with_passwords(&pws), 512 * 1024));
}

/// Attack: at most 100 patterns make aho-corasick's automatic kind try a full DFA first. With
/// about 1 MiB of non-sharing login bytes (about a million trie states) over a wide byte
/// alphabet (stride 256), the DFA transition table is states x 256 x 4 bytes, about 1 GiB,
/// allocated and filled on every run. Logins are within every parser cap.
#[test]
fn a_full_mib_of_100_random_logins_screens_within_512_mib() {
    let pws = random_passwords(100, 10_400, 11);
    let total: usize = pws.iter().map(String::len).sum();
    assert!(total <= wardenlens_agentdvr::MAX_LOGIN_BYTES);
    assert_imports_one(&run_dry_limited(&doc_with_passwords(&pws), 512 * 1024));
}

/// Run `import agentdvr --dry-run` without a resource limit.
fn run_dry(doc: &str) -> Output {
    run_dry_limited(doc, 4 * 1024 * 1024)
}

/// The id column of each row whose status is a login refusal, and of each would-import row.
fn refused_and_imported(out: &Output) -> (Vec<String>, Vec<String>) {
    assert!(
        out.status.success(),
        "exit {:?}, stderr {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut refused = Vec::new();
    let mut imported = Vec::new();
    for line in stdout.lines().skip(1) {
        let id = line.split_whitespace().next().unwrap().to_owned();
        if line.contains("path contains the login") {
            refused.push(id);
        } else if line.contains("would import") {
            imported.push(id);
        }
    }
    (refused, imported)
}

/// Cameras `(id, path)` plus a skipped carrier (id 999, no source) holding `logins` as
/// passwords.
fn doc_with_paths(paths: &[(u32, String)], logins: &[String]) -> String {
    let mut body = String::new();
    for (i, p) in paths {
        let _ = write!(
            body,
            "<camera id=\"{i}\" name=\"Cam {i}\"><settings><videosourcestring>\
             rtsp://192.0.2.1{p}</videosourcestring></settings></camera>"
        );
    }
    let mut fields = String::new();
    for l in logins {
        let _ = write!(fields, "<password>{l}</password>");
    }
    let _ = write!(
        body,
        "<camera id=\"999\" name=\"Carrier\"><settings>{fields}</settings></camera>"
    );
    format!("<objects><cameras>{body}</cameras></objects>")
}

/// The naive oracle: the path holds a login, ASCII-case-insensitively.
fn oracle_holds(path: &str, logins: &[String]) -> bool {
    let p = path.to_ascii_lowercase();
    logins.iter().any(|l| p.contains(&l.to_ascii_lowercase()))
}

fn check_against_oracle(paths: &[(u32, String)], logins: &[String]) -> usize {
    let (refused, imported) = refused_and_imported(&run_dry(&doc_with_paths(paths, logins)));
    for (i, p) in paths {
        let id = format!("agentdvr-{i}");
        let expect_refused = oracle_holds(p, logins);
        assert_eq!(
            refused.contains(&id),
            expect_refused,
            "path {p:?} logins {logins:?}: refused {}",
            refused.contains(&id)
        );
        assert_eq!(imported.contains(&id), !expect_refused, "path {p:?}");
    }
    refused.len()
}

/// Random small-alphabet paths and logins (heavy overlap: prefixes, suffixes, nested and
/// case-mixed logins) agree with the naive substring oracle on every camera.
#[test]
fn the_screen_agrees_with_a_naive_case_insensitive_substring_oracle() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let chars: Vec<char> = "aAbB_-.".chars().collect();
    let mut pick = |n: u64| usize::try_from(rng.next() % n).unwrap();
    for round in 0..4_u32 {
        let mut logins: Vec<String> = Vec::new();
        for _ in 0..(5 + round * 6) {
            let len = 2 + pick(4);
            let s: String = (0..len).map(|_| chars[pick(7)]).collect();
            logins.push(s);
        }
        let paths: Vec<(u32, String)> = (1..=200_u32)
            .map(|i| {
                // Non-empty segments of letters and `_`, `-`, `.`, never all dots, so core
                // accepts every path and each camera reaches the screen.
                let mut s = String::new();
                for _ in 0..=pick(3) {
                    let mut seg: String = (0..=pick(5)).map(|_| chars[pick(7)]).collect();
                    if seg.chars().all(|c| c == '.') {
                        seg.push('a');
                    }
                    s.push('/');
                    s.push_str(&seg);
                }
                (i, s)
            })
            .collect();
        let refused = check_against_oracle(&paths, &logins);
        // The table is not vacuous: some paths are refused and some imported.
        assert!(
            refused > 0 && refused < paths.len(),
            "round {round}: {refused} refused"
        );
    }
}

/// Edge cases of the multi-pattern search: a login that is the whole path, a prefix or suffix
/// of another login, one only present in upper case, one at the very end, overlapping logins,
/// and a 512-byte path holding a login in its last bytes.
#[test]
fn edge_case_logins_are_caught_exactly_where_the_oracle_says() {
    let long = format!("/{}Zq9", "x".repeat(508));
    assert_eq!(long.len(), 512);
    let paths: Vec<(u32, String)> = vec![
        (1, "/live/Secret9".to_owned()),
        (2, "/live/SECRET".to_owned()),
        (3, "/live/secre".to_owned()),
        (4, "/ab/cd".to_owned()),
        (5, "/abab".to_owned()),
        (6, "/x/aba".to_owned()),
        (7, long.clone()),
        (8, "/x".repeat(10)),
        (9, "/tail-Fake.Pw".to_owned()),
    ];
    let logins: Vec<String> = vec![
        "secret9x".to_owned(),
        "Secret".to_owned(),
        "babab".to_owned(),
        "abab".to_owned(),
        "zQ9".to_owned(),
        "fake.pw".to_owned(),
    ];
    assert_eq!(check_against_oracle(&paths, &logins), 5);
}
