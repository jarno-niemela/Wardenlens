//! Command tests with an injected terminal, a temporary HOME and synthetic values only.
//! They never read the real `~/.config/wardenlens` or `~/.local/share/wardenlens`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use wardenlens_secrets::KeyFile;
use wardenlens_vault::Vault;
use zeroize::Zeroizing;

use super::run;
use crate::args::{Cli, Command, VaultCommand};
use crate::env::{Env, Paths};
use crate::error::CliError;
use crate::terminal::{StdoutKind, Terminal};

/// A scripted terminal.
struct Fake {
    stdin_tty: bool,
    stdout: StdoutKind,
    prompts: VecDeque<Vec<u8>>,
    piped: Vec<u8>,
    drip: Drip,
    out: Vec<u8>,
    err: Vec<u8>,
}

impl Fake {
    fn pipe() -> Self {
        Self {
            stdin_tty: false,
            stdout: StdoutKind::Pipe,
            prompts: VecDeque::new(),
            piped: Vec::new(),
            drip: Drip::default(),
            out: Vec::new(),
            err: Vec::new(),
        }
    }

    fn tty() -> Self {
        Self {
            stdin_tty: true,
            stdout: StdoutKind::Tty,
            ..Self::pipe()
        }
    }

    fn with_stdin(mut self, bytes: &str) -> Self {
        self.piped = bytes.as_bytes().to_vec();
        self
    }

    /// Stdin for a streaming command, handed out `n` bytes per read.
    fn with_stream(mut self, bytes: &[u8], n: usize) -> Self {
        self.drip = Drip {
            data: bytes.to_vec(),
            pos: 0,
            n,
        };
        self
    }

    fn with_prompts(mut self, lines: &[&str]) -> Self {
        self.prompts = lines.iter().map(|l| l.as_bytes().to_vec()).collect();
        self
    }

    fn out(&self) -> String {
        String::from_utf8(self.out.clone()).unwrap()
    }

    fn err(&self) -> String {
        String::from_utf8(self.err.clone()).unwrap()
    }
}

/// A reader that returns at most `n` bytes per call.
#[derive(Default)]
struct Drip {
    data: Vec<u8>,
    pos: usize,
    n: usize,
}

impl Read for Drip {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rest = self.data.get(self.pos..).unwrap_or_default();
        let k = rest.len().min(self.n.max(1)).min(buf.len());
        buf[..k].copy_from_slice(&rest[..k]);
        self.pos = self.pos.saturating_add(k);
        Ok(k)
    }
}

impl Terminal for Fake {
    fn stdin_is_tty(&self) -> bool {
        self.stdin_tty
    }
    fn stdout_kind(&self) -> StdoutKind {
        self.stdout
    }
    fn prompt_secret(&mut self, _label: &str) -> io::Result<Zeroizing<Vec<u8>>> {
        assert!(self.stdin_tty, "a prompt needs a terminal");
        self.prompts
            .pop_front()
            .map(Zeroizing::new)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no input"))
    }
    fn read_piped(&mut self, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        assert!(!self.stdin_tty, "piped input only when stdin is not a tty");
        if self.piped.len() > limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too long"));
        }
        Ok(Zeroizing::new(std::mem::take(&mut self.piped)))
    }
    fn stream(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        (&mut self.drip, &mut self.out)
    }
    fn out(&mut self) -> &mut dyn Write {
        &mut self.out
    }
    fn err(&mut self) -> &mut dyn Write {
        &mut self.err
    }
}

struct Home {
    dir: TempDir,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir }
    }

    fn env(&self) -> Env {
        Env {
            home: Some(self.dir.path().as_os_str().to_owned()),
            ..Env::default()
        }
    }

    fn paths(&self) -> Paths {
        self.env().paths().unwrap()
    }

    fn init(&self) {
        let mut t = Fake::pipe();
        cmd(&self.env(), &["init"], &mut t).unwrap();
    }
}

fn parse(args: &[&str]) -> VaultCommand {
    let mut full = vec!["wardenlens", "vault"];
    full.extend_from_slice(args);
    match <Cli as clap::Parser>::try_parse_from(full).unwrap().command {
        Some(Command::Vault(c)) => c,
        None
        | Some(
            Command::Config(_)
            | Command::Import(_)
            | Command::Secrets(_)
            | Command::Token(_)
            | Command::Serve
            | Command::Health
            | Command::Camera(_),
        ) => {
            panic!("no vault command")
        }
    }
}

fn cmd(env: &Env, args: &[&str], term: &mut Fake) -> Result<(), CliError> {
    run(parse(args), env, term)
}

/// Runs a command that must succeed and returns its stdout.
fn ok(h: &Home, args: &[&str], mut t: Fake) -> String {
    cmd(&h.env(), args, &mut t).unwrap();
    t.out()
}

fn set_text(h: &Home, id: &str, kind: &str, value: &str) {
    ok(
        h,
        &["set", id, "--kind", kind],
        Fake::pipe().with_stdin(value),
    );
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

const MARK: &str = "zq-synthetic-mark-7781";

// ---- argv -----------------------------------------------------------------------------------

#[test]
fn a_value_on_argv_is_a_usage_error() {
    let argv = [
        "wardenlens",
        "vault",
        "set",
        "cam:a:host",
        "--kind",
        "host",
        "192.0.2.5",
    ];
    assert!(<Cli as clap::Parser>::try_parse_from(argv).is_err());
    let argv = [
        "wardenlens",
        "vault",
        "set",
        "cam:a:host",
        "--kind",
        "host",
        "--value",
        "x",
    ];
    assert!(<Cli as clap::Parser>::try_parse_from(argv).is_err());
}

// ---- init -----------------------------------------------------------------------------------

#[test]
fn init_creates_private_vault_and_key_at_the_fixed_paths() {
    let h = Home::new();
    h.init();
    let p = h.paths();
    assert_eq!(
        p.db,
        h.dir.path().join(".local/share/wardenlens/dev-vault.db")
    );
    assert_eq!(p.key, h.dir.path().join(".config/wardenlens/dev-vault.key"));
    assert_eq!(mode(&p.db), 0o600);
    assert_eq!(mode(&p.key), 0o600);
    assert_eq!(mode(p.db.parent().unwrap()), 0o700);
    assert_eq!(mode(p.key.parent().unwrap()), 0o700);
    Vault::open(&p.db, KeyFile::load(&p.key).unwrap()).unwrap();
}

#[test]
fn init_twice_refuses_and_keeps_the_key() {
    let h = Home::new();
    h.init();
    let before = std::fs::read(h.paths().key).unwrap();
    let mut t = Fake::pipe();
    assert!(cmd(&h.env(), &["init"], &mut t).is_err());
    assert_eq!(std::fs::read(h.paths().key).unwrap(), before);
}

#[test]
fn init_refuses_xdg_elsewhere_and_creates_nothing() {
    for (data, config) in [(Some("/x/data"), None), (None, Some("/x/config"))] {
        let h = Home::new();
        let mut env = h.env();
        env.xdg_data_home = data.map(OsString::from);
        env.xdg_config_home = config.map(OsString::from);
        let err = cmd(&env, &["init"], &mut Fake::pipe()).unwrap_err();
        assert!(err.to_string().contains("XDG_"), "{err}");
        assert!(!h.dir.path().join(".local").exists());
        assert!(!h.dir.path().join(".config").exists());
    }
}

#[test]
fn init_accepts_xdg_set_to_the_default_location() {
    let h = Home::new();
    let mut env = h.env();
    env.xdg_data_home = Some(h.dir.path().join(".local/share").into_os_string());
    env.xdg_config_home = Some(h.dir.path().join(".config").into_os_string());
    cmd(&env, &["init"], &mut Fake::pipe()).unwrap();
}

#[test]
fn init_refuses_overrides() {
    let h = Home::new();
    let mut env = h.env();
    env.vault = Some(h.dir.path().join("elsewhere.db").into_os_string());
    assert!(cmd(&env, &["init"], &mut Fake::pipe()).is_err());
    assert!(!h.dir.path().join("elsewhere.db").exists());
}

#[test]
fn init_refuses_a_git_work_tree_and_creates_nothing() {
    let h = Home::new();
    std::fs::create_dir(h.dir.path().join(".git")).unwrap();
    let err = cmd(&h.env(), &["init"], &mut Fake::pipe()).unwrap_err();
    assert!(err.to_string().contains("git work tree"), "{err}");
    assert!(!h.dir.path().join(".local").exists());
    assert!(!h.dir.path().join(".config").exists());
}

#[test]
fn init_refuses_a_loose_existing_directory() {
    let h = Home::new();
    let d = h.dir.path().join(".config/wardenlens");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(cmd(&h.env(), &["init"], &mut Fake::pipe()).is_err());
}

#[test]
fn init_reuses_an_imported_key_and_never_overwrites_it() {
    let h = Home::new();
    let p = h.paths();
    std::fs::create_dir_all(p.key.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        p.key.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    KeyFile::generate(&p.key).unwrap();
    let before = std::fs::read(&p.key).unwrap();
    h.init();
    assert_eq!(std::fs::read(&p.key).unwrap(), before);
}

#[test]
fn a_failed_init_removes_the_key_it_created() {
    let h = Home::new();
    let p = h.paths();
    // A non-empty foreign file where the vault goes: Vault::create refuses it.
    std::fs::create_dir_all(p.db.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        p.db.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(&p.db, b"not a vault").unwrap();
    std::fs::set_permissions(&p.db, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(cmd(&h.env(), &["init"], &mut Fake::pipe()).is_err());
    assert!(!p.key.exists());
}

// ---- set / get / list / rm ------------------------------------------------------------------

#[test]
fn set_reads_a_piped_value_and_get_writes_it_without_trailing_text() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77\n");
    let mut t = Fake::pipe();
    cmd(&h.env(), &["get", "cam:a:host"], &mut t).unwrap();
    assert_eq!(t.out, b"192.0.2.77");
    assert_eq!(t.err, b"");
}

#[test]
fn set_prompts_on_a_terminal() {
    let h = Home::new();
    h.init();
    ok(
        &h,
        &["set", "cam:a:name", "--kind", "display-name"],
        Fake::tty().with_prompts(&["Front Gate"]),
    );
    let out = ok(&h, &["get", "cam:a:name"], Fake::pipe());
    assert_eq!(out, "Front Gate");
}

#[test]
fn credentials_are_two_lines_and_get_selects_a_field() {
    let h = Home::new();
    h.init();
    ok(
        &h,
        &["set", "cam:a:credential", "--kind", "credential"],
        Fake::pipe().with_stdin("svc-reader\npw-synthetic-1\n"),
    );
    let user = ok(
        &h,
        &["get", "cam:a:credential", "--field", "username"],
        Fake::pipe(),
    );
    let pass = ok(
        &h,
        &["get", "cam:a:credential", "--field", "password"],
        Fake::pipe(),
    );
    assert_eq!(
        (user.as_str(), pass.as_str()),
        ("svc-reader", "pw-synthetic-1")
    );
    let mut t = Fake::pipe();
    assert!(cmd(&h.env(), &["get", "cam:a:credential"], &mut t).is_err());
    assert_eq!(t.out, b"");
    ok(
        &h,
        &["set", "cam:b:credential", "--kind", "credential"],
        Fake::tty().with_prompts(&["u2", "p2-synthetic"]),
    );
    let pass = ok(
        &h,
        &["get", "cam:b:credential", "--field", "password"],
        Fake::pipe(),
    );
    assert_eq!(pass, "p2-synthetic");
}

#[test]
fn a_one_line_credential_is_refused() {
    let h = Home::new();
    h.init();
    let mut t = Fake::pipe().with_stdin("only-a-user");
    assert!(
        cmd(
            &h.env(),
            &["set", "cam:a:credential", "--kind", "credential"],
            &mut t
        )
        .is_err()
    );
}

#[test]
fn field_on_a_text_entry_is_refused() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    let mut t = Fake::pipe();
    assert!(
        cmd(
            &h.env(),
            &["get", "cam:a:host", "--field", "password"],
            &mut t
        )
        .is_err()
    );
    assert_eq!(t.out, b"");
}

#[test]
fn get_refuses_stdout_that_is_not_a_pipe_or_terminal() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    let mut t = Fake::pipe();
    t.stdout = StdoutKind::Other;
    assert!(cmd(&h.env(), &["get", "cam:a:host"], &mut t).is_err());
    assert_eq!(t.out, b"");
    let mut t = Fake::tty();
    cmd(&h.env(), &["get", "cam:a:host"], &mut t).unwrap();
    assert_eq!(t.out, b"192.0.2.77");
}

#[test]
fn unknown_id_error_names_only_the_asked_id() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:alpha:host", "host", "192.0.2.77");
    let err = cmd(&h.env(), &["get", "cam:alpha:hosx"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.to_string(), "no entry with id cam:alpha:hosx");
}

#[test]
fn set_warns_when_the_value_is_unscannable() {
    let h = Home::new();
    h.init();
    let mut t = Fake::pipe().with_stdin("ab");
    cmd(&h.env(), &["set", "cam:a:note", "--kind", "other"], &mut t).unwrap();
    assert!(t.err().contains("unscannable"), "{}", t.err());
    let mut t = Fake::pipe().with_stdin("a-long-enough-synthetic-value");
    cmd(&h.env(), &["set", "cam:a:note2", "--kind", "other"], &mut t).unwrap();
    assert!(!t.err().contains("unscannable"));
}

#[test]
fn list_shows_ids_kinds_and_the_flag_never_values() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:note", "other", "ab");
    set_text(&h, "cam:b:note", "other", &format!("{MARK}-long-enough"));
    let out = ok(&h, &["list"], Fake::pipe());
    assert!(out.contains("cam:a:note\tother\tunscannable"), "{out}");
    assert!(out.contains("cam:b:note\tother\tscannable"), "{out}");
    assert!(!out.contains(MARK));
}

#[test]
fn rm_removes_and_reports_an_unknown_id() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    ok(&h, &["rm", "cam:a:host"], Fake::pipe());
    assert_eq!(ok(&h, &["list"], Fake::pipe()), "");
    assert!(cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).is_err());
}

#[test]
fn errors_never_carry_the_value() {
    let h = Home::new();
    h.init();
    let bad = format!("not a host {MARK}");
    let mut t = Fake::pipe().with_stdin(&bad);
    let err = cmd(&h.env(), &["set", "cam:a:host", "--kind", "host"], &mut t).unwrap_err();
    assert!(!format!("{err} {err:?}").contains(MARK), "{err}");
    assert!(!t.err().contains(MARK) && !t.out().contains(MARK));
}

#[test]
fn an_oversized_piped_value_is_refused() {
    let h = Home::new();
    h.init();
    let big = "x".repeat(100_000);
    let mut t = Fake::pipe().with_stdin(&big);
    assert!(cmd(&h.env(), &["set", "cam:a:note", "--kind", "other"], &mut t).is_err());
}

#[test]
fn invalid_utf8_is_refused() {
    let h = Home::new();
    h.init();
    let mut t = Fake::pipe();
    t.piped = vec![0xff, 0xfe, 0xfd];
    assert!(cmd(&h.env(), &["set", "cam:a:note", "--kind", "other"], &mut t).is_err());
}

#[test]
fn the_key_in_the_environment_is_refused_everywhere() {
    let h = Home::new();
    h.init();
    let mut env = h.env();
    env.key_var_set = true;
    let key = h.paths().key.to_str().unwrap().to_owned();
    let invocations: [&[&str]; 11] = [
        &["init"],
        &["set", "cam:a:host", "--kind", "host"],
        &["get", "cam:a:host"],
        &["list"],
        &["rm", "cam:a:host"],
        &["rekey"],
        &["check-key"],
        &["check-key", &key],
        &["key", "export"],
        &["key", "import"],
        &["import-legacy"],
    ];
    for args in invocations {
        let mut t = Fake::tty().with_stdin("");
        let err = cmd(&env, args, &mut t).unwrap_err();
        assert!(
            err.to_string().contains("WARDENLENS_VAULT_KEY"),
            "{args:?}: {err}"
        );
    }
}

#[test]
fn a_third_piped_credential_line_is_refused_without_naming_it() {
    let h = Home::new();
    h.init();
    let mut t = Fake::pipe().with_stdin(&format!("svc-reader\npw-synthetic-1\n{MARK}\n"));
    let err = cmd(
        &h.env(),
        &["set", "cam:a:credential", "--kind", "credential"],
        &mut t,
    )
    .unwrap_err();
    assert!(!format!("{err} {err:?}").contains(MARK), "{err}");
    assert_eq!(ok(&h, &["list"], Fake::pipe()), "");
}

#[test]
fn piped_input_loses_one_line_ending_and_one_blank_line_only() {
    let cases = [
        ("u\np\n", "p"),
        ("u\np\n\n", "p"),
        ("u\np", "p"),
        ("u\r\np\r\n", "p"),
        ("u\r\np\r\n\r\n", "p"),
        ("u\np\n\n\n", "p"),
    ];
    for (input, want) in cases {
        let h = Home::new();
        h.init();
        let mut t = Fake::pipe().with_stdin(input);
        let r = cmd(
            &h.env(),
            &["set", "cam:a:credential", "--kind", "credential"],
            &mut t,
        );
        if input.ends_with("\n\n\n") {
            // Two blank lines are a third and fourth line: refused.
            assert!(r.is_err(), "{input:?}");
            continue;
        }
        r.unwrap();
        let args = ["get", "cam:a:credential", "--field"];
        let pass = ok(&h, &[args[0], args[1], args[2], "password"], Fake::pipe());
        assert_eq!(pass, want, "{input:?}");
        let user = ok(&h, &[args[0], args[1], args[2], "username"], Fake::pipe());
        assert_eq!(user, "u", "{input:?}");
    }
}

#[test]
fn piped_text_kinds_get_the_same_trailing_treatment() {
    for (kind, input, want) in [
        ("secret", "tok-synthetic-123456\r\n", "tok-synthetic-123456"),
        (
            "secret",
            "tok-synthetic-123456\r\n\r\n",
            "tok-synthetic-123456",
        ),
        ("secret", "tok-synthetic-123456\n\n", "tok-synthetic-123456"),
        ("host", "192.0.2.77\n\n", "192.0.2.77"),
    ] {
        let h = Home::new();
        h.init();
        let mut t = Fake::pipe().with_stdin(input);
        cmd(&h.env(), &["set", "cam:a:x", "--kind", kind], &mut t).unwrap();
        assert_eq!(ok(&h, &["get", "cam:a:x"], Fake::pipe()), want, "{input:?}");
    }
}

#[test]
fn a_write_command_on_a_missing_vault_exits_like_a_read_command() {
    let h = Home::new();
    let read = cmd(&h.env(), &["list"], &mut Fake::pipe()).unwrap_err();
    let mut t = Fake::pipe().with_stdin("192.0.2.77");
    let write = cmd(&h.env(), &["set", "cam:a:host", "--kind", "host"], &mut t).unwrap_err();
    assert_eq!(read.exit_code(), 2);
    assert_eq!(write.exit_code(), 2);
}

#[test]
fn key_import_refusals_exit_one() {
    let h = Home::new();
    let src = Home::new();
    let k = KeyFile::generate(&src.dir.path().join("k")).unwrap();
    let text = k.to_base64().as_str().to_owned();
    ok(&h, &["key", "import"], Fake::tty().with_prompts(&[&text]));
    let again = cmd(
        &h.env(),
        &["key", "import"],
        &mut Fake::tty().with_prompts(&[&text]),
    );
    assert_eq!(again.unwrap_err().exit_code(), 1);
    let h2 = Home::new();
    let bad = cmd(
        &h2.env(),
        &["key", "import"],
        &mut Fake::tty().with_prompts(&["not base64!"]),
    );
    assert_eq!(bad.unwrap_err().exit_code(), 1);
}

#[test]
fn an_unsafe_next_key_is_reported_as_such_and_never_as_recoverable() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    let p = h.paths();
    std::fs::remove_file(&p.key).unwrap();
    KeyFile::generate(&p.key).unwrap();
    let next = p.next_key();
    std::fs::write(&next, [0u8; 32]).unwrap();
    std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o644)).unwrap();
    let read = cmd(&h.env(), &["list"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(read.exit_code(), 2);
    assert!(
        read.to_string().contains("fails the key file rules"),
        "{read}"
    );
    assert!(
        !read.to_string().contains("run `wardenlens vault rekey`"),
        "{read}"
    );
    let write = cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(write.exit_code(), 2);
    assert!(
        write.to_string().contains("fails the key file rules"),
        "{write}"
    );
    assert!(next.exists());
}

#[test]
fn a_partial_legacy_import_keeps_its_typed_error_and_reports_progress() {
    let home = Home::new();
    home.init();
    // Fill the vault to one below its entry limit, so the second imported entry is refused.
    let p = home.paths();
    let mut vault = Vault::open(&p.db, KeyFile::load(&p.key).unwrap()).unwrap();
    for n in 0..wardenlens_vault::MAX_ENTRIES - 1 {
        let id = wardenlens_core::entry::EntryId::new(&format!("fill:{n}")).unwrap();
        let v = wardenlens_vault::Value::Text(secrecy::SecretString::from("192.0.2.1".to_owned()));
        vault
            .set(
                &id,
                wardenlens_core::entry::EntryKind::Host,
                &v,
                wardenlens_vault::Scan::Normal,
            )
            .unwrap();
    }
    drop(vault);
    let json = r#"[{"name":"A","login":"svc","password":"pw-synthetic-1"},
                   {"name":"B","login":"svc","password":"pw-synthetic-2"}]"#;
    let files = legacy_files(&home, json, "[cameras.cam-a]\nname = \"A\"\nmystery = 1\n");
    let (json_arg, inv_arg) = (files.json.to_str().unwrap(), files.toml.to_str().unwrap());
    let mut t = Fake::pipe();
    let err = cmd(
        &home.env(),
        &[
            "import-legacy",
            "--secret-json",
            json_arg,
            "--inventory",
            inv_arg,
        ],
        &mut t,
    )
    .unwrap_err();
    assert!(matches!(err, CliError::Vault(_)), "{err:?}");
    let all = format!("{}{}", t.out(), t.err());
    assert!(all.contains("re-run is safe"), "{all}");
    assert!(all.contains("1 of 4 imported"), "{all}");
    assert!(all.contains("mystery"), "{all}");
    assert!(!all.contains("pw-synthetic"), "{all}");
}

#[test]
fn a_wrong_key_exits_two() {
    let h = Home::new();
    h.init();
    let p = h.paths();
    std::fs::remove_file(&p.key).unwrap();
    KeyFile::generate(&p.key).unwrap();
    let err = cmd(&h.env(), &["list"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    let err = cmd(&h.env(), &["get", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    let err = cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
}

// ---- keys -----------------------------------------------------------------------------------

#[test]
fn key_export_needs_a_terminal_and_prints_base64() {
    let h = Home::new();
    h.init();
    let mut t = Fake::pipe();
    assert!(cmd(&h.env(), &["key", "export"], &mut t).is_err());
    assert_eq!(t.out, b"");
    let out = ok(&h, &["key", "export"], Fake::tty());
    let key = KeyFile::load(&h.paths().key).unwrap();
    assert_eq!(out.trim_end(), key.to_base64().as_str());
}

#[test]
fn key_import_needs_a_terminal_and_never_overwrites() {
    let h = Home::new();
    let src = Home::new();
    let src_key = KeyFile::generate(&src.dir.path().join("k")).unwrap();
    let text = src_key.to_base64();
    let mut t = Fake::pipe().with_stdin(text.as_str());
    assert!(cmd(&h.env(), &["key", "import"], &mut t).is_err());
    assert!(!h.paths().key.exists());
    ok(
        &h,
        &["key", "import"],
        Fake::tty().with_prompts(&[text.as_str()]),
    );
    let p = h.paths();
    assert_eq!(mode(&p.key), 0o600);
    assert_eq!(
        std::fs::read(&p.key).unwrap(),
        std::fs::read(src.dir.path().join("k")).unwrap()
    );
    let mut t = Fake::tty().with_prompts(&[text.as_str()]);
    assert!(cmd(&h.env(), &["key", "import"], &mut t).is_err());
    let mut t = Fake::tty().with_prompts(&["not base64"]);
    let h2 = Home::new();
    assert!(cmd(&h2.env(), &["key", "import"], &mut t).is_err());
    assert!(!h2.paths().key.exists());
}

#[test]
fn key_import_refuses_xdg_elsewhere_and_work_trees() {
    let h = Home::new();
    let mut env = h.env();
    env.xdg_config_home = Some(OsString::from("/x/config"));
    assert!(
        cmd(
            &env,
            &["key", "import"],
            &mut Fake::tty().with_prompts(&["x"])
        )
        .is_err()
    );
    std::fs::create_dir(h.dir.path().join(".git")).unwrap();
    assert!(
        cmd(
            &h.env(),
            &["key", "import"],
            &mut Fake::tty().with_prompts(&["x"])
        )
        .is_err()
    );
    assert!(!h.dir.path().join(".config").exists());
}

#[test]
fn check_key_applies_the_key_rules() {
    let h = Home::new();
    h.init();
    let out = ok(&h, &["check-key"], Fake::pipe());
    assert!(!out.contains(&*KeyFile::load(&h.paths().key).unwrap().to_base64()));
    let key = h.paths().key;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let path = key.to_str().unwrap().to_owned();
    let err = cmd(&h.env(), &["check-key", &path], &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
}

// ---- rekey and recovery ---------------------------------------------------------------------

fn rekey_ok(h: &Home) -> Fake {
    let mut t = Fake::tty();
    cmd(&h.env(), &["rekey"], &mut t).unwrap();
    t
}

#[test]
fn rekey_without_a_terminal_changes_nothing() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    let before = std::fs::read(h.paths().key).unwrap();
    let mut t = Fake::pipe();
    assert!(cmd(&h.env(), &["rekey"], &mut t).is_err());
    assert_eq!(std::fs::read(h.paths().key).unwrap(), before);
    assert!(!h.paths().next_key().exists());
    assert_eq!(t.out, b"");
}

#[test]
fn rekey_reseals_and_ends_with_a_key_export() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    let before = std::fs::read(h.paths().key).unwrap();
    let t = rekey_ok(&h);
    let p = h.paths();
    let after = std::fs::read(&p.key).unwrap();
    assert_ne!(before, after);
    assert_eq!(mode(&p.key), 0o600);
    assert!(!p.next_key().exists());
    assert_eq!(ok(&h, &["get", "cam:a:host"], Fake::pipe()), "192.0.2.77");
    let key = KeyFile::load(&p.key).unwrap();
    assert_eq!(t.out().trim_end(), key.to_base64().as_str());
    assert!(t.err().contains("re-export the key now"), "{}", t.err());
}

/// Rotates the vault by hand and leaves `<key>.next` behind: a crash between commit and rename.
fn crash_after_commit(h: &Home) {
    let p = h.paths();
    let mut v = Vault::open(&p.db, KeyFile::load(&p.key).unwrap()).unwrap();
    v.rekey(KeyFile::generate(&p.next_key()).unwrap()).unwrap();
}

#[test]
fn read_commands_never_recover_and_point_at_the_write_command() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    crash_after_commit(&h);
    let (key, next) = (h.paths().key, h.paths().next_key());
    let before = std::fs::read(&key).unwrap();
    for args in [&["list"][..], &["get", "cam:a:host"]] {
        let err = cmd(&h.env(), args, &mut Fake::pipe()).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("rekey"), "{err}");
    }
    assert_eq!(std::fs::read(&key).unwrap(), before);
    assert!(next.exists());
}

#[test]
fn a_write_command_completes_an_interrupted_rekey() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    crash_after_commit(&h);
    let new_bytes = std::fs::read(h.paths().next_key()).unwrap();
    set_text(&h, "cam:b:host", "host", "192.0.2.78");
    assert_eq!(std::fs::read(h.paths().key).unwrap(), new_bytes);
    assert!(!h.paths().next_key().exists());
    assert_eq!(ok(&h, &["get", "cam:a:host"], Fake::pipe()), "192.0.2.77");
}

#[test]
fn a_write_command_deletes_a_stale_next_key() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    KeyFile::generate(&h.paths().next_key()).unwrap();
    let before = std::fs::read(h.paths().key).unwrap();
    set_text(&h, "cam:b:host", "host", "192.0.2.78");
    assert!(!h.paths().next_key().exists());
    assert_eq!(std::fs::read(h.paths().key).unwrap(), before);
}

#[test]
fn rekey_recovers_before_it_starts() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    crash_after_commit(&h);
    rekey_ok(&h);
    assert!(!h.paths().next_key().exists());
    assert_eq!(ok(&h, &["get", "cam:a:host"], Fake::pipe()), "192.0.2.77");
}

#[test]
fn an_unsafe_next_key_is_neither_used_nor_renamed() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    crash_after_commit(&h);
    let (key, next) = (h.paths().key, h.paths().next_key());
    std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = std::fs::read(&key).unwrap();
    let err = cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert_eq!(std::fs::read(&key).unwrap(), before);
    assert!(next.exists());
}

#[test]
fn a_next_key_that_opens_nothing_is_left_alone() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    let p = h.paths();
    std::fs::remove_file(&p.key).unwrap();
    KeyFile::generate(&p.key).unwrap();
    KeyFile::generate(&p.next_key()).unwrap();
    let err = cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(p.next_key().exists());
}

#[test]
fn a_held_lock_refuses_recovery_and_leaves_next_in_place() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    crash_after_commit(&h);
    let _x = super::lock_exclusive();
    let held = super::session::DirLock::acquire(h.paths().key.parent().unwrap()).unwrap();
    let err = cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert!(err.to_string().contains("another vault write"), "{err}");
    assert!(h.paths().next_key().exists());
    drop(held);
    ok(&h, &["rm", "cam:a:host"], Fake::pipe());
}

/// A lock released while the next writer is still inside its grace period is taken (#134: a
/// child copied the descriptor across a concurrent `fork` and held the lock until `exec`).
#[test]
fn a_lock_released_during_the_grace_period_is_acquired() {
    let _x = super::lock_exclusive();
    let h = Home::new();
    h.init();
    let dir = h.paths().key.parent().unwrap().to_owned();
    let mut held = Some(super::session::DirLock::acquire(&dir).unwrap());
    let mut pauses = Vec::new();
    let got = super::session::DirLock::acquire_with(&dir, 5, |n| {
        pauses.push(n);
        if n == 2 {
            drop(held.take());
        }
    });
    assert!(got.is_ok());
    assert_eq!(pauses, [1, 2]);
}

/// A lock that stays held is still refused, after exactly `attempts - 1` pauses.
#[test]
fn a_lock_held_throughout_the_grace_period_is_refused() {
    let _x = super::lock_exclusive();
    let h = Home::new();
    h.init();
    let dir = h.paths().key.parent().unwrap().to_owned();
    let _held = super::session::DirLock::acquire(&dir).unwrap();
    let mut pauses = 0u32;
    let err = super::session::DirLock::acquire_with(&dir, 4, |_| pauses += 1)
        .err()
        .unwrap();
    assert!(err.to_string().contains("another vault write"), "{err}");
    assert_eq!(err.exit_code(), 1);
    assert_eq!(pauses, 3);
}

// ---- import-legacy --------------------------------------------------------------------------

struct Legacy {
    json: PathBuf,
    toml: PathBuf,
}

fn legacy_files(h: &Home, json: &str, toml: &str) -> Legacy {
    let l = Legacy {
        json: h.dir.path().join("secret.json"),
        toml: h.dir.path().join("inv.toml"),
    };
    std::fs::write(&l.json, json).unwrap();
    std::fs::write(&l.toml, toml).unwrap();
    l
}

const JSON: &str = r#"[{"name":"Front Gate","login":"svc-reader","password":"pw-synthetic-9","onvif":"http://192.0.2.10:8000/zq"},
 {"name":"Unlisted Cam","login":"admin","password":"pw-synthetic-8"}]"#;
const TOML: &str = r#"
site_note = "zq-top-level-synthetic"
[cameras.reolink-1]
name = "Front Gate"
host = "192.0.2.10"
mac = "02:00:00:00:00:01"
vendor = "acme"
colour = "grey"
"#;

fn import(home: &Home, files: &Legacy) -> Fake {
    let mut term = Fake::pipe();
    let json = files.json.to_str().unwrap();
    let inv = files.toml.to_str().unwrap();
    let args = ["import-legacy", "--secret-json", json, "--inventory", inv];
    cmd(&home.env(), &args, &mut term).unwrap();
    term
}

#[test]
fn import_legacy_imports_mapped_fields_and_lists_unknown_keys_by_name() {
    let h = Home::new();
    h.init();
    let t = import(&h, &legacy_files(&h, JSON, TOML));
    let out = t.out();
    assert!(out.contains("imported 6 entries"), "{out}");
    let all = format!("{out}{}", t.err());
    for secret in [
        "pw-synthetic",
        "svc-reader",
        "192.0.2",
        "zq-top-level",
        "02:00:00",
        "Front Gate",
        "grey",
    ] {
        assert!(!all.contains(secret), "{secret} leaked: {all}");
    }
    assert!(out.contains("not imported"), "{out}");
    for key in [
        "site_note",
        "reolink-1.colour",
        "reolink-1.onvif",
        "reolink-1.name",
    ] {
        assert!(out.contains(key), "{key} missing: {out}");
    }
    let list = ok(&h, &["list"], Fake::pipe());
    for id in [
        "cam:reolink-1:credential",
        "cam:reolink-1:host",
        "cam:reolink-1:mac",
        "cam:reolink-1:name",
        "cam:import-json-2:credential",
    ] {
        assert!(list.contains(id), "{id}: {list}");
    }
    assert_eq!(
        ok(&h, &["get", "cam:reolink-1:host"], Fake::pipe()),
        "192.0.2.10"
    );
    assert_eq!(
        ok(
            &h,
            &["get", "cam:reolink-1:credential", "--field", "password"],
            Fake::pipe()
        ),
        "pw-synthetic-9"
    );
}

#[test]
fn import_legacy_is_idempotent() {
    let h = Home::new();
    h.init();
    let l = legacy_files(&h, JSON, TOML);
    import(&h, &l);
    let first = ok(&h, &["list"], Fake::pipe());
    import(&h, &l);
    assert_eq!(first, ok(&h, &["list"], Fake::pipe()));
}

#[test]
fn import_legacy_honours_keys_truncated() {
    let h = Home::new();
    h.init();
    let mut obj = String::from(r#"[{"name":"Solo","login":"u","password":"p-synthetic-long""#);
    for i in 0..1100 {
        write!(obj, r#","k{i}":"v""#).unwrap();
    }
    obj.push_str("}]");
    let l = legacy_files(&h, &obj, "[cameras.x]\nhost = \"192.0.2.9\"\n");
    let t = import(&h, &l);
    assert!(t.out().contains("list cut at 1024"), "{}", t.out());
}

#[test]
fn import_legacy_uses_default_files_and_skips_a_missing_default() {
    let h = Home::new();
    h.init();
    let cfg = h.dir.path().join(".config/wardenlens");
    std::fs::write(cfg.join("cameras.local.toml"), TOML).unwrap();
    let out = ok(&h, &["import-legacy"], Fake::pipe());
    assert!(out.contains("cam:reolink-1:host"), "{out}");
}

#[test]
fn import_legacy_errors_are_not_value_bearing() {
    let h = Home::new();
    h.init();
    let l = legacy_files(&h, &format!("[{{\"password\": \"{MARK}\" oops"), "x = 1");
    let (j, i) = (l.json.to_str().unwrap(), l.toml.to_str().unwrap());
    let err = cmd(
        &h.env(),
        &["import-legacy", "--secret-json", j, "--inventory", i],
        &mut Fake::pipe(),
    )
    .unwrap_err();
    assert!(!err.to_string().contains(MARK), "{err}");
    let l = legacy_files(&h, "[]", &format!("a = \"{MARK}\" b"));
    let (j, i) = (l.json.to_str().unwrap(), l.toml.to_str().unwrap());
    let err = cmd(
        &h.env(),
        &["import-legacy", "--secret-json", j, "--inventory", i],
        &mut Fake::pipe(),
    )
    .unwrap_err();
    assert!(!err.to_string().contains(MARK), "{err}");
}

#[test]
fn import_legacy_needs_a_file_and_an_explicit_missing_path_is_an_error() {
    let h = Home::new();
    h.init();
    assert!(cmd(&h.env(), &["import-legacy"], &mut Fake::pipe()).is_err());
    let missing = h.dir.path().join("nope.json");
    let args = ["import-legacy", "--secret-json", missing.to_str().unwrap()];
    assert!(cmd(&h.env(), &args, &mut Fake::pipe()).is_err());
}

#[test]
fn import_legacy_refuses_two_inventory_cameras_with_one_name() {
    let h = Home::new();
    h.init();
    let toml = "[cameras.a]\nname = \"Same\"\n[cameras.b]\nname = \"Same\"\n";
    let l = legacy_files(&h, "[]", toml);
    let (j, i) = (l.json.to_str().unwrap(), l.toml.to_str().unwrap());
    assert!(
        cmd(
            &h.env(),
            &["import-legacy", "--secret-json", j, "--inventory", i],
            &mut Fake::pipe()
        )
        .is_err()
    );
    assert_eq!(ok(&h, &["list"], Fake::pipe()), "");
}

#[test]
fn import_legacy_refuses_inventory_names_equal_after_normalisation() {
    let h = Home::new();
    h.init();
    // The second name holds a no-break space: the same name once stored.
    let toml = "[cameras.a]\nname = \"Porte Nord\"\n[cameras.b]\nname = \"Porte\u{A0}Nord\"\n";
    let json = r#"[{"name":"Porte Nord","login":"u","password":"pw-synthetic-7"}]"#;
    let l = legacy_files(&h, json, toml);
    let (j, i) = (l.json.to_str().unwrap(), l.toml.to_str().unwrap());
    let err = cmd(
        &h.env(),
        &["import-legacy", "--secret-json", j, "--inventory", i],
        &mut Fake::pipe(),
    )
    .unwrap_err();
    assert!(
        matches!(err, CliError::Refused(msg) if msg.contains("share a display name")),
        "{err:?}"
    );
    assert_eq!(ok(&h, &["list"], Fake::pipe()), "");
}

#[test]
fn import_legacy_refuses_an_oversized_file() {
    let h = Home::new();
    h.init();
    let l = legacy_files(&h, &format!("[\"{}\"]", "x".repeat(1_100_000)), "x = 1");
    let (j, i) = (l.json.to_str().unwrap(), l.toml.to_str().unwrap());
    assert!(
        cmd(
            &h.env(),
            &["import-legacy", "--secret-json", j, "--inventory", i],
            &mut Fake::pipe()
        )
        .is_err()
    );
}

// ---- adversarial (#94 verification) ---------------------------------------------------------

#[test]
fn adv_check_key_with_a_path_still_refuses_the_key_variable() {
    // ADR 0006 section 6: if WARDENLENS_VAULT_KEY is set, startup fails. `check-key <path>` is
    // what the container runs at startup (#69).
    let h = Home::new();
    h.init();
    let mut env = h.env();
    env.key_var_set = true;
    let path = h.paths().key.to_str().unwrap().to_owned();
    let err = cmd(&env, &["check-key", &path], &mut Fake::pipe());
    assert!(
        err.is_err(),
        "check-key <path> passed with WARDENLENS_VAULT_KEY set"
    );
}

#[test]
fn adv_a_piped_credential_with_a_third_line_is_not_folded_into_the_password() {
    let h = Home::new();
    h.init();
    // `echo -e "u\np\n"` and a stray extra line both produce more than two lines.
    let input = "svc-reader\npw-synthetic-1\nextra\n";
    let mut t = Fake::pipe().with_stdin(input);
    let r = cmd(
        &h.env(),
        &["set", "cam:a:credential", "--kind", "credential"],
        &mut t,
    );
    if r.is_ok() {
        let pass = ok(
            &h,
            &["get", "cam:a:credential", "--field", "password"],
            Fake::pipe(),
        );
        assert_eq!(
            pass, "pw-synthetic-1",
            "input {input:?} stored a multi-line password"
        );
    }
}

#[test]
fn adv_a_piped_credential_with_a_blank_trailing_line_keeps_no_newline() {
    let h = Home::new();
    h.init();
    // `echo -e "u\np\n"` adds its own newline: three line ends.
    let mut t = Fake::pipe().with_stdin("svc-reader\npw-synthetic-1\n\n");
    let r = cmd(
        &h.env(),
        &["set", "cam:a:credential", "--kind", "credential"],
        &mut t,
    );
    if r.is_ok() {
        let pass = ok(
            &h,
            &["get", "cam:a:credential", "--field", "password"],
            Fake::pipe(),
        );
        assert_eq!(pass, "pw-synthetic-1");
    }
}

#[test]
fn adv_a_piped_secret_with_a_blank_trailing_line_keeps_no_newline() {
    let h = Home::new();
    h.init();
    let mut t = Fake::pipe().with_stdin("tok-synthetic-123456\n\n");
    let r = cmd(
        &h.env(),
        &["set", "cam:a:secret", "--kind", "secret"],
        &mut t,
    );
    if r.is_ok() {
        let v = ok(&h, &["get", "cam:a:secret"], Fake::pipe());
        assert!(!v.contains('\n'), "stored {v:?}");
    }
}

#[test]
fn adv_a_symlinked_next_key_is_neither_used_nor_renamed() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    crash_after_commit(&h);
    let p = h.paths();
    let moved = p.key.parent().unwrap().join("moved.key");
    std::fs::rename(p.next_key(), &moved).unwrap();
    std::os::unix::fs::symlink(&moved, p.next_key()).unwrap();
    let before = std::fs::read(&p.key).unwrap();
    let err = cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert_eq!(std::fs::read(&p.key).unwrap(), before);
    assert!(p.next_key().symlink_metadata().unwrap().is_symlink());
}

#[test]
fn adv_a_stale_symlinked_next_key_is_removed_without_touching_its_target() {
    let h = Home::new();
    h.init();
    let p = h.paths();
    let before = std::fs::read(&p.key).unwrap();
    std::os::unix::fs::symlink(&p.key, p.next_key()).unwrap();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    assert!(p.next_key().symlink_metadata().is_err());
    assert_eq!(std::fs::read(&p.key).unwrap(), before);
}

#[test]
fn adv_read_commands_ignore_a_stale_next_key_and_leave_it() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    KeyFile::generate(&h.paths().next_key()).unwrap();
    assert!(ok(&h, &["list"], Fake::pipe()).contains("cam:a:host"));
    assert_eq!(ok(&h, &["get", "cam:a:host"], Fake::pipe()), "192.0.2.77");
    assert!(h.paths().next_key().exists());
}

#[test]
fn adv_rekey_with_the_lock_busy_changes_nothing() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    let before = std::fs::read(h.paths().key).unwrap();
    let _x = super::lock_exclusive();
    let held = super::session::DirLock::acquire(h.paths().key.parent().unwrap()).unwrap();
    let mut t = Fake::tty();
    assert!(cmd(&h.env(), &["rekey"], &mut t).is_err());
    assert_eq!(t.out, b"");
    assert!(!h.paths().next_key().exists());
    drop(held);
    assert_eq!(std::fs::read(h.paths().key).unwrap(), before);
}

#[test]
fn adv_rekey_twice_and_every_entry_kind_survives() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    ok(
        &h,
        &["set", "cam:a:credential", "--kind", "credential"],
        Fake::pipe().with_stdin("svc-reader\npw-synthetic-1\n"),
    );
    set_text(&h, "cam:a:mac", "mac", "02:00:00:00:00:01");
    rekey_ok(&h);
    rekey_ok(&h);
    assert_eq!(ok(&h, &["get", "cam:a:host"], Fake::pipe()), "192.0.2.77");
    assert_eq!(
        ok(
            &h,
            &["get", "cam:a:credential", "--field", "password"],
            Fake::pipe()
        ),
        "pw-synthetic-1"
    );
}

#[test]
fn adv_init_refuses_a_home_reached_through_a_symlink_into_a_work_tree() {
    let outer = Home::new();
    let repo = outer.dir.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(repo.join("sub")).unwrap();
    let link = outer.dir.path().join("link");
    std::os::unix::fs::symlink(repo.join("sub"), &link).unwrap();
    let env = Env {
        home: Some(link.into_os_string()),
        ..Env::default()
    };
    assert!(cmd(&env, &["init"], &mut Fake::pipe()).is_err());
    assert!(!repo.join("sub/.local").exists());
    assert!(!repo.join("sub/.config").exists());
}

#[test]
fn adv_init_accepts_xdg_defaults_with_a_trailing_slash() {
    let h = Home::new();
    let mut env = h.env();
    let mut d = h.dir.path().join(".local/share").into_os_string();
    d.push("/");
    env.xdg_data_home = Some(d);
    cmd(&env, &["init"], &mut Fake::pipe()).unwrap();
}

#[test]
fn adv_init_refuses_xdg_that_is_relative_or_dotted() {
    for v in ["relative/share", ".local/share"] {
        let h = Home::new();
        let mut env = h.env();
        env.xdg_data_home = Some(OsString::from(v));
        assert!(cmd(&env, &["init"], &mut Fake::pipe()).is_err(), "{v}");
        assert!(!h.dir.path().join(".local").exists());
    }
    let h = Home::new();
    let mut env = h.env();
    let mut d = h.dir.path().join(".config").into_os_string();
    d.push("/../elsewhere");
    env.xdg_config_home = Some(d);
    assert!(cmd(&env, &["init"], &mut Fake::pipe()).is_err());
}

#[test]
fn adv_an_override_inside_a_work_tree_is_refused_by_set() {
    let h = Home::new();
    h.init();
    let repo = h.dir.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let mut env = h.env();
    env.vault = Some(repo.join("v.db").into_os_string());
    let mut t = Fake::pipe().with_stdin("192.0.2.77");
    assert!(cmd(&env, &["set", "cam:a:host", "--kind", "host"], &mut t).is_err());
    assert!(!repo.join("v.db").exists());
}

#[test]
fn adv_import_legacy_never_prints_any_value_including_unknown_and_refused_ones() {
    let h = Home::new();
    h.init();
    let json = format!(
        r#"[{{"name":"Cam {MARK}","login":"u-{MARK}","password":"p-{MARK}","extra":"x-{MARK}"}},
           {{"password":"lonely-{MARK}"}},
           {{"login":"","password":"empty-login-{MARK}"}}]"#
    );
    let toml = format!(
        "note = \"top-{MARK}\"\n[cameras.cam1]\nhost = \"not a host {MARK}\"\nserial = \"SN-{MARK}\"\nweird = \"w-{MARK}\"\n"
    );
    let l = legacy_files(&h, &json, &toml);
    let t = import(&h, &l);
    let all = format!("{}{}", t.out(), t.err());
    assert!(!all.contains(MARK), "{all}");
    for key in ["cam1.host", "cam1.weird", "note", "extra", "password"] {
        assert!(all.contains(key), "{key} not reported: {all}");
    }
}

#[test]
fn adv_import_legacy_json_name_mapped_through_display_name() {
    let h = Home::new();
    h.init();
    let json = r#"[{"name":"Porch","login":"svc","password":"pw-synthetic-77"}]"#;
    let toml = "[cameras.porch-1]\ndisplay_name = \"Porch\"\nhost = \"192.0.2.31\"\n";
    let t = import(&h, &legacy_files(&h, json, toml));
    let list = ok(&h, &["list"], Fake::pipe());
    assert!(list.contains("cam:porch-1:credential"), "{list}");
    assert!(list.contains("cam:porch-1:name"), "{list}");
    assert!(t.out().contains("porch-1.name"), "{}", t.out());
}

#[test]
fn adv_import_legacy_unusable_inventory_id_does_not_collide() {
    let h = Home::new();
    h.init();
    let json = r#"[{"name":"Shed","login":"svc","password":"pw-synthetic-55"}]"#;
    let toml = "[cameras.\"Bad Id\"]\nname = \"Shed\"\nhost = \"192.0.2.32\"\n[cameras.import-json-1]\nhost = \"192.0.2.33\"\n";
    let t = import(&h, &legacy_files(&h, json, toml));
    let list = ok(&h, &["list"], Fake::pipe());
    // Every mapped field is present exactly once and nothing overwrote anything.
    assert_eq!(list.matches(":host").count(), 2, "{list}");
    assert!(list.contains(":credential"), "{list}");
    assert!(t.out().contains("not imported"), "{}", t.out());
}

#[test]
fn adv_import_legacy_reserved_prefix_section_does_not_overwrite_a_json_ordinal() {
    let h = Home::new();
    h.init();
    // The unmapped JSON camera gets cam:import-json-1:*; a TOML section named with the reserved
    // prefix must fall back to its own ordinal, never overwrite it.
    let json = r#"[{"name":"Lone","login":"svc","password":"pw-synthetic-66"}]"#;
    let toml = "[cameras.import-json-1]\nname = \"Other\"\n";
    import(&h, &legacy_files(&h, json, toml));
    let list = ok(&h, &["list"], Fake::pipe());
    assert_eq!(list.matches("cam:import-json-1:name").count(), 1, "{list}");
    let name = ok(&h, &["get", "cam:import-json-1:name"], Fake::pipe());
    assert_eq!(name, "Lone");
}

#[test]
fn adv_get_on_an_uninitialised_vault_exits_two_and_set_matches() {
    let h = Home::new();
    let err = cmd(&h.env(), &["get", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    let mut t = Fake::pipe().with_stdin("192.0.2.77");
    let err2 = cmd(&h.env(), &["set", "cam:a:host", "--kind", "host"], &mut t).unwrap_err();
    assert_eq!(err.exit_code(), err2.exit_code(), "get: {err}; set: {err2}");
}

#[test]
fn adv_debug_of_errors_and_env_never_carries_values() {
    let h = Home::new();
    h.init();
    for (kind, bad) in [
        ("mac", format!("zz:{MARK}")),
        ("host", format!("{MARK} with space")),
        ("display-name", format!("a\u{7}{MARK}")),
    ] {
        let mut t = Fake::pipe().with_stdin(&bad);
        let err = cmd(&h.env(), &["set", "cam:a:x", "--kind", kind], &mut t).unwrap_err();
        assert!(!format!("{err} {err:?}").contains(MARK), "{kind}: {err:?}");
        assert!(!t.err().contains(MARK) && !t.out().contains(MARK));
    }
}

#[test]
fn adv_key_import_accepts_surrounding_whitespace_and_rejects_31_bytes() {
    let h = Home::new();
    let src = Home::new();
    let k = KeyFile::generate(&src.dir.path().join("k")).unwrap();
    let text = format!("  {}  \r", k.to_base64().as_str());
    ok(&h, &["key", "import"], Fake::tty().with_prompts(&[&text]));
    let h2 = Home::new();
    let short = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let mut t = Fake::tty().with_prompts(&[short]);
    assert!(cmd(&h2.env(), &["key", "import"], &mut t).is_err());
    assert!(!h2.paths().key.exists());
}

// ---- adversary round 2 ------------------------------------------------------------------------

#[test]
fn adv2_a_one_line_piped_credential_with_its_line_ending_is_refused() {
    // `echo svc-reader | wardenlens vault set ... --kind credential` is one line, as is
    // "svc-reader" without the newline (refused by `a_one_line_credential_is_refused`). The
    // contract in `set --help` is "exactly two lines": neither form may store an empty password.
    for input in ["svc-reader\n", "svc-reader\r\n"] {
        let h = Home::new();
        h.init();
        let mut t = Fake::pipe().with_stdin(input);
        let r = cmd(
            &h.env(),
            &["set", "cam:a:credential", "--kind", "credential"],
            &mut t,
        );
        assert!(r.is_err(), "{input:?} was stored as a credential");
    }
}

#[test]
fn adv2_an_explicitly_empty_piped_password_is_two_lines_and_accepted() {
    let h = Home::new();
    h.init();
    ok(
        &h,
        &["set", "cam:a:credential", "--kind", "credential"],
        Fake::pipe().with_stdin("svc-reader\n\n"),
    );
    let pass = ok(
        &h,
        &["get", "cam:a:credential", "--field", "password"],
        Fake::pipe(),
    );
    assert_eq!(pass, "");
}

#[test]
fn adv2_credential_separators_and_trailing_forms() {
    // (input, Some(password)) accepted, None refused.
    let cases: [(&str, Option<&str>); 8] = [
        ("u\np\n\r\n", Some("p")),
        ("u\np\r\n\n", Some("p")),
        ("u\n\npw-synthetic\n", None),
        ("u\npw-synthetic\n \n", None),
        ("u\npw-synthetic\nx", None),
        ("u\r\npw syn thetic", Some("pw syn thetic")),
        ("\npw-synthetic\n", None),
        ("u\np\r\n\r\n\r\n", None),
    ];
    for (input, want) in cases {
        let h = Home::new();
        h.init();
        let mut t = Fake::pipe().with_stdin(input);
        let r = cmd(
            &h.env(),
            &["set", "cam:a:credential", "--kind", "credential"],
            &mut t,
        );
        if let Some(w) = want {
            {
                r.unwrap();
                let got = ok(
                    &h,
                    &["get", "cam:a:credential", "--field", "password"],
                    Fake::pipe(),
                );
                assert_eq!(got, w, "{input:?}");
            }
        } else {
            {
                let err = r.unwrap_err();
                assert!(!format!("{err} {err:?}").contains("pw-synthetic"), "{err}");
                assert!(!t.err().contains("pw-synthetic") && !t.out().contains("pw-synthetic"));
            }
        }
    }
}

#[test]
fn adv2_every_subcommand_refuses_the_key_variable_before_touching_anything() {
    // Even on an empty HOME (no vault): the key-variable refusal comes first, and nothing is created.
    let h = Home::new();
    let mut env = h.env();
    env.key_var_set = true;
    for args in [&["init"][..], &["key", "import"]] {
        let mut t = Fake::tty().with_prompts(&["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]);
        let err = cmd(&env, args, &mut t).unwrap_err();
        assert!(err.to_string().contains("WARDENLENS_VAULT_KEY"), "{err}");
        assert_eq!(err.exit_code(), 1);
    }
    assert_eq!(std::fs::read_dir(h.dir.path()).unwrap().count(), 0);
}

#[test]
fn adv2_unsafe_next_rule_text_is_identical_for_read_and_write() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    crash_after_commit(&h);
    let next = h.paths().next_key();
    // A symlink as next: fails the key rules.
    let real = h.dir.path().join("elsewhere.key");
    std::fs::rename(&next, &real).unwrap();
    std::os::unix::fs::symlink(&real, &next).unwrap();
    let r = cmd(&h.env(), &["list"], &mut Fake::pipe()).unwrap_err();
    let w = cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert_eq!(r.to_string(), w.to_string());
    assert_eq!((r.exit_code(), w.exit_code()), (2, 2));
    assert!(
        std::fs::symlink_metadata(&next)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn adv2_a_partial_legacy_import_then_a_rerun_completes_it() {
    let home = Home::new();
    home.init();
    let p = home.paths();
    let mut vault = Vault::open(&p.db, KeyFile::load(&p.key).unwrap()).unwrap();
    let mut fill = Vec::new();
    for n in 0..wardenlens_vault::MAX_ENTRIES - 1 {
        let id = wardenlens_core::entry::EntryId::new(&format!("fill:{n}")).unwrap();
        let v = wardenlens_vault::Value::Text(secrecy::SecretString::from("192.0.2.1".to_owned()));
        vault
            .set(
                &id,
                wardenlens_core::entry::EntryKind::Host,
                &v,
                wardenlens_vault::Scan::Normal,
            )
            .unwrap();
        fill.push(id);
    }
    drop(vault);
    let json = r#"[{"name":"A","login":"svc","password":"pw-synthetic-1"}]"#;
    let files = legacy_files(&home, json, "[cameras.cam-a]\nname = \"A\"\n");
    let (j, i) = (files.json.to_str().unwrap(), files.toml.to_str().unwrap());
    let args = ["import-legacy", "--secret-json", j, "--inventory", i];
    let err = cmd(&home.env(), &args, &mut Fake::pipe()).unwrap_err();
    assert_eq!(err.exit_code(), 1, "{err}");
    // Make room and re-run: everything is imported, nothing duplicated.
    for id in fill.iter().take(10) {
        ok(&home, &["rm", id.as_str()], Fake::pipe());
    }
    let out = ok(&home, &args, Fake::pipe());
    assert!(out.contains("imported"), "{out}");
    assert!(!out.contains("pw-synthetic"), "{out}");
}

// ---- scan exit codes ----------------------------------------------------------------------

/// A terminal whose output always fails.
struct Broken(Fails, Fails);

struct Fails;

impl Write for Fails {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Fails {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }
}

impl Terminal for Broken {
    fn stdin_is_tty(&self) -> bool {
        false
    }
    fn stdout_kind(&self) -> StdoutKind {
        StdoutKind::Pipe
    }
    fn prompt_secret(&mut self, _: &str) -> io::Result<Zeroizing<Vec<u8>>> {
        Err(io::Error::other("no prompt"))
    }
    fn read_piped(&mut self, _: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(Vec::new()))
    }
    fn stream(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        (&mut self.1, &mut self.0)
    }
    fn out(&mut self) -> &mut dyn Write {
        &mut self.0
    }
    fn err(&mut self) -> &mut dyn Write {
        &mut self.1
    }
}

fn scan_args(path: &Path) -> crate::args::ScanArgs {
    crate::args::ScanArgs {
        paths: vec![path.to_owned()],
        ..crate::args::ScanArgs::default()
    }
}

#[test]
fn a_walk_over_the_limit_exits_two_not_one() {
    let h = Home::new();
    h.init();
    let work = tempfile::tempdir().unwrap();
    for i in 0..4 {
        std::fs::write(work.path().join(format!("f{i}")), "x").unwrap();
    }
    let run_with = |limit| {
        let mut t = Fake::pipe();
        super::scan::run_with(&scan_args(work.path()), &h.paths(), &mut t, limit)
    };
    assert!(run_with(4).is_ok());
    let e = run_with(3).unwrap_err();
    assert!(matches!(e, CliError::CouldNotScan(_)), "{e:?}");
    assert_eq!(e.exit_code(), 2);
}

#[test]
fn an_output_error_exits_two_not_one() {
    let h = Home::new();
    h.init();
    // The summary line goes to stderr, which fails.
    let work = tempfile::tempdir().unwrap();
    let e = super::scan::run(
        &scan_args(work.path()),
        &h.paths(),
        &mut Broken(Fails, Fails),
    )
    .unwrap_err();
    assert!(matches!(e, CliError::CouldNotScan(_)), "{e:?}");
    assert_eq!(e.exit_code(), 2);
    // And a hit report that cannot be written is not a "hit found" either.
    set_text(&h, "tok:a", "secret", MARK);
    let f = work.path().join("leak.txt");
    std::fs::write(&f, format!("{MARK}\n")).unwrap();
    let e = super::scan::run(&scan_args(&f), &h.paths(), &mut Broken(Fails, Fails)).unwrap_err();
    assert_eq!(e.exit_code(), 2, "{e:?}");
}

mod redact;
