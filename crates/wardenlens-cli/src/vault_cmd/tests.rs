//! Command tests with an injected terminal, a temporary HOME and synthetic values only.
//! They never read the real `~/.config/wardenlens` or `~/.local/share/wardenlens`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{self, Write};
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
        None => panic!("no command"),
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
    let err = cmd(&env, &["list"], &mut Fake::pipe()).unwrap_err();
    assert!(err.to_string().contains("WARDENLENS_VAULT_KEY"), "{err}");
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
fn recovery_waits_for_the_lock() {
    let h = Home::new();
    h.init();
    set_text(&h, "cam:a:host", "host", "192.0.2.77");
    crash_after_commit(&h);
    let held = super::session::DirLock::acquire(h.paths().key.parent().unwrap()).unwrap();
    let err = cmd(&h.env(), &["rm", "cam:a:host"], &mut Fake::pipe()).unwrap_err();
    assert!(err.to_string().contains("another vault write"), "{err}");
    assert!(h.paths().next_key().exists());
    drop(held);
    ok(&h, &["rm", "cam:a:host"], Fake::pipe());
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
