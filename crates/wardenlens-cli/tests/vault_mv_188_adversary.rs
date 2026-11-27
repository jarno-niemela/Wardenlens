//! Adversary tests for #188 (PR #215): `vault import-legacy` id joining, `--map`, `--dry-run`
//! and `vault mv`, through the real binary. Temporary HOME, cleared environment, synthetic
//! values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const MARK: &str = "zqsyntheticmark7713";

fn home() -> TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn run(h: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .env_clear()
        .env("HOME", h.path())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn all(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(h: &TempDir, args: &[&str]) -> String {
    let o = run(h, args);
    assert!(o.status.success(), "{args:?}: {}", all(&o));
    all(&o)
}

fn files(h: &TempDir, json: &str, toml: &str) -> (String, String) {
    let dir = h.path().join("in");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let j = dir.join("secret.json");
    let t = dir.join("inv.toml");
    std::fs::write(&j, json).unwrap();
    std::fs::write(&t, toml).unwrap();
    for p in [&j, &t] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (
        j.to_str().unwrap().to_owned(),
        t.to_str().unwrap().to_owned(),
    )
}

fn import(h: &TempDir, f: &(String, String), extra: &[&str]) -> Output {
    let mut a = vec![
        "vault",
        "import-legacy",
        "--secret-json",
        f.0.as_str(),
        "--inventory",
        f.1.as_str(),
    ];
    a.extend_from_slice(extra);
    run(h, &a)
}

/// Every regular file under `root` with its bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                out.insert(p.clone(), Vec::new());
                stack.push(p);
            } else {
                out.insert(p.clone(), std::fs::read(&p).unwrap_or_default());
            }
        }
    }
    out
}

/// The importer accepts an inventory section `a:b` next to `a`. A later `vault mv a z` must
/// rename camera `a` only; it must not carry camera `a:b`'s credential and host off to
/// `cam:z:b:*`.
#[test]
fn vault_mv_does_not_carry_off_a_colon_named_inventory_cameras_entries() {
    let h = home();
    ok(&h, &["vault", "init"]);
    let json = r#"[{"name":"a","login":"svc-a","password":"pw-synthetic-a1"},
                   {"name":"a:b","login":"svc-b","password":"pw-synthetic-b1"}]"#;
    let toml = "[cameras.a]\nhost = \"192.0.2.10\"\n[cameras.\"a:b\"]\nhost = \"192.0.2.11\"\n";
    let f = files(&h, json, toml);
    let o = import(&h, &f, &[]);
    assert!(o.status.success(), "{}", all(&o));
    let list = ok(&h, &["vault", "list"]);
    assert!(list.contains("cam:a:b:credential"), "{list}");
    ok(&h, &["vault", "mv", "a", "z"]);
    let list = ok(&h, &["vault", "list"]);
    assert!(
        list.contains("cam:a:b:credential") && list.contains("cam:a:b:host"),
        "camera a:b lost its entries to z: {list}"
    );
}

/// No synthetic value ever reaches stdout or stderr, on success, dry run, or each failure.
#[test]
fn no_value_leaks_through_any_import_legacy_or_mv_path() {
    let h = home();
    ok(&h, &["vault", "init"]);
    let json = format!(
        r#"[{{"name":"Acme {MARK}n","login":"{MARK}l","password":"{MARK}p","gpu":"{MARK}g"}},
            {{"name":"Bolt {MARK}m","login":"{MARK}l2","password":"{MARK}p2"}},
            {{"name":"Bolt other {MARK}o","login":"{MARK}l3","password":"{MARK}p3"}}]"#
    );
    let toml = format!(
        "note = \"{MARK}t\"\n[cameras.alpha-1]\nvendor = \"Acme\"\nhost = \"192.0.2.10\"\nname = \"Hall {MARK}h\"\n\
         [cameras.beta-2]\nvendor = \"Bolt\"\nhost = \"192.0.2.11\"\n\
         [cameras.beta-3]\nvendor = \"Bolt\"\nhost = \"192.0.2.12\"\nserial = \"{MARK}s\"\n"
    );
    let f = files(&h, &json, &toml);
    let mut outputs = Vec::new();
    // Ambiguous (2 and 3), dry run of an unresolved file.
    outputs.push(import(&h, &f, &[]));
    outputs.push(import(&h, &f, &["--dry-run"]));
    // Bad maps of every kind, with the mark in the argument.
    let bad_id = format!("1={MARK}");
    let bad_form = format!("{MARK}=alpha-1");
    let bad_eq = MARK.to_owned();
    for m in [
        bad_id.as_str(),
        bad_form.as_str(),
        bad_eq.as_str(),
        "0=alpha-1",
        "9=alpha-1",
    ] {
        outputs.push(import(&h, &f, &["--map", m]));
    }
    outputs.push(import(&h, &f, &["--map", "2=beta-2", "--map", "2=beta-3"]));
    outputs.push(import(&h, &f, &["--map", "2=alpha-1", "--map", "3=beta-3"]));
    // Dry run and real import that succeed.
    outputs.push(import(
        &h,
        &f,
        &["--dry-run", "--map", "2=beta-2", "--map", "3=beta-3"],
    ));
    let real = import(&h, &f, &["--map", "2=beta-2", "--map", "3=beta-3"]);
    assert!(real.status.success(), "{}", all(&real));
    outputs.push(real);
    // A second import refuses the existing ids.
    outputs.push(import(&h, &f, &["--map", "2=beta-2", "--map", "3=beta-3"]));
    // mv in every outcome.
    outputs.push(run(&h, &["vault", "mv", "beta-2", "beta-3"]));
    outputs.push(run(&h, &["vault", "mv", "beta-2", "gamma"]));
    outputs.push(run(&h, &["vault", "mv", "nope", "gamma-2"]));
    outputs.push(run(&h, &["vault", "mv", MARK, "Bad Id"]));
    outputs.push(run(&h, &["vault", "mv", "gamma", "gamma"]));
    for o in &outputs {
        let text = all(o);
        assert!(!text.contains(MARK), "{text}");
        assert!(!text.contains("192.0.2."), "{text}");
    }
}

/// A dry run leaves an existing vault, its key and every other file byte-identical.
#[test]
fn a_dry_run_changes_no_byte_under_home() {
    let h = home();
    ok(&h, &["vault", "init"]);
    let json = r#"[{"name":"alpha-1","login":"svc","password":"pw-synthetic-dry"}]"#;
    let toml = "[cameras.alpha-1]\nhost = \"192.0.2.10\"\n";
    let f = files(&h, json, toml);
    let before = snapshot(h.path());
    let o = import(&h, &f, &["--dry-run"]);
    assert!(o.status.success(), "{}", all(&o));
    assert!(all(&o).contains("cam:alpha-1:credential"), "{}", all(&o));
    assert_eq!(snapshot(h.path()), before);
    let list = ok(&h, &["vault", "list"]);
    assert!(!list.contains("alpha-1"), "{list}");
}

/// The grouped field report names each field once, with a count, and no camera id or value.
#[test]
fn the_unused_field_report_is_grouped_and_value_free() {
    let h = home();
    ok(&h, &["vault", "init"]);
    let json = format!(
        r#"[{{"name":"alpha-1","login":"svc","password":"pw-synthetic-g1","gpu":"{MARK}","hikPort":1}},
            {{"name":"beta-2","login":"svc","password":"pw-synthetic-g2","gpu":2}}]"#
    );
    let toml =
        "[cameras.alpha-1]\nhost = \"192.0.2.10\"\n[cameras.beta-2]\nhost = \"192.0.2.11\"\n";
    let f = files(&h, &json, toml);
    let o = import(&h, &f, &[]);
    let text = all(&o);
    assert!(o.status.success(), "{text}");
    assert_eq!(text.matches("gpu").count(), 1, "{text}");
    assert!(text.contains("gpu: 2"), "{text}");
    assert!(text.contains("hikPort: 1"), "{text}");
    assert!(!text.contains(MARK), "{text}");
    assert!(!text.contains("import-json"), "{text}");
}
