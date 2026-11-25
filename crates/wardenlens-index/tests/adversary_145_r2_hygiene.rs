//! Adversarial hygiene for #145 round 2 (PR #147 at 0a01fcc). `open.rs` and `migrate.rs` hold a
//! raw `rusqlite::Connection` before wrapping it in `sql::Db`, so there the compiler does not stop
//! SQL; only the text scan of `src/tests/hygiene.rs` does, and its list of driver methods misses
//! several that run SQL. These scans use the full list of `rusqlite` 0.43 `Connection` methods that
//! take SQL or open a transaction, and pin the `ReadSql` constructor to the reviewed constants.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::path::{Path, PathBuf};

/// Every `rusqlite` 0.43 `Connection` method that runs SQL text, opens a transaction or copies a
/// database in or out.
const DRIVER_SQL_METHODS: &[&str] = &[
    ".prepare(",
    ".prepare_cached(",
    ".prepare_with_flags(",
    ".execute(",
    ".execute_batch(",
    ".query_row(",
    ".query_one(",
    ".query_row_and_then(",
    ".pragma(",
    ".pragma_query(",
    ".pragma_query_one(",
    ".pragma_query_value(",
    ".pragma_update(",
    ".pragma_update_and_check(",
    ".transaction(",
    ".transaction_with_behavior(",
    ".unchecked_transaction(",
    ".savepoint(",
    ".savepoint_with_name(",
    ".backup(",
    ".restore(",
    ".blob_open(",
];

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Production text of a file: up to the first `#[cfg(test)]`, comments stripped, wrapped method
/// calls joined onto their receiver line.
fn code(path: &Path) -> String {
    let mut acc = String::new();
    for line in std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .take_while(|l| !l.starts_with("#[cfg(test)]"))
    {
        let line = line.split("//").next().unwrap_or("");
        if line.trim_start().starts_with('.') {
            acc.push_str(line.trim_start());
        } else {
            acc.push('\n');
            acc.push_str(line);
        }
    }
    acc
}

fn production_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(src())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    out.sort();
    out
}

/// No production file but `sql.rs` calls a driver method that runs SQL, including the files that
/// hold a raw `Connection` before wrapping it (where only this text check stands).
#[test]
fn no_file_but_sql_rs_calls_any_sql_running_driver_method() {
    let mut bad = Vec::new();
    for p in production_files() {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name == "sql.rs" {
            continue;
        }
        let text = code(&p);
        for m in DRIVER_SQL_METHODS {
            if text.contains(m) {
                bad.push(format!("{name}: {m}"));
            }
        }
    }
    assert!(bad.is_empty(), "driver SQL calls outside sql.rs: {bad:?}");
}

/// In `sql.rs` itself, a `ReadSql` is only ever made by a reviewed `const`: the number of
/// `ReadSql(` constructions in production code equals the number of `: ReadSql =` constants (plus
/// the struct definition), so no function body mints a token from other text.
#[test]
fn read_tokens_are_only_minted_by_the_reviewed_constants() {
    let text = code(&src().join("sql.rs"));
    let consts = text.matches(": ReadSql =").count();
    let constructions = text.matches("ReadSql(").count();
    // `struct ReadSql(&'static str)` is one construction-shaped occurrence.
    assert_eq!(
        constructions,
        consts + 1,
        "a ReadSql is made outside the reviewed constants"
    );
    assert!(consts >= 16, "found only {consts} constants");
}

/// The test-only conveniences of `sql.rs` (the `From<&str>` token and the `Deref` to the raw
/// connection) must each be behind `#[cfg(test)]`: every `impl ... for ReadSql` and
/// `impl ... for Db` that is not the inherent impl sits after the first `#[cfg(test)]` line.
#[test]
fn the_test_only_escape_hatches_are_not_in_production_code() {
    let text = code(&src().join("sql.rs"));
    for needle in [
        "From<&'static str> for ReadSql",
        "From<&&'static str> for ReadSql",
        "Deref for Db",
        "DerefMut for Db",
        "AsRef<Connection>",
        "Borrow<Connection>",
        "fn conn(",
        "fn inner(",
        "fn into_inner(",
    ] {
        assert!(!text.contains(needle), "production sql.rs has {needle}");
    }
    // Every `#[cfg(test)]` item in sql.rs must be at the end (the scan stops at the first one):
    // a production item after it would be invisible to every text check.
    let full = std::fs::read_to_string(src().join("sql.rs")).unwrap();
    let first = full.find("#[cfg(test)]").unwrap();
    let mut depth = 0i32;
    let mut item_gated = false;
    for line in full[first..].lines() {
        let t = line.trim_start();
        if depth == 0 {
            if t.starts_with("#[cfg(test)]") {
                item_gated = true;
                continue;
            }
            if t.is_empty() || t.starts_with("//") || t.starts_with("#[") {
                continue;
            }
            assert!(
                item_gated,
                "an item after the first #[cfg(test)] is not test-only: {line}"
            );
        }
        depth += i32::try_from(t.matches('{').count()).unwrap();
        depth -= i32::try_from(t.matches('}').count()).unwrap();
        if depth == 0 && (t.ends_with('}') || t.ends_with(';')) {
            item_gated = false;
        }
    }
}
