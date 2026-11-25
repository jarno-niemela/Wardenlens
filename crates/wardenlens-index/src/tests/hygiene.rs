//! Invariant 5: no SQL is built from data, and nothing but `sql.rs` runs SQL. The compiler
//! enforces it: the connection is a `sql::Db` whose `rusqlite::Connection` is private to `sql.rs`,
//! the read wrappers take a `ReadSql` token and the others a `&'static str`. These text tests are
//! a **secondary** layer over every production source file found on disk (not a hand-kept list):
//! no direct driver call outside `sql.rs`, no raw `Connection` held outside the three files that
//! open one, and the setup wrappers used only by the open sequence and the reference schema.

use std::path::{Path, PathBuf};

/// `rusqlite` methods that take SQL text.
const SQL_CALLS: [&str; 8] = [
    ".prepare(",
    ".prepare_cached(",
    ".execute(",
    ".execute_batch(",
    ".query_row(",
    ".query_one(",
    ".pragma_update(",
    ".pragma_query_value(",
];

fn production_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "tests") {
                    continue; // the test modules
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out.sort();
    out
}

/// The text of a production file without comments, and without the `#[cfg(test)]` modules.
fn code(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .take_while(|l| !l.starts_with("#[cfg(test)]"))
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .split('\n')
        .fold(String::new(), |mut acc, line| {
            // Join a wrapped method call (`w\n    .execute(`) onto the receiver's line.
            if line.trim_start().starts_with('.') {
                acc.push_str(line.trim_start());
            } else {
                acc.push('\n');
                acc.push_str(line);
            }
            acc
        })
}

fn file_name(p: &Path) -> String {
    p.file_name().unwrap().to_string_lossy().into_owned()
}

#[test]
fn the_scan_sees_the_production_sources() {
    let names: Vec<_> = production_sources().iter().map(|p| file_name(p)).collect();
    for want in [
        "sql.rs",
        "open.rs",
        "ops.rs",
        "migrate.rs",
        "lib.rs",
        "cursor.rs",
    ] {
        assert!(
            names.iter().any(|n| n == want),
            "{want} not found in {names:?}"
        );
    }
}

#[test]
fn only_sql_rs_calls_the_driver_with_sql_text() {
    let mut calls_in_sql_rs = 0;
    for p in production_sources() {
        let text = code(&p);
        for call in SQL_CALLS {
            // `WriteTx`'s methods are `write` and `write_batch`, so there is no exemption: any
            // `.execute(` outside sql.rs is a direct driver call.
            let n = text.matches(call).count();
            if file_name(&p) == "sql.rs" {
                calls_in_sql_rs += n;
            } else {
                assert_eq!(n, 0, "{}: direct call {call} outside sql.rs", p.display());
            }
        }
    }
    assert!(
        calls_in_sql_rs >= 4,
        "the scan did not find the sql.rs wrappers"
    );
}

#[test]
fn no_source_formats_or_concatenates_strings_into_sql() {
    for p in production_sources() {
        let text = code(&p);
        let name = file_name(&p);
        // `format!` builds the cursor text and the scratch directory name only; neither is SQL.
        if name != "cursor.rs" {
            assert!(!text.contains("format!"), "{name}: format!");
        }
        assert!(!text.contains("concat!"), "{name}");
        assert!(!text.contains("push_str("), "{name}");
        assert!(!text.contains("+ \"") && !text.contains("\" +"), "{name}");
    }
}

#[test]
fn the_wrappers_take_only_static_strings() {
    let sql = code(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sql.rs"));
    for f in [
        "prepare(",
        "execute_unversioned(",
        "query_row_unversioned<",
        "query_row<",
        "write<",
        "write_batch(",
    ] {
        let at = sql
            .find(&format!("fn {f}"))
            .unwrap_or_else(|| panic!("{f}"));
        let sig: String = sql[at..].chars().take_while(|c| *c != '{').collect();
        // Reads take a `ReadSql` token (only `sql.rs` can make one), the rest a `&'static str`.
        assert!(
            sig.contains("&'static str") || sig.contains("ReadSql"),
            "{f}: {sig}"
        );
    }
}

/// Statements that are not index data run through `sql::execute_unversioned` and
/// `sql::query_row_unversioned`, which do not bump the generation: only the open sequence and the
/// reference schema may use them, never a segment operation (those need a `WriteTx`, enforced by
/// the types).
#[test]
fn execute_unversioned_is_used_only_by_open_and_migrate() {
    let mut seen = 0;
    for p in production_sources() {
        let n = code(&p).matches("execute_unversioned(").count()
            + code(&p).matches("query_row_unversioned(").count();
        let name = file_name(&p);
        if name == "sql.rs" {
            continue;
        }
        if name == "open.rs" || name == "migrate.rs" {
            seen += n;
        } else {
            assert_eq!(n, 0, "{name} runs an unversioned statement");
        }
    }
    assert!(seen >= 4, "the scan found {seen} uses");
}

/// Only `sql.rs` (the wrapper) and the two files that open a connection name the driver's
/// `Connection`; a field or parameter of that type elsewhere would be a way round `sql::Db`.
#[test]
fn only_the_files_that_open_a_connection_name_the_raw_connection() {
    for p in production_sources() {
        let name = file_name(&p);
        let text = code(&p);
        let uses = text.contains("Connection");
        if matches!(name.as_str(), "sql.rs" | "open.rs" | "migrate.rs") {
            continue;
        }
        assert!(!uses, "{name} names the driver's Connection");
    }
}
