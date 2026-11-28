//! Invariant 5: no SQL is built from data, and nothing but `sql.rs` runs SQL. The compiler
//! enforces it: the connection is a `sql::Db` whose `rusqlite::Connection` is private to `sql.rs`,
//! the read wrappers take a `ReadSql` token and the others a `&'static str`. These text tests are
//! a **secondary** layer over every production source file found on disk (not a hand-kept list):
//! no direct driver call outside `sql.rs`, no raw `Connection` held outside the three files that
//! open one, and the setup wrappers used only by the open sequence and the reference schema.

use std::path::{Path, PathBuf};

/// Every `rusqlite` 0.43 `Connection` method that runs SQL text, opens a transaction or copies a
/// database in or out (the same list `tests/adversary_145_r2_hygiene.rs` scans for).
const SQL_CALLS: &[&str] = &[
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
    // The same methods called as associated functions, and the other entry points that run SQL.
    "Connection::prepare(",
    "Connection::prepare_cached(",
    "Connection::prepare_with_flags(",
    "Connection::execute(",
    "Connection::execute_batch(",
    "Connection::query_row(",
    "Connection::query_one(",
    "Connection::query_row_and_then(",
    "Connection::pragma(",
    "Connection::pragma_query(",
    "Connection::pragma_query_one(",
    "Connection::pragma_query_value(",
    "Connection::pragma_update(",
    "Connection::pragma_update_and_check(",
    "Connection::transaction(",
    "Connection::transaction_with_behavior(",
    "Connection::unchecked_transaction(",
    "Connection::savepoint(",
    "Connection::savepoint_with_name(",
    "Connection::backup(",
    "Connection::restore(",
    "Connection::blob_open(",
    "Backup::new(",
    "Batch::new(",
    "Transaction::new(",
    "Transaction::new_unchecked(",
    "Savepoint::new(",
    "Savepoint::with_name(",
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

/// Removes every turbofish (`::<...>`) that is followed by `(`, so `conn.query_row::<i64, _, _>(`
/// reads as `conn.query_row(`.
fn strip_turbofish(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("::<") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 3..];
        let mut depth = 1usize;
        let mut end = None;
        for (i, c) in after.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(e) if after[e..].starts_with('(') => rest = &after[e..],
            _ => {
                out.push_str("::<");
                rest = after;
            }
        }
    }
    out.push_str(rest);
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
        .map(strip_turbofish)
        .fold(String::new(), |mut acc, line| {
            // Join a wrapped method call (`w\n    .execute(`) onto the receiver's line.
            if line.trim_start().starts_with('.') {
                acc.push_str(line.trim_start());
            } else {
                acc.push('\n');
                acc.push_str(&line);
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

/// Statements that are not index data run through `sql::execute_unversioned`,
/// `sql::query_row_unversioned` and `sql::unversioned_tx`, which do not bump the generation: only the open sequence and the
/// reference schema may use them, never a segment operation (those need a `WriteTx`, enforced by
/// the types).
#[test]
fn execute_unversioned_is_used_only_by_open_and_migrate() {
    let mut seen = 0;
    for p in production_sources() {
        let text = code(&p);
        let n = text.matches("execute_unversioned(").count()
            + text.matches("query_row_unversioned(").count()
            + text.matches("unversioned_tx(").count();
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

/// Adversary (#149): open.rs and migrate.rs hold a raw `Connection`, so the text scan is the only
/// guard there. A turbofish call or an associated-function call through the driver should be seen.
#[test]
fn adv_149_the_scan_sees_turbofish_and_associated_function_calls() {
    let dir = tempfile::tempdir().unwrap();
    for (i, src) in [
        "fn f(conn: &Connection) { let _ = conn.query_row::<i64, _, _>(\"x\", [], |r| r.get(0)); }",
        "fn f(conn: &Connection) { let _ = conn.pragma_query_value::<i64, _>(None, \"x\", |r| r.get(0)); }",
        "fn f(a: &Connection, b: &mut Connection) { let _ = rusqlite::backup::Backup::new(a, b); }",
        "fn f(conn: &Connection) { let _ = Connection::execute(conn, \"x\", []); }",
    ]
    .iter()
    .enumerate()
    {
        let p = dir.path().join(format!("f{i}.rs"));
        std::fs::write(&p, src).unwrap();
        let text = code(&p);
        let n: usize = SQL_CALLS.iter().map(|c| text.matches(c).count()).sum();
        assert!(n > 0, "the scan misses: {src}");
    }
}

/// Adversary (#149 round 2): every method in the dot-form list is also listed in its
/// associated-function form (`Connection::query_one(&c, ..)` runs SQL just as `.query_one(` does).
#[test]
fn adv_149_r2_every_dot_form_has_its_associated_function_form() {
    let missing: Vec<String> = SQL_CALLS
        .iter()
        .filter_map(|c| c.strip_prefix('.'))
        .map(|m| format!("Connection::{m}"))
        .filter(|a| !SQL_CALLS.contains(&a.as_str()))
        .collect();
    assert!(missing.is_empty(), "not scanned: {missing:?}");
}
