//! Invariant 5: no SQL is built from data. The production sources are read at compile time and
//! scanned; the enforcement is the shape (statements are `&'static str` constants in `sql.rs`)
//! plus this grep.

const SOURCES: [(&str, &str); 9] = [
    ("lib.rs", include_str!("../lib.rs")),
    ("error.rs", include_str!("../error.rs")),
    ("migrate.rs", include_str!("../migrate.rs")),
    ("open.rs", include_str!("../open.rs")),
    ("ops.rs", include_str!("../ops.rs")),
    ("rows.rs", include_str!("../rows.rs")),
    ("sql.rs", include_str!("../sql.rs")),
    ("cursor.rs", include_str!("../cursor.rs")),
    ("tests-excluded", ""),
];

/// Calls that take SQL text.
const SQL_CALLS: [&str; 7] = [
    ".prepare(",
    ".execute(",
    ".execute_batch(",
    ".query_row(",
    ".prepare_cached(",
    ".query_one(",
    ".pragma_update(",
];

fn code_lines(src: &str) -> Vec<&str> {
    // Production code only: stop at the first test module.
    src.lines()
        .take_while(|l| !l.starts_with("#[cfg(test)]"))
        .collect()
}

#[test]
fn no_source_formats_or_concatenates_sql() {
    for (name, src) in SOURCES {
        for (n, line) in code_lines(src).into_iter().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            // `format!` is allowed only for the cursor text, which is not SQL.
            if code.contains("format!") {
                assert!(
                    name == "cursor.rs",
                    "{name}:{n}: format! in production code: {line}"
                );
            }
            assert!(!code.contains("concat!"), "{name}:{n}: {line}");
            assert!(
                !code.contains("+ \"") && !code.contains("\" +"),
                "{name}:{n}: {line}"
            );
            assert!(!code.contains("push_str("), "{name}:{n}: {line}");
        }
    }
}

#[test]
fn every_sql_call_takes_a_constant_from_the_sql_module_or_a_script() {
    let mut calls = 0;
    for (name, src) in SOURCES {
        for (n, line) in code_lines(src).into_iter().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for call in SQL_CALLS {
                if let Some(at) = code.find(call) {
                    calls += 1;
                    let args = code.get(at + call.len()..).unwrap_or("");
                    // An argument on a later line (rustfmt wraps) is the identifier `sql::X`, the
                    // function parameter `sql`, or a migration script `m.sql`.
                    let ok = args.trim().is_empty()
                        || args.starts_with("sql::")
                        || args.starts_with("m.sql")
                        || args.starts_with("sql,")
                        || args.starts_with("query,");
                    assert!(ok, "{name}:{n}: {line}");
                }
            }
        }
    }
    assert!(
        calls > 10,
        "the grep saw only {calls} calls: the scan is not reaching the code"
    );
}

#[test]
fn sql_constants_carry_no_interpolation() {
    let src = include_str!("../sql.rs");
    assert!(!src.contains("{}") && !src.contains("{0}"));
    assert!(src.contains("&str"));
}
