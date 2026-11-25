use super::*;
use crate::time::DurationMs;

const MINIMAL: &str = r#"
[api]
listen = "127.0.0.1:8080"
[storage]
hot_root = "/srv/wardenlens/hot"
archive_root = "/srv/wardenlens/archive"
[recording]
[database]
path = "/srv/wardenlens/state/index.db"
[secrets]
key_file = "/srv/wardenlens/state/secrets.key"
"#;

/// `MINIMAL` with one line replaced.
fn with(from: &str, to: &str) -> String {
    assert!(MINIMAL.contains(from), "{from}");
    MINIMAL.replacen(from, to, 1)
}

/// `MINIMAL` with `line` appended to `[section]`.
fn with_line(section: &str, line: &str) -> String {
    let header = format!("[{section}]\n");
    assert!(MINIMAL.contains(&header), "{section}");
    MINIMAL.replacen(&header, &format!("{header}{line}\n"), 1)
}

fn parse(text: &str) -> Result<Config, ConfigError> {
    Config::from_toml_str(text)
}

#[test]
fn minimal_config_gets_the_adr_defaults() {
    let c = parse(MINIMAL).unwrap();
    assert_eq!(c.listen(), "127.0.0.1:8080".parse().unwrap());
    assert!(!c.allow_unspecified_bind());
    assert!(!c.allow_cgnat_bind());
    assert_eq!(c.segment_target_secs(), 60);
    assert_eq!(c.max_actions_per_tick(), 64);
    assert_eq!(c.storage_policy(), Policy::default());
    assert_eq!(c.hot_root(), Path::new("/srv/wardenlens/hot"));
    assert_eq!(c.archive_root(), Path::new("/srv/wardenlens/archive"));
    assert_eq!(
        c.database_path(),
        Path::new("/srv/wardenlens/state/index.db")
    );
    assert_eq!(c.key_file(), Path::new("/srv/wardenlens/state/secrets.key"));
}

#[test]
fn explicit_values_reach_the_policy() {
    let text = MINIMAL
        .replace("[storage]\n", "[storage]\nhot_min_free_percent = 10\narchive_min_free_percent = 90\nhot_max_age = 3600\nmax_actions_per_tick = 5\n")
        .replace("[recording]\n", "[recording]\nsegment_target_secs = 120\n");
    let c = parse(&text).unwrap();
    let p = c.storage_policy();
    assert_eq!(p.hot_min_free.get(), 10);
    assert_eq!(p.archive_min_free.get(), 90);
    assert_eq!(p.hot_max_age, DurationMs::from_secs(3600));
    assert_eq!(c.max_actions_per_tick(), 5);
    assert_eq!(c.segment_target_secs(), 120);
}

#[test]
fn example_file_parses() {
    let text = include_str!("../../../../docs/config.example.toml");
    let c = parse(text).unwrap();
    assert_eq!(c.listen(), "127.0.0.1:8080".parse().unwrap());
    assert_eq!(c.hot_root(), Path::new("/srv/wardenlens/hot"));
    assert_eq!(c.storage_policy(), Policy::default());
    // Only synthetic paths and loopback: the example must never carry site data.
    for line in text
        .lines()
        .filter(|l| l.contains('/') && !l.trim_start().starts_with('#'))
    {
        assert!(
            line.contains("/srv/wardenlens/") || line.contains("127.0.0.1"),
            "{line}"
        );
    }
}

// --- invariant: LAN-only bind, through the config -------------------------------------------

#[test]
fn listen_is_checked_with_both_flags() {
    let listen = |addr: &str, flags: &str| {
        let text = with(
            "listen = \"127.0.0.1:8080\"",
            &format!("listen = \"{addr}\"\n{flags}"),
        );
        parse(&text).map(|c| c.listen())
    };
    let refused = |reason| Err(ConfigError::Listen { reason });
    assert!(listen("192.168.1.5:80", "").is_ok());
    assert!(listen("[fd00::1]:80", "").is_ok());
    assert!(listen("[fe80::1%2]:80", "").is_ok());
    assert_eq!(
        listen(
            "192.0.2.1:80",
            "allow_unspecified_bind = true\nallow_cgnat_bind = true"
        ),
        refused(ListenProblem::Bind(BindError::NotLan))
    );
    assert_eq!(
        listen("0.0.0.0:80", ""),
        refused(ListenProblem::Bind(BindError::UnspecifiedNotAllowed))
    );
    assert!(listen("0.0.0.0:80", "allow_unspecified_bind = true").is_ok());
    assert!(listen("[::]:80", "allow_unspecified_bind = true").is_ok());
    assert!(listen("[::ffff:0.0.0.0]:80", "allow_unspecified_bind = true").is_ok());
    assert_eq!(
        listen("100.64.0.1:80", ""),
        refused(ListenProblem::Bind(BindError::CgnatNotAllowed))
    );
    assert!(listen("100.64.0.1:80", "allow_cgnat_bind = true").is_ok());
    assert_eq!(
        listen("127.0.0.1:0", ""),
        refused(ListenProblem::Bind(BindError::PortZero))
    );
    for bad in [
        "localhost:80",
        "127.0.0.1",
        "[fe80::1%eth0]:80",
        "",
        "[::1]",
    ] {
        assert_eq!(
            listen(bad, ""),
            refused(ListenProblem::NotSocketAddr),
            "{bad:?}"
        );
    }
}

#[test]
fn listen_is_required_and_must_be_a_string() {
    let text = MINIMAL.replace("listen = \"127.0.0.1:8080\"\n", "");
    assert_eq!(
        parse(&text),
        Err(ConfigError::Missing { key: "api.listen" })
    );
    let text = with("\"127.0.0.1:8080\"", "8080");
    assert_eq!(
        parse(&text),
        Err(ConfigError::WrongType { key: "api.listen" })
    );
}

// --- invariant: roots and paths -------------------------------------------------------------

#[test]
fn path_table_for_every_path_key() {
    use PathProblem::*;
    let cases: &[(&str, Result<(), PathProblem>)] = &[
        ("/srv/x", Ok(())),
        ("/a", Ok(())),
        ("/srv/with space/x", Ok(())),
        ("/srv/.hidden/x", Ok(())),
        ("/srv/...", Ok(())),
        ("/srv/a..b", Ok(())),
        ("", Err(BadLength)),
        ("relative/x", Err(NotAbsolute)),
        ("srv", Err(NotAbsolute)),
        ("./srv", Err(NotAbsolute)),
        ("../srv", Err(NotAbsolute)),
        ("~/srv", Err(NotAbsolute)),
        ("/", Err(Root)),
        ("//", Err(NotCanonical)),
        ("/srv/", Err(NotCanonical)),
        ("/srv//x", Err(NotCanonical)),
        ("//srv/x", Err(NotCanonical)),
        ("/srv/./x", Err(DotComponent)),
        ("/srv/../x", Err(DotComponent)),
        ("/srv/x/..", Err(DotComponent)),
        ("/./x", Err(DotComponent)),
        ("/srv/x\\u0000y", Err(ControlChar)),
        ("/srv/x\\ny", Err(ControlChar)),
        ("/srv/x\\u007fy", Err(ControlChar)),
        // Invisible characters (`text::is_invisible`: Cf, separators), not only Cc.
        ("/srv/x\\u202ey", Err(ControlChar)),
        ("/srv/x\\u2066y", Err(ControlChar)),
        ("/srv/x\\u2028y", Err(ControlChar)),
        ("/srv/x\\u2029y", Err(ControlChar)),
        ("/srv/x\\u200by", Err(ControlChar)),
        ("/srv/x\\ufeffy", Err(ControlChar)),
        ("/srv/x\\u00ady", Err(ControlChar)),
        ("/srv/x\\u180ey", Err(ControlChar)),
    ];
    let keys = [
        ("storage.hot_root", "hot_root = \"/srv/wardenlens/hot\""),
        (
            "storage.archive_root",
            "archive_root = \"/srv/wardenlens/archive\"",
        ),
        ("database.path", "path = \"/srv/wardenlens/state/index.db\""),
        (
            "secrets.key_file",
            "key_file = \"/srv/wardenlens/state/secrets.key\"",
        ),
    ];
    for (key, line) in keys {
        let name = line.split(' ').next().unwrap();
        for (value, want) in cases {
            let text = with(line, &format!("{name} = \"{value}\""));
            let got = parse(&text);
            match want {
                // Only this key's own validity is under test: a valid value may still collide
                // with another path of MINIMAL, never with a path problem.
                Ok(()) => assert!(
                    !matches!(got, Err(ConfigError::Path { .. })),
                    "{key} {value}"
                ),
                Err(reason) => {
                    assert_eq!(
                        got,
                        Err(ConfigError::Path {
                            key,
                            reason: *reason
                        }),
                        "{key} {value:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn path_over_4096_bytes_is_refused_and_4096_is_accepted() {
    let exact = format!("/{}", "a".repeat(4095));
    let over = format!("/{}", "a".repeat(4096));
    assert_eq!(paths::validate(&exact), Ok(()));
    assert_eq!(paths::validate(&over), Err(PathProblem::BadLength));
}

#[test]
#[expect(clippy::too_many_lines, reason = "a data table of cases")]
fn layout_table() {
    use ConflictKind::{Nested, Same};
    // (hot, archive, database, key_file, expected conflict)
    type Case = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        Option<(&'static str, &'static str, ConflictKind)>,
    );
    let cases: &[Case] = &[
        ("/srv/h", "/srv/a", "/srv/s/db", "/srv/s/k", None),
        // component-wise, not byte-wise, prefix
        ("/srv/h", "/srv/hh", "/srv/s/db", "/srv/s/k", None),
        ("/srv/a", "/srv/ab", "/srv/s/db", "/srv/s/k", None),
        ("/srv/h", "/srv/a", "/srv/hot-state/db", "/srv/s/k", None),
        // roots
        (
            "/srv/h",
            "/srv/h",
            "/s/db",
            "/s/k",
            Some(("storage.hot_root", "storage.archive_root", Same)),
        ),
        (
            "/srv/h",
            "/srv/h/a",
            "/s/db",
            "/s/k",
            Some(("storage.hot_root", "storage.archive_root", Nested)),
        ),
        (
            "/srv/h/x",
            "/srv/h",
            "/s/db",
            "/s/k",
            Some(("storage.hot_root", "storage.archive_root", Nested)),
        ),
        (
            "/srv",
            "/srv/a",
            "/s/db",
            "/s/k",
            Some(("storage.hot_root", "storage.archive_root", Nested)),
        ),
        // database and key file
        (
            "/srv/h",
            "/srv/a",
            "/srv/h",
            "/s/k",
            Some(("database.path", "storage.hot_root", Same)),
        ),
        (
            "/srv/h",
            "/srv/a",
            "/srv/h/db",
            "/s/k",
            Some(("database.path", "storage.hot_root", Nested)),
        ),
        (
            "/srv/h",
            "/srv/a",
            "/srv/a/db",
            "/s/k",
            Some(("database.path", "storage.archive_root", Nested)),
        ),
        (
            "/srv/h",
            "/srv/a",
            "/s/db",
            "/srv/h/k",
            Some(("secrets.key_file", "storage.hot_root", Nested)),
        ),
        (
            "/srv/h",
            "/srv/a",
            "/s/db",
            "/srv/a/sub/k",
            Some(("secrets.key_file", "storage.archive_root", Nested)),
        ),
        (
            "/srv/h",
            "/srv/a",
            "/s/x",
            "/s/x",
            Some(("secrets.key_file", "database.path", Same)),
        ),
        ("/srv/h", "/srv/a", "/s/db", "/s/db2", None),
    ];
    for (hot, archive, db, key, want) in cases {
        let text = format!(
            "[api]\nlisten=\"127.0.0.1:80\"\n[storage]\nhot_root=\"{hot}\"\narchive_root=\"{archive}\"\n[database]\npath=\"{db}\"\n[secrets]\nkey_file=\"{key}\"\n"
        );
        let want = want.map(|(key, other, reason)| ConfigError::Conflict { key, other, reason });
        assert_eq!(parse(&text).err(), want, "{hot} {archive} {db} {key}");
    }
}

// --- invariant: ranges ----------------------------------------------------------------------

#[test]
fn numeric_key_ranges() {
    // (section, key, min, max)
    let keys: &[(&str, &str, i64, i64)] = &[
        ("storage", "hot_min_free_percent", 0, 90),
        ("storage", "archive_min_free_percent", 0, 90),
        ("storage", "hot_max_age", 60, 604_800),
        ("storage", "max_actions_per_tick", 1, 1024),
        ("recording", "segment_target_secs", 10, 290),
    ];
    for (section, key, min, max) in keys {
        let full: &'static str = Box::leak(format!("{section}.{key}").into_boxed_str());
        let run = |v: &str| parse(&with_line(section, &format!("{key} = {v}")));
        for ok in [*min, *max, min + 1, max - 1] {
            assert!(run(&ok.to_string()).is_ok(), "{full} {ok}");
        }
        for bad in [min - 1, max + 1, i64::MIN, i64::MAX, -1] {
            assert_eq!(
                run(&bad.to_string()).err(),
                Some(ConfigError::OutOfRange {
                    key: full,
                    min: *min,
                    max: *max
                }),
                "{full} {bad}"
            );
        }
        for wrong in ["\"30\"", "30.0", "true", "[30]", "{ a = 1 }", "1979-05-27"] {
            assert_eq!(
                run(wrong).err(),
                Some(ConfigError::WrongType { key: full }),
                "{full} {wrong}"
            );
        }
    }
}

#[test]
fn integer_beyond_i64_is_a_syntax_error_without_the_value() {
    let err = parse(&with_line(
        "recording",
        "segment_target_secs = 99999999999999999999999",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::Syntax { .. }), "{err:?}");
    assert!(!err.to_string().contains("9999"));
}

#[test]
fn flags_must_be_booleans() {
    for key in ["allow_unspecified_bind", "allow_cgnat_bind"] {
        for wrong in ["1", "\"true\"", "\"false\""] {
            let err = parse(&with_line("api", &format!("{key} = {wrong}"))).unwrap_err();
            assert!(
                matches!(err, ConfigError::WrongType { .. }),
                "{key} {wrong}"
            );
        }
    }
}

#[test]
fn path_keys_must_be_strings() {
    for (key, section) in [
        ("hot_root", "storage"),
        ("path", "database"),
        ("key_file", "secrets"),
    ] {
        let text = MINIMAL
            .lines()
            .map(|l| {
                if l.trim_start().starts_with(&format!("{key} =")) {
                    format!("{key} = 7")
                } else {
                    l.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let err = parse(&text).unwrap_err();
        assert!(
            matches!(err, ConfigError::WrongType { .. }),
            "{section}.{key}"
        );
    }
}

#[test]
fn missing_required_keys_are_named() {
    for (line, key) in [
        ("hot_root = \"/srv/wardenlens/hot\"\n", "storage.hot_root"),
        (
            "archive_root = \"/srv/wardenlens/archive\"\n",
            "storage.archive_root",
        ),
        (
            "path = \"/srv/wardenlens/state/index.db\"\n",
            "database.path",
        ),
        (
            "key_file = \"/srv/wardenlens/state/secrets.key\"\n",
            "secrets.key_file",
        ),
    ] {
        assert_eq!(
            parse(&MINIMAL.replace(line, "")),
            Err(ConfigError::Missing { key })
        );
    }
    // A whole section missing reports the same key.
    assert_eq!(parse(""), Err(ConfigError::Missing { key: "api.listen" }));
    assert_eq!(
        parse("[api]\nlisten = \"127.0.0.1:80\"\n"),
        Err(ConfigError::Missing {
            key: "storage.hot_root"
        })
    );
}

#[test]
fn sections_must_be_tables() {
    for section in ["api", "storage", "recording", "database", "secrets"] {
        assert_eq!(
            parse(&format!("{section} = 1\n")),
            Err(ConfigError::WrongType {
                key: Box::leak(section.to_owned().into_boxed_str())
            })
        );
    }
}

// --- invariant: unknown fields, size bound --------------------------------------------------

#[test]
fn unknown_keys_are_refused_at_every_level() {
    assert_eq!(
        parse(&format!("{MINIMAL}\n[extra]\nx = 1\n")),
        Err(ConfigError::UnknownKey { section: "<root>" })
    );
    assert_eq!(
        parse(&format!("top = 1\n{MINIMAL}")),
        Err(ConfigError::UnknownKey { section: "<root>" })
    );
    for section in ["api", "storage", "recording", "database", "secrets"] {
        let err = parse(&with_line(section, "bogus = 1")).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownKey { section: s } if s == section),
            "{section}"
        );
    }
    // Old key names from the superseded ticket text are unknown too.
    for (section, line) in [
        ("api", "allow_unspecified = true"),
        ("recording", "segment_seconds = 60"),
        ("storage", "hot = 1"),
    ] {
        assert!(matches!(
            parse(&with_line(section, line)),
            Err(ConfigError::UnknownKey { .. })
        ));
    }
    // A nested table where a scalar is expected is a type error, not silently accepted.
    assert!(matches!(
        parse(&with_line("api", "[api.listen]")).unwrap_err(),
        ConfigError::Syntax { .. } | ConfigError::WrongType { .. }
    ));
}

#[test]
fn size_limit_is_exact() {
    let pad = |total: usize| {
        let mut text = String::from(MINIMAL);
        let fill = total - text.len() - 1;
        text.push('#');
        text.push_str(&"x".repeat(fill - 1));
        text.push('\n');
        assert_eq!(text.len(), total);
        text
    };
    assert!(parse(&pad(MAX_CONFIG_BYTES)).is_ok());
    assert_eq!(
        parse(&pad(MAX_CONFIG_BYTES + 1)),
        Err(ConfigError::TooLarge {
            len: MAX_CONFIG_BYTES + 1,
            max: MAX_CONFIG_BYTES
        })
    );
    // Refused before parsing: invalid toml of that size reports the size, not a syntax error.
    let garbage = "=".repeat(MAX_CONFIG_BYTES + 1);
    assert!(matches!(parse(&garbage), Err(ConfigError::TooLarge { .. })));
}

// --- invariant: errors never echo input (SEC-6) ---------------------------------------------

const SENTINEL: &str = "SENTINEL-4f9a7c";

fn assert_clean(err: &ConfigError) {
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains("SENTINEL"), "{text}");
        assert!(!text.contains("4f9a7c"), "{text}");
    }
}

#[test]
fn no_error_echoes_the_value_of_any_key() {
    let keys = [
        ("api", "listen"),
        ("api", "allow_unspecified_bind"),
        ("api", "allow_cgnat_bind"),
        ("storage", "hot_root"),
        ("storage", "archive_root"),
        ("storage", "hot_min_free_percent"),
        ("storage", "archive_min_free_percent"),
        ("storage", "hot_max_age"),
        ("storage", "max_actions_per_tick"),
        ("recording", "segment_target_secs"),
        ("database", "path"),
        ("secrets", "key_file"),
    ];
    for (section, key) in keys {
        // Replace the key if MINIMAL has it, otherwise add it.
        let mut text = String::new();
        let mut in_section = false;
        let mut done = false;
        for line in MINIMAL.lines() {
            if line.starts_with('[') {
                in_section = line == format!("[{section}]");
                text.push_str(line);
                text.push('\n');
                if in_section && !done {
                    text.push_str(key);
                    text.push_str(" = \"");
                    text.push_str(SENTINEL);
                    text.push_str("\"\n");
                    done = true;
                }
            } else if in_section && line.trim_start().starts_with(&format!("{key} =")) {
                // dropped: replaced by the sentinel line above
            } else {
                text.push_str(line);
                text.push('\n');
            }
        }
        let err = parse(&text).unwrap_err();
        assert_clean(&err);
        // The key itself is named, apart from the generic parse errors.
        assert!(err.to_string().contains(key), "{key}: {err}");
    }
}

#[test]
fn no_error_echoes_a_sentinel_in_malformed_or_unknown_input() {
    for text in [
        SENTINEL.to_owned(),
        format!("{SENTINEL} = "),
        format!("[{SENTINEL}\n"),
        format!("{SENTINEL} = 1\n"),
        format!("[{SENTINEL}]\nx = 1\n"),
        format!("[api]\n{SENTINEL} = 1\n"),
        format!("[api]\nlisten = \"{SENTINEL}\nx\"\n"),
        format!("[api]\nlisten = 1\nlisten = \"{SENTINEL}\"\n"),
        format!("{MINIMAL}\n# {SENTINEL}\n{SENTINEL}\n"),
        with("127.0.0.1:8080", &format!("{SENTINEL}\\u0000")),
        with("/srv/wardenlens/hot", &format!("/{SENTINEL}/../x")),
        with("/srv/wardenlens/hot", SENTINEL),
        with(
            "/srv/wardenlens/hot",
            &format!("/srv/wardenlens/archive/{SENTINEL}"),
        ),
        with(
            "/srv/wardenlens/state/index.db",
            &format!("/srv/wardenlens/hot/{SENTINEL}"),
        ),
        MINIMAL.replace("127.0.0.1:8080", "8.8.8.8:80") + SENTINEL,
        with("127.0.0.1:8080", &format!("[fe80::1%{SENTINEL}]:80")),
    ] {
        let err = parse(&text).unwrap_err();
        assert_clean(&err);
    }
}

#[test]
fn rejected_address_and_path_values_are_not_echoed() {
    let cases = [
        with("127.0.0.1:8080", "203.0.113.77:8080"),
        with(
            "/srv/wardenlens/hot",
            "/srv/wardenlens/archive/inner-secret-name",
        ),
        with("/srv/wardenlens/hot", "relative-secret-name"),
    ];
    for text in cases {
        let shown = parse(&text).unwrap_err().to_string();
        assert!(!shown.contains("203.0.113"), "{shown}");
        assert!(!shown.contains("secret-name"), "{shown}");
    }
}

#[test]
fn every_error_variant_has_a_message_naming_its_subject() {
    let samples = [
        (ConfigError::TooLarge { len: 2, max: 1 }, "bytes"),
        (ConfigError::Syntax { line: Some(3) }, "line 3"),
        (ConfigError::Syntax { line: None }, "unknown"),
        (ConfigError::UnknownKey { section: "api" }, "[api]"),
        (ConfigError::Missing { key: "k.x" }, "k.x"),
        (ConfigError::WrongType { key: "k.x" }, "k.x"),
        (
            ConfigError::OutOfRange {
                key: "k.x",
                min: 1,
                max: 2,
            },
            "1 to 2",
        ),
        (
            ConfigError::Listen {
                reason: ListenProblem::NotSocketAddr,
            },
            "api.listen",
        ),
        (
            ConfigError::Path {
                key: "k.x",
                reason: PathProblem::Root,
            },
            "k.x",
        ),
        (
            ConfigError::Conflict {
                key: "k.x",
                other: "k.y",
                reason: ConflictKind::Same,
            },
            "k.y",
        ),
    ];
    for (err, needle) in samples {
        assert!(err.to_string().contains(needle), "{err}");
    }
}

#[test]
fn syntax_error_reports_the_line() {
    let err = parse("[api]\nlisten = \n").unwrap_err();
    assert_eq!(err, ConfigError::Syntax { line: Some(2) });
}
