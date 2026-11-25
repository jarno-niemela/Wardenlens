//! Adversarial tests for the service config (#47, PR #136).
#![expect(clippy::unwrap_used, reason = "adversarial tests")]

use std::net::SocketAddr;
use std::path::Path;

use wardenlens_core::config::{
    BindClass, BindError, Config, ConfigError, ConflictKind, ListenProblem, MAX_CONFIG_BYTES,
    PathProblem, bind,
};

const BASE: &str = r#"
[api]
listen = "127.0.0.1:8080"

[storage]
hot_root = "/srv/wardenlens/hot"
archive_root = "/srv/wardenlens/archive"

[database]
path = "/srv/wardenlens/state/index.db"

[secrets]
key_file = "/srv/wardenlens/state/secrets.key"
"#;

fn listen_cfg(listen: &str, unspec: bool, cgnat: bool) -> String {
    format!(
        "[api]\nlisten = \"{listen}\"\nallow_unspecified_bind = {unspec}\nallow_cgnat_bind = {cgnat}\n\
         [storage]\nhot_root = \"/srv/wardenlens/hot\"\narchive_root = \"/srv/wardenlens/archive\"\n\
         [database]\npath = \"/srv/wardenlens/state/index.db\"\n\
         [secrets]\nkey_file = \"/srv/wardenlens/state/secrets.key\"\n"
    )
}

fn paths_cfg(hot: &str, archive: &str, db: &str, key: &str) -> String {
    format!(
        "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{hot}\"\narchive_root = \"{archive}\"\n\
         [database]\npath = \"{db}\"\n[secrets]\nkey_file = \"{key}\"\n"
    )
}

/// Runs `f` on a thread with a small (default-sized) stack so stack exhaustion shows up as a
/// failed join instead of only on large-stack main threads.
fn on_small_stack<F: FnOnce() + Send + 'static>(f: F) -> bool {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .is_ok()
}

// ---------------------------------------------------------------- bind (invariant 1)

/// Full flag matrix: each class x each (unspec, cgnat) combination, through the public
/// `Config` entry point (not just `check_bind`).
#[test]
fn every_class_under_every_flag_combination_through_config() {
    // (listen, class) ; class decides which flag opens it
    let rows: &[(&str, &str)] = &[
        ("127.0.0.1:1", "lan"),
        ("127.255.255.254:1", "lan"),
        ("[::1]:1", "lan"),
        ("[::ffff:127.0.0.1]:1", "lan"),
        ("10.0.0.1:1", "lan"),
        ("172.16.0.1:1", "lan"),
        ("172.31.255.254:1", "lan"),
        ("192.168.0.1:1", "lan"),
        ("[::ffff:192.168.0.1]:1", "lan"),
        ("[fc00::1]:1", "lan"),
        ("[fdff::1]:1", "lan"),
        ("169.254.0.1:1", "lan"),
        ("[fe80::1]:1", "lan"),
        ("[fe80::1%1]:1", "lan"),
        ("[febf::1%7]:1", "lan"),
        ("100.64.0.1:1", "cgnat"),
        ("[::ffff:100.100.100.100]:1", "cgnat"),
        ("0.0.0.0:1", "unspec"),
        ("[::]:1", "unspec"),
        ("[::ffff:0.0.0.0]:1", "unspec"),
        ("192.0.2.1:1", "refused"),
        ("198.51.100.1:1", "refused"),
        ("203.0.113.1:1", "refused"),
        ("[::ffff:192.0.2.1]:1", "refused"),
        ("[2001:db8::1]:1", "refused"),
        ("[2001:db8::1%1]:1", "refused"),
        ("[fec0::1]:1", "refused"),
        ("[ff02::1]:1", "refused"),
        ("[ff02::1%1]:1", "refused"),
        ("224.0.0.1:1", "refused"),
        ("255.255.255.255:1", "refused"),
        ("0.0.0.1:1", "refused"),
        ("[::0.0.0.0]:1", "unspec"), // that is `::` itself
        ("[::10.0.0.1]:1", "refused"),
        ("[::127.0.0.1]:1", "refused"),
        ("[64:ff9b::10.0.0.1]:1", "refused"),
        ("[64:ff9b::0.0.0.0]:1", "refused"),
        ("[2002:a00:1::]:1", "refused"),
        ("[2002::]:1", "refused"),
        ("[::ffff:0:0.0.0.0]:1", "refused"),
        ("[::ffff:0:127.0.0.1]:1", "refused"),
        ("[100::1]:1", "refused"),
        ("[2001::1]:1", "refused"), // Teredo embeds IPv4
        ("[2001:0:a00:1::]:1", "refused"),
        ("[fe80::ffff:a00:1]:1", "lan"),
    ];
    for (listen, kind) in rows {
        for unspec in [false, true] {
            for cgnat in [false, true] {
                let r = Config::from_toml_str(&listen_cfg(listen, unspec, cgnat));
                let want_ok = match *kind {
                    "lan" => true,
                    "cgnat" => cgnat,
                    "unspec" => unspec,
                    _ => false,
                };
                assert_eq!(
                    r.is_ok(),
                    want_ok,
                    "{listen} unspec={unspec} cgnat={cgnat}: {r:?}"
                );
                if let Ok(c) = r {
                    let addr: SocketAddr = listen.parse().unwrap();
                    assert_eq!(
                        c.listen(),
                        addr,
                        "{listen}: listen must be preserved exactly"
                    );
                }
            }
        }
    }
}

#[test]
fn listen_with_surrounding_whitespace_or_odd_forms_is_refused() {
    for listen in [
        " 127.0.0.1:8080",
        "127.0.0.1:8080 ",
        "127.0.0.1:8080\\n",
        "127.0.0.1:+8080",
        "[127.0.0.1]:8080",
        "[::1]:8080:80",
        "[fe80::1%eth0]:8080",
        "[fe80::1%-1]:8080",
        "[fe80::1%+1]:8080",
        "[fe80::1%4294967296]:8080",
        "[fe80::1%0x2]:8080",
        "localhost:8080",
        "127.0.0.1:0",
        "[::1]:0",
        "http://127.0.0.1:8080",
        "127.0.0.1:8080/",
        "\u{ff11}27.0.0.1:8080",
    ] {
        let r = Config::from_toml_str(&listen_cfg(listen, true, true));
        assert!(r.is_err(), "{listen:?} accepted: {r:?}");
    }
}

#[test]
fn leading_zero_port_policy_documented() {
    // std accepts "08080"? Record whatever it does; the config must agree with std's parse.
    let s = "127.0.0.1:08080";
    let std_ok = s.parse::<SocketAddr>().is_ok();
    let cfg_ok = Config::from_toml_str(&listen_cfg(s, false, false)).is_ok();
    assert_eq!(std_ok, cfg_ok);
}

#[test]
fn check_bind_port_zero_takes_precedence_over_class() {
    let a: SocketAddr = "8.8.8.8:0".parse().unwrap();
    assert_eq!(bind::check_bind(a, false, false), Err(BindError::PortZero));
    let a: SocketAddr = "100.64.0.1:0".parse().unwrap();
    assert_eq!(bind::check_bind(a, false, false), Err(BindError::PortZero));
}

#[test]
fn classify_is_scope_independent_for_every_v6_class() {
    for (text, class) in [
        ("fe80::1", BindClass::LinkLocal),
        ("fd00::1", BindClass::UniqueLocal),
        ("::1", BindClass::Loopback),
        ("2001:db8::1", BindClass::Refused),
    ] {
        for scope in [0_u32, 1, u32::MAX] {
            let addr = SocketAddr::V6(std::net::SocketAddrV6::new(
                text.parse().unwrap(),
                80,
                0,
                scope,
            ));
            assert_eq!(bind::classify(addr.ip()), class, "{text}%{scope}");
        }
    }
}

// ---------------------------------------------------------------- paths (invariant 2)

#[test]
fn path_lexical_table() {
    let ok = "/srv/wardenlens/state/index.db";
    let cases: &[(&str, Option<PathProblem>)] = &[
        ("/srv/wardenlens/hot", None),
        ("srv/wardenlens/hot", Some(PathProblem::NotAbsolute)),
        ("./srv/hot", Some(PathProblem::NotAbsolute)),
        ("~/hot", Some(PathProblem::NotAbsolute)),
        ("", Some(PathProblem::BadLength)),
        ("/", Some(PathProblem::Root)),
        ("//", Some(PathProblem::NotCanonical)),
        ("//srv/hot", Some(PathProblem::NotCanonical)),
        ("/srv//hot", Some(PathProblem::NotCanonical)),
        ("/srv/hot/", Some(PathProblem::NotCanonical)),
        ("/srv/./hot", Some(PathProblem::DotComponent)),
        ("/srv/hot/.", Some(PathProblem::DotComponent)),
        ("/srv/../hot", Some(PathProblem::DotComponent)),
        ("/..", Some(PathProblem::DotComponent)),
        ("/.", Some(PathProblem::DotComponent)),
        ("/srv/hot\\u0000", Some(PathProblem::ControlChar)),
        ("/srv/hot\\n", Some(PathProblem::ControlChar)),
        ("/srv/hot\\r", Some(PathProblem::ControlChar)),
        ("/srv/hot\\u007f", Some(PathProblem::ControlChar)),
        ("/srv/hot\\u0085", Some(PathProblem::ControlChar)),
        ("/srv/...", None),
        ("/srv/.hot", None),
        ("/srv/..hot", None),
    ];
    for (hot, want) in cases {
        let r = Config::from_toml_str(&paths_cfg(hot, "/srv/wardenlens/archive", ok, "/srv/k"));
        match want {
            None => assert!(r.is_ok(), "{hot:?}: {r:?}"),
            Some(p) => assert_eq!(
                r,
                Err(ConfigError::Path {
                    key: "storage.hot_root",
                    reason: *p
                }),
                "{hot:?}"
            ),
        }
    }
}

/// Every pair relation among the four paths, in both orders.
#[test]
fn layout_every_pair_both_orders() {
    let hot = "/srv/w/hot";
    let arc = "/srv/w/archive";
    let db = "/srv/w/state/index.db";
    let key = "/srv/w/state/secrets.key";
    // Same
    for (h, a, d, k) in [
        (hot, hot, db, key),
        (hot, arc, hot, key),
        (hot, arc, arc, key),
        (hot, arc, db, hot),
        (hot, arc, db, arc),
        (hot, arc, db, db),
    ] {
        let r = Config::from_toml_str(&paths_cfg(h, a, d, k));
        assert!(
            matches!(
                r,
                Err(ConfigError::Conflict {
                    reason: ConflictKind::Same,
                    ..
                })
            ),
            "{h} {a} {d} {k}: {r:?}"
        );
    }
    // Nested, both directions
    for (h, a, d, k) in [
        ("/srv/w", "/srv/w/archive", db, key),
        ("/srv/w/archive/hot", "/srv/w/archive", db, key),
        (hot, arc, "/srv/w/hot/index.db", key),
        (hot, arc, "/srv/w/archive/x/index.db", key),
        (hot, arc, db, "/srv/w/hot/secrets.key"),
        (hot, arc, db, "/srv/w/archive/secrets.key"),
        ("/srv/w/state/index.db/hot", arc, db, key),
    ] {
        let r = Config::from_toml_str(&paths_cfg(h, a, d, k));
        assert!(
            matches!(
                r,
                Err(ConfigError::Conflict {
                    reason: ConflictKind::Nested,
                    ..
                })
            ),
            "{h} {a} {d} {k}: {r:?}"
        );
    }
    // Component prefix but not a path prefix: accepted.
    for (h, a) in [
        ("/srv/hot", "/srv/hot2"),
        ("/srv/hot2", "/srv/hot"),
        ("/srv/a", "/srv/a.b"),
    ] {
        let r = Config::from_toml_str(&paths_cfg(h, a, db, key));
        assert!(r.is_ok(), "{h} {a}: {r:?}");
    }
}

/// A key file nested *under* the database path (or the other way round) is a conflict the
/// same way a file under a root is: the two must be independent files.
#[test]
#[ignore = "follow-up #137: database.path and secrets.key_file are only compared for equality"]
fn key_file_and_database_must_not_nest() {
    let r = Config::from_toml_str(&paths_cfg(
        "/srv/w/hot",
        "/srv/w/archive",
        "/srv/w/state",
        "/srv/w/state/secrets.key",
    ));
    assert!(
        r.is_err(),
        "database path is a directory holding the key file: {r:?}"
    );
}

#[test]
fn paths_roundtrip_exactly() {
    let c = Config::from_toml_str(BASE).unwrap();
    assert_eq!(c.hot_root(), Path::new("/srv/wardenlens/hot"));
    assert_eq!(c.archive_root(), Path::new("/srv/wardenlens/archive"));
    assert_eq!(
        c.database_path(),
        Path::new("/srv/wardenlens/state/index.db")
    );
    assert_eq!(c.key_file(), Path::new("/srv/wardenlens/state/secrets.key"));
}

#[test]
fn unicode_paths_lookalike_roots_are_distinct_but_accepted() {
    // NFC vs NFD spellings are different byte paths on Linux; both accepted and distinct.
    let r = Config::from_toml_str(&paths_cfg(
        "/srv/caf\u{e9}",
        "/srv/cafe\u{301}",
        "/srv/state/db",
        "/srv/state/key",
    ));
    assert!(r.is_ok(), "{r:?}");
}

// ---------------------------------------------------------------- numbers (invariant 3)

fn with_storage(extra: &str) -> String {
    BASE.replace("[storage]\n", &format!("[storage]\n{extra}\n"))
}

fn with_recording(extra: &str) -> String {
    format!("{BASE}\n[recording]\n{extra}\n")
}

#[test]
fn numeric_edges_every_key() {
    let rows: &[(&str, bool, i64, i64)] = &[
        ("hot_min_free_percent", true, 0, 90),
        ("archive_min_free_percent", true, 0, 90),
        ("hot_max_age", true, 60, 604_800),
        ("max_actions_per_tick", true, 1, 1024),
        ("segment_target_secs", false, 10, 290),
    ];
    for (name, storage, lo, hi) in rows {
        let mk = |v: String| {
            let line = format!("{name} = {v}");
            if *storage {
                with_storage(&line)
            } else {
                with_recording(&line)
            }
        };
        for v in [*lo, *hi] {
            assert!(
                Config::from_toml_str(&mk(v.to_string())).is_ok(),
                "{name}={v}"
            );
        }
        for v in [
            lo - 1,
            hi + 1,
            -1,
            i64::MIN,
            i64::MAX,
            i64::from(u32::MAX) + *lo,
            i64::from(u8::MAX) + 1 + lo,
        ] {
            if (*lo..=*hi).contains(&v) {
                continue;
            }
            let r = Config::from_toml_str(&mk(v.to_string()));
            assert!(
                matches!(r, Err(ConfigError::OutOfRange { .. })),
                "{name}={v}: {r:?}"
            );
        }
        for v in [
            "25.0",
            "\"25\"",
            "true",
            "[25]",
            "1979-05-27",
            "inf",
            "nan",
            "0x19",
            "0o31",
            "0b11001",
        ] {
            let r = Config::from_toml_str(&mk(v.to_owned()));
            // hex/octal/binary are valid TOML integers: accepted iff in range
            if v.starts_with("0x") || v.starts_with("0o") || v.starts_with("0b") {
                let n = 25_i64;
                assert_eq!(r.is_ok(), (*lo..=*hi).contains(&n), "{name}={v}: {r:?}");
            } else {
                assert!(r.is_err(), "{name}={v}");
            }
        }
    }
}

#[test]
fn defaults_match_adr_0005() {
    let c = Config::from_toml_str(BASE).unwrap();
    let p = c.storage_policy();
    assert_eq!(p.hot_min_free.get(), 25);
    assert_eq!(p.archive_min_free.get(), 25);
    assert_eq!(p, wardenlens_core::storage::Policy::default());
    assert_eq!(c.segment_target_secs(), 60);
    assert_eq!(c.max_actions_per_tick(), 64);
    assert!(!c.allow_cgnat_bind());
    assert!(!c.allow_unspecified_bind());
}

#[test]
fn segment_target_secs_is_accepted_by_the_segmenter_across_range() {
    for v in 10..=290_u32 {
        let c =
            Config::from_toml_str(&with_recording(&format!("segment_target_secs = {v}"))).unwrap();
        assert!(
            wardenlens_core::recording::SegmentConfig::new(
                c.segment_target_secs(),
                64 * 1024 * 1024
            )
            .is_ok(),
            "{v}"
        );
    }
}

// ---------------------------------------------------------------- size, strictness (invariant 4)

#[test]
fn size_bound_counts_bytes_not_chars() {
    // Multibyte padding: under 64 Ki chars but over 64 KiB bytes.
    let pad_chars = MAX_CONFIG_BYTES / 2;
    let text = format!("{BASE}# {}\n", "\u{e9}".repeat(pad_chars));
    assert!(text.chars().count() < MAX_CONFIG_BYTES);
    assert!(text.len() > MAX_CONFIG_BYTES);
    assert!(matches!(
        Config::from_toml_str(&text),
        Err(ConfigError::TooLarge { .. })
    ));
}

#[test]
fn oversized_invalid_input_reports_too_large_not_syntax() {
    let text = "\u{0}".repeat(MAX_CONFIG_BYTES + 1);
    assert!(matches!(
        Config::from_toml_str(&text),
        Err(ConfigError::TooLarge { .. })
    ));
}

#[test]
fn deeply_nested_arrays_within_bound_do_not_overflow_the_stack() {
    let depth = (MAX_CONFIG_BYTES - 16) / 2;
    let text = format!("x = {}{}\n", "[".repeat(depth), "]".repeat(depth));
    assert!(text.len() <= MAX_CONFIG_BYTES);
    assert!(on_small_stack(move || {
        assert!(Config::from_toml_str(&text).is_err());
    }));
}

#[test]
fn deeply_nested_inline_tables_within_bound_do_not_overflow_the_stack() {
    let depth = (MAX_CONFIG_BYTES - 16) / 7;
    let text = format!("x = {}1{}\n", "{a = ".repeat(depth), "}".repeat(depth));
    assert!(text.len() <= MAX_CONFIG_BYTES);
    assert!(on_small_stack(move || {
        assert!(Config::from_toml_str(&text).is_err());
    }));
}

#[test]
fn deeply_dotted_keys_within_bound_do_not_overflow_the_stack() {
    let depth = (MAX_CONFIG_BYTES - 16) / 2;
    let text = format!("{}a = 1\n", "a.".repeat(depth));
    assert!(text.len() <= MAX_CONFIG_BYTES);
    assert!(on_small_stack(move || {
        assert!(Config::from_toml_str(&text).is_err());
    }));
}

#[test]
fn deeply_dotted_table_header_within_bound_does_not_overflow_the_stack() {
    let depth = (MAX_CONFIG_BYTES - 16) / 2;
    let text = format!("[{}a]\n", "a.".repeat(depth));
    assert!(text.len() <= MAX_CONFIG_BYTES);
    assert!(on_small_stack(move || {
        assert!(Config::from_toml_str(&text).is_err());
    }));
}

#[test]
fn deeply_dotted_known_section_does_not_overflow_the_stack() {
    // Starts with a known section so the root check passes, nesting sits inside it.
    let depth = (MAX_CONFIG_BYTES - BASE.len() - 64) / 2;
    let text = format!("{BASE}\n[storage.{}a]\n", "a.".repeat(depth));
    assert!(text.len() <= MAX_CONFIG_BYTES);
    assert!(on_small_stack(move || {
        assert!(Config::from_toml_str(&text).is_err());
    }));
}

#[test]
fn unknown_keys_refused_in_every_form() {
    for extra in [
        "[api]\nlisten = \"127.0.0.1:1\"\nallow_unspecified = true\n",
        "[api.extra]\n",
        "[[recording]]\n",
        "[storage.hot]\npath = \"/srv/x\"\n",
        "[database.path.x]\n",
        "unknown = 1\n",
        "[\"api\"]\nListen = \"127.0.0.1:1\"\n",
        "api.allow_unspecified = true\n",
        "storage = { hot_root = \"/srv/a\", archive_root = \"/srv/b\", extra = 1 }\n",
        "[recording]\nsegment_seconds = 60\n",
        "[secrets]\nkey_file = \"/srv/k\"\nkey_file_mode = 1\n",
        "[database]\npath = \"/srv/d\"\nPath = \"/srv/d\"\n",
    ] {
        // Put the extra first so it is the only thing in its (possibly duplicate) section;
        // if it duplicates a section in BASE that is a syntax error, also a refusal.
        let text = format!("{extra}\n");
        let r = Config::from_toml_str(&text);
        assert!(r.is_err(), "{extra:?}");
        let text2 = format!(
            "{BASE}\n{}",
            extra.replace("[api]\nlisten = \"127.0.0.1:1\"\n", "[api.z]\n")
        );
        assert!(Config::from_toml_str(&text2).is_err(), "{text2}");
    }
}

#[test]
fn bom_and_crlf_input() {
    let crlf = BASE.replace('\n', "\r\n");
    assert!(
        Config::from_toml_str(&crlf).is_ok(),
        "CRLF config must parse"
    );
    let bom = format!("\u{feff}{BASE}");
    // Whatever the policy, it must not panic and must not echo.
    let _ = Config::from_toml_str(&bom);
}

// ---------------------------------------------------------------- no echo (invariant 5)

const S: &str = "Zq7SENTINELx9";

fn assert_no_echo(r: &Result<Config, ConfigError>, ctx: &str) {
    if let Err(e) = r {
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(S), "{ctx}: {shown}");
        assert!(!shown.contains("Zq7"), "{ctx}: {shown}");
    }
}

#[test]
fn no_echo_over_every_error_path() {
    let inputs = vec![
        S.to_owned(),
        format!("{S} = "),
        format!("[{S}]"),
        format!("[api]\n{S} = 1\n"),
        format!("[api]\nlisten = \"{S}\"\n"),
        format!("[api]\nlisten = {S}\n"),
        format!("[api]\nlisten = \"{S}:80\"\n"),
        format!("[api]\nlisten = 1\n# {S}\n"),
        format!("{BASE}\n[storage.x]\n{S} = 1\n"),
        format!("{BASE}\n\"{S}\" = 1\n"),
        format!("x = \"\"\"{S}"),
        format!("x = '{S}"),
        format!("x = \"\\u{S}\""),
        format!("x = 1979-05-27T{S}"),
        format!("x = {{ {S} }}"),
        format!("x = [{S}]"),
        format!("x = 1\nx = \"{S}\""),
        format!("{S} = 1\n{S} = 2\n"),
        format!("[a]\n[a]\n# {S}"),
        format!("[api]\nlisten = \"127.0.0.1:8080\"\n[api]\n{S}=1"),
        paths_cfg(
            &format!("/srv/{S}"),
            &format!("/srv/{S}"),
            "/srv/d",
            "/srv/k",
        ),
        paths_cfg(S, "/srv/a", "/srv/d", "/srv/k"),
        paths_cfg(&format!("/srv/{S}/.."), "/srv/a", "/srv/d", "/srv/k"),
        paths_cfg(&format!("/srv/{S}\\u0001"), "/srv/a", "/srv/d", "/srv/k"),
        format!("{BASE}\n[recording]\nsegment_target_secs = \"{S}\"\n"),
        format!("{BASE}\n[recording]\nsegment_target_secs = 99999999999999999999 # {S}\n"),
        format!("\u{0}{S}"),
        format!("x = \"{S}\u{0}\""),
    ];
    for text in &inputs {
        let r = Config::from_toml_str(text);
        assert!(r.is_err(), "{text:?}");
        assert_no_echo(&r, text);
    }
}

#[test]
fn listen_error_variants_carry_no_input() {
    let r = Config::from_toml_str(&listen_cfg("192.0.2.1:8080", false, false));
    assert_eq!(
        r,
        Err(ConfigError::Listen {
            reason: ListenProblem::Bind(BindError::NotLan)
        })
    );
    let msg = r.unwrap_err().to_string();
    assert!(!msg.contains("192.0.2"), "{msg}");
}

#[test]
fn syntax_line_is_correct_after_multibyte_text() {
    let text = "# \u{e9}\u{e9}\u{e9}\n# \u{1f600}\nx = \u{e9}\n";
    let r = Config::from_toml_str(text);
    assert_eq!(r, Err(ConfigError::Syntax { line: Some(3) }));
}

#[test]
fn syntax_line_counts_crlf_once() {
    let text = "a = 1\r\nb = 2\r\nc = =\r\n";
    assert_eq!(
        Config::from_toml_str(text),
        Err(ConfigError::Syntax { line: Some(3) })
    );
}
