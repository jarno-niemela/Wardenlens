//! Invariant 1: open. The refusal table is the enumeration of what can sit at the path.

use std::os::unix::fs::symlink;

use rusqlite::Connection;
use rustix::fs::{CWD, FileType, Mode, mknodat};
use wardenlens_core::storage::{SegmentIndex, Tier};

use super::*;
use crate::error::IndexError;
use crate::open::APPLICATION_ID;

fn pragma_i64(c: &Connection, p: &str) -> i64 {
    c.query_row(&format!("PRAGMA {p}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn fresh_open_sets_and_verifies_every_pragma() {
    let (f, idx) = open_new();
    let mode = std::fs::metadata(&f.path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600);
    let c = &idx.conn;
    assert_eq!(
        c.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    assert_eq!(pragma_i64(c, "synchronous"), 2);
    assert_eq!(pragma_i64(c, "foreign_keys"), 1);
    assert_eq!(pragma_i64(c, "application_id"), i64::from(APPLICATION_ID));
    assert_eq!(pragma_i64(c, "user_version"), 1);
    assert_eq!(pragma_i64(c, "busy_timeout"), 5000);
    assert_eq!(pragma_i64(c, "journal_size_limit"), 67_108_864);
    // The pragma statements in sql.rs carry these literal values.
    assert!(
        crate::sql::BOOTSTRAP.contains(&format!("PRAGMA application_id = {APPLICATION_ID};")),
        "the bootstrap sets the application id of open.rs"
    );
    assert_eq!(
        crate::sql::SET_JOURNAL_LIMIT,
        format!(
            "PRAGMA journal_size_limit = {}",
            crate::open::JOURNAL_SIZE_LIMIT
        )
    );
}

#[test]
fn application_id_is_in_the_main_file_header_before_wal_data() {
    // The identity check reads the header only, so it must hold with a live -wal.
    let (f, idx) = open_new();
    let head = std::fs::read(&f.path).unwrap();
    assert_eq!(&head[68..72], &APPLICATION_ID.to_be_bytes());
    drop(idx);
}

#[test]
fn reopen_keeps_data_and_works_with_a_live_wal() {
    let (f, mut idx) = open_new();
    let id = idx
        .insert(&rec("cam1", BASE, 1000, 10, 1), Tier::Hot)
        .unwrap();
    // Reopen while the first handle is alive: its -wal holds the row, the main file does not.
    let idx2 = Index::open(&f.path).unwrap();
    assert!(idx2.get(id).unwrap().is_some());
}

#[test]
fn reopen_after_close_is_idempotent() {
    let (f, idx) = open_new();
    drop(idx);
    drop(Index::open(&f.path).unwrap());
    drop(Index::open(&f.path).unwrap());
}

fn make_foreign(f: &Fixture, setup: &str, wal: bool) -> Connection {
    let c = raw(&f.path);
    if wal {
        c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
            .unwrap();
    }
    c.execute_batch(setup).unwrap();
    chmod(&f.path, 0o600);
    // SQLite made `-wal` and `-shm` with the mode of the day (0644): the content rules are
    // under test here, the mode rule has its own rows.
    for suffix in ["-wal", "-shm"] {
        let mut n = f.path.as_os_str().to_owned();
        n.push(suffix);
        if std::path::Path::new(&n).exists() {
            chmod(std::path::Path::new(&n), 0o600);
        }
    }
    c
}

/// One row of the refusal table: set the path up, then open must fail with the expected error and
/// leave every byte of the directory as it was.
struct Case {
    name: &'static str,
    setup: fn(&Fixture) -> Option<Connection>,
    expect: fn(&IndexError) -> bool,
}

fn write_private(p: &std::path::Path, bytes: &[u8]) {
    std::fs::write(p, bytes).unwrap();
    chmod(p, 0o600);
}

fn sidecar(f: &Fixture, suffix: &str) -> std::path::PathBuf {
    let mut n = f.path.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

fn own_rollback_db(f: &Fixture) {
    // An index-shaped file that is still in rollback mode (a crash before WAL was switched on).
    let c = raw(&f.path);
    c.execute_batch(&format!(
        "PRAGMA application_id = {APPLICATION_ID}; CREATE TABLE t(x);"
    ))
    .unwrap();
    drop(c);
    chmod(&f.path, 0o600);
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "text file",
            setup: |f| {
                write_private(&f.path, &[b'x'; 300]);
                None
            },
            expect: |e| matches!(e, IndexError::NotAnIndex),
        },
        Case {
            name: "short non-sqlite file",
            setup: |f| {
                write_private(&f.path, b"hi");
                None
            },
            expect: |e| matches!(e, IndexError::NotAnIndex),
        },
        Case {
            name: "magic only, header truncated",
            setup: |f| {
                write_private(&f.path, b"SQLite format 3\0");
                None
            },
            expect: |e| matches!(e, IndexError::NotAnIndex),
        },
        Case {
            name: "foreign rollback db",
            setup: |f| {
                make_foreign(f, "CREATE TABLE t(x);", false);
                None
            },
            expect: |e| matches!(e, IndexError::WrongApplicationId { found: 0 }),
        },
        Case {
            name: "foreign WAL db with live -wal",
            setup: |f| {
                Some(make_foreign(
                    f,
                    "CREATE TABLE t(x); INSERT INTO t VALUES (1);",
                    true,
                ))
            },
            expect: |e| matches!(e, IndexError::WrongApplicationId { found: 0 }),
        },
        Case {
            name: "db with a meta table",
            setup: |f| Some(make_foreign(f, "CREATE TABLE meta(key, value);", true)),
            expect: |e| matches!(e, IndexError::WrongApplicationId { .. }),
        },
        Case {
            name: "other application id",
            setup: |f| {
                make_foreign(f, "PRAGMA application_id = 42; CREATE TABLE t(x);", false);
                None
            },
            expect: |e| matches!(e, IndexError::WrongApplicationId { found: 42 }),
        },
        Case {
            name: "foreign db with a hot journal",
            setup: |f| {
                make_foreign(f, "CREATE TABLE t(x);", false);
                write_private(&sidecar(f, "-journal"), &[7u8; 64]);
                None
            },
            expect: |e| matches!(e, IndexError::WrongApplicationId { .. }),
        },
        Case {
            name: "empty main + -wal",
            setup: |f| {
                write_private(&f.path, b"");
                write_private(&sidecar(f, "-wal"), &[1u8; 40]);
                None
            },
            expect: |e| matches!(e, IndexError::StraySidecar { suffix: "-wal" }),
        },
        Case {
            name: "empty main + -shm",
            setup: |f| {
                write_private(&f.path, b"");
                write_private(&sidecar(f, "-shm"), &[1u8; 40]);
                None
            },
            expect: |e| matches!(e, IndexError::StraySidecar { suffix: "-shm" }),
        },
        Case {
            name: "empty main + -journal",
            setup: |f| {
                write_private(&f.path, b"");
                write_private(&sidecar(f, "-journal"), &[1u8; 40]);
                None
            },
            expect: |e| matches!(e, IndexError::StraySidecar { suffix: "-journal" }),
        },
        Case {
            name: "empty main + zero-length -wal",
            setup: |f| {
                write_private(&f.path, b"");
                write_private(&sidecar(f, "-wal"), b"");
                None
            },
            expect: |e| matches!(e, IndexError::StraySidecar { suffix: "-wal" }),
        },
        Case {
            name: "missing main + -wal (litter-free refusal)",
            setup: |f| {
                write_private(&sidecar(f, "-wal"), &[1u8; 40]);
                None
            },
            expect: |e| matches!(e, IndexError::StraySidecar { suffix: "-wal" }),
        },
        Case {
            name: "own rollback db + non-empty -journal",
            setup: |f| {
                own_rollback_db(f);
                write_private(&sidecar(f, "-journal"), &[9u8; 64]);
                None
            },
            expect: |e| matches!(e, IndexError::PendingJournal),
        },
        Case {
            name: "own rollback db + non-empty -wal",
            setup: |f| {
                own_rollback_db(f);
                write_private(&sidecar(f, "-wal"), &[9u8; 64]);
                None
            },
            expect: |e| matches!(e, IndexError::StraySidecar { suffix: "-wal" }),
        },
        Case {
            name: "-wal is a symlink",
            setup: |f| {
                drop(Index::open(&f.path).unwrap());
                write_private(&f.dir.path().join("t"), b"x");
                symlink(f.dir.path().join("t"), sidecar(f, "-wal")).unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::BadSidecar { suffix: "-wal" }),
        },
        Case {
            name: "-shm is a symlink",
            setup: |f| {
                drop(Index::open(&f.path).unwrap());
                write_private(&f.dir.path().join("t"), b"x");
                symlink(f.dir.path().join("t"), sidecar(f, "-shm")).unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::BadSidecar { suffix: "-shm" }),
        },
        Case {
            name: "-journal is a symlink",
            setup: |f| {
                drop(Index::open(&f.path).unwrap());
                write_private(&f.dir.path().join("t"), b"x");
                symlink(f.dir.path().join("t"), sidecar(f, "-journal")).unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::BadSidecar { suffix: "-journal" }),
        },
        Case {
            name: "-wal is a FIFO",
            setup: |f| {
                drop(Index::open(&f.path).unwrap());
                mknodat(
                    CWD,
                    sidecar(f, "-wal"),
                    FileType::Fifo,
                    Mode::RUSR | Mode::WUSR,
                    0,
                )
                .unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::BadSidecar { suffix: "-wal" }),
        },
        Case {
            name: "-journal is a directory",
            setup: |f| {
                drop(Index::open(&f.path).unwrap());
                std::fs::create_dir(sidecar(f, "-journal")).unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::BadSidecar { suffix: "-journal" }),
        },
        Case {
            name: "main is a symlink to a real index",
            setup: |f| {
                let real = f.dir.path().join("real.db");
                drop(Index::open(&real).unwrap());
                symlink(&real, &f.path).unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::Fs(_)),
        },
        Case {
            name: "main is a dangling symlink",
            setup: |f| {
                symlink(f.dir.path().join("nowhere"), &f.path).unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::Fs(_)),
        },
        Case {
            name: "main is a FIFO",
            setup: |f| {
                mknodat(CWD, &f.path, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::Fs(wardenlens_fsutil::FsError::NotRegular)),
        },
        Case {
            name: "main is a directory",
            setup: |f| {
                std::fs::create_dir(&f.path).unwrap();
                None
            },
            expect: |e| matches!(e, IndexError::Fs(wardenlens_fsutil::FsError::NotRegular)),
        },
        Case {
            name: "main has mode 0644",
            setup: |f| {
                drop(Index::open(&f.path).unwrap());
                chmod(&f.path, 0o644);
                None
            },
            expect: |e| {
                matches!(
                    e,
                    IndexError::Fs(wardenlens_fsutil::FsError::InsecureMode { .. })
                )
            },
        },
    ]
}

#[test]
fn every_refusal_is_typed_and_leaves_the_directory_byte_identical() {
    for case in cases() {
        let f = fixture();
        let _keep = (case.setup)(&f);
        let before = snapshot(f.dir.path());
        let err = Index::open(&f.path).expect_err(case.name);
        assert!((case.expect)(&err), "{}: got {err:?}", case.name);
        assert_eq!(
            before,
            snapshot(f.dir.path()),
            "{}: directory changed",
            case.name
        );
    }
}

#[test]
fn missing_parent_directory_is_a_typed_fs_error() {
    let f = fixture();
    let err = Index::open(&f.dir.path().join("no").join("index.db")).unwrap_err();
    assert!(matches!(err, IndexError::Fs(e) if e.is_not_found()));
}

#[test]
fn path_swapped_to_a_symlink_before_sqlite_opens_is_refused() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let other = f.dir.path().join("other.db");
    drop(Index::open(&other).unwrap());
    let before = std::fs::read(&other).unwrap();
    let path = f.path.clone();
    let other2 = other.clone();
    let err = Index::open_with(&f.path, crate::migrate::MIGRATIONS, move || {
        std::fs::remove_file(&path).unwrap();
        symlink(&other2, &path).unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(err, IndexError::Sqlite { .. } | IndexError::Fs(_)),
        "{err:?}"
    );
    assert_eq!(before, std::fs::read(&other).unwrap());
}

#[test]
fn file_swapped_for_another_regular_file_is_an_identity_mismatch() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let path = f.path.clone();
    let err = Index::open_with(&f.path, crate::migrate::MIGRATIONS, move || {
        // The old inode stays alive through our descriptor, so the new file has another inode.
        let moved = path.with_extension("old");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::copy(&moved, &path).unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(
            err,
            IndexError::Fs(wardenlens_fsutil::FsError::IdentityMismatch)
        ),
        "{err:?}"
    );
}

#[test]
fn a_file_created_empty_by_a_refused_open_is_removed() {
    let f = fixture();
    write_private(&sidecar(&f, "-journal"), &[1u8; 8]);
    assert!(Index::open(&f.path).is_err());
    assert!(!f.path.exists());
}

#[test]
fn empty_regular_file_owned_by_us_is_adopted() {
    let f = fixture();
    write_private(&f.path, b"");
    let _ = Index::open(&f.path).unwrap();
}

/// A crash before the first checkpoint: the main file holds only the creation bootstrap (version
/// 0) and the `-wal` holds the migration and every row. This is what a new deployment looks like
/// for hours, so it must open with every row.
#[test]
fn a_crash_before_the_first_checkpoint_opens_with_every_row() {
    let live = private_tempdir();
    let lp = live.path().join("index.db");
    let mut idx = Index::open(&lp).unwrap();
    for k in 0..5 {
        idx.insert(&rec("cam1", BASE + k * 10_000, 1000, 10, 1), Tier::Hot)
            .unwrap();
    }
    let crash = private_tempdir();
    let cp = crash.path().join("index.db");
    for s in ["", "-wal"] {
        let (mut a, mut b) = (lp.as_os_str().to_owned(), cp.as_os_str().to_owned());
        a.push(s);
        b.push(s);
        std::fs::copy(&a, &b).unwrap();
        chmod(std::path::Path::new(&b), 0o600);
    }
    drop(idx);
    // Sanity of the setup: the crash image has a non-empty -wal and a main file of one page set.
    assert!(
        std::fs::metadata(format!("{}-wal", cp.display()))
            .unwrap()
            .len()
            > 32
    );
    let idx = Index::open(&cp).unwrap();
    assert_eq!(idx.bytes_by_tier().unwrap().hot.segments, 5);
}
