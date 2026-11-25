//! The sidecar matrix (TEST-9): every state of the main file crossed with every state of each of
//! `-journal`, `-wal` and `-shm`. Each cell is either "opens, data intact" or a typed refusal
//! after which the directory is byte-identical. Also the parent-directory and sidecar owner/mode
//! rules (ADR 0005 section 5 and P3).

use rusqlite::Connection;
use wardenlens_core::storage::{SegmentIndex, Tier};

use super::*;
use crate::error::IndexError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Main {
    /// Index header, rollback mode, no schema yet: the creation window.
    Rollback,
    /// A complete index in WAL mode.
    Wal,
    /// An index of a newer build (`user_version` 99, in the main file and in the paired `-wal`).
    TooNew,
    /// A foreign rollback-mode database.
    Foreign,
    /// A foreign WAL-mode database.
    ForeignWal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    None,
    Empty,
    /// Written by SQLite for this very database.
    Ours,
    /// Written by SQLite for another database (a real hot journal or `-wal`).
    Foreign,
    /// Bytes that are not any SQLite file.
    Junk,
    /// 700 zero bytes: what a crash before a `-wal` header was written leaves.
    Zeroed,
    /// 8 bytes that are not a WAL header.
    Short,
    /// The first 4 bytes of a WAL magic and nothing else: not a valid header prefix.
    TornMagic,
    /// Magic and format version (8 bytes): a header write cut short.
    TornHeader,
}

const MAINS: [Main; 5] = [
    Main::Rollback,
    Main::Wal,
    Main::TooNew,
    Main::Foreign,
    Main::ForeignWal,
];
const SIDES: [Side; 9] = [
    Side::None,
    Side::Empty,
    Side::Ours,
    Side::Foreign,
    Side::Junk,
    Side::Zeroed,
    Side::Short,
    Side::TornMagic,
    Side::TornHeader,
];
const SUFFIXES: [&str; 3] = ["-journal", "-wal", "-shm"];

fn put(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    chmod(path, 0o600);
}

fn side_path(f: &Fixture, suffix: &str) -> std::path::PathBuf {
    let mut n = f.path.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

/// A real hot rollback journal of a foreign database (the adversary's recipe).
fn foreign_journal() -> Vec<u8> {
    let dir = private_tempdir();
    let other = dir.path().join("foreign.db");
    let c = Connection::open(&other).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode = DELETE; PRAGMA page_size = 4096; CREATE TABLE t(x BLOB);",
    )
    .unwrap();
    for _ in 0..50 {
        c.execute("INSERT INTO t VALUES (zeroblob(3000))", [])
            .unwrap();
    }
    c.execute_batch("PRAGMA cache_size = 2; BEGIN; UPDATE t SET x = zeroblob(3001);")
        .unwrap();
    let journal = std::fs::read(side_path_of(&other, "-journal")).unwrap();
    c.execute_batch("ROLLBACK").unwrap();
    assert!(journal.len() > 4096);
    journal
}

fn side_path_of(p: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

/// Real `-wal` and `-shm` bytes of a foreign WAL database (taken while it is open).
fn foreign_wal() -> (Vec<u8>, Vec<u8>) {
    let dir = private_tempdir();
    let other = dir.path().join("foreign.db");
    let c = Connection::open(&other).unwrap();
    c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
        .unwrap();
    c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1), (2), (3);")
        .unwrap();
    let wal = std::fs::read(side_path_of(&other, "-wal")).unwrap();
    let shm = std::fs::read(side_path_of(&other, "-shm")).unwrap();
    assert!(wal.len() > 32);
    (wal, shm)
}

/// The main file and, for [`Side::Ours`], the matching real `-wal` and `-shm`, copied while a
/// connection is still open (the state a crash leaves). Returns the live connection of a
/// foreign WAL database, if any, which must outlive the cell.
type WalPair = Option<(Vec<u8>, Vec<u8>)>;

fn build_main(f: &Fixture, main: Main) -> (Option<Connection>, WalPair) {
    match main {
        Main::Rollback => {
            let c = raw(&f.path);
            c.execute_batch(crate::sql::BOOTSTRAP).unwrap();
            drop(c);
            chmod(&f.path, 0o600);
            (None, None)
        }
        Main::Foreign => {
            let c = raw(&f.path);
            c.execute_batch("CREATE TABLE t(x);").unwrap();
            drop(c);
            chmod(&f.path, 0o600);
            (None, None)
        }
        Main::ForeignWal => {
            let c = raw(&f.path);
            c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
                .unwrap();
            c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1);")
                .unwrap();
            chmod(&f.path, 0o600);
            (Some(c), None)
        }
        Main::Wal | Main::TooNew => {
            // A complete index; a second connection then writes (into the WAL) while we copy.
            let base = private_tempdir();
            let src = base.path().join("index.db");
            let mut idx = Index::open(&src).unwrap();
            idx.insert(&rec("cam1", BASE, 1000, 10, 1), Tier::Hot)
                .unwrap();
            drop(idx);
            let c = raw(&src);
            c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
                .unwrap();
            c.execute_batch(
                "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, \
                 frame_count, tier) VALUES ('cam1', 1700000100000, 1000, 1700000101000, 5, 1, 0);",
            )
            .unwrap();
            if main == Main::TooNew {
                c.execute_batch("PRAGMA user_version = 99;").unwrap();
            }
            let mut main_bytes = std::fs::read(&src).unwrap();
            let wal = std::fs::read(side_path_of(&src, "-wal")).unwrap();
            let shm = std::fs::read(side_path_of(&src, "-shm")).unwrap();
            drop(c);
            if main == Main::TooNew {
                // The checkpointed file: version 99 is in the main file itself.
                main_bytes = std::fs::read(&src).unwrap();
            }
            put(&f.path, &main_bytes);
            (None, Some((wal, shm)))
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Want {
    Open,
    Refuse(fn(&IndexError) -> bool),
}

fn is_pending(e: &IndexError) -> bool {
    matches!(e, IndexError::PendingJournal)
}
fn is_foreign_wal(e: &IndexError) -> bool {
    matches!(e, IndexError::ForeignWal)
}
fn is_wrong_app(e: &IndexError) -> bool {
    matches!(e, IndexError::WrongApplicationId { found: 0 })
}
fn is_too_new(e: &IndexError) -> bool {
    matches!(
        e,
        IndexError::SchemaTooNew {
            found: 99,
            supported: 2
        }
    )
}

fn stray(suffix: &'static str) -> impl Fn(&IndexError) -> bool {
    move |e| matches!(e, IndexError::StraySidecar { suffix: s } if *s == suffix)
}

/// The expected outcome of one cell, written out independently of the code under test.
fn want(main: Main, suffix: &str, side: Side) -> Want {
    // A foreign database is refused by its header, whatever sits next to it.
    if matches!(main, Main::Foreign | Main::ForeignWal) {
        return Want::Refuse(is_wrong_app);
    }
    // Cells where the sidecar is acceptable: a too-new file is still refused for its version.
    let accepted = if main == Main::TooNew {
        Want::Refuse(is_too_new)
    } else {
        Want::Open
    };
    match (suffix, side) {
        (_, Side::None) => accepted,
        ("-journal", Side::Empty) => Want::Refuse(|e| stray("-journal")(e)),
        ("-journal", _) => Want::Refuse(is_pending),
        ("-wal", _) if main == Main::Rollback => Want::Refuse(|e| stray("-wal")(e)),
        ("-shm", _) if main == Main::Rollback => Want::Refuse(|e| stray("-shm")(e)),
        // The main file is judged first: a too-new main is reported as that, not as a bad `-wal`.
        ("-wal", Side::Foreign) if main == Main::TooNew => Want::Refuse(is_too_new),
        ("-wal", Side::Foreign) => Want::Refuse(is_foreign_wal),
        // Not a WAL header and not a torn one: SQLite did not write it.
        ("-wal", Side::Junk | Side::Short | Side::TornMagic) => {
            Want::Refuse(|e| matches!(e, IndexError::InvalidWal))
        }
        // A torn header is an empty WAL, as SQLite treats it.
        // An empty or our own `-wal`, and any `-shm` (SQLite rebuilds it from the `-wal`; it is
        // never replayed).
        ("-wal" | "-shm", _) => accepted,
        _ => unreachable!("every cell is listed"),
    }
}

fn setup_cell(main: Main, suffix: &str, side: Side) -> (Fixture, Option<Connection>) {
    let f = fixture();
    let (keep, ours) = build_main(&f, main);
    let sp = side_path(&f, suffix);
    let (own_wal, own_shm) = ours.unwrap_or_else(|| (foreign_wal().0, foreign_wal().1));
    match (suffix, side) {
        (_, Side::None) => {
            // A live foreign WAL database brought its own sidecars: keep them as they are.
        }
        (_, Side::Empty) => put(&sp, b""),
        ("-wal", Side::Ours) => put(&sp, &own_wal),
        ("-shm", Side::Ours) => put(&sp, &own_shm),
        ("-wal", Side::Foreign) => put(&sp, &foreign_wal().0),
        ("-shm", Side::Foreign) => put(&sp, &foreign_wal().1),
        ("-journal", Side::Ours | Side::Foreign) => put(&sp, &foreign_journal()),
        (_, Side::Junk) => put(&sp, &[0xd9u8; 700]),
        (_, Side::Zeroed) => put(&sp, &[0u8; 700]),
        (_, Side::Short) => put(&sp, &[1u8; 8]),
        (_, Side::TornMagic) => put(&sp, &[0x37, 0x7f, 0x06, 0x82]),
        (_, Side::TornHeader) => put(&sp, &[0x37, 0x7f, 0x06, 0x82, 0x00, 0x2d, 0xe2, 0x18]),
        _ => unreachable!(),
    }
    // The foreign WAL database brought its own `-wal`/`-shm` (mode of its creation): make them
    // private so the matrix tests the content rule, not the mode rule (tested separately).
    for s in ["-wal", "-shm", "-journal"] {
        let p = side_path(&f, s);
        if p.exists() {
            chmod(&p, 0o600);
        }
    }
    (f, keep)
}

/// Cells that make no sense are skipped: `Ours` for `-journal` (an index never has one) is
/// covered by `Foreign`, and a foreign main has no "own" sidecar.
fn cells() -> Vec<(Main, &'static str, Side)> {
    let mut out = Vec::new();
    for main in MAINS {
        for suffix in SUFFIXES {
            for side in SIDES {
                if suffix == "-journal" && side == Side::Ours {
                    continue;
                }
                // A live foreign WAL database already owns `-wal` and `-shm`.
                if main == Main::ForeignWal && side != Side::None {
                    continue;
                }
                out.push((main, suffix, side));
            }
        }
    }
    out
}

#[test]
fn the_matrix_has_every_main_state_and_every_sidecar_state() {
    let cells = cells();
    for main in MAINS {
        for suffix in SUFFIXES {
            assert!(cells.iter().any(|c| c.0 == main && c.1 == suffix));
        }
    }
    assert_eq!(cells.len(), 107);
}

#[test]
fn every_cell_opens_or_is_refused_with_the_directory_byte_identical() {
    let mut refused = 0;
    let mut opened = 0;
    for (main, suffix, side) in cells() {
        let (f, _keep) = setup_cell(main, suffix, side);
        let before = snapshot(f.dir.path());
        let label = format!("{main:?} + {suffix} {side:?}");
        match (want(main, suffix, side), Index::open(&f.path)) {
            (Want::Open, Ok(idx)) => {
                opened += 1;
                if main == Main::Wal {
                    // The rows of the real `-wal` are there: replayed from our own file.
                    let n = idx.bytes_by_tier().unwrap().hot.segments;
                    assert!(n >= 1, "{label}: {n} rows");
                    if suffix == "-wal" && side == Side::Ours {
                        assert_eq!(n, 2, "{label}: the -wal frame was not applied");
                    }
                }
            }
            (Want::Refuse(check), Err(e)) => {
                refused += 1;
                assert!(check(&e), "{label}: {e:?}");
                assert_eq!(before, snapshot(f.dir.path()), "{label}: directory changed");
            }
            (Want::Open, Err(e)) => panic!("{label}: refused: {e:?}"),
            (Want::Refuse(_), Ok(_)) => panic!("{label}: opened"),
        }
    }
    assert!(
        refused > 30 && opened >= 6,
        "refused {refused} opened {opened}"
    );
}

#[test]
fn a_refusal_never_leaves_a_scratch_directory_behind() {
    let (f, _k) = setup_cell(Main::TooNew, "-wal", Side::Ours);
    assert!(Index::open(&f.path).is_err());
    let names: Vec<_> = snapshot(f.dir.path()).into_keys().collect();
    assert!(
        names.iter().all(|n| !n.starts_with(".wardenlens-probe")),
        "{names:?}"
    );
}

#[test]
fn a_planted_wal_is_never_checkpointed_by_the_refusal() {
    // The adversary's blocker: a `-wal` of another database must not reach index.db.
    let (f, _k) = setup_cell(Main::Wal, "-wal", Side::Foreign);
    let main_before = std::fs::read(&f.path).unwrap();
    assert!(matches!(
        Index::open(&f.path).unwrap_err(),
        IndexError::ForeignWal
    ));
    assert_eq!(main_before, std::fs::read(&f.path).unwrap());
}

// ---- parent directory and sidecar owner/mode ----

#[test]
fn an_unsafe_parent_directory_is_refused_before_anything_is_created() {
    for mode in [0o777, 0o775, 0o757, 0o770, 0o707, 0o722, 0o702] {
        let f = fixture();
        chmod(f.dir.path(), mode);
        let err = Index::open(&f.path).unwrap_err();
        chmod(f.dir.path(), 0o700);
        assert!(
            matches!(
                err,
                IndexError::Fs(wardenlens_fsutil::FsError::ParentWritable)
            ),
            "{mode:o}: {err:?}"
        );
        assert!(!f.path.exists(), "{mode:o}: a file was created");
    }
    // 0750 and 0755 are not writable by others: fine.
    for mode in [0o700, 0o750, 0o755] {
        let f = fixture();
        chmod(f.dir.path(), mode);
        let ok = Index::open(&f.path);
        chmod(f.dir.path(), 0o700);
        assert!(ok.is_ok(), "{mode:o}");
    }
}

#[test]
fn a_sidecar_with_group_or_other_bits_or_special_bits_is_refused_untouched() {
    for suffix in SUFFIXES {
        for mode in [0o666, 0o660, 0o640, 0o604, 0o606, 0o4600, 0o2600, 0o1600] {
            let (f, _k) = setup_cell(Main::Wal, suffix, Side::Empty);
            chmod(&side_path(&f, suffix), mode);
            let before = snapshot(f.dir.path());
            let err = Index::open(&f.path).unwrap_err();
            let ok = matches!(&err, IndexError::InsecureSidecar { suffix: s } if *s == suffix);
            assert!(ok, "{suffix} {mode:o}: {err:?}");
            assert_eq!(before, snapshot(f.dir.path()), "{suffix} {mode:o}");
        }
    }
}

/// A sidecar with a second hard link is refused for every sidecar, main state and content (the
/// link rule runs with the other sidecar checks, before the header is judged), and neither name
/// nor anything else in the directory changes.
#[test]
fn a_hard_linked_sidecar_is_refused_untouched_in_every_cell() {
    for main in MAINS {
        for suffix in SUFFIXES {
            for side in [Side::Empty, Side::Ours, Side::Junk] {
                // The fixture of a live foreign WAL database holds its `-shm` mapped; overwriting
                // it in place would crash that fixture connection (SIGBUS), not the code under test.
                if main == Main::ForeignWal && suffix == "-shm" {
                    continue;
                }
                let (f, _k) = setup_cell(main, suffix, side);
                let sp = side_path(&f, suffix);
                if !sp.exists() {
                    continue;
                }
                let twin = f.dir.path().join("twin.bin");
                std::fs::hard_link(&sp, &twin).unwrap();
                let before = snapshot(f.dir.path());
                let err = Index::open(&f.path).unwrap_err();
                assert!(
                    matches!(&err, IndexError::InsecureSidecar { suffix: s } if *s == suffix),
                    "{main:?} {suffix} {side:?}: {err:?}"
                );
                assert_eq!(before, snapshot(f.dir.path()), "{main:?} {suffix} {side:?}");
            }
        }
    }
}

#[test]
fn a_sidecar_with_mode_0600_or_0400_passes_the_mode_rule() {
    let (f, _k) = setup_cell(Main::Wal, "-shm", Side::Empty);
    chmod(&side_path(&f, "-shm"), 0o400);
    // Mode is fine; SQLite then rebuilds a read-only shm or reports it: either way not a mode error.
    if let Err(e) = Index::open(&f.path) {
        assert!(!matches!(e, IndexError::InsecureSidecar { .. }), "{e:?}");
    }
}

#[test]
fn the_wal_checks_run_for_every_main_state_before_the_header_is_judged() {
    // A world-writable `-wal` next to a *foreign* main file is still an InsecureSidecar: the
    // sidecars are looked at first, so nothing about them is trusted whatever the main file is.
    for main in MAINS {
        let (f, _k) = setup_cell(main, "-wal", Side::Junk);
        chmod(&side_path(&f, "-wal"), 0o666);
        let err = Index::open(&f.path).unwrap_err();
        assert!(
            matches!(err, IndexError::InsecureSidecar { suffix: "-wal" }),
            "{main:?}: {err:?}"
        );
    }
}
