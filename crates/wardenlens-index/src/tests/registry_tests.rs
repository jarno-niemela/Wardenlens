//! Ticket #148: a second open of one index file in this process is refused, whatever the name.

use std::path::Path;

use wardenlens_core::storage::{SegmentIndex, Tier};

use super::*;
use crate::error::IndexError;

/// Descriptors of this process that name `dir/index.db` (reads `/proc/self/fd`).
fn fds_on(path: &Path) -> usize {
    let want = std::fs::canonicalize(path).unwrap();
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| std::fs::read_link(e.path()).is_ok_and(|t| t == want))
        .count()
}

fn is_refused<T>(r: &Result<T, IndexError>) -> bool {
    matches!(r, Err(IndexError::AlreadyOpenInProcess))
}

#[test]
fn a_second_open_is_refused_and_the_first_handle_keeps_working() {
    let (f, mut first) = open_new();
    let fds = fds_on(&f.path);
    assert!(fds >= 1);
    let before = snapshot(f.dir.path());
    assert!(is_refused(&Index::open(&f.path)));
    // The descriptor count did not change (the child lock probe in tests/adversary_148.rs
    // proves the locks themselves).
    assert_eq!(fds_on(&f.path), fds);
    assert_eq!(snapshot(f.dir.path()), before);
    // The first handle is intact.
    let id = first
        .insert(&rec("cam1", BASE, 1000, 10, 1), Tier::Hot)
        .unwrap();
    assert!(first.get(id).unwrap().is_some());
    assert!(is_refused(&Index::open(&f.path)));
    assert_eq!(fds_on(&f.path), fds);
}

#[test]
fn drop_then_reopen_works_and_keeps_the_rows() {
    let (f, mut first) = open_new();
    let id = first
        .insert(&rec("cam1", BASE, 1000, 10, 1), Tier::Hot)
        .unwrap();
    drop(first);
    let again = Index::open(&f.path).unwrap();
    assert!(again.get(id).unwrap().is_some());
}

#[test]
fn another_name_of_the_same_file_is_refused() {
    let (f, _first) = open_new();
    // A symlinked directory.
    let other = private_tempdir();
    let link = other.path().join("dirlink");
    std::os::unix::fs::symlink(f.dir.path(), &link).unwrap();
    let before = snapshot(f.dir.path());
    assert!(is_refused(&Index::open(&link.join("index.db"))));
    // A hard link, in a second private directory.
    let hard = other.path().join("index.db");
    std::fs::hard_link(&f.path, &hard).unwrap();
    assert!(is_refused(&Index::open(&hard)));
    std::fs::remove_file(&hard).unwrap();
    // A relative-looking spelling of the same path.
    let dotted = f.dir.path().join(".").join("index.db");
    assert!(is_refused(&Index::open(&dotted)));
    assert_eq!(snapshot(f.dir.path()), before);
}

#[test]
fn a_different_file_opens_alongside() {
    let (_f, _first) = open_new();
    let (_g, _second) = open_new();
}

#[test]
fn entries_do_not_leak_when_open_fails_after_registration() {
    // Other tests run in parallel and register files of their own, so check by identity:
    // after a failed open the same file is openable again, which needs its entry gone.
    let f = fixture();
    std::fs::write(&f.path, b"definitely not sqlite, long enough to be judged").unwrap();
    chmod(&f.path, 0o600);
    for _ in 0..3 {
        let err = Index::open(&f.path).unwrap_err();
        assert!(matches!(err, IndexError::NotAnIndex), "{err:?}");
    }
    // An empty file with a stray sidecar: refused after the registration and the fresh file.
    let g = fixture();
    std::fs::write(&g.path, b"").unwrap();
    chmod(&g.path, 0o600);
    let journal = g.dir.path().join("index.db-journal");
    std::fs::write(&journal, b"").unwrap();
    chmod(&journal, 0o600);
    for _ in 0..3 {
        let err = Index::open(&g.path).unwrap_err();
        assert!(matches!(err, IndexError::StraySidecar { .. }), "{err:?}");
    }
    // A refusal before registration (missing parent) registers nothing either.
    let missing = g.dir.path().join("nope").join("index.db");
    assert!(Index::open(&missing).is_err());
    assert!(Index::open(&missing).is_err());
    // And a clean open after the failures works, then reopens after drop.
    std::fs::remove_file(&journal).unwrap();
    drop(Index::open(&g.path).unwrap());
    drop(Index::open(&g.path).unwrap());
}

#[test]
fn a_poisoned_registry_is_recovered() {
    let r = std::thread::spawn(|| {
        let _guard = crate::registry::registry_for_test();
        panic!("poison the registry on purpose");
    })
    .join();
    assert!(r.is_err());
    let (_f, _idx) = open_new();
}

/// The names beside a live index: which are refused as sidecars of it and which open as
/// indexes of their own (table, both directions).
#[test]
fn sidecar_name_table_beside_a_live_index() {
    let (f, _live) = open_new();
    for (name, refused_as_sidecar) in [
        ("index.db-shm", true),
        ("index.db-wal", true),
        ("index.db-journal", true),
        ("index.db-wal-shm", false),
        ("index.db-shm-wal", false),
        ("-wal", false),
        ("-shm", false),
        ("-journal", false),
        ("index.db-wal2", false),
    ] {
        let r = Index::open(&f.dir.path().join(name));
        assert_eq!(is_refused(&r), refused_as_sidecar, "{name}: {:?}", r.err());
        if !refused_as_sidecar {
            assert!(r.is_ok(), "{name}");
        }
    }
}

/// Ticket #210: dropping an `Index` closes its registered descriptor and removes its key under
/// the registry mutex. While another thread holds that mutex the descriptor must still be open
/// (the close may not run ahead of the lock), so no open can see a closed-but-registered file.
#[test]
fn dropping_an_index_closes_the_descriptor_only_under_the_registry_lock() {
    let (f, idx) = open_new();
    assert!(fds_on(&f.path) >= 1);
    let guard = crate::registry::registry_for_test();
    let (tx, rx) = std::sync::mpsc::channel();
    let t = std::thread::spawn(move || {
        tx.send(()).unwrap();
        drop(idx);
    });
    rx.recv().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    // The connection's own descriptors may close first; the registered one must not.
    assert!(
        fds_on(&f.path) >= 1,
        "the descriptor closed before the registry lock was taken"
    );
    drop(guard);
    t.join().unwrap();
    assert_eq!(fds_on(&f.path), 0);
}

/// Ticket #210, the field symptom: a file unlinked before its `Index` drops frees its inode at
/// the close; a fresh file that reuses the inode must never be refused as already open. Bounded
/// stress (about a second): threads create, open, unlink, drop and open a fresh file.
#[test]
fn a_reused_inode_of_an_unlinked_index_is_never_refused() {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let workers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                while std::time::Instant::now() < deadline {
                    let old = private_tempdir();
                    let idx = Index::open(&old.path().join("index.db")).unwrap();
                    // Unlinked while open: its inode is freed by the close in the drop below.
                    std::fs::remove_dir_all(old.path()).unwrap();
                    let fresh = private_tempdir();
                    let path = fresh.path().join("index.db");
                    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
                    let racer = std::thread::spawn({
                        let start = std::sync::Arc::clone(&start);
                        move || {
                            start.wait();
                            Index::open(&path).map(drop)
                        }
                    });
                    start.wait();
                    drop(idx);
                    let r = racer.join().unwrap();
                    assert!(r.is_ok(), "{r:?}");
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
}
