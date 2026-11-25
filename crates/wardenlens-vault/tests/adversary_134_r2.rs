//! Round-2 adversarial tests for #134 (opens racing committed writes). Synthetic values only.
//! Every race is paced by rendezvous channels: one write in flight per open, no sleeps or clocks.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::KeyFile;
use wardenlens_vault::{Scan, Value, Vault};

const ROUNDS: usize = 30;

fn dir() -> TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    tmp
}

fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

fn text(s: &str) -> Value {
    Value::Text(SecretString::from(s.to_owned()))
}

fn vault_with(tmp: &TempDir, n: usize) -> PathBuf {
    let db = tmp.path().join("v.db");
    let mut v = Vault::create(&db, KeyFile::generate(&tmp.path().join("k")).unwrap()).unwrap();
    for i in 0..n {
        v.set(
            &id(&format!("secret:s{i}")),
            EntryKind::Secret,
            &text(&format!("synthetic-value-{i:04}")),
            Scan::Normal,
        )
        .unwrap();
    }
    drop(v);
    db
}

/// The writer starts a whole transaction (no journal yet) at the moment the open starts, so the
/// journal can appear between the probe's journal check and its read: the window the original
/// unbounded-writer test aimed at and the rewritten one (journal already hot) mostly skips.
#[test]
fn an_open_racing_a_whole_write_transaction_succeeds() {
    let tmp = dir();
    let db = vault_with(&tmp, 5);
    let (go_tx, go_rx) = sync_channel::<()>(0);
    let (done_tx, done_rx) = sync_channel::<()>(0);
    let writer = {
        let db = db.clone();
        std::thread::spawn(move || {
            let c = rusqlite::Connection::open(&db).unwrap();
            c.busy_timeout(Duration::from_secs(5)).unwrap();
            for _ in 0..ROUNDS {
                go_rx.recv().unwrap();
                c.execute_batch(
                    "BEGIN IMMEDIATE; UPDATE entries SET updated_at = updated_at + 1; COMMIT;",
                )
                .unwrap();
                done_rx.recv().unwrap();
            }
        })
    };
    let mut failures = Vec::new();
    for _ in 0..ROUNDS {
        let key = KeyFile::load(&tmp.path().join("k")).unwrap();
        go_tx.send(()).unwrap();
        match Vault::open(&db, key) {
            Ok(v) => drop(v),
            Err(e) => failures.push(format!("{e:?}")),
        }
        done_tx.send(()).unwrap();
    }
    writer.join().unwrap();
    assert!(failures.is_empty(), "{failures:?}");
}

/// A realistic rival: another `Vault` adds one entry per round while an open runs. The opened
/// vault sees either the state before the write or the state after it, never a third.
#[test]
fn an_open_racing_a_vault_set_sees_before_or_after() {
    let tmp = dir();
    let db = vault_with(&tmp, 3);
    let (go_tx, go_rx) = sync_channel::<()>(0);
    let (done_tx, done_rx) = sync_channel::<()>(0);
    let writer = {
        let db = db.clone();
        let key_path = tmp.path().join("k");
        std::thread::spawn(move || {
            let mut v = Vault::open(&db, KeyFile::load(&key_path).unwrap()).unwrap();
            for i in 0..ROUNDS {
                go_rx.recv().unwrap();
                v.set(
                    &id(&format!("secret:w{i}")),
                    EntryKind::Secret,
                    &text("synthetic-racer"),
                    Scan::Normal,
                )
                .unwrap();
                done_rx.recv().unwrap();
            }
        })
    };
    let mut failures = Vec::new();
    for round in 0..ROUNDS {
        let key = KeyFile::load(&tmp.path().join("k")).unwrap();
        go_tx.send(()).unwrap();
        match Vault::open(&db, key) {
            Ok(v) => match v.list() {
                Ok(l) if l.len() == 3 + round || l.len() == 4 + round => {}
                other => failures.push(format!("round {round}: {:?}", other.map(|l| l.len()))),
            },
            Err(e) => failures.push(format!("round {round}: {e:?}")),
        }
        done_tx.send(()).unwrap();
    }
    writer.join().unwrap();
    assert!(failures.is_empty(), "{failures:?}");
}

/// A bounded burst (three commits back to back) per open is not starvation: it lasts far less
/// than `BUSY_TIMEOUT`, so the open must still succeed.
#[test]
fn an_open_racing_a_short_burst_of_commits_succeeds() {
    let tmp = dir();
    let db = vault_with(&tmp, 5);
    let (go_tx, go_rx) = sync_channel::<()>(0);
    let (done_tx, done_rx) = sync_channel::<()>(0);
    let writer = {
        let db = db.clone();
        std::thread::spawn(move || {
            let c = rusqlite::Connection::open(&db).unwrap();
            c.busy_timeout(Duration::from_secs(5)).unwrap();
            for _ in 0..ROUNDS {
                go_rx.recv().unwrap();
                for _ in 0..3 {
                    c.execute_batch(
                        "BEGIN IMMEDIATE; UPDATE entries SET updated_at = updated_at + 1; COMMIT;",
                    )
                    .unwrap();
                }
                done_rx.recv().unwrap();
            }
        })
    };
    let mut failures = Vec::new();
    for _ in 0..ROUNDS {
        let key = KeyFile::load(&tmp.path().join("k")).unwrap();
        go_tx.send(()).unwrap();
        match Vault::open(&db, key) {
            Ok(v) => drop(v),
            Err(e) => failures.push(format!("{e:?}")),
        }
        done_tx.send(()).unwrap();
    }
    writer.join().unwrap();
    assert!(failures.is_empty(), "{failures:?}");
}
