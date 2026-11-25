//! Adversarial tests for #49 round 4 (PR #140 at 5182310): the opener `flock`, the instance id
//! and the probe-created `-shm`.
//!
//! The cross-process tests re-run this test binary as child processes (selected by an
//! environment variable) and coordinate with them over stdin and stdout lines, never by timing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::print_stdout,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_index::Index;

const BASE: i64 = 1_700_000_000_000;
const CHILD_ENV: &str = "WL49R4_CHILD_PATH";
const MARK: &str = "WL49R4:";

fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

fn rec(camera: &str, start: i64, dur: u64, bytes: u64) -> SegmentRecord {
    SegmentRecord::new(cam(camera), UnixMs::new(start).unwrap(), dur, bytes, 1)
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

fn count(idx: &Index, camera: &str) -> usize {
    idx.list(
        &cam(camera),
        Timestamp::from_unix_millis(0),
        Timestamp::from_unix_millis(i64::MAX),
        1000,
        None,
    )
    .unwrap()
    .items
    .len()
}

/// POSIX (fcntl) locks this process holds on the inode of `path`, from `/proc/locks`.
fn own_posix_locks_on(path: &Path) -> Vec<String> {
    let md = std::fs::metadata(path).unwrap();
    let dev = md.dev();
    // /proc/locks prints MAJOR:MINOR:INODE with major and minor in hex.
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    let key = format!("{major:02x}:{minor:02x}:{}", md.ino());
    let pid = std::process::id().to_string();
    std::fs::read_to_string("/proc/locks")
        .unwrap()
        .lines()
        .filter(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.get(1) == Some(&"POSIX")
                && f.get(4) == Some(&pid.as_str())
                && f.get(5) == Some(&key.as_str())
        })
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The flock descriptor and SQLite's POSIX locks
// ---------------------------------------------------------------------------------------------

/// Control: a plain WAL connection keeps a POSIX shared lock on the main file while it is open.
/// That lock is what tells another process's closing connection "you are not the last one; do
/// not checkpoint and delete the `-wal`".
#[test]
fn control_a_plain_wal_connection_holds_a_posix_lock_on_the_main_file() {
    let dir = private_tempdir();
    let path = dir.path().join("plain.db");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
        .unwrap();
    c.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
        .unwrap();
    assert!(
        !own_posix_locks_on(&path).is_empty(),
        "an open WAL connection must hold its shared lock on the main file"
    );
}

/// `Index::open` closes the `dup` of the verified descriptor that carried the `flock` when the
/// guard drops, after the read-write connection exists. POSIX record locks belong to the process
/// and closing *any* descriptor of the inode drops all of them (fcntl(2)), so the connection's
/// shared lock on the main file is silently gone when `open` returns.
#[test]
fn an_open_index_keeps_sqlites_posix_lock_on_the_main_file() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    let locks = own_posix_locks_on(&path);
    assert!(
        !locks.is_empty(),
        "an open Index holds no POSIX lock on its main file: SQLite's WAL shared lock was \
         dropped by closing one of our own descriptors"
    );
}

// ---------------------------------------------------------------------------------------------
// Cross-process: a second Index::open and close while the first is live
// ---------------------------------------------------------------------------------------------

struct Peer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Peer {
    fn spawn(path: &Path) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "child_holder_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn expect(&mut self, want: &str) {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.stdout.read_line(&mut line).unwrap();
            assert!(n > 0, "child ended before printing {want}");
            if let Some((_, rest)) = line.trim_end().split_once(MARK) {
                assert_eq!(rest, want, "child said {rest}");
                return;
            }
        }
    }

    fn send(&mut self, cmd: &str) {
        writeln!(self.stdin, "{cmd}").unwrap();
        self.stdin.flush().unwrap();
    }
}

/// Runs only as a child of `a_second_opener_closing_never_loses_a_live_index_commits`.
/// Protocol: open, say `ready`; on `insert`, insert one row and say `inserted`; on `crash`,
/// leave without closing the connection (no checkpoint, the `-wal` stays as a crash leaves it).
#[test]
fn child_holder_entry() {
    let Some(path) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let path = PathBuf::from(path);
    let mut idx = Index::open(&path).unwrap();
    let mut next: i64 = 1;
    let say = |s: &str| {
        println!("{MARK}{s}");
        std::io::stdout().flush().unwrap();
    };
    say("ready");
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    while let Some(Ok(cmd)) = lines.next() {
        match cmd.as_str() {
            "insert" => {
                idx.insert(&rec("live", BASE + next * 50_000, 1000, 10), Tier::Hot)
                    .unwrap();
                next += 1;
                say("inserted");
            }
            "crash" => {
                say("crashing");
                // No destructors: the connection is never closed, as in a power cut.
                std::process::exit(0);
            }
            other => panic!("unknown command {other}"),
        }
    }
}

/// ADR 0005 section 5 asks every process to open through `Index::open`, which this test does in
/// both processes. Process A has the index open; process B opens and closes it; then A commits a
/// row and crashes. The committed row must survive (`synchronous = FULL`).
///
/// Because A's POSIX shared lock on the main file was dropped when `open` closed its `flock`
/// descriptor, B's close believes it is the last connection: it checkpoints and **unlinks the
/// `-wal` and `-shm` under A**. A then commits into an unlinked `-wal` inode, and the commit is
/// lost at the crash.
#[test]
fn a_second_opener_closing_never_loses_a_live_index_commits() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    {
        let mut idx = Index::open(&path).unwrap();
        idx.insert(&rec("live", BASE, 1000, 10), Tier::Hot).unwrap();
    }

    let mut a = Peer::spawn(&path);
    a.expect("ready");

    // Process B (this one): a full checked open, a read, and a close.
    {
        let idx = Index::open(&path).unwrap();
        assert_eq!(count(&idx, "live"), 1);
    }
    let wal_after_b = sidecar(&path, "-wal").exists();

    a.send("insert");
    a.expect("inserted");
    a.send("crash");
    a.expect("crashing");
    let status = a.child.wait().unwrap();
    assert!(status.success());

    let idx = Index::open(&path).unwrap();
    let rows = count(&idx, "live");
    assert_eq!(
        rows, 2,
        "a row committed by a live Index was lost after a crash (the -wal existed after the \
         other process closed: {wal_after_b})"
    );
}

// ---------------------------------------------------------------------------------------------
// Crash recovery: a main file torn in the middle of a checkpoint
// ---------------------------------------------------------------------------------------------

/// The newest copy of page `pgno` in a `-wal`, and the page size.
fn newest_wal_page(wal: &[u8], pgno: u32) -> (Vec<u8>, usize) {
    let page = u32::from_be_bytes(wal[8..12].try_into().unwrap()) as usize;
    let mut found = None;
    let mut at = 32;
    while at + 24 + page <= wal.len() {
        let n = u32::from_be_bytes(wal[at..at + 4].try_into().unwrap());
        if n == pgno {
            found = Some(wal[at + 24..at + 24 + page].to_vec());
        }
        at += 24 + page;
    }
    (found.expect("page in -wal"), page)
}

/// A process creates the index, commits `rows` rows and crashes before any checkpoint, so the
/// main file is the version-0 bootstrap and the `-wal` holds migration 1 and every row.
fn crashed_before_first_checkpoint(path: &Path, rows: usize) {
    let mut a = Peer::spawn(path);
    a.expect("ready");
    for _ in 0..rows {
        a.send("insert");
        a.expect("inserted");
    }
    a.send("crash");
    a.expect("crashing");
    assert!(a.child.wait().unwrap().success());
}

/// Control: the crash above recovers, every committed row is there.
#[test]
fn control_a_crash_before_the_first_checkpoint_recovers_every_row() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    crashed_before_first_checkpoint(&path, 3);
    assert!(std::fs::metadata(sidecar(&path, "-wal")).unwrap().len() > 32);
    let idx = Index::open(&path).unwrap();
    assert_eq!(count(&idx, "live"), 3);
}

/// A power cut while a checkpoint copies page 1 from the `-wal` into the main file can leave
/// that page torn at a sector boundary: the first 512 bytes new, the rest old. The `-wal` is
/// this index's own and still holds every frame, so SQLite's replay restores a sound database
/// (what a plain SQLite open does). `wal_verdict` reads the instance id from the torn main file
/// alone; when that read fails it compares `None` with the view's id and reports `ForeignWal`
/// for the index's own `-wal`, whose remedy (move the `-wal` out) leaves a damaged main file
/// and the committed rows outside the index. ADR 0005 section 5 and the `wal_verdict` comment
/// say a main file torn mid-checkpoint is decided by the replayed view.
#[test]
fn a_main_file_torn_mid_checkpoint_is_recovered_from_its_own_wal() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    crashed_before_first_checkpoint(&path, 3);

    let wal = std::fs::read(sidecar(&path, "-wal")).unwrap();
    let (page1, page) = newest_wal_page(&wal, 1);
    assert!(page >= 1024);
    // The torn write: only the first sector of the new page 1 reached the main file.
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.write_all_at(&page1[..512], 0).unwrap();
    drop(f);

    // The real files replay consistently: a plain read-only SQLite connection sees every row.
    {
        let c = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        c.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .unwrap();
        let n: i64 = c
            .query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 3);
        let ok: String = c
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ok, "ok");
    }

    match Index::open(&path) {
        Ok(idx) => assert_eq!(count(&idx, "live"), 3),
        Err(e) => panic!("the index's own -wal after a torn checkpoint was refused: {e:?} ({e})"),
    }
}

// ---------------------------------------------------------------------------------------------
// The torn -wal rule: "only an all-zero -wal, or a prefix of a WAL magic"
// ---------------------------------------------------------------------------------------------

fn closed_index(dir: &Path) -> PathBuf {
    let path = dir.join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    drop(idx);
    assert!(!sidecar(&path, "-wal").exists());
    path
}

/// ADR 0005 section 5 (round 4): only an all-zero `-wal`, or a short one that is a prefix of a
/// WAL magic, is an empty WAL; any other is `InvalidWal`, "never opened read-write, so never
/// deleted or rewritten". `check_wal_header` looks only at the first 32 bytes, so a file whose
/// header is zero but whose body holds data is taken as torn, opened read-write, and SQLite
/// rewrites and then deletes it.
#[test]
fn a_wal_with_a_zero_header_and_a_non_zero_body_is_never_rewritten() {
    let forms: Vec<(&str, Vec<u8>)> = vec![("zero header, data body", {
        let mut v = vec![0u8; 32];
        v.extend(std::iter::repeat_n(0xAB, 4096));
        v
    })];
    let mut bad = Vec::new();
    for (name, bytes) in forms {
        let dir = private_tempdir();
        let path = closed_index(dir.path());
        let wal = sidecar(&path, "-wal");
        std::fs::write(&wal, &bytes).unwrap();
        std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600)).unwrap();
        let outcome = match Index::open(&path) {
            Ok(mut idx) => {
                idx.insert(&rec("cam1", BASE + 10_000, 1000, 10), Tier::Hot)
                    .unwrap();
                drop(idx);
                "opened"
            }
            Err(_) => "refused",
        };
        let after = std::fs::read(&wal).ok();
        if after.as_deref() != Some(bytes.as_slice()) {
            bad.push(format!(
                "{name}: {outcome}, -wal now {:?} bytes",
                after.map(|a| a.len())
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "a non-empty, non-SQLite -wal was rewritten: {bad:#?}"
    );
}
