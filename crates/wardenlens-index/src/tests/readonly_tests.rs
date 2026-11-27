//! `Index::open_read_only` (#163): it writes nothing, and refuses what the read-write open refuses.

use std::num::NonZeroU16;

use wardenlens_core::camera::{CameraId, ModelRef, RtspPath, StreamSet};
use wardenlens_core::time::UnixMs;

use super::*;
use crate::cameras::CameraRecord;
use crate::error::IndexError;
use crate::migrate::MIGRATIONS;

fn record(id: &str) -> CameraRecord {
    CameraRecord::new(
        CameraId::new(id).unwrap(),
        ModelRef::new("acme", "c1").unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(RtspPath::new("/s").unwrap(), None),
    )
}

/// An index with one camera, closed (so no sidecar is left).
fn with_camera() -> Fixture {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    idx.upsert_camera(&record("cam-1"), &[], UnixMs::new(BASE).unwrap())
        .unwrap();
    drop(idx);
    f
}

#[test]
fn it_reads_the_cameras_and_leaves_the_directory_byte_identical() {
    let f = with_camera();
    let before = snapshot(f.dir.path());
    let ro = Index::open_read_only(&f.path).unwrap();
    let got = ro
        .get_camera(&CameraId::new("cam-1").unwrap(), &[])
        .unwrap()
        .unwrap();
    assert_eq!(got.record().id().as_str(), "cam-1");
    assert!(
        ro.get_camera(&CameraId::new("cam-2").unwrap(), &[])
            .unwrap()
            .is_none()
    );
    assert_eq!(ro.list_cameras(&[]).unwrap().len(), 1);
    drop(ro);
    assert_eq!(snapshot(f.dir.path()), before);
}

#[test]
fn a_missing_file_is_not_found_and_nothing_is_created() {
    let f = fixture();
    let err = Index::open_read_only(&f.path).unwrap_err();
    assert!(
        matches!(&err, IndexError::Fs(e) if e.is_not_found()),
        "{err:?}"
    );
    assert!(snapshot(f.dir.path()).is_empty());
}

#[test]
fn a_zero_length_file_is_reported_not_formatted() {
    let f = fixture();
    std::fs::write(&f.path, b"").unwrap();
    chmod(&f.path, 0o600);
    let before = snapshot(f.dir.path());
    let err = Index::open_read_only(&f.path).unwrap_err();
    assert!(matches!(err, IndexError::Uninitialised), "{err:?}");
    assert_eq!(snapshot(f.dir.path()), before);
}

#[test]
fn an_older_schema_is_reported_not_migrated() {
    let f = fixture();
    let older = &MIGRATIONS[..MIGRATIONS.len() - 1];
    drop(Index::open_with(&f.path, older, || {}).unwrap());
    let before = snapshot(f.dir.path());
    let err = Index::open_read_only(&f.path).unwrap_err();
    assert!(matches!(err, IndexError::NeedsMigration), "{err:?}");
    assert_eq!(snapshot(f.dir.path()), before, "the file was migrated");
    // The real open then migrates it.
    drop(Index::open(&f.path).unwrap());
    assert_ne!(snapshot(f.dir.path()), before);
    Index::open_read_only(&f.path).unwrap();
}

#[test]
fn a_file_that_is_not_an_index_is_refused_like_the_real_open() {
    let f = fixture();
    std::fs::write(
        &f.path,
        b"this is not a database at all, but it is long enough",
    )
    .unwrap();
    chmod(&f.path, 0o600);
    let before = snapshot(f.dir.path());
    let ro = Index::open_read_only(&f.path).unwrap_err();
    assert!(matches!(ro, IndexError::NotAnIndex), "{ro:?}");
    assert_eq!(snapshot(f.dir.path()), before);
}

/// Every sidecar state the real open refuses is refused the same way, with nothing written.
#[test]
fn sidecars_are_refused_exactly_as_the_real_open_refuses_them() {
    type Setup = fn(&Fixture);
    let write = |f: &Fixture, suffix: &str, bytes: &[u8], mode: u32| {
        let p = std::path::PathBuf::from(format!("{}{suffix}", f.path.display()));
        std::fs::write(&p, bytes).unwrap();
        chmod(&p, mode);
    };
    let _ = write;
    let cases: [(&str, Setup); 5] = [
        ("garbage -wal", |f| {
            let p = format!("{}-wal", f.path.display());
            std::fs::write(&p, [7u8; 64]).unwrap();
            chmod(std::path::Path::new(&p), 0o600);
        }),
        ("empty -journal", |f| {
            let p = format!("{}-journal", f.path.display());
            std::fs::write(&p, b"").unwrap();
            chmod(std::path::Path::new(&p), 0o600);
        }),
        ("non-empty -journal", |f| {
            let p = format!("{}-journal", f.path.display());
            std::fs::write(&p, [1u8; 32]).unwrap();
            chmod(std::path::Path::new(&p), 0o600);
        }),
        ("-wal readable by others", |f| {
            let p = format!("{}-wal", f.path.display());
            std::fs::write(&p, b"").unwrap();
            chmod(std::path::Path::new(&p), 0o644);
        }),
        ("-shm that is a directory", |f| {
            std::fs::create_dir(format!("{}-shm", f.path.display())).unwrap();
        }),
    ];
    for (name, setup) in cases {
        let f = with_camera();
        setup(&f);
        let before = snapshot(f.dir.path());
        let ro = Index::open_read_only(&f.path).unwrap_err();
        assert_eq!(
            snapshot(f.dir.path()),
            before,
            "{name}: the read-only open wrote"
        );
        let rw = Index::open(&f.path).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&ro),
            std::mem::discriminant(&rw),
            "{name}: read-only {ro:?}, read-write {rw:?}"
        );
        assert_eq!(ro.to_string(), rw.to_string(), "{name}");
    }
}

#[test]
fn a_sidecar_with_no_main_file_is_the_stray_sidecar_refusal_and_nothing_is_created() {
    let f = fixture();
    let p = format!("{}-wal", f.path.display());
    std::fs::write(&p, b"not a wal").unwrap();
    chmod(std::path::Path::new(&p), 0o600);
    let before = snapshot(f.dir.path());
    let ro = Index::open_read_only(&f.path).unwrap_err();
    assert!(
        matches!(ro, IndexError::StraySidecar { suffix: "-wal" }),
        "{ro:?}"
    );
    assert_eq!(snapshot(f.dir.path()), before);
    let rw = Index::open(&f.path).unwrap_err();
    assert_eq!(ro.to_string(), rw.to_string());
}

#[test]
fn a_file_this_process_has_open_is_refused_and_the_first_handle_is_untouched() {
    let f = with_camera();
    let first = Index::open(&f.path).unwrap();
    let err = Index::open_read_only(&f.path).unwrap_err();
    assert!(matches!(err, IndexError::AlreadyOpenInProcess), "{err:?}");
    assert_eq!(first.list_cameras(&[]).unwrap().len(), 1);
}

#[test]
fn a_symlinked_index_is_refused() {
    let f = with_camera();
    let link = f.dir.path().join("link.db");
    std::os::unix::fs::symlink(&f.path, &link).unwrap();
    let err = Index::open_read_only(&link).unwrap_err();
    assert!(matches!(err, IndexError::Fs(_)), "{err:?}");
}

#[test]
fn a_newer_schema_is_refused_untouched() {
    let f = with_camera();
    raw(&f.path)
        .pragma_update(None, "user_version", 99)
        .unwrap();
    let before = snapshot(f.dir.path());
    let err = Index::open_read_only(&f.path).unwrap_err();
    assert!(matches!(err, IndexError::SchemaTooNew { .. }), "{err:?}");
    assert_eq!(snapshot(f.dir.path()), before);
}

/// A live writer (its `-wal` holds the row, its `-shm` exists): the reader sees the row, and the
/// main file and the `-wal` are untouched. Without the `-shm` (a crash) it reports `NeedsRecovery`
/// and writes nothing, not even the `-shm`.
#[test]
fn a_wal_is_read_when_its_shm_exists_and_reported_when_it_does_not() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    idx.upsert_camera(&record("cam-1"), &[], UnixMs::new(BASE).unwrap())
        .unwrap();
    let live = idx.into_foreign();
    let wal = format!("{}-wal", f.path.display());
    assert!(
        std::fs::metadata(&wal).unwrap().len() > 0,
        "the row is in the -wal"
    );
    let before = snapshot(f.dir.path());
    let ro = Index::open_read_only(&f.path).unwrap();
    assert_eq!(ro.list_cameras(&[]).unwrap().len(), 1);
    drop(ro);
    let after = snapshot(f.dir.path());
    for name in ["index.db", "index.db-wal"] {
        assert_eq!(after[name], before[name], "{name} changed");
    }
    // A crash leaves the -wal and no -shm: a copy of the two files is that state.
    let g = fixture();
    for name in ["index.db", "index.db-wal"] {
        let to = g.dir.path().join(name);
        std::fs::copy(f.dir.path().join(name), &to).unwrap();
        chmod(&to, 0o600);
    }
    let before = snapshot(g.dir.path());
    let err = Index::open_read_only(&g.path).unwrap_err();
    assert!(matches!(err, IndexError::NeedsRecovery), "{err:?}");
    assert_eq!(snapshot(g.dir.path()), before);
    drop(live);
}
