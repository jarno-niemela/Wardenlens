//! `TransientFault` for `IndexError`: busy and I/O failures are retried, everything else is final.

use rusqlite::ErrorCode;
use wardenlens_core::storage::TransientFault;
use wardenlens_index::IndexError;

#[test]
fn busy_and_io_failures_are_transient_and_everything_else_is_not() {
    let sqlite = |code| IndexError::Sqlite { op: "insert", code };
    let transient = [
        IndexError::Busy { op: "insert" },
        sqlite(Some(ErrorCode::SystemIoFailure)),
        sqlite(Some(ErrorCode::DiskFull)),
        sqlite(Some(ErrorCode::OutOfMemory)),
    ];
    let permanent = [
        IndexError::Duplicate,
        IndexError::Constraint { op: "insert" },
        IndexError::InvalidRecord { field: "bytes" },
        IndexError::Damaged,
        sqlite(Some(ErrorCode::ReadOnly)),
        sqlite(None),
    ];
    assert!(transient.iter().all(TransientFault::is_transient));
    assert!(permanent.iter().all(|e| !TransientFault::is_transient(e)));
}

/// Unwritable is its own class (#195): never transient, and never a verdict on the record.
#[test]
fn a_read_only_or_unopenable_index_is_unwritable_and_nothing_else_is() {
    let sqlite = |code| IndexError::Sqlite { op: "insert", code };
    let io = |kind| IndexError::Io { op: "insert", kind };
    let unwritable = [
        sqlite(Some(ErrorCode::ReadOnly)),
        sqlite(Some(ErrorCode::CannotOpen)),
        io(std::io::ErrorKind::ReadOnlyFilesystem),
        io(std::io::ErrorKind::PermissionDenied),
    ];
    let other = [
        IndexError::Busy { op: "insert" },
        IndexError::Duplicate,
        IndexError::Constraint { op: "insert" },
        IndexError::InvalidRecord { field: "bytes" },
        IndexError::Damaged,
        sqlite(Some(ErrorCode::DiskFull)),
        sqlite(Some(ErrorCode::SystemIoFailure)),
        sqlite(Some(ErrorCode::DatabaseCorrupt)),
        sqlite(None),
        io(std::io::ErrorKind::NotFound),
    ];
    assert!(unwritable.iter().all(TransientFault::is_unwritable));
    assert!(unwritable.iter().all(|e| !TransientFault::is_transient(e)));
    assert!(other.iter().all(|e| !TransientFault::is_unwritable(e)));
}
