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
