//! How the recorder judges a failed `Index::insert`.

use wardenlens_index::IndexError;

/// Classifies an index error. The recorder retries a transient one a bounded number of times and
/// quarantines the file on any other (ADR 0005 section 3): a constraint, a duplicate, a bad
/// record, or a permanent failure.
pub trait IndexFault {
    /// True when the same insert may succeed later (the database was busy, an I/O error).
    fn is_transient(&self) -> bool;
}

impl IndexFault for IndexError {
    fn is_transient(&self) -> bool {
        IndexError::is_transient(self)
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::ErrorCode;

    use super::*;

    #[test]
    fn busy_and_io_failures_are_transient_and_everything_else_is_not() {
        let transient = [
            IndexError::Busy { op: "insert" },
            IndexError::Sqlite {
                op: "insert",
                code: Some(ErrorCode::SystemIoFailure),
            },
            IndexError::Sqlite {
                op: "insert",
                code: Some(ErrorCode::DiskFull),
            },
        ];
        let permanent = [
            IndexError::Duplicate,
            IndexError::Constraint { op: "insert" },
            IndexError::InvalidRecord { field: "bytes" },
            IndexError::Damaged,
            IndexError::Sqlite {
                op: "insert",
                code: Some(ErrorCode::ReadOnly),
            },
            IndexError::Sqlite {
                op: "insert",
                code: None,
            },
        ];
        assert!(transient.iter().all(IndexFault::is_transient));
        assert!(permanent.iter().all(|e| !IndexFault::is_transient(e)));
    }
}
