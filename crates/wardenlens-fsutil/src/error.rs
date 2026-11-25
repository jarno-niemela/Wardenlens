use rustix::io::Errno;

/// Errors from this crate. None of them carries a path (paths name cameras and times).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FsError {
    /// A path component was empty, `.`, `..`, or contained `/` or NUL. No syscall was made.
    #[error("invalid path component")]
    InvalidComponent,
    /// A system call failed.
    #[error("{op} failed: {source}")]
    Io {
        /// The operation that failed.
        op: &'static str,
        /// The errno.
        #[source]
        source: Errno,
    },
    /// The opened object is not a regular file.
    #[error("not a regular file")]
    NotRegular,
    /// The file grants group or other access.
    #[error("file mode {mode:o} grants group or other access")]
    InsecureMode {
        /// The permission bits found.
        mode: u32,
    },
    /// The file is not owned by the effective user.
    #[error("file is owned by uid {found}, expected {expected}")]
    WrongOwner {
        /// The owner found.
        found: u32,
        /// The effective uid.
        expected: u32,
    },
    /// The directory is not owned by the effective user.
    #[error("directory is not owned by the current user")]
    ParentWrongOwner,
    /// The directory is writable by group or others.
    #[error("directory is writable by group or others")]
    ParentWritable,
    /// The last component of the path is a symbolic link (refused, never followed).
    #[error("the path is a symbolic link")]
    Symlink,
    /// The path no longer names the file that was checked (swapped between check and open).
    #[error("path no longer refers to the checked file")]
    IdentityMismatch,
}

impl FsError {
    pub(crate) fn io(op: &'static str) -> impl FnOnce(Errno) -> Self {
        move |source| Self::Io { op, source }
    }

    /// Keeps only the errno of a `std::io::Error` (`EIO` when it has none).
    pub(crate) fn io_err(op: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |e| Self::Io {
            op,
            source: Errno::from_raw_os_error(e.raw_os_error().unwrap_or(Errno::IO.raw_os_error())),
        }
    }

    /// The errno, if this is a system-call failure.
    #[must_use]
    pub fn errno(&self) -> Option<Errno> {
        match self {
            Self::Io { source, .. } => Some(*source),
            _ => None,
        }
    }

    /// True when the failure is exactly `ENOENT`.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        self.errno() == Some(Errno::NOENT)
    }
}
