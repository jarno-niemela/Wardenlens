//! Process limits raised at start-up (ADR 0004 section 9).

use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

/// Raises the soft `RLIMIT_NOFILE` to the hard limit, so 256 API connections plus the recording
/// files and the camera sockets do not exhaust descriptors. Safe wrappers only (no `unsafe`).
///
/// # Errors
/// The `errno` when the kernel refuses; the limit is then unchanged and the caller carries on.
pub(crate) fn raise_nofile_limit() -> Result<(), rustix::io::Errno> {
    let now = getrlimit(Resource::Nofile);
    if now.current == now.maximum {
        return Ok(());
    }
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: now.maximum,
            maximum: now.maximum,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_soft_limit_ends_at_the_hard_limit() {
        raise_nofile_limit().unwrap();
        let l = getrlimit(Resource::Nofile);
        assert_eq!(l.current, l.maximum);
        // Idempotent.
        raise_nofile_limit().unwrap();
    }
}
