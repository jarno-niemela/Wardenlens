//! The terminal the commands talk to, behind a trait so tests can simulate a TTY and a pipe.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::fd::AsFd;

use rustix::fs::{FileType, fstat};
use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

/// What standard output is connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StdoutKind {
    /// A terminal.
    Tty,
    /// A pipe (FIFO).
    Pipe,
    /// A file, socket or anything else: a value must not be written there.
    Other,
}

/// Standard streams and the no-echo prompt.
pub(crate) trait Terminal {
    /// True if standard input is a terminal.
    fn stdin_is_tty(&self) -> bool;
    /// What standard output is.
    fn stdout_kind(&self) -> StdoutKind;
    /// Reads one line without echo (a terminal is required). The line ends at a newline, which
    /// is not part of the result.
    fn prompt_secret(&mut self, label: &str) -> io::Result<Zeroizing<Vec<u8>>>;
    /// Reads piped standard input up to `limit` bytes; more is an `InvalidData` error.
    fn read_piped(&mut self, limit: usize) -> io::Result<Zeroizing<Vec<u8>>>;
    /// Standard input and output together, for a filter that streams one into the other
    /// (`read_piped` is for a value that fits in memory).
    fn stream(&mut self) -> (&mut dyn Read, &mut dyn Write);
    /// Standard output.
    fn out(&mut self) -> &mut dyn Write;
    /// Standard error (notices and warnings; never a value).
    fn err(&mut self) -> &mut dyn Write;
}

/// The process's real standard streams.
pub(crate) struct StdTerminal {
    stdin: io::Stdin,
    stdout: io::Stdout,
    stderr: io::Stderr,
}

impl StdTerminal {
    pub(crate) fn new() -> Self {
        Self {
            stdin: io::stdin(),
            stdout: io::stdout(),
            stderr: io::stderr(),
        }
    }
}

/// Restores the terminal mode when dropped, so an early return never leaves echo off.
struct EchoOff<'a, F: AsFd> {
    fd: &'a F,
    saved: rustix::termios::Termios,
}

impl<'a, F: AsFd> EchoOff<'a, F> {
    fn new(fd: &'a F) -> io::Result<Self> {
        let saved = tcgetattr(fd)?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        // Keep the newline echo so the cursor moves when the owner presses enter.
        quiet.local_modes.insert(LocalModes::ECHONL);
        tcsetattr(fd, OptionalActions::Drain, &quiet)?;
        Ok(Self { fd, saved })
    }
}

impl<F: AsFd> Drop for EchoOff<'_, F> {
    fn drop(&mut self) {
        // Nothing useful can be done if restoring fails during unwinding or return.
        let _ = tcsetattr(self.fd, OptionalActions::Drain, &self.saved);
    }
}

/// Longest prompted line in bytes (two credential fields and a separator fit).
const MAX_PROMPT_LINE: usize = 16 * 1024;

impl Terminal for StdTerminal {
    fn stdin_is_tty(&self) -> bool {
        io::stdin().is_terminal()
    }

    fn stdout_kind(&self) -> StdoutKind {
        if self.stdout.is_terminal() {
            return StdoutKind::Tty;
        }
        match fstat(self.stdout.as_fd()) {
            Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Fifo => StdoutKind::Pipe,
            _ => StdoutKind::Other,
        }
    }

    fn prompt_secret(&mut self, label: &str) -> io::Result<Zeroizing<Vec<u8>>> {
        let stdin = io::stdin();
        write!(self.stderr, "{label}: ")?;
        self.stderr.flush()?;
        let guard = EchoOff::new(&stdin)?;
        // Full capacity up front: a reallocation would leave an unzeroed copy behind.
        let mut line = Zeroizing::new(Vec::with_capacity(MAX_PROMPT_LINE));
        let n = stdin
            .lock()
            .take(u64::try_from(MAX_PROMPT_LINE).unwrap_or(u64::MAX))
            .read_until(b'\n', &mut line)?;
        drop(guard);
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no input"));
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        } else if n >= MAX_PROMPT_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "input too long"));
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(line)
    }

    fn read_piped(&mut self, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        // Full capacity up front: a reallocation would leave an unzeroed copy behind.
        let mut buf = Zeroizing::new(Vec::with_capacity(limit.saturating_add(1)));
        let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        io::stdin().lock().take(cap).read_to_end(&mut buf)?;
        if buf.len() > limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "input too long"));
        }
        Ok(buf)
    }

    fn stream(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        (&mut self.stdin, &mut self.stdout)
    }

    fn out(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn err(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }
}
