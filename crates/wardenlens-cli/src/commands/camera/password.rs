//! Reading the camera password: a no-echo prompt on a terminal, else one line of stdin. Never
//! argv (it would show in `/proc/<pid>/cmdline`, ADR 0002 risk 11).
//!
//! The bytes live in a [`Zeroizing`] buffer and leave it only as a [`SecretString`], which is
//! zeroised on drop and prints nothing. Nothing here is formatted into an error.

use secrecy::SecretString;
use wardenlens_core::camera::MAX_CREDENTIAL_PART_LEN;
use zeroize::Zeroizing;

use crate::terminal::Terminal;

/// Room for the password and a line ending or two.
const PIPED_LIMIT: usize = MAX_CREDENTIAL_PART_LEN + 4;

/// Why the password could not be read. Fixed texts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PasswordError {
    /// Nothing could be read, or it was too long.
    #[error("the password could not be read from stdin or the prompt")]
    Read,
    /// The input is not UTF-8.
    #[error("the password is not valid UTF-8")]
    NotUtf8,
    /// The input has more than one line.
    #[error("the password must be one line; a second line was refused")]
    MoreThanOneLine,
    /// The password is empty.
    #[error("an empty password is refused")]
    Empty,
}

/// Removes one line ending (`\n` or `\r\n`) and, if there was one, nothing else.
fn strip_line_end(bytes: &[u8]) -> &[u8] {
    match bytes.strip_suffix(b"\n") {
        Some(b) => b.strip_suffix(b"\r").unwrap_or(b),
        None => bytes,
    }
}

/// Reads the password: the prompt `label` on a terminal, else the whole of stdin, which must be
/// one line.
///
/// # Errors
/// [`PasswordError`].
pub(crate) fn read(term: &mut impl Terminal, label: &str) -> Result<SecretString, PasswordError> {
    let raw: Zeroizing<Vec<u8>> = if term.stdin_is_tty() {
        term.prompt_secret(label).map_err(|_| PasswordError::Read)?
    } else {
        term.read_piped(PIPED_LIMIT)
            .map_err(|_| PasswordError::Read)?
    };
    let line = strip_line_end(&raw);
    if line.contains(&b'\n') {
        return Err(PasswordError::MoreThanOneLine);
    }
    if line.is_empty() {
        return Err(PasswordError::Empty);
    }
    let text = std::str::from_utf8(line).map_err(|_| PasswordError::NotUtf8)?;
    Ok(SecretString::from(text.to_owned()))
}

#[cfg(test)]
pub(super) mod tests {
    use std::io::{self, Read, Write};

    use secrecy::ExposeSecret;

    use super::*;
    use crate::terminal::StdoutKind;

    /// A terminal that is a TTY or a pipe holding `input`.
    pub(crate) struct Scripted {
        pub(crate) tty: bool,
        pub(crate) input: Vec<u8>,
        pub(crate) out: Vec<u8>,
        pub(crate) err: Vec<u8>,
    }

    impl Scripted {
        pub(crate) fn piped(input: &str) -> Self {
            Self {
                tty: false,
                input: input.as_bytes().to_vec(),
                out: Vec::new(),
                err: Vec::new(),
            }
        }
    }

    impl Terminal for Scripted {
        fn stdin_is_tty(&self) -> bool {
            self.tty
        }
        fn stdout_kind(&self) -> StdoutKind {
            StdoutKind::Pipe
        }
        fn prompt_secret(&mut self, label: &str) -> io::Result<Zeroizing<Vec<u8>>> {
            // The label goes to stderr, as on the real terminal; the line is one of the input.
            write!(self.err, "{label}: ")?;
            let end = self
                .input
                .iter()
                .position(|b| *b == b'\n')
                .unwrap_or(self.input.len());
            let line: Vec<u8> = self.input.drain(..end).collect();
            self.input.drain(..self.input.len().min(1));
            Ok(Zeroizing::new(line))
        }
        fn read_piped(&mut self, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
            if self.input.len() > limit {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "too long"));
            }
            Ok(Zeroizing::new(std::mem::take(&mut self.input)))
        }
        fn stream(&mut self) -> (&mut dyn Read, &mut dyn Write) {
            unreachable!("not used by camera commands")
        }
        fn out(&mut self) -> &mut dyn Write {
            &mut self.out
        }
        fn err(&mut self) -> &mut dyn Write {
            &mut self.err
        }
    }

    fn read_piped(input: &str) -> Result<String, PasswordError> {
        read(&mut Scripted::piped(input), "password").map(|s| s.expose_secret().to_owned())
    }

    #[test]
    fn one_line_of_stdin_is_the_password() {
        assert_eq!(read_piped("pw\n").unwrap(), "pw");
        assert_eq!(read_piped("pw\r\n").unwrap(), "pw");
        assert_eq!(read_piped("pw").unwrap(), "pw");
        // Inner spaces and a lone carriage return at the end are part of the password.
        assert_eq!(read_piped(" a b \n").unwrap(), " a b ");
        assert_eq!(read_piped("pw\r").unwrap(), "pw\r");
    }

    #[test]
    fn the_refusals() {
        assert_eq!(read_piped(""), Err(PasswordError::Empty));
        assert_eq!(read_piped("\n"), Err(PasswordError::Empty));
        assert_eq!(read_piped("a\nb\n"), Err(PasswordError::MoreThanOneLine));
        assert_eq!(read_piped("a\n\n"), Err(PasswordError::MoreThanOneLine));
        let too_long = "x".repeat(PIPED_LIMIT + 1);
        assert_eq!(read_piped(&too_long), Err(PasswordError::Read));
        let mut bad = Scripted::piped("");
        bad.input = vec![0xff, 0xfe];
        assert_eq!(
            read(&mut bad, "password").unwrap_err(),
            PasswordError::NotUtf8
        );
    }

    #[test]
    fn a_terminal_gets_a_prompt_on_stderr_and_nothing_on_stdout() {
        let mut term = Scripted::piped("pw\n");
        term.tty = true;
        let secret = read(&mut term, "password").unwrap();
        assert_eq!(secret.expose_secret(), "pw");
        assert_eq!(term.err, b"password: ");
        assert_eq!(term.out.len(), 0);
    }

    #[test]
    fn debug_of_the_secret_shows_nothing() {
        let secret = read(&mut Scripted::piped("sentinel-pw\n"), "password").unwrap();
        assert!(!format!("{secret:?}").contains("sentinel-pw"));
    }
}
