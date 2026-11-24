//! Reading a value for `set`: a no-echo prompt on a terminal, else stdin. Never argv.

use secrecy::SecretString;
use wardenlens_core::entry::EntryKind;
use wardenlens_secrets::Credentials;
use wardenlens_vault::{MAX_VALUE_LEN, Value};
use zeroize::Zeroizing;

use crate::error::CliError;
use crate::terminal::Terminal;

/// Room for two fields and their line ends.
const PIPED_LIMIT: usize = MAX_VALUE_LEN * 2 + 4;

fn utf8(bytes: &[u8]) -> Result<Zeroizing<String>, CliError> {
    std::str::from_utf8(bytes)
        .map(|s| Zeroizing::new(s.to_owned()))
        .map_err(|_| CliError::Refused("value is not valid UTF-8"))
}

fn strip_line_end(bytes: &[u8]) -> &[u8] {
    let b = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    b.strip_suffix(b"\r").unwrap_or(b)
}

fn input_error(e: &std::io::Error) -> CliError {
    match e.kind() {
        std::io::ErrorKind::InvalidData => CliError::Refused("value is too large"),
        _ => CliError::Refused("could not read the value"),
    }
}

/// Reads the value for `kind`. A credential is two lines (username, then password).
pub(super) fn read(kind: EntryKind, term: &mut impl Terminal) -> Result<Value, CliError> {
    let tty = term.stdin_is_tty();
    if kind == EntryKind::Credential {
        let (user, pass) = if tty {
            let u = term
                .prompt_secret("username")
                .map_err(|e| input_error(&e))?;
            let p = term
                .prompt_secret("password")
                .map_err(|e| input_error(&e))?;
            (utf8(&u)?, utf8(&p)?)
        } else {
            let raw = term.read_piped(PIPED_LIMIT).map_err(|e| input_error(&e))?;
            let at = raw
                .iter()
                .position(|b| *b == b'\n')
                .ok_or(CliError::Refused(
                    "a credential is two lines on stdin: username, then password",
                ))?;
            let (u, rest) = raw.split_at(at);
            let p = rest.get(1..).unwrap_or_default();
            (utf8(strip_line_end(u))?, utf8(strip_line_end(p))?)
        };
        return Ok(Value::Credential(Credentials::new(
            user.as_str(),
            pass.as_str(),
        )));
    }
    let text = if tty {
        utf8(&term.prompt_secret("value").map_err(|e| input_error(&e))?)?
    } else {
        let raw = term.read_piped(PIPED_LIMIT).map_err(|e| input_error(&e))?;
        utf8(strip_line_end(&raw))?
    };
    Ok(Value::Text(SecretString::from(text.as_str().to_owned())))
}
