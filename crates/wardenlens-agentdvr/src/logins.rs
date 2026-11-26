//! The logins of a parse: every user and password text the document holds, collected where it is
//! read, so a caller can keep them out of anything it writes.
//!
//! Collected for **every occurrence** of these elements, whatever the camera entry does with
//! them (repeated elements, over-long fields and skipped entries included), after XML decoding,
//! from the whole text of the element (not the [`crate::MAX_FIELD_BYTES`] slice the entry keeps):
//!
//! * `objects/cameras/camera/settings/login` and `.../password`: the text raw and trimmed;
//! * `objects/cameras/camera/settings/videosourcestring`: for every `@` of the text after `://`
//!   (or of the whole text), the user and the password of the userinfo before it (not cut at
//!   `/`), each raw, trimmed and percent-decoded; and the value of every credential-named
//!   `name=value` parameter anywhere in the text (core's denied names, to the next `&` and to
//!   the next delimiter).
//!
//! Text in any element below one of these three is collected too. Anything else is not: other
//! `settings` children (including a microphone's own credentials, if the file has any), other
//! attributes and the host. Candidates are deliberately generous, because a missed one leaks and
//! an extra one only over-refuses. Values empty after trimming are left out.
//!
//! The set is bounded: duplicates count once, and more than [`MAX_LOGINS`] distinct values, or
//! more than [`MAX_LOGIN_BYTES`] bytes of them, or more than [`MAX_LOGIN_WORK`] bytes of work (every candidate
//! offered, duplicates included, and the scans), refuses the whole document with
//! [`ImportError::TooManyLogins`]. Nothing is dropped silently. The order is not significant.

use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::fmt;

use secrecy::zeroize::Zeroizing;

use crate::ImportError;
use crate::source::for_each_candidate;

/// Most distinct login values a document may hold.
pub const MAX_LOGINS: usize = 4096;

/// Most bytes all the distinct login values may hold together.
pub const MAX_LOGIN_BYTES: usize = 1024 * 1024;

/// Most work, in bytes, one document may cost the login collection: every candidate byte offered
/// (duplicates included) plus the bytes scanned per text, at a small constant factor each. The
/// 8 MiB input limit times this constant bounds the parse; past it the document is refused.
pub const MAX_LOGIN_WORK: usize = 16 * crate::MAX_INPUT_BYTES;

/// Work charged per byte of a source text for the candidate scans.
const SCAN_FACTOR: usize = 8;

/// One value; ordered and borrowed as its text so a lookup needs no copy.
#[derive(Clone)]
pub(crate) struct Secret(Zeroizing<String>);

impl Secret {
    pub(crate) fn new(text: &str) -> Self {
        Self(Zeroizing::new(text.to_owned()))
    }
}

impl std::hash::Hash for Secret {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}
impl Eq for Secret {}
impl PartialOrd for Secret {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Secret {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_str().cmp(other.0.as_str())
    }
}
impl Borrow<str> for Secret {
    fn borrow(&self) -> &str {
        self.0.as_str()
    }
}

/// The collected login texts, distinct. Zeroised on drop; `Debug` shows only the count.
#[derive(Clone, Default)]
pub struct Logins {
    set: BTreeSet<Secret>,
    bytes: usize,
    work: usize,
}

impl Logins {
    /// The values, in no particular order. Sensitive: never print them.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.set.iter().map(|s| s.0.as_str())
    }

    /// How many distinct values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// True if there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Charges `n` bytes of work; past [`MAX_LOGIN_WORK`] the document is refused.
    pub(crate) fn charge(&mut self, n: usize) -> Result<(), ImportError> {
        self.work = self.work.saturating_add(n);
        if self.work > MAX_LOGIN_WORK {
            return Err(ImportError::TooManyLogins);
        }
        Ok(())
    }

    /// The work charged so far, in bytes.
    #[must_use]
    pub fn work(&self) -> usize {
        self.work
    }

    /// Adds one value unless it is blank or already there. The length is checked before
    /// anything is copied. Every offered byte is charged, a duplicate or a blank too.
    fn push(&mut self, value: &str) -> Result<(), ImportError> {
        self.charge(value.len().max(1))?;
        if value.trim().is_empty() || self.set.contains(value) {
            return Ok(());
        }
        let bytes = self.bytes.saturating_add(value.len());
        if self.set.len() >= MAX_LOGINS || bytes > MAX_LOGIN_BYTES {
            return Err(ImportError::TooManyLogins);
        }
        self.bytes = bytes;
        self.set.insert(Secret(Zeroizing::new(value.to_owned())));
        Ok(())
    }

    fn push_text(&mut self, text: &str) -> Result<(), ImportError> {
        self.push(text)?;
        let trimmed = text.trim();
        if trimmed != text {
            self.push(trimmed)?;
        }
        Ok(())
    }

    /// A `login` or `password` field ended with `text`.
    pub(crate) fn add_field(&mut self, text: &str) -> Result<(), ImportError> {
        self.push_text(text)
    }

    /// A `videosourcestring` field ended with `text`.
    pub(crate) fn add_source(&mut self, text: &str) -> Result<(), ImportError> {
        // The scans of `for_each_candidate` (`@`, `:`, `=` and the name checks): at most
        // `SCAN_FACTOR` passes over the text.
        self.charge(text.len().saturating_mul(SCAN_FACTOR))?;
        for_each_candidate(text, &mut |v| self.push_text(v))
    }
}

impl fmt::Debug for Logins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Logins([redacted; {}])", self.set.len())
    }
}
