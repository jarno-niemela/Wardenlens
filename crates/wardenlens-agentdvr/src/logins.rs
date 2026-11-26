//! The logins of a parse: every user and password text the document holds, collected where it is
//! read, so a caller can keep them out of anything it writes.
//!
//! Collected for **every occurrence** of `login`, `password` and `videosourcestring` under any
//! `settings` of any `camera` (repeated elements and skipped entries included), after XML
//! decoding. Candidates are deliberately generous, because a missed one leaks and an extra one only
//! over-refuses: each text raw and trimmed, and for a source (with or without a scheme) the
//! parts of the userinfo before the last `@` (not cut at `/`), raw and percent-decoded. Values that
//! are empty after trimming are left out. The host is **not** a login and is not collected. The
//! 8 MiB input and 256-camera caps bound the total; there is no per-entry count.

use std::fmt;

use secrecy::zeroize::Zeroizing;

use crate::source::userinfo_candidates;

/// The collected login texts. Zeroised on drop; `Debug` shows only the count.
#[derive(Clone, Default)]
pub struct Logins(Vec<Zeroizing<String>>);

impl Logins {
    /// The values, in document order. Sensitive: never print them.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|s| s.as_str())
    }

    /// How many values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn push(&mut self, value: &str) {
        if !value.trim().is_empty() {
            self.0.push(Zeroizing::new(value.to_owned()));
        }
    }

    fn push_text(&mut self, text: &str) {
        self.push(text);
        let trimmed = text.trim();
        if trimmed != text {
            self.push(trimmed);
        }
    }

    /// A `login` or `password` field ended with `text`.
    pub(crate) fn add_field(&mut self, text: &str) {
        self.push_text(text);
    }

    /// A `videosourcestring` field ended with `text`.
    pub(crate) fn add_source(&mut self, text: &str) {
        for v in userinfo_candidates(text) {
            self.push_text(&v);
        }
    }
}

impl fmt::Debug for Logins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Logins([redacted; {}])", self.0.len())
    }
}
