//! Names and ids: display-name normalisation, slugs and the id allocator.
//!
//! The normalisation is the vault's display-name rule (`wardenlens-vault`, `display_name_text`,
//! ADR 0006 section 1), restated here because this crate depends on core only (ADR 0004). Both
//! use core's one predicate, `text::is_dropped_invisible`, for what is deleted.

use std::collections::BTreeSet;

use wardenlens_core::camera::{CameraError, CameraId, MAX_CAMERA_ID_LEN};
use wardenlens_core::text::is_dropped_invisible;

/// Longest slug before a dedup suffix: leaves room for `-256` (4 bytes) in 32.
const MAX_SLUG_LEN: usize = MAX_CAMERA_ID_LEN - 4;

/// The name as stored: every white-space character is one U+0020, a run is one space, invisible
/// characters are dropped and the ends are trimmed.
pub(crate) fn normalise_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut pending_space = false;
    for c in raw.chars() {
        if c.is_whitespace() {
            pending_space = true;
        } else if !is_dropped_invisible(c) {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push(c);
        }
    }
    out
}

/// The slug of a normalised name: ASCII lower-case letters and digits, any other run as one `-`,
/// no leading or trailing `-`, `cam-` in front when it does not start with a letter (`cam` when
/// empty), at most [`MAX_SLUG_LEN`] bytes.
pub(crate) fn slug(name: &str) -> String {
    let mut out = String::new();
    let mut pending_dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(c.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    if !out.starts_with(|c: char| c.is_ascii_lowercase()) {
        out = if out.is_empty() {
            "cam".to_owned()
        } else {
            format!("cam-{out}")
        };
    }
    truncate_slug(&mut out, MAX_SLUG_LEN);
    out
}

/// Cuts to `max` bytes (the text is ASCII) and drops a trailing `-`.
fn truncate_slug(s: &mut String, max: usize) {
    s.truncate(max);
    while s.ends_with('-') {
        s.pop();
    }
}

/// Hands out unique [`CameraId`]s in call order: the slug, then `-2`, `-3`, ...
#[derive(Default)]
pub(crate) struct IdAllocator {
    used: BTreeSet<String>,
}

impl IdAllocator {
    pub(crate) fn allocate(&mut self, normalised_name: &str) -> Result<CameraId, CameraError> {
        let base = slug(normalised_name);
        let chosen = if self.used.contains(&base) {
            // At most 256 ids are ever in `used`, so a free number below 258 always exists; the
            // range is bounded by `u32::MAX` only so the search cannot loop forever.
            (2_u32..=u32::MAX)
                .map(|n| suffixed(&base, n))
                .find(|candidate| !self.used.contains(candidate))
                .ok_or(CameraError::IdTooLong)?
        } else {
            base
        };
        let id = CameraId::new(&chosen)?;
        self.used.insert(chosen);
        Ok(id)
    }
}

/// `base-n`, with `base` cut so the whole id stays within the id length limit.
fn suffixed(base: &str, n: u32) -> String {
    let suffix = format!("-{n}");
    let mut head = base.to_owned();
    truncate_slug(&mut head, MAX_CAMERA_ID_LEN.saturating_sub(suffix.len()));
    format!("{head}{suffix}")
}
