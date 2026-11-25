//! [`ModelRef`]: which catalogue entry a camera is (vendor and model slugs).
//!
//! The slugs are the catalogue's own (`cameras/<vendor>/<model>.toml`, see
//! [`CatalogueEntry::vendor_slug`]); a value is valid exactly when it is its own slug.
//!
//! | input | result |
//! |---|---|
//! | `reolink` / `rlc-520a`, `tp-link` / `tapo-c110`, `a` / `1` | accepted |
//! | empty, `Reolink` (upper case), `a--b`, `-a`, `a-`, `a b`, `a_b`, `a.b`, `a/b`, non-ASCII | `ModelSlug` |
//! | more than 64 bytes | `ModelSlug` |
//!
//! A catalogue entry converts with [`ModelRef::from_entry`], which slugs its vendor and model.
//! A model reference names a product, not a site, so it is printed as is.

use std::fmt;

use super::CameraError;
use crate::catalogue::CatalogueEntry;
use crate::catalogue::is_slug;

/// Longest vendor or model slug in bytes.
pub const MAX_SLUG_LEN: usize = 64;

/// A validated reference to a catalogue model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModelRef {
    vendor: String,
    model: String,
}

fn check(text: &str) -> Result<(), CameraError> {
    if text.len() <= MAX_SLUG_LEN && is_slug(text) {
        Ok(())
    } else {
        Err(CameraError::ModelSlug)
    }
}

impl ModelRef {
    /// Validates a vendor and a model slug.
    ///
    /// # Errors
    /// [`CameraError::ModelSlug`] when either is not a canonical slug of 1 to 64 bytes.
    pub fn new(vendor: &str, model: &str) -> Result<Self, CameraError> {
        check(vendor)?;
        check(model)?;
        Ok(Self {
            vendor: vendor.to_owned(),
            model: model.to_owned(),
        })
    }

    /// The reference of a catalogue entry (its vendor and model slugs).
    ///
    /// # Errors
    /// [`CameraError::ModelSlug`] when a slug is empty or over 64 bytes.
    pub fn from_entry(entry: &CatalogueEntry) -> Result<Self, CameraError> {
        Self::new(&entry.vendor_slug(), &entry.model_slug())
    }

    /// The vendor slug.
    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    /// The model slug.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
}

impl fmt::Display for ModelRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.vendor, self.model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_catalogue_slugs() {
        for (v, m) in [
            ("reolink", "rlc-520a"),
            ("tp-link", "tapo-c110"),
            ("a", "1"),
            (&"a".repeat(64), &"9".repeat(64)),
        ] {
            let r = ModelRef::new(v, m).unwrap();
            assert_eq!((r.vendor(), r.model()), (v, m));
            assert_eq!(r.to_string(), format!("{v}/{m}"));
        }
    }

    #[test]
    fn rejects_non_slugs() {
        for bad in [
            "",
            "Reolink",
            "a--b",
            "-a",
            "a-",
            "a b",
            "a_b",
            "a.b",
            "a/b",
            "..",
            "\u{e9}",
            "a\0",
            "a\n",
            &"a".repeat(65),
        ] {
            assert_eq!(
                ModelRef::new(bad, "ok"),
                Err(CameraError::ModelSlug),
                "{bad:?}"
            );
            assert_eq!(
                ModelRef::new("ok", bad),
                Err(CameraError::ModelSlug),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn from_entry_uses_the_catalogue_slugs() {
        let entry = CatalogueEntry::from_toml_str(
            "vendor = \"TP-Link\"\nmodel = \"Tapo C110\"\nsupport = \"community\"\n\
             [[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n",
        )
        .unwrap();
        let r = ModelRef::from_entry(&entry).unwrap();
        assert_eq!((r.vendor(), r.model()), ("tp-link", "tapo-c110"));
        assert_eq!(r.vendor(), entry.vendor_slug());
        assert_eq!(r.model(), entry.model_slug());
    }

    #[test]
    fn from_entry_refuses_a_name_with_no_alphanumerics() {
        let entry = CatalogueEntry::from_toml_str(
            "vendor = \"Acme\"\nmodel = \"---\"\nsupport = \"community\"\n\
             [[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n",
        )
        .unwrap();
        assert_eq!(ModelRef::from_entry(&entry), Err(CameraError::ModelSlug));
    }

    proptest::proptest! {
        #[test]
        fn accepted_values_are_their_own_slug(s in "\\PC{0,70}") {
            if let Ok(r) = ModelRef::new(&s, &s) {
                proptest::prop_assert_eq!(r.vendor(), s.as_str());
                proptest::prop_assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
                proptest::prop_assert!(!s.starts_with('-') && !s.ends_with('-') && !s.contains("--"));
            }
        }
    }
}
