//! Supported-camera catalogue: typed entries, a structural guard, a soft lint and the support matrix.
//!
//! One entry describes one camera *model* (never a site's camera). Entries live in
//! `cameras/<vendor>/<model>.toml` at the repository root; the format is documented in
//! `cameras/FORMAT.md` and the generated support matrix is `cameras/README.md`.
//! The repository is public, so [`validate`] refuses disallowed characters and [`lint`] warns about text that looks like site
//! data; the authoritative check is the exact-match `wardenlens vault scan cameras/` (ADR 0006).
//!
//! This module is pure: it parses and checks `&str` input. Reading files is the caller's job.
//!
//! ```
//! use wardenlens_core::catalogue::{CatalogueEntry, validate};
//!
//! let toml = r#"
//! vendor = "Acme"
//! model = "C1"
//! support = "community"
//! [[evidence]]
//! reference = "docs/adr/0002-camera-integration.md"
//! "#;
//! let entry = CatalogueEntry::from_toml_str(toml)?;
//! validate(&entry)?;
//! assert_eq!(entry.model_slug(), "c1");
//! # Ok::<(), wardenlens_core::catalogue::CatalogueError>(())
//! ```

mod entry;
mod error;
mod guard;
mod matrix;
mod validate;

pub(crate) use entry::is_slug;
pub use entry::{
    CatalogueEntry, Codec, ConfigFeature, Event, EventKind, EventSource, EventStatus, Evidence,
    FirmwareFamily, Protocol, ProtocolKind, Stream, StreamRole, SupportLevel,
};
pub use error::{CatalogueError, SiteDataKind};
pub use guard::{LintWarning, check_source, lint_source};
pub use matrix::render_matrix;
pub use validate::{lint, validate};
