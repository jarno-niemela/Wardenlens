//! Loads every checked-in `cameras/<vendor>/<model>.toml`, validates it and checks the
//! generated support matrix `cameras/README.md` is up to date.
//!
//! Regenerate the matrix with `WARDENLENS_BLESS=1 cargo test -p wardenlens-core --test catalogue`.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] fns may panic on failure"
)]

use std::fs;
use std::path::{Path, PathBuf};

use wardenlens_core::catalogue::{CatalogueEntry, check_source, render_matrix, validate};

fn cameras_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras")
}

/// Returns `(path, entry)` for every `cameras/*/*.toml`, sorted by path.
fn load_all() -> Vec<(PathBuf, CatalogueEntry)> {
    let mut paths = Vec::new();
    for vendor in fs::read_dir(cameras_dir()).unwrap() {
        let vendor = vendor.unwrap().path();
        if !vendor.is_dir() {
            let name = vendor
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            assert!(
                name == "README.md" || name == "FORMAT.md",
                "unexpected file directly under cameras/: {}",
                vendor.display()
            );
            continue;
        }
        for file in fs::read_dir(&vendor).unwrap() {
            let file = file.unwrap().path();
            assert_eq!(
                file.extension().and_then(|e| e.to_str()),
                Some("toml"),
                "unexpected non-toml file {}",
                file.display()
            );
            paths.push(file);
        }
    }
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let text = fs::read_to_string(&p).unwrap();
            let entry = CatalogueEntry::from_toml_str(&text)
                .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            (p, entry)
        })
        .collect()
}

#[test]
fn has_the_initial_entries() {
    let entries = load_all();
    let models: Vec<&str> = entries.iter().map(|(_, e)| e.model.as_str()).collect();
    for expected in ["RLC-520A", "IPC-HFW4431R-Z", "Tapo C110", "RTT-8700"] {
        assert!(models.contains(&expected), "missing {expected}");
    }
}

#[test]
fn every_entry_is_valid() {
    for (path, entry) in load_all() {
        validate(&entry).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
}

#[test]
fn file_paths_match_vendor_and_model_slugs() {
    for (path, entry) in load_all() {
        let expected = cameras_dir()
            .join(entry.vendor_slug())
            .join(format!("{}.toml", entry.model_slug()));
        assert_eq!(
            fs::canonicalize(&path).unwrap(),
            fs::canonicalize(&expected).unwrap_or(expected),
            "file path must be cameras/<vendor-slug>/<model-slug>.toml"
        );
    }
}

#[test]
fn readme_matrix_is_up_to_date() {
    let entries: Vec<CatalogueEntry> = load_all().into_iter().map(|(_, e)| e).collect();
    let rendered = render_matrix(&entries);
    let readme = cameras_dir().join("README.md");
    if std::env::var_os("WARDENLENS_BLESS").is_some() {
        fs::write(&readme, &rendered).unwrap();
        return;
    }
    let current = fs::read_to_string(&readme).unwrap_or_default();
    assert!(
        current == rendered,
        "cameras/README.md is stale; regenerate it by running: \
         WARDENLENS_BLESS=1 cargo test -p wardenlens-core --test catalogue"
    );
}

#[test]
fn published_docs_use_only_allowed_characters() {
    for name in ["README.md", "FORMAT.md"] {
        let text = fs::read_to_string(cameras_dir().join(name)).unwrap();
        check_source(&text).unwrap_or_else(|e| panic!("cameras/{name}: {e}"));
    }
}
