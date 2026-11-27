//! The camera catalogue (`cameras/`, #32) compiled into the binary, and what `camera add` reads
//! from an entry: its RTSP paths and the ports of its RTSP and ONVIF services.
//!
//! The files are embedded with `include_str!`, so the binary needs no data directory and the
//! catalogue it runs with is the one it was built from. A test lists `cameras/` and fails when a
//! file is missing from [`SOURCES`], so a new entry cannot be forgotten.

use std::num::NonZeroU16;

use wardenlens_core::camera::{CameraError, DEFAULT_RTSP_PORT, ModelRef};
use wardenlens_core::catalogue::{CatalogueEntry, CatalogueError, ProtocolKind, validate};

/// Every entry of `cameras/`, in directory order.
const SOURCES: [&str; 4] = [
    include_str!("../../../../../cameras/dahua/ipc-hfw4431r-z.toml"),
    include_str!("../../../../../cameras/reolink/rlc-520a.toml"),
    include_str!("../../../../../cameras/rtt/rtt-8700.toml"),
    include_str!("../../../../../cameras/tp-link/tapo-c110.toml"),
];

/// The ONVIF HTTP port when the entry names none.
pub(super) const DEFAULT_ONVIF_PORT: NonZeroU16 = NonZeroU16::MIN.saturating_add(79);

/// Parses and validates the embedded entries.
///
/// # Errors
/// [`CatalogueError`] when an embedded file is invalid (a test pins that none is).
pub(super) fn load() -> Result<Vec<CatalogueEntry>, CatalogueError> {
    SOURCES
        .iter()
        .map(|text| {
            let entry = CatalogueEntry::from_toml_str(text)?;
            validate(&entry)?;
            Ok(entry)
        })
        .collect()
}

/// `vendor/model` as the two slugs of a [`ModelRef`].
///
/// # Errors
/// [`CameraError::ModelSlug`] when `text` has no `/` or a part is not a slug.
pub(super) fn parse_model(text: &str) -> Result<ModelRef, CameraError> {
    let (vendor, model) = text.split_once('/').ok_or(CameraError::ModelSlug)?;
    ModelRef::new(vendor, model)
}

/// The entry for `model`, if the catalogue has one.
pub(super) fn find<'a>(
    entries: &'a [CatalogueEntry],
    model: &ModelRef,
) -> Option<&'a CatalogueEntry> {
    entries
        .iter()
        .find(|e| ModelRef::from_entry(e).is_ok_and(|m| &m == model))
}

/// The entry's RTSP paths: the first is the main stream, the second the sub stream (the order
/// the catalogue files list them in).
pub(super) fn rtsp_paths(entry: &CatalogueEntry) -> (Option<&str>, Option<&str>) {
    let mut paths = entry
        .protocols
        .iter()
        .filter(|p| p.kind == ProtocolKind::Rtsp)
        .flat_map(|p| p.paths.iter().map(String::as_str));
    (paths.next(), paths.next())
}

/// The entry's RTSP path with the same part before `?` as `path` that shares the longest prefix
/// with it (so a sub stream's answer is pointed at the sub stream's path), for a refusal to name.
pub(super) fn listed_like<'a>(entry: &'a CatalogueEntry, path: &str) -> Option<&'a str> {
    let head = |p: &str| p.split_once('?').map_or(p.len(), |(h, _)| h.len());
    let same = |l: &&str| l[..head(l)] == path[..head(path)];
    let common = |l: &&str| {
        l.bytes()
            .zip(path.bytes())
            .take_while(|(x, y)| x == y)
            .count()
    };
    entry
        .protocols
        .iter()
        .filter(|p| p.kind == ProtocolKind::Rtsp)
        .flat_map(|p| p.paths.iter().map(String::as_str))
        .filter(same)
        .max_by_key(common)
}

fn port_of(entry: &CatalogueEntry, kind: ProtocolKind, default: NonZeroU16) -> NonZeroU16 {
    entry
        .protocols
        .iter()
        .filter(|p| p.kind == kind)
        .find_map(|p| p.port.and_then(NonZeroU16::new))
        .unwrap_or(default)
}

/// The entry's RTSP port, else 554.
pub(super) fn rtsp_port(entry: &CatalogueEntry) -> NonZeroU16 {
    port_of(entry, ProtocolKind::Rtsp, DEFAULT_RTSP_PORT)
}

/// The entry's ONVIF port, else 80.
pub(super) fn onvif_port(entry: &CatalogueEntry) -> NonZeroU16 {
    port_of(entry, ProtocolKind::Onvif, DEFAULT_ONVIF_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_entries_are_valid_and_cover_the_cameras_directory() {
        let entries = load().unwrap();
        assert_eq!(entries.len(), SOURCES.len());
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras");
        let mut on_disk = Vec::new();
        for vendor in std::fs::read_dir(&root).unwrap() {
            let vendor = vendor.unwrap().path();
            if !vendor.is_dir() {
                continue;
            }
            for file in std::fs::read_dir(&vendor).unwrap() {
                let text = std::fs::read_to_string(file.unwrap().path()).unwrap();
                on_disk.push(text);
            }
        }
        on_disk.sort();
        let mut embedded: Vec<String> = SOURCES.iter().map(|s| (*s).to_owned()).collect();
        embedded.sort();
        assert_eq!(on_disk, embedded, "add the new file to SOURCES");
    }

    #[test]
    fn models_parse_as_vendor_slash_model() {
        assert!(parse_model("reolink/rlc-520a").is_ok());
        for bad in [
            "",
            "reolink",
            "/rlc",
            "reolink/",
            "Reolink/RLC",
            "a/b/c",
            "a b/c",
        ] {
            assert!(parse_model(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn paths_and_ports_come_from_the_entry() {
        let entries = load().unwrap();
        let reolink = find(&entries, &parse_model("reolink/rlc-520a").unwrap()).unwrap();
        assert_eq!(
            rtsp_paths(reolink),
            (Some("/h264Preview_01_main"), Some("/h264Preview_01_sub"))
        );
        assert_eq!(rtsp_port(reolink).get(), 554);
        assert_eq!(onvif_port(reolink).get(), 8000);
        // The Dahua entry names no RTSP port and an ONVIF port of 80.
        let dahua = find(&entries, &parse_model("dahua/ipc-hfw4431r-z").unwrap()).unwrap();
        assert_eq!(rtsp_port(dahua), DEFAULT_RTSP_PORT);
        assert!(find(&entries, &parse_model("acme/none").unwrap()).is_none());
    }
}
