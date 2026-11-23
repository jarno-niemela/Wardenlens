//! Generation of the `cameras/README.md` support matrix.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use super::entry::{CatalogueEntry, EventStatus, StreamRole};

/// Renders the support matrix as Markdown: one row per entry, sorted by vendor slug then model
/// slug, so the output depends only on the set of entries, not their order.
///
/// Events seen only in camera advertisements are marked with `*`. The text is what is checked
/// in as `cameras/README.md`.
#[must_use]
pub fn render_matrix(entries: &[CatalogueEntry]) -> String {
    let mut sorted: Vec<&CatalogueEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| (e.vendor_slug(), e.model_slug()));

    let mut out = String::from(
        "# Supported cameras\n\n\
         <!-- Generated from cameras/*/*.toml. Do not edit by hand. Regenerate with:\n\
         WARDENLENS_BLESS=1 cargo test -p wardenlens-core --test catalogue -->\n\n\
         One row per camera model. Entry format: [FORMAT.md](FORMAT.md).\n\
         Events marked `*` are advertised by the camera but not yet seen live.\n\n\
         | Vendor | Model | Support | Firmware | Main stream | Events | Protocols |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for e in sorted {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} |",
            cell(&e.vendor),
            model_cell(e),
            e.support.as_str(),
            join_or_dash(e.firmware.iter().map(ToString::to_string)),
            main_stream(e),
            events(e),
            join_or_dash(
                e.protocols
                    .iter()
                    .map(|p| p.kind)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|k| k.as_str().to_owned())
            ),
        );
    }
    out
}

fn model_cell(e: &CatalogueEntry) -> String {
    if e.aliases.is_empty() {
        cell(&e.model)
    } else {
        let aliases: Vec<String> = e.aliases.iter().map(|a| cell(a)).collect();
        format!("{} (aka {})", cell(&e.model), aliases.join(", "))
    }
}

fn main_stream(e: &CatalogueEntry) -> String {
    e.streams
        .iter()
        .find(|s| s.role == StreamRole::Main)
        .map_or_else(
            || "-".to_owned(),
            |s| format!("{}x{} {}", s.width, s.height, s.codec.as_str()),
        )
}

fn events(e: &CatalogueEntry) -> String {
    // A kind is "observed" if any channel observed it.
    let kinds: BTreeSet<_> = e.events.iter().map(|ev| ev.kind).collect();
    join_or_dash(kinds.into_iter().map(|k| {
        let observed = e
            .events
            .iter()
            .any(|ev| ev.kind == k && ev.status == EventStatus::Observed);
        format!("{}{}", k.as_str(), if observed { "" } else { "*" })
    }))
}

fn join_or_dash(items: impl Iterator<Item = String>) -> String {
    let v: Vec<String> = items.collect();
    if v.is_empty() {
        "-".to_owned()
    } else {
        v.join(", ")
    }
}

/// Makes text safe inside a Markdown table cell.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(vendor: &str, model: &str, extra: &str) -> CatalogueEntry {
        CatalogueEntry::from_toml_str(&format!(
            "vendor=\"{vendor}\"\nmodel=\"{model}\"\nsupport=\"partial\"\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn empty_catalogue_renders_header_only() {
        let m = render_matrix(&[]);
        assert!(m.contains("| Vendor | Model |"));
        assert_eq!(m.lines().filter(|l| l.starts_with("| ")).count(), 1);
    }

    #[test]
    fn rows_are_sorted_and_independent_of_input_order() {
        let a = entry("Zed", "B", "");
        let b = entry("Alpha", "Z", "");
        let c = entry("Alpha", "A", "");
        let one = render_matrix(&[a.clone(), b.clone(), c.clone()]);
        let two = render_matrix(&[c, a, b]);
        assert_eq!(one, two);
        let rows: Vec<&str> = one
            .lines()
            .filter(|l| l.starts_with("| "))
            .skip(1)
            .collect();
        assert!(rows[0].starts_with("| Alpha | A |"), "{rows:?}");
        assert!(rows[1].starts_with("| Alpha | Z |"));
        assert!(rows[2].starts_with("| Zed | B |"));
    }

    #[test]
    fn renders_features_and_marks_advertised_events() {
        let e = entry(
            "V",
            "M",
            "aliases=[\"OEM\"]\nfirmware=[\"1.5\"]\n\
             streams=[{role=\"sub\",codec=\"h264\",width=1,height=1},{role=\"main\",codec=\"h265\",width=1920,height=1080}]\n\
             protocols=[{kind=\"onvif\"},{kind=\"rtsp\"},{kind=\"onvif\"}]\n\
             events=[{kind=\"motion\",source=\"onvif\",status=\"observed\"},{kind=\"person\",source=\"onvif\",status=\"advertised\"}]\n",
        );
        let m = render_matrix(&[e]);
        assert!(m.contains("| V | M (aka OEM) | partial | 1.5 | 1920x1080 H.265 | motion, person* | rtsp, onvif |"), "{m}");
    }

    #[test]
    fn missing_data_renders_as_dash_and_pipes_are_escaped() {
        let m = render_matrix(&[entry("A|B", "M", "")]);
        assert!(m.contains("| A\\|B | M | partial | - | - | - | - |"), "{m}");
    }
}
