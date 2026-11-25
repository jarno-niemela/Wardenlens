//! The query-string allow-list of a camera model (ADR 0005 section 5, ticket #50).
//!
//! A vendor RTSP path can carry a credential in its query string, and a credential-name list can
//! never be complete. So a query string is accepted only when the catalogue entry of the camera's
//! model lists it: it must equal, byte for byte, the query of one of the entry's RTSP paths. A
//! path without a query is always allowed here (its other rules are [`RtspPath`]'s).
//!
//! | camera model | path | result |
//! |---|---|---|
//! | any | `/stream1` (no `?`) | allowed |
//! | in the catalogue, lists `/cam?channel=1&subtype=0` | `/x?channel=1&subtype=0` | allowed (only the query is compared) |
//! | in the catalogue, lists `/cam?channel=1&subtype=0` | `/cam?channel=2&subtype=0`, `/cam?`, `/cam?CHANNEL=1&subtype=0` | refused |
//! | not in the catalogue | any path with a `?` | refused |

use crate::camera::{ModelRef, RtspPath};

use super::{CatalogueEntry, ProtocolKind};

/// True when `path` has no query string, or `model` is in `catalogue` and one of its RTSP paths
/// has exactly the query of `path`. It does not check credential names: that is [`RtspPath::new`].
#[must_use]
pub fn query_allowed(catalogue: &[CatalogueEntry], model: &ModelRef, path: &RtspPath) -> bool {
    let Some(query) = path.query() else {
        return true;
    };
    catalogue
        .iter()
        .filter(|e| ModelRef::from_entry(e).is_ok_and(|m| &m == model))
        .flat_map(|e| &e.protocols)
        .filter(|p| p.kind == ProtocolKind::Rtsp)
        .flat_map(|p| &p.paths)
        .any(|listed| listed.split_once('?').map(|(_, q)| q) == Some(query))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(vendor: &str, model: &str, kind: &str, paths: &str) -> CatalogueEntry {
        CatalogueEntry::from_toml_str(&format!(
            "vendor = \"{vendor}\"\nmodel = \"{model}\"\nsupport = \"community\"\n\
             [[protocols]]\nkind = \"{kind}\"\npaths = [{paths}]\n\
             [[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n"
        ))
        .unwrap()
    }

    fn model(v: &str, m: &str) -> ModelRef {
        ModelRef::new(v, m).unwrap()
    }

    #[test]
    fn the_table() {
        let cat = vec![
            entry(
                "Acme",
                "C1",
                "rtsp",
                "\"/cam?channel=1&subtype=0\", \"/plain\"",
            ),
            entry("Acme", "C2", "onvif", "\"/cam?channel=9\""),
            entry("Acme", "C3", "rtsp", ""),
        ];
        let c1 = model("acme", "c1");
        for (m, path, ok) in [
            (&c1, "/stream1", true),
            (&c1, "/x?channel=1&subtype=0", true),
            (&c1, "/cam?channel=1&subtype=0", true),
            (&c1, "/cam?channel=2&subtype=0", false),
            (&c1, "/cam?channel=1&subtype=0&x=1", false),
            (&c1, "/cam?", false),
            (&c1, "/cam?CHANNEL=1&subtype=0", false),
            (&c1, "/cam?channel=1&subtype=0?", false),
            // an ONVIF path is not an RTSP path
            (&model("acme", "c2"), "/cam?channel=9", false),
            (&model("acme", "c3"), "/a?b=1", false),
            (&model("acme", "c3"), "/a", true),
            (&model("acme", "unknown"), "/a?channel=1&subtype=0", false),
            (&model("other", "c1"), "/a?channel=1&subtype=0", false),
            (&model("acme", "unknown"), "/a", true),
        ] {
            let p = RtspPath::new(path).unwrap();
            assert_eq!(query_allowed(&cat, m, &p), ok, "{m} {path}");
        }
        assert!(query_allowed(&[], &c1, &RtspPath::new("/plain").unwrap()));
        assert!(!query_allowed(&[], &c1, &RtspPath::new("/p?a=1").unwrap()));
    }
}
