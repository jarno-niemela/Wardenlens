//! `import-legacy` mapping: pure functions from the parsed legacy files to entries.
//!
//! Only mapped fields are imported. Every other key is reported **by name** so the owner can
//! classify it; nothing is guessed. Ids come from inventory ids (or an ordinal), never from a
//! value (ADR 0006 sections 1 and 4). Reading the files is the CLI's job.

use std::collections::{BTreeMap, BTreeSet};

use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::Credentials;

use crate::store::Value;

/// Most cameras accepted from one legacy file (SEC-2).
pub const MAX_LEGACY_CAMERAS: usize = 256;
/// Longest unknown key name reported; longer names are cut.
const MAX_REPORTED_KEY_LEN: usize = 64;

/// An entry ready for `Vault::set`.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewEntry {
    /// The entry id, `cam:<inventory id>:<field>`.
    pub id: EntryId,
    /// The kind to store it as.
    pub kind: EntryKind,
    /// The value.
    pub value: Value,
}

/// The result of mapping one legacy file.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct LegacyImport {
    /// Entries for the mapped fields.
    pub entries: Vec<NewEntry>,
    /// Unmapped keys as `<inventory id>.<key>`. Names only; never values.
    pub unknown_keys: Vec<String>,
}

/// Why a legacy file could not be mapped. Never carries a value or a camera name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LegacyError {
    /// The JSON is not an array of objects.
    #[error("secret file must be a JSON array of objects")]
    NotAnArray,
    /// The TOML has no `cameras` table of tables.
    #[error("inventory must have a [cameras.<id>] table per camera")]
    NoCamerasTable,
    /// A camera entry is not an object or table.
    #[error("camera entry is not an object")]
    NotAnObject,
    /// A mapped field has the wrong type.
    #[error("a mapped field is not a string")]
    NotAString,
    /// Two cameras share a name.
    #[error("two cameras share a name")]
    DuplicateName,
    /// The file lists more than 256 cameras.
    #[error("too many cameras")]
    TooMany,
}

/// Keys of the inventory TOML that are public configuration (ADR 0006 section 1): skipped
/// silently rather than reported as unknown.
const PUBLIC_TOML_KEYS: [&str; 6] = [
    "vendor",
    "model",
    "firmware",
    "onvif_port",
    "port",
    "rtsp_port",
];

fn entry_id(inv: &str, field: &str) -> Option<EntryId> {
    EntryId::new(&format!("cam:{inv}:{field}")).ok()
}

/// A usable inventory id for a section, else the ordinal fallback `import-<n>` (1-based).
fn inventory_id(candidate: Option<&str>, ordinal: usize) -> String {
    match candidate {
        Some(c) if entry_id(c, "host").is_some() => c.to_owned(),
        _ => format!("import-{}", ordinal.saturating_add(1)),
    }
}

fn report_key(inv: &str, key: &str) -> String {
    let cut: String = key.chars().take(MAX_REPORTED_KEY_LEN).collect();
    format!("{inv}.{cut}")
}

fn text(kind: EntryKind, id: Option<EntryId>, value: &str) -> Option<NewEntry> {
    Some(NewEntry {
        id: id?,
        kind,
        value: Value::Text(SecretString::from(value.to_owned())),
    })
}

/// Maps the `AgentDVR` secret file (a JSON array of camera objects).
///
/// Mapped: `name` (display name), `login` or `username`, and `password` (a credential entry).
/// `names_to_ids` maps a camera name to its inventory id; a camera not in it gets an ordinal
/// id. Anything else is listed in `unknown_keys`.
///
/// # Errors
/// [`LegacyError`] for a wrongly shaped file or duplicate camera names.
pub fn map_secret_json(
    json: &serde_json::Value,
    names_to_ids: &BTreeMap<String, String>,
) -> Result<LegacyImport, LegacyError> {
    let cameras = json.as_array().ok_or(LegacyError::NotAnArray)?;
    if cameras.len() > MAX_LEGACY_CAMERAS {
        return Err(LegacyError::TooMany);
    }
    let mut out = LegacyImport::default();
    let mut seen = BTreeSet::new();
    let mut used_ids = BTreeSet::new();
    for (ordinal, camera) in cameras.iter().enumerate() {
        let obj = camera.as_object().ok_or(LegacyError::NotAnObject)?;
        let name = string_field(obj.get("name"))?;
        if let Some(n) = name
            && !seen.insert(n.to_owned())
        {
            return Err(LegacyError::DuplicateName);
        }
        let mapped = name.and_then(|n| names_to_ids.get(n)).map(String::as_str);
        let mut inv = inventory_id(mapped, ordinal);
        if !used_ids.insert(inv.clone()) {
            inv = format!("import-{}", ordinal.saturating_add(1));
            used_ids.insert(inv.clone());
        }
        let login = match string_field(obj.get("login"))? {
            Some(l) => Some(l),
            None => string_field(obj.get("username"))?,
        };
        let password = string_field(obj.get("password"))?;
        if let Some(n) = name {
            out.entries
                .extend(text(EntryKind::DisplayName, entry_id(&inv, "name"), n));
        }
        if let (Some(user), Some(id)) = (login, entry_id(&inv, "credential")) {
            out.entries.push(NewEntry {
                id,
                kind: EntryKind::Credential,
                value: Value::Credential(Credentials::new(user, password.unwrap_or_default())),
            });
        }
        for key in obj.keys() {
            if !matches!(key.as_str(), "name" | "login" | "username" | "password") {
                out.unknown_keys.push(report_key(&inv, key));
            }
        }
    }
    Ok(out)
}

fn string_field(v: Option<&serde_json::Value>) -> Result<Option<&str>, LegacyError> {
    match v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(LegacyError::NotAString),
    }
}

/// Maps the camera inventory (`[cameras.<id>]` tables).
///
/// Mapped: `host`, `mac`, `serial` and `name` (or `display_name`). Public configuration keys
/// (vendor, model, ports) are skipped; anything else is listed in `unknown_keys`. The section
/// name is the inventory id; an unusable one falls back to an ordinal.
///
/// # Errors
/// [`LegacyError`] for a wrongly shaped file.
pub fn map_inventory_toml(table: &toml::Table) -> Result<LegacyImport, LegacyError> {
    let cameras = table
        .get("cameras")
        .and_then(toml::Value::as_table)
        .ok_or(LegacyError::NoCamerasTable)?;
    if cameras.len() > MAX_LEGACY_CAMERAS {
        return Err(LegacyError::TooMany);
    }
    let mut out = LegacyImport::default();
    for (ordinal, (section, camera)) in cameras.iter().enumerate() {
        let obj = camera.as_table().ok_or(LegacyError::NotAnObject)?;
        let inv = inventory_id(Some(section), ordinal);
        for (key, value) in obj {
            let (kind, field) = match key.as_str() {
                "host" => (EntryKind::Host, "host"),
                "mac" => (EntryKind::Mac, "mac"),
                "serial" => (EntryKind::Serial, "serial"),
                "name" | "display_name" => (EntryKind::DisplayName, "name"),
                k if PUBLIC_TOML_KEYS.contains(&k) => continue,
                k => {
                    out.unknown_keys.push(report_key(&inv, k));
                    continue;
                }
            };
            let s = value.as_str().ok_or(LegacyError::NotAString)?;
            out.entries.extend(text(kind, entry_id(&inv, field), s));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn ids() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("Front Gate".to_owned(), "reolink-1".to_owned()),
            ("Garage".to_owned(), "tapo".to_owned()),
        ])
    }

    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    fn find<'a>(i: &'a LegacyImport, id: &str) -> &'a NewEntry {
        i.entries.iter().find(|e| e.id.as_str() == id).unwrap()
    }

    fn entry_ids(i: &LegacyImport) -> Vec<&str> {
        i.entries.iter().map(|e| e.id.as_str()).collect()
    }

    #[test]
    fn maps_json_cameras_to_inventory_ids() {
        let doc = json(
            r#"[{"name":"Front Gate","login":"svc-reader","password":"Tr0ub4dor-x9","onvif":"http://192.0.2.10:8000/x"},
                {"name":"Garage","login":"admin","password":"pw-garage-1"}]"#,
        );
        let imp = map_secret_json(&doc, &ids()).unwrap();
        assert_eq!(
            entry_ids(&imp),
            [
                "cam:reolink-1:name",
                "cam:reolink-1:credential",
                "cam:tapo:name",
                "cam:tapo:credential"
            ]
        );
        let cred = find(&imp, "cam:reolink-1:credential");
        assert_eq!(cred.kind, EntryKind::Credential);
        let Value::Credential(pair) = &cred.value else {
            panic!("shape")
        };
        assert_eq!(pair.username, "svc-reader");
        assert_eq!(pair.password.expose_secret(), "Tr0ub4dor-x9");
        let name = find(&imp, "cam:tapo:name");
        assert_eq!(name.kind, EntryKind::DisplayName);
        let Value::Text(shown) = &name.value else {
            panic!("shape")
        };
        assert_eq!(shown.expose_secret(), "Garage");
    }

    #[test]
    fn json_unknown_keys_are_listed_by_name_only() {
        let v = json(
            r#"[{"name":"Front Gate","login":"u","password":"p","onvif":"http://192.0.2.10/","ptz":true}]"#,
        );
        let i = map_secret_json(&v, &ids()).unwrap();
        assert_eq!(i.unknown_keys, ["reolink-1.onvif", "reolink-1.ptz"]);
        let all = format!("{:?}", i.unknown_keys);
        assert!(!all.contains("192.0.2.10") && !all.contains("Front Gate"));
    }

    #[test]
    fn json_ids_never_come_from_values() {
        let v = json(
            r#"[{"name":"192.0.2.10 Cam","login":"u","password":"p"},{"name":"Other","login":"u2","password":"p2"}]"#,
        );
        let i = map_secret_json(&v, &ids()).unwrap();
        assert_eq!(
            entry_ids(&i),
            [
                "cam:import-1:name",
                "cam:import-1:credential",
                "cam:import-2:name",
                "cam:import-2:credential"
            ]
        );
    }

    #[test]
    fn json_without_a_name_still_imports_the_credential() {
        let v = json(r#"[{"login":"u","password":"p"}]"#);
        let i = map_secret_json(&v, &ids()).unwrap();
        assert_eq!(entry_ids(&i), ["cam:import-1:credential"]);
    }

    #[test]
    fn json_login_without_password_gets_an_empty_password() {
        let v = json(r#"[{"name":"Garage","login":"u"}]"#);
        let i = map_secret_json(&v, &ids()).unwrap();
        let Value::Credential(c) = &find(&i, "cam:tapo:credential").value else {
            panic!("shape")
        };
        assert_eq!(c.password.expose_secret(), "");
    }

    #[test]
    fn json_without_login_imports_no_credential() {
        let v = json(r#"[{"name":"Garage","password":"orphan"}]"#);
        let i = map_secret_json(&v, &ids()).unwrap();
        assert_eq!(entry_ids(&i), ["cam:tapo:name"]);
    }

    #[test]
    fn json_shape_errors_do_not_leak() {
        assert_eq!(
            map_secret_json(&json("{}"), &ids()).unwrap_err(),
            LegacyError::NotAnArray
        );
        assert_eq!(
            map_secret_json(&json("[1]"), &ids()).unwrap_err(),
            LegacyError::NotAnObject
        );
        assert_eq!(
            map_secret_json(&json(r#"[{"name":5}]"#), &ids()).unwrap_err(),
            LegacyError::NotAString
        );
        assert_eq!(
            map_secret_json(&json(r#"[{"name":"A"},{"name":"A"}]"#), &ids()).unwrap_err(),
            LegacyError::DuplicateName
        );
        assert_eq!(
            map_secret_json(&json("[]"), &ids()).unwrap().entries.len(),
            0
        );
    }

    #[test]
    fn json_camera_count_is_bounded() {
        let many = serde_json::Value::Array(vec![serde_json::json!({}); MAX_LEGACY_CAMERAS + 1]);
        assert_eq!(
            map_secret_json(&many, &ids()).unwrap_err(),
            LegacyError::TooMany
        );
        let ok = serde_json::Value::Array(vec![serde_json::json!({}); MAX_LEGACY_CAMERAS]);
        assert!(map_secret_json(&ok, &ids()).is_ok());
    }

    #[test]
    fn json_inventory_id_collision_falls_back_to_an_ordinal() {
        let m = BTreeMap::from([
            ("A".to_owned(), "same".to_owned()),
            ("B".to_owned(), "same".to_owned()),
        ]);
        let v = json(
            r#"[{"name":"A","login":"u","password":"p"},{"name":"B","login":"u","password":"p"}]"#,
        );
        let i = map_secret_json(&v, &m).unwrap();
        let got = entry_ids(&i);
        assert!(got.contains(&"cam:same:credential") && got.contains(&"cam:import-2:credential"));
    }

    fn toml_of(s: &str) -> toml::Table {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn maps_inventory_toml() {
        let t = toml_of(
            r#"
[cameras.reolink-1]
host = "192.0.2.10"
mac = "02:00:5e:00:53:af"
serial = "SN-0042-ZQ"
name = "Back Door North"
vendor = "reolink"
onvif_port = 8000
"#,
        );
        let i = map_inventory_toml(&t).unwrap();
        assert_eq!(
            entry_ids(&i),
            [
                "cam:reolink-1:host",
                "cam:reolink-1:mac",
                "cam:reolink-1:name",
                "cam:reolink-1:serial"
            ]
        );
        assert_eq!(find(&i, "cam:reolink-1:host").kind, EntryKind::Host);
        assert_eq!(find(&i, "cam:reolink-1:mac").kind, EntryKind::Mac);
        assert_eq!(find(&i, "cam:reolink-1:serial").kind, EntryKind::Serial);
        assert_eq!(find(&i, "cam:reolink-1:name").kind, EntryKind::DisplayName);
        assert!(i.unknown_keys.is_empty(), "public keys are not unknown");
    }

    #[test]
    fn toml_unknown_keys_are_listed_by_name_only() {
        let t = toml_of(
            r#"
[cameras.tapo]
host = "nvr-1.example.invalid"
location = "12 Example Lane"
rtsp_path = "/stream1"
"#,
        );
        let i = map_inventory_toml(&t).unwrap();
        assert_eq!(entry_ids(&i), ["cam:tapo:host"]);
        assert_eq!(i.unknown_keys, ["tapo.location", "tapo.rtsp_path"]);
        assert!(!format!("{:?}", i.unknown_keys).contains("Example Lane"));
    }

    #[test]
    fn toml_section_names_that_are_not_valid_ids_become_ordinals() {
        let t = toml_of(
            r#"
[cameras."Front Gate 192.0.2.10"]
host = "192.0.2.10"
"#,
        );
        let i = map_inventory_toml(&t).unwrap();
        assert_eq!(entry_ids(&i), ["cam:import-1:host"]);
    }

    #[test]
    fn toml_mapped_fields_must_be_strings() {
        let t = toml_of(
            "[cameras.a]
host = 5
",
        );
        assert_eq!(map_inventory_toml(&t).unwrap_err(), LegacyError::NotAString);
    }

    #[test]
    fn toml_shape_errors() {
        assert_eq!(
            map_inventory_toml(&toml_of("x = 1")).unwrap_err(),
            LegacyError::NoCamerasTable
        );
        assert_eq!(
            map_inventory_toml(&toml_of(
                "[cameras]
a = 1"
            ))
            .unwrap_err(),
            LegacyError::NotAnObject
        );
    }

    #[test]
    fn mapped_entries_import_into_a_vault() {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            d.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let key = wardenlens_secrets::KeyFile::generate(&d.path().join("k")).unwrap();
        let mut v = crate::Vault::create(&d.path().join("v.db"), key).unwrap();
        let t =
            toml_of("[cameras.reolink-1]\nhost = \"192.0.2.10\"\nmac = \"02:00:5e:00:53:af\"\n");
        let j = json(r#"[{"name":"Front Gate","login":"svc-reader","password":"Tr0ub4dor-x9"}]"#);
        for imp in [
            map_inventory_toml(&t).unwrap(),
            map_secret_json(&j, &ids()).unwrap(),
        ] {
            for e in &imp.entries {
                v.set(&e.id, e.kind, &e.value, false).unwrap();
            }
        }
        let listed: Vec<String> = v.list().unwrap().iter().map(|e| e.id.to_string()).collect();
        assert_eq!(
            listed,
            [
                "cam:reolink-1:credential",
                "cam:reolink-1:host",
                "cam:reolink-1:mac",
                "cam:reolink-1:name"
            ]
        );
    }
}
