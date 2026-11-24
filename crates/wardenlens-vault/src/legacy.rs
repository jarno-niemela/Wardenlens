//! `import-legacy` mapping: pure functions from the parsed legacy files to entries.
//!
//! Every key is either imported or reported **by name** so the owner can classify it; nothing
//! is guessed and nothing is dropped silently (ADR 0006 section 4). Ids come from inventory ids
//! (or a per-file ordinal), never from a value (section 1). Reading the files is the CLI's job.
//!
//! **The CLI (#94) must import through [`map_legacy`]**, never by calling the two mappers and
//! storing both results: `Vault::set` is an upsert, so two files that produce the same entry id
//! (a JSON camera mapped to `tapo` and a `[cameras.tapo]` section both give `cam:tapo:name`)
//! would silently overwrite each other. [`map_legacy`] checks the union and refuses any overlap.
//!
//! An inventory id or section name starting with `import-` is reserved for ordinals: it falls
//! back to an ordinal id and is reported by name. The two files use distinct ordinal namespaces (`import-json-<n>` and `import-toml-<n>`), so
//! an unnamed camera of one file can never be merged with an unusable section of the other. A
//! duplicate entry id inside one mapping result is refused ([`LegacyError::DuplicateId`]); it is
//! never overwritten.

use std::collections::{BTreeMap, BTreeSet};

use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::Credentials;

use crate::store::Value;
use crate::validate::{check_credential, normalize_text};

/// Most cameras accepted from one legacy file (SEC-2).
pub const MAX_LEGACY_CAMERAS: usize = 256;
/// Most unknown or skipped keys reported; further ones only set `keys_truncated`.
pub const MAX_REPORTED_KEYS: usize = 1024;
/// Longest key name reported; longer names are cut.
const MAX_REPORTED_KEY_LEN: usize = 64;
/// The longest field suffix an inventory id must leave room for.
const LONGEST_FIELD: &str = "credential";
/// Ids starting with this are the ordinal fallbacks; real ids never use it.
const RESERVED_PREFIX: &str = "import-";

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
    /// Keys that were not imported, as `<inventory id>.<key>` (or the bare key for a top-level
    /// TOML key): unmapped keys, a `password` without a login, a `username` shadowed by a
    /// different `login`, and a `display_name` next to a `name`. Names only, never values;
    /// control and non-printable characters are escaped. At most [`MAX_REPORTED_KEYS`].
    pub unknown_keys: Vec<String>,
    /// True if more keys than [`MAX_REPORTED_KEYS`] were skipped and the list was cut.
    pub keys_truncated: bool,
}

impl LegacyImport {
    /// Combines two mapping results into one, for a single import.
    ///
    /// # Errors
    /// [`LegacyError::DuplicateId`] if any entry id occurs in both (or twice in either).
    /// Nothing is combined then; the second result never overwrites the first.
    pub fn merge(mut self, other: Self) -> Result<Self, LegacyError> {
        let mut taken = BTreeSet::new();
        for e in self.entries.iter().chain(other.entries.iter()) {
            if !taken.insert(e.id.as_str().to_owned()) {
                return Err(LegacyError::DuplicateId(e.id.to_string()));
            }
        }
        self.entries.extend(other.entries);
        self.keys_truncated |= other.keys_truncated;
        for key in other.unknown_keys {
            if self.unknown_keys.len() >= MAX_REPORTED_KEYS {
                self.keys_truncated = true;
                break;
            }
            self.unknown_keys.push(key);
        }
        Ok(self)
    }

    fn report(&mut self, inv: Option<&str>, key: &str) {
        if self.unknown_keys.len() >= MAX_REPORTED_KEYS {
            self.keys_truncated = true;
            return;
        }
        let cut = printable(key);
        self.unknown_keys.push(match inv {
            Some(inv) => format!("{inv}.{cut}"),
            None => cut,
        });
    }

    fn push(
        &mut self,
        taken: &mut BTreeSet<String>,
        inv: &str,
        field: &str,
        kind: EntryKind,
        value: Value,
    ) -> Result<(), LegacyError> {
        let id = entry_id(inv, field)?;
        if !taken.insert(id.as_str().to_owned()) {
            return Err(LegacyError::DuplicateId(id.to_string()));
        }
        self.entries.push(NewEntry { id, kind, value });
        Ok(())
    }
}

/// Why a legacy file could not be mapped. Never carries a value or a camera name; the only
/// text it holds is an entry id built from an inventory id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
    /// Two mapped fields would be stored under one entry id.
    #[error("entry id {0} would be written twice")]
    DuplicateId(String),
    /// An entry id could not be built (cannot happen for ids this module accepts).
    #[error("could not build an entry id")]
    InvalidId,
    /// The file lists more than 256 cameras.
    #[error("too many cameras")]
    TooMany,
}

/// Maps both legacy files for one import and refuses any entry id the two would share.
///
/// **This is the entry point the CLI (#94) must import through.** Either file may be absent.
///
/// # Errors
/// Any error of [`map_secret_json`] or [`map_inventory_toml`], and
/// [`LegacyError::DuplicateId`] if the two results overlap.
pub fn map_legacy(
    json: Option<&serde_json::Value>,
    names_to_ids: &BTreeMap<String, String>,
    toml: Option<&toml::Table>,
) -> Result<LegacyImport, LegacyError> {
    let j = json
        .map(|j| map_secret_json(j, names_to_ids))
        .transpose()?
        .unwrap_or_default();
    let t = toml
        .map(map_inventory_toml)
        .transpose()?
        .unwrap_or_default();
    j.merge(t)
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

fn entry_id(inv: &str, field: &str) -> Result<EntryId, LegacyError> {
    EntryId::new(&format!("cam:{inv}:{field}")).map_err(|_| LegacyError::InvalidId)
}

/// A usable inventory id for a section, else the ordinal fallback `import-<ns>-<n>` (1-based).
/// Usable means every field id, including the longest (`:credential`), fits the id rules, so
/// no field is ever dropped for length, and the id does not start with the reserved `import-`
/// prefix. The returned flag is true when a real candidate was refused for the prefix.
fn inventory_id(candidate: Option<&str>, namespace: &str, ordinal: usize) -> (String, bool) {
    match candidate {
        Some(c) if c.starts_with(RESERVED_PREFIX) => (ordinal_id(namespace, ordinal), true),
        Some(c) if entry_id(c, LONGEST_FIELD).is_ok() => (c.to_owned(), false),
        _ => (ordinal_id(namespace, ordinal), false),
    }
}

fn ordinal_id(namespace: &str, ordinal: usize) -> String {
    format!("{RESERVED_PREFIX}{namespace}-{}", ordinal.saturating_add(1))
}

/// True if the mapper may emit `value` for `kind`: the vault would accept it.
fn storable(kind: EntryKind, value: &str) -> bool {
    normalize_text(kind, value).is_ok()
}

/// A key name safe to print: cut to 64 characters, control and non-printable characters
/// escaped.
fn printable(key: &str) -> String {
    let mut out = String::new();
    for c in key.chars().take(MAX_REPORTED_KEY_LEN) {
        if c.escape_debug().count() == 1 || matches!(c, '\'' | '"') {
            out.push(c);
        } else {
            out.extend(c.escape_debug());
        }
    }
    out
}

fn text(s: &str) -> Value {
    Value::Text(SecretString::from(s.to_owned()))
}

/// Maps the `AgentDVR` secret file (a JSON array of camera objects).
///
/// Mapped: `name` (display name), `login` or `username`, and `password` (a credential entry).
/// `names_to_ids` maps a camera name to its inventory id; a camera not in it gets the ordinal id
/// `import-json-<n>`. A `password` without a login, and a `username` that differs from `login`,
/// are reported in `unknown_keys`, as is every other key.
///
/// # Errors
/// [`LegacyError`] for a wrongly shaped file, duplicate camera names or a duplicate entry id.
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
    let mut taken = BTreeSet::new();
    for (ordinal, camera) in cameras.iter().enumerate() {
        let obj = camera.as_object().ok_or(LegacyError::NotAnObject)?;
        let mut skipped: Vec<&str> = Vec::new();
        let name = string_field(obj.get("name"))?;
        if let Some(n) = name
            && !seen.insert(n.to_owned())
        {
            return Err(LegacyError::DuplicateName);
        }
        let name = name.filter(|n| {
            let ok = storable(EntryKind::DisplayName, n);
            if !ok {
                skipped.push("name");
            }
            ok
        });
        let mapped = name.and_then(|n| names_to_ids.get(n)).map(String::as_str);
        let (inv, renamed) = inventory_id(mapped, "json", ordinal);
        if renamed && let Some(m) = mapped {
            out.report(Some("cameras"), m);
        }
        let login = non_empty(string_field(obj.get("login"))?, "login", &mut skipped);
        let username = non_empty(string_field(obj.get("username"))?, "username", &mut skipped);
        let password = string_field(obj.get("password"))?;
        let account = login
            .map(|l| (l, "login"))
            .or(username.map(|u| (u, "username")));
        if let Some(n) = name {
            out.push(&mut taken, &inv, "name", EntryKind::DisplayName, text(n))?;
        }
        match (account, password) {
            (Some((account, key)), password) => {
                let password = password.unwrap_or_default();
                if check_credential(account, password).is_ok() {
                    out.push(
                        &mut taken,
                        &inv,
                        "credential",
                        EntryKind::Credential,
                        Value::Credential(Credentials::new(account, password)),
                    )?;
                } else {
                    skipped.push(key);
                }
            }
            (None, Some(_)) => out.report(Some(&inv), "password"),
            (None, None) => {}
        }
        if let (Some(l), Some(u)) = (login, username)
            && l != u
        {
            out.report(Some(&inv), "username");
        }
        for key in skipped {
            out.report(Some(&inv), key);
        }
        for key in obj.keys() {
            if !matches!(key.as_str(), "name" | "login" | "username" | "password") {
                out.report(Some(&inv), key);
            }
        }
    }
    Ok(out)
}

/// An empty string is the same as an absent field; its key is reported by name.
fn non_empty<'a>(
    v: Option<&'a str>,
    key: &'static str,
    skipped: &mut Vec<&'static str>,
) -> Option<&'a str> {
    match v {
        Some("") => {
            skipped.push(key);
            None
        }
        other => other,
    }
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
/// Mapped: `host`, `mac`, `serial` and `name` (or `display_name`; when both are present `name`
/// is imported and `display_name` is reported). Public configuration keys (vendor, model,
/// ports) are skipped; anything else, including top-level keys outside `[cameras]`, is listed
/// in `unknown_keys`. The section name is the inventory id; an unusable one falls back to the
/// ordinal id `import-toml-<n>`.
///
/// # Errors
/// [`LegacyError`] for a wrongly shaped file or a duplicate entry id.
pub fn map_inventory_toml(table: &toml::Table) -> Result<LegacyImport, LegacyError> {
    let cameras = table
        .get("cameras")
        .and_then(toml::Value::as_table)
        .ok_or(LegacyError::NoCamerasTable)?;
    if cameras.len() > MAX_LEGACY_CAMERAS {
        return Err(LegacyError::TooMany);
    }
    let mut out = LegacyImport::default();
    let mut taken = BTreeSet::new();
    for key in table.keys().filter(|k| k.as_str() != "cameras") {
        out.report(None, key);
    }
    for (ordinal, (section, camera)) in cameras.iter().enumerate() {
        let obj = camera.as_table().ok_or(LegacyError::NotAnObject)?;
        let (inv, renamed) = inventory_id(Some(section), "toml", ordinal);
        if renamed {
            out.report(Some("cameras"), section);
        }
        for (key, value) in obj {
            let (kind, field) = match key.as_str() {
                "host" => (EntryKind::Host, "host"),
                "mac" => (EntryKind::Mac, "mac"),
                "serial" => (EntryKind::Serial, "serial"),
                "name" => (EntryKind::DisplayName, "name"),
                "display_name" if !obj.contains_key("name") => (EntryKind::DisplayName, "name"),
                k if PUBLIC_TOML_KEYS.contains(&k) => continue,
                k => {
                    out.report(Some(&inv), k);
                    continue;
                }
            };
            let s = value.as_str().ok_or(LegacyError::NotAString)?;
            if storable(kind, s) {
                out.push(&mut taken, &inv, field, kind, text(s))?;
            } else {
                out.report(Some(&inv), key);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::Scan;

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
                "cam:import-json-1:name",
                "cam:import-json-1:credential",
                "cam:import-json-2:name",
                "cam:import-json-2:credential"
            ]
        );
    }

    #[test]
    fn json_without_a_name_still_imports_the_credential() {
        let v = json(r#"[{"login":"u","password":"p"}]"#);
        let i = map_secret_json(&v, &ids()).unwrap();
        assert_eq!(entry_ids(&i), ["cam:import-json-1:credential"]);
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
        assert_eq!(i.unknown_keys, ["tapo.password"]);
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
    fn json_inventory_id_collision_is_refused() {
        let m = BTreeMap::from([
            ("A".to_owned(), "same".to_owned()),
            ("B".to_owned(), "same".to_owned()),
        ]);
        let v = json(
            r#"[{"name":"A","login":"u","password":"p"},{"name":"B","login":"u","password":"p"}]"#,
        );
        assert_eq!(
            map_secret_json(&v, &m).unwrap_err(),
            LegacyError::DuplicateId("cam:same:name".to_owned())
        );
    }

    #[test]
    fn json_real_id_with_the_reserved_prefix_becomes_an_ordinal_and_is_reported() {
        let m = BTreeMap::from([("A".to_owned(), "import-json-2".to_owned())]);
        let v = json(r#"[{"name":"A","login":"u","password":"p"},{"login":"v","password":"q"}]"#);
        let i = map_secret_json(&v, &m).unwrap();
        assert_eq!(
            entry_ids(&i),
            [
                "cam:import-json-1:name",
                "cam:import-json-1:credential",
                "cam:import-json-2:credential"
            ]
        );
        assert_eq!(i.unknown_keys, ["cameras.import-json-2"]);
    }

    #[test]
    fn toml_section_with_the_reserved_prefix_becomes_an_ordinal_and_is_reported() {
        let t = toml_of(
            "[cameras.\"Front Gate\"]\nhost = \"192.0.2.10\"\n[cameras.import-toml-1]\nhost = \"192.0.2.11\"\n",
        );
        let i = map_inventory_toml(&t).unwrap();
        assert_eq!(
            entry_ids(&i),
            ["cam:import-toml-1:host", "cam:import-toml-2:host"]
        );
        assert_eq!(i.unknown_keys, ["cameras.import-toml-1"]);
    }

    #[test]
    fn map_legacy_refuses_ids_shared_by_the_two_files() {
        let t = toml_of("[cameras.tapo]\nname = \"Garage Side\"\n");
        let j = json(r#"[{"name":"Garage","login":"u","password":"p"}]"#);
        assert_eq!(
            map_legacy(Some(&j), &ids(), Some(&t)).unwrap_err(),
            LegacyError::DuplicateId("cam:tapo:name".to_owned())
        );
    }

    #[test]
    fn map_legacy_with_a_section_named_like_an_ordinal_collides_with_nothing() {
        let t = toml_of("[cameras.import-json-1]\nname = \"Back Door North\"\n");
        let j = json(r#"[{"name":"Front Gate","login":"svc-reader","password":"x"}]"#);
        let i = map_legacy(Some(&j), &BTreeMap::new(), Some(&t)).unwrap();
        let mut seen = BTreeSet::new();
        for e in &i.entries {
            assert!(seen.insert(e.id.as_str()), "duplicate {}", e.id);
        }
    }

    #[test]
    fn map_legacy_combines_and_bounds_the_reports() {
        let big = |n: usize| {
            let mut obj = serde_json::Map::new();
            for k in 0..n {
                obj.insert(format!("k{k}"), serde_json::Value::Null);
            }
            serde_json::Value::Array(vec![serde_json::Value::Object(obj)])
        };
        let j = big(MAX_REPORTED_KEYS - 1);
        let t = toml_of("[site]\na = 1\n[other]\nb = 2\n[cameras.a]\nhost = \"192.0.2.10\"\n");
        let i = map_legacy(Some(&j), &ids(), Some(&t)).unwrap();
        assert_eq!(i.unknown_keys.len(), MAX_REPORTED_KEYS);
        assert!(i.keys_truncated);
        assert_eq!(entry_ids(&i), ["cam:a:host"]);
        let none = map_legacy(None, &ids(), None).unwrap();
        assert!(none.entries.is_empty() && !none.keys_truncated);
    }

    #[test]
    fn empty_fields_are_absent_and_reported_by_name() {
        let v = json(r#"[{"name":"","login":"","username":"svc-reader","password":"p"}]"#);
        let i = map_secret_json(&v, &BTreeMap::new()).unwrap();
        assert_eq!(entry_ids(&i), ["cam:import-json-1:credential"]);
        assert_eq!(
            i.unknown_keys,
            ["import-json-1.name", "import-json-1.login"]
        );
        let t = toml_of("[cameras.a]\nhost = \"\"\n");
        let i = map_inventory_toml(&t).unwrap();
        assert!(i.entries.is_empty());
        assert_eq!(i.unknown_keys, ["a.host"]);
    }

    #[test]
    fn ordinals_of_the_two_files_are_distinct() {
        let j = map_secret_json(&json(r#"[{"login":"u","password":"p"}]"#), &ids()).unwrap();
        let t = map_inventory_toml(&toml_of("[cameras.\"A B\"]\nhost = \"192.0.2.10\"\n")).unwrap();
        assert_ne!(
            entry_ids(&j)[0].split(':').nth(1),
            entry_ids(&t)[0].split(':').nth(1)
        );
    }

    #[test]
    fn json_skipped_fields_are_reported() {
        let v = json(
            r#"[{"name":"Garage","login":"a","username":"b","password":"p"},{"name":"Front Gate","username":"u2"}]"#,
        );
        let i = map_secret_json(&v, &ids()).unwrap();
        assert_eq!(i.unknown_keys, ["tapo.username"]);
        // `username` alone is taken as the login.
        assert!(entry_ids(&i).contains(&"cam:reolink-1:credential"));
        // Equal login and username: nothing to report.
        let v = json(r#"[{"login":"a","username":"a"}]"#);
        let quiet = map_secret_json(&v, &ids()).unwrap();
        assert_eq!(quiet.unknown_keys.len(), 0);
    }

    #[test]
    fn toml_name_and_display_name_together_report_the_second() {
        let t = toml_of("[cameras.a]\nname = \"Back Door\"\ndisplay_name = \"Rear\"\n");
        let i = map_inventory_toml(&t).unwrap();
        assert_eq!(entry_ids(&i), ["cam:a:name"]);
        assert_eq!(i.unknown_keys, ["a.display_name"]);
        let t = toml_of("[cameras.a]\ndisplay_name = \"Back Door\"\n");
        assert_eq!(entry_ids(&map_inventory_toml(&t).unwrap()), ["cam:a:name"]);
    }

    #[test]
    fn toml_top_level_keys_are_reported_by_name() {
        let t =
            toml_of("[site]\naddress = \"12 Example Lane\"\n[cameras.a]\nhost = \"192.0.2.10\"\n");
        let i = map_inventory_toml(&t).unwrap();
        assert_eq!(i.unknown_keys, ["site"]);
    }

    #[test]
    fn inventory_ids_leave_room_for_the_longest_field() {
        // `cam:` + 113 + `:credential` = 128 bytes.
        let fits = "a".repeat(113);
        let m = BTreeMap::from([("G".to_owned(), fits.clone())]);
        let v = json(r#"[{"name":"G","login":"u","password":"p"}]"#);
        let i = map_secret_json(&v, &m).unwrap();
        assert!(entry_ids(&i).contains(&format!("cam:{fits}:credential").as_str()));
        let long = "a".repeat(114);
        let m = BTreeMap::from([("G".to_owned(), long)]);
        let i = map_secret_json(&v, &m).unwrap();
        assert!(entry_ids(&i).contains(&"cam:import-json-1:credential"));
    }

    #[test]
    fn reported_key_names_are_escaped_and_capped() {
        let v = json("[{\"name\":\"Garage\",\"x\\u001b[2J\\ny\":1}]");
        let i = map_secret_json(&v, &ids()).unwrap();
        assert!(
            i.unknown_keys
                .iter()
                .all(|k| !k.chars().any(char::is_control))
        );
        let mut obj = serde_json::Map::new();
        for n in 0..(MAX_REPORTED_KEYS + 5) {
            obj.insert(format!("k{n}"), serde_json::Value::Null);
        }
        let v = serde_json::Value::Array(vec![serde_json::Value::Object(obj)]);
        let i = map_secret_json(&v, &ids()).unwrap();
        assert_eq!(i.unknown_keys.len(), MAX_REPORTED_KEYS);
        assert!(i.keys_truncated);
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
        assert_eq!(entry_ids(&i), ["cam:import-toml-1:host"]);
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
                v.set(&e.id, e.kind, &e.value, Scan::Normal).unwrap();
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
