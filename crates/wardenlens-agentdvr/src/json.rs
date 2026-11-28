//! The JSON reader: `objects.json` in, [`RawCamera`] out, with the same limits and the same login
//! collection as the XML walk (see `document`). Everything after this (the camera rules, the ids,
//! the duplicate-name check) is shared with XML, so the two formats cannot drift.
//!
//! # The layout (an assumption, for the owner to check against a real file locally)
//!
//! The JSON mirrors the XML layout field for field. The real `AgentDVR` JSON schema is not
//! documented publicly and no real file was read to write this; the names below are the XML
//! importer's, in JSON form. A file with another layout is refused (`NotObjects`) or yields cameras
//! that are skipped (`MissingName`, `NoSource`); nothing is guessed.
//!
//! ```text
//! { "cameras": [
//!     { "id": 1, "name": "Porch", "deleted": false,
//!       "settings": { "videosourcestring": "rtsp://host/path", "login": "user", "password": "secret" } }
//! ] }
//! ```
//!
//! Names are exact and case-sensitive at exactly these paths; every other member, at any depth, is
//! ignored (and never collected as a login, as in XML).
//!
//! * `id`: a number or a string of digits that fits `u32`; anything else is no id (the position id
//!   is used). `name`: a string; anything else is `MissingName`. `deleted`: `true`, `"true"`, `"1"`
//!   or `1`; anything else is not deleted (as in XML).
//! * `videosourcestring`, `login`, `password`: a string, or `null` (absent). A number, a boolean,
//!   an array or an object there refuses the whole document ([`ImportError::FieldNotText`]):
//!   a value that is not collected as a login could leak into a path.
//! * A repeated member of the same object (two `settings`, two `login`) refuses the whole
//!   document: the JSON text has two meanings and which one a reader keeps differs. (XML skips the
//!   one camera; the stricter refusal is fail-closed.)
//!
//! # Limits
//!
//! Size is checked by the caller's [`crate::MAX_INPUT_BYTES`] before any parsing; depth
//! ([`crate::MAX_DEPTH`], the root object is depth 1) is checked by a string-aware scan before the
//! parser runs, so the parser never recurses past it; cameras are counted as the array is read
//! ([`crate::MAX_CAMERAS`]). No error carries input text: a parser message is never forwarded.
//!
//! **Memory.** Field texts are copied into `Zeroizing` buffers at once. The JSON parser itself may
//! hold an unescaped copy of a string that contains an escape (`é`) in a scratch buffer that is
//! freed, not wiped; a string without an escape is read in place from the (zeroised) input.

use std::collections::HashSet;
use std::fmt;

use secrecy::zeroize::Zeroizing;
use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::document::{Field, RawCamera, Slot, collect_field};
use crate::logins::Secret;
use crate::{ImportError, Logins, MAX_CAMERAS, MAX_DEPTH, MAX_FIELD_BYTES};

/// Custom serde error texts that this module turns back into typed errors. A serde message that
/// echoes input starts with something else (`invalid type: ...`), so no input can forge these.
const TOO_MANY_CAMERAS: &str = "wardenlens:too-many-cameras";

/// One text member: absent (missing or `null`), a string, or a value that is not text.
#[derive(Default)]
enum Text {
    #[default]
    Absent,
    Str(Zeroizing<String>),
    Other,
}

struct TextVisitor;

impl<'de> Visitor<'de> for TextVisitor {
    type Value = Text;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Text, E> {
        Ok(Text::Str(Zeroizing::new(v.to_owned())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Text, E> {
        Ok(Text::Str(Zeroizing::new(v)))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Text, E> {
        Ok(Text::Absent)
    }
    fn visit_none<E: de::Error>(self) -> Result<Text, E> {
        Ok(Text::Absent)
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Text, E> {
        Ok(Text::Other)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Text, E> {
        Ok(Text::Other)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Text, E> {
        Ok(Text::Other)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Text, E> {
        Ok(Text::Other)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Text, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Text::Other)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Text, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Text::Other)
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(TextVisitor)
    }
}

/// A non-secret scalar member (`id`, `name`, `deleted`) of any JSON type.
#[derive(Default)]
enum Loose {
    #[default]
    Absent,
    Str(String),
    Num(u64),
    Bool(bool),
    Other,
}

struct LooseVisitor;

impl<'de> Visitor<'de> for LooseVisitor {
    type Value = Loose;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a scalar")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Loose, E> {
        Ok(Loose::Str(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Loose, E> {
        Ok(Loose::Str(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Loose, E> {
        Ok(Loose::Absent)
    }
    fn visit_none<E: de::Error>(self) -> Result<Loose, E> {
        Ok(Loose::Absent)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Loose, E> {
        Ok(Loose::Bool(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Loose, E> {
        Ok(Loose::Num(v))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Loose, E> {
        Ok(Loose::Other)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Loose, E> {
        Ok(Loose::Other)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Loose, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Loose::Other)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Loose, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Loose::Other)
    }
}

impl<'de> Deserialize<'de> for Loose {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(LooseVisitor)
    }
}

/// The keys of the objects this reader looks at; any other key is `Other` and its value is
/// skipped. Exact and case-sensitive.
#[derive(Deserialize)]
enum Key {
    #[serde(rename = "cameras")]
    Cameras,
    #[serde(rename = "id")]
    Id,
    #[serde(rename = "name")]
    Name,
    #[serde(rename = "deleted")]
    Deleted,
    #[serde(rename = "settings")]
    Settings,
    #[serde(rename = "videosourcestring")]
    Source,
    #[serde(rename = "login")]
    Login,
    #[serde(rename = "password")]
    Password,
    #[serde(other)]
    Other,
}

/// Stores `value` in `slot`; a second value for the same key is an error (see the module docs).
fn put<T, E: de::Error>(slot: &mut Option<T>, value: T, key: &'static str) -> Result<(), E> {
    if slot.replace(value).is_some() {
        return Err(E::duplicate_field(key));
    }
    Ok(())
}

/// Reads the value of an unwanted key.
fn skip<'de, A: MapAccess<'de>>(map: &mut A) -> Result<(), A::Error> {
    map.next_value::<IgnoredAny>().map(|_| ())
}

#[derive(Default)]
struct SettingsJson {
    videosourcestring: Text,
    login: Text,
    password: Text,
}

struct SettingsVisitor;

impl<'de> Visitor<'de> for SettingsVisitor {
    type Value = SettingsJson;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SettingsJson, A::Error> {
        let (mut source, mut login, mut password) = (None, None, None);
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Source => put(&mut source, map.next_value()?, "videosourcestring")?,
                Key::Login => put(&mut login, map.next_value()?, "login")?,
                Key::Password => put(&mut password, map.next_value()?, "password")?,
                _ => skip(&mut map)?,
            }
        }
        Ok(SettingsJson {
            videosourcestring: source.unwrap_or_default(),
            login: login.unwrap_or_default(),
            password: password.unwrap_or_default(),
        })
    }
}

impl<'de> Deserialize<'de> for SettingsJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(SettingsVisitor)
    }
}

#[derive(Default)]
struct CameraJson {
    id: Loose,
    name: Loose,
    deleted: Loose,
    settings: Option<SettingsJson>,
}

struct CameraVisitor;

impl<'de> Visitor<'de> for CameraVisitor {
    type Value = CameraJson;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }
    /// A `null` entry is a camera with nothing in it (skipped as nameless), not a refusal.
    fn visit_unit<E: de::Error>(self) -> Result<CameraJson, E> {
        Ok(CameraJson::default())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<CameraJson, A::Error> {
        let (mut id, mut name, mut deleted) = (None, None, None);
        let mut settings: Option<Option<SettingsJson>> = None;
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Id => put(&mut id, map.next_value()?, "id")?,
                Key::Name => put(&mut name, map.next_value()?, "name")?,
                Key::Deleted => put(&mut deleted, map.next_value()?, "deleted")?,
                Key::Settings => put(&mut settings, map.next_value()?, "settings")?,
                _ => skip(&mut map)?,
            }
        }
        Ok(CameraJson {
            id: id.unwrap_or_default(),
            name: name.unwrap_or_default(),
            deleted: deleted.unwrap_or_default(),
            settings: settings.flatten(),
        })
    }
}

impl<'de> Deserialize<'de> for CameraJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(CameraVisitor)
    }
}

/// The `cameras` array, cut off at [`MAX_CAMERAS`] while it is read.
struct Cameras(Vec<CameraJson>);

struct CamerasVisitor;

impl<'de> Visitor<'de> for CamerasVisitor {
    type Value = Cameras;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Cameras, A::Error> {
        let mut all = Vec::new();
        while let Some(c) = seq.next_element::<CameraJson>()? {
            if all.len() >= MAX_CAMERAS {
                return Err(de::Error::custom(TOO_MANY_CAMERAS));
            }
            all.push(c);
        }
        Ok(Cameras(all))
    }
}

impl<'de> Deserialize<'de> for Cameras {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_seq(CamerasVisitor)
    }
}

/// The root object: only its `cameras` member matters.
struct Root {
    cameras: Option<Cameras>,
}

struct RootVisitor;

impl<'de> Visitor<'de> for RootVisitor {
    type Value = Root;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Root, A::Error> {
        let mut cameras: Option<Option<Cameras>> = None;
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Cameras => put(&mut cameras, map.next_value()?, "cameras")?,
                _ => skip(&mut map)?,
            }
        }
        Ok(Root {
            cameras: cameras.flatten(),
        })
    }
}

impl<'de> Deserialize<'de> for Root {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(RootVisitor)
    }
}

/// Refuses a document that does not start with `{` ([`ImportError::NotObjects`]) or nests deeper
/// than [`MAX_DEPTH`] ([`ImportError::TooDeep`]), before the parser sees it. String-aware: a
/// bracket inside a string does not count, and an escaped quote does not end the string.
fn check_depth(text: &str) -> Result<(), ImportError> {
    let bytes = text.as_bytes();
    let first = bytes
        .iter()
        .copied()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
    if first != Some(b'{') {
        return Err(ImportError::NotObjects);
    }
    let (mut depth, mut in_string, mut escaped) = (0_usize, false, false);
    for &b in bytes {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > MAX_DEPTH {
                    return Err(ImportError::TooDeep);
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// Reads the cameras of `text` (UTF-8, BOM already removed).
pub(crate) fn read(text: &str) -> Result<(Vec<RawCamera>, Logins), ImportError> {
    check_depth(text)?;
    let root: Root = serde_json::from_str(text).map_err(|e| match e.classify() {
        serde_json::error::Category::Data => {
            if e.to_string().starts_with(TOO_MANY_CAMERAS) {
                ImportError::TooManyCameras
            } else {
                ImportError::NotObjects
            }
        }
        _ => ImportError::MalformedJson {
            line: e.line(),
            column: e.column(),
        },
    })?;
    let Some(Cameras(cameras)) = root.cameras else {
        return Err(ImportError::NotObjects);
    };
    let mut logins = Logins::default();
    let mut seen_fields: HashSet<Secret> = HashSet::new();
    let mut seen_sources: HashSet<Secret> = HashSet::new();
    let mut raws = Vec::with_capacity(cameras.len());
    for (position, c) in cameras.into_iter().enumerate() {
        let mut raw = RawCamera {
            position,
            ..RawCamera::default()
        };
        raw.agent_id = match c.id {
            Loose::Num(n) => u32::try_from(n).ok(),
            Loose::Str(s) => s.parse::<u32>().ok(),
            _ => None,
        };
        raw.name = match c.name {
            Loose::Str(s) => Some(s),
            _ => None,
        };
        raw.deleted = match c.deleted {
            Loose::Bool(b) => b,
            Loose::Str(s) => s.eq_ignore_ascii_case("true") || s == "1",
            Loose::Num(n) => n == 1,
            _ => false,
        };
        if let Some(s) = c.settings {
            raw.settings_count = 1;
            for (slot, field, text) in [
                (&mut raw.source, Field::Source, s.videosourcestring),
                (&mut raw.login, Field::Login, s.login),
                (&mut raw.password, Field::Password, s.password),
            ] {
                fill(
                    slot,
                    field,
                    text,
                    &mut logins,
                    &mut seen_fields,
                    &mut seen_sources,
                )?;
            }
        }
        raws.push(raw);
    }
    Ok((raws, logins))
}

/// Collects the whole text for the logins, then keeps it in the slot unless it is over the field
/// limit (then the slot only says so, as in XML).
fn fill(
    slot: &mut Slot,
    field: Field,
    text: Text,
    logins: &mut Logins,
    seen_fields: &mut HashSet<Secret>,
    seen_sources: &mut HashSet<Secret>,
) -> Result<(), ImportError> {
    match text {
        Text::Absent => Ok(()),
        Text::Other => Err(ImportError::FieldNotText),
        Text::Str(s) => {
            collect_field(logins, seen_fields, seen_sources, field, &s)?;
            slot.count = 1;
            if s.len() > MAX_FIELD_BYTES {
                slot.too_long = true;
            } else {
                slot.text = Some(s);
            }
            Ok(())
        }
    }
}
