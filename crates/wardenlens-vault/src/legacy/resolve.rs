//! Joins each legacy JSON camera to an inventory id (#188).
//!
//! The `AgentDVR` JSON has no host and no id: its display name is the only link to the
//! inventory. Matching is generic and deterministic, and never guesses:
//!
//! 1. `--map <index>=<id>` decides a camera outright.
//! 2. Otherwise the display name is compared, case-insensitively (Unicode lower-casing after the
//!    vault's own white-space and invisible-character clean-up), with every usable inventory
//!    camera. An **exact** match (the whole name equals the id or the inventory `name`) beats a
//!    **token** match (the id, the `vendor` or the `model`, as whole words, occurs in the name;
//!    the one with more words wins). Substrings inside a word never match.
//! 3. A best score reached by two or more cameras is [`Row::Ambiguous`]; no score at all is
//!    [`Row::NoMatch`]. Both make [`Resolution::into_ids`] fail; neither falls back to a guess.
//!
//! Indexes count from 1, like the `import-json-<n>` ids. Nothing here prints or returns a name,
//! a host or a login: reports carry indexes and inventory ids only. Inventory section names
//! reach reports only through the key-name escaper and only if they are usable ids.

use std::collections::BTreeMap;

use wardenlens_core::camera::is_combining_mark;

use super::{LegacyError, MAX_LEGACY_CAMERAS, inventory_id, printable, string_field};
use crate::validate::display_name_text;

/// Most candidate ids named in one ambiguity report.
const MAX_LISTED_IDS: usize = 8;
/// Most words of a display name that are compared; a longer name matches nothing.
const MAX_NAME_WORDS: usize = 64;

/// How a camera got its id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Basis {
    /// `--map`.
    Explicit,
    /// The whole name equals the id or the inventory name.
    Exact,
    /// The id, vendor or model occurs in the name as whole words.
    Token,
}

/// The outcome for one JSON camera.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Row {
    /// One inventory id.
    Mapped {
        /// The inventory id.
        id: String,
        /// Why.
        basis: Basis,
    },
    /// Nothing in the inventory matches.
    NoMatch,
    /// Several inventory ids match equally well (sorted).
    Ambiguous(Vec<String>),
}

/// One row per JSON camera, in file order (`rows()[0]` is index 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    rows: Vec<Row>,
}

impl Resolution {
    /// The rows, for a report.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// Checks that every camera has its own id.
    ///
    /// # Errors
    /// [`LegacyError::Unresolved`] if any camera is unmatched or ambiguous, else
    /// [`LegacyError::SharedId`] if two cameras got one id (any mix of explicit and matched).
    pub fn check(&self) -> Result<(), LegacyError> {
        let mut missing = Vec::new();
        let mut ambiguous = Vec::new();
        let mut by_id: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (i, row) in self.rows.iter().enumerate() {
            let index = i.saturating_add(1);
            match row {
                Row::NoMatch => missing.push(index),
                Row::Ambiguous(ids) => ambiguous.push((index, ids.clone())),
                Row::Mapped { id, .. } => by_id.entry(id).or_default().push(index),
            }
        }
        if !missing.is_empty() || !ambiguous.is_empty() {
            return Err(LegacyError::Unresolved { missing, ambiguous });
        }
        let shared: Vec<(String, Vec<usize>)> = by_id
            .into_iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(id, v)| (id.to_owned(), v))
            .collect();
        if shared.is_empty() {
            Ok(())
        } else {
            Err(LegacyError::SharedId(shared))
        }
    }

    /// The id of every camera, after [`Resolution::check`].
    ///
    /// # Errors
    /// As [`Resolution::check`].
    pub fn into_ids(self) -> Result<Vec<String>, LegacyError> {
        self.check()?;
        Ok(self
            .rows
            .into_iter()
            .filter_map(|r| match r {
                Row::Mapped { id, .. } => Some(id),
                _ => None,
            })
            .collect())
    }
}

/// An inventory camera as the matcher sees it.
struct Candidate {
    id: String,
    /// Folded whole names that count as an exact match: the id and the inventory name(s).
    exact: Vec<String>,
    /// Word sequences that count as a token match: the id, the vendor, the model.
    words: Vec<Vec<String>>,
}

fn fold(raw: &str) -> String {
    display_name_text(raw).to_lowercase()
}

/// Words are runs of letters, digits and combining marks: a mark never splits a word, so the
/// composed and decomposed spellings of one name give the same words.
fn words(folded: &str) -> Vec<String> {
    folded
        .split(|c: char| !(c.is_alphanumeric() || is_combining_mark(c)))
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

fn candidates(table: Option<&toml::Table>) -> Vec<Candidate> {
    let Some(cameras) = table
        .and_then(|t| t.get("cameras"))
        .and_then(toml::Value::as_table)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, (section, camera)) in cameras.iter().enumerate() {
        // Only an id the importer would really use: the others get an `import-toml-<n>` id.
        let (id, refused) = inventory_id(Some(section), "toml", i);
        if refused {
            continue;
        }
        let field = |key: &str| {
            camera
                .as_table()
                .and_then(|c| c.get(key))
                .and_then(toml::Value::as_str)
                .map(fold)
        };
        let mut exact = vec![fold(&id)];
        exact.extend(field("name"));
        exact.extend(field("display_name"));
        let mut word_lists = vec![words(&fold(&id))];
        word_lists.extend(field("vendor").map(|v| words(&v)));
        word_lists.extend(field("model").map(|m| words(&m)));
        exact.retain(|e| !e.is_empty());
        word_lists.retain(|w| !w.is_empty());
        out.push(Candidate {
            id,
            exact,
            words: word_lists,
        });
    }
    out
}

fn contains_run(haystack: &[String], needle: &[String]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Exact is `(2, 0)`; a token match is `(1, number of words)`; no match is `None`.
fn score(name: &str, name_words: &[String], c: &Candidate) -> Option<(u8, usize)> {
    if c.exact.iter().any(|e| e == name) {
        return Some((2, 0));
    }
    c.words
        .iter()
        .filter(|w| contains_run(name_words, w))
        .map(|w| (1, w.len()))
        .max()
}

/// Decides the inventory id of every JSON camera. `explicit` is the `--map` list
/// (`(index, id)`, indexes from 1). `table` is the parsed inventory, if any.
///
/// # Errors
/// [`LegacyError::NotAnArray`], [`LegacyError::NotAnObject`], [`LegacyError::NotAString`],
/// [`LegacyError::TooMany`] for a wrongly shaped file;
/// [`LegacyError::MapDuplicateIndex`], [`LegacyError::MapIndexOutOfRange`] and
/// [`LegacyError::MapUnknownId`] for a bad `--map`. Unmatched and ambiguous cameras are not
/// errors here: they are rows, so a dry run can show them (see [`Resolution::check`]).
pub fn resolve_ids(
    json: &serde_json::Value,
    table: Option<&toml::Table>,
    explicit: &[(usize, String)],
) -> Result<Resolution, LegacyError> {
    let cameras = json.as_array().ok_or(LegacyError::NotAnArray)?;
    if cameras.len() > MAX_LEGACY_CAMERAS {
        return Err(LegacyError::TooMany);
    }
    if table
        .and_then(|t| t.get("cameras"))
        .and_then(toml::Value::as_table)
        .is_some_and(|c| c.len() > MAX_LEGACY_CAMERAS)
    {
        return Err(LegacyError::TooMany);
    }
    let inventory = candidates(table);
    let mut chosen: BTreeMap<usize, &str> = BTreeMap::new();
    for (index, id) in explicit {
        if *index == 0 || *index > cameras.len() {
            return Err(LegacyError::MapIndexOutOfRange);
        }
        if !inventory.iter().any(|c| &c.id == id) {
            return Err(LegacyError::MapUnknownId);
        }
        if chosen.insert(*index, id).is_some() {
            return Err(LegacyError::MapDuplicateIndex);
        }
    }
    let mut rows = Vec::with_capacity(cameras.len());
    for (i, camera) in cameras.iter().enumerate() {
        let obj = camera.as_object().ok_or(LegacyError::NotAnObject)?;
        let name = string_field(obj.get("name"))?;
        if let Some(id) = chosen.get(&i.saturating_add(1)) {
            rows.push(Row::Mapped {
                id: (*id).to_owned(),
                basis: Basis::Explicit,
            });
            continue;
        }
        let folded = name.map_or_default(fold);
        let name_words = words(&folded);
        // A name of absurd length is not a camera name: no match, and no work for the scorer.
        let folded = if name_words.len() > MAX_NAME_WORDS {
            String::new()
        } else {
            folded
        };
        let scored: Vec<((u8, usize), &Candidate)> = inventory
            .iter()
            .filter(|_| !folded.is_empty())
            .filter_map(|c| score(&folded, &name_words, c).map(|s| (s, c)))
            .collect();
        let best = scored.iter().map(|(s, _)| *s).max();
        let mut top: Vec<&str> = scored
            .iter()
            .filter(|(s, _)| Some(*s) == best)
            .map(|(_, c)| c.id.as_str())
            .collect();
        top.sort_unstable();
        rows.push(match (best, top.as_slice()) {
            (Some((tier, _)), [only]) => Row::Mapped {
                id: (*only).to_owned(),
                basis: if tier == 2 {
                    Basis::Exact
                } else {
                    Basis::Token
                },
            },
            (Some(_), _) => Row::Ambiguous(top.iter().map(|s| (*s).to_owned()).collect()),
            (None, _) => Row::NoMatch,
        });
    }
    Ok(Resolution { rows })
}

fn list_ids(ids: &[String]) -> String {
    let mut shown: Vec<String> = ids
        .iter()
        .take(MAX_LISTED_IDS)
        .map(|i| printable(i))
        .collect();
    if ids.len() > MAX_LISTED_IDS {
        shown.push(format!(
            "and {} more",
            ids.len().saturating_sub(MAX_LISTED_IDS)
        ));
    }
    shown.join(", ")
}

fn list_indexes(indexes: &[usize]) -> String {
    indexes
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Text of [`LegacyError::Unresolved`]: indexes and ids only.
pub(super) fn unresolved_text(missing: &[usize], ambiguous: &[(usize, Vec<String>)]) -> String {
    let mut parts = vec![String::from("cannot join every camera to an inventory id")];
    if !missing.is_empty() {
        parts.push(format!(
            "no match for camera index {}",
            list_indexes(missing)
        ));
    }
    for (index, ids) in ambiguous {
        parts.push(format!(
            "camera index {index} matches several ids equally ({})",
            list_ids(ids)
        ));
    }
    if !missing.is_empty() {
        parts.push(String::from(
            "each JSON camera needs a [cameras.<id>] section in the inventory, and --map can only name an id that has one",
        ));
    }
    parts.push(String::from("map each with --map <index>=<id>"));
    parts.join("; ")
}

/// Text of [`LegacyError::SharedId`]: indexes and ids only.
pub(super) fn shared_text(shared: &[(String, Vec<usize>)]) -> String {
    let parts: Vec<String> = shared
        .iter()
        .map(|(id, idx)| {
            format!(
                "camera indexes {} both map to id {}",
                list_indexes(idx),
                printable(id)
            )
        })
        .collect();
    format!("two cameras cannot share an id: {}", parts.join("; "))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn table(s: &str) -> toml::Table {
        toml::from_str(s).unwrap()
    }

    fn json(names: &[&str]) -> serde_json::Value {
        serde_json::Value::Array(
            names
                .iter()
                .map(|n| serde_json::json!({ "name": n, "login": "u", "password": "pw-synthetic-9" }))
                .collect(),
        )
    }

    const INV: &str = r#"
[cameras.alpha-1]
vendor = "Acme"
model = "C200"
host = "192.0.2.10"
[cameras.beta-2]
vendor = "Bolt"
model = "RLC-810A"
name = "Back Door"
host = "192.0.2.11"
[cameras.beta-3]
vendor = "Bolt"
model = "RLC-810A"
host = "192.0.2.12"
"#;

    fn rows(names: &[&str], inv: &str, map: &[(usize, &str)]) -> Vec<Row> {
        let m: Vec<(usize, String)> = map.iter().map(|(i, s)| (*i, (*s).to_owned())).collect();
        resolve_ids(&json(names), Some(&table(inv)), &m)
            .unwrap()
            .rows()
            .to_vec()
    }

    fn mapped(id: &str, basis: Basis) -> Row {
        Row::Mapped {
            id: id.to_owned(),
            basis,
        }
    }

    #[test]
    fn an_exact_id_or_inventory_name_matches_whatever_the_case() {
        let r = rows(&["ALPHA-1", "back door"], INV, &[]);
        assert_eq!(
            r,
            [
                mapped("alpha-1", Basis::Exact),
                mapped("beta-2", Basis::Exact)
            ]
        );
    }

    #[test]
    fn a_vendor_or_model_word_matches_when_one_camera_has_it() {
        let r = rows(&["Garage C200 north"], INV, &[]);
        assert_eq!(r, [mapped("alpha-1", Basis::Token)]);
    }

    #[test]
    fn an_exact_id_beats_a_token_match_of_another_camera() {
        // `alpha-1` is exact for camera 1; "acme" alone would also hit alpha-1 by vendor, and a
        // second acme camera would tie it. The exact id wins.
        let inv = format!("{INV}\n[cameras.alpha-2]\nvendor = \"Acme\"\n");
        let r = rows(&["alpha-1"], &inv, &[]);
        assert_eq!(r, [mapped("alpha-1", Basis::Exact)]);
        let r = rows(&["Acme"], &inv, &[]);
        assert_eq!(
            r,
            [Row::Ambiguous(vec!["alpha-1".into(), "alpha-2".into()])]
        );
    }

    #[test]
    fn two_cameras_of_one_model_are_ambiguous_until_mapped_by_hand() {
        let r = rows(&["Bolt front", "Bolt rear"], INV, &[]);
        let both = Row::Ambiguous(vec!["beta-2".into(), "beta-3".into()]);
        assert_eq!(r, [both.clone(), both]);
        let r = rows(
            &["Bolt front", "Bolt rear"],
            INV,
            &[(1, "beta-3"), (2, "beta-2")],
        );
        assert_eq!(
            r,
            [
                mapped("beta-3", Basis::Explicit),
                mapped("beta-2", Basis::Explicit)
            ]
        );
        let res = resolve_ids(
            &json(&["Bolt front", "Bolt rear"]),
            Some(&table(INV)),
            &[(1, "beta-3".into()), (2, "beta-2".into())],
        )
        .unwrap();
        assert_eq!(res.into_ids().unwrap(), ["beta-3", "beta-2"]);
    }

    #[test]
    fn a_name_that_matches_no_id_is_a_row_and_a_check_error() {
        let res = resolve_ids(&json(&["Mystery Cam"]), Some(&table(INV)), &[]).unwrap();
        assert_eq!(res.rows(), [Row::NoMatch]);
        let err = res.check().unwrap_err();
        assert_eq!(
            err,
            LegacyError::Unresolved {
                missing: vec![1],
                ambiguous: vec![]
            }
        );
        let text = err.to_string();
        assert!(
            text.contains("camera index 1") && text.contains("--map"),
            "{text}"
        );
        assert!(!text.contains("Mystery"), "{text}");
    }

    #[test]
    fn no_inventory_means_nothing_matches() {
        let res = resolve_ids(&json(&["Acme"]), None, &[]).unwrap();
        assert_eq!(res.rows(), [Row::NoMatch]);
        assert_eq!(
            resolve_ids(&json(&["Acme"]), None, &[(1, "alpha-1".into())]).unwrap_err(),
            LegacyError::MapUnknownId
        );
    }

    #[test]
    fn a_word_inside_a_longer_word_never_matches() {
        // Names that are substrings of several ids, or ids that are substrings of a word.
        let inv = "[cameras.garage-1]\n[cameras.garage-2]\n[cameras.cam]\n";
        assert_eq!(rows(&["Garage"], inv, &[]), [Row::NoMatch]);
        assert_eq!(rows(&["garag"], inv, &[]), [Row::NoMatch]);
        assert_eq!(rows(&["camera"], inv, &[]), [Row::NoMatch]);
        assert_eq!(
            rows(&["Garage 2"], inv, &[]),
            [mapped("garage-2", Basis::Token)]
        );
        assert_eq!(
            rows(&["garage-1"], inv, &[]),
            [mapped("garage-1", Basis::Exact)]
        );
    }

    #[test]
    fn the_longer_token_match_wins_over_a_shorter_one() {
        let inv = "[cameras.garage]\n[cameras.garage-1]\n";
        assert_eq!(
            rows(&["Garage 1 side"], inv, &[]),
            [mapped("garage-1", Basis::Token)]
        );
        // Only the shorter id occurs: it matches alone.
        assert_eq!(
            rows(&["Garage side"], inv, &[]),
            [mapped("garage", Basis::Token)]
        );
    }

    #[test]
    fn unicode_lower_casing_decides_case() {
        let inv = "[cameras.a]\nmodel = \"\u{c9}toile\"\n[cameras.b]\nvendor = \"Kelvin\"\n";
        assert_eq!(
            rows(&["\u{c9}TOILE"], inv, &[]),
            [mapped("a", Basis::Token)]
        );
        assert_eq!(
            rows(&["\u{e9}toile"], inv, &[]),
            [mapped("a", Basis::Token)]
        );
        // KELVIN SIGN lower-cases to a plain k: the same word.
        assert_eq!(
            rows(&["\u{212a}elvin"], inv, &[]),
            [mapped("b", Basis::Token)]
        );
        // A look-alike letter from another script is a different word.
        assert_eq!(rows(&["\u{41a}elvin"], inv, &[]), [Row::NoMatch]);
    }

    #[test]
    fn white_space_and_invisible_characters_do_not_hide_a_match() {
        let r = rows(&["  Back\u{a0}Door\u{200b} "], INV, &[]);
        assert_eq!(r, [mapped("beta-2", Basis::Exact)]);
    }

    #[test]
    fn an_empty_missing_or_punctuation_only_name_matches_nothing() {
        let doc =
            serde_json::json!([{"name": ""}, {"login": "u"}, {"name": "---"}, {"name": null}]);
        let res = resolve_ids(&doc, Some(&table(INV)), &[]).unwrap();
        assert_eq!(res.rows(), [const { Row::NoMatch }; 4]);
        // An inventory camera with an empty vendor, model or name never matches an empty name.
        let inv = "[cameras.x]\nvendor = \"\"\nmodel = \"-\"\nname = \"\"\n";
        let res = resolve_ids(&doc, Some(&table(inv)), &[]).unwrap();
        assert_eq!(res.rows(), [const { Row::NoMatch }; 4]);
    }

    #[test]
    fn a_bad_map_is_refused_by_kind() {
        let doc = json(&["a", "b"]);
        let t = table(INV);
        let go = |m: &[(usize, &str)]| {
            let m: Vec<(usize, String)> = m.iter().map(|(i, s)| (*i, (*s).to_owned())).collect();
            resolve_ids(&doc, Some(&t), &m).unwrap_err()
        };
        assert_eq!(go(&[(0, "alpha-1")]), LegacyError::MapIndexOutOfRange);
        assert_eq!(go(&[(3, "alpha-1")]), LegacyError::MapIndexOutOfRange);
        assert_eq!(go(&[(1, "nope")]), LegacyError::MapUnknownId);
        assert_eq!(
            go(&[(1, "alpha-1"), (1, "beta-2")]),
            LegacyError::MapDuplicateIndex
        );
    }

    #[test]
    fn two_cameras_on_one_id_are_refused_however_they_got_there() {
        let go = |names: &[&str], map: &[(usize, &str)]| {
            let m: Vec<(usize, String)> = map.iter().map(|(i, s)| (*i, (*s).to_owned())).collect();
            resolve_ids(&json(names), Some(&table(INV)), &m)
                .unwrap()
                .check()
                .unwrap_err()
        };
        let want = LegacyError::SharedId(vec![("alpha-1".into(), vec![1, 2])]);
        // Two explicit maps.
        assert_eq!(go(&["x", "y"], &[(1, "alpha-1"), (2, "alpha-1")]), want);
        // Explicit and matched.
        assert_eq!(go(&["x", "alpha-1"], &[(1, "alpha-1")]), want);
        // Matched and matched.
        assert_eq!(go(&["Acme one", "alpha-1"], &[]), want);
        let text = want.to_string();
        assert!(text.contains("1, 2") && text.contains("alpha-1"), "{text}");
    }

    #[test]
    fn reports_hold_indexes_and_inventory_ids_only() {
        let inv = "[cameras.alpha-1]\nvendor = \"Acme\"\nhost = \"192.0.2.10\"\n[cameras.alpha-2]\nvendor = \"Acme\"\nhost = \"192.0.2.11\"\n";
        let doc = serde_json::json!([
            {"name": "Acme 192.0.2.10 secretname", "login": "svc-reader", "password": "pw-synthetic-9"},
            {"name": "Nothing 192.0.2.99", "login": "svc-reader", "password": "pw-synthetic-9"}
        ]);
        let err = resolve_ids(&doc, Some(&table(inv)), &[])
            .unwrap()
            .check()
            .unwrap_err();
        let text = err.to_string();
        for leak in [
            "secretname",
            "192.0.2",
            "svc-reader",
            "pw-synthetic",
            "Acme",
            "Nothing",
        ] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        assert!(
            text.contains("alpha-1") && text.contains("alpha-2"),
            "{text}"
        );
        assert!(format!("{err:?}").contains("Unresolved"));
    }

    #[test]
    fn a_long_ambiguity_list_is_cut() {
        let mut inv = String::new();
        for i in 0..30 {
            let _ = writeln!(inv, "[cameras.cam-{i:02}]\nvendor = \"Acme\"");
        }
        let err = resolve_ids(&json(&["Acme"]), Some(&table(&inv)), &[])
            .unwrap()
            .check()
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("and 22 more"), "{text}");
        assert!(!text.contains("cam-29"), "{text}");
    }

    #[test]
    fn unusable_inventory_ids_are_never_candidates() {
        // A reserved prefix and an over-long id fall back to ordinals in the importer.
        let long = "a".repeat(120);
        let inv = format!(
            "[cameras.import-7]\nvendor = \"Acme\"\n[cameras.{long}]\nvendor = \"Acme\"\n[cameras.ok]\nvendor = \"Acme\"\n"
        );
        assert_eq!(rows(&["Acme"], &inv, &[]), [mapped("ok", Basis::Token)]);
        assert_eq!(
            resolve_ids(&json(&["x"]), Some(&table(&inv)), &[(1, "import-7".into())]).unwrap_err(),
            LegacyError::MapUnknownId
        );
    }

    #[test]
    fn an_oversized_inventory_is_refused_before_scoring() {
        let mut inv = String::new();
        for i in 0..=MAX_LEGACY_CAMERAS {
            let _ = writeln!(inv, "[cameras.c{i}]");
        }
        assert_eq!(
            resolve_ids(&json(&["c1"]), Some(&table(&inv)), &[]).unwrap_err(),
            LegacyError::TooMany
        );
        // Exactly the cap is fine.
        let inv: String = (0..MAX_LEGACY_CAMERAS).fold(String::new(), |mut s, i| {
            let _ = writeln!(s, "[cameras.c{i}]");
            s
        });
        assert_eq!(rows(&["c1"], &inv, &[]), [mapped("c1", Basis::Exact)]);
    }

    #[test]
    fn a_name_of_too_many_words_matches_nothing() {
        let inv = "[cameras.yard]\n";
        let long = format!("yard {}", "w ".repeat(MAX_NAME_WORDS));
        assert_eq!(rows(&[long.as_str()], inv, &[]), [Row::NoMatch]);
        let ok = format!("yard {}", "w ".repeat(MAX_NAME_WORDS - 2));
        assert_eq!(
            rows(&[ok.as_str()], inv, &[]),
            [mapped("yard", Basis::Token)]
        );
    }

    #[test]
    fn a_missing_section_is_explained_in_the_message() {
        let err = resolve_ids(&json(&["Mystery"]), None, &[])
            .unwrap()
            .check()
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("[cameras.<id>] section"), "{text}");
        // A pure ambiguity does not claim a section is missing.
        let inv = "[cameras.a]\nvendor = \"Acme\"\n[cameras.b]\nvendor = \"Acme\"\n";
        let text = resolve_ids(&json(&["Acme"]), Some(&table(inv)), &[])
            .unwrap()
            .check()
            .unwrap_err()
            .to_string();
        assert!(!text.contains("needs a [cameras"), "{text}");
    }

    #[test]
    fn the_file_shape_is_checked() {
        let t = table(INV);
        assert_eq!(
            resolve_ids(&serde_json::json!({}), Some(&t), &[]).unwrap_err(),
            LegacyError::NotAnArray
        );
        assert_eq!(
            resolve_ids(&serde_json::json!([1]), Some(&t), &[]).unwrap_err(),
            LegacyError::NotAnObject
        );
        assert_eq!(
            resolve_ids(&serde_json::json!([{"name": 5}]), Some(&t), &[]).unwrap_err(),
            LegacyError::NotAString
        );
        let many = serde_json::Value::Array(vec![serde_json::json!({}); MAX_LEGACY_CAMERAS + 1]);
        assert_eq!(
            resolve_ids(&many, Some(&t), &[]).unwrap_err(),
            LegacyError::TooMany
        );
    }

    #[test]
    fn the_resolved_ids_drive_the_mapping() {
        use crate::legacy::map_secret_json_with_ids;
        use std::collections::BTreeMap;
        // The inventory owns the name of beta-2; alpha-1 has none, so the JSON name is kept.
        let names = BTreeMap::from([("Back Door".to_owned(), "beta-2".to_owned())]);
        let doc = json(&["Acme", "Back Door"]);
        let ids = resolve_ids(&doc, Some(&table(INV)), &[])
            .unwrap()
            .into_ids()
            .unwrap();
        assert_eq!(ids, ["alpha-1", "beta-2"]);
        let imp = map_secret_json_with_ids(&doc, &ids, &names).unwrap();
        let got: Vec<&str> = imp.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            got,
            [
                "cam:alpha-1:name",
                "cam:alpha-1:credential",
                "cam:beta-2:credential"
            ]
        );
        assert_eq!(imp.unused_fields.get("name"), Some(&1));
        // A wrong number of ids, or an unusable one, is refused.
        assert_eq!(
            map_secret_json_with_ids(&doc, &ids[..1], &names).unwrap_err(),
            LegacyError::InvalidId
        );
        let bad = ["alpha-1".to_owned(), "import-1".to_owned()];
        assert_eq!(
            map_secret_json_with_ids(&doc, &bad, &names).unwrap_err(),
            LegacyError::InvalidId
        );
    }
}
