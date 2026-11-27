//! Adversary tests for #188 (PR #215): the legacy-camera matcher and `Vault::rename_camera`.
//! Synthetic names, documentation-range hosts and invented passwords only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;

use proptest::prelude::*;
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;
use wardenlens_core::camera::CameraId;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::{Credentials, KeyFile};
use wardenlens_vault::legacy::{Basis, LegacyError, Row, resolve_ids};
use wardenlens_vault::{Scan, Value, Vault, VaultError};

fn table(s: &str) -> toml::Table {
    toml::from_str(s).unwrap()
}

fn doc(names: &[&str]) -> serde_json::Value {
    serde_json::Value::Array(
        names
            .iter()
            .map(|n| serde_json::json!({ "name": n, "login": "u", "password": "pw-synthetic-9" }))
            .collect(),
    )
}

fn rows(names: &[&str], inv: &str) -> Vec<Row> {
    resolve_ids(&doc(names), Some(&table(inv)), &[])
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

// ---- matcher --------------------------------------------------------------------------------

/// The same visible name must give the same answer in NFC and NFD. A combining mark is not
/// alphanumeric, so the NFD form splits "garagé" into "garage" + mark, and the word "garage"
/// then matches although the name holds a different word ("substrings inside a word never match").
#[test]
fn a_decomposed_accent_does_not_turn_a_different_word_into_a_match() {
    let inv = "[cameras.garage]\n";
    let composed = rows(&["Garag\u{e9}"], inv);
    let decomposed = rows(&["Garage\u{301}"], inv);
    assert_eq!(composed, [Row::NoMatch]);
    assert_eq!(decomposed, composed, "NFD and NFC of one name disagree");
}

/// A combining mark in the middle of a word must not cut it into two matchable words either.
#[test]
fn a_combining_mark_inside_a_word_does_not_split_it() {
    let inv = "[cameras.cafe-cam]\nvendor = \"Cafe\"\n[cameras.other]\nmodel = \"Noir\"\n";
    // "Cafe\u{301}noir" renders as one word "Cafénoir".
    assert_eq!(rows(&["Cafe\u{301}noir"], inv), [Row::NoMatch]);
}

/// Right-to-left overrides and zero-width characters are dropped or split, never guessed.
#[test]
fn bidi_overrides_never_produce_a_match_on_reversed_text() {
    let inv = "[cameras.garage-1]\n[cameras.garage-2]\n";
    // U+202E makes "1-egarag" display as "garage-1".
    let r = rows(&["\u{202e}1-egarag"], inv);
    assert_eq!(r, [Row::NoMatch]);
}

#[test]
fn a_zero_width_character_inside_a_word_joins_it_back() {
    // ZWSP is dropped by the vault clean-up, so "Gar<ZWSP>age 2" is "garage 2".
    let inv = "[cameras.garage-1]\n[cameras.garage-2]\n";
    assert_eq!(
        rows(&["Gar\u{200b}age 2"], inv),
        [mapped("garage-2", Basis::Token)]
    );
}

#[test]
fn a_cyrillic_lookalike_id_never_matches() {
    // "gаrage-1" with U+0430 CYRILLIC SMALL A.
    let inv = "[cameras.garage-1]\n";
    assert_eq!(rows(&["g\u{430}rage-1"], inv), [Row::NoMatch]);
}

#[test]
fn an_exact_id_and_an_exact_inventory_name_of_two_cameras_tie() {
    let inv = "[cameras.garage]\n[cameras.cam-2]\nname = \"Garage\"\n";
    assert_eq!(
        rows(&["garage"], inv),
        [Row::Ambiguous(vec!["cam-2".into(), "garage".into()])]
    );
}

#[test]
fn inventory_names_differing_only_by_case_tie() {
    let inv = "[cameras.a]\nname = \"Garage\"\n[cameras.b]\nname = \"garage\"\n";
    assert_eq!(
        rows(&["Garage"], inv),
        [Row::Ambiguous(vec!["a".into(), "b".into()])]
    );
}

#[test]
fn a_map_onto_an_unusable_id_is_unknown() {
    let inv = "[cameras.\"Bad Id\"]\nvendor = \"Acme\"\n[cameras.ok]\n";
    let err = resolve_ids(
        &doc(&["Acme"]),
        Some(&table(inv)),
        &[(1, "Bad Id".to_owned())],
    )
    .unwrap_err();
    assert_eq!(err, LegacyError::MapUnknownId);
    // And the unusable section is not a candidate either.
    assert_eq!(rows(&["Acme"], inv), [Row::NoMatch]);
}

#[test]
fn the_same_index_mapped_twice_to_one_id_is_still_a_duplicate() {
    let inv = "[cameras.a]\n";
    let err = resolve_ids(
        &doc(&["x"]),
        Some(&table(inv)),
        &[(1, "a".to_owned()), (1, "a".to_owned())],
    )
    .unwrap_err();
    assert_eq!(err, LegacyError::MapDuplicateIndex);
}

#[test]
fn an_index_past_usize_range_edges_is_out_of_range() {
    let inv = "[cameras.a]\n";
    for i in [0, 2, usize::MAX] {
        let err = resolve_ids(&doc(&["x"]), Some(&table(inv)), &[(i, "a".to_owned())]).unwrap_err();
        assert_eq!(err, LegacyError::MapIndexOutOfRange, "{i}");
    }
}

/// 256 cameras against a large inventory: every camera ambiguous between every twin, error
/// text bounded, no panic.
#[test]
fn many_cameras_and_twins_stay_ambiguous_and_the_report_is_bounded() {
    let mut inv = String::new();
    for i in 0..200 {
        let _ = write!(
            inv,
            "[cameras.cam-{i:03}]\nvendor = \"Acme\"\nmodel = \"X1\"\n"
        );
    }
    let names: Vec<String> = (0..256).map(|i| format!("Acme X1 #{i}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let resolution = resolve_ids(&doc(&refs), Some(&table(&inv)), &[]).unwrap();
    assert!(
        resolution
            .rows()
            .iter()
            .all(|r| matches!(r, Row::Ambiguous(v) if v.len() == 200))
    );
    let text = resolution.check().unwrap_err().to_string();
    assert!(
        text.len() < 256 * 200,
        "report not bounded: {} bytes",
        text.len()
    );
}

proptest! {
    /// Two inventory cameras with the same vendor and model and ids made of words that never
    /// occur in a name can never be told apart by the name: neither may be picked.
    #[test]
    fn twins_are_never_guessed(words in proptest::collection::vec(
        prop_oneof![Just("acme"), Just("x1"), Just("front"), Just("door"), Just("1"), Just("2"),
                    Just("ACME"), Just("X1"), Just("-"), Just("\u{a0}")], 0..6)) {
        let inv = "[cameras.qq-one]\nvendor = \"Acme\"\nmodel = \"X1\"\n\
                   [cameras.qq-two]\nvendor = \"Acme\"\nmodel = \"X1\"\n";
        let name = words.join(" ");
        let r = rows(&[name.as_str()], inv);
        prop_assert!(
            matches!(r.as_slice(), [Row::NoMatch | Row::Ambiguous(_)]),
            "{name:?} -> {r:?}"
        );
    }

    /// The result does not depend on letter case or on white space / invisible padding.
    #[test]
    fn case_and_padding_do_not_change_the_answer(
        words in proptest::collection::vec(
            prop_oneof![Just("acme"), Just("bolt"), Just("c200"), Just("rlc"), Just("810a"),
                        Just("back"), Just("door"), Just("alpha"), Just("1"), Just("beta")], 1..5),
        pad in prop_oneof![Just(" "), Just("\u{a0}"), Just("  \u{200b}"), Just("\t")],
    ) {
        let inv = "[cameras.alpha-1]\nvendor = \"Acme\"\nmodel = \"C200\"\n\
                   [cameras.beta-2]\nvendor = \"Bolt\"\nmodel = \"RLC-810A\"\nname = \"Back Door\"\n\
                   [cameras.beta-3]\nvendor = \"Bolt\"\nmodel = \"RLC-810A\"\n";
        let plain = words.join(" ");
        let shouty = words.join(pad).to_uppercase();
        let padded = format!("{pad}{shouty}{pad}");
        prop_assert_eq!(rows(&[plain.as_str()], inv), rows(&[padded.as_str()], inv));
    }
}

// ---- rename_camera --------------------------------------------------------------------------

fn fresh() -> (TempDir, Vault) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let v = Vault::create(&tmp.path().join("v.db"), key).unwrap();
    (tmp, v)
}

fn put(v: &mut Vault, entry: &str, kind: EntryKind, value: &str) {
    let value = if kind == EntryKind::Credential {
        Value::Credential(Credentials::new("svc-reader", value))
    } else {
        Value::Text(SecretString::from(value.to_owned()))
    };
    v.set(&EntryId::new(entry).unwrap(), kind, &value, Scan::Normal)
        .unwrap();
}

fn ids(v: &Vault) -> Vec<String> {
    v.list()
        .unwrap()
        .iter()
        .map(|e| e.id.as_str().to_owned())
        .collect()
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

/// The importer accepts an inventory section `a:b` (it builds `cam:a:b:credential`), so the
/// vault can hold camera `a:b` next to camera `a`. Renaming camera `a` must not carry off the
/// credential of camera `a:b`.
#[test]
fn renaming_a_camera_does_not_move_a_colon_extended_cameras_credential() {
    let (_t, mut v) = fresh();
    put(&mut v, "cam:a:host", EntryKind::Host, "192.0.2.10");
    put(
        &mut v,
        "cam:a:b:credential",
        EntryKind::Credential,
        "pw-synthetic-ab",
    );
    put(&mut v, "cam:a:b:host", EntryKind::Host, "192.0.2.11");
    v.rename_camera(&cam("a"), &cam("z")).unwrap();
    let got = ids(&v);
    assert!(got.contains(&"cam:a:b:credential".to_owned()), "{got:?}");
    assert!(got.contains(&"cam:a:b:host".to_owned()), "{got:?}");
}

#[test]
fn a_taken_target_in_the_middle_rolls_back_and_names_no_value() {
    // A taken target in the middle of the id order: one entry has already moved when the
    // conflict is found, so only a real rollback leaves the listing unchanged.
    let (_t, mut v) = fresh();
    put(&mut v, "cam:a:aaa", EntryKind::Other, "synthetic-1");
    put(&mut v, "cam:a:mmm", EntryKind::Other, "synthetic-2");
    put(&mut v, "cam:a:zzz", EntryKind::Other, "synthetic-3");
    put(&mut v, "cam:b:mmm", EntryKind::Other, "synthetic-other");
    let before = ids(&v);
    let err = v.rename_camera(&cam("a"), &cam("b")).unwrap_err();
    assert!(matches!(&err, VaultError::RenameTargetExists { id } if id == "cam:b:mmm"));
    assert!(!err.to_string().contains("synthetic"), "{err}");
    assert!(!format!("{err:?}").contains("synthetic"), "{err:?}");
    assert_eq!(ids(&v), before);
}

#[test]
fn rename_errors_are_typed_and_value_free() {
    let (_t, mut v) = fresh();
    for e in [
        v.rename_camera(&cam("a"), &cam("a")).unwrap_err(),
        v.rename_camera(&cam("a"), &cam("b")).unwrap_err(),
    ] {
        assert!(
            matches!(e, VaultError::RenameSame | VaultError::NothingToRename),
            "{e:?}"
        );
    }
}

#[test]
fn renaming_back_and_forth_round_trips() {
    let (_t, mut v) = fresh();
    put(&mut v, "cam:a:host", EntryKind::Host, "192.0.2.10");
    put(
        &mut v,
        "cam:a:credential",
        EntryKind::Credential,
        "pw-synthetic-rt",
    );
    let before = ids(&v);
    v.rename_camera(&cam("a"), &cam("b")).unwrap();
    v.rename_camera(&cam("b"), &cam("a")).unwrap();
    assert_eq!(ids(&v), before);
    let Value::Credential(c) = v
        .get(&EntryId::new("cam:a:credential").unwrap())
        .unwrap()
        .unwrap()
        .value
    else {
        panic!("shape")
    };
    assert_eq!(c.password.expose_secret(), "pw-synthetic-rt");
}
