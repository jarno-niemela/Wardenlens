//! The spelling matrix (ADR 0006 section 8): a stored display name `Porte Nord Est` is found in
//! a file in every combination of encoding, word separator and invisible character, except the
//! cells the ADR lists as gaps, which must stay missing (the test pins them).

use std::fmt::Write as _;

use wardenlens_core::entry::EntryKind::DisplayName;

use super::{entry, matcher};
use crate::scan::scan;

/// How the characters of the name, its separators and (optionally) the invisible are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Enc {
    Literal,
    /// A `\uXXXX` escape for every character (surrogate pair above the BMP).
    JsonU,
    /// The JSON short escapes (`\t`, `\f`, `\n`) where one exists, otherwise literal.
    JsonShort,
    /// `%XX` for every byte.
    PctAll,
    /// `%20` for a plain space, everything else literal.
    PctSpace,
}

const ENCODINGS: [Enc; 5] = [
    Enc::Literal,
    Enc::JsonU,
    Enc::JsonShort,
    Enc::PctAll,
    Enc::PctSpace,
];

/// Word separators: space, tab, form feed, NBSP, NNBSP, U+3000, a double space, a line break.
const SEPARATORS: [&str; 8] = [
    " ", "\t", "\u{C}", "\u{A0}", "\u{202F}", "\u{3000}", "  ", "\n",
];

/// Dropped invisible characters: ZWSP, a variation selector, the soft hyphen, a word joiner and
/// an astral tag-range variation selector.
const INVISIBLES: [char; 5] = ['\u{200B}', '\u{FE0F}', '\u{00AD}', '\u{2060}', '\u{E0100}'];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    None,
    /// Inside a word: `Po<inv>rte`.
    Inside,
    /// Before the name, glued to a preceding letter: `x<inv>Porte`.
    Before,
    /// After the name, glued to a following letter: `Est<inv>x`.
    After,
}

fn encode(enc: Enc, s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match enc {
            Enc::Literal => out.push(c),
            Enc::JsonU => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units).iter() {
                    let _ = write!(out, "\\u{u:04x}");
                }
            }
            Enc::JsonShort => match c {
                '\t' => out.push_str("\\t"),
                '\u{C}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                _ => out.push(c),
            },
            Enc::PctAll => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    let _ = write!(out, "%{b:02X}");
                }
            }
            Enc::PctSpace => out.push_str(&if c == ' ' {
                "%20".to_owned()
            } else {
                c.to_string()
            }),
        }
    }
    out
}

/// The text of one cell. `literal_invisible` writes the invisible as itself while the rest is
/// encoded.
fn render(enc: Enc, sep: &str, place: Place, inv: char, literal_invisible: bool) -> String {
    let piece = if literal_invisible {
        inv.to_string()
    } else {
        encode(enc, &inv.to_string())
    };
    let word0 = match place {
        Place::Inside => format!("{}{piece}{}", encode(enc, "Po"), encode(enc, "rte")),
        _ => encode(enc, "Porte"),
    };
    let name = format!(
        "{word0}{s}{}{s}{}",
        encode(enc, "Nord"),
        encode(enc, "Est"),
        s = encode(enc, sep)
    );
    match place {
        Place::Before => format!("label=x{piece}{name}\n"),
        Place::After => format!("label={name}{piece}x\n"),
        Place::None | Place::Inside => format!("label={name}\n"),
    }
}

/// The documented gaps (ADR 0006 section 8): a line break written as an escape is never
/// decoded, because decoding it would move line numbers. A literal line break is found (joined
/// view), and so is the same separator in a plain-space-only encoding.
fn is_gap(enc: Enc, sep: &str) -> bool {
    sep == "\n" && matches!(enc, Enc::JsonU | Enc::JsonShort | Enc::PctAll)
}

#[test]
fn stored_display_name_is_found_in_every_spelling_except_the_documented_gaps() {
    let m = matcher(&[entry("cam:a:name", DisplayName, "Porte Nord Est")]);
    let mut wrong = Vec::new();
    let mut cells = 0usize;
    let mut missing = 0usize;
    let mut check = |enc: Enc, sep: &str, place: Place, inv: char, literal: bool| {
        let text = render(enc, sep, place, inv, literal);
        let found = !scan(&m, text.as_bytes()).unwrap().hits.is_empty();
        cells += 1;
        let want = !is_gap(enc, sep);
        if !want {
            missing += 1;
        }
        if found != want {
            wrong.push(format!(
                "{enc:?} sep={sep:?} {place:?} U+{:04X} literal_invisible={literal}: found={found} {text:?}",
                u32::from(inv)
            ));
        }
    };
    for enc in ENCODINGS {
        for sep in SEPARATORS {
            check(enc, sep, Place::None, '\u{200B}', true);
            for place in [Place::Inside, Place::Before, Place::After] {
                for inv in INVISIBLES {
                    for literal in [true, false] {
                        check(enc, sep, place, inv, literal);
                    }
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{} cells wrong: {wrong:#?}", wrong.len());
    // The matrix is not vacuous: many cells, and exactly the documented gaps are missing.
    assert!(cells > 1000, "{cells}");
    assert!(missing > 0 && missing < cells / 5, "{missing} of {cells}");
}

#[test]
fn the_mixed_spellings_the_adversary_found_are_found() {
    let m = matcher(&[entry("cam:a:name", DisplayName, "Porte Nord Est")]);
    for body in [
        "label=x\u{200B}Porte%20Nord%20Est\n",
        "label=x\u{FE0F}Porte%20Nord%20Est\n",
        "{\"label\":\"x\u{200B}Porte\\u0020Nord\\u0020Est\"}\n",
        "{\"label\":\"x\u{200B}Porte\\tNord\\fEst\"}\n",
        "{\"label\":\"Porte\\tNord Est\"}\n",
    ] {
        assert_eq!(scan(&m, body.as_bytes()).unwrap().hits.len(), 1, "{body:?}");
    }
}

/// The JSON short escapes that are decoded (`\"`, `\\`, `\/`) inside a stored value.
#[test]
fn json_quote_backslash_and_slash_escapes_are_decoded() {
    let m = matcher(&[entry(
        "cam:a:name",
        DisplayName,
        "Porte/Nord \"Est\" Sud\\Ouest",
    )]);
    let body = r#"{"label":"Porte\/Nord \"Est\" Sud\\Ouest"}"#;
    assert_eq!(scan(&m, body.as_bytes()).unwrap().hits.len(), 1);
}

/// The documented gaps stay gaps, and they do not move line numbers.
#[test]
fn escaped_line_breaks_between_words_stay_a_documented_gap() {
    let m = matcher(&[entry("cam:a:name", DisplayName, "Porte Nord Est")]);
    for body in [
        r"Porte\nNord\nEst",
        r"Porte\rNord\rEst",
        "Porte\\u000aNord\\u000dEst",
        "Porte\\u0085Nord\\u2028Est\\u2029",
        "Porte%0ANord%0dEst",
        "Porte%C2%85Nord%E2%80%A8Est",
    ] {
        assert!(scan(&m, body.as_bytes()).unwrap().hits.is_empty(), "{body}");
    }
}
