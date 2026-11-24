//! Round-4 adversarial tests for the catalogue site-data guard: the round-4 fixes (XML secret
//! elements, camelCase keys, model-line comments, blank evidence section, `//` paths) and
//! false positives on legitimate catalogue prose.

use wardenlens_core::catalogue::{CatalogueEntry, CatalogueError, check_source, validate};

const EV: &str = "[[evidence]]\nreference=\"docs/adr/0002-camera-integration.md\"\n";

fn entry_text(extra: &str) -> String {
    format!("vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n{extra}\n{EV}")
}

fn full(toml: &str) -> Result<(), CatalogueError> {
    CatalogueEntry::from_toml_str(toml).and_then(|e| validate(&e))
}

fn quirk(q: &str) -> Result<(), CatalogueError> {
    full(&entry_text(&format!("quirks=['''{q}''']")))
}

fn accepted(inputs: &[&str], f: impl Fn(&str) -> Result<(), CatalogueError>) -> Vec<String> {
    inputs
        .iter()
        .filter(|i| f(i).is_ok())
        .map(|i| format!("{i:?}"))
        .collect()
}

fn rejected(inputs: &[&str], f: impl Fn(&str) -> Result<(), CatalogueError>) -> Vec<String> {
    inputs
        .iter()
        .filter_map(|i| f(i).err().map(|e| format!("{i:?}: {e}")))
        .collect()
}

// ---- XML elements x camelCase keys (the two halves of the round-3 major combined) ----

/// The separator form catches `loginPassword=x`, and the element form catches `<password>x`, but
/// the element form only matches a key exactly. Hikvision ISAPI user bodies carry
/// `<loginPassword>`, and vendor XML commonly uses prefixed element names.
#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn camel_case_and_prefixed_xml_secret_elements_are_rejected() {
    let inputs = [
        "<loginPassword>hunter2</loginPassword>",
        "<adminPassword>hunter2</adminPassword>",
        "<newPassword>hunter2</newPassword>",
        "<onvifPwd>hunter2</onvifPwd>",
        "<rtspPass>hunter2</rtspPass>",
        "<userPassword>hunter2</userPassword>",
        "<tt:AdminPassword>hunter2</tt:AdminPassword>",
        "<apiToken>abc</apiToken>",
    ];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted in raw source: {bad:?}");
}

/// Text hidden behind markup inside a secret element: the guard reads only up to the next `<`.
#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn xml_secret_behind_cdata_or_comment_is_rejected() {
    let inputs = [
        "<Password><![CDATA[hunter2]]></Password>",
        "<Password><!-- x -->hunter2</Password>",
    ];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn xml_secret_with_entity_escaped_brackets_is_rejected() {
    let inputs = ["&lt;Password&gt;hunter2&lt;/Password&gt;"];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn xml_secret_elements_with_unusual_whitespace_and_case_are_rejected() {
    let inputs = [
        "<PASSWORD>hunter2</PASSWORD>",
        "<Password >hunter2</Password>",
        "<Password\tType=\"x\">hunter2</Password>",
        "<a:b:Password>hunter2</a:b:Password>",
        "<Password>\thunter2</Password>",
        "<User><Name>x</Name><Password>hunter2</Password></User>",
        "<Pin>4711</Pin>",
        "<auth>bearer-abc</auth>",
    ];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

/// Multi-line TOML strings: the element on one raw line and the secret on the next.
#[test]
fn xml_secret_split_across_lines_of_a_multiline_string_is_rejected() {
    let toml = entry_text("quirks=['''\n<Password>\nhunter2\n</Password>\n''']");
    assert!(full(&toml).is_err());
}

// ---- camelCase boundary ----

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn camel_case_short_keys_after_digits_or_capitals_are_rejected() {
    let inputs = [
        "adminPin=4711",
        "rtspUser=admin",
        "cloudToken=abc",
        "camSecret=abc",
        "onvifAuth=abc",
        "ADMIN_PASS=x",
    ];
    let bad = accepted(&inputs, quirk);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

/// Ordinary identifiers that merely contain a short key must not become credentials.
#[test]
fn identifiers_containing_short_keys_are_accepted() {
    let inputs = [
        "Compass=north",
        "Bypass: yes",
        "Spin=3 rotations",
        "Repin=no",
        "OAuth2 is not offered.",
        "superuser accounts are not needed.",
        "WSPullPointSupport=true",
        "isPinned=false",
        "hasUsers: false",
        "Tokenizer=default",
        "Passwords are hashed by the firmware.",
        "Password-protected: yes",
    ];
    let bad = rejected(&inputs, quirk);
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

/// Quirk prose that names ONVIF or CGI operations in camelCase followed by a colon.
#[test]
fn camel_case_operation_names_in_prose_are_accepted() {
    let inputs = [
        "ONVIF SetUser: fails with a SOAP fault on this firmware.",
        "GetUsers: returns an empty list.",
        "CGI getLogin: answers 401 until digest is used.",
        "ONVIF CreateUsers: rejected.",
    ];
    let bad = rejected(&inputs, quirk);
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

// ---- XML element false positives on legitimate prose ----

#[test]
fn angle_bracket_placeholders_in_prose_are_accepted() {
    let inputs = [
        "RTSP paths are /<channel>/<stream> on newer firmware.",
        "The <UserLevel> element must be Administrator.",
        "The response holds a <Token> element per profile.",
        "Profiles are listed as <tt:Profiles token=\"x\"> elements.",
    ];
    let bad = rejected(&inputs, quirk);
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

// ---- model-line comments ----

#[test]
#[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
fn comments_on_model_and_alias_lines_are_scanned_strictly() {
    let inputs = [
        "vendor=\"A\"\nmodel = \"B\" # sn ABCDEF1234XYZ\nsupport=\"verified\"\n",
        "vendor=\"A\"\nmodel = 'B' # 10.0.0.1\nsupport=\"verified\"\n",
        "vendor=\"A\"\nmodel = \"B\\\"\" # 10.0.0.1\nsupport=\"verified\"\n",
        "vendor=\"A\"\nmodel = \"\"\"B\"\"\" # 10.0.0.1\nsupport=\"verified\"\n",
        "vendor=\"A\"\nmodel=\"B\"\naliases = [\"X\", 'Y'] # SN-ABCDEFGHJK12\nsupport=\"verified\"\n",
        "vendor=\"A\"\nmodel=\"B\"\naliases = [\"X\"] # 2J0A1B2C3D\nsupport=\"verified\"\n",
        "vendor=\"A\"\n  model\t=  \"B\" #ABCDE12345\nsupport=\"verified\"\n",
    ];
    let bad = accepted(&inputs, check_source);
    assert!(bad.is_empty(), "accepted: {bad:?}");
}

/// A `#` inside the model string is not a comment, so a legitimate name stays in model mode.
#[test]
fn hash_inside_a_model_string_does_not_start_a_comment() {
    for line in [
        "model = \"IPC-HDBW2431EP-S-0280B#2\"\n",
        "model = 'IPC-HDBW2431EP-S-0280B#2'\n",
        "aliases = [\"DS-2CD2T87G2P-LSU#\"]\n",
    ] {
        assert_eq!(check_source(line), Ok(()), "{line}");
    }
}

/// Multi-line alias arrays are a normal TOML layout; real model names on the continuation lines
/// must not be refused as serials.
#[test]
fn multiline_alias_array_with_real_model_names_is_accepted() {
    let toml = "vendor=\"Hikvision\"\nmodel=\"DS-2CD2387G2P-LSU\"\naliases = [\n  \"DS-2CD2T87G2P-LSU\",\n]\nsupport=\"community\"\n[[evidence]]\nreference=\"x\"\n";
    assert_eq!(full(toml), Ok(()));
}

// ---- evidence and paths ----

#[test]
fn whitespace_only_evidence_section_variants_are_rejected() {
    for s in ["\\t", "\\n", " \\r\\n "] {
        let toml = format!(
            "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n[[evidence]]\nreference=\"x\"\nsection=\"{s}\"\n"
        );
        assert!(full(&toml).is_err(), "{s:?}");
    }
}

#[test]
fn network_path_lookalikes_are_rejected() {
    for p in ["//host/x", "///host/x", "//[fe80::1]/x"] {
        let toml = entry_text(&format!("[[protocols]]\nkind=\"rtsp\"\npaths=['{p}']"));
        assert!(full(&toml).is_err(), "{p}");
    }
}

// ---- legitimate catalogue content (false positives) ----

#[test]
fn legitimate_catalogue_prose_is_accepted() {
    let inputs = [
        "ONVIF PullMessages with Timeout=PT10S returns an empty reply; PT5S works.",
        "Login on port 9000 uses the modern encrypted BC login.",
        "WS-Security UsernameToken digest works; PasswordText is refused.",
        "The token in GetStreamUri responses is per profile.",
        "Uses HTTP digest auth.",
        "auth: digest",
        "MSG_ID_GET_SERVICE_PORTS = 37 is read-only.",
        "eventManager.cgi?action=attach&codes=[All] stays open.",
        "Code=VideoMotion;action=Start;index=0",
        "The heartbeat= parameter is ignored.",
        "error_code -40413 from an unauthenticated probe.",
        "The password is the cloud account password.",
        "Camera Account: created in the Tapo app.",
    ];
    let bad = rejected(&inputs, quirk);
    assert!(bad.is_empty(), "rejected: {bad:?}");
}

#[test]
fn guard_does_not_panic_on_xml_and_camel_edges() {
    for t in [
        "<",
        "<>",
        "</",
        "<a:>x",
        "<:password>x",
        "<password",
        "<password>",
        "<\u{00E9}password>x",
        "a\u{00E9}Password=x",
        "\u{00E9}<password>\u{00E9}",
        "model = \"\u{00E9}#",
        "model = '",
        "model = \"\\",
    ] {
        let _ = check_source(t);
        let _ = quirk(t);
    }
    let _ = check_source(&"<password>".repeat(6000));
    let _ = check_source(&"<".repeat(60_000));
    let _ = check_source(&"aP".repeat(30_000));
}
