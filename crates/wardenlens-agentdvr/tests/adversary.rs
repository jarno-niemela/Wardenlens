//! Adversary tests for #51 (PR #144): public API only.

use secrecy::ExposeSecret;
use wardenlens_agentdvr::{ImportError, SkipReason, parse};

fn doc(cameras: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><objects><cameras>{cameras}</cameras></objects>"
    )
}

fn cam(id: u32, name: &str, settings: &str) -> String {
    format!("<camera id=\"{id}\" name=\"{name}\"><settings>{settings}</settings></camera>")
}

// ---- P1: every emitted value is accepted by the sink (vault `check_credential` refuses an
// empty username). A credential with an empty user can never be stored.

#[test]
fn password_field_without_login_never_emits_a_credential_with_an_empty_user() {
    let d = doc(&cam(
        1,
        "Porch",
        "<videosourcestring>rtsp://192.0.2.10/s</videosourcestring><login></login><password>secret</password>",
    ));
    let i = parse(d.as_bytes()).expect("parses");
    for c in &i.cameras {
        if let Some(cred) = &c.credential {
            assert!(
                !cred.user.is_empty(),
                "emitted a credential with an empty user that the vault refuses"
            );
        }
    }
    assert_eq!(i.cameras.len() + i.skipped.len(), 1);
}

#[test]
fn url_password_without_user_never_emits_a_credential_with_an_empty_user() {
    let d = doc(&cam(
        1,
        "Porch",
        "<videosourcestring>rtsp://:secret@192.0.2.10/s</videosourcestring>",
    ));
    let i = parse(d.as_bytes()).expect("parses");
    for c in &i.cameras {
        if let Some(cred) = &c.credential {
            assert!(
                !cred.user.is_empty(),
                "emitted a credential with an empty user that the vault refuses"
            );
        }
    }
}

// ---- Leaks: Debug/Display of everything public.

#[test]
fn no_userinfo_in_debug_of_import_for_awkward_url_shapes() {
    let sentinels = ["zzuserzz", "zzpasszz"];
    let sources = [
        "rtsp://zzuserzz:zzpasszz@192.0.2.10/s",
        "rtsp://zzuserzz:zzpasszz@[2001:db8::1]:554/s",
        "rtsp://zzuserzz:zz%70asszz@192.0.2.10/s",
        "rtsp://zzuserzz:zzpasszz@192.0.2.10?x=1",
        "rtsp://zzuserzz:zzpass/zz@192.0.2.10/s",
        "rtsp://zzuserzz:zzpass?zz@192.0.2.10/s",
        "rtsp://zzuserzz:zzpass#zz@192.0.2.10/s",
        "rtsp://zzuserzz@zzpasszz@192.0.2.10/s",
        "RTSP://zzuserzz:zzpasszz@192.0.2.10:99999/s",
        "rtsp://zzuserzz:zzpasszz@bad host/s",
        "rtsp://zzuserzz:zzpasszz@192.0.2.10/user=zzuserzz&password=zzpasszz",
        "http://zzuserzz:zzpasszz@192.0.2.10/s",
    ];
    for s in sources {
        let d = doc(&cam(
            1,
            "Porch",
            &format!("<videosourcestring>{s}</videosourcestring>"),
        ));
        let out = match parse(d.as_bytes()) {
            Ok(i) => format!("{i:?}"),
            Err(e) => format!("{e:?} {e}"),
        };
        for needle in sentinels {
            assert!(!out.contains(needle), "{s}: {out}");
        }
    }
}

// ---- URL split

#[test]
fn host_and_port_never_contain_userinfo_and_last_at_wins() {
    let d = doc(&cam(
        1,
        "Porch",
        "<videosourcestring>rtsp://us:p@ss@192.0.2.10:8554/s</videosourcestring>",
    ));
    let i = parse(d.as_bytes()).expect("parses");
    let c = &i.cameras[0];
    assert_eq!(c.host.expose(), "192.0.2.10");
    assert_eq!(c.port.get(), 8554);
    let cred = c.credential.as_ref().expect("credential");
    assert_eq!(cred.user, "us");
    assert_eq!(cred.password.expose_secret(), "p@ss");
}

#[test]
fn ipv6_host_with_port_and_query_only() {
    let d = doc(&cam(
        1,
        "Porch",
        "<videosourcestring>rtsp://[2001:db8::1]:8554?ch=1</videosourcestring>",
    ));
    let i = parse(d.as_bytes()).expect("parses");
    let c = &i.cameras[0];
    assert_eq!(c.port.get(), 8554);
    assert_eq!(c.path.as_str(), "/?ch=1");
}

#[test]
fn zero_port_and_overflowing_port_are_invalid_port() {
    for s in [
        "rtsp://192.0.2.10:0/s",
        "rtsp://192.0.2.10:65536/s",
        "rtsp://192.0.2.10:-1/s",
    ] {
        let d = doc(&cam(
            1,
            "Porch",
            &format!("<videosourcestring>{s}</videosourcestring>"),
        ));
        let i = parse(d.as_bytes()).expect("parses");
        assert_eq!(i.skipped[0].reason, SkipReason::InvalidPort, "{s}");
    }
}

// ---- Identity

#[test]
fn names_equal_after_normalisation_refuse_the_import() {
    let d = doc(&format!(
        "{}{}",
        cam(
            1,
            "Front  Door",
            "<videosourcestring>rtsp://192.0.2.10/s</videosourcestring>"
        ),
        cam(
            2,
            "Front&#160;Door\u{200B}",
            "<videosourcestring>rtsp://192.0.2.11/s</videosourcestring>"
        ),
    ));
    assert!(matches!(
        parse(d.as_bytes()).unwrap_err(),
        ImportError::DuplicateName { .. }
    ));
}

#[test]
fn slug_collisions_dedup_deterministically_and_ids_are_unique() {
    let names = ["a-2", "A", "a", "a 3", "Ä", "ö", "123"];
    let body: String = names
        .iter()
        .enumerate()
        .map(|(n, name)| {
            cam(
                u32::try_from(n).unwrap(),
                name,
                &format!("<videosourcestring>rtsp://192.0.2.{n}/s</videosourcestring>"),
            )
        })
        .collect();
    let d = doc(&body);
    let a = parse(d.as_bytes()).expect("parses");
    let b = parse(d.as_bytes()).expect("parses");
    let ids_a: Vec<_> = a.cameras.iter().map(|c| c.id.as_str().to_owned()).collect();
    let ids_b: Vec<_> = b.cameras.iter().map(|c| c.id.as_str().to_owned()).collect();
    assert_eq!(ids_a, ids_b);
    let set: std::collections::BTreeSet<_> = ids_a.iter().collect();
    assert_eq!(set.len(), ids_a.len(), "{ids_a:?}");
    assert_eq!(ids_a.len(), names.len());
}

#[test]
fn many_long_names_with_equal_slug_prefix_all_get_unique_ids() {
    let prefix = "x".repeat(40);
    let body: String = (0..256_u32)
        .map(|n| {
            cam(
                n,
                &format!("{prefix} {n}"),
                &format!("<videosourcestring>rtsp://192.0.2.1/s{n}</videosourcestring>"),
            )
        })
        .collect();
    let i = parse(doc(&body).as_bytes()).expect("parses");
    assert_eq!(i.cameras.len(), 256, "skipped: {:?}", i.skipped);
    let set: std::collections::BTreeSet<_> = i.cameras.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(set.len(), 256);
}

// ---- Hostile XML

#[test]
fn decl_in_the_middle_of_the_document_is_malformed_not_an_encoding_error() {
    let d = "<objects><?xml version=\"1.0\" encoding=\"latin1\"?></objects>";
    assert!(
        matches!(parse(d.as_bytes()), Err(ImportError::Malformed { .. })),
        "{:?}",
        parse(d.as_bytes())
    );
}

#[test]
fn entity_and_doctype_variants_are_refused() {
    for d in [
        "<!DOCTYPE objects [<!ENTITY a \"b\">]><objects/>",
        "<!DOCTYPE objects SYSTEM \"file:///etc/passwd\"><objects/>",
        "<objects><cameras>&a;</cameras></objects>",
        "<objects name=\"&a;\"/>",
        "<objects>&#0;</objects>",
        "<objects>&#xD800;</objects>",
        "<objects>&#x110000;</objects>",
        "<objects></object>",
        "<objects><cameras></objects>",
        "<objects/><objects/>",
        "<objects/>trailing",
        "<objects",
        "\u{FEFF}\u{FEFF}<objects/>",
    ] {
        assert!(parse(d.as_bytes()).is_err(), "{d}");
    }
}

#[test]
fn truncation_sweep_never_panics_and_never_drops_a_camera_silently() {
    let full = doc(&format!(
        "{}{}",
        cam(
            1,
            "Porch",
            "<videosourcestring>rtsp://user:secret@192.0.2.10/s</videosourcestring>"
        ),
        cam(
            2,
            "Yard",
            "<videosourcestring>rtsp://192.0.2.11/s</videosourcestring><login>user</login><password>secret</password>"
        ),
    ));
    for len in 0..full.len() {
        let Some(prefix) = full.get(..len) else {
            continue;
        };
        if let Ok(i) = parse(prefix.as_bytes()) {
            panic!("truncated at {len} parsed: {} cameras", i.cameras.len());
        }
    }
}

#[test]
fn utf16_and_latin1_documents_are_refused() {
    let utf16: Vec<u8> = "\u{FEFF}<objects/>"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(parse(&utf16).is_err());
    let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><objects/>";
    assert_eq!(parse(latin1).unwrap_err(), ImportError::UnsupportedEncoding);
}

#[test]
fn whitespace_only_login_is_not_a_credential_over_url_userinfo() {
    // A blank login field should not override real URL userinfo with a blank user.
    let d = doc(&cam(
        1,
        "Porch",
        "<videosourcestring>rtsp://user:secret@192.0.2.10/s</videosourcestring><login> </login><password></password>",
    ));
    let i = parse(d.as_bytes()).expect("parses");
    let cred = i.cameras[0].credential.as_ref().expect("credential");
    assert_eq!(cred.user, "user");
}

#[test]
fn login_field_without_password_does_not_silently_drop_the_url_password() {
    // The URL holds the password; the login field holds only the user. Importing
    // ("user", "") loses the password without any report (P1).
    let d = doc(&cam(
        1,
        "Porch",
        "<videosourcestring>rtsp://user:secret@192.0.2.10/s</videosourcestring><login>user</login><password></password>",
    ));
    let i = parse(d.as_bytes()).expect("parses");
    if let Some(c) = i.cameras.first() {
        let cred = c.credential.as_ref().expect("credential");
        assert_eq!(cred.password.expose_secret(), "secret");
    } else {
        assert_eq!(i.skipped.len(), 1);
    }
}
