//! Adversary tests for #163 / #207 (PR #213, round 1): `import` against rows `camera add` made.

use super::*;

const LISTED: &str = "/cam/realmonitor?channel=1&amp;subtype=0";

fn import_ready(model: &str, host: &str) -> Vec<crate::commands::import::Ready> {
    let xml = format!(
        "<objects><cameras><camera id=\"1\" name=\"Imported Cam\"><settings>\
         <videosourcestring>rtsp://{host}:554{LISTED}</videosourcestring>\
         <login>other-user-x</login><password>other-pass-x</password></settings>\
         </camera></cameras></objects>"
    );
    let parsed = wardenlens_agentdvr::parse(xml.as_bytes()).unwrap();
    let (v, m) = model.split_once('/').unwrap();
    vec![crate::commands::import::Ready {
        draft: parsed.cameras[0].clone(),
        model: ModelRef::new(v, m).unwrap(),
    }]
}

/// #207: a hand-added camera under `agentdvr-1` must keep its host, name and login when an
/// `objects.xml` camera 1 of the same model is imported. Round 2: the registry has no provenance,
/// so the guarantee is that no such camera can exist: `camera add` refuses the reserved prefix
/// (the scenario of the round-1 test), before it prompts, connects or writes. The expectation is
/// the original one, that the hand-added camera's vault entries are never replaced, now met by
/// refusal; an import over a row that predates the reservation cannot be told apart.
#[test]
fn import_never_overwrites_a_hand_added_camera_of_the_same_model() {
    let site = Site::new();
    let a = args(
        "agentdvr-1",
        "127.0.0.1",
        "dahua/ipc-hfw4431r-z",
        Some(closed_port()),
    );
    let o = run_add(&site, &foreign(), &a, &pw());
    assert!(matches!(o.result, Err(CameraCmdError::ReservedId)));
    assert_eq!(o.input_left, pw().len(), "nothing was prompted");
    assert!(site.files().iter().all(|f| !f.contains("vault")));
    assert_eq!(site.cameras().len(), 0);
    // The import then creates the row itself: its own, not a hand-added one.
    let catalogue = crate::commands::camera::catalogue().unwrap();
    let key = wardenlens_secrets::KeyFile::load(site.config.key_file()).unwrap();
    let rows = crate::commands::import::write_all(
        &site.config,
        key,
        &import_ready("dahua/ipc-hfw4431r-z", "198.51.100.9"),
        &catalogue,
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(site.entry("agentdvr-1", EntryKind::Host).is_some());
}
