//! Adversary tests for #67 (PR #204, round 1). Loopback and TEST-NET only; threads are
//! coordinated with channels, never with sleeps.

use std::net::TcpListener;
use std::sync::mpsc;

use wardenlens_core::camera::{ModelRef, RtspPath, StreamSet};
use wardenlens_index::{CameraRecord, MAX_CAMERAS};

use super::*;

/// A fake camera whose **first** connection is held until the test sends on `release`; the test
/// learns that the connection arrived from `reached`. Later connections are served at once.
struct Gated {
    port: NonZeroU16,
    reached: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
}

fn gated(main_uri: &str, sub_uri: &str) -> Gated {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = NonZeroU16::new(listener.local_addr().unwrap().port()).unwrap();
    let (reached_tx, reached) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let mode = Mode::Cam {
        main_uri: main_uri.to_owned(),
        sub_uri: sub_uri.to_owned(),
    };
    let requests = Mutex::new(Vec::new());
    std::thread::spawn(move || {
        let mut first = true;
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            if first {
                first = false;
                let _ = reached_tx.send(());
                if release_rx.recv().is_err() {
                    return;
                }
            }
            serve(stream, &mode, &requests);
        }
    });
    Gated {
        port,
        reached,
        release,
    }
}

/// Two `camera add` runs for the same id: the second starts while the first is waiting for the
/// camera. `add` promises it never overwrites a registered id ("`remove` it first"), so the run
/// that finishes last must be refused and the camera stored by the other must be untouched.
#[test]
fn a_concurrent_add_of_the_same_id_never_overwrites_the_camera_the_other_one_stored() {
    let site = Site::new();
    let slow = gated(
        "rtsp://127.0.0.1:554/slow_main",
        "rtsp://127.0.0.1:554/slow_sub",
    );
    let quick = cam(
        "rtsp://127.0.0.1:554/quick_main",
        "rtsp://127.0.0.1:554/quick_sub",
    );
    let net = foreign();

    let mut a_slow = args("dup", "127.0.0.1", "reolink/rlc-520a", Some(slow.port));
    a_slow.name = Some("Slow one".to_owned());
    let mut a_quick = args("dup", "127.0.0.1", "reolink/rlc-520a", Some(quick.port()));
    a_quick.name = Some("Quick one".to_owned());

    let (slow_result, quick_result) = std::thread::scope(|s| {
        let site = &site;
        let net = &net;
        let a_slow = &a_slow;
        let handle = s.spawn(move || run_add(site, net, a_slow, "pw-of-the-slow-run\n").result);
        // The slow run has passed its "already registered?" check and waits for the camera.
        slow.reached.recv().unwrap();
        let quick_result = run_add(site, net, &a_quick, "pw-of-the-quick-run\n").result;
        slow.release.send(()).unwrap();
        (handle.join().unwrap(), quick_result)
    });

    quick_result.unwrap();
    assert!(
        matches!(slow_result, Err(CameraCmdError::AlreadyRegistered)),
        "the later add was not refused: {slow_result:?}"
    );
    let cams = site.cameras();
    assert_eq!(cams.len(), 1);
    assert_eq!(
        cams[0].record().streams().main.as_str(),
        "/quick_main",
        "the registry row of the first camera was overwritten"
    );
    let Some(Value::Credential(c)) = site.entry("dup", EntryKind::Credential) else {
        panic!("no credential");
    };
    assert_eq!(
        c.password.expose_secret(),
        "pw-of-the-quick-run",
        "the stored login of the first camera was overwritten"
    );
    let Some(Value::Text(name)) = site.entry("dup", EntryKind::DisplayName) else {
        panic!("no name");
    };
    assert_eq!(name.expose_secret(), "Quick one");
}

/// The module doc of `add`: "Any other failure ... stops the command: guessing paths for a
/// camera that answered would hide a mistake." A camera that answered `GetProfiles` has answered;
/// if it then drops `GetStreamUri`, the catalogue paths must not be guessed for it.
#[test]
fn a_camera_that_answered_get_profiles_is_not_given_catalogue_paths() {
    let site = Site::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = NonZeroU16::new(listener.local_addr().unwrap().port()).unwrap();
    let mode = Mode::Cam {
        main_uri: "rtsp://127.0.0.1:8554/real_main".to_owned(),
        sub_uri: "rtsp://127.0.0.1:8554/real_sub".to_owned(),
    };
    std::thread::spawn(move || {
        let requests = Mutex::new(Vec::new());
        let mut first = true;
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            if first {
                first = false;
                serve(stream, &mode, &requests);
            } else {
                // Accept and close before any answer: a retryable failure, every time.
                drop(stream);
            }
        }
    });
    let a = args("half", "127.0.0.1", "reolink/rlc-520a", Some(port));
    let o = run_add(&site, &foreign(), &a, &pw());
    assert!(
        matches!(o.result, Err(CameraCmdError::Onvif(_))),
        "a camera that answered ONVIF got the catalogue's paths: {:?}, out {:?}",
        o.result,
        o.out
    );
    assert_nothing_stored(&site);
}

/// An IPv6 camera: the vetted address is turned into a client host and probed.
#[test]
fn an_ipv6_camera_is_probed_over_onvif() {
    let Ok(listener) = TcpListener::bind("[::1]:0") else {
        return; // no IPv6 loopback on this machine
    };
    let port = NonZeroU16::new(listener.local_addr().unwrap().port()).unwrap();
    let mode = Mode::Cam {
        main_uri: "rtsp://[::1]:8554/v6_main".to_owned(),
        sub_uri: "rtsp://[::1]:8554/v6_sub".to_owned(),
    };
    std::thread::spawn(move || {
        let requests = Mutex::new(Vec::new());
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            serve(stream, &mode, &requests);
        }
    });
    let site = Site::new();
    let a = args("six", "::1", "reolink/rlc-520a", Some(port));
    let o = run_add(&site, &foreign(), &a, &pw());
    o.result.unwrap();
    assert!(o.out.contains("streams from ONVIF"), "{}", o.out);
    let Some(Value::Text(host)) = site.entry("six", EntryKind::Host) else {
        panic!()
    };
    assert_eq!(host.expose_secret(), "::1");
}

/// A name that resolves to an IPv4-mapped IPv6 address (a resolver with `AI_V4MAPPED`) is a
/// valid camera address that passed the guard; it must be probed, not refused as a bad host.
#[test]
fn a_name_resolving_to_a_mapped_address_is_probed() {
    let site = Site::new();
    let fake = cam(
        "rtsp://127.0.0.1:8554/m_main",
        "rtsp://127.0.0.1:8554/m_sub",
    );
    let net = Fake {
        own: Vec::new(),
        names: vec![("cam.example.invalid", vec![ip("::ffff:127.0.0.1")])],
    };
    let a = args(
        "mapped",
        "cam.example.invalid",
        "reolink/rlc-520a",
        Some(fake.port()),
    );
    let o = run_add(&site, &net, &a, &pw());
    assert!(o.result.is_ok(), "{:?}", o.result);
}

/// A sub stream with a query the catalogue does not list refuses the add before any vault write.
#[test]
fn a_sub_stream_query_the_catalogue_does_not_list_stores_nothing() {
    let site = Site::new();
    let fake = cam(
        "rtsp://127.0.0.1:554/live",
        "rtsp://127.0.0.1:554/live2?evil=1",
    );
    let a = args("cam-a", "127.0.0.1", "reolink/rlc-520a", Some(fake.port()));
    let o = run_add(&site, &foreign(), &a, &pw());
    assert!(
        matches!(o.result, Err(CameraCmdError::PathQuery)),
        "{:?}",
        o.result
    );
    assert_nothing_stored(&site);
}

/// The registry refuses the row (it is full): the vault entries just written are removed again,
/// and nothing of the cameras already registered is touched.
#[test]
fn a_registry_refusal_rolls_the_vault_back_and_touches_no_other_camera() {
    let site = Site::new();
    add_closed(&site, "keep", "reolink/rlc-520a");
    let entries = catalogue().unwrap();
    let mut index = Index::open(site.config.database_path()).unwrap();
    let model = ModelRef::new("reolink", "rlc-520a").unwrap();
    let t = now().unwrap();
    for n in 1..MAX_CAMERAS {
        let record = CameraRecord::new(
            CameraId::new(&format!("filler-{n:04}")).unwrap(),
            model.clone(),
            NonZeroU16::new(554).unwrap(),
            StreamSet::new(RtspPath::new("/m").unwrap(), None),
        );
        index.upsert_camera(&record, &entries, t).unwrap();
    }
    drop(index);
    let before = site.vault().list().unwrap().len();
    let a = args(
        "one-too-many",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    let err = run_add(&site, &foreign(), &a, &pw()).result.unwrap_err();
    assert!(matches!(err, CameraCmdError::Index(_)), "{err:?}");
    for kind in [
        EntryKind::Credential,
        EntryKind::Host,
        EntryKind::DisplayName,
    ] {
        assert!(
            site.entry("one-too-many", kind).is_none(),
            "{kind:?} left behind"
        );
        assert!(
            site.entry("keep", kind).is_some(),
            "{kind:?} of another camera removed"
        );
    }
    assert_eq!(site.vault().list().unwrap().len(), before);
}

/// `remove` deletes exactly one id, even when other ids share its prefix.
#[test]
fn remove_spares_ids_that_share_a_prefix() {
    let site = Site::new();
    for id in ["yar", "yard", "yard-2", "yard2"] {
        add_closed(&site, id, "reolink/rlc-520a");
    }
    remove(&site.config, "yard", &mut Scripted::piped("")).unwrap();
    let ids: Vec<String> = site
        .cameras()
        .iter()
        .map(|c| c.record().id().to_string())
        .collect();
    assert_eq!(ids, ["yar", "yard-2", "yard2"]);
    for id in ["yar", "yard-2", "yard2"] {
        for kind in [
            EntryKind::Credential,
            EntryKind::Host,
            EntryKind::DisplayName,
        ] {
            assert!(site.entry(id, kind).is_some(), "{id} {kind:?}");
        }
    }
    assert_eq!(site.vault().list().unwrap().len(), 9);
}

/// The display cap is exact: 256 characters are shown whole, 257 are cut; an escaped character
/// counts once.
#[test]
fn display_safe_cuts_at_exactly_256_characters() {
    let at = "x".repeat(256);
    assert_eq!(guard::display_safe(&at), at);
    let over = guard::display_safe(&"x".repeat(257));
    assert_eq!(over, format!("{at}..."));
    let escaped = guard::display_safe(&"\u{202e}".repeat(257));
    assert_eq!(escaped, format!("{}...", "\\u{202e}".repeat(256)));
    assert!(escaped.bytes().all(|b| (0x20..0x7f).contains(&b)));
}
