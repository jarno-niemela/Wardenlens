//! End-to-end tests of `camera add|list|remove` over a loopback fake ONVIF camera, a temp
//! registry and a temp vault. Addresses are loopback (the fake) or TEST-NET; nothing leaves the
//! machine and nothing reads the real config or vault.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use secrecy::ExposeSecret;
use wardenlens_core::camera::{CameraId, ModelRef};
use wardenlens_core::connection::Backoff;
use wardenlens_core::time::DurationMs;
use wardenlens_onvif::ClientConfig;

use super::add::{Services, add};
use super::guard::testing::Fake;
use super::password::tests::Scripted;
use super::*;
use crate::args::{AddArgs, Cli, Command};
use crate::commands::serve::camera_inputs;

const PASSWORD: &str = "sentinel-pw-0451";
const USER: &str = "sentinel-user";

// ---- the fake camera ----

const NS: &str = r#"xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema""#;

fn envelope(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><env:Envelope {NS}><env:Body>{body}</env:Body></env:Envelope>"#
    )
}

fn profile(token: &str, w: u32, h: u32) -> String {
    format!(
        r#"<trt:Profiles fixed="true" token="{token}"><tt:Name>{token}</tt:Name><tt:VideoEncoderConfiguration token="ve"><tt:Name>e</tt:Name><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>{w}</tt:Width><tt:Height>{h}</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>"#
    )
}

#[derive(Clone)]
enum Mode {
    /// Two profiles; stream URIs `main_uri` and `sub_uri`.
    Cam { main_uri: String, sub_uri: String },
    /// A SOAP fault that says the login was refused.
    NotAuthorized,
}

struct FakeCamera {
    addr: std::net::SocketAddr,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl FakeCamera {
    fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (a, r, s) = (accepted.clone(), requests.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { return };
                a.fetch_add(1, Ordering::SeqCst);
                serve(stream, &mode, &r);
            }
        });
        Self {
            addr,
            accepted,
            requests,
            stop,
        }
    }

    fn port(&self) -> NonZeroU16 {
        NonZeroU16::new(self.addr.port()).unwrap()
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn all_requests(&self) -> String {
        self.requests.lock().unwrap().join("\n")
    }
}

impl Drop for FakeCamera {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve(mut stream: TcpStream, mode: &Mode, requests: &Mutex<Vec<String>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let text = loop {
        let Ok(n) = stream.read(&mut chunk) else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text[..end]
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if buf.len() >= end.saturating_add(4).saturating_add(len) {
                break text;
            }
        }
    };
    requests.lock().unwrap().push(text.clone());
    let body = match mode {
        Mode::NotAuthorized => envelope(
            "<env:Fault><env:Code><env:Value>env:Sender</env:Value><env:Subcode><env:Value>ter:NotAuthorized</env:Value></env:Subcode></env:Code><env:Reason><env:Text xml:lang=\"en\">no</env:Text></env:Reason></env:Fault>",
        ),
        Mode::Cam { main_uri, sub_uri } => {
            if text.contains("GetProfiles") {
                envelope(&format!(
                    "<trt:GetProfilesResponse>{}{}</trt:GetProfilesResponse>",
                    profile("main_tok", 2560, 1440),
                    profile("sub_tok", 640, 360)
                ))
            } else {
                let uri = if text.contains("sub_tok") {
                    sub_uri
                } else {
                    main_uri
                };
                envelope(&format!(
                    "<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>{uri}</tt:Uri><tt:InvalidAfterConnect>false</tt:InvalidAfterConnect></trt:MediaUri></trt:GetStreamUriResponse>"
                ))
            }
        }
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

fn cam(main_uri: &str, sub_uri: &str) -> FakeCamera {
    FakeCamera::start(Mode::Cam {
        main_uri: main_uri.to_owned(),
        sub_uri: sub_uri.to_owned(),
    })
}

/// A port that nothing listens on: every connect is refused at once.
fn closed_port() -> NonZeroU16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    NonZeroU16::new(l.local_addr().unwrap().port()).unwrap()
}

// ---- the site ----

struct Site {
    _dir: tempfile::TempDir,
    config: Config,
}

impl Site {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path().display().to_string();
        for d in ["state", "keys"] {
            let p = dir.path().join(d);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = Config::from_toml_str(&format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n"
        ))
        .unwrap();
        KeyFile::generate(config.key_file()).unwrap();
        Self { _dir: dir, config }
    }

    fn key(&self) -> KeyFile {
        KeyFile::load(self.config.key_file()).unwrap()
    }

    fn vault(&self) -> Vault {
        Vault::open(&vault_path(&self.config), self.key()).unwrap()
    }

    fn entry(&self, id: &str, kind: EntryKind) -> Option<Value> {
        let entry_id = CameraId::new(id).unwrap().entry_id(kind).unwrap();
        self.vault().get(&entry_id).unwrap().map(|e| e.value)
    }

    fn cameras(&self) -> Vec<wardenlens_index::StoredCamera> {
        Index::open(self.config.database_path())
            .unwrap()
            .list_cameras(&catalogue().unwrap())
            .unwrap()
    }

    fn files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.config.database_path().parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

fn fast() -> ClientConfig {
    let mut c = ClientConfig::default();
    c.connect_timeout = Duration::from_secs(5);
    c.request_timeout = Duration::from_secs(5);
    c.backoff = Backoff::new(DurationMs::from_millis(1), DurationMs::from_millis(1));
    c
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// The machine owns nothing, so loopback is the fake camera.
fn foreign() -> Fake {
    Fake {
        own: Vec::new(),
        names: Vec::new(),
    }
}

fn args(id: &str, host: &str, model: &str, onvif_port: Option<NonZeroU16>) -> AddArgs {
    AddArgs {
        id: id.to_owned(),
        host: host.to_owned(),
        model: model.to_owned(),
        username: USER.to_owned(),
        onvif_port,
        name: None,
    }
}

struct Outcome {
    result: Result<(), CameraCmdError>,
    out: String,
    err: String,
    input_left: usize,
}

fn run_add(site: &Site, net: &Fake, a: &AddArgs, stdin: &str) -> Outcome {
    let mut term = Scripted::piped(stdin);
    let services = Services {
        network: net,
        client: fast(),
        clock: now,
    };
    let result = add(&site.config, a, &mut term, &services);
    Outcome {
        result,
        out: String::from_utf8(term.out.clone()).unwrap(),
        err: String::from_utf8(term.err.clone()).unwrap(),
        input_left: term.input.len(),
    }
}

fn pw() -> String {
    format!("{PASSWORD}\n")
}

fn assert_nothing_stored(site: &Site) {
    if std::fs::symlink_metadata(site.config.database_path()).is_ok() {
        assert_eq!(site.cameras().len(), 0);
    }
    if std::fs::symlink_metadata(vault_path(&site.config)).is_ok() {
        assert_eq!(site.vault().list().unwrap().len(), 0);
    }
}

// ---- add: ONVIF success ----

#[test]
fn add_asks_onvif_for_both_streams_and_serve_reads_the_camera_back() {
    let site = Site::new();
    let fake = cam(
        "rtsp://127.0.0.1:8554/onvif_main",
        "rtsp://127.0.0.1:8554/onvif_sub",
    );
    let a = args(
        "front-door",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(fake.port()),
    );
    let o = run_add(&site, &foreign(), &a, &pw());
    o.result.unwrap();
    assert_eq!(
        o.out,
        "added front-door: model reolink/rlc-520a, port 8554, main /onvif_main, sub /onvif_sub (streams from ONVIF)\n"
    );
    assert_eq!(o.err, "");

    // The registry holds what the camera said, not the catalogue.
    let cams = site.cameras();
    assert_eq!(cams.len(), 1);
    let r = cams[0].record();
    assert_eq!(r.id().as_str(), "front-door");
    assert_eq!(r.model().to_string(), "reolink/rlc-520a");
    assert_eq!(r.port().get(), 8554);
    assert_eq!(r.streams().main.as_str(), "/onvif_main");
    assert_eq!(r.streams().sub.as_ref().unwrap().as_str(), "/onvif_sub");

    // The vault holds the sealed host, name and login under the names `import` and `serve` use.
    let Some(Value::Credential(c)) = site.entry("front-door", EntryKind::Credential) else {
        panic!("no credential entry");
    };
    assert_eq!(c.username, USER);
    assert_eq!(c.password.expose_secret(), PASSWORD);
    let Some(Value::Text(host)) = site.entry("front-door", EntryKind::Host) else {
        panic!("no host entry");
    };
    assert_eq!(host.expose_secret(), "127.0.0.1");
    let Some(Value::Text(name)) = site.entry("front-door", EntryKind::DisplayName) else {
        panic!("no name entry");
    };
    assert_eq!(name.expose_secret(), "front-door");

    // `serve`'s own loader picks the camera up.
    let index = Index::open(site.config.database_path()).unwrap();
    let inputs = camera_inputs(&site.config, &index, site.key()).unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].camera.id().as_str(), "front-door");
    assert_eq!(inputs[0].camera.port().get(), 8554);
    assert_eq!(inputs[0].camera.name().expose(), "front-door");

    // The password went to the camera only as a digest, never in clear.
    let wire = fake.all_requests();
    assert!(wire.contains("GetProfiles") && wire.contains("GetStreamUri"));
    assert!(wire.contains(USER));
    assert!(!wire.contains(PASSWORD));
    // Nothing printed holds a secret.
    assert!(!o.out.contains(PASSWORD) && !o.out.contains(USER));
}

#[test]
fn a_display_name_is_stored_and_a_sub_stream_on_another_port_is_left_out() {
    let site = Site::new();
    let fake = cam(
        "rtsp://127.0.0.1:8554/onvif_main",
        "rtsp://127.0.0.1:9554/onvif_sub",
    );
    let mut a = args("garage", "127.0.0.1", "reolink/rlc-520a", Some(fake.port()));
    a.name = Some("Garage side".to_owned());
    let o = run_add(&site, &foreign(), &a, &pw());
    o.result.unwrap();
    assert!(o.out.contains("sub none"), "{}", o.out);
    assert!(o.err.contains("another port"), "{}", o.err);
    assert!(site.cameras()[0].record().streams().sub.is_none());
    let Some(Value::Text(name)) = site.entry("garage", EntryKind::DisplayName) else {
        panic!()
    };
    assert_eq!(name.expose_secret(), "Garage side");
}

#[test]
fn a_main_path_that_carries_a_login_is_refused_and_nothing_is_stored() {
    let site = Site::new();
    let fake = cam(
        "rtsp://127.0.0.1:554/live?user=a&password=b",
        "rtsp://127.0.0.1:554/live2",
    );
    let a = args("cam-a", "127.0.0.1", "reolink/rlc-520a", Some(fake.port()));
    let o = run_add(&site, &foreign(), &a, &pw());
    assert!(
        matches!(o.result, Err(CameraCmdError::Onvif(_))),
        "{:?}",
        o.result
    );
    assert_nothing_stored(&site);
}

#[test]
fn a_query_the_catalogue_does_not_list_is_refused_before_the_vault_is_written() {
    let site = Site::new();
    let fake = cam(
        "rtsp://127.0.0.1:554/live?channel=2",
        "rtsp://127.0.0.1:554/live2",
    );
    let a = args("cam-a", "127.0.0.1", "reolink/rlc-520a", Some(fake.port()));
    let o = run_add(&site, &foreign(), &a, &pw());
    let err = o.result.unwrap_err();
    assert!(matches!(err, CameraCmdError::PathQuery), "{err:?}");
    assert_eq!(err.exit_code(), 1);
    assert_nothing_stored(&site);
}

// ---- add: the fallback ----

#[test]
fn an_unreachable_camera_gets_the_catalogue_paths() {
    let site = Site::new();
    let a = args("yard", "127.0.0.1", "reolink/rlc-520a", Some(closed_port()));
    let o = run_add(&site, &foreign(), &a, &pw());
    o.result.unwrap();
    assert_eq!(
        o.out,
        "added yard: model reolink/rlc-520a, port 554, main /h264Preview_01_main, sub /h264Preview_01_sub (streams from catalogue)\n"
    );
    assert!(o.err.contains("did not answer ONVIF"), "{}", o.err);
    let r = site.cameras();
    let r = r[0].record();
    assert_eq!(r.port().get(), 554);
    assert_eq!(r.streams().main.as_str(), "/h264Preview_01_main");
    assert_eq!(
        r.streams().sub.as_ref().unwrap().as_str(),
        "/h264Preview_01_sub"
    );
    let index = Index::open(site.config.database_path()).unwrap();
    assert_eq!(
        camera_inputs(&site.config, &index, site.key())
            .unwrap()
            .len(),
        1
    );
}

/// The catalogue's query strings are listed, so a Dahua camera can be stored from them.
#[test]
fn the_fallback_stores_a_catalogue_path_with_its_listed_query() {
    let site = Site::new();
    let a = args(
        "lawn",
        "127.0.0.1",
        "dahua/ipc-hfw4431r-z",
        Some(closed_port()),
    );
    run_add(&site, &foreign(), &a, &pw()).result.unwrap();
    let cams = site.cameras();
    assert_eq!(
        cams[0].record().streams().main.as_str(),
        "/cam/realmonitor?channel=1&subtype=0"
    );
    // `serve` lists the registry with the catalogue too, so the stored query does not break it.
    let index = Index::open(site.config.database_path()).unwrap();
    let inputs = camera_inputs(&site.config, &index, site.key()).unwrap();
    assert_eq!(inputs.len(), 1);
}

/// Only an unreachable camera falls back: one that answered and refused the login is an error,
/// and nothing is stored.
#[test]
fn a_refused_login_is_an_error_not_a_fallback() {
    let site = Site::new();
    let fake = FakeCamera::start(Mode::NotAuthorized);
    let a = args("cam-a", "127.0.0.1", "reolink/rlc-520a", Some(fake.port()));
    let o = run_add(&site, &foreign(), &a, &pw());
    let err = o.result.unwrap_err();
    assert!(
        matches!(err, CameraCmdError::Onvif(OnvifError::NotAuthorized)),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 1);
    assert_nothing_stored(&site);
}

// ---- add: refusals before any request ----

#[test]
fn own_and_metadata_addresses_are_refused_before_any_connection_or_prompt() {
    let site = Site::new();
    let fake = cam("rtsp://127.0.0.1:554/a", "rtsp://127.0.0.1:554/b");
    let net = Fake {
        own: vec![ip("127.0.0.1")],
        names: vec![("self.example.invalid", vec![ip("127.0.0.1")])],
    };
    for host in ["127.0.0.1", "169.254.169.254", "self.example.invalid"] {
        let a = args("cam-a", host, "reolink/rlc-520a", Some(fake.port()));
        let o = run_add(&site, &net, &a, &pw());
        let err = o.result.unwrap_err();
        assert!(matches!(err, CameraCmdError::Guard(_)), "{host}: {err:?}");
        assert_eq!(err.exit_code(), 1);
        assert_eq!(o.input_left, pw().len(), "the password was read for {host}");
    }
    assert_eq!(fake.accepted(), 0, "a connection was made");
    assert_nothing_stored(&site);
}

#[test]
fn the_real_network_refuses_loopback_in_the_command() {
    let site = Site::new();
    let fake = cam("rtsp://127.0.0.1:554/a", "rtsp://127.0.0.1:554/b");
    let a = args("cam-a", "127.0.0.1", "reolink/rlc-520a", Some(fake.port()));
    let mut term = Scripted::piped(&pw());
    let services = Services {
        network: &guard::SystemNetwork,
        client: fast(),
        clock: now,
    };
    let err = add(&site.config, &a, &mut term, &services).unwrap_err();
    assert!(matches!(err, CameraCmdError::Guard(_)), "{err:?}");
    assert_eq!(fake.accepted(), 0);
}

#[test]
fn bad_arguments_and_logins_stop_before_any_connection_or_write() {
    let site = Site::new();
    let fake = cam("rtsp://127.0.0.1:554/a", "rtsp://127.0.0.1:554/b");
    let port = Some(fake.port());
    let model = "reolink/rlc-520a";
    let cases: Vec<(AddArgs, String)> = vec![
        (args("Bad Id", "127.0.0.1", model, port), pw()),
        (args("", "127.0.0.1", model, port), pw()),
        (args("cam-a", "not a host", model, port), pw()),
        (args("cam-a", "127.0.0.1", "reolink", port), pw()),
        (args("cam-a", "127.0.0.1", "acme/none", port), pw()),
        (args("cam-a", "127.0.0.1", model, port), String::new()),
        (args("cam-a", "127.0.0.1", model, port), "a\nb\n".to_owned()),
        (
            AddArgs {
                username: String::new(),
                ..args("cam-a", "127.0.0.1", model, port)
            },
            pw(),
        ),
        (
            AddArgs {
                name: Some(" ".to_owned()),
                ..args("cam-a", "127.0.0.1", model, port)
            },
            pw(),
        ),
    ];
    for (a, stdin) in cases {
        let o = run_add(&site, &foreign(), &a, &stdin);
        let err = o.result.unwrap_err();
        assert_eq!(err.exit_code(), 1, "{a:?}: {err:?}");
    }
    assert_eq!(fake.accepted(), 0);
    assert_eq!(site.files().len(), 0, "{:?}", site.files());
}

#[test]
fn an_unknown_model_is_unknown_model() {
    let site = Site::new();
    let o = run_add(
        &site,
        &foreign(),
        &args("cam-a", "127.0.0.1", "acme/none", None),
        &pw(),
    );
    assert!(matches!(o.result, Err(CameraCmdError::UnknownModel)));
}

#[test]
fn a_missing_key_file_points_at_secrets_init() {
    let site = Site::new();
    std::fs::remove_file(site.config.key_file()).unwrap();
    let a = args(
        "cam-a",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    let err = run_add(&site, &foreign(), &a, &pw()).result.unwrap_err();
    assert!(matches!(err, CameraCmdError::KeyMissing { .. }), "{err:?}");
    assert!(err.to_string().contains("secrets init"));
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn an_id_that_exists_is_never_overwritten() {
    let site = Site::new();
    let a = args(
        "cam-a",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    run_add(&site, &foreign(), &a, &pw()).result.unwrap();
    let before = site.cameras();
    let fake = cam("rtsp://127.0.0.1:1554/x", "rtsp://127.0.0.1:1554/y");
    let b = args(
        "cam-a",
        "127.0.0.1",
        "dahua/ipc-hfw4431r-z",
        Some(fake.port()),
    );
    let err = run_add(&site, &foreign(), &b, "other-pw\n")
        .result
        .unwrap_err();
    assert!(matches!(err, CameraCmdError::AlreadyRegistered), "{err:?}");
    assert_eq!(err.exit_code(), 1);
    assert_eq!(fake.accepted(), 0);
    assert_eq!(site.cameras(), before);
    let Some(Value::Credential(c)) = site.entry("cam-a", EntryKind::Credential) else {
        panic!()
    };
    assert_eq!(c.password.expose_secret(), PASSWORD);
}

// ---- the grammar ----

/// The password has no argument: a value on argv is a usage error, whatever the spelling.
#[test]
fn the_password_cannot_be_given_on_the_command_line() {
    let base = [
        "wardenlens",
        "camera",
        "add",
        "--id",
        "a",
        "--host",
        "h",
        "--model",
        "x/y",
        "--username",
        "u",
    ];
    assert!(Cli::try_parse_from(base).is_ok());
    for extra in [
        ["--password", "p"],
        ["--pass", "p"],
        ["--pw", "p"],
        ["-p", "p"],
    ] {
        let mut argv = base.to_vec();
        argv.extend(extra);
        assert!(Cli::try_parse_from(argv).is_err(), "{extra:?}");
    }
    let cli = Cli::try_parse_from(base).unwrap();
    let Some(Command::Camera(crate::args::CameraCommand::Add(a))) = cli.command else {
        panic!()
    };
    assert_eq!(a.onvif_port, None);
    // A port of zero cannot be built.
    let mut zero = base.to_vec();
    zero.extend(["--onvif-port", "0"]);
    assert!(Cli::try_parse_from(zero).is_err());
}

// ---- list and remove ----

fn add_closed(site: &Site, id: &str, model: &str) {
    let a = args(id, "127.0.0.1", model, Some(closed_port()));
    run_add(site, &foreign(), &a, &pw()).result.unwrap();
}

fn list_out(site: &Site) -> (String, String) {
    let mut term = Scripted::piped("");
    list(&site.config, &mut term).unwrap();
    (
        String::from_utf8(term.out).unwrap(),
        String::from_utf8(term.err).unwrap(),
    )
}

#[test]
fn list_shows_id_model_and_host_and_never_a_login() {
    let site = Site::new();
    let (out, _) = list_out(&site);
    assert_eq!(out, "no cameras are registered\n");
    assert_eq!(site.files().len(), 0, "list created files");

    add_closed(&site, "yard", "reolink/rlc-520a");
    add_closed(&site, "lawn", "dahua/ipc-hfw4431r-z");
    let (out, err) = list_out(&site);
    assert_eq!(err, "");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(lines[0].starts_with("ID") && lines[0].contains("MODEL") && lines[0].contains("HOST"));
    assert!(
        lines[1].starts_with("lawn")
            && lines[1].contains("dahua/ipc-hfw4431r-z")
            && lines[1].ends_with("127.0.0.1"),
        "{out}"
    );
    assert!(
        lines[2].starts_with("yard")
            && lines[2].contains("reolink/rlc-520a")
            && lines[2].ends_with("127.0.0.1"),
        "{out}"
    );
    assert!(!out.contains(USER) && !out.contains(PASSWORD));
}

#[test]
fn list_without_a_usable_vault_still_lists_and_says_so() {
    let site = Site::new();
    add_closed(&site, "yard", "reolink/rlc-520a");
    std::fs::remove_file(site.config.key_file()).unwrap();
    let (out, err) = list_out(&site);
    assert!(
        out.contains("yard") && out.trim_end().ends_with('-'),
        "{out}"
    );
    assert!(err.contains("hosts not shown"), "{err}");
}

#[test]
fn remove_deletes_the_row_and_every_vault_entry_and_only_that_camera() {
    let site = Site::new();
    add_closed(&site, "yard", "reolink/rlc-520a");
    add_closed(&site, "lawn", "dahua/ipc-hfw4431r-z");
    let mut term = Scripted::piped("");
    remove(&site.config, "yard", &mut term).unwrap();
    assert_eq!(
        String::from_utf8(term.out).unwrap(),
        "removed yard; its recordings were not deleted\n"
    );
    let ids: Vec<String> = site
        .cameras()
        .iter()
        .map(|c| c.record().id().to_string())
        .collect();
    assert_eq!(ids, ["lawn"]);
    for kind in [
        EntryKind::Credential,
        EntryKind::Host,
        EntryKind::DisplayName,
    ] {
        assert!(site.entry("yard", kind).is_none(), "{kind:?}");
        assert!(site.entry("lawn", kind).is_some(), "{kind:?}");
    }
    let index = Index::open(site.config.database_path()).unwrap();
    assert_eq!(
        camera_inputs(&site.config, &index, site.key())
            .unwrap()
            .len(),
        1
    );
    // One handle per index file per process (#148): release this one before `add` opens it.
    drop(index);
    // The id can be added again.
    add_closed(&site, "yard", "reolink/rlc-520a");
    assert_eq!(site.cameras().len(), 2);
}

#[test]
fn remove_of_an_unknown_id_is_not_found_and_creates_nothing() {
    let site = Site::new();
    let err = remove(&site.config, "nobody", &mut Scripted::piped("")).unwrap_err();
    assert!(matches!(err, CameraCmdError::NotFound));
    assert_eq!(err.exit_code(), 1);
    assert_eq!(site.files().len(), 0);
    add_closed(&site, "yard", "reolink/rlc-520a");
    let err = remove(&site.config, "nobody", &mut Scripted::piped("")).unwrap_err();
    assert!(matches!(err, CameraCmdError::NotFound));
    assert_eq!(site.cameras().len(), 1);
    let err = remove(&site.config, "Bad Id", &mut Scripted::piped("")).unwrap_err();
    assert!(matches!(err, CameraCmdError::Camera(_)));
}

/// A remove that failed after the row went leaves vault entries; running it again cleans them.
#[test]
fn remove_cleans_vault_entries_that_have_no_row() {
    let site = Site::new();
    add_closed(&site, "yard", "reolink/rlc-520a");
    Index::open(site.config.database_path())
        .unwrap()
        .remove_camera(&CameraId::new("yard").unwrap())
        .unwrap();
    remove(&site.config, "yard", &mut Scripted::piped("")).unwrap();
    assert!(site.entry("yard", EntryKind::Credential).is_none());
    assert!(site.entry("yard", EntryKind::Host).is_none());
    assert!(matches!(
        remove(&site.config, "yard", &mut Scripted::piped("")),
        Err(CameraCmdError::NotFound)
    ));
}

// ---- exit codes ----

#[test]
fn exit_codes_follow_the_table() {
    assert_eq!(CameraCmdError::UnknownModel.exit_code(), 1);
    // A full registry and a duplicate id are refusals; any other registry error is a failure.
    assert_eq!(
        CameraCmdError::Index(IndexError::TooManyCameras { max: 1 }).exit_code(),
        1
    );
    assert_eq!(
        CameraCmdError::Index(IndexError::CameraExists).exit_code(),
        1
    );
    assert_eq!(CameraCmdError::Index(IndexError::Damaged).exit_code(), 2);
    assert_eq!(CameraCmdError::NotFound.exit_code(), 1);
    assert_eq!(CameraCmdError::NoCataloguePaths.exit_code(), 1);
    assert_eq!(CameraCmdError::Clock.exit_code(), 2);
    assert_eq!(
        CameraCmdError::Discovery(DiscoveryError::Random).exit_code(),
        2
    );
    assert_eq!(
        CameraCmdError::Password(PasswordError::Empty).exit_code(),
        1
    );
    assert_eq!(
        CameraCmdError::Credential(CredentialRule::Nul).exit_code(),
        1
    );
}

// ---- the other error variants ----

/// A terminal whose output always fails, as a closed pipe does.
struct Broken;

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Terminal for Broken {
    fn stdin_is_tty(&self) -> bool {
        false
    }
    fn stdout_kind(&self) -> crate::terminal::StdoutKind {
        crate::terminal::StdoutKind::Pipe
    }
    fn prompt_secret(&mut self, _: &str) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    fn read_piped(&mut self, _: usize) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
        Ok(zeroize::Zeroizing::new(pw().into_bytes()))
    }
    fn stream(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        unreachable!("not used by camera commands")
    }
    fn out(&mut self) -> &mut dyn Write {
        Box::leak(Box::new(FailingWriter))
    }
    fn err(&mut self) -> &mut dyn Write {
        Box::leak(Box::new(FailingWriter))
    }
}

#[test]
fn a_closed_stdout_is_exit_2_for_list_and_remove_but_not_for_a_stored_add() {
    let site = Site::new();
    add_closed(&site, "yard", "reolink/rlc-520a");
    let err = list(&site.config, &mut Broken).unwrap_err();
    assert!(matches!(err, CameraCmdError::Output(_)), "{err:?}");
    assert_eq!(err.exit_code(), 2);
    let err = remove(&site.config, "yard", &mut Broken).unwrap_err();
    assert!(matches!(err, CameraCmdError::Output(_)), "{err:?}");
    // The removal itself was done before the report failed.
    assert_eq!(site.cameras().len(), 0);
    // `add` has stored the camera when it prints, so a closed stdout is not an error exit.
    let a = args("lawn", "127.0.0.1", "reolink/rlc-520a", Some(closed_port()));
    let services = Services {
        network: &foreign(),
        client: fast(),
        clock: now,
    };
    add(&site.config, &a, &mut Broken, &services).unwrap();
    assert_eq!(site.cameras().len(), 1);
}

/// A vault file that is not ours is refused and left byte for byte as it was; the add stores
/// no camera (P3).
#[test]
fn a_foreign_vault_file_is_refused_and_untouched() {
    let site = Site::new();
    let path = vault_path(&site.config);
    let junk = b"not a vault, SQLite format 3? no".to_vec();
    std::fs::write(&path, &junk).unwrap();
    let a = args(
        "cam-a",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    let err = run_add(&site, &foreign(), &a, &pw()).result.unwrap_err();
    assert!(matches!(err, CameraCmdError::Vault(_)), "{err:?}");
    assert_eq!(err.exit_code(), 2);
    assert_eq!(std::fs::read(&path).unwrap(), junk);
    assert_eq!(site.cameras().len(), 0);
    // `remove` and `list` refuse it the same way and do not write to it.
    let err = remove(&site.config, "cam-a", &mut Scripted::piped("")).unwrap_err();
    assert!(matches!(err, CameraCmdError::Vault(_)), "{err:?}");
    assert_eq!(std::fs::read(&path).unwrap(), junk);
}

#[test]
fn a_foreign_index_file_is_refused_and_untouched() {
    let site = Site::new();
    let junk = b"this is not an index".to_vec();
    std::fs::write(site.config.database_path(), &junk).unwrap();
    let err = list(&site.config, &mut Scripted::piped("")).unwrap_err();
    assert!(matches!(err, CameraCmdError::Index(_)), "{err:?}");
    assert_eq!(err.exit_code(), 2);
    let a = args(
        "cam-a",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    let err = run_add(&site, &foreign(), &a, &pw()).result.unwrap_err();
    assert!(matches!(err, CameraCmdError::Index(_)), "{err:?}");
    assert_eq!(std::fs::read(site.config.database_path()).unwrap(), junk);
}

#[test]
fn a_bad_key_file_is_a_key_error() {
    let site = Site::new();
    std::fs::write(site.config.key_file(), b"short").unwrap();
    std::fs::set_permissions(
        site.config.key_file(),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let a = args(
        "cam-a",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    let err = run_add(&site, &foreign(), &a, &pw()).result.unwrap_err();
    assert!(matches!(err, CameraCmdError::Key(_)), "{err:?}");
    assert_eq!(err.exit_code(), 2);
}

/// Every message is a fixed text: no host, login or path of the camera is in any error.
#[test]
fn errors_never_carry_the_inputs() {
    let site = Site::new();
    let mut a = args("cam-a", "169.254.169.254", "reolink/rlc-520a", None);
    a.username = "user-sentinel-zz".to_owned();
    let err = run_add(&site, &foreign(), &a, "pw-sentinel-zz\n")
        .result
        .unwrap_err();
    let text = error_chain(&err);
    for secret in ["169.254.169.254", "user-sentinel-zz", "pw-sentinel-zz"] {
        assert!(!text.contains(secret), "{text}");
    }
    let dbg = format!("{err:?}");
    assert!(
        !dbg.contains("pw-sentinel-zz") && !dbg.contains("user-sentinel-zz"),
        "{dbg}"
    );
}

// ---- round 2: rollback, clock, password order ----

/// A vault whose `set` fails on the `fail_on`-th call (1-based) and records what is removed.
struct FailingVault {
    inner: Vault,
    calls: usize,
    fail_on: usize,
}

impl add::VaultOps for FailingVault {
    fn set(
        &mut self,
        id: &wardenlens_core::entry::EntryId,
        kind: EntryKind,
        value: &Value,
    ) -> Result<(), VaultError> {
        self.calls = self.calls.saturating_add(1);
        if self.calls == self.fail_on {
            return Err(VaultError::TooManyEntries);
        }
        wardenlens_vault::Vault::set(
            &mut self.inner,
            id,
            kind,
            value,
            wardenlens_vault::Scan::Normal,
        )
        .map(drop)
    }
    fn rm(&mut self, id: &wardenlens_core::entry::EntryId) -> Result<bool, VaultError> {
        self.inner.rm(id)
    }
}

/// A failure at each of the three vault writes removes the entries this run wrote and its own
/// registry row, and no other camera is touched.
#[test]
fn a_vault_failure_part_way_removes_this_runs_row_and_entries_only() {
    for fail_on in 1..=3 {
        let site = Site::new();
        add_closed(&site, "keep", "reolink/rlc-520a");
        let before = site.vault().list().unwrap().len();
        let entries = catalogue().unwrap();
        let record = wardenlens_index::CameraRecord::new(
            CameraId::new("mine").unwrap(),
            catalogue::parse_model("reolink/rlc-520a").unwrap(),
            NonZeroU16::new(554).unwrap(),
            wardenlens_core::camera::StreamSet::new(
                wardenlens_core::camera::RtspPath::new("/m").unwrap(),
                None,
            ),
        );
        let req = add::test_request("mine");
        let mut index = Index::open(site.config.database_path()).unwrap();
        let mut vault = FailingVault {
            inner: site.vault(),
            calls: 0,
            fail_on,
        };
        let err = add::commit(
            &mut index,
            &mut vault,
            &record,
            &entries,
            now().unwrap(),
            &req,
            secrecy::SecretString::from("pw".to_owned()),
        )
        .unwrap_err();
        assert!(
            matches!(err, CameraCmdError::Vault(_)),
            "{fail_on}: {err:?}"
        );
        drop(vault);
        // One handle per index file per process (#148): release this one before the helper opens it.
        drop(index);
        let ids: Vec<String> = site
            .cameras()
            .iter()
            .map(|c| c.record().id().to_string())
            .collect();
        assert_eq!(ids, ["keep"], "fail_on {fail_on}: the row was left");
        for kind in [
            EntryKind::Credential,
            EntryKind::Host,
            EntryKind::DisplayName,
        ] {
            assert!(site.entry("mine", kind).is_none(), "{fail_on} {kind:?}");
            assert!(site.entry("keep", kind).is_some(), "{fail_on} {kind:?}");
        }
        assert_eq!(site.vault().list().unwrap().len(), before, "{fail_on}");
    }
}

fn broken_clock() -> Result<UnixMs, CameraCmdError> {
    Err(CameraCmdError::Clock)
}

/// The clock is read before the first write: a clock failure leaves no vault, no registry row.
#[test]
fn a_clock_failure_writes_nothing() {
    let site = Site::new();
    let a = args(
        "cam-a",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    let mut term = Scripted::piped(&pw());
    let services = Services {
        network: &foreign(),
        client: fast(),
        clock: broken_clock,
    };
    let err = add(&site.config, &a, &mut term, &services).unwrap_err();
    assert!(matches!(err, CameraCmdError::Clock), "{err:?}");
    assert_eq!(site.files().len(), 0, "{:?}", site.files());
}

/// The operator is asked for the password only after the key file and the duplicate check.
#[test]
fn the_password_is_not_read_for_a_duplicate_id_or_a_missing_key() {
    let site = Site::new();
    add_closed(&site, "cam-a", "reolink/rlc-520a");
    let a = args(
        "cam-a",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    let o = run_add(&site, &foreign(), &a, &pw());
    assert!(matches!(o.result, Err(CameraCmdError::AlreadyRegistered)));
    assert_eq!(o.input_left, pw().len(), "the password was read");
    std::fs::remove_file(site.config.key_file()).unwrap();
    let b = args(
        "cam-b",
        "127.0.0.1",
        "reolink/rlc-520a",
        Some(closed_port()),
    );
    let o = run_add(&site, &foreign(), &b, &pw());
    assert!(matches!(o.result, Err(CameraCmdError::KeyMissing { .. })));
    assert_eq!(o.input_left, pw().len(), "the password was read");
}

/// `camera add` refuses the id prefix that `import agentdvr` owns, before any prompt, connection
/// or write (#207), so an import never meets a hand-added row.
#[test]
fn camera_add_refuses_the_import_id_prefix_and_writes_nothing() {
    for id in ["agentdvr-1", "agentdvr-", "agentdvr-front-door"] {
        let site = Site::new();
        let a = args(id, "127.0.0.1", "dahua/ipc-hfw4431r-z", Some(closed_port()));
        let o = run_add(&site, &foreign(), &a, &pw());
        assert!(matches!(o.result, Err(CameraCmdError::ReservedId)), "{id}");
        assert_eq!(o.input_left, pw().len(), "{id}: the password was read");
        assert_eq!(CameraCmdError::ReservedId.exit_code(), 1);
        assert_eq!(site.cameras().len(), 0);
        assert!(
            site.files().iter().all(|f| !f.contains("vault")),
            "{:?}",
            site.files()
        );
    }
    // A near miss is an ordinary id.
    let site = Site::new();
    add_closed(&site, "agentdvr", "dahua/ipc-hfw4431r-z");
    add_closed(&site, "my-agentdvr-1", "dahua/ipc-hfw4431r-z");
}

/// `import` reads the registry with the catalogue: a row under a catalogue-listed query path is
/// read and updated by a re-import under the same model, and left alone under another.
#[test]
fn import_updates_its_own_rows_and_keeps_a_row_mapped_to_another_model() {
    let site = Site::new();
    let xml = "<objects><cameras><camera id=\"1\" name=\"A\"><settings>\
               <videosourcestring>rtsp://192.0.2.5:554/live</videosourcestring>\
               <login>import-user</login><password>import-password-1</password></settings>\
               </camera></cameras></objects>";
    let parsed = wardenlens_agentdvr::parse(xml.as_bytes()).unwrap();
    assert_eq!(parsed.cameras[0].id.as_str(), "agentdvr-1");
    let catalogue = crate::commands::camera::catalogue().unwrap();
    let ready = |v: &str, m: &str| {
        vec![crate::commands::import::Ready {
            draft: parsed.cameras[0].clone(),
            model: ModelRef::new(v, m).unwrap(),
        }]
    };
    let write = |r: &[crate::commands::import::Ready]| {
        let key = wardenlens_secrets::KeyFile::load(site.config.key_file()).unwrap();
        crate::commands::import::write_all(&site.config, key, r, &catalogue).unwrap()
    };
    write(&ready("dahua", "ipc-hfw4431r-z"));
    assert_eq!(
        site.cameras()[0].record().model().to_string(),
        "dahua/ipc-hfw4431r-z"
    );
    // Another model: kept.
    write(&ready("agentdvr", "imported"));
    assert_eq!(
        site.cameras()[0].record().model().to_string(),
        "dahua/ipc-hfw4431r-z"
    );
    // The same model: an update.
    write(&ready("dahua", "ipc-hfw4431r-z"));
    let cams = site.cameras();
    assert_eq!(cams.len(), 1);
    assert_eq!(cams[0].record().streams().main.as_str(), "/live");
}

mod adversary;
mod adversary_163;
