//! Hand-written synthetic documents: documentation addresses (192.0.2.x) and `user`/`secret`
//! style values only.

use secrecy::ExposeSecret;

use crate::{CameraDraft, Import, SkipReason, parse};

/// One camera entry of a synthetic document.
#[derive(Clone)]
pub(super) struct Cam {
    pub name: Option<String>,
    pub source: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
    pub deleted: Option<&'static str>,
}

impl Cam {
    pub(super) fn new(name: &str, source: &str) -> Self {
        Self {
            name: Some(name.to_owned()),
            source: Some(source.to_owned()),
            login: None,
            password: None,
            deleted: None,
        }
    }

    pub(super) fn login(mut self, login: &str, password: &str) -> Self {
        self.login = Some(login.to_owned());
        self.password = Some(password.to_owned());
        self
    }
}

/// XML-escapes `s` for text and attribute use.
pub(super) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(super) fn cam_xml(c: &Cam, id: usize) -> String {
    let mut attrs = format!(" id=\"{id}\"");
    if let Some(n) = &c.name {
        attrs.push_str(&format!(" name=\"{}\"", esc(n)));
    }
    if let Some(d) = c.deleted {
        attrs.push_str(&format!(" deleted=\"{d}\""));
    }
    let mut settings = String::new();
    if let Some(s) = &c.source {
        settings.push_str(&format!(
            "<videosourcestring>{}</videosourcestring>",
            esc(s)
        ));
    }
    if let Some(l) = &c.login {
        settings.push_str(&format!("<login>{}</login>", esc(l)));
    }
    if let Some(p) = &c.password {
        settings.push_str(&format!("<password>{}</password>", esc(p)));
    }
    format!(
        "<camera{attrs}><settings><sourceindex>2</sourceindex>{settings}</settings><ptz>0</ptz></camera>"
    )
}

/// A complete document holding `cams`.
pub(super) fn doc(cams: &[Cam]) -> String {
    let body: String = cams
        .iter()
        .enumerate()
        .map(|(i, c)| cam_xml(c, i))
        .collect();
    wrap(&body)
}

pub(super) fn wrap(cameras_inner: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<objects xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n  <cameras>{cameras_inner}</cameras>\n  <microphones />\n</objects>\n"
    )
}

pub(super) fn parse_ok(cams: &[Cam]) -> Import {
    parse(doc(cams).as_bytes()).unwrap_or_else(|e| panic!("parse failed: {e}"))
}

/// Parses a one-camera document with `source`; the camera is either imported or skipped.
pub(super) fn one(source: &str) -> Result<CameraDraft, SkipReason> {
    let import = parse_ok(&[Cam::new("Cam", source)]);
    assert_eq!(import.cameras.len() + import.skipped.len(), 1);
    match import.cameras.into_iter().next() {
        Some(c) => Ok(c),
        None => Err(import.skipped[0].reason),
    }
}

/// The credential of a draft as plain strings.
pub(super) fn cred(d: &CameraDraft) -> Option<(String, String)> {
    d.credential
        .as_ref()
        .map(|c| (c.user.clone(), c.password.expose_secret().to_owned()))
}
