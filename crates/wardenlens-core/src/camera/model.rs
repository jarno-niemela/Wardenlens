//! [`Camera`], [`StreamSet`] and [`RtspUrl`].

use std::fmt;
use std::num::NonZeroU16;

use super::{CameraError, CameraId, DisplayName, Host, ModelRef, RtspPath, StreamRole};

/// The standard RTSP port.
pub const DEFAULT_RTSP_PORT: NonZeroU16 = match NonZeroU16::new(554) {
    Some(p) => p,
    None => NonZeroU16::MIN,
};

/// The streams of one camera: a main stream and an optional sub stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamSet {
    /// The full-resolution stream (always present).
    pub main: RtspPath,
    /// The low-resolution stream, if the camera has one.
    pub sub: Option<RtspPath>,
}

impl StreamSet {
    /// A stream set from its paths.
    #[must_use]
    pub fn new(main: RtspPath, sub: Option<RtspPath>) -> Self {
        Self { main, sub }
    }

    /// The path of `role`, if there is one. The match is exhaustive on purpose: a new role must
    /// decide where its path lives.
    #[must_use]
    pub fn get(&self, role: StreamRole) -> Option<&RtspPath> {
        match role {
            StreamRole::Main => Some(&self.main),
            StreamRole::Sub => self.sub.as_ref(),
        }
    }
}

/// An RTSP URL without credentials. `Debug` and `Display` print `rtsp://<redacted>` because the
/// host identifies the site; use [`RtspUrl::as_str`] to hand it to the client.
#[derive(Clone, PartialEq, Eq)]
pub struct RtspUrl(String);

impl RtspUrl {
    /// The URL text. Sensitive: call at the last moment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RtspUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rtsp://<redacted>")
    }
}

impl fmt::Display for RtspUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rtsp://<redacted>")
    }
}

/// One camera. `Debug` shows the id, model and port; the host, name and paths are redacted by
/// their types. It holds no credential (ADR 0006: a `CredentialSource` supplies it by id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Camera {
    id: CameraId,
    name: DisplayName,
    model: ModelRef,
    host: Host,
    port: NonZeroU16,
    streams: StreamSet,
    allow_basic_auth: bool,
}

impl Camera {
    /// Assembles a camera from validated parts.
    #[must_use]
    pub fn new(
        id: CameraId,
        name: DisplayName,
        model: ModelRef,
        host: Host,
        port: NonZeroU16,
        streams: StreamSet,
    ) -> Self {
        Self {
            id,
            name,
            model,
            host,
            port,
            streams,
            allow_basic_auth: false,
        }
    }

    /// Sets the per-camera opt-in to Basic authentication (ADR 0002 item 15). Off by default.
    #[must_use]
    pub fn with_allow_basic_auth(mut self, allow: bool) -> Self {
        self.allow_basic_auth = allow;
        self
    }

    /// Whether a Basic-only authentication challenge may be answered with the password, which
    /// then crosses the network in base64 cleartext. Off unless the operator opted this camera in.
    #[must_use]
    pub fn allow_basic_auth(&self) -> bool {
        self.allow_basic_auth
    }

    /// The camera id.
    #[must_use]
    pub fn id(&self) -> &CameraId {
        &self.id
    }

    /// The display name (redacting `Debug`/`Display`).
    #[must_use]
    pub fn name(&self) -> &DisplayName {
        &self.name
    }

    /// The catalogue model this camera is.
    #[must_use]
    pub fn model(&self) -> &ModelRef {
        &self.model
    }

    /// The streams (redacting `Debug`/`Display`).
    #[must_use]
    pub fn streams(&self) -> &StreamSet {
        &self.streams
    }

    /// The host (redacting `Debug`/`Display`).
    #[must_use]
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The RTSP port.
    #[must_use]
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// The path of `role`, if the camera has that stream.
    #[must_use]
    pub fn path(&self, role: StreamRole) -> Option<&RtspPath> {
        self.streams.get(role)
    }

    /// The credential-free RTSP URL for `role`: `rtsp://<host>:<port><path>`.
    ///
    /// # Errors
    /// [`CameraError::NoSuchStream`] when the camera has no stream for `role`.
    pub fn rtsp_url(&self, role: StreamRole) -> Result<RtspUrl, CameraError> {
        let path = self.path(role).ok_or(CameraError::NoSuchStream)?;
        Ok(RtspUrl(format!(
            "rtsp://{}:{}{}",
            self.host.url_host(),
            self.port,
            path.as_str()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::Strategy;

    fn cam(host: &str, port: u16, main: &str, sub: Option<&str>) -> Camera {
        Camera::new(
            CameraId::new("reolink-1").unwrap(),
            DisplayName::new("Back Door North").unwrap(),
            ModelRef::new("reolink", "rlc-520a").unwrap(),
            Host::new(host).unwrap(),
            NonZeroU16::new(port).unwrap(),
            StreamSet::new(
                RtspPath::new(main).unwrap(),
                sub.map(|s| RtspPath::new(s).unwrap()),
            ),
        )
    }

    #[test]
    fn the_basic_opt_in_is_off_unless_set_and_does_not_change_equality_of_the_rest() {
        let c = cam("192.0.2.1", 554, "/a", None);
        assert!(!c.allow_basic_auth());
        let on = c.clone().with_allow_basic_auth(true);
        assert!(on.allow_basic_auth());
        assert_ne!(c, on);
        assert!(!on.with_allow_basic_auth(false).allow_basic_auth());
    }

    #[test]
    fn default_port_is_554() {
        assert_eq!(DEFAULT_RTSP_PORT.get(), 554);
    }

    #[test]
    fn builds_urls_for_each_host_kind() {
        let c = cam("192.0.2.10", 554, "/main", Some("/sub?channel=1&subtype=1"));
        assert_eq!(
            c.rtsp_url(StreamRole::Main).unwrap().as_str(),
            "rtsp://192.0.2.10:554/main"
        );
        assert_eq!(
            c.rtsp_url(StreamRole::Sub).unwrap().as_str(),
            "rtsp://192.0.2.10:554/sub?channel=1&subtype=1"
        );
        let c = cam("2001:db8::1", 8554, "/m", None);
        assert_eq!(
            c.rtsp_url(StreamRole::Main).unwrap().as_str(),
            "rtsp://[2001:db8::1]:8554/m"
        );
        let c = cam("Cam.Example.INVALID", 1, "/", None);
        assert_eq!(
            c.rtsp_url(StreamRole::Main).unwrap().as_str(),
            "rtsp://cam.example.invalid:1/"
        );
    }

    #[test]
    fn missing_sub_stream_is_an_error() {
        let c = cam("192.0.2.10", 554, "/main", None);
        assert_eq!(c.rtsp_url(StreamRole::Sub), Err(CameraError::NoSuchStream));
        assert!(c.path(StreamRole::Sub).is_none());
        assert_eq!(c.path(StreamRole::Main).unwrap().as_str(), "/main");
    }

    #[test]
    fn camera_exposes_model_and_streams() {
        let c = cam("192.0.2.10", 554, "/main", Some("/sub"));
        assert_eq!(c.model().to_string(), "reolink/rlc-520a");
        assert_eq!(c.streams().main.as_str(), "/main");
        assert_eq!(c.streams().sub.as_ref().map(RtspPath::as_str), Some("/sub"));
        assert_eq!(c.streams().get(StreamRole::Sub), c.path(StreamRole::Sub));
    }

    #[test]
    fn stream_role_is_the_catalogue_enum() {
        let r: crate::catalogue::StreamRole = StreamRole::Main;
        let mut set = std::collections::HashSet::new();
        set.insert(r);
        assert!(set.contains(&StreamRole::Main) && !set.contains(&StreamRole::Sub));
    }

    #[test]
    fn debug_never_prints_a_path_even_with_an_unlisted_credential_name() {
        let c = cam(
            "192.0.2.10",
            554,
            "/cam?pin=Tr0ub4dor-x9",
            Some("/sub?who=svc-reader"),
        );
        for shown in [
            format!("{c:?}"),
            format!("{c:#?}"),
            format!("{:?}", c.streams()),
        ] {
            assert!(
                !shown.contains("Tr0ub4dor") && !shown.contains("svc-reader"),
                "{shown}"
            );
            assert!(!shown.contains("pin="), "{shown}");
        }
    }

    #[test]
    fn debug_display_of_camera_and_url_redact_host_and_name() {
        let c = cam("nvr-9.example.invalid", 554, "/main", Some("/sub"));
        let url = c.rtsp_url(StreamRole::Main).unwrap();
        let shown = [
            format!("{c:?}"),
            format!("{c:#?}"),
            format!("{:?}", Some(&c)),
            format!("{url}"),
            format!("{url:?}"),
            format!("{url:#?}"),
            format!("{:?}", c.rtsp_url(StreamRole::Sub)),
        ];
        for s in shown {
            assert!(
                !s.contains("nvr-9")
                    && !s.contains("example")
                    && !s.contains("Back")
                    && !s.contains("Door"),
                "{s}"
            );
        }
        assert!(format!("{c:?}").contains("reolink-1"));
    }

    fn parse_back(url: &str) -> (Host, u16, String) {
        let rest = url.strip_prefix("rtsp://").unwrap();
        let slash = rest.find('/').unwrap();
        let (authority, path) = rest.split_at(slash);
        let (host, port) = authority.rsplit_once(':').unwrap();
        (
            Host::new(host).unwrap(),
            port.parse().unwrap(),
            path.to_owned(),
        )
    }

    proptest::proptest! {
        #[test]
        fn url_has_no_credentials_and_parses_back(
            host in proptest::prop_oneof![
                proptest::arbitrary::any::<[u8; 4]>()
                    .prop_map(|o| format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
                    .boxed(),
                proptest::arbitrary::any::<u128>()
                    .prop_map(|b| std::net::Ipv6Addr::from(b).to_string())
                    .boxed(),
                "[a-z][a-z0-9-]{0,10}[a-z](\\.[a-z][a-z0-9]{0,8}){0,3}".boxed(),
            ],
            port in 1u16..=u16::MAX,
            path in "/[a-zA-Z0-9_/=&?;:,~-]{0,100}",
        ) {
            proptest::prop_assume!(!path.starts_with("//"));
            let Ok(p) = RtspPath::new(&path) else { return Ok(()); };
            let h = Host::new(&host).unwrap();
            let c = Camera::new(
                CameraId::new("cam1").unwrap(),
                DisplayName::new("n").unwrap(),
                ModelRef::new("acme", "c1").unwrap(),
                h.clone(),
                NonZeroU16::new(port).unwrap(),
                StreamSet::new(p.clone(), None),
            );
            let url = c.rtsp_url(StreamRole::Main).unwrap();
            proptest::prop_assert!(!url.as_str().contains('@'));
            let (ph, pp, ppath) = parse_back(url.as_str());
            proptest::prop_assert_eq!(ph, h);
            proptest::prop_assert_eq!(pp, port);
            proptest::prop_assert_eq!(ppath, p.as_str());
        }
    }
}
