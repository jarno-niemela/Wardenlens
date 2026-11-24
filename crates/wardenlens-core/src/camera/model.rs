//! [`Camera`], [`StreamRole`] and [`RtspUrl`].

use std::fmt;
use std::num::NonZeroU16;

use super::{CameraError, CameraId, DisplayName, Host, RtspPath};

/// The standard RTSP port.
pub const DEFAULT_RTSP_PORT: NonZeroU16 = match NonZeroU16::new(554) {
    Some(p) => p,
    None => NonZeroU16::MIN,
};

/// Which of a camera's streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum StreamRole {
    /// The full-resolution stream (always present).
    Main,
    /// The low-resolution stream (optional).
    Sub,
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

/// One camera. `Debug` shows the id, port and paths; the host and name are redacted by their types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Camera {
    id: CameraId,
    name: DisplayName,
    host: Host,
    port: NonZeroU16,
    main_path: RtspPath,
    sub_path: Option<RtspPath>,
}

impl Camera {
    /// Assembles a camera from validated parts.
    #[must_use]
    pub fn new(
        id: CameraId,
        name: DisplayName,
        host: Host,
        port: NonZeroU16,
        main_path: RtspPath,
        sub_path: Option<RtspPath>,
    ) -> Self {
        Self {
            id,
            name,
            host,
            port,
            main_path,
            sub_path,
        }
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
        match role {
            StreamRole::Main => Some(&self.main_path),
            StreamRole::Sub => self.sub_path.as_ref(),
        }
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
            Host::new(host).unwrap(),
            NonZeroU16::new(port).unwrap(),
            RtspPath::new(main).unwrap(),
            sub.map(|s| RtspPath::new(s).unwrap()),
        )
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
                h.clone(),
                NonZeroU16::new(port).unwrap(),
                p.clone(),
                None,
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
