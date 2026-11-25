//! [`OnvifClient`]: the three calls over [`crate::transport`].

use std::num::NonZeroU16;

use wardenlens_core::camera::{Credential, Host};

use crate::model::{DeviceInformation, Profile, ProfileToken};
use crate::parse::{parse_device_information, parse_profiles, parse_stream_uri};
use crate::stream_uri::StreamEndpoint;
use crate::transport::{ClientConfig, Request1, post};
use crate::wsse::{envelope, escape};
use crate::{MAX_SERVICE_PATH_LEN, OnvifError};

const NS_DEVICE: &str = "http://www.onvif.org/ver10/device/wsdl";
const NS_MEDIA: &str = "http://www.onvif.org/ver10/media/wsdl";
const NS_SCHEMA: &str = "http://www.onvif.org/ver10/schema";
/// The default service path. Many cameras serve the media calls here too.
pub const DEFAULT_SERVICE_PATH: &str = "/onvif/device_service";

/// A validated service path (`/onvif/device_service`): `/` then `pchar` bytes without `?`, `#`,
/// `%` or `@`, no `//` at the start, at most [`MAX_SERVICE_PATH_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServicePath(String);

impl ServicePath {
    fn new(text: &str) -> Result<Self, OnvifError> {
        let ok = text.starts_with('/')
            && !text.starts_with("//")
            && text.len() <= MAX_SERVICE_PATH_LEN
            && text.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'/' | b'-'
                            | b'.'
                            | b'_'
                            | b'~'
                            | b':'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                    )
            })
            && !text.split('/').any(|s| s == "." || s == "..");
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(OnvifError::InvalidServicePath)
        }
    }
}

/// A client for one camera's ONVIF services over plain HTTP.
///
/// The `host` and `port` are the operator's configuration and stay authoritative: nothing a camera
/// replies can change where this client connects. Each call opens its own connection (see
/// the crate documentation for the retry contract) and is safe to run concurrently. `Debug` redacts
/// the host and the credential.
#[derive(Debug, Clone)]
pub struct OnvifClient {
    host: Host,
    port: NonZeroU16,
    credential: Option<Credential>,
    device_path: ServicePath,
    media_path: ServicePath,
    config: ClientConfig,
}

impl OnvifClient {
    /// A client for the ONVIF HTTP port `port` of `host`, authenticating as `credential` (or not
    /// at all). Both service paths start as [`DEFAULT_SERVICE_PATH`].
    #[must_use]
    pub fn new(host: Host, port: NonZeroU16, credential: Option<Credential>) -> Self {
        let default = ServicePath(DEFAULT_SERVICE_PATH.to_owned());
        Self {
            host,
            port,
            credential,
            device_path: default.clone(),
            media_path: default,
            config: ClientConfig::default(),
        }
    }

    /// Replaces the timing and retry settings.
    #[must_use]
    pub fn with_config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the path of the device service.
    ///
    /// # Errors
    /// [`OnvifError::InvalidServicePath`].
    pub fn with_device_path(mut self, path: &str) -> Result<Self, OnvifError> {
        self.device_path = ServicePath::new(path)?;
        Ok(self)
    }

    /// Sets the path of the media service (`GetProfiles`, `GetStreamUri`).
    ///
    /// # Errors
    /// [`OnvifError::InvalidServicePath`].
    pub fn with_media_path(mut self, path: &str) -> Result<Self, OnvifError> {
        self.media_path = ServicePath::new(path)?;
        Ok(self)
    }

    /// Sends one SOAP call and returns the reply body, ready for a parser. A non-success HTTP
    /// status is final: a fault in its body is reported as such, anything else as `HttpStatus`.
    async fn call<T>(
        &self,
        path: &ServicePath,
        action: &str,
        body: &str,
        parse: impl FnOnce(&[u8]) -> Result<T, OnvifError>,
    ) -> Result<T, OnvifError> {
        let envelope = envelope(self.credential.as_ref(), body)?;
        let req = Request1 {
            host: &self.host,
            port: self.port.get(),
            path: &path.0,
            action,
            body: envelope,
        };
        let (status, reply) = post(&req, &self.config).await?;
        match parse(&reply) {
            Ok(v) if (200..300).contains(&status) => Ok(v),
            Err(e @ (OnvifError::SoapFault | OnvifError::NotAuthorized)) => Err(e),
            Err(e) if (200..300).contains(&status) => Err(e),
            _ => Err(OnvifError::HttpStatus { status }),
        }
    }

    /// `GetDeviceInformation` on the device service.
    ///
    /// # Errors
    /// Any [`OnvifError`]: unreachable, HTTP or SOAP failure, or an invalid reply.
    pub async fn get_device_information(&self) -> Result<DeviceInformation, OnvifError> {
        let body = format!("<tds:GetDeviceInformation xmlns:tds=\"{NS_DEVICE}\"/>");
        self.call(
            &self.device_path,
            "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
            &body,
            parse_device_information,
        )
        .await
    }

    /// `GetProfiles` on the media service: the profiles that have a video encoder.
    ///
    /// # Errors
    /// Any [`OnvifError`].
    pub async fn get_profiles(&self) -> Result<Vec<Profile>, OnvifError> {
        let body = format!("<trt:GetProfiles xmlns:trt=\"{NS_MEDIA}\"/>");
        self.call(
            &self.media_path,
            "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
            &body,
            parse_profiles,
        )
        .await
    }

    /// `GetStreamUri` (RTP-Unicast over RTSP) for `profile`, reduced to a path and a port. The
    /// host the camera names is discarded: see [`crate::stream_uri`].
    ///
    /// # Errors
    /// Any [`OnvifError`].
    pub async fn get_stream_uri(
        &self,
        profile: &ProfileToken,
    ) -> Result<StreamEndpoint, OnvifError> {
        let token = escape(profile.as_str()).ok_or(OnvifError::InvalidToken)?;
        let body = format!(
            "<trt:GetStreamUri xmlns:trt=\"{NS_MEDIA}\" xmlns:tt=\"{NS_SCHEMA}\">\
             <trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>\
             <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>\
             <trt:ProfileToken>{token}</trt:ProfileToken></trt:GetStreamUri>"
        );
        self.call(
            &self.media_path,
            "http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
            &body,
            parse_stream_uri,
        )
        .await
    }
}
