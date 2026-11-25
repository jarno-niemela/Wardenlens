//! Typed errors. None of them carries response text, a URL, a host, a user name, a password or a
//! digest (SEC-6): the only payloads are byte positions, counts, status codes, static field names
//! chosen by this crate and core's [`CameraError`] (which names a rule and never echoes input).

use wardenlens_core::camera::CameraError;

/// Why an ONVIF call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OnvifError {
    // ---- the reply, as parsed ----
    /// The reply body is empty or only white space.
    #[error("the camera sent an empty reply")]
    EmptyReply,
    /// The reply is longer than [`crate::MAX_BODY_BYTES`] (the read stops at the limit).
    #[error("the reply is longer than the 1 MiB limit")]
    BodyTooLarge,
    /// The reply is not valid UTF-8 (UTF-16 replies are refused too).
    #[error("the reply is not valid UTF-8")]
    NotUtf8,
    /// The XML declaration names an encoding other than UTF-8.
    #[error("the XML declaration names an encoding other than UTF-8")]
    UnsupportedEncoding,
    /// The reply has a `<!DOCTYPE ...>` declaration. DTDs and entities are refused outright.
    #[error("the reply has a DOCTYPE declaration, which is refused")]
    DocType,
    /// The reply is not well-formed XML: a syntax error, an entity other than the five predefined
    /// ones, a character reference to a character XML forbids, mismatched tags, text outside the
    /// root, a second root or a truncated document. `position` is the byte offset of the failure.
    #[error("the reply is not well-formed XML (near byte {position})")]
    Malformed {
        /// Byte offset in the reply where the parser gave up.
        position: u64,
    },
    /// Elements are nested deeper than [`crate::MAX_DEPTH`].
    #[error("the reply nests elements deeper than the limit")]
    TooDeep,
    /// The reply has more than [`crate::MAX_ELEMENTS`] elements.
    #[error("the reply has more elements than the limit")]
    TooManyElements,
    /// The reply is a SOAP fault (any code). The fault text is never kept.
    #[error("the camera answered with a SOAP fault")]
    SoapFault,
    /// The reply is a SOAP fault whose code says the credentials were refused
    /// (`ter:NotAuthorized`).
    #[error("the camera refused the credentials (SOAP fault)")]
    NotAuthorized,
    /// The reply is well-formed XML but not the SOAP envelope this call expects: no `Envelope`,
    /// no `Body`, or a missing response element. `element` is a fixed name chosen by this crate.
    #[error("the reply does not have the expected element {element}")]
    MissingElement {
        /// The element this crate looked for.
        element: &'static str,
    },
    /// A field of the reply is empty, too long, not a number, out of range or outside the allowed
    /// character set. `field` is a fixed name chosen by this crate (never the offending value).
    #[error("the reply has an invalid value for {field}")]
    InvalidField {
        /// The field this crate was reading.
        field: &'static str,
    },
    /// The reply lists more profiles than [`crate::MAX_PROFILES`].
    #[error("the reply lists more profiles than the limit")]
    TooManyProfiles,

    // ---- the stream URI ----
    /// The stream URI is not an `rtsp://` URI.
    #[error("the stream URI is not an rtsp:// URI")]
    StreamUriScheme,
    /// The stream URI has no usable authority (a space, a control character, a malformed bracketed
    /// host, or an unbracketed host with more than one `:`).
    #[error("the stream URI has a malformed authority")]
    StreamUriAuthority,
    /// The stream URI names a port that is not 1 to 65535.
    #[error("the stream URI has an invalid port")]
    StreamUriPort,
    /// The stream URI path or query was refused by core's [`wardenlens_core::camera::RtspPath`]
    /// (a credential parameter, a `%`, a dot segment, ...). The rule is named, the text is not.
    #[error("the stream URI path was refused: {0}")]
    StreamUriPath(CameraError),

    // ---- the request ----
    /// The user name has a character XML 1.0 cannot carry, so it cannot go into the request.
    #[error("the user name has a character that cannot be sent in XML")]
    UserNotXmlSafe,
    /// A service path is empty, does not start with a single `/`, is too long or has a character
    /// outside `pchar`.
    #[error("the service path is invalid")]
    InvalidServicePath,
    /// The profile token is empty, too long or has a character outside `[A-Za-z0-9._:-]`.
    #[error("the profile token is invalid")]
    InvalidToken,
    /// The operating system could not supply random bytes for the nonce.
    #[error("the operating system random source failed")]
    Random,
    /// The system clock is before 1970-01-01 or beyond year 9999.
    #[error("the system clock is out of range")]
    Clock,

    // ---- the exchange ----
    /// No attempt got an HTTP response head: every connect failed or timed out, or the camera
    /// closed the connection or stayed silent before answering. `attempts` is how many were made.
    #[error("the camera is unreachable after {attempts} attempts")]
    Unreachable {
        /// Number of attempts made.
        attempts: u8,
    },
    /// The camera answered HTTP 401.
    #[error("the camera answered HTTP 401")]
    Unauthorized,
    /// The camera answered a status that is neither success nor a SOAP fault carrier.
    #[error("the camera answered HTTP status {status}")]
    HttpStatus {
        /// The status code.
        status: u16,
    },
    /// The connection failed after the response head arrived, while reading the body.
    #[error("the connection failed while reading the reply")]
    Transport,
    /// The body did not arrive within the request timeout after the head did.
    #[error("the reply body did not arrive in time")]
    Timeout,
}
