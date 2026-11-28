//! Typed errors and skip reasons. None of them carries input: no URL, host, user, password,
//! name or XML text (SEC-6). The only numbers are byte positions and counts.

/// Why the whole import failed. The document is rejected; nothing is imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ImportError {
    /// The input is longer than [`crate::MAX_INPUT_BYTES`].
    #[error("input is longer than the 8 MiB limit")]
    TooLarge,
    /// The input is not valid UTF-8 (UTF-16 documents are refused too).
    #[error("input is not valid UTF-8")]
    NotUtf8,
    /// The XML declaration names an encoding other than UTF-8.
    #[error("the XML declaration names an encoding other than UTF-8")]
    UnsupportedEncoding,
    /// The document has a `<!DOCTYPE ...>` declaration. DTDs, internal entities and external
    /// entities are refused outright.
    #[error("the document has a DOCTYPE declaration, which is refused")]
    DocType,
    /// The XML is not well formed: a syntax error, an entity other than the five predefined ones
    /// or a character reference, a duplicate attribute, mismatched tags, text outside the root,
    /// a second root, or a truncated document. `position` is the byte offset of the failure.
    #[error("the document is not well-formed XML (near byte {position})")]
    Malformed {
        /// Byte offset in the input where the parser gave up.
        position: u64,
    },
    /// The JSON is not well formed: a syntax error, a truncated document, text after the value,
    /// an invalid escape or a control character in a string. The line and column are positions
    /// only; the parser's own message (which can echo input) is never forwarded.
    #[error("the document is not well-formed JSON (line {line}, column {column})")]
    MalformedJson {
        /// One-based line of the failure.
        line: usize,
        /// One-based column of the failure.
        column: usize,
    },
    /// A `videosourcestring`, `login` or `password` member of a JSON camera is a number, a
    /// boolean, an array or an object. Refused whole: a value that is not collected as a login
    /// could leak into a path.
    #[error("a source or login member is not a string")]
    FieldNotText,
    /// Elements are nested deeper than [`crate::MAX_DEPTH`].
    #[error("elements are nested deeper than the limit")]
    TooDeep,
    /// More than [`crate::MAX_CAMERAS`] `camera` elements.
    #[error("the document has more cameras than the limit")]
    TooManyCameras,
    /// The login collection went over a limit: more distinct login values (users, passwords,
    /// credential parameters) than [`crate::MAX_LOGINS`], more than [`crate::MAX_LOGIN_BYTES`]
    /// bytes of them, or more than [`crate::MAX_LOGIN_WORK`] bytes of work (every candidate
    /// offered, duplicates included, and the scans). The whole document is refused: a login that
    /// is not collected could leak into a path.
    #[error("the document holds more login values, or costs more login work, than the limit")]
    TooManyLogins,
    /// The document is well formed but its root element is not `objects`, or it has none.
    #[error("the document is not an AgentDVR objects file")]
    NotObjects,
    /// Two imported cameras have the same name once normalised. Never merged and never resolved
    /// by first-wins: a credential must not land on the wrong camera (ADR 0006, #43). The
    /// positions are those of the two `camera` elements (the name itself is not reported).
    #[error("cameras {first} and {second} have the same name after normalisation")]
    DuplicateName {
        /// Zero-based position of the first camera with the name.
        first: usize,
        /// Zero-based position of the later one.
        second: usize,
    },
}

/// Why one camera entry was not imported. The rest of the import goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[non_exhaustive]
pub enum SkipReason {
    /// The camera is marked `deleted`.
    #[error("camera is marked deleted")]
    Deleted,
    /// A `settings`, `videosourcestring`, `login` or `password` element appears twice, so the
    /// entry has two possible meanings.
    #[error("camera has a repeated settings or source element")]
    RepeatedElement,
    /// A source or login field is longer than the field limit.
    #[error("a source or login field is too long")]
    FieldTooLong,
    /// The camera has no `name` attribute.
    #[error("camera has no name")]
    MissingName,
    /// The name is refused by core's display-name rules or cannot make a camera id.
    #[error("camera name is refused by the display-name rules")]
    NameRefused,
    /// There is no source URL (empty, absent, or an ONVIF-only entry with no stream URL).
    #[error("camera has no source URL")]
    NoSource,
    /// The source is not a URL (for example a local device name).
    #[error("source is not a URL")]
    NotAUrl,
    /// The source scheme is not `rtsp` (http, mjpeg, file, rtsps, ...).
    #[error("source scheme is not rtsp")]
    UnsupportedScheme,
    /// The source has a control character.
    #[error("source has a control character")]
    InvalidUrl,
    /// The host is empty, malformed or refused by core's host rules.
    #[error("source host is refused")]
    InvalidHost,
    /// The port is not a number from 1 to 65535.
    #[error("source port is not 1 to 65535")]
    InvalidPort,
    /// The path or query is refused by core's RTSP path rules.
    #[error("source path is refused")]
    InvalidPath,
    /// The path or query carries a credential (the `/user=..&password=..` form). It cannot be
    /// moved to the vault safely, so the camera is skipped.
    #[error("source path carries a credential")]
    CredentialInPath,
    /// The user or password has a control character, percent-decodes to invalid UTF-8, or the
    /// user has a `:` (ambiguous under RTSP Basic authentication).
    #[error("source login is malformed")]
    InvalidCredential,
    /// There is a password but no user (the vault refuses a credential with an empty user).
    #[error("login has a password but no user")]
    CredentialWithoutUser,
    /// The login fields and the URL userinfo both hold a credential and they differ. Neither is
    /// chosen and nothing is merged.
    #[error("login fields and URL userinfo disagree")]
    ConflictingCredential,
    /// The camera id could not be built. Cannot happen today (the id is `agentdvr-` and digits,
    /// and a test pins the extremes); it is a typed skip so no panic path exists.
    #[error("camera id could not be built")]
    IdRefused,
}
