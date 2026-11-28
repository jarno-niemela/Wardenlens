//! WS-Security `UsernameToken` with a password digest, and the SOAP envelopes this crate sends.
//!
//! The digest is `Base64(SHA1(nonce + created + password))` (WS-Security `UsernameToken` Profile
//! 1.0 section 3.1, adopted by ONVIF Core section 5.12.2; the test vector below is from the ONVIF
//! guide material, not from the OASIS profile text). The three parts are the **raw** nonce
//! bytes, the `Created` text exactly as sent, and the password bytes. SHA-1 is required by the
//! profile the cameras implement; it only answers that challenge and never protects anything
//! locally (SEC-7: the audited `RustCrypto` `sha1`, nothing hand-rolled).
//!
//! The password reaches exactly one place: the input buffer of [`digest`], a `Zeroizing` buffer
//! that is wiped when the function returns (the hasher state is wiped on drop too, through the
//! `sha1` `zeroize` feature). It is never formatted, never stored in the request builder and
//! never part of an error.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use secrecy::ExposeSecret;
use secrecy::zeroize::Zeroizing;
use sha1::{Digest, Sha1};
use wardenlens_core::camera::Credential;

use crate::OnvifError;

/// Length of the nonce in bytes (16, from the operating system's random source).
pub(crate) const NONCE_LEN: usize = 16;

const NS_WSSE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const NS_WSU: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const PASSWORD_DIGEST: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const BASE64_BINARY: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

/// `Base64(SHA1(nonce + created + password))`, the value of the `Password` element.
pub(crate) fn digest(nonce: &[u8], created: &str, password: &str) -> Zeroizing<String> {
    let capacity = nonce
        .len()
        .saturating_add(created.len())
        .saturating_add(password.len());
    // Exact capacity: the buffer never reallocates, so no unwiped copy of the password is left.
    let mut input: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(capacity));
    input.extend_from_slice(nonce);
    input.extend_from_slice(created.as_bytes());
    input.extend_from_slice(password.as_bytes());
    let mut hasher = Sha1::new();
    hasher.update(input.as_slice());
    Zeroizing::new(STANDARD.encode(hasher.finalize()))
}

/// `secs` since the Unix epoch as `YYYY-MM-DDThh:mm:ssZ` (UTC, the `xs:dateTime` form the
/// ONVIF Core example uses), or `None` after year 9999.
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    reason = "Hinnant's civil-from-days on i64; `secs` is capped at year 9999, so no step can overflow"
)]
pub(crate) fn format_utc(secs: u64) -> Option<String> {
    const LAST_SECOND_OF_9999: u64 = 253_402_300_799;
    if secs > LAST_SECOND_OF_9999 {
        return None;
    }
    let days = i64::try_from(secs / 86_400).ok()?;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// The current time in the `Created` format.
pub(crate) fn created_now() -> Result<String, OnvifError> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| OnvifError::Clock)?
        .as_secs();
    format_utc(secs).ok_or(OnvifError::Clock)
}

/// A fresh nonce from the operating system's random source.
pub(crate) fn fresh_nonce() -> Result<[u8; NONCE_LEN], OnvifError> {
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| OnvifError::Random)?;
    Ok(nonce)
}

/// A character XML 1.0 allows (production `Char`).
fn is_xml_char(c: char) -> bool {
    matches!(u32::from(c), 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x1_0000..=0x10_FFFF)
}

/// `text` escaped for element content, or `None` when it has a character XML cannot carry.
pub(crate) fn escape(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if !is_xml_char(c) {
            return None;
        }
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    Some(out)
}

/// The `Security` header for `credential`, with the given nonce and `Created`.
pub(crate) fn security_header(
    credential: &Credential,
    nonce: &[u8; NONCE_LEN],
    created: &str,
) -> Result<Zeroizing<String>, OnvifError> {
    let user = escape(&credential.user).ok_or(OnvifError::UserNotXmlSafe)?;
    let digest = digest(nonce, created, credential.password.expose_secret());
    let nonce_b64 = STANDARD.encode(nonce);
    Ok(Zeroizing::new(format!(
        "<s:Header><wsse:Security s:mustUnderstand=\"1\" xmlns:wsse=\"{NS_WSSE}\" xmlns:wsu=\"{NS_WSU}\">\
         <wsse:UsernameToken><wsse:Username>{user}</wsse:Username>\
         <wsse:Password Type=\"{PASSWORD_DIGEST}\">{}</wsse:Password>\
         <wsse:Nonce EncodingType=\"{BASE64_BINARY}\">{nonce_b64}</wsse:Nonce>\
         <wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>",
        digest.as_str()
    )))
}

/// A complete SOAP 1.2 envelope around `body`, with a `UsernameToken` when `credential` is set.
pub(crate) fn envelope(credential: Option<&Credential>, body: &str) -> Result<Bytes, OnvifError> {
    let header = match credential {
        Some(c) => {
            let nonce = fresh_nonce()?;
            let created = created_now()?;
            security_header(c, &nonce, &created)?
        }
        None => Zeroizing::default(),
    };
    Ok(Bytes::from(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">{}<s:Body>{body}</s:Body></s:Envelope>",
        header.as_str()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    // A worked example from the ONVIF guide material (WS-UsernameToken), not from OASIS
    // UsernameToken Profile section 3.1: nonce, `Created` and password below give exactly this
    // `Password` digest. Independently checked with `hashlib`.
    const SPEC_NONCE_B64: &str = "LKqI6G/AikKCQrN0zqZFlg==";
    const SPEC_CREATED: &str = "2010-09-16T07:50:45Z";
    const SPEC_PASSWORD: &str = "userpassword";
    const SPEC_DIGEST: &str = "tuOSpGlFlIXsozq4HFNeeGeFLEI=";

    fn spec_nonce() -> Vec<u8> {
        STANDARD.decode(SPEC_NONCE_B64).unwrap_or_default()
    }

    #[test]
    fn spec_vector_digest() {
        assert_eq!(spec_nonce().len(), 16);
        let d = digest(&spec_nonce(), SPEC_CREATED, SPEC_PASSWORD);
        assert_eq!(d.as_str(), SPEC_DIGEST);
    }

    #[test]
    fn digest_depends_on_each_part_and_their_order() {
        let n = spec_nonce();
        let base = digest(&n, SPEC_CREATED, SPEC_PASSWORD);
        assert_ne!(
            digest(&n, SPEC_CREATED, "userpassworD").as_str(),
            base.as_str()
        );
        assert_ne!(
            digest(&n, "2010-09-16T07:50:46Z", SPEC_PASSWORD).as_str(),
            base.as_str()
        );
        let mut other = n.clone();
        other[0] ^= 1;
        assert_ne!(
            digest(&other, SPEC_CREATED, SPEC_PASSWORD).as_str(),
            base.as_str()
        );
        // Order matters: password first gives another value.
        let swapped = digest(SPEC_PASSWORD.as_bytes(), SPEC_CREATED, "");
        assert_ne!(swapped.as_str(), base.as_str());
    }

    #[test]
    fn format_utc_table() {
        // Expected values computed independently with Python's `datetime`.
        let rows: [(u64, Option<&str>); 9] = [
            (0, Some("1970-01-01T00:00:00Z")),
            (86_399, Some("1970-01-01T23:59:59Z")),
            (951_782_400, Some("2000-02-29T00:00:00Z")),
            (951_868_800, Some("2000-03-01T00:00:00Z")),
            (1_000_000_000, Some("2001-09-09T01:46:40Z")),
            (1_284_623_445, Some("2010-09-16T07:50:45Z")),
            (1_709_164_800, Some("2024-02-29T00:00:00Z")),
            (253_402_300_799, Some("9999-12-31T23:59:59Z")),
            (253_402_300_800, None),
        ];
        for (secs, want) in rows {
            assert_eq!(format_utc(secs).as_deref(), want, "secs {secs}");
        }
        assert_eq!(format_utc(u64::MAX), None);
    }

    #[test]
    fn created_now_has_the_spec_shape() {
        let c = created_now().unwrap_or_default();
        let b = c.as_bytes();
        assert_eq!(b.len(), 20);
        assert_eq!(b.get(4), Some(&b'-'));
        assert_eq!(b.get(10), Some(&b'T'));
        assert_eq!(b.last(), Some(&b'Z'));
    }

    #[test]
    fn nonces_are_16_bytes_and_differ() {
        let a = fresh_nonce().unwrap_or_default();
        let b = fresh_nonce().unwrap_or_default();
        assert_eq!(a.len(), NONCE_LEN);
        assert_ne!(a, b);
        assert_ne!(a, [0_u8; NONCE_LEN]);
    }

    #[test]
    fn escape_table() {
        assert_eq!(
            escape("a&b<c>d\"e'f").as_deref(),
            Some("a&amp;b&lt;c&gt;d&quot;e&apos;f")
        );
        assert_eq!(
            escape("caf\u{e9} \u{1F600}").as_deref(),
            Some("caf\u{e9} \u{1F600}")
        );
        assert_eq!(escape("\u{1}"), None);
        assert_eq!(escape("a\u{0}b"), None);
        assert_eq!(escape("\u{FFFE}"), None);
        assert_eq!(escape("tab\there").as_deref(), Some("tab\there"));
    }

    #[test]
    fn header_carries_the_spec_digest_and_escaped_user() {
        let nonce: [u8; NONCE_LEN] = spec_nonce().try_into().unwrap_or_default();
        let cred = Credential::new("u<ser", SecretString::from(SPEC_PASSWORD));
        let h = security_header(&cred, &nonce, SPEC_CREATED).unwrap_or_default();
        assert!(h.contains("<wsse:Username>u&lt;ser</wsse:Username>"));
        assert!(h.contains(&format!("#PasswordDigest\">{SPEC_DIGEST}</wsse:Password>")));
        assert!(h.contains(&format!("#Base64Binary\">{SPEC_NONCE_B64}</wsse:Nonce>")));
        assert!(h.contains(&format!("<wsu:Created>{SPEC_CREATED}</wsu:Created>")));
        assert!(!h.contains(SPEC_PASSWORD));
    }

    #[test]
    fn user_with_a_control_character_is_refused() {
        let cred = Credential::new("a\u{1}b", SecretString::from("pw"));
        let r = security_header(&cred, &[0; NONCE_LEN], SPEC_CREATED);
        assert_eq!(r.err(), Some(OnvifError::UserNotXmlSafe));
    }

    #[test]
    fn anonymous_envelope_has_no_header() {
        let b = envelope(None, "<x/>").unwrap_or_default();
        let s = String::from_utf8_lossy(&b);
        assert!(!s.contains("Security"));
        assert!(s.contains("<s:Body><x/></s:Body>"));
    }

    #[test]
    fn two_envelopes_use_different_nonces() {
        let cred = Credential::new("u", SecretString::from("pw"));
        let a = envelope(Some(&cred), "<x/>").unwrap_or_default();
        let b = envelope(Some(&cred), "<x/>").unwrap_or_default();
        let nonce = |m: &Bytes| {
            let s = String::from_utf8_lossy(m).into_owned();
            let from = s.find("#Base64Binary\">").map_or(0, |i| i + 15);
            s[from..].split('<').next().unwrap_or_default().to_owned()
        };
        assert_ne!(nonce(&a), nonce(&b));
        assert_eq!(STANDARD.decode(nonce(&a)).map_or(0, |v| v.len()), 16);
    }
}
