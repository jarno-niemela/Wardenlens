//! Which credential a camera entry gets, if any, and the check that every emitted credential
//! passes core's one storable-login rule ([`Credential::check`], shared with the vault).
//!
//! Sources: the `login` and `password` fields of `settings`, and the userinfo of the source URL.
//!
//! - A login field that is empty or only white space counts as no user. The fields are present
//!   when the user or the password is non-empty.
//! - Neither present: no credential. Exactly one present: that one.
//! - Both present: they must be the same pair (after percent-decoding the URL's). Otherwise the
//!   camera is skipped as [`SkipReason::ConflictingCredential`]: nothing is chosen, merged or
//!   dropped. In particular a login field with a user and no password beside a URL that has a
//!   password conflicts, so a password is never replaced by an empty one.
//! - The chosen pair is then checked: a control character (RTSP header injection) or a `:` in
//!   the user (ambiguous under Basic authentication) is [`SkipReason::InvalidCredential`]; no
//!   user is [`SkipReason::CredentialWithoutUser`]; the rest of the vault's rule (length, NUL)
//!   is [`Credential::check`].

use secrecy::SecretString;
use secrecy::zeroize::Zeroizing;
use wardenlens_core::camera::{Credential, CredentialRule};

use crate::SkipReason;
use crate::source::RawUserinfo;

/// The credential for one entry. `login` and `password` are the field texts as read.
pub(crate) fn choose(
    login: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    userinfo: Option<&RawUserinfo>,
) -> Result<Option<Credential>, SkipReason> {
    let user_field = login.filter(|l| !l.trim().is_empty()).unwrap_or_default();
    let password_field = password.unwrap_or_default();
    let fields_present = !user_field.is_empty() || !password_field.is_empty();
    let (user, password) = match (fields_present, userinfo) {
        (false, None) => return Ok(None),
        (true, None) => (user_field, password_field),
        (false, Some(u)) => u.decode()?,
        (true, Some(u)) => {
            let (url_user, url_password) = u.decode()?;
            if *url_user != *user_field || *url_password != *password_field {
                return Err(SkipReason::ConflictingCredential);
            }
            (user_field, password_field)
        }
    };
    validate(&user, &password)?;
    Ok(Some(Credential::new(
        user.as_str(),
        SecretString::from(password.as_str().to_owned()),
    )))
}

/// The checks every emitted credential passes.
pub(crate) fn validate(user: &str, password: &str) -> Result<(), SkipReason> {
    let control = |s: &str| s.chars().any(char::is_control);
    if control(user) || control(password) || user.contains(':') {
        return Err(SkipReason::InvalidCredential);
    }
    Credential::check(user, password).map_err(|rule| match rule {
        CredentialRule::UserEmpty => SkipReason::CredentialWithoutUser,
        _ => SkipReason::InvalidCredential,
    })
}
