//! [`Credential`] and the [`CredentialSource`] port (ADR 0006 section 10).
//!
//! The password is a [`SecretString`]; the user name is treated as sensitive too. `Debug` prints
//! neither, and `Credential` has no `Display`. Credentials are never part of a camera URL.

use std::fmt;

use secrecy::SecretString;

use super::CameraId;

/// A camera login. Hand it to the RTSP client in process; never put it in a URL or a log.
#[derive(Clone)]
pub struct Credential {
    /// The user name (sensitive; not printed by `Debug`).
    pub user: String,
    /// The password.
    pub password: SecretString,
}

impl Credential {
    /// Builds a credential from its two parts.
    #[must_use]
    pub fn new(user: impl Into<String>, password: SecretString) -> Self {
        Self {
            user: user.into(),
            password,
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("user", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Where camera credentials come from (the vault in production, a fake in tests). Users take it
/// as a generic parameter, never `dyn` (ARCH-3).
pub trait CredentialSource {
    /// The source's own error type. It must not carry credential or host values.
    type Error: std::error::Error;

    /// The credential for `camera`, or `None` when the camera has none (anonymous stream).
    ///
    /// # Errors
    /// The source's error when the lookup itself fails.
    fn credential(&self, camera: &CameraId) -> Result<Option<Credential>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::collections::HashMap;

    fn cred() -> Credential {
        Credential::new("svc-reader", SecretString::from("Tr0ub4dor-x9".to_owned()))
    }

    #[test]
    fn debug_never_prints_user_or_password_in_any_format() {
        let c = cred();
        let all = [
            format!("{c:?}"),
            format!("{c:#?}"),
            format!("{:?}", Some(&c)),
            format!("{:#?}", vec![c.clone()]),
            format!("{:?}", (&c, 1)),
        ];
        for shown in all {
            assert!(
                !shown.contains("Tr0ub4dor") && !shown.contains("x9"),
                "{shown}"
            );
            assert!(!shown.contains("svc-reader"), "{shown}");
            assert!(shown.contains("redacted"));
        }
    }

    #[test]
    fn clone_keeps_the_values() {
        let c = cred().clone();
        assert_eq!(c.user, "svc-reader");
        assert_eq!(c.password.expose_secret(), "Tr0ub4dor-x9");
    }

    #[derive(Debug, thiserror::Error)]
    #[error("lookup failed")]
    struct Fail;

    struct Fake(HashMap<String, Credential>, bool);

    impl CredentialSource for Fake {
        type Error = Fail;
        fn credential(&self, camera: &CameraId) -> Result<Option<Credential>, Fail> {
            if self.1 {
                return Err(Fail);
            }
            Ok(self.0.get(camera.as_str()).cloned())
        }
    }

    fn user_of<S: CredentialSource>(src: &S, id: &CameraId) -> Result<Option<String>, S::Error> {
        Ok(src.credential(id)?.map(|c| c.user))
    }

    #[test]
    fn works_through_generics() {
        let mut m = HashMap::new();
        m.insert("cam1".to_owned(), cred());
        let src = Fake(m, false);
        let id = CameraId::new("cam1").unwrap();
        assert_eq!(user_of(&src, &id).unwrap().as_deref(), Some("svc-reader"));
        assert!(
            src.credential(&CameraId::new("cam2").unwrap())
                .unwrap()
                .is_none()
        );
        assert!(Fake(HashMap::new(), true).credential(&id).is_err());
    }
}
