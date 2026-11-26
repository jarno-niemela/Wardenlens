//! `wardenlens token create|list|revoke` (#65): API tokens in the index at `database.path`.
//!
//! Generation, encoding and hashing are `wardenlens_api::token` (the one codec); the index only
//! stores what it is given ([`Index::insert_token`] and friends). This module adds no crypto.
//!
//! * `create --name <label>` validates the name first (nothing is opened for a bad one), generates a
//!   token, stores its id, digest, name and time, and prints the `wl_<id>_<secret>` string as the
//!   only line on stdout. Everything else goes to stderr. The secret is never logged and is
//!   zeroised after printing. An id collision (an id of an active **or revoked** token) generates
//!   a new token, at most [`MAX_ATTEMPTS`] times, then fails with [`TokenError::IdCollision`].
//!   Before anything is generated, stdout must be open for writing (`fcntl(F_GETFL)`) and not
//!   `/dev/null` (which is also what the Rust runtime turns a closed fd 1 into), else
//!   [`TokenError::StdoutClosed`] and nothing is created. The token is delivered once its line
//!   has been written **and flushed** to stdout; the stderr hint after that is best-effort (its
//!   failure is ignored, exit 0). If writing or flushing stdout fails, the token is revoked: when
//!   that succeeds the result is [`TokenError::Output`]; when it fails the token may still be
//!   active and the result is [`TokenError::OutputUnrevoked`], which names the id.
//! * `list` prints a tab-separated table, oldest first: id, name, created and last used (UTC, or
//!   `never`), revoked (`yes`/`no`). Names hold no control character (checked when stored and when
//!   read), so a name cannot forge a line or a column.
//! * `revoke <id>` sets `revoked` (the row stays). An already revoked token is a success; an
//!   unknown id is [`TokenError::NotFound`] (exit 1). Its stderr confirmation is best-effort:
//!   once the token is revoked the command exits 0 whatever stderr does.
//!
//! Exit codes: 0 success; 1 an unknown id or an invalid config; 2 everything else.

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use wardenlens_api::token::{RandomUnavailable, Token};
use wardenlens_core::time::UnixMs;
use wardenlens_core::token_store::{
    InvalidTokenId, InvalidTokenName, NewToken, RevokeOutcome, TokenId, TokenName, TokenSummary,
};
use wardenlens_index::{Index, IndexError};
use zeroize::Zeroizing;

use super::{Context, report_error};
use crate::args::TokenCommand;
use crate::config_file::{ConfigFileError, load, resolve_path};

/// How many tokens `create` generates before it gives up on a colliding id. With 40 random bits
/// of id, a second collision in a row is already astronomically unlikely, so reaching the limit
/// means the generator or the store is broken.
const MAX_ATTEMPTS: u32 = 8;

/// Why a token command failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TokenError {
    /// The config could not be used.
    #[error(transparent)]
    Config(#[from] ConfigFileError),
    /// The name was refused.
    #[error("invalid token name: {0}")]
    Name(#[source] InvalidTokenName),
    /// The id argument is not a token id.
    #[error("invalid token id: {0}")]
    InvalidId(#[source] InvalidTokenId),
    /// No token has this id.
    #[error("no token with id {id}")]
    NotFound { id: String },
    /// The index refused.
    #[error("the token store cannot be used")]
    Index(#[source] IndexError),
    /// Every generated token had an id that exists; nothing was stored.
    #[error("no unused token id found in {attempts} attempts; nothing was stored")]
    IdCollision { attempts: u32 },
    /// The system random generator is unavailable.
    #[error("the system random number generator is unavailable")]
    Random(#[source] RandomUnavailable),
    /// The clock is outside 2000 to 2099.
    #[error("the system clock is outside the supported range")]
    Clock,
    /// Writing to stdout failed. For `create`, a token that had been stored was revoked again
    /// (so none is left active); `list` has nothing to undo.
    #[error("cannot write to stdout")]
    Output(#[source] io::Error),
    /// `create` could not write its token to stdout and could not revoke it either: the token
    /// may still be active, but nobody has its secret. Names the id (never the secret). The
    /// error source is the output failure; why the revoke failed is `revoke`, shown in the
    /// message.
    #[error(
        "cannot write to stdout, and token {id} could not be revoked ({revoke}); run `wardenlens token revoke {id}`"
    )]
    OutputUnrevoked {
        id: String,
        #[source]
        source: io::Error,
        revoke: RevokeFailure,
    },
    /// `create` needs stdout to deliver the token and it is unusable for that: not open for
    /// writing (a read-only descriptor), or `/dev/null`, which is also what the Rust runtime turns
    /// a closed fd 1 into; nothing was created.
    #[error("stdout is not open for writing (or is /dev/null); nothing was created")]
    StdoutClosed,
}

/// Why the revoke after a failed delivery did not revoke.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RevokeFailure {
    /// The store failed.
    #[error("the token store failed: {0}")]
    Index(#[source] IndexError),
    /// The store has no row with the id that was just inserted.
    #[error("the token row is missing")]
    Missing,
}

impl TokenError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Config(e) => e.exit_code(),
            Self::NotFound { .. } => 1,
            _ => 2,
        }
    }
}

pub(crate) fn execute(cmd: &TokenCommand, ctx: &Context<'_>) -> ExitCode {
    match run(cmd, ctx, &mut io::stdout().lock(), &mut io::stderr().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, ctx.log_format);
            ExitCode::from(e.exit_code())
        }
    }
}

fn run(
    cmd: &TokenCommand,
    ctx: &Context<'_>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<(), TokenError> {
    // Arguments are checked before any file is opened, so a bad one creates nothing.
    let parsed = match cmd {
        TokenCommand::Create { name } => {
            let name = TokenName::new(name).map_err(TokenError::Name)?;
            // Before anything is generated or stored: a token that cannot be delivered is
            // never made.
            stdout_is_writable()?;
            Parsed::Create(name)
        }
        TokenCommand::List => Parsed::List,
        TokenCommand::Revoke { id } => {
            Parsed::Revoke(TokenId::parse(id).map_err(TokenError::InvalidId)?)
        }
    };
    let config = load(&resolve_path(ctx.config_flag, ctx.env)?)?;
    let mut index = Index::open(config.database_path()).map_err(TokenError::Index)?;
    match parsed {
        Parsed::Create(name) => create(&mut index, &name, Token::generate, out, err),
        Parsed::List => {
            let tokens = index.list_tokens().map_err(TokenError::Index)?;
            print_table(&tokens, out).map_err(TokenError::Output)
        }
        Parsed::Revoke(id) => revoke(&mut index, id, err),
    }
}

enum Parsed {
    Create(TokenName),
    List,
    Revoke(TokenId),
}

/// Fails with [`TokenError::StdoutClosed`] unless fd 1 can show the token to somebody: it must be
/// open with a write access mode and must not be `/dev/null`. (A full or broken stdout that is
/// open is caught later, by the write itself.)
///
/// Rust's runtime reopens a closed fd 1 as `/dev/null` before `main`, so "closed" cannot be seen
/// as `EBADF` here; it looks exactly like a redirect to `/dev/null`, which would swallow the token
/// just the same, so both are refused.
fn stdout_is_writable() -> Result<(), TokenError> {
    use rustix::fs::{FileType, OFlags, fcntl_getfl, fstat, stat};
    use std::os::fd::AsFd as _;
    let fd = io::stdout().as_fd().try_clone_to_owned().ok();
    let usable = fd.as_ref().is_some_and(|fd| {
        let writable = fcntl_getfl(fd).is_ok_and(|f| f.intersects(OFlags::WRONLY | OFlags::RDWR));
        let null = match (fstat(fd), stat("/dev/null")) {
            (Ok(a), Ok(b)) => {
                FileType::from_raw_mode(a.st_mode) == FileType::CharacterDevice
                    && a.st_rdev == b.st_rdev
            }
            _ => false,
        };
        writable && !null
    });
    if usable {
        Ok(())
    } else {
        Err(TokenError::StdoutClosed)
    }
}

fn now() -> Result<UnixMs, TokenError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .ok_or(TokenError::Clock)?;
    UnixMs::new(ms).map_err(|_| TokenError::Clock)
}

/// Generates and stores a token, regenerating on an id collision (see the module docs).
fn store_new_token(
    index: &mut Index,
    name: &TokenName,
    created_at: UnixMs,
    mut generate: impl FnMut() -> Result<Token, RandomUnavailable>,
) -> Result<Token, TokenError> {
    for _ in 0..MAX_ATTEMPTS {
        let token = generate().map_err(TokenError::Random)?;
        let record = NewToken {
            id: *token.id(),
            digest: token.secret().digest(),
            name: name.clone(),
            created_at,
        };
        match index.insert_token(&record) {
            Ok(()) => return Ok(token),
            Err(IndexError::TokenIdTaken) => {}
            Err(e) => return Err(TokenError::Index(e)),
        }
    }
    Err(TokenError::IdCollision {
        attempts: MAX_ATTEMPTS,
    })
}

fn create(
    index: &mut Index,
    name: &TokenName,
    generate: impl FnMut() -> Result<Token, RandomUnavailable>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<(), TokenError> {
    let token = store_new_token(index, name, now()?, generate)?;
    deliver(&token, out, |id| revoke_undelivered(index, *id))?;
    // The token has been delivered (written and flushed). From here nothing may fail the
    // command: a script that saw a failure exit would discard a token that is valid. The hint
    // is best-effort; the id is public and the secret is not repeated.
    let _ = writeln!(
        err,
        "created token {} (\"{}\"); this is the only time it is shown",
        token.id(),
        name.as_str()
    );
    Ok(())
}

/// Revokes a token that could not be delivered; `Revoked` and `AlreadyRevoked` are success, an
/// unknown id is [`RevokeFailure::Missing`].
fn revoke_undelivered(index: &mut Index, id: TokenId) -> Result<(), RevokeFailure> {
    match index.revoke_token(&id) {
        Ok(RevokeOutcome::Revoked | RevokeOutcome::AlreadyRevoked) => Ok(()),
        Ok(RevokeOutcome::NotFound) => Err(RevokeFailure::Missing),
        Err(e) => Err(RevokeFailure::Index(e)),
    }
}

/// Writes the token line to `out` and flushes. On a write or flush failure nobody has the
/// secret, so `revoke` is called: if it reports success the error is [`TokenError::Output`],
/// otherwise [`TokenError::OutputUnrevoked`].
fn deliver(
    token: &Token,
    out: &mut impl Write,
    revoke: impl FnOnce(&TokenId) -> Result<(), RevokeFailure>,
) -> Result<(), TokenError> {
    let shown = Zeroizing::new(token.expose());
    let printed = writeln!(out, "{}", shown.as_str()).and_then(|()| out.flush());
    match printed {
        Ok(()) => Ok(()),
        Err(source) => match revoke(token.id()) {
            Ok(()) => Err(TokenError::Output(source)),
            Err(revoke) => Err(TokenError::OutputUnrevoked {
                id: token.id().to_string(),
                source,
                revoke,
            }),
        },
    }
}

fn revoke(index: &mut Index, id: TokenId, err: &mut impl Write) -> Result<(), TokenError> {
    let message = match index.revoke_token(&id).map_err(TokenError::Index)? {
        RevokeOutcome::Revoked => format!("revoked token {id}"),
        RevokeOutcome::AlreadyRevoked => format!("token {id} was already revoked"),
        RevokeOutcome::NotFound => return Err(TokenError::NotFound { id: id.to_string() }),
    };
    // Revoked: the command has done its work. A failing stderr must not turn that into a
    // failure exit (best-effort, like the `create` hint).
    let _ = writeln!(err, "{message}");
    Ok(())
}

fn print_table(tokens: &[TokenSummary], out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "id\tname\tcreated\tlast used\trevoked")?;
    for t in tokens {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            t.id,
            t.name.as_str(),
            t.created_at.to_utc_text(),
            t.last_used_at
                .map_or_else(|| "never".to_owned(), UnixMs::to_utc_text),
            if t.revoked { "yes" } else { "no" }
        )?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_700_000_000_000;

    fn open() -> (tempfile::TempDir, Index) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // The index refuses a group-writable parent, which a umask of 0002 would give.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("index.db");
        let index = Index::open(&path).unwrap();
        (dir, index)
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    fn name(s: &str) -> TokenName {
        TokenName::new(s).unwrap()
    }

    fn at(ms: i64) -> UnixMs {
        UnixMs::new(ms).unwrap()
    }

    /// A token with a chosen id and a secret made of `fill` (any of `A..=Z` is canonical in the
    /// first position) and 42 more `A`s: 43 characters, so it parses.
    fn token(id: &str, fill: char) -> Token {
        Token::parse(&format!("wl_{id}_{fill}{}", "A".repeat(42))).unwrap()
    }

    #[test]
    fn a_new_token_is_stored_as_a_digest_and_verifies() {
        let (_d, mut index) = open();
        let made = store_new_token(&mut index, &name("grafana"), at(T0), Token::generate).unwrap();
        let record = index.find_token(made.id()).unwrap();
        assert!(made.verify(record.as_ref()));
        // The stored digest is the digest of the secret, not the secret.
        assert_eq!(record.unwrap().digest, made.secret().digest());
        let listed = index.list_tokens().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_str(), "grafana");
        assert_eq!(listed[0].created_at, at(T0));
    }

    #[test]
    fn a_collision_regenerates_and_never_reuses_a_revoked_id() {
        let (_d, mut index) = open();
        // An active token and a revoked one hold the ids the generator offers first.
        store_new_token(&mut index, &name("a"), at(T0), || {
            Ok(token("aaaaaaaa", 'B'))
        })
        .unwrap();
        store_new_token(&mut index, &name("b"), at(T0), || {
            Ok(token("bbbbbbbb", 'C'))
        })
        .unwrap();
        index
            .revoke_token(&TokenId::parse("bbbbbbbb").unwrap())
            .unwrap();
        let mut offered = vec![
            token("aaaaaaaa", 'D'),
            token("bbbbbbbb", 'E'),
            token("cccccccc", 'F'),
        ]
        .into_iter();
        let made = store_new_token(&mut index, &name("c"), at(T0), || {
            Ok(offered.next().unwrap())
        })
        .unwrap();
        assert_eq!(made.id().as_str(), "cccccccc");
        assert_eq!(
            offered.next().map(|t| t.id().to_string()),
            None,
            "all three offered"
        );
        // The two earlier rows are untouched.
        let a = index
            .find_token(&TokenId::parse("aaaaaaaa").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(a.digest, token("aaaaaaaa", 'B').secret().digest());
        let b = index
            .find_token(&TokenId::parse("bbbbbbbb").unwrap())
            .unwrap()
            .unwrap();
        assert!(b.revoked);
        assert_eq!(index.list_tokens().unwrap().len(), 3);
    }

    #[test]
    fn collisions_stop_after_the_bound_with_a_typed_error_and_store_nothing_new() {
        let (_d, mut index) = open();
        store_new_token(&mut index, &name("a"), at(T0), || {
            Ok(token("aaaaaaaa", 'B'))
        })
        .unwrap();
        let mut calls = 0_u32;
        let err = store_new_token(&mut index, &name("x"), at(T0), || {
            calls += 1;
            Ok(token("aaaaaaaa", 'J'))
        })
        .unwrap_err();
        assert!(
            matches!(err, TokenError::IdCollision { attempts } if attempts == MAX_ATTEMPTS),
            "{err:?}"
        );
        assert_eq!(calls, MAX_ATTEMPTS);
        assert_eq!(index.list_tokens().unwrap().len(), 1);
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn one_collision_below_the_bound_still_succeeds() {
        let (_d, mut index) = open();
        store_new_token(&mut index, &name("a"), at(T0), || {
            Ok(token("aaaaaaaa", 'B'))
        })
        .unwrap();
        let mut calls = 0_u32;
        let made = store_new_token(&mut index, &name("x"), at(T0), || {
            calls += 1;
            Ok(if calls < MAX_ATTEMPTS {
                token("aaaaaaaa", 'J')
            } else {
                token("dddddddd", 'J')
            })
        })
        .unwrap();
        assert_eq!(made.id().as_str(), "dddddddd");
    }

    #[test]
    fn an_unavailable_random_source_is_a_typed_error() {
        let (_d, mut index) = open();
        let err =
            store_new_token(&mut index, &name("x"), at(T0), || Err(RandomUnavailable)).unwrap_err();
        assert!(matches!(err, TokenError::Random(_)));
        assert_eq!(err.exit_code(), 2);
        assert_eq!(index.list_tokens().unwrap(), vec![]);
    }

    #[test]
    fn create_prints_only_the_token_on_stdout_and_never_the_secret_on_stderr() {
        let (_d, mut index) = open();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        create(&mut index, &name("ci"), Token::generate, &mut out, &mut err).unwrap();
        let printed = String::from_utf8(out).unwrap();
        assert!(printed.ends_with('\n') && printed.matches('\n').count() == 1);
        let parsed = Token::parse(printed.trim_end()).unwrap();
        let hint = String::from_utf8(err).unwrap();
        assert!(hint.contains(parsed.id().as_str()));
        assert!(!hint.contains(printed.trim_end().rsplit('_').next().unwrap()));
        assert!(parsed.verify(index.find_token(parsed.id()).unwrap().as_ref()));
    }

    /// A writer that always fails.
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn a_token_that_cannot_be_printed_is_revoked_again() {
        let (_d, mut index) = open();
        let err = create(
            &mut index,
            &name("ci"),
            Token::generate,
            &mut Broken,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenError::Output(_)));
        assert_eq!(err.exit_code(), 2);
        let listed = index.list_tokens().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].revoked);
    }

    /// Fails only on `flush`: the line may sit in a buffer, so the token is not delivered.
    struct FlushFails(Vec<u8>);
    impl Write for FlushFails {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn a_failed_flush_counts_as_not_delivered_and_revokes() {
        let (_d, mut index) = open();
        let err = create(
            &mut index,
            &name("ci"),
            Token::generate,
            &mut FlushFails(Vec::new()),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenError::Output(_)), "{err:?}");
        assert!(index.list_tokens().unwrap()[0].revoked);
    }

    #[test]
    fn revoking_an_undelivered_token_maps_every_outcome() {
        let (_d, mut index) = open();
        let made = store_new_token(&mut index, &name("a"), at(T0), Token::generate).unwrap();
        assert!(revoke_undelivered(&mut index, *made.id()).is_ok());
        assert!(
            revoke_undelivered(&mut index, *made.id()).is_ok(),
            "already revoked"
        );
        let unknown = TokenId::parse("zzzzzzzz").unwrap();
        assert!(matches!(
            revoke_undelivered(&mut index, unknown),
            Err(RevokeFailure::Missing)
        ));
        let e = TokenError::OutputUnrevoked {
            id: "zzzzzzzz".to_owned(),
            source: io::Error::from(io::ErrorKind::BrokenPipe),
            revoke: RevokeFailure::Missing,
        };
        assert!(e.to_string().contains("the token row is missing"));
    }

    #[test]
    fn deliver_revokes_once_on_failure_and_never_on_success() {
        let t = token("aaaaaaaa", 'B');
        for (out_ok, revoke_ok) in [(true, true), (false, true), (false, false)] {
            let failure = || RevokeFailure::Index(IndexError::Busy { op: "revoke token" });
            let mut calls = 0_u32;
            let mut seen = None;
            let result = if out_ok {
                deliver(&t, &mut Vec::new(), |id| {
                    calls += 1;
                    seen = Some(*id);
                    if revoke_ok { Ok(()) } else { Err(failure()) }
                })
            } else {
                deliver(&t, &mut Broken, |id| {
                    calls += 1;
                    seen = Some(*id);
                    if revoke_ok { Ok(()) } else { Err(failure()) }
                })
            };
            match (out_ok, revoke_ok) {
                (true, _) => {
                    assert!(result.is_ok());
                    assert_eq!(calls, 0, "a delivered token is never revoked");
                }
                (false, true) => {
                    assert!(matches!(result, Err(TokenError::Output(_))));
                    assert_eq!((calls, seen), (1, Some(*t.id())));
                }
                (false, false) => {
                    let e = result.unwrap_err();
                    assert_eq!((calls, seen), (1, Some(*t.id())));
                    assert_eq!(e.exit_code(), 2);
                    let msg = e.to_string();
                    assert!(msg.contains("aaaaaaaa"), "{msg}");
                    assert!(msg.contains("wardenlens token revoke aaaaaaaa"), "{msg}");
                    let secret = t.expose().splitn(3, '_').nth(2).unwrap().to_owned();
                    assert!(!msg.contains(&secret) && !format!("{e:?}").contains(&secret));
                    // The revoke failure's cause is kept, and it is not the output error's.
                    assert!(msg.contains("database is busy"), "{msg}");
                    assert!(
                        matches!(
                            e,
                            TokenError::OutputUnrevoked {
                                revoke: RevokeFailure::Index(IndexError::Busy { .. }),
                                ..
                            }
                        ),
                        "{e:?}"
                    );
                    assert!(
                        std::error::Error::source(&e)
                            .is_some_and(<dyn std::error::Error>::is::<io::Error>)
                    );
                }
            }
        }
    }

    #[test]
    fn a_failing_stderr_after_delivery_is_never_a_failure() {
        let (_d, mut index) = open();
        let mut out = Vec::new();
        create(
            &mut index,
            &name("ci"),
            Token::generate,
            &mut out,
            &mut Broken,
        )
        .unwrap();
        // The token was printed and is still active.
        let printed = String::from_utf8(out).unwrap();
        let parsed = Token::parse(printed.trim_end()).unwrap();
        assert!(parsed.verify(index.find_token(parsed.id()).unwrap().as_ref()));
        // The same for the confirmation of `revoke`.
        revoke(&mut index, *parsed.id(), &mut Broken).unwrap();
        assert!(!parsed.verify(index.find_token(parsed.id()).unwrap().as_ref()));
    }

    #[test]
    fn revoke_distinguishes_revoked_already_revoked_and_unknown() {
        let (_d, mut index) = open();
        let made = store_new_token(&mut index, &name("a"), at(T0), Token::generate).unwrap();
        let mut err = Vec::new();
        revoke(&mut index, *made.id(), &mut err).unwrap();
        assert!(String::from_utf8(err).unwrap().starts_with("revoked token"));
        assert!(!made.verify(index.find_token(made.id()).unwrap().as_ref()));
        let mut err = Vec::new();
        revoke(&mut index, *made.id(), &mut err).unwrap();
        assert!(String::from_utf8(err).unwrap().contains("already revoked"));
        let unknown = TokenId::parse("zzzzzzzz").unwrap();
        let e = revoke(&mut index, unknown, &mut Vec::new()).unwrap_err();
        assert!(matches!(&e, TokenError::NotFound { id } if id == "zzzzzzzz"));
        assert_eq!(e.exit_code(), 1);
    }

    #[test]
    fn the_table_shows_id_name_times_and_flag_and_never_the_secret_or_digest() {
        let (_d, mut index) = open();
        let a = store_new_token(&mut index, &name("grafana"), at(T0), Token::generate).unwrap();
        let b =
            store_new_token(&mut index, &name("backup"), at(T0 + 1000), Token::generate).unwrap();
        index.touch_token(b.id(), at(T0 + 5000)).unwrap();
        index.revoke_token(b.id()).unwrap();
        let mut out = Vec::new();
        print_table(&index.list_tokens().unwrap(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "id\tname\tcreated\tlast used\trevoked");
        assert_eq!(
            lines[1],
            format!("{}\tgrafana\t2023-11-14T22:13:20Z\tnever\tno", a.id())
        );
        assert_eq!(
            lines[2],
            format!(
                "{}\tbackup\t2023-11-14T22:13:21Z\t2023-11-14T22:13:25Z\tyes",
                b.id()
            )
        );
        assert_eq!(lines.len(), 3);
        for t in [&a, &b] {
            let exposed = t.expose();
            let secret = exposed.splitn(3, '_').nth(2).unwrap();
            assert_eq!(secret.len(), 43);
            assert!(!text.contains(secret));
            assert!(!text.contains(&exposed));
            assert!(!text.contains(&hex(&t.secret().digest())));
        }
    }
}
