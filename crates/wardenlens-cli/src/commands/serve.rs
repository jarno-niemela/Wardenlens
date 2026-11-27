//! `wardenlens serve` (#68): the service. This module reads the config, the key file, the camera
//! registry and the vault, builds one RTSP source per registered camera, binds `api.listen` and
//! hands everything to [`crate::wiring::run`], which does the wiring (see its module docs).
//!
//! * The config, the key file and the index must be usable, or nothing starts (exit 2; an invalid
//!   config is exit 1, as for the other commands). The first thing taken is the process lock, an
//!   exclusive `flock` on `wardenlens.lock` in the directory of `database.path`, held until the
//!   process exits (ADR 0005 section 9): a second `serve` exits 2 at once. Other commands (`token`,
//!   `import`) do not take it; they serialise with the service through `Index::open`.
//! * A camera whose host is missing from the vault, or whose vault entries cannot be read, is
//!   logged **by id** and skipped; the others run. Its login is decrypted here into the stream
//!   source and goes nowhere else.
//! * SIGTERM or SIGINT stops the service: ingest is cancelled, open segments are flushed and
//!   indexed, and the process exits 0 within 10 s (exit 1 if that deadline is missed).
//! * Exit codes: 0 stopped on a signal; 1 an invalid config or a shutdown that overran its
//!   deadline; 2 everything else that prevented start-up.

use std::io;
use std::path::Path;
use std::process::ExitCode;

use secrecy::{ExposeSecret, SecretString};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use wardenlens_core::camera::{
    Camera, CameraError, CameraId, Credential, DisplayName, Host, StreamRole,
};
use wardenlens_core::config::Config;
use wardenlens_core::entry::EntryKind;
use wardenlens_fsutil::{FileLock, FsError, PrivateFile, open_private_file};
use wardenlens_index::{Index, IndexError};
use wardenlens_ingest::RetinaSource;
use wardenlens_secrets::{KeyFile, SecretsError};
use wardenlens_vault::{Value, Vault, VaultError};

use super::import::vault_path;
use super::{Context, report_error};
use crate::config_file::{ConfigFileError, load, resolve_path};
use crate::wiring::{
    CameraInput, ConnectionStats, ServeError, SystemClock, Tuning, raise_nofile_limit, run,
};

/// Why `serve` failed.
#[derive(Debug, thiserror::Error)]
enum CommandError {
    /// The config could not be used.
    #[error(transparent)]
    Config(#[from] ConfigFileError),
    /// The key file does not exist.
    #[error("key file {path:?} does not exist; run `wardenlens secrets init` to create it")]
    KeyMissing { path: std::path::PathBuf },
    /// The key file was refused.
    #[error("the key file cannot be used")]
    Key(#[source] SecretsError),
    /// Another `serve` holds the process lock (`wardenlens.lock` next to the index).
    #[error("another wardenlens instance is running (it holds the process lock)")]
    AlreadyRunning,
    /// The process lock file cannot be created or locked.
    #[error("the process lock cannot be taken")]
    Lock(#[source] FsError),
    /// The index cannot be opened.
    #[error("the index cannot be opened")]
    Index(#[source] IndexError),
    /// The registry has cameras and the vault cannot be opened with the key.
    #[error("the vault cannot be used")]
    Vault(#[source] VaultError),
    /// The async runtime or a signal handler could not be set up.
    #[error("the runtime cannot be started")]
    Runtime(#[source] io::Error),
    /// `api.listen` cannot be bound.
    #[error("the API address cannot be bound")]
    Bind(#[source] io::Error),
    /// The service refused to start or did not stop in time.
    #[error(transparent)]
    Serve(#[from] ServeError),
}

impl CommandError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Config(e) => e.exit_code(),
            Self::Serve(ServeError::ShutdownTimeout(_)) => 1,
            _ => 2,
        }
    }
}

pub(crate) fn execute(ctx: &Context<'_>) -> ExitCode {
    match start(ctx) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, ctx.log_format);
            ExitCode::from(e.exit_code())
        }
    }
}

fn start(ctx: &Context<'_>) -> Result<(), CommandError> {
    let config = load(&resolve_path(ctx.config_flag, ctx.env)?)?;
    if let Err(e) = raise_nofile_limit() {
        tracing::warn!(error = %e, "could not raise the open-file limit");
    }
    let key = load_key(config.key_file())?;
    // Held (not read) until this function returns, i.e. for the life of the service.
    let _process_lock = take_process_lock(&config)?;
    let index = Index::open(config.database_path()).map_err(CommandError::Index)?;
    let cameras = camera_inputs(&config, &index, key)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CommandError::Runtime)?;
    runtime.block_on(async {
        let listener = TcpListener::bind(config.listen())
            .await
            .map_err(CommandError::Bind)?;
        let mut term = signal(SignalKind::terminate()).map_err(CommandError::Runtime)?;
        let mut int = signal(SignalKind::interrupt()).map_err(CommandError::Runtime)?;
        let shutdown = async {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        };
        tracing::info!(port = config.listen().port(), "API listening");
        run(
            &config,
            index,
            cameras,
            listener,
            shutdown,
            Tuning::default(),
            ConnectionStats::default(),
        )
        .await
        .map_err(CommandError::from)
    })
}

/// The file name of the process lock, next to the index.
const LOCK_FILE_NAME: &str = "wardenlens.lock";

/// Takes the exclusive process lock; `AlreadyRunning` when another description holds it.
fn take_process_lock(config: &Config) -> Result<(PrivateFile, FileLock), CommandError> {
    let dir = match config.database_path().parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file = open_private_file(&dir.join(LOCK_FILE_NAME)).map_err(CommandError::Lock)?;
    match file.try_lock_exclusive().map_err(CommandError::Lock)? {
        Some(lock) => Ok((file, lock)),
        None => Err(CommandError::AlreadyRunning),
    }
}

/// The key file, or a message that points at `secrets init` when it is missing.
fn load_key(path: &Path) -> Result<KeyFile, CommandError> {
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
        return Err(CommandError::KeyMissing {
            path: path.to_path_buf(),
        });
    }
    KeyFile::load(path).map_err(CommandError::Key)
}

/// One stream source per registered camera that the vault can complete. The vault is opened only
/// when there is a camera to read it for, and is dropped (with the key) before the service runs.
fn camera_inputs(
    config: &Config,
    index: &Index,
    key: KeyFile,
) -> Result<Vec<CameraInput<RetinaSource<SystemClock>>>, CommandError> {
    let stored = index.list_cameras(&[]).map_err(CommandError::Index)?;
    if stored.is_empty() {
        tracing::warn!("no cameras are registered; the service records nothing");
        return Ok(Vec::new());
    }
    let vault = Vault::open(&vault_path(config), key).map_err(CommandError::Vault)?;
    let mut inputs = Vec::new();
    for s in &stored {
        let record = s.record();
        match read_camera(&vault, record.id()) {
            Ok(secrets) => {
                let camera = Camera::new(
                    record.id().clone(),
                    secrets.name,
                    record.model().clone(),
                    secrets.host.clone(),
                    record.port(),
                    record.streams().clone(),
                );
                let source = RetinaSource::new(
                    secrets.host,
                    record.port(),
                    record.streams().main.clone(),
                    secrets.credential,
                    StreamRole::Main,
                    SystemClock,
                );
                inputs.push(CameraInput { camera, source });
            }
            Err(reason) => {
                tracing::error!(camera = %record.id(), reason, "camera skipped: vault entries unusable");
            }
        }
    }
    let ids: Vec<&str> = inputs.iter().map(|i| i.camera.id().as_str()).collect();
    tracing::info!(cameras = ?ids, "cameras to record");
    Ok(inputs)
}

/// What the vault holds of one camera.
struct CameraSecrets {
    host: Host,
    name: DisplayName,
    credential: Option<Credential>,
}

/// Reads `cam:<id>:host`, `:name` and `:credential`. The reason is a fixed word, never a value.
fn read_camera(vault: &Vault, id: &CameraId) -> Result<CameraSecrets, &'static str> {
    let text = |kind: EntryKind| -> Result<SecretString, &'static str> {
        let entry_id = id.entry_id(kind).map_err(|_: CameraError| "bad entry id")?;
        match vault.get(&entry_id) {
            Ok(Some(entry)) => match entry.value {
                Value::Text(t) => Ok(t),
                _ => Err("entry has the wrong shape"),
            },
            Ok(None) => Err("entry missing"),
            Err(_) => Err("entry unreadable"),
        }
    };
    let host = Host::new(text(EntryKind::Host)?.expose_secret()).map_err(|_| "host invalid")?;
    let name = DisplayName::new(text(EntryKind::DisplayName)?.expose_secret())
        .map_err(|_| "name invalid")?;
    let credential_id = id
        .entry_id(EntryKind::Credential)
        .map_err(|_: CameraError| "bad entry id")?;
    let credential = match vault.get(&credential_id) {
        Ok(None) => None,
        Ok(Some(entry)) => match entry.value {
            Value::Credential(c) => Some(Credential::new(c.username, c.password)),
            _ => return Err("entry has the wrong shape"),
        },
        Err(_) => return Err("entry unreadable"),
    };
    Ok(CameraSecrets {
        host,
        name,
        credential,
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use wardenlens_core::camera::{ModelRef, RtspPath, StreamSet};
    use wardenlens_core::time::UnixMs;
    use wardenlens_index::CameraRecord;
    use wardenlens_secrets::Credentials;
    use wardenlens_vault::Scan;

    use super::*;

    struct Site {
        _dir: tempfile::TempDir,
        config: Config,
    }

    impl Site {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let t = dir.path().display().to_string();
            for d in ["state", "keys"] {
                let p = dir.path().join(d);
                std::fs::create_dir_all(&p).unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let config = Config::from_toml_str(&format!(
                "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
                 archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
                 [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n"
            ))
            .unwrap();
            KeyFile::generate(config.key_file()).unwrap();
            Self { _dir: dir, config }
        }

        fn key(&self) -> KeyFile {
            KeyFile::load(self.config.key_file()).unwrap()
        }

        /// Registers `id` in the index and, per `parts`, writes its vault entries.
        fn add(&self, id: &str, host: bool, name: bool, login: Option<(&str, &str)>) {
            let id = CameraId::new(id).unwrap();
            let mut index = Index::open(self.config.database_path()).unwrap();
            let record = CameraRecord::new(
                id.clone(),
                ModelRef::new("acme", "c1").unwrap(),
                NonZeroU16::new(554).unwrap(),
                StreamSet::new(RtspPath::new("/s1").unwrap(), None),
            );
            index
                .upsert_camera(&record, &[], UnixMs::new(1_700_000_000_000).unwrap())
                .unwrap();
            drop(index);
            let path = vault_path(&self.config);
            let mut vault = if path.exists() {
                Vault::open(&path, self.key()).unwrap()
            } else {
                Vault::create(&path, self.key()).unwrap()
            };
            let text = |s: &str| Value::Text(SecretString::from(s.to_owned()));
            if host {
                vault
                    .set(
                        &id.entry_id(EntryKind::Host).unwrap(),
                        EntryKind::Host,
                        &text("192.0.2.10"),
                        Scan::Normal,
                    )
                    .unwrap();
            }
            if name {
                vault
                    .set(
                        &id.entry_id(EntryKind::DisplayName).unwrap(),
                        EntryKind::DisplayName,
                        &text("Synthetic"),
                        Scan::Normal,
                    )
                    .unwrap();
            }
            if let Some((u, p)) = login {
                vault
                    .set(
                        &id.entry_id(EntryKind::Credential).unwrap(),
                        EntryKind::Credential,
                        &Value::Credential(Credentials::new(u, p)),
                        Scan::Normal,
                    )
                    .unwrap();
            }
        }
    }

    #[test]
    fn a_camera_with_host_name_and_login_is_read() {
        let site = Site::new();
        site.add("cam-a", true, true, Some(("svc-user", "synthetic-pass-1")));
        let index = Index::open(site.config.database_path()).unwrap();
        let inputs = camera_inputs(&site.config, &index, site.key()).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].camera.id().as_str(), "cam-a");
        assert_eq!(inputs[0].camera.port().get(), 554);
    }

    /// One camera with a missing entry is skipped; the others are kept. A camera without a login
    /// entry is anonymous, not an error.
    #[test]
    fn an_incomplete_camera_is_skipped_and_the_others_run() {
        let site = Site::new();
        site.add("cam-a", true, true, None);
        site.add("cam-nohost", false, true, Some(("u", "p")));
        site.add("cam-noname", true, false, None);
        site.add("cam-b", true, true, Some(("u", "p")));
        let index = Index::open(site.config.database_path()).unwrap();
        let inputs = camera_inputs(&site.config, &index, site.key()).unwrap();
        let ids: Vec<&str> = inputs.iter().map(|i| i.camera.id().as_str()).collect();
        assert_eq!(ids, ["cam-a", "cam-b"]);
    }

    #[test]
    fn an_empty_registry_needs_no_vault() {
        let site = Site::new();
        let index = Index::open(site.config.database_path()).unwrap();
        assert!(!vault_path(&site.config).exists());
        let inputs = camera_inputs(&site.config, &index, site.key()).unwrap();
        assert!(inputs.is_empty());
    }

    /// With cameras registered, a vault that does not exist is a refusal (exit 2), not a service
    /// that silently records nothing.
    #[test]
    fn registered_cameras_without_a_vault_refuse_to_start() {
        let site = Site::new();
        site.add("cam-a", true, true, None);
        std::fs::remove_file(vault_path(&site.config)).unwrap();
        let index = Index::open(site.config.database_path()).unwrap();
        let err = camera_inputs(&site.config, &index, site.key())
            .err()
            .unwrap();
        assert!(matches!(err, CommandError::Vault(_)));
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn exit_codes() {
        assert_eq!(CommandError::AlreadyRunning.exit_code(), 2);
        assert_eq!(
            CommandError::Serve(ServeError::ShutdownTimeout(Duration::from_secs(10))).exit_code(),
            1
        );
        let invalid =
            ConfigFileError::Invalid(wardenlens_core::config::ConfigError::Missing { key: "k" });
        assert_eq!(CommandError::Config(invalid).exit_code(), 1);
    }

    #[test]
    fn a_second_lock_on_the_same_site_is_refused_until_the_first_is_dropped() {
        let site = Site::new();
        let first = take_process_lock(&site.config).unwrap();
        let err = take_process_lock(&site.config).err().unwrap();
        assert!(matches!(err, CommandError::AlreadyRunning));
        drop(first);
        take_process_lock(&site.config).unwrap();
    }
}
