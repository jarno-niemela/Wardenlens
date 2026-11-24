//! The key file: a raw 32-byte file with strict permission rules (ADR 0006 section 6).

use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustix::fs::{Mode, OFlags};
use zeroize::Zeroizing;

use crate::error::SecretsError;

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Base64 of 32 bytes, with padding.
const KEY_B64_LEN: usize = 44;

/// A 32-byte symmetric key, zeroised on drop. `Debug` redacts it.
pub struct KeyFile {
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyFile([redacted])")
    }
}

fn io_err(operation: &'static str) -> impl FnOnce(std::io::Error) -> SecretsError {
    move |source| SecretsError::Io { operation, source }
}

/// Opens `path` with typed rustix flags; `O_NOFOLLOW` and `O_CLOEXEC` are always set, so they
/// cannot be dropped by a conversion.
fn open_nofollow(path: &Path, flags: OFlags, mode: Mode) -> std::io::Result<File> {
    let fd = rustix::fs::open(path, flags | OFlags::NOFOLLOW | OFlags::CLOEXEC, mode)?;
    Ok(File::from(fd))
}

/// Flushes the directory entry of a freshly created file so the only key survives a crash.
fn sync_parent(path: &Path) -> Result<(), SecretsError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(io_err("syncing directory"))
}

fn is_symlink_error(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
}

/// Refuses a path inside a git work tree (a `.git` entry in any ancestor of the parent directory).
///
/// This only detects a `.git` entry in an ancestor; a work tree with a separate git dir, or a bare
/// "dotfiles" work tree, is not detected.
fn refuse_work_tree(path: &Path) -> Result<(), SecretsError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        Some(_) => Path::new("."),
        None => return Err(SecretsError::KeyFileNoParent),
    };
    let parent = parent
        .canonicalize()
        .map_err(io_err("resolving directory"))?;
    for dir in parent.ancestors() {
        if dir.join(".git").symlink_metadata().is_ok() {
            return Err(SecretsError::KeyFileInWorkTree);
        }
    }
    Ok(())
}

impl KeyFile {
    /// Loads and validates a key file.
    ///
    /// Refuses a symlink, a non-regular file, a file owned by another user, any group or other
    /// permission bit, a length other than 32 bytes, and a location inside a git work tree. The
    /// checks run on the opened descriptor, not on the path.
    ///
    /// # Errors
    /// The matching [`SecretsError`] variant for the rule that failed.
    pub fn load(path: &Path) -> Result<Self, SecretsError> {
        refuse_work_tree(path)?;
        // NONBLOCK and NOCTTY: opening a FIFO or terminal must not block; the fstat below then
        // refuses it as not regular.
        let mut file = open_nofollow(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|e| {
            if is_symlink_error(&e) {
                SecretsError::KeyFileSymlink
            } else {
                io_err("opening")(e)
            }
        })?;
        let meta = file.metadata().map_err(io_err("inspecting"))?;
        if !meta.is_file() {
            return Err(SecretsError::KeyFileNotRegular);
        }
        if meta.uid() != rustix::process::getuid().as_raw() {
            return Err(SecretsError::KeyFileWrongOwner);
        }
        if meta.mode() & 0o077 != 0 {
            return Err(SecretsError::KeyFilePermissions);
        }
        if usize::try_from(meta.len()).ok() != Some(KEY_LEN) {
            return Err(SecretsError::KeyFileWrongLength);
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        file.read_exact(bytes.as_mut_slice())
            .map_err(io_err("reading"))?;
        // Guard against growth between the length check and the read.
        let mut extra = [0u8; 1];
        if file.read(&mut extra).map_err(io_err("reading"))? != 0 {
            return Err(SecretsError::KeyFileWrongLength);
        }
        Ok(Self { bytes })
    }

    /// Creates a new key file from the OS RNG with mode 0600, `O_EXCL` and `O_NOFOLLOW`.
    ///
    /// # Errors
    /// [`SecretsError::KeyFileExists`] if the path exists; other variants as for [`Self::load`].
    pub fn generate(path: &Path) -> Result<Self, SecretsError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(bytes.as_mut_slice()).map_err(|_| SecretsError::Random)?;
        Self::create(path, bytes)
    }

    /// Creates a key file from the base64 text produced by [`Self::to_base64`]
    /// (`vault key import`), under the same rules as [`Self::generate`].
    ///
    /// # Errors
    /// [`SecretsError::InvalidKeyEncoding`] or as [`Self::generate`].
    pub fn import(path: &Path, text: &str) -> Result<Self, SecretsError> {
        Self::create(path, decode_key(text)?)
    }

    fn create(path: &Path, bytes: Zeroizing<[u8; KEY_LEN]>) -> Result<Self, SecretsError> {
        refuse_work_tree(path)?;
        let mut file = open_nofollow(
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOCTTY,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => SecretsError::KeyFileExists,
            _ if is_symlink_error(&e) => SecretsError::KeyFileSymlink,
            _ => io_err("creating")(e),
        })?;
        if let Err(e) = write_and_sync(&mut file, bytes.as_slice()).and_then(|()| sync_parent(path))
        {
            // Never leave a partial key behind. The path is removed by name, so a concurrent
            // rename of the path between create and cleanup could remove a different file.
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        Ok(Self { bytes })
    }

    /// The key as base64 text for a password manager (`vault key export`).
    pub fn to_base64(&self) -> Zeroizing<String> {
        // Pre-reserved so the encoder never reallocates and leaves key copies behind.
        let mut text = Zeroizing::new(String::with_capacity(KEY_B64_LEN));
        STANDARD.encode_string(self.bytes.as_slice(), &mut text);
        text
    }

    /// Builds a key from base64 text without touching the filesystem.
    ///
    /// # Errors
    /// [`SecretsError::InvalidKeyEncoding`].
    pub fn from_base64(text: &str) -> Result<Self, SecretsError> {
        Ok(Self {
            bytes: decode_key(text)?,
        })
    }

    pub(crate) fn as_array(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

fn write_and_sync(file: &mut File, bytes: &[u8]) -> Result<(), SecretsError> {
    file.write_all(bytes).map_err(io_err("writing"))?;
    file.sync_all().map_err(io_err("syncing"))
}

fn decode_key(text: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError> {
    let text = text.trim();
    if text.len() != KEY_B64_LEN {
        return Err(SecretsError::InvalidKeyEncoding);
    }
    // Decode into a roomy fixed buffer so no reallocation leaves key copies behind.
    let mut buf = Zeroizing::new([0u8; 64]);
    let n = STANDARD
        .decode_slice(text.as_bytes(), buf.as_mut_slice())
        .map_err(|_| SecretsError::InvalidKeyEncoding)?;
    if n != KEY_LEN {
        return Err(SecretsError::InvalidKeyEncoding);
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(buf.get(..KEY_LEN).ok_or(SecretsError::InvalidKeyEncoding)?);
    Ok(out)
}
