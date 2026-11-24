# 0006. Sensitive-data store (encrypted vault) and exact-match leak scan

- Status: proposed
- Date: 2026-11-23
- Ticket: #42 (epic #16)

Examples use only synthetic values: TEST-NET-1 `192.0.2.x`, `*.invalid`, made-up MACs (`00:00:5e:00:53:xx`-style
documentation values and `02:...` locally administered ones), made-up serials and passwords. None of them is, or is
derived from, a real site value. Cameras are referred to by inventory id (`reolink-1`, see ADR 0002).
Crate facts were observed on 2026-11-23 with `cargo info <crate>`, the crates.io API (`updated_at`, owners, readme,
dependency list) and a scratch probe project outside the repo; nothing was written from memory. "Last release" is the
crates.io `updated_at` of the crate (the date of its newest version).

## Context

Sensitive data must never reach a commit, a log, a commit message, an issue or PR comment, or an agent prompt. This is a
public repository worked on by AI agents on the owner's machine, so the realistic leak is an accident: an agent
pastes a camera address into a spike note, a log line, a PR body or a prompt, or an owner pastes a password into a chat.

Today the data is scattered: credentials in `~/.config/wardenlens/agentdvr-cameras.secret.json` (by camera name),
hosts in `~/.config/wardenlens/cameras.local.toml` (by camera id), and the guards try to *recognise* secrets by shape
(`scripts/agents check`: RFC1918 and ULA regexes, `scheme://user:pass@`, a secret-file value scan; the catalogue guard
of PR #71). PR #71 showed that shape matching does not converge: five verification rounds, each fixing the previous
round's bypasses (quoted keys, percent-encoding, XML elements, camelCase, comments) and the adversary still found more,
because the set of ways to write a credential or an address is open-ended. The owner's direction (2026-11-23): keep
passwords, PII and other sensitive information in a database, **on the development side too**, and make the guard
robust rather than heuristic.

The service needs the same store anyway: camera credentials arrive from the AgentDVR import (#66), the CLI and later the
UI, and must be encrypted at rest. One design serves both.

Constraints: `unsafe_code = "forbid"` (SEC-1), no hand-rolled cryptography (SEC-7), `cargo deny` must pass (SEC-8,
licence allow list in `deny.toml`), ADR 0004's crate map (section 8), a Docker deployment (#69), and a headless host
(no desktop keyring, no interactive prompt in hooks or CI).

## Options and decisions

### 1. What the store holds

**One encrypted store for every sensitive value, each entry with a typed kind.** An entry is
`(id, kind, value)`. The id is an **opaque, non-sensitive reference** such as `cam:reolink-1:host` and is the only thing
that may appear in committed files, prompts and logs. Ids match `[a-z0-9][a-z0-9:_.-]{0,127}`, are plaintext in the
database and in `vault list`, and must never be derived from a value. The prefix `meta:` is **reserved** for the store's
own entries (`meta:keycheck`); `set` and `import-legacy` refuse it. Imported ids come from the inventory ids (ADR 0002,
`cam:reolink-1:host`) or from an ordinal (`cam:import-json-3:host` or `cam:import-toml-3:host`), never from a value. **One rule refuses a bad id:** before
storing, the section 7 matcher for the new value (built for its kind) is run over the id string, and a hit refuses the
entry (this catches `cam:192-0-2-10:host` for the value `192.0.2.10`). Everything else about ids is review (residual
risk 6).

| kind (stable code) | holds | examples (synthetic) |
|---|---|---|
| `credential` (1) | a username and password pair | `cam:reolink-1:credential` = (`svc-reader`, `Tr0ub4dor-x9`) |
| `secret` (2) | one opaque secret: API token, cloud key, password | `cloud:example:token` |
| `host` (3) | a LAN address or hostname: IPv4, IPv6 or DNS name | `192.0.2.10`, `nvr-1.example.invalid` |
| `mac` (4) | a MAC address | `02:00:5e:00:53:af` |
| `serial` (5) | a device serial number | `SN-0042-ZQ` |
| `display-name` (6) | a camera or site display name | `Back Door North` |
| `other` (7) | any other user-supplied sensitive text (PII: street address, phone, name) | `12 Example Lane` |

`secret` is the one addition to the kinds listed in #74 (which has credential, host, mac, serial, display-name,
other): API secrets and cloud credentials need password-style expansion (section 7) without a username, and `other`
is deliberately weaker (case-insensitive, whitespace-collapsed) because PII prose is not typed exactly. Kind codes are
stable on disk and are bound into the ciphertext (section 3); a new kind takes a new code, never a reused one.

**Limits (SEC-2).** A value is at most 4096 bytes of UTF-8, an id at most 128 bytes, a store at most 10,000 entries; all
are checked on `set` and on `open`. Values are validated per kind on `set` (an IPv4 host must parse with std's strict
`Ipv4Addr`, a MAC must reduce to 12 hex digits; a hostname is validated **per label**: 1 to 63 bytes of `a-z`, `0-9`,
`-` and `_` (the underscore is allowed because service and DNS-SD names use it), no label starting or ending with a
hyphen, the whole name at most 253 bytes, lower-cased at `set`, trailing dot removed; IDN hostnames are entered in
their `xn--` form).

**What stays out of the store.** Anything that is not about the site: vendor, model, firmware family, stream codec,
resolution, ONVIF profile numbers, RTSP path templates, default ports, inventory ids (`reolink-1`). These are public
(ADR 0002, the catalogue of #32) and stay ordinary configuration.

### 2. Encryption: XChaCha20-Poly1305 with a key file, or `age`

Observed 2026-11-23:

| | `chacha20poly1305` | `age` |
|---|---|---|
| version | 0.11.0 | 0.12.1 |
| licence (`cargo info`) | Apache-2.0 OR MIT | MIT OR Apache-2.0 |
| last release (crates.io) | 2026-08-05 | 2026-07-14 |
| owners (crates.io) | newpavlov, team `github:rustcrypto:aeads` | str4d (single owner) |
| downloads (all time / recent) | 121.9 M / 45.3 M | 8.6 M / 4.7 M |
| audit | readme: "one security audit by NCC Group, with no significant findings" (the linked report is dated 2020-02 and covered the RustCrypto AES-GCM and ChaCha20Poly1305 implementations; 0.11 postdates it, so the audit is of an earlier code base) | the crate readme names no audit; it states the format spec (age-encryption.org/v1) and a Go reference implementation, not an audit of this crate |
| scratch probe, `default-features = false` | with `alloc`, `zeroize`: 19 lines in `cargo tree` for the crate alone | 181 unique packages |
| `cargo deny check` with repo `deny.toml` | `advisories ok, bans ok, licenses ok, sources ok` (whole candidate set, below) | **advisories FAILED**: RUSTSEC-2026-0387 (`crypto-bigint 0.5.5`, timing variability, reached through `p256` 0.13.2 / `elliptic-curve` 0.13.8 from `age`; the one dependent that pins `^0.5` precludes the fix) |

Options:

1. **`chacha20poly1305` XChaCha20-Poly1305 with a 32-byte key file** (chosen). RustCrypto AEAD. (The `age` format builds its payloads on the 96-bit-nonce ChaCha20-Poly1305 with a derived key and a
   counter; XChaCha20 is the extended-nonce variant.) A 192-bit nonce makes random nonces safe without a
   counter (no state to persist, no nonce-reuse bookkeeping), AAD is a first-class input (needed for the binding in
   section 3), small dependency tree, already named by #48. Con: we define a small record format; a record format is
   not cryptography (SEC-7 is about primitives), and the format is a single AEAD call.
2. **`age`**. Pro: a standard, interoperable file format, recipients and identities. Con: its value is file
   encryption with X25519 or scrypt recipients; we have one local machine and one key. Passphrase mode is interactive and
   deliberately slow (unusable from a pre-commit hook or a daemon), and X25519 adds a key-management layer we do not
   need. Measured cost: 181 packages and a failing `cargo deny` advisory in the scratch probe. Rejected.
3. **Whole-database encryption (SQLCipher)**. Pro: hides ids and kinds. Con: a C library with its own build and
   licence story, a different SQLite build than ADR 0005's, and the ids are non-sensitive by design. Not evaluated with
   `cargo info`; rejected on structure, revisit if ids ever become sensitive.
4. **OS keyring for the key**. Rejected: no desktop session in Docker, hooks or CI; the key file with permission checks
   is the portable minimum.

**Decision: option 1**, `chacha20poly1305 = { version = "0.11", default-features = false, features = ["alloc",
"zeroize"] }` (feature list confirmed with `cargo info`: `alloc = [aead/alloc]`, `zeroize = [dep:zeroize,
chacha20/zeroize]`). Randomness comes from `getrandom` (0.4.3, MIT OR Apache-2.0, already in ADR 0004's table), called
directly, so the AEAD crate's `getrandom` feature is not needed. Single-owner `age` and the age of the NCC audit are
recorded as the reasons this is not a "settled forever" choice: the record carries a version byte (section 3) so the
algorithm can be replaced by a re-seal migration.

### 3. Record format and binding

```
record  = version (1 byte, 0x01) || nonce (24 bytes) || ciphertext || tag (16 bytes)
AAD     = version (1 byte) || kind code (1 byte) || entry id (UTF-8, the rest)
```

- `version = 0x01` means XChaCha20-Poly1305 with this AAD layout. An unknown version is a typed error
  (`UnsupportedVersion`), never a guess. The version is also in the AAD, so a record cannot be relabelled to another
  version.
- The nonce is 24 bytes from the operating-system RNG, fresh for every seal, including re-seals during rotation.
- The AAD binds the ciphertext to its entry id and kind. Moving a record to another row (swap two entries, copy a
  `host` record into a `credential` row) fails authentication. The kind is one fixed byte so the id needs no length
  prefix: the AAD is unambiguous.
- Plaintext: for kinds other than `credential`, the UTF-8 value. For `credential`: `username_len (u16, big endian) ||
  username || password`. Lengths are checked against the section 1 limits before any allocation (SEC-2).
- `meta:keycheck` is sealed with the **reserved kind byte `0x00`**, which is never assigned to an entry kind, so a
  keycheck record cannot be moved into `entries` and an entry cannot be moved into `meta`. Its plaintext is the fixed
  ASCII string `wardenlens-vault-keycheck-v1`.
- Minimum record length is `1 + 24 + 16`; shorter input is a typed error. Errors never contain key, plaintext or
  ciphertext bytes (ERR-5, SEC-6).

### 4. Storage: SQLite, one file for the service and one per developer

SQLite, consistent with ADR 0005 / #41 (`rusqlite` 0.43 with `bundled`, WAL for the recording index). **If ADR 0005
chooses a different SQLite crate, the vault follows it; the vault does not set that choice.**

| file | purpose | default location |
|---|---|---|
| service vault | camera credentials, host, display names for the running service | `/var/lib/wardenlens/vault.db` (a volume), separate from the recording index |
| developer vault | the same kinds for tooling, spikes and the leak scan | `$HOME/.local/share/wardenlens/dev-vault.db`, mode 0600, directory 0700. **Always this fixed path** (the one the git hooks use, section 9); `vault init` **refuses** when `XDG_DATA_HOME` or `XDG_CONFIG_HOME` is set and would resolve the dev vault or key elsewhere |

Rules:

- **The vault is a separate file from the recording index** (ADR 0005 / #49). A backup, copy or `sqlite3` dump of the
  index then contains no sensitive value at all, and the key is never stored in either file.
- The dev vault lives **outside every repository**. `vault init` and every open refuse a path that is inside a git work
  tree (walk the canonical path's ancestors for `.git`; SEC-4) and a symlink.
- **Opening (safe Rust only).** SQLite's own file descriptor is not used for checks (the `rusqlite` accessor for it is an
  `unsafe` function, SEC-1). Instead: (1) open **our own** descriptor on the path with `O_NOFOLLOW` and `fstat` it
  (regular file, owner, mode, device and inode); (2) open SQLite **by path** with `SQLITE_OPEN_NOFOLLOW`; (3) `stat` the path
  again and **compare device and inode** with step 1 (or, equivalently, re-open and compare). A path swapped between the
  check and the open makes the comparison fail and the open is refused.
- The file is created with mode 0600 (created before SQLite opens it, so it never exists with a wider mode) and opened
  only if it is owned by the current user and not group- or world-accessible.
- The vault uses `journal_mode = DELETE` and `synchronous = FULL`: it is tiny and rarely written, and no `-wal`
  or `-shm` sidecar files are created. (Sidecars would only hold ciphertext anyway.) Every connection sets a busy
  timeout of 5 seconds, so a scan during a write waits instead of failing.
- Schema (version 1): `meta(key TEXT PRIMARY KEY, value BLOB)` holding `schema_version` and `keycheck` (a sealed
  constant under id `meta:keycheck`, so a wrong key is detected before any entry is touched), and
  `entries(id TEXT PRIMARY KEY, kind INTEGER NOT NULL, record BLOB NOT NULL, created_at INTEGER NOT NULL, updated_at
  INTEGER NOT NULL)`. The `kind` column is a convenience copy; the authoritative kind is the one authenticated in the
  AAD, and a mismatch between column and AAD is a typed `CorruptEntry` error. No value and no hash of a value is
  stored in plaintext. **The length of every value is visible**: a record is `1 + 24 + length + 16` bytes, so a reader of
  the file learns that an entry is, say, 12 bytes long. There is no padding in v1; this is listed as residual risk 12.
- **Migration (`vault import-legacy`).** Reads `agentdvr-cameras.secret.json` and `cameras.local.toml` and imports
  **mapped fields only** (the host, display name, username, password and similar fields the importer knows) as
  `cam:<id>:credential`, `cam:<id>:host`, `cam:<id>:name`, with ids from the inventory ids or an ordinal (section 1).
  **Unknown keys are not imported and not guessed:** the importer lists them **by key name** (never by value) so the
  owner can classify each with `vault set`. (An earlier draft turned every unknown scalar into an `other` entry; that
  put public strings into the matcher and made the false positives unmanageable.) It is idempotent, and prints counts and
  ids, never values. After a successful import the **owner** deletes the two legacy files (documented step, not
  automatic: #76). The old files are plaintext, so until they are deleted the vault adds protection but does not
  remove the exposure.
- **Refusing a value that is already public (`vault set`, `import-legacy`).** Before storing a value, the command
  builds the section 7 matcher for that value alone and scans the tracked files of the work tree it is run in
  (`git ls-files`; outside a work tree it prints a notice and skips). For kinds other than `credential` and
  `secret`, a hit **refuses** the value with the single message "remove or replace the tracked occurrence, then store it" (the
  tracked text is what must change; there is no "store it anyway"). For `credential` and `secret`, a hit does
  **not** refuse: the value is stored as **`unscannable`** (it would match its own public occurrences on every scan) with a
  warning, "this value already appears in tracked files; rotate it". The location follows the redaction rules of section 8. **There is no allowlist in v1.** A value that
  is below the minimum length, or a single-label host shorter than 8 characters, is stored but marked **`unscannable`**
  (it would otherwise match public text), `list` shows the mark and every scan prints a warning naming its id.

### 5. Crate map (amends ADR 0004 section 8)

ADR 0004 section 8 left "the encryption crate" and the vault to this ADR. Decision:

| crate | responsibility | depends on (workspace) |
|---|---|---|
| core | adds the pure types `EntryId` (validated, section 1 charset), `EntryKind`, `Credential { user: String, password: SecretString }` (redacting `Debug`) and the trait `CredentialSource` (section 10); no crypto, no I/O. Core may depend on `secrecy` and `zeroize`, which are pure crates, as it already does on `serde` (ADR 0004 is amended accordingly) | none |
| secrets (#48) | primitives only: `KeyFile` (load, generate, permission checks), `seal`/`open` with the section 3 format, `Credentials`, redacting wrappers. **No SQLite, no scan.** | core |
| **vault** (new, #74, #75) | the store (`rusqlite`), per-kind validation, the section 7 normaliser and the section 8 scanner (`aho-corasick`), `import-legacy` mapping logic. Library only | core, secrets |
| index | unchanged responsibility. **Does not depend on `vault` or `secrets`** and never holds a sensitive value or a ciphertext of one | core |
| cli | the `wardenlens vault` subcommands (`init`, `set`, `get`, `list`, `rm`, `rekey`, `import-legacy`, `scan`, `redact`, `check-key`, `key export`, `key import`), argument and TTY handling, composition with index, the `CredentialSource` implementation wired into ingest | all |

Direction: `cli -> vault -> secrets -> core`, `cli -> index -> core`. `api` must not depend on `vault`, `secrets` or
`index` (ADR 0004 rule). Splitting `vault` from `secrets` keeps ARCH-2 (secrets stays a small audited-surface crate with
the crypto and the key rules; the vault carries the larger dependency set, SQLite and the matcher) and keeps SQLite
out of the crate that every service component would otherwise inherit. The scan lives in `vault`, not in `cli`, so
the catalogue test and any future caller use the same library function (`vault::scan`). The service reads camera
hosts, names and credentials through `cli`, which opens the service vault and the index and builds core `Camera` values;
no other crate reads the vault.

ADR 0004 is updated with a pointer to this ADR in section 8, and its core-dependency sentence (section 5) now names
`secrecy` and `zeroize`; its table row for `secrets` ("redacting wrappers for camera credentials") is narrowed by the
row above.

### 6. Key lifecycle

- **Format.** A raw 32-byte file. Exactly 32 bytes, no header, no text encoding (so there is nothing to mis-parse).
- **Generation.** `wardenlens vault init` (and `KeyFile::generate`) draws 32 bytes from the OS RNG (`getrandom`)
  and creates the file with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600; an existing file is never overwritten. The
  flags are set through `std::os::unix::fs::OpenOptionsExt` with constants from a safe crate (no `unsafe`, SEC-1); #48
  names and justifies that crate (SEC-8) if std alone does not expose them.
- **Key export and import.** `vault key export` prints the key as base64 and `vault key import` reads it back (key
  files are raw bytes, so a human-storable form is needed for the password manager). Both work **only on a TTY**
  (`export` refuses a non-terminal stdout, `import` reads from a no-echo prompt), never print to a log, and `import`
  creates the file with the same `O_EXCL` and 0600 rules.
- **Location.** Dev: `$HOME/.config/wardenlens/dev-vault.key` (fixed, directory 0700, see section 4 for the `XDG_*`
  refusal), a different directory from the database. Never inside a git work tree (same rule as the database). Service: the host file
  `/etc/wardenlens/vault.key` by default (overridable through `WARDENLENS_KEY_FILE_HOST` in the compose `.env`), seen inside
  the container at `/run/secrets/wardenlens_vault_key`, the path in `WARDENLENS_VAULT_KEY_FILE`.
  **Normative: a compose secret source is never inside a git work tree.** `wardenlens vault check-key <path>` applies the
  key checks below plus this rule and is run by #69's setup and tests. As a backstop only, `/secrets/` and `*.key` are
  in `.gitignore` (done with this ADR) and in `.dockerignore` (#69 creates it).
- **Backups: the protection is conditional.** The database and the key are separate files, but the dev key
  (`~/.config`) and the dev database (`~/.local/share`) are both under `$HOME`, so a whole-home or whole-disk backup
  holds both and then gives no protection. **The key path must be excluded from backups** (#69 documents this for the
  service key, #76 for the dev key) and the key is kept in the password manager instead (`vault key export`, below).
- **Permission checks (refuse, do not warn).** `KeyFile::load` refuses a file that is not a regular file (symlinks are
  refused, `O_NOFOLLOW` plus `fstat` on our own opened descriptor, not a path check followed by an open), not owned by the
  current user, readable or writable by group or others (`mode & 0o077 != 0`), or not exactly 32 bytes. The same
  checks apply to the vault file. The error says which rule failed, never the contents.
- **No environment variables for key material.** The key is never read from an environment variable. If
  `WARDENLENS_VAULT_KEY` is set, startup fails with an error telling the user to
  use a file (an environment is inherited by every child, shows in `/proc/<pid>/environ` and in `docker inspect`).
  **Among vault- and path-related variables the binary reads exactly these and no others** (ordinary variables such as
  `RUST_LOG` stay allowed): `WARDENLENS_VAULT` (path), `WARDENLENS_VAULT_KEY_FILE`
  (path), `WARDENLENS_REQUIRE_VAULT` (a flag), `HOME` (the base of the fixed dev paths) and `XDG_DATA_HOME` and
  `XDG_CONFIG_HOME` (read only so `vault init` can refuse when they point elsewhere).
  `WARDENLENS_KEY_FILE_HOST` is read by compose from `.env`, never by the binary. **`WARDENLENS_VAULT_KEY` is the
  rejected name** (it looks like key material); setting it is an error.
- **Docker.** Compose `secrets:` with a file source **outside the work tree** (`secrets: { wardenlens_vault_key: {
  file: ${WARDENLENS_KEY_FILE_HOST:-/etc/wardenlens/vault.key} } }`; `./secrets/vault.key` would sit inside the repository
  and is not allowed), mounted at `/run/secrets/wardenlens_vault_key`. Environment variables are rejected as above.
  **Not verified here:** whether Compose in non-swarm mode presents the mounted file with the mode and the owner the
  strict check needs (0600/0400, the container user's uid) or as world-readable 0444. **#69 tests both the uid and the
  mode** of the bind-mounted secret on the real compose version. If it fails the check, the options are the long-syntax
  `mode:`/`uid:` or a documented, explicit exception for the single path `/run/secrets/` (inside the container only),
  not weakening the check for other paths. Until #69 settles it, the strict check stays. **The service key is rotated as stop, rekey, start:** the container is stopped, `rekey` runs **on the host**
  against the host key and database files, and the container is started again (the container never rotates in place).
- **Rotation (`vault rekey`).** Generate the new key as `<key>.next` (0600, `O_EXCL`, fsynced; **the key directory is fsynced right after the file is
  created, before the transaction starts**, so a crash cannot lose the only copy of the new key), open a single SQLite
  transaction, re-open every entry with the old key and re-seal it with the new key and a fresh nonce, write a new
  `keycheck`, commit, then atomically rename `<key>.next` over the key file and fsync the directory. A crash between
  commit and rename leaves a `.next` file. **Recovery runs only in write commands, under the write lock** (the exclusive
  SQLite write transaction, so two processes cannot race): if the vault does not open with the current key but opens
  with `.next`, the rename is completed (**`<key>.next` must first pass the same `KeyFile::load` checks** as any key: regular
  file, owner, no group or world access, exactly 32 bytes, not a symlink, outside a work tree; otherwise it is neither
  used nor renamed); if it opens with the current key, a stale `.next` is deleted. Read commands
  (`scan`, `get`, `list`) never rename or delete a key file: on a mismatch they fail (exit 2) and point to the write
  command that recovers. **`rekey` checks for a TTY before it changes anything and refuses without one** (the closing step needs it, and a rotation
  that cannot finish its export would strand the owner). **It ends with a mandatory step: it prints "re-export the key now" and runs `vault key
  export`** (a TTY is required), because the previous password-manager copy no longer opens the database. The old key is
  overwritten by the rename; backups of it still decrypt older copies of the database, which is why backups of key and
  database are kept separately and rotated together.
- **Key loss.** There is no recovery path by design. A lost key means the database is unreadable: delete it, `vault
  init`, and re-enter or re-import the values from their sources (AgentDVR export, the owner's password manager, the
  camera labels). Because #76 has the owner delete the legacy plaintext files after the import, the owner must keep a
  copy of the key in the password manager (offline, separate from database backups) before deleting them. Losing the
  key of the *dev* vault also disables the scan until the vault is rebuilt; the gate says so (section 9). The
  password-manager copy (`vault key export`) is the recovery path, not a backup of the database.
- **Memory.** Keys are held in `Zeroizing<[u8; 32]>`, values in `secrecy::SecretString` / `SecretBox`, with the
  `zeroize` feature of `chacha20poly1305` on; see section 10. Core dumps are disabled at process start with
  `setrlimit(RLIMIT_CORE, 0)` through `rustix` (a safe API; section 11), in the `cli` binary.

### 7. Leak scan: exact match, not shape

**Principle.** The scan does not ask "does this look like a credential or an address?". It asks "does this text
contain one of the values that are actually in the vault, in any of the listed renderings?". A vault of N values
yields a finite set of needles (the renderings listed below); there is no open-ended grammar to bypass, and a text with an
address-shaped or password-shaped string that is not in the vault passes (no false positives from shape). The
shape heuristics of `scripts/agents check` and the catalogue guard are demoted to an optional soft lint (warnings only,
section 9).

**Views of the text.** Every input is matched in four views, and a hit in any of them counts (reported once per
entry and line):

1. **raw**: the bytes as they are;
2. **squeezed**: decode UTF-8 (invalid bytes become U+FFFD), then delete the invisible characters U+00AD, U+200B to
   U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066 to U+2069 and U+FEFF; map the fullwidth ASCII block U+FF01 to
   U+FF5E onto U+0021 to U+007E; map U+3002, U+FF61 and U+2024 to `.`; map U+2010 to U+2015 and U+2212 to `-`; map
   U+00A0, U+2000 to U+200A and U+3000 to a space. Line breaks are never touched, so line numbers stay valid;
3. **decoded**: the squeezed view with `%XX` sequences percent-decoded once (invalid sequences left as they are); the
   decoded **byte string is re-decoded as UTF-8, lossy** (invalid sequences become U+FFFD), so `%E2%80%93` becomes the
   en dash U+2013.
   `%0A` and `%0D` (any case) are **not** decoded, so a decoded view never gains a line break and line numbers stay valid;
4. **JSON-unescaped**: the squeezed view with JSON string escapes decoded once: `\uXXXX` (a surrogate pair such as
   `\uD83D\uDE00` becomes one character), `\"`, `\\` and `\/`. **Never decoded**, so the view never gains a line break:
   `\n`, `\r`, `\t`, `\u000a`, `\u000d`, `\u0085`, `\u2028` and `\u2029` (any case of the hex digits). A lone surrogate
   (`\uD83D` without its partner) is left as it is. This is what matches a password in a JSON log, including the
   `\u0026` and `\u0027` forms for `&` and `'` that .NET and Go writers produce. The needle list therefore has no
   JSON-escaped form (a JSON-escaped needle would miss any escape style it did not anticipate).

**Which view is built from which.** The squeezed view is built from the raw text; the decoded, the JSON-unescaped and the
joined view (below) are each built from the **squeezed** text, independently of each other (the decoded view is not
JSON-unescaped and the other way round). The decoding steps do not squeeze again, so a character of the squeeze table that
appears only after decoding is not mapped by the squeeze; the decoded and JSON-unescaped views are therefore also matched
against the unsqueezed needles (next paragraph), which finds the encoded forms of a character *inside a stored value*.
What stays a gap (section 8) is an invisible character **inserted** as an escape into text (`%E2%80%8B`, `\u200b`) in the
middle of a value that does not contain it.

**Needles are squeezed with the same table.** Every literal needle (the raw value, its slugs, its joined-view form, its
compact serial form, its XML and percent forms) is built from the stored value and then passed through the **same squeeze
table** (and the fold, where the kind uses it), and the squeezed, decoded, JSON-unescaped and joined views are matched
against these **squeezed needles**. The **raw** view is matched against the **unsqueezed** needles (the bytes as stored, in the fold
where the kind uses it), and **the decoded and the JSON-unescaped views are matched against both the squeezed and the
unsqueezed needles**, so that a character of the squeeze table that appears inside the stored value itself is found
whether the text carries it literally, squeezed, percent-encoded or JSON-escaped.
Without this a stored `Garage – Side` (en dash, U+2013) would never match `Garage - Side`, because the text view has
the dash mapped to `-` and the needle would not. Required found examples for a stored display name `Garage – Side`
(en dash): `Garage – Side` (raw view), `Garage - Side`, `GARAGE - SIDE` (fold), `Garage%20-%20Side` (decoded view, squeezed
needle), **URL-encoded** `Garage%20%E2%80%93%20Side` (decoded view, unsqueezed needle) and **JSON-escaped**
`Garage \u2013 Side` (a literal backslash-u escape; JSON view, unsqueezed needle); for a stored secret `pa"ss–word` (en dash):
the JSON log text `"password":"pa\"ss–word"` (the JSON-unescaped view yields `pa"ss-word` after the squeeze, the squeezed
needle is `pa"ss-word`) **and fully JSON-escaped** `"password":"pa\"ss\u2013word"` (the JSON view yields the en dash, the
unsqueezed needle matches). Checked by hand against the tables above; #75 pins them in tests.

Each view keeps an **offset map** back to the raw bytes (one entry per output character: the raw byte range it came
from), which `vault redact` uses (section 10).

Matching is done on these views for every kind; the per-kind rules below only add a **fold** (the view lowercased with
the full lowercase mapping, `char::to_lowercase`, applied to the needles too; this is not Unicode case folding
and a string can change length) and, for two kinds, a **joined** view.

Tables, not heuristics: the same four views are applied to every file the same way, and the mapping is part of the
tested contract. A character not in the tables (for example a Cyrillic lookalike) is not mapped; see "what the scan
cannot catch".

**Minimum length (every kind with literal needles).** A value (and so each of its needles) must be at least **7 bytes**. The
rule is applied to the stored value **and to each needle after the squeeze table and the fold**: if any needle falls below 7
bytes (for example a value made only of zero-width characters squeezes to an empty needle), the whole entry is **`unscannable`** and warned about on every scan; it is never partly scanned. IPv4, IPv6 and MAC
values have fixed formats and are exempt. 7 (not 6) is chosen so that every base64 alignment of a secret is at least 8
characters (below), and no state of the scan can reveal that a value is exactly 6 bytes.

**Per-kind rules.** A "boundary" is the rule for what may touch a match; `A` means ASCII letter or digit.

*`host`, IPv4* (value parses with std `Ipv4Addr`; stored as its 32-bit value `n`). Not expanded into strings: the text is
tokenised and every candidate is converted to a `u32` and looked up in a hash set, because mixed separators make the
string set explode.
- Field form: a **field** is a maximal run of digits; it counts only if it has 1 to 3 digits, is at most 255 (leading
  zeros allowed, read as decimal). A run of 4 or more digits is not a field and breaks a chain. A **chain** is a maximal
  sequence of fields joined by exactly one separator each from `.`, `-`, `_`, `[.]`, `(.)`, `{.}`, any mix. Every four
  consecutive fields of a chain are a **window** and all are checked, so `10.192.0.2.10` still yields `192.0.2.10`, and
  `1192.0.2.10` yields nothing (the first run has four digits). Fields are compared as numbers, so `192.0.2.1` never
  matches inside `192.0.2.10` (that window is `192.0.2.10`, not equal to `n`).
- 32-bit decimal: a digit run of 8 to 10 digits equal to `n`, not touching another digit.
- Hex: `0x` followed by exactly 8 hex digits (case-insensitive) equal to `n` and **not followed by another hex digit**, or
  8 bare hex digits equal to `n` not touching another hex digit on either side.
- Worked example, stored value `192.0.2.10` (`n = 3221225994`, hex `c000020a`). Found: `192.0.2.10`, `192-0-2-10`,
  `192_0_2_10`, `192[.]0[.]2[.]10`, `192.000.002.010`, `192.0.2.10:554`, `rtsp://192.0.2.10/stream`, the fullwidth
  `１９２．０．２．１０` (squeezed view), `192%2E0%2E2%2E10` (decoded view), `3221225994`, `0xC000020A`, `c000020a`.
  Not found: `192.0.2.100`, `192.0.2.1`, `192.0.2` (partial), `192 0 2 10` (spaces), `0300.0.02.012` (octal),
  `192.0.2.x`.

*`host`, IPv6* (value parses with std `Ipv6Addr`; stored as its 128-bit value). Candidate runs are maximal runs of hex
digits, `:` and `.` containing at least two colons. **All of the following always run for every run; a later step is
never skipped because an earlier one parsed.** A word glued to an address can itself parse as a different, valid address
(the run `ce:2001:db8::1` from `Source:2001:db8::1` parses as `ce:2001:db8::1`), so "the whole run parsed" proves nothing.
(1) Try the whole run with std `Ipv6Addr::from_str`. (2) Try the run with only its trailing `.` characters removed, **and** with all its trailing `:` and `.`
removed (two trimmings, because a trailing `::` can be part of the address: `1:2::.` is found through the first, `fe80::1:`
through the second; a leading `::` is always kept, so `::ffff:c000:20a.` is found). (3) For the run and for each trimmed
variant, try the **suffix sub-runs**: the candidates are the suffixes **starting at a group boundary within the last 45 bytes
of the (trimmed) run** (the start of the run if it is that short, and the position after every `:`), and each **ends at the
end of that run**; it never ends earlier (SEC-2: bounded work per run). **A hit is any run or suffix, from any step, whose value equals a
stored value.** Ending anywhere would turn prefixes into hits (`2001:db8::10` would hit `2001:db8::1`), which is why only
suffixes are tried; the cost is the gap listed in section 8 (a trailing word glued on). Equal 128-bit value is a hit; an IPv4-mapped
address (`::ffff:a.b.c.d` or `::ffff:c000:20a`) is also looked up among the IPv4 values. A zone suffix (`%eth0`) ends the
run and is ignored. Required **found** examples for a stored `2001:db8::1`: `2001:db8::1`, `2001:0DB8:0:0:0:0:0:1`,
`2001:db8::0.0.0.1`, `2001:db8::1.`, `addr:2001:db8::1`, `1:2::.` (for a stored `1:2::`), `Source:2001:db8::1`, `beef:2001:db8::1`,
`[2001:db8::1]:8080`; for a stored `fe80::1`: `fe80::1:`, `Interface:fe80::1`, `dead:fe80::1`. For a stored IPv4
`192.0.2.10`: `::ffff:c000:20a`, `::ffff:c000:20a.` and `::ffff:192.0.2.10`. **Not found:** for a stored `2001:db8::1`:
`2001:db8::10`, `2001:db8::1:2`, `2001:db8::1234`, `cafe2001:db8::1` (gap, see section 8) and `2001:db8::1:554` (the unbracketed port form, gap); for a stored `fe80::1`: `fe80::1ff:fe23:4567:890a`; for a stored IPv4
`192.0.2.10`: `::ffff:192.0.2.100`. (Every example above was checked against this rule with a scratch program outside the
repository, Python's `ipaddress` standing in for std's parser; #75's tests pin them against the real implementation.)

*`host`, DNS name* (labels as in section 1, lower-case, no trailing dot). Matched in the fold, left boundary: not `A`,
`-` or `_`; right boundary: not `A`, `-` or `_` (a `.` is allowed on either side, so `a.nvr-1.example.invalid` and `nvr-1.example.invalid.` both
match; this is deliberately conservative: a sub-domain of a vault host reveals the host). Example, stored
`nvr-1.example.invalid`: found in `NVR-1.Example.INVALID`, `http://nvr-1.example.invalid:8080/`, `nvr-1.example.invalid.`;
not found in `xnvr-1.example.invalid` (left boundary) or `nvr-1.example.invalid-backup` (right boundary), and not for the bare label `nvr-1`.

*`mac`* (value reduces to 12 hex digits; stored lower-case). Tokenised, not expanded: five separators across five positions
would be 3,125 strings, times case, times three group sizes. A candidate is a sequence of hex groups joined by single
separators, **each separator any single non-hex character** (any mix; so `:`, `-`, `.`, `_`, space and also `/` or `x`
qualify; two characters in a row, such as `: `, break the chain), in one of the group shapes 6 x (1 or 2 hex digits, a
single digit is zero-padded, so MACs written **without leading zeros** match), 3 x 4, 2 x 6 or 1 x 12 hex digits. A group
is a maximal run of hex digits, so a hit never touches another hex digit (a 16-digit EUI-64 is not a 12-digit hit); any
six, three, two or one consecutive groups of a longer chain are windows. The 12 digits are lower-cased and looked up. Example, stored `02:00:5e:00:53:af`: found as `02:00:5e:00:53:af`, `02-00-5E-00-53-AF`, `0200.5e00.53af`,
`02_00_5e_00_53_af`, `02 00 5e 00 53 af`, `02005e0053af`, `0200 5e00 53af` (3 x 4) and the mixed
`02:00-5e.00_53 af`, and without leading zeros `2:0:5e:0:53:af`. Not found: `02:00:5e:00:53` (5 groups), `02005e0053af11`
(14 digits), `02:00:5e:00:53:ae` (differs).

*`serial`* (trimmed). Needles: the value as entered and the **compact** form (the characters `-`, `_`, `.` and space
removed), both matched in the fold, boundary: not `A` on either side; minimum 7 bytes of the compact form.
Example, stored `SN-0042-ZQ`: found as `sn-0042-zq`, `SN0042ZQ`, `sn0042zq`, `Serial: SN-0042-ZQ.`; not found as `SN 0042 ZQ`
(a regrouping other than the two forms; see section 8), `XSN-0042-ZQ` (boundary).

*`secret` and the password of `credential`* (case-sensitive; minimum 7 bytes). Needles, deduplicated:
1. the raw value;
2. **percent-encoding**: unreserved characters (`A-Z a-z 0-9 - . _ ~`) kept and every other byte as `%XX`, in upper-case and
   in lower-case hex; and the **every-byte** form (`%63%6f...`), upper and lower; and the **form-encoding** variant (space as `+`);
3. **base64**, standard (`+/`) and URL-safe (`-_`) alphabets, **without padding**, at all three alignments. A secret
   inside a larger base64 blob (for example an HTTP Basic `user:secret` header) is encoded at a byte offset the scan does not
   know, so for each `k` in 0, 1, 2 the value is encoded with `k` filler bytes in front, and only the characters
   fully determined by the value are kept: from character `ceil(8k / 6)` up to, not including, character
   `floor(8(k + n) / 6)`, where `n` is the value length in bytes. With the 7-byte minimum (below) the shortest
   needle is 8 characters (`k=1`, `n=7`: characters 2 to 10), so **no alignment is ever dropped**. No `=` can appear in a needle. Worked example, value `correct-horse-9` (15 bytes):
   `k=0` encodes to `Y29ycmVjdC1ob3JzZS05` and all 20 characters are kept; `k=1` encodes to
   `AGNvcnJlY3QtaG9yc2UtOQ` and the needle is `NvcnJlY3QtaG9yc2UtO` (characters 2 to 20); `k=2` encodes to
   `AABjb3JyZWN0LWhvcnNlLTk` and the needle is `jb3JyZWN0LWhvcnNlLT` (characters 3 to 21). The dropped characters depend
   on the unknown neighbouring bytes;
4. **lower-case and upper-case hex** of the bytes (log hex dumps);
5. the **XML escape** (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`) when it differs from the raw value (JSON escapes are
   handled by the fourth view, not by a needle).
No boundary rule: a substring hit on a password is a leak. A secret shorter than 7 bytes is **unscannable** (section 8).
The username of a `credential` is **not scanned** (usernames such as `admin` are generic and would flood every text; a
sensitive username belongs in an `other` entry).

*`display-name`* and *`other`* (matched in the fold; the value is whitespace-collapsed: any run of Unicode whitespace
becomes one space). They are matched in a **joined** view of each text, in addition to the four views: every line
break (`\n`, `\r\n` or a lone `\r`) and the spaces and tabs that follow it become one space, and any run of spaces, tabs and NBSP becomes one space, so
a name wrapped across lines or indented is found; a hit is reported at the line where it starts. Boundary: not `A`. Minimum
7 bytes. `display-name` additionally gets the **slug** needles with each space replaced by `-`, by `_`, and removed.
Example, stored `Back Door North`: found in `back   door north`, `BACK DOOR NORTH`, `back-door-north`,
`back_door_north`, `BackDoorNorth`, and `Back Door` newline plus four spaces `North`; not found as `Door North`. Not
handled: comment or quote markers at the start of the wrapped line (`# North`, `> North`).

**Complexity.** Literal needles go into one `aho-corasick` automaton (leftmost-longest is unnecessary; all matches are
checked against the boundary rule). IPv4, IPv6 and MAC use single-pass tokenisers and hash sets. Cost is linear in the
text for a fixed vault. The target of #75 is under 1 s for 1 MB.

**Files.** A file that starts with a UTF-16 byte order mark (`FF FE` or `FE FF`) is **decoded as UTF-16 text** and scanned (its NUL
bytes are not a binary marker). Otherwise a file with a NUL byte in its first 8 KiB is **binary and skipped, with a notice** (a count and, subject to
the redaction rule of section 8, a path; it is also item 5 of the gap list). A tracked or staged text file larger than
8 MiB **fails** the scan (exit 2); an untracked file larger than 8 MiB only **warns**. No allowlist exists in v1.

### 8. Output, exit codes and what the scan cannot catch

- A hit is reported as `entry-id kind location`. **The matched text, the surrounding line, the entry's value and its
  length are never printed** (SEC-6, ERR-5). The report cannot be used to learn a value beyond "this id occurs here".
- **A path, ref name, commit message or author line that itself contains a hit is never printed**, because printing
  the location would print the value. The tool first runs the matcher over every path, ref name and message it is about to
  print, in every report, error and notice. Locations are: `path:line` for a clean path in the tree or the index;
  `<redacted-path> blob <sha>` (blob id, then `:line` for a content hit) when the path contains a hit or a hit is in
  a blob whose path does; `commit:<sha>:message` for a hit in a commit message, `commit:<sha>:author` and `commit:<sha>:committer` for the author and
  committer lines, and `commit:<sha>:header` for any other commit header (`mergetag`, `gpgsig`, `encoding`, ...);
  `tag:<sha>:message` and `tag:<sha>:tagger` for a tag message or tagger line, and `tag:<sha>:header` for any other tag
  header (including the tag's `tag` name header); `ref:<index>` (the zero-based position of the ref in the pre-push
  input) when a ref name contains a hit; `ref:<index>` is also used for every ref when the name was not clean. #75 tests
  a vault value in a file name and in a branch name, in an unchanged file renamed to a value-bearing name, and in a new
  blob that appears at one clean path and one value-bearing path (both are reported).
- Exit codes: `0` no hit; `1` at least one hit; `2` the scan could not run (vault present but key missing, wrong
  permissions, wrong key, corrupt entry, a file over the size cap). **Failing to scan is never a pass.**
- The report also lists, on **every** scan, the `unscannable` entries by id and kind (value below the minimum length, a
  single-label host under 8 characters, or a `credential` or `secret` stored as `unscannable` because it equals public
  text, see section 4), so the gap is visible instead of silent. There is **no `partial` state**: an earlier draft reported
  a dropped base64 alignment as `partial`, but with the 7-byte minimum no alignment is ever dropped (the shortest needle,
  `k=1` with `n=7`, is 8 characters), and reporting it would have revealed that a value is exactly 6 bytes long.

**What the scan cannot catch** (residual risk; **the list below is illustrative, not exhaustive**: anything that
is not a listed rendering of a vault value is outside the guarantee):

1. **A value that is not in the vault.** The central gap. An address the owner never entered, a camera added through
   the camera's own web page, a value typed straight into a file. Mitigation: the vault is the only sanctioned way in
   (`import-legacy`, the import command, `vault set`), and the optional shape lint flags candidates for the owner to
   add; it can never prove absence.
2. Values below the minimum length, and generic usernames.
3. Transformations not listed: gzip, encryption, rot13, reversal, base32, base85, a password split over two lines or
   two table cells, a prefix or fragment of a value, IPv4 written with spaces, per-octet hex (`c0.00.02.0a`),
   octal octets, IPv6 embedded MACs (EUI-64 / SLAAC addresses), entity-encoded markup (`&#46;`), double percent-encoding,
   **shell escapes** (`\$`, `'\''` in a quoted password), **MIME base64 wrapped at 76 columns** (a line break
   inside the blob), regrouped phone numbers (`555 0100` against `5550100`), **spaced hex dumps** (`63 6f 72 ...`), a display name encoded
   with `+` for spaces (`Back+Door+North`), **defanged hostnames** (`nvr-1[.]example[.]invalid`), and **IDN (Unicode) forms of `xn--` hostnames**, **an IPv6 address with a trailing word glued on** (`2001:db8::1:<hex word>`), **a hex word or a dotted prefix glued on in
   front** (`cafe2001:db8::1`, `1.2001:db8::1`), **IPv4-compatible, NAT64 and translated forms** of an address, the
   **unbracketed port form** `2001:db8::1:554`, **invisible characters inserted as escapes** into the middle of a value (`%E2%80%8B`, `\u200b`: the decoding steps run after the
   squeeze step and do not squeeze again), **Rust renderings** of a value such as `Ipv4Addr::new(192, 0, 2, 10)` and `[192, 0, 2, 10]`, and **byte-array MACs**
   (`[0x02, 0x00, 0x5e, 0x00, 0x53, 0xaf]`).
4. Lookalike characters: Cyrillic or other homoglyphs, NFD vs NFC forms, transliteration (`ä` to `a`) of display names
   and `other` text.
5. Non-text content: images, screenshots, video thumbnails, compressed archives, binary blobs. A snapshot of a camera
   image can identify a site and no text scan sees it.
6. Derived or contextual information: relationships between values, counts, layout, positions of cameras, timestamps
   of events, a hostname's label alone (`nvr-1`), geo-location.
7. Anything the scan is not run on (section 9): text posted through the GitHub API (see residual risk 9), tool output
   seen only by an agent, tag and commit messages on a machine without the hooks.

### 9. Where the scan runs

**Locating the vault and key.** Every surface calls the same command, `wardenlens vault scan`. The gate,
`scripts/agents check` and the catalogue test resolve the vault as `WARDENLENS_VAULT` (a path) or the default dev path, and
the key as `WARDENLENS_VAULT_KEY_FILE` (a path) or the default dev key path (section 6). **The git hooks resolve both from
the fixed default paths only** (`$HOME/.local/share/wardenlens/dev-vault.db`, `$HOME/.config/wardenlens/dev-vault.key`;
the hook passes `--default-paths`) **and ignore `WARDENLENS_VAULT*` and `XDG_*`**, so a variable set for one `git commit` cannot
point the hook at an empty vault. (`HOME` itself can still be set by a process; the guard rule of residual risk 1 names it.) The checks of section 6 apply (outside work trees, 0600, owned). There are four
outcomes, and the first is the only one that skips:

| situation | gate / agents check / test | git hooks |
|---|---|---|
| no vault file, `WARDENLENS_REQUIRE_VAULT` unset | prints `vault scan: SKIPPED (no vault at <path>)` and continues | same, prints once |
| no vault file, `WARDENLENS_REQUIRE_VAULT=1` | fails | fails |
| vault file present, key missing, unreadable or wrong | fails (exit 2) | fails |
| vault present and key ok | scans, fails on exit 1 | scans, blocks on exit 1 |

The owner sets `WARDENLENS_REQUIRE_VAULT=1` in the shell profile of the development machine, so a deleted vault or key
cannot silently turn the scan off there. It is a convenience, not a security boundary: a process that sets the
environment can also unset it (see residual risk).

**Surfaces (normative for #75, #32, #76):**

1. **`scripts/gate`** gains a `vault scan` step after the tests: `cargo run -q -p wardenlens-cli --locked -- vault scan`
   over `git ls-files --cached --others --exclude-standard`, using the **tree's own build** (the gate checks the tree
   it is in). It prints `SKIPPED` as above when there is no vault. **`GITHUB_ACTIONS` never skips a scan when a vault is
   present**; the only skip is the first row of the table above (public CI skips because it has no vault).
2. **`scripts/agents check PROMPT_FILE`** runs `$HOME/.cargo/bin/wardenlens vault scan PROMPT_FILE` (the same fixed
   installed binary as the hooks, not a build from the tree) and refuses on exit 1 or 2; **it fails closed when a vault
   exists but that binary is missing** (with the install command). The scan
   replaces the RFC1918, ULA, `scheme://user:pass@` and secret-file regexes and the `jq` secret-file loop. When there is
   **no vault**, the existing regex checks stay as a blocking fallback so a machine without a vault is not left with
   nothing; when a vault is present they become non-blocking warnings (the soft lint) and can be removed later.
   `scripts/agents record` calls the same function, because it re-vets the prompt it saves.
3. **Git hooks (human-installed, locked paths `.githooks/**`).** `.githooks/pre-commit` runs `vault scan --staged`
   (the staged blobs, read from the index with `git`, not the working tree, plus the staged file names); `.githooks/pre-push`
   runs `vault scan --range <remote_sha>..<local_sha>` for every updated ref it receives on stdin (a new branch uses
   the range against the remote-tracking refs, as the existing hook does). It scans **the blobs that are new to the remote**
   (`git rev-list --objects` over the range, so a merge resolution that exists only in the merge commit is covered, which
   a per-commit patch scan would miss), but **takes the paths from `git diff-tree`**, not from the `rev-list` listing:
   `git diff-tree -r --name-only --root -m -z` over **every new commit** (recursive, names only, `--root` so the root
   commit is included, and `-m` so each parent of a merge is diffed separately; see its man page). The `rev-list` listing
   gives one path per new blob and so misses a rename of unchanged content (the blob is not new, the path is) and a second
   path for the same new blob. Also scanned: the **full raw content of every new commit and annotated tag object, read with `git cat-file`**: every
   header (`author`, `committer`, `encoding`, `gpgsig`, `mergetag`, and for a tag the `tag`, `tagger` and `object` headers) plus
   the message, so nothing a header can carry is skipped; and the ref names: all of it becomes public on push. "New to the remote" is
   computed against `--remotes=<destination remote>` (that remote's tracking refs only, not every remote, so a commit another
   remote already has is not wrongly treated as published here). **The hooks also run the literal needles (passwords,
   hostnames, serials, display names) and the IPv4, IPv6 and MAC tokenisers over binary blobs**, which the gate skips
   (section 7): a vault value stored in the clear inside a binary file is still caught. The hooks
   use a binary installed by the human (`cargo install --locked --path crates/wardenlens-cli`) at the **fixed path**
   `$HOME/.cargo/bin/wardenlens`; there is **no `WARDENLENS_BIN` override**. It is **not** a build from the working tree, because a hook that
   runs code from the tree being checked can be edited out of the way by the change it checks. If the vault exists and
   the binary is missing, the hook fails with the install command. #75 stages the two files for the owner (agents
   cannot write them).
4. **The catalogue test (#32).** Structure stays where it is: `wardenlens-core` parses every `cameras/<vendor>/<model>.toml`
   and fails on unknown fields, missing evidence, a stale README. The exact-match part is a test in
   `crates/wardenlens-cli/tests/` (cli depends on `vault`; core must not, and this avoids a dev-dependency cycle)
   that calls the library `vault::scan` over `cameras/` and `docs/`, and follows the table above (skip with a printed
   notice, `WARDENLENS_REQUIRE_VAULT=1` makes a missing vault a failure). It never prints a value.
5. **Generated docs.** `cargo doc` output is not committed; the committed generated file is `cameras/README.md`
   and `docs/openapi.json`, both inside the tracked-tree scan of the gate.

**Public CI has no vault** (the vault is on the owner's machine and its key must never be a repository secret).
Therefore CI keeps only the structural checks: the catalogue schema and README staleness test, `cargo deny`, fmt, clippy,
tests, and, if kept, the optional shape lint as warnings. The `vault scan` step and the catalogue exact-match test print
`SKIPPED (no vault)` and pass. **A leak is stopped on the developer machine (gate, hooks) or not stopped at all**;
CI cannot see it. Consequences stated plainly: a contributor without a vault (anyone but the owner) is not protected by
the scan and the human reviewers plus the verification agents are their only check; and a push that bypassed the local
hooks reaches the public repository unchecked, after which the value must be considered public (rotate what can be
rotated: passwords, tokens; addresses cannot be). GitHub's own secret scanning and push protection are separate,
shape-based, and not relied on here.

**Recommended further surfaces (not part of #75, proposed as follow-up tickets, locked files for the owner):**
a Claude Code `UserPromptSubmit` hook (blocks the owner pasting a vault value into a prompt), `PreToolUse` hooks on
`Bash`, `Write` and `Edit` (scan the command or the new content before it runs, which is what prevents a value an
agent already knows from reaching a file, a `gh` body or a log), a `scripts/ticket` and `scripts/verify` step that
scans issue and PR bodies before `gh` posts them, and a detective scan of `~/.claude/projects` transcripts with
`vault scan PATH...` (this finds a leak after the fact; a transcript cannot be unsent).

### 10. Access, in-memory handling and the CLI

- **Access.** Tooling and spikes read values with `wardenlens vault get <ref>` (CLI) or the `vault` library; committed
  files, prompts and notes contain only ids such as `cam:reolink-1:host`. The ids appear in `.toml` or `.md` as
  plain text; a value never does.
- **CLI rules (#74).** `set <id> --kind K` reads the value from stdin or a TTY prompt (no echo), **never from argv**
  (argv is visible in `ps`, shell history and agent transcripts). `get <id>` writes the value, with no trailing text, to
  stdout only when stdout is a pipe or a TTY, never to a log, and refuses an unknown id with an error that does not
  suggest nearby ids. For `credential` entries `get <id> --field password|username` selects one field; **credentials never
  go on argv of another program** (#76): scripts read the value into a shell variable and pass it through stdin, a
  file descriptor, or `curl --config -`/`--netrc-file`, never `-u user:pass`. `list` shows ids, kinds and the
  `unscannable` flag, never values. `rm`, `rekey`, `init`, `import-legacy`, `scan`, `check-key`, `key export` and
  `key import` as above. **`redact`** (added by #76) is an exact-match stdin filter: it reads text on stdin and
  writes it with every hit replaced by `[REDACTED:<entry-id>]`, using the section 7 matcher; it replaces the shape-based
  `redact()` of `spikes/s1-cameras/lib.sh`. A hit found in a view is mapped back to raw bytes through the view's offset
  map (section 7) and those raw bytes are replaced. **When a hit cannot be mapped exactly** (a view character that came
  from several raw characters and lies partly inside the hit, or a joined-view match spanning a line break), `redact`
  replaces **the whole raw line** (or lines) the hit touches, never a guessed sub-range.
- **RTSP URLs on argv (accepted spike-only exception).** The `ffmpeg`/`ffprobe` spikes pass an RTSP URL with credentials
  on argv (ADR 0002). That stays an accepted exception **for the spikes only**; the product uses `retina` with
  in-process credentials (below) and never puts a credential in a URL or on argv.
- **Credentials to `ingest` (ports).** Core defines `Credential { user: String, password: SecretString }` (redacting
  `Debug`) and a `CredentialSource` trait; `ingest` and the other users take it as a **generic**, never `dyn` (ARCH-3).
  The `cli` wires the vault implementation into it; no other crate reads the vault. Camera URLs never embed
  credentials, and library errors are logged by camera id with the URL stripped (#43). A UI that accepts credentials
  later goes through a core port as well (follow-up).
- **In memory (SEC-6).** `secrecy` `SecretString` and `SecretBox` for values and `Zeroizing` for keys and decrypted
  buffers; `Debug` of every type that can hold a value is redacting (verified in the probe: `SecretString` prints
  `SecretBox<str>([REDACTED])`); `expose_secret` is called at the last moment, in the smallest scope. Errors carry ids and
  kinds only. Core camera types that carry a host or display name (#43) have a redacting `Debug` and `Display` too,
  and logs identify cameras by id, never by host or name (ADR 0004's tracing rules).
- **What zeroisation does not do.** The `aho-corasick` automaton and tokeniser sets built for a scan hold needles in
  ordinary memory and are not zeroed; the scan process is short-lived. `zeroize` is best effort (copies made by the
  allocator or in swap are outside its reach). Core dumps are suppressed with `setrlimit(RLIMIT_CORE, 0)` through
  `rustix` (safe, section 11), which lowers the heap-on-disk risk but does not remove swap or a live memory read.

### 11. New dependencies

Observed 2026-11-23. "Defaults off" is the planned `default-features = false` use. Every licence expression contains
an entry on the `deny.toml` allow list (`MIT` or `Apache-2.0`).

| crate | version | licence | last release | owners (crates.io) | features used | where | deny.toml change |
|---|---|---|---|---|---|---|---|
| chacha20poly1305 | 0.11.0 | Apache-2.0 OR MIT | 2026-08-05 | newpavlov, team rustcrypto:aeads | no defaults; `alloc`, `zeroize` | secrets | no |
| zeroize | 1.9.2 | Apache-2.0 OR MIT | 2026-11-17 | tarcieri, team rustcrypto:utils | defaults | core, secrets, vault | no |
| secrecy | 0.10.3 | Apache-2.0 OR MIT | 2024-10-09 | tony-iqlusion | defaults (no `serde`) | core, secrets, vault | no |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | 2026-06-17 | dhardy, team rust-random | defaults | secrets | no |
| aho-corasick | 1.1.5 | Unlicense OR MIT | 2026-08-03 | BurntSushi | no defaults; `std` | vault | no |
| rusqlite | 0.43.0 | MIT | 2026-11-15 | thomcc, gwenn | `bundled` (as planned in #41) | vault, index | no |
| base64 | 0.23.1 | MIT OR Apache-2.0 | 2026-08-04 | alicemaz, marshallpierce | `std` only (already in ADR 0004) | vault | no |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 | 2025-08-21 | SimonSapin, teams servo | defaults | vault | no |
| rustix | 1.1.6 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 2026-10-27 | sunfishcode | `process` (for `setrlimit`) and, if std lacks the open flags, `fs`; no libc backend assumed. **Not probed with `cargo deny`; #48 re-runs it (SEC-8)** | secrets or cli | no (to be confirmed) |
| rpassword | 7.5.5 | Apache-2.0 | 2026-11-10 | conradkleinespel | defaults | cli (no-echo TTY prompt for `set`; candidate only, #74 confirms) | no |

Probe: a scratch project outside the repo (given `license = "MIT"`) with `chacha20poly1305` (no defaults, `alloc`), `secrecy`,
`zeroize`, `aho-corasick` (`std`), `getrandom`, `rusqlite` (`bundled`), `base64` and `percent-encoding` resolved to 36
lines in `cargo tree -e normal` (including the probe itself) and `cargo deny check licenses advisories bans sources`
with the repo's `deny.toml` gave `advisories ok, bans ok, licenses ok, sources ok`; a compiled program sealed a record with
`XChaCha20Poly1305` and AAD, printed a `SecretString` as `SecretBox<str>([REDACTED])` and matched a needle with
`AhoCorasick`. `deny.toml` needs no change. `rpassword`, `rustix` and `percent-encoding` were not in that probe; their
`cargo deny` result is for #74 and #75 to re-run (SEC-8) in their PRs.

Maintenance notes. `secrecy` 0.10.3 was last released 2024-10-09 (single owner) but is a 2-line dependency tree, is
widely used (212 M downloads) and is small enough to replace with an own `Zeroizing<String>` newtype if it stalls.
`rpassword` is single-owner and only a candidate; if #74 rejects it, the no-echo prompt must still come from a crate
and never from shelling out to `stty` (SEC-5), or `set` accepts stdin only. The `chacha20poly1305` audit predates 0.11 (section 2); a new audit or an
advisory is the trigger to re-evaluate, and the version byte makes a migration possible.

## Decision

Normative summary (the sections above give the detail and the reasons):

1. **One vault, seven kinds, opaque ids.** Every sensitive value lives in an encrypted SQLite vault; committed text
   holds ids only (section 1).
2. **XChaCha20-Poly1305 with a 32-byte key file** (`chacha20poly1305` 0.11), not `age`; record = version, 24-byte random
   nonce, ciphertext, tag; AAD binds version, kind and id (sections 2 and 3).
3. **Separate vault files** (service, per developer), outside every work tree, mode 0600, never the recording index
   (section 4); the key file is outside every work tree, never in an environment variable, checked on every load, and
   excluded from backups (section 6).
4. **Crates:** `secrets` is the cipher and key rules only, the new `vault` crate holds store, normaliser and scan, `index`
   depends on neither, `cli` composes (section 5).
5. **Leak scan by exact match** on the section 7 views and per-kind rules, reporting ids and redacted locations only,
   failing closed (sections 7 and 8); shape checks are an optional soft lint.
6. **It runs** in the gate, `scripts/agents check`, the human-installed git hooks and the cli catalogue test; **public CI
   has no vault and keeps the structural checks only** (section 9).
7. **A value is protected if and only if it is in the vault**; the residual risks are listed in the threat model.

## Threat model

Context: a home NVR, one owner, a public repository, AI agents running as the owner's user with shell access, a
service in Docker on the same host.

**Assets.** Camera credentials, cloud tokens and API secrets; LAN addresses and hostnames, MACs and serials (they
identify and locate the site and are the first thing an attacker who learns the network wants); camera display names (they
describe rooms and people); the owner's PII.

**Prevented or substantially reduced**

| leak | how |
|---|---|
| a database or a copy of it leaks | the vault file holds only XChaCha20-Poly1305 records; the key is a separate file, never in the repo, never in an environment variable; the recording index holds none of it. **This holds for a backup only if the key path is excluded from that backup** (residual risk 10) |
| accidental commit by owner or agent | `pre-commit` and `pre-push` (exact match on every stored value in every listed rendering, commit messages and file names included) and the gate; blocked before the push |
| a value in a prompt to an agent | `scripts/agents check` scans the prompt before dispatch; with the proposed hooks, the owner's own prompt too |
| a value in a log | values are redacting types (`Debug`), the service logs ids not hosts or names, and the scan can be run on log files (`vault scan PATH...`) |
| a value in a tracked doc or the catalogue | gate and the catalogue test scan the tree; the structural checks remain in public CI |
| a camera's credentials in a process list | values never travel on argv (CLI and scripts), with the one accepted spike-only exception of the `ffmpeg`/`ffprobe` RTSP URL (section 10) |

**Residual risk (not prevented)**

1. **Root or the same user on the host.** The key file and the database sit next to each other for the user who runs
   the service and the agents. Anyone or anything running as that user can read both, so **an agent with shell access
   can run `vault get` or read the key file**: the vault protects against accidents and leaked copies, not against a
   hostile or prompt-injected agent. Recommended and out of scope here: deny rules in the agent settings for the vault
   and key paths and for `vault get`, a Bash guard rule that refuses an agent setting `WARDENLENS_VAULT*`,
   `WARDENLENS_REQUIRE_VAULT`, any other `WARDENLENS_*`, `XDG_*` or `HOME` for a git command (the same way the guard already treats
   `WARDENLENS_ALLOW_REWRITE`), possibly a separate OS account for agents. **Binary replacement:** an agent running as the owner can overwrite the
   installed `~/.cargo/bin/wardenlens` (for example with `cargo install`), which the hooks and `scripts/agents check` trust;
   the same deny and guard follow-up covers that path. **Oracle note:** `vault scan -` and `vault redact`
   tell whoever feeds them text whether it contains a vault value, so an agent (or anyone with access) can test guesses
   for a low-entropy value (a short password, a likely host) without reading the vault; the deny-rule follow-up covers
   them as well as `vault get`.
2. **A value that is not in the vault** (section 8, item 1) and the other items of section 8. Shape matching would not
   have caught these reliably either (PR #71); the difference is that the gap is now defined: a value is protected
   if and only if it is in the vault.
3. **Output of `vault get`** reaches whoever runs it. If an agent runs `vault get` in its own shell, the value is in
   its transcript. Scripts must use the value without echoing it; the transcript scan is detective only.
4. **No scan in public CI** (section 9): a bypass of the local hooks, or a contributor without a vault, is not caught.
5. **Already-public history.** A value pushed once cannot be recalled. Rotate what can be rotated; a LAN address
   changed only by renumbering.
6. **Ids are plaintext.** An id derived from a value (`cam:192-0-2-10:host`) defeats the point. The ids of inventory
   cameras (`reolink-1`) are public. `vault set` refuses an id in which the matcher finds the entry's own value
   (section 1); an id built from some other sensitive text is caught only by review.
7. **Heap, swap, core dumps** (section 10).
8. **A weak or short secret** below 7 bytes, a single-label host under 8 characters, and generic usernames, are not
   scanned (marked `unscannable`).
9. **Text that reaches GitHub without passing a git hook.** Issue and PR bodies and comments (`gh issue comment`,
   `gh pr create --body`), commit status descriptions and anything written through the GitHub contents API never
   pass `pre-commit` or `pre-push`. Until the proposed scan in `scripts/ticket` and `scripts/verify` exists, only the
   agents' own care and review protect them.
10. **Backups that hold both files.** A whole-home or whole-disk backup contains the dev key and the dev database
    and gives no protection against its leak. #69 and #76 document excluding the key path from backups.
11. **Agent tool output and same-user agents.** The output of any command an agent runs (including `vault get` and
    the scan's own notices) is seen by the agent and recorded in its transcript; no hook scans it before it is seen.
    This is residual risk 1 and 3 seen from the other side: the vault does not stop an agent that runs as the owner.
12. **Value lengths are visible** in the vault file (a record is `41 + length` bytes; section 4); no padding in v1.

**Why exact match beats shape match.** A shape rule has to predict every way a secret can be written; PR #71 needed
five rounds and three more were queued in #72, and each round fixed what the previous adversary found, while every fix
added false positives (version strings, resolutions, WS-Discovery multicast, model names). An exact match has a finite
needle set derived from data that exists. Its false-negative classes are illustrative and written down, not exhaustive (section 8), and
its false positives are limited to the real values (and the 7-byte minimum). It also removes the guesswork from the
reviewers: "does the text contain a value from the store" is decidable.

## Consequences

Each of the eight tickets below carries an **"Amended by ADR 0006" section** (added 2026-11-23 on the PR #77
verification rounds). The amendments **mirror this ADR at the merged commit** (they were brought in line with it when the owner approved the
round-5 fold-in) and summarise it; **where an amendment or an older ticket text differs from this ADR, this ADR wins**, and
the implementer reads the ADR first.

- **#48 (`wardenlens-secrets`).** The cipher only, no SQLite and no scan: XChaCha20-Poly1305 with a key file; record
  = version byte, 24-byte random nonce, ciphertext, tag. `seal(&key, kind, &EntryId, plaintext)` and `open(...)` with
  AAD = version, kind byte, entry id (**not** keyed by camera id; this overrides the ticket's `seal(&key, camera_id,
  &Credentials)`). `KeyFile`: OS RNG, `O_EXCL|O_NOFOLLOW`, refuse group- or world-readable files, a wrong owner and a
  path inside a git work tree. The `vault key export/import` base64 encoding helpers. `Credentials` stays as the payload
  codec for kind `credential`. Dependencies: `chacha20poly1305` (`alloc`, `zeroize`), `secrecy`, `zeroize`, `getrandom`,
  and `rustix` if std lacks what it needs. A test asserts that swapping id or kind, a wrong key, truncation and an unknown
  version each give a typed error without secret material.
- **#74 (vault store and CLI).** The new `wardenlens-vault` crate (core, secrets) with the seven kinds and stable codes
  and the reserved `meta:` prefix; schema, limits, busy timeout and per-kind validation (sections 1 and 4);
  `import-legacy` imports mapped fields only and lists unknown keys by name, ids never from values; `vault set` and
  import scan the tracked tree and refuse a value already present; `unscannable` marking and warning; refuse paths
  inside a work tree; `rekey` (TTY checked before rotating) with `.next` recovery only under the write lock; `vault init` refusing when `XDG_*` would resolve the dev paths elsewhere; `vault key export/import` (TTY only);
  `get`/`set` rules of section 10. Blocked by this ADR, #48 and ADR 0005's SQLite crate choice.
- **#75 (scan).** The `scan` module of the vault crate with the views, per-kind rules, exit codes and report of
  sections 7 and 8; `wardenlens vault scan [--staged | --range A..B | PATH... | -]`; the `scripts/gate` step; the
  `scripts/agents check` replacement with the no-vault regex fallback; the staged `.githooks/pre-commit` and
  `.githooks/pre-push` for the owner (fixed installed binary, no `WARDENLENS_BIN`; the hooks resolve the vault from the
  fixed default paths only and ignore `WARDENLENS_VAULT*`; `GITHUB_ACTIONS` never skips a scan when a vault is present). The report never prints a path, ref or message that contains a hit (the `<redacted-path>`,
  `commit:<sha>:message|author`, `ref:<index>` forms), with tests that put a vault value in a file name and in a branch
  name. IPv6 trimming and sub-runs with the four required found examples, IPv4-mapped hex, MACs without leading zeros
  and any single non-hex separator, the `char::to_lowercase` fold, the joined view, no `%0A`/`%0D` decoding; pre-push
  scans new blobs, takes paths from `git diff-tree -r --name-only --root -m` over every new commit, and scans commit
  (message, author, committer) and tag messages, with tests for an unchanged file renamed to a value-bearing name and for
  one new blob at a clean and a value-bearing path; IPv6 sub-runs always checked (`Source:2001:db8::1`,
  `Interface:fe80::1`, `beef:2001:db8::1`, `dead:fe80::1`); files with a UTF-16 BOM decoded as text; binary files skipped with a notice (the hooks still run the literal needles and the tokenisers over binary blobs); raw commit and tag objects scanned with `git cat-file` (all headers, `commit:<sha>:header`, `tag:<sha>:header`); the 7-byte minimum applied to the value and every squeezed needle, with no `partial` state; the decoded and JSON views matched against squeezed and unsqueezed needles; the refusal message "remove or replace the tracked occurrence, then store it"; pre-push uses `--remotes=<destination remote>` and scans the tag `tagger` line; the JSON-unescaped view; SQLite opened with `SQLITE_OPEN_NOFOLLOW` plus an `fstat` comparison; `vault redact` offset maps with whole-line fallback; tracked files over the limit fail,
  untracked ones warn; no allowlist. Proptest (TEST-3) that the matcher finds a value after each listed transformation.
- **#76 (spikes and docs).** `spikes/s1-cameras/lib.sh` and `spikes/s2-gpu` read through `vault get` with ids; adds
  `wardenlens vault redact` (an exact-match stdin filter) and replaces the shape-based `redact()` in `lib.sh` with it;
  the ffmpeg/ffprobe RTSP URL on argv stays the accepted spike-only exception (ADR 0002); documents excluding the vault
  key path from backups; the README and the agent memory notes name ids, not paths; legacy files deleted by the owner
  only after the key is backed up with `vault key export` (section 6).
- **#50 (camera registry).** The `cameras` table has **no credential, host or display-name column**: those are vault
  entries `cam:<id>:credential`, `cam:<id>:host`, `cam:<id>:name` (#74). The table keeps id, model, port, main/sub path
  templates, created and updated. The index depends on core only; the `cli` builds core `Camera` values from an index
  row and the vault entries. The ticket **no longer depends on #48 for credential blobs** (its `Blocked by` line is updated; it still needs the
  core camera model and the index crate, #43 and #49). Its test becomes "the index
  file contains none of the synthetic host, name or credential values" (a byte grep after inserting a camera through the
  registry); the encrypted-at-rest assertion belongs to #74 (vault file).
- **#43 (core camera model).** Core may depend on `secrecy` and `zeroize` (pure crates). Core defines `Credential {
  user: String, password: SecretString }` (redacting `Debug`) and the `CredentialSource` trait, used through generics;
  the cli wires in the vault implementation. Camera URLs never embed credentials, and library errors are logged by
  camera id with the URL stripped. Also `EntryId` and `EntryKind`, and a redacting `Debug`/`Display` for host and display
  name.
- **#69 (Docker).** The compose secret source for the vault key is a host path outside every work tree, by default
  `/etc/wardenlens/vault.key` (`WARDENLENS_KEY_FILE_HOST` in `.env`); `/secrets/` and `*.key` go into `.dockerignore`
  (and are already in `.gitignore`); a test that the container user's uid and the file mode of the bind-mounted secret
  pass the strict key check; the container runs `wardenlens vault check-key` at startup; the service key is rotated as stop the container, `rekey` on the host, start the container; documents
  excluding the key path from backups.
- **#32 (catalogue).** Keeps structural validation and the generated README; the site-data guarantee is #75's exact-match
  scan (the exact-match catalogue test lives in `crates/wardenlens-cli/tests/` and calls `vault scan` when a vault is present); the shape
  check becomes an optional soft lint and is not required. Its blocker remains #75.
- **Also touched, without an amendment section:** #66 (`import agentdvr`) writes credentials, host and name to the service
  vault, not to the index; #72 is superseded for the site-data classes it lists, except the catalogue's structural items.
- **Older text.** Where this ADR and an older ticket body differ (#48 `camera_id` AAD, #50 `credential_blob`, #74's
  six kinds, #75's "expands every value into forms" for IP and MAC, #76's file names), **this ADR wins**; the amendment
  sections above already record it, and the implementer keeps the ticket text in step in the PR that implements it.
- **Follow-ups (listed, not built by this ADR):** Claude Code hooks (`UserPromptSubmit`, `PreToolUse` on Bash, Write and
  Edit) and the Bash guard and deny rules of residual risk 1, with `WARDENLENS_*`, `XDG_*` and `HOME` on the guard's
  list of names an agent may not set; scanning `gh` bodies in `scripts/ticket` and `scripts/verify` (residual risk 9);
  `vault exec` (inject a value into a child's environment or file descriptor so scripts never see it); a transcript
  scan routine; a core port for credential entry from the UI.
- **Harder.** A new developer machine needs `vault init` and an import before the scan protects it; there is no key
  recovery; the scan adds a step to the gate and hooks that fails closed when the vault is unreadable.
