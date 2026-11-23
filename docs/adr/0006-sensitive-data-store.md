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
database and in `vault list`, and must never be derived from a value. `vault set` only enforces a cheap guard (it
refuses an id that is a rendering of its own value, such as `cam:192-0-2-10:host`); the rest is review, see residual
risk 6 in the threat model.

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
`Ipv4Addr`, a MAC must reduce to 12 hex digits, a hostname must be ASCII letters, digits and hyphens, at most 253
bytes, lower-cased, without trailing dot; IDN hostnames are entered in their `xn--` form).

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

1. **`chacha20poly1305` XChaCha20-Poly1305 with a 32-byte key file** (chosen). RustCrypto AEAD, the construction is
   the one the `age` format itself builds on for payloads; a 192-bit random nonce makes random nonces safe without a
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
- Minimum record length is `1 + 24 + 16`; shorter input is a typed error. Errors never contain key, plaintext or
  ciphertext bytes (ERR-5, SEC-6).

### 4. Storage: SQLite, one file for the service and one per developer

SQLite, consistent with ADR 0005 / #41 (`rusqlite` 0.43 with `bundled`, WAL for the recording index). **If ADR 0005
chooses a different SQLite crate, the vault follows it; the vault does not set that choice.**

| file | purpose | default location |
|---|---|---|
| service vault | camera credentials, host, display names for the running service | `/var/lib/wardenlens/vault.db` (a volume), separate from the recording index |
| developer vault | the same kinds for tooling, spikes and the leak scan | `${XDG_DATA_HOME:-$HOME/.local/share}/wardenlens/dev-vault.db`, mode 0600, directory 0700 |

Rules:

- **The vault is a separate file from the recording index** (ADR 0005 / #49). A backup, copy or `sqlite3` dump of the
  index then contains no sensitive value at all, and the key is never stored in either file.
- The dev vault lives **outside every repository**. `vault init` and every open refuse a path that is inside a git work
  tree (walk the canonical path's ancestors for `.git`; SEC-4) and a symlink.
- The file is created with mode 0600 (created before SQLite opens it, so it never exists with a wider mode) and opened
  only if it is owned by the current user and not group- or world-accessible.
- The vault uses `journal_mode = DELETE` and `synchronous = FULL`: it is tiny and rarely written, and no `-wal`
  or `-shm` sidecar files are created. (Sidecars would only hold ciphertext anyway.)
- Schema (version 1): `meta(key TEXT PRIMARY KEY, value BLOB)` holding `schema_version` and `keycheck` (a sealed
  constant under id `meta:keycheck`, so a wrong key is detected before any entry is touched), and
  `entries(id TEXT PRIMARY KEY, kind INTEGER NOT NULL, record BLOB NOT NULL, created_at INTEGER NOT NULL, updated_at
  INTEGER NOT NULL)`. The `kind` column is a convenience copy; the authoritative kind is the one authenticated in the
  AAD, and a mismatch between column and AAD is a typed `CorruptEntry` error. No value, length or hash of a value is
  stored in plaintext.
- **Migration (`vault import-legacy`).** Reads `agentdvr-cameras.secret.json` and `cameras.local.toml` and writes
  entries (`cam:<id>:credential`, `cam:<id>:host`, `cam:<id>:name`, ...). It never drops a value silently: any scalar
  in either file that the importer does not recognise becomes an `other` entry and is listed (ids only) in its output.
  It is idempotent (re-running updates entries) and prints counts and ids, never values. After a successful import the
  **owner** deletes the two legacy files (documented step, not automatic: #76). The old files are plaintext, so until
  they are deleted the vault adds protection but does not remove the exposure.

### 5. Crate map (amends ADR 0004 section 8)

ADR 0004 section 8 left "the encryption crate" and the vault to this ADR. Decision:

| crate | responsibility | depends on (workspace) |
|---|---|---|
| core | adds the pure types `EntryId` (validated, section 1 charset), `EntryKind`; no crypto, no I/O | none |
| secrets (#48) | primitives only: `KeyFile` (load, generate, permission checks), `seal`/`open` with the section 3 format, `Credentials`, redacting wrappers. **No SQLite, no scan.** | core |
| **vault** (new, #74, #75) | the store (`rusqlite`), per-kind validation, the section 7 normaliser and the section 8 scanner (`aho-corasick`), `import-legacy` mapping logic. Library only | core, secrets |
| index | unchanged responsibility. **Does not depend on `vault` or `secrets`** and never holds a sensitive value or a ciphertext of one | core |
| cli | the `wardenlens vault` subcommands (`init`, `set`, `get`, `list`, `rm`, `rekey`, `import-legacy`, `scan`), argument and TTY handling, composition with index | all |

Direction: `cli -> vault -> secrets -> core`, `cli -> index -> core`. `api` must not depend on `vault`, `secrets` or
`index` (ADR 0004 rule). Splitting `vault` from `secrets` keeps ARCH-2 (secrets stays a small audited-surface crate with
the crypto and the key rules; the vault carries the larger dependency set, SQLite and the matcher) and keeps SQLite
out of the crate that every service component would otherwise inherit. The scan lives in `vault`, not in `cli`, so
the catalogue test and any future caller use the same library function (`vault::scan`). The service reads camera
hosts, names and credentials through `cli`, which opens the service vault and the index and builds core `Camera` values;
no other crate reads the vault.

ADR 0004 section 8 is updated with a pointer to this ADR; its table row for `secrets` ("redacting wrappers for camera
credentials") is narrowed by the row above.

### 6. Key lifecycle

- **Format.** A raw 32-byte file. Exactly 32 bytes, no header, no text encoding (so there is nothing to mis-parse).
- **Generation.** `wardenlens vault init` (and `KeyFile::generate`) draws 32 bytes from the OS RNG (`getrandom`)
  and creates the file with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600; an existing file is never overwritten. The
  flags are set through `std::os::unix::fs::OpenOptionsExt` with constants from a safe crate (no `unsafe`, SEC-1); #48
  names and justifies that crate (SEC-8) if std alone does not expose them.
- **Location.** Dev: `${XDG_CONFIG_HOME:-$HOME/.config}/wardenlens/dev-vault.key` (directory 0700), a different directory
  from the database so that a copy or backup of one does not carry the other. Never inside a git work tree (same rule as
  the database). Service: the path in `WARDENLENS_VAULT_KEY_FILE`, by default `/run/secrets/wardenlens_vault_key`.
- **Permission checks (refuse, do not warn).** `KeyFile::load` refuses a file that is not a regular file (symlinks are
  refused, `O_NOFOLLOW` plus `fstat` on the opened descriptor, not a path check followed by an open), not owned by the
  current user, readable or writable by group or others (`mode & 0o077 != 0`), or not exactly 32 bytes. The same
  checks apply to the vault file. The error says which rule failed, never the contents.
- **No environment variables for key material.** The key is never read from an environment variable. If
  `WARDENLENS_VAULT_KEY` (or any variable that is not a path) is set, startup fails with an error telling the user to
  use a file (an environment is inherited by every child, shows in `/proc/<pid>/environ` and in `docker inspect`).
  Only the *path* variables `WARDENLENS_VAULT` and `WARDENLENS_VAULT_KEY_FILE` exist.
- **Docker.** Compose `secrets:` with a file source on the host (`secrets: { wardenlens_vault_key: { file:
  ./secrets/vault.key } }`), mounted at `/run/secrets/wardenlens_vault_key`. Environment variables are rejected as
  above. **Not verified here:** whether Compose in non-swarm mode presents the mounted file as 0600/0400 or as
  world-readable 0444. #69 must test it on the real compose version. If it is group- or world-readable, the options
  are the long-syntax `mode:` or a documented, explicit exception for the single path `/run/secrets/` (inside the
  container only), not weakening the check for other paths. Until #69 settles it, the strict check stays.
- **Rotation (`vault rekey`).** Generate the new key as `<key>.next` (0600, `O_EXCL`, fsynced), open a single SQLite
  transaction, re-open every entry with the old key and re-seal it with the new key and a fresh nonce, write a new
  `keycheck`, commit, then atomically rename `<key>.next` over the key file and fsync the directory. A crash between
  commit and rename leaves a `.next` file: on startup, if the vault does not open with the current key but opens with
  `.next`, the rename is completed; if it opens with the current key, a stale `.next` is deleted. The old key is
  overwritten by the rename; backups of it still decrypt older copies of the database, which is why backups of key and
  database are kept separately and rotated together.
- **Key loss.** There is no recovery path by design. A lost key means the database is unreadable: delete it, `vault
  init`, and re-enter or re-import the values from their sources (AgentDVR export, the owner's password manager, the
  camera labels). Because #76 has the owner delete the legacy plaintext files after the import, the owner must keep a
  copy of the key in the password manager (offline, separate from database backups) before deleting them. Losing the
  key of the *dev* vault also disables the scan until the vault is rebuilt; the gate says so (section 9).
- **Memory.** Keys are held in `Zeroizing<[u8; 32]>`, values in `secrecy::SecretString` / `SecretBox`, with the
  `zeroize` feature of `chacha20poly1305` on; see section 10.

### 7. Leak scan: exact match, not shape

**Principle.** The scan does not ask "does this look like a credential or an address?". It asks "does this text
contain one of the values that are actually in the vault, in any of the listed renderings?". A vault of N values
yields a finite, enumerable set of needles; there is no open-ended grammar to bypass, and a text with an
address-shaped or password-shaped string that is not in the vault passes (no false positives from shape). The
shape heuristics of `scripts/agents check` and the catalogue guard are demoted to an optional soft lint (warnings only,
section 9).

**Views of the text.** Every input is matched in three views, and a hit in any of them counts (reported once per
entry and line):

1. **raw**: the bytes as they are;
2. **squeezed**: decode UTF-8 (invalid bytes become U+FFFD), then delete the invisible characters U+00AD, U+200B to
   U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066 to U+2069 and U+FEFF; map the fullwidth ASCII block U+FF01 to
   U+FF5E onto U+0021 to U+007E; map U+3002, U+FF61 and U+2024 to `.`; map U+2010 to U+2015 and U+2212 to `-`; map
   U+00A0, U+2000 to U+200A and U+3000 to a space. Line breaks are never touched, so line numbers stay valid;
3. **decoded**: the squeezed view with `%XX` sequences percent-decoded once (invalid sequences left as they are).

Tables, not heuristics: the same three views are applied to every file the same way, and the mapping is part of the
tested contract. A character not in the tables (for example a Cyrillic lookalike) is not mapped; see "what the scan
cannot catch".

**Per-kind rules.** A "boundary" is the rule for what may touch a match; `A` means ASCII letter or digit.

*`host`, IPv4* (value parses with std `Ipv4Addr`; stored as its 32-bit value `n`). Not expanded into strings: the text is
tokenised and every candidate is converted to a `u32` and looked up in a hash set, because mixed separators make the
string set explode.
- Field form: four decimal fields of 1 to 3 digits (leading zeros allowed, read as decimal, each at most 255) joined
  by one separator each from `.`, `-`, `_`, `[.]`, `(.)`, `{.}`, any mix. Any four consecutive fields of a longer
  chain are a window and are all checked, so `10.192.0.2.10` still yields `192.0.2.10`. Fields are compared as numbers, so
  `192.0.2.1` never matches inside `192.0.2.10` (the candidate window is `192.0.2.10`, not equal to `n`).
- 32-bit decimal: a digit run of 8 to 10 digits equal to `n`, not touching another digit.
- Hex: `0x` followed by 8 hex digits (case-insensitive) equal to `n`, or 8 bare hex digits equal to `n` not touching
  another hex digit.
- Worked example, stored value `192.0.2.10` (`n = 3221225994`, hex `c000020a`). Found: `192.0.2.10`, `192-0-2-10`,
  `192_0_2_10`, `192[.]0[.]2[.]10`, `192.000.002.010`, `192.0.2.10:554`, `rtsp://192.0.2.10/stream`, the fullwidth
  `１９２．０．２．１０` (squeezed view), `192%2E0%2E2%2E10` (decoded view), `3221225994`, `0xC000020A`, `c000020a`.
  Not found: `192.0.2.100`, `192.0.2.1`, `192.0.2` (partial), `192 0 2 10` (spaces), `0300.0.02.012` (octal),
  `192.0.2.x`.

*`host`, IPv6* (value parses with std `Ipv6Addr`; stored as its 128-bit value). Candidate tokens: maximal runs of hex
digits, `:` and `.` containing at least two colons, parsed with std `Ipv6Addr::from_str`; equal 128-bit value is a hit.
So `2001:db8::1`, `2001:0DB8:0:0:0:0:0:1` and `2001:db8::0.0.0.1` all match a stored `2001:db8::1`. A zone suffix
(`%eth0`) ends the token and is ignored.

*`host`, DNS name* (ASCII, lower-case, no trailing dot). ASCII case-insensitive literal, left boundary: not `A`,
`-` or `_`; right boundary: not `A`, `-` or `_` (a `.` is allowed on either side, so `a.nvr-1.example.invalid` and `nvr-1.example.invalid.` both
match; this is deliberately conservative: a sub-domain of a vault host reveals the host). Example, stored
`nvr-1.example.invalid`: found in `NVR-1.Example.INVALID`, `http://nvr-1.example.invalid:8080/`, `nvr-1.example.invalid.`;
not found in `xnvr-1.example.invalid` (left boundary) or `nvr-1.example.invalid-backup` (right boundary), and not for the bare label `nvr-1`.

*`mac`* (value reduces to 12 hex digits; stored lower-case). Tokenised, not expanded: five separators across five positions
would be 3,125 strings, times case, times three group sizes. A candidate is a sequence of hex groups joined by single
separators from `:`, `-`, `.`, `_`, space (any mix), in one of the group shapes 6 x 2, 3 x 4, 2 x 6 or 1 x 12 hex
digits; any six, three, two or one consecutive groups of a longer chain are windows, with the digit run on each side
not adjacent to another hex digit (so a 16-digit EUI-64 is not a 12-digit hit). The 12 digits are lower-cased and looked
up. Example, stored `02:00:5e:00:53:af`: found as `02:00:5e:00:53:af`, `02-00-5E-00-53-AF`, `0200.5e00.53af`,
`02_00_5e_00_53_af`, `02 00 5e 00 53 af`, `02005e0053af`, `0200 5e00 53af` (3 x 4) and the mixed
`02:00-5e.00_53 af`. Not found: `02:00:5e:00:53` (5 groups), `02005e0053af11`
(14 digits), `02:00:5e:00:53:ae` (differs).

*`serial`* (trimmed). Needles: the value as entered and the **compact** form (the characters `-`, `_`, `.` and space
removed), both ASCII case-insensitive, boundary: not `A` on either side; minimum 6 characters of the compact form.
Example, stored `SN-0042-ZQ`: found as `sn-0042-zq`, `SN0042ZQ`, `sn0042zq`, `Serial: SN-0042-ZQ.`; not found as `SN 0042 ZQ`
(a regrouping other than the two forms; see limits), `XSN-0042-ZQ` (boundary).

*`secret` and the password of `credential`* (case-sensitive; minimum 6 bytes). Needles, deduplicated:
1. the raw value;
2. **percent-encoding**: unreserved characters (`A-Z a-z 0-9 - . _ ~`) kept and every other byte as `%XX`, in upper-case and
   in lower-case hex; and the **every-byte** form (`%63%6f...`), upper and lower; and the **form-encoding** variant (space as `+`);
3. **base64**, standard (`+/`) and URL-safe (`-_`) alphabets, **without padding**, at all three alignments. A secret
   inside a larger base64 blob (for example an HTTP Basic `user:secret` header) is encoded at a byte offset the scan does not
   know, so for each `k` in 0, 1, 2 the value is encoded with `k` filler bytes in front, and only the characters
   fully determined by the value are kept: from character `ceil(8k / 6)` up to, not including, character
   `floor(8(k + n) / 6)`, where `n` is the value length in bytes. A needle shorter than 8 characters is dropped (too
   weak). No `=` can appear in a needle. Worked example, value `correct-horse-9` (15 bytes):
   `k=0` encodes to `Y29ycmVjdC1ob3JzZS05` and all 20 characters are kept; `k=1` encodes to
   `AGNvcnJlY3QtaG9yc2UtOQ` and the needle is `NvcnJlY3QtaG9yc2UtO` (characters 2 to 20); `k=2` encodes to
   `AABjb3JyZWN0LWhvcnNlLTk` and the needle is `jb3JyZWN0LWhvcnNlLT` (characters 3 to 21). The dropped characters depend
   on the unknown neighbouring bytes;
4. **lower-case and upper-case hex** of the bytes (log hex dumps);
5. the **JSON-string escape** (`"` as `\"`, `\` as `\\`, control and non-ASCII as `\uXXXX`) and the **XML escape** (`&amp;`,
   `&lt;`, `&gt;`, `&quot;`, `&apos;`) when they differ from the raw value.
No boundary rule: a substring hit on a password is a leak. A secret shorter than 6 bytes is **unscannable** (section 8).
The username of a `credential` is **not scanned** (usernames such as `admin` are generic and would flood every text; a
sensitive username belongs in an `other` entry).

*`display-name`* and *`other`* (whitespace-collapsed: any run of Unicode whitespace in the value, and, in the text views,
any run of spaces, tabs and NBSP, becomes one space; line breaks are kept). ASCII case-insensitive, boundary: not `A`.
Minimum 6 bytes. `display-name` additionally gets the **slug** needles with each space replaced by `-`, by `_`, and
removed. Example, stored `Back Door North`: found in `back   door north`, `BACK DOOR NORTH`, `back-door-north`,
`back_door_north`, `BackDoorNorth`; not found when the name wraps across a line (`Back Door\nNorth`) or as `Door North`.

**Complexity.** Literal needles go into one `aho-corasick` automaton (leftmost-longest is unnecessary; all matches are
checked against the boundary rule). IPv4, IPv6 and MAC use single-pass tokenisers and hash sets. Cost is linear in the
text for a fixed vault. The target of #75 is under 1 s for 1 MB. Text above 8 MiB per file is refused (error, not skipped,
SEC-2).

### 8. Output, exit codes and what the scan cannot catch

- A hit is reported as `entry-id kind location`, where the location is `path:line` (tree, staged) or
  `commit:path:line` (range). **The matched text, the surrounding line, the entry's value and its length are never
  printed** (SEC-6, ERR-5). The report cannot be used to learn a value beyond "this id occurs here".
- Exit codes: `0` no hit; `1` at least one hit; `2` the scan could not run (vault present but key missing, wrong
  permissions, wrong key, corrupt entry, a file over the size cap). **Failing to scan is never a pass.**
- The report also lists `unscannable` entries by id and kind (value below the minimum length, or a base64 alignment
  dropped as too weak), so the gap is visible instead of silent.

**What the scan cannot catch** (residual risk, repeated in section 10):

1. **A value that is not in the vault.** The central gap. An address the owner never entered, a camera added through
   the camera's own web page, a value typed straight into a file. Mitigation: the vault is the only sanctioned way in
   (`import-legacy`, the import command, `vault set`), and the optional shape lint flags candidates for the owner to
   add; it can never prove absence.
2. Values below the minimum length, and generic usernames.
3. Transformations not listed: gzip, encryption, rot13, reversal, base32, base85, a password split over two lines or
   two table cells, a prefix or fragment of a value, IPv4 written with spaces, per-octet hex (`c0.00.02.0a`),
   octal octets, IPv6 embedded MACs (EUI-64 / SLAAC addresses), entity-encoded markup (`&#46;`), double percent-encoding.
4. Lookalike characters: Cyrillic or other homoglyphs, NFD vs NFC forms, transliteration (`ä` to `a`) of display names
   and `other` text.
5. Non-text content: images, screenshots, video thumbnails, compressed archives, binary blobs. A snapshot of a camera
   image can identify a site and no text scan sees it.
6. Derived or contextual information: relationships between values, counts, layout, positions of cameras, timestamps
   of events, a hostname's label alone (`nvr-1`), geo-location.
7. Anything the scan is not run on (section 9).

### 9. Where the scan runs

**Locating the vault and key.** Every surface calls the same command, `wardenlens vault scan`, which resolves the vault
as `WARDENLENS_VAULT` (a path) or the default dev path, and the key as `WARDENLENS_VAULT_KEY_FILE` (a path) or the
default dev key path (section 6). The checks of section 6 apply (outside work trees, 0600, owned). There are four
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
   it is in). It prints `SKIPPED` as above when there is no vault. `GITHUB_ACTIONS=true` means "public CI" (below).
2. **`scripts/agents check PROMPT_FILE`** runs `wardenlens vault scan PROMPT_FILE` and refuses on exit 1 or 2; this
   replaces the RFC1918, ULA, `scheme://user:pass@` and secret-file regexes and the `jq` secret-file loop. When there is
   **no vault**, the existing regex checks stay as a blocking fallback so a machine without a vault is not left with
   nothing; when a vault is present they become non-blocking warnings (the soft lint) and can be removed later.
   `scripts/agents record` calls the same function, because it re-vets the prompt it saves.
3. **Git hooks (human-installed, locked paths `.githooks/**`).** `.githooks/pre-commit` runs `vault scan --staged`
   (the staged blobs, read from the index with `git`, not the working tree, plus the staged file names); `.githooks/pre-push`
   runs `vault scan --range <remote_sha>..<local_sha>` for every updated ref it receives on stdin (a new branch uses
   the range against the remote-tracking refs, as the existing hook does), scanning every commit's added content,
   the commit messages and author lines, the file paths and the ref names: all of it becomes public on push. The hooks
   use a binary installed by the human (`cargo install --locked --path crates/wardenlens-cli`, default
   `$HOME/.cargo/bin/wardenlens`, override `WARDENLENS_BIN`), **not** a build from the working tree, because a hook that
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
  `unscannable` flag, never values. `rm`, `rekey`, `init`, `import-legacy`, `scan` as above.
- **In memory (SEC-6).** `secrecy` `SecretString` and `SecretBox` for values and `Zeroizing` for keys and decrypted
  buffers; `Debug` of every type that can hold a value is redacting (verified in the probe: `SecretString` prints
  `SecretBox<str>([REDACTED])`); `expose_secret` is called at the last moment, in the smallest scope. Errors carry ids and
  kinds only. Core camera types that carry a host or display name (#43) have a redacting `Debug` and `Display` too,
  and logs identify cameras by id, never by host or name (ADR 0004's tracing rules).
- **What zeroisation does not do.** The `aho-corasick` automaton and tokeniser sets built for a scan hold needles in
  ordinary memory and are not zeroed; the scan process is short-lived. `zeroize` is best effort (copies made by the
  allocator or in swap are outside its reach). No core dumps are suppressed (that needs `unsafe` or a libc call, SEC-1).

### 11. New dependencies

Observed 2026-11-23. "Defaults off" is the planned `default-features = false` use. Every licence expression contains
an entry on the `deny.toml` allow list (`MIT` or `Apache-2.0`).

| crate | version | licence | last release | owners (crates.io) | features used | where | deny.toml change |
|---|---|---|---|---|---|---|---|
| chacha20poly1305 | 0.11.0 | Apache-2.0 OR MIT | 2026-08-05 | newpavlov, team rustcrypto:aeads | no defaults; `alloc`, `zeroize` | secrets | no |
| zeroize | 1.9.2 | Apache-2.0 OR MIT | 2026-11-17 | tarcieri, team rustcrypto:utils | defaults | secrets, vault | no |
| secrecy | 0.10.3 | Apache-2.0 OR MIT | 2024-10-09 | tony-iqlusion | defaults (no `serde`) | secrets, vault | no |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | 2026-06-17 | dhardy, team rust-random | defaults | secrets | no |
| aho-corasick | 1.1.5 | Unlicense OR MIT | 2026-08-03 | BurntSushi | no defaults; `std` | vault | no |
| rusqlite | 0.43.0 | MIT | 2026-11-15 | thomcc, gwenn | `bundled` (as planned in #41) | vault, index | no |
| base64 | 0.23.1 | MIT OR Apache-2.0 | 2026-08-04 | alicemaz, marshallpierce | `std` only (already in ADR 0004) | vault | no |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 | 2025-08-21 | SimonSapin, teams servo | defaults | vault | no |
| rpassword | 7.5.5 | Apache-2.0 | 2026-11-10 | conradkleinespel | defaults | cli (no-echo TTY prompt for `set`; candidate only, #74 confirms) | no |

Probe: a scratch project outside the repo (given `license = "MIT"`) with `chacha20poly1305` (no defaults, `alloc`), `secrecy`,
`zeroize`, `aho-corasick` (`std`), `getrandom`, `rusqlite` (`bundled`), `base64` and `percent-encoding` resolved to 36
lines in `cargo tree -e normal` (including the probe itself) and `cargo deny check licenses advisories bans sources`
with the repo's `deny.toml` gave `advisories ok, bans ok, licenses ok, sources ok`; a compiled program sealed a record with
`XChaCha20Poly1305` and AAD, printed a `SecretString` as `SecretBox<str>([REDACTED])` and matched a needle with
`AhoCorasick`. `deny.toml` needs no change. `rpassword` and `percent-encoding` were not in that probe; their
`cargo deny` result is for #74 and #75 to re-run (SEC-8) in their PRs.

Maintenance notes. `secrecy` 0.10.3 was last released 2024-10-09 (single owner) but is a 2-line dependency tree, is
widely used (212 M downloads) and is small enough to replace with an own `Zeroizing<String>` newtype if it stalls.
`rpassword` is single-owner and only a candidate; if #74 rejects it, the no-echo prompt must still come from a crate
and never from shelling out to `stty` (SEC-5), or `set` accepts stdin only. The `chacha20poly1305` audit predates 0.11 (section 2); a new audit or an
advisory is the trigger to re-evaluate, and the version byte makes a migration possible.

## Threat model

Context: a home NVR, one owner, a public repository, AI agents running as the owner's user with shell access, a
service in Docker on the same host.

**Assets.** Camera credentials, cloud tokens and API secrets; LAN addresses and hostnames, MACs and serials (they
identify and locate the site and are the first thing an attacker who learns the network wants); camera display names (they
describe rooms and people); the owner's PII.

**Prevented or substantially reduced**

| leak | how |
|---|---|
| a database or backup leaks | the vault file and every backup hold only XChaCha20-Poly1305 records; the key is a separate file, never in the same backup, never in the repo, never in an environment variable; the recording index holds none of it |
| accidental commit by owner or agent | `pre-commit` and `pre-push` (exact match on every stored value in every listed rendering, commit messages and file names included) and the gate; blocked before the push |
| a value in a prompt to an agent | `scripts/agents check` scans the prompt before dispatch; with the proposed hooks, the owner's own prompt too |
| a value in a log | values are redacting types (`Debug`), the service logs ids not hosts or names, and the scan can be run on log files (`vault scan PATH...`) |
| a value in a tracked doc or the catalogue | gate and the catalogue test scan the tree; the structural checks remain in public CI |
| a camera's credentials in a process list | values never travel on argv (CLI and scripts) |

**Residual risk (not prevented)**

1. **Root or the same user on the host.** The key file and the database sit next to each other for the user who runs
   the service and the agents. Anyone or anything running as that user can read both, so **an agent with shell access
   can run `vault get` or read the key file**: the vault protects against accidents and leaked copies, not against a
   hostile or prompt-injected agent. Recommended and out of scope here: deny rules in the agent settings for the vault
   and key paths and for `vault get`, a Bash guard rule that refuses an agent setting `WARDENLENS_VAULT*`,
   `WARDENLENS_REQUIRE_VAULT` or `XDG_*`/`HOME` for a git command (the same way the guard already treats
   `WARDENLENS_ALLOW_REWRITE`), possibly a separate OS account for agents.
2. **A value that is not in the vault** (section 8, item 1) and the other items of section 8. Shape matching would not
   have caught these reliably either (PR #71); the difference is that the gap is now defined: a value is protected
   if and only if it is in the vault.
3. **Output of `vault get`** reaches whoever runs it. If an agent runs `vault get` in its own shell, the value is in
   its transcript. Scripts must use the value without echoing it; the transcript scan is detective only.
4. **No scan in public CI** (section 9): a bypass of the local hooks, or a contributor without a vault, is not caught.
5. **Already-public history.** A value pushed once cannot be recalled. Rotate what can be rotated; a LAN address
   changed only by renumbering.
6. **Ids are plaintext.** An id derived from a value (`cam:192-0-2-10:host`) defeats the point. The ids of inventory
   cameras (`reolink-1`) are public. Review is the control; `vault set` rejects ids that match the host-IPv4 or MAC
   forms of its own value as a cheap guard.
7. **Heap, swap, core dumps** (section 10).
8. **A weak or short secret** below 6 bytes, and generic usernames, are not scanned.

**Why exact match beats shape match.** A shape rule has to predict every way a secret can be written; PR #71 needed
five rounds and three more were queued in #72, and each round fixed what the previous adversary found, while every fix
added false positives (version strings, resolutions, WS-Discovery multicast, model names). An exact match has a finite
needle set derived from data that exists. Its false-negative classes are enumerable and written down (section 8), and
its false positives are limited to the real values (and the 6-byte minimum). It also removes the guesswork from the
reviewers: "does the text contain a value from the store" is decidable.

## Consequences

- **#48 (`wardenlens-secrets`).** Implements section 2, 3, 6 and 10: `KeyFile::load`/`generate` (exactly 32 bytes,
  O_EXCL, 0600, refuse group/world access and symlinks, owner check), `seal(&key, &EntryId, EntryKind, plaintext) ->
  Vec<u8>` and `open(...)` with the record format of section 3 (the ticket's `seal(&key, camera_id, &Credentials)` is
  **overridden**: the binding is to entry id **and** kind, and plaintext is per kind). `Credentials` stays as the payload
  codec for kind `credential`. Dependencies: `chacha20poly1305` with `alloc` and `zeroize`, `secrecy`, `zeroize`,
  `getrandom`; **no `rusqlite`**. A test asserts that swapping id or kind, a wrong key, truncation and an unknown
  version each give a typed error without secret material.
- **#74 (vault store and CLI).** Creates the new `wardenlens-vault` crate (crate "as decided in ADR 0006") and the
  `vault` subcommands in cli; schema, limits and per-kind validation of sections 1 and 4; seven kinds (adds `secret`);
  refuse paths inside a git work tree; `rekey`; `import-legacy` per section 4; `get` and `set` rules of section 10;
  `list` shows `unscannable`. Blocked by this ADR and #48, and by ADR 0005's SQLite crate choice.
- **#75 (scan).** The `scan` module of the vault crate with the views, per-kind rules, exit codes and report of
  sections 7 and 8, `wardenlens vault scan [--staged | --range A..B | PATH... | -]`, the `scripts/gate` step, the
  `scripts/agents check` replacement with the no-vault regex fallback, and the staged `.githooks/pre-commit` and
  `.githooks/pre-push` for the owner. Tests: every rule's "found" and "not found" example above, the no-print rule, and
  `0 / 1 / 2` exit codes. Proptest (TEST-3) that the matcher finds a value after each listed transformation.
  Overrides the ticket's "vault values in normalised forms" wording with the tokeniser design where it applies.
- **#76 (spikes and docs).** `spikes/s1-cameras/lib.sh` and `spikes/s2-gpu` read through `vault get` with ids; no
  loose files after `import-legacy`; the README and the agent memory notes name ids, not paths; legacy files deleted by
  the owner after a key backup (section 6).
- **#50 (camera registry), overridden.** The `cameras` table has **no `credential_blob`, no `host` and no display-name
  column**: those are vault entries `cam:<id>:credential`, `cam:<id>:host`, `cam:<id>:name`. The table keeps id, model,
  port, main/sub path templates, created and updated. The index depends on core only. The `cli` builds core `Camera`
  values from an index row and the vault entries. The test "the raw DB file contains neither the plaintext password
  nor the username" becomes "the index file contains none of the synthetic host, name or credential values" (a byte
  grep after inserting a camera through the registry); the encrypted-at-rest assertion belongs to #74 (vault file).
  Its "Blocked by #48" becomes "Blocked by #74".
- **#32 (catalogue).** Keeps structural validation and the generated README; the exact-match site-data guarantee is
  the gate's scan plus the cli test of section 9; any shape lint in `wardenlens-core` is optional, warning-only and
  need not close the gaps queued in #72. Its blocker remains #75.
- **Also touched.** #43 (core camera model): a redacting `Debug`/`Display` for host and display name and `EntryId` and
  `EntryKind` in core; #66 (`import agentdvr`): writes credentials, host and name to the service vault, not to the index;
  #69 (Docker): compose `secrets:` for the key, and the permission test of section 6; #72: closed as superseded for
  the site-data classes it lists, except the catalogue's structural items.
- **Older text.** Where this ADR and an older ticket body differ (#48 `camera_id` AAD, #50 `credential_blob`, #74's
  six kinds, #75's "expands every value into forms" for IP and MAC, #76's file names), **this ADR wins** and the
  implementer updates the ticket text in the PR that implements it.
- **Follow-ups to open:** the optional hook and settings surfaces of section 9 and residual risk 1; `scripts/ticket`
  and `scripts/verify` pre-post scan; `vault exec` (inject a value into a child's environment or file descriptor so
  scripts never see it); a transcript-scan routine.
- **Harder.** A new developer machine needs `vault init` and an import before the scan protects it; there is no key
  recovery; the scan adds a step to the gate and hooks that fails closed when the vault is unreadable.
