# 0004. Service architecture, HTTP/OpenAPI stack and API auth

- Status: proposed
- Date: 2026-11-23
- Ticket: #40 (epic #16)

Cameras are referred to by inventory id only (`reolink-1`, `reolink-2`, `xr`, `tapo`, `hdipc`, see ADR 0002).
Examples use only `192.0.2.x` (TEST-NET-1) or `*.invalid`. Crate facts below were observed on 2026-11-23 with
`cargo info <crate>` and the crates.io API (version, licence, `rust-version`, last update, owners, feature lists).
Nothing was written from memory. "Last release" is the crates.io `updated_at` of the crate, which is the date of its
newest published version.

## Context

Phase 1 adds the first I/O crates: camera discovery, RTSP ingest, a recorder, tiered storage, a SQLite index and an
HTTP API. The async runtime, the HTTP/OpenAPI stack, the ONVIF approach, the crate map and the API authentication
model are cross-cutting: every later ticket depends on them (DOC-5, ARCH-2). The `onvif` crate on crates.io is a
0.0.0 placeholder, so ONVIF is hand-rolled. The API is the only network service Wardenlens exposes, so this ADR also
fixes its security boundary.

Constraints: workspace `unsafe_code = "forbid"` and `rust-version = 1.100` (the installed cargo is 1.100.0), the
`deny.toml` licence allow list (`MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, `BSD-3-Clause`,
`ISC`, `Unicode-3.0`, `Zlib`), five cameras, one host, a Docker deployment (epic #16), and a GTX 970 host (ADR 0003).

## Options and decisions

### 1. Async runtime

1. **tokio** (chosen). The ingest crate (`retina`, named in epic #16), axum, hyper and the UDP socket for WS-Discovery
   all run on it; it is the de-facto runtime. Pro: one runtime, no bridging. Con: large feature surface; mitigated by
   enabling only `rt-multi-thread`, `net`, `time`, `sync`, `signal`, `macros` (default features are empty).
2. async-std / smol. Rejected: the HTTP and RTSP crates we want do not target them, so we would run two runtimes.
3. Blocking threads only. Rejected: five long-lived RTSP sessions, reconnect timers and an HTTP server are I/O-bound
   fan-out where async is the clearer model.

`wardenlens-core` stays synchronous and runtime-free (ARCH-1). Core traits may use `async fn` in traits (no runtime
dependency) and are used through generics, not `dyn`.

### 2. HTTP framework

1. **axum 0.8** (chosen; 0.8.9, MIT, tokio-rs). Pro: thin layer over hyper and tower, extractors, same org as tokio
   and tracing, and `utoipa-axum 0.3.0` requires `axum ^0.8.4` (checked in its crates.io dependency list). Con: pre-1.0,
   so minor bumps may break; pin `0.8` and bump deliberately.
2. actix-web. Rejected: its own runtime and ecosystem, a poorer fit with tokio-based `retina`/`hyper-util`.
3. warp / poem / rocket. Rejected: smaller or older ecosystems and no better OpenAPI integration than axum.

Features: `default-features = false` with `http1`, `json`, `query`, `tokio`. The defaults add `form`, `matched-path`,
`original-uri`, `tower-log`, `tracing`; none is needed. HTTP/2 is not enabled: a LAN API for a handful of clients
gains nothing from it, and it removes `h2`.

### 3. OpenAPI generator

1. **utoipa 6 + utoipa-axum 0.3** (chosen). The spec is derived from the same handler and type definitions that
   serve requests (`#[utoipa::path]` and `OpenApiRouter`), so the spec cannot silently drift. Both 6.0.0 and 0.3.0
   were released 2026-09-22 by the same maintainer (`juhaku`, a single owner, see Risks).
2. aide. Rejected: the stable release is 0.15.1 (2025-08-19) targeting axum 0.8.1 via `axum-extra ^0.10`; all
   releases since are alphas (`0.16.0-alpha.4`, 2026-04-14). Building on an alpha for the public contract is worse than
   a single-maintainer stable crate. It has four owners, which is its strength; revisit if utoipa stalls.
3. Hand-written spec. Rejected: guaranteed drift between the YAML/JSON and the handlers; no compile-time link.

Rules: `utoipa` is used with `default-features = false, features = ["macros"]` (the default is already `macros`; the
explicit form documents intent and avoids enabling extra integrations such as `chrono`, `uuid`, `yaml`). The API
crate exposes `openapi()`; a test serialises it and compares it with a committed `docs/openapi.json` so spec changes
are visible in review (follow-up ticket). The spec declares one `bearerAuth` security scheme. The spec itself is
served only to authenticated clients (see section 9).

### 4. CLI parser

**clap 4** (chosen; 4.6.9, `derive`). Pro: standard, maintained by the rust-cli org, derive API gives typed args and
generated help; the default features (`std`, `color`, `help`, `usage`, `error-context`, `suggestions`) are kept
because they are the CLI user experience (clap 4 has no heavy defaults). Rejected: `argh` and `lexopt` (smaller but
thinner help and subcommand ergonomics; the binary size is not a constraint on this host), hand parsing (SEC-2:
untrusted args deserve a real parser). Only the `cli` crate depends on clap.

### 5. Logging

**tracing** (libraries emit events and spans) + **tracing-subscriber** (only in the `cli` crate; features `fmt`,
`env-filter`, `std`; the `ansi`, `tracing-log`, `smallvec` defaults are dropped, `json` can be added when a log
collector exists). Pro: structured, async-aware, and axum/hyper-util already emit `tracing`. Rejected: `log` +
`env_logger` (no spans, so request and per-camera context is awkward). SEC-6 applies: spans use `skip_all` unless
fields are named explicitly, secrets are redacting newtypes (ADR 0006), and the API logs the token id, never the token.
Output goes to stderr through the subscriber (`print_stdout`/`print_stderr` lints stay on).

### 6. Errors

**thiserror 2** in library crates (ERR-2) and **anyhow 1** only in `wardenlens-cli` (ERR-3). Each library defines its
own error enum; crates never expose another crate's error type in a public signature unless wrapped with `#[source]`.
Messages follow ERR-5. `wardenlens-core` may depend on `thiserror` (a proc-macro crate with no I/O); this is the
only external dependency allowed in core (see Crate map). Rejected: `anyhow` in libraries (callers cannot match),
`eyre`/`snafu` (no gain over the two chosen crates, a third idiom).

### 7. ONVIF approach (hand-rolled)

1. **quick-xml + hyper-util client + sha1/base64** (chosen).
   - Transport: `hyper-util` legacy client (`client-legacy`, `http1`, `tokio`) with `http-body-util`; plain HTTP
     only. ADR 0002 measured ONVIF on plain HTTP ports (tapo 2020, hdipc 1018, reolink 8000). `hyper` and `hyper-util`
     are already in the tree via axum, so this adds only `http-body-util` and the `client-legacy` feature (probe
     below: 119 crates in the full set).
   - Parsing and writing: `quick-xml` 0.42 (no default features; `serialize` is not enabled, the SOAP bodies we need
     are a handful of fixed requests, `GetCapabilities`, `GetProfiles`, `GetStreamUri`, PullPoint, built from string
     templates with escaped values and read with the event reader). quick-xml does not expand custom entities, which
     limits entity-expansion attacks from a hostile device; we additionally cap response size (1 MiB), element depth
     (64) and each request with a timeout (SEC-2/3).
   - Authentication: WS-Security UsernameToken digest, `Base64(SHA1(nonce + created + password))`, with a 16-byte
     nonce from `getrandom`. SHA-1 is required by the WS-Security profile the cameras implement; it is used only to
     answer that challenge, never for a local security decision (SEC-7: audited RustCrypto `sha1` and `base64`,
     nothing hand-rolled). `base64` is used with `default-features = false, features = ["std"]` to drop the
     `simd-unsafe` default.
   - Discovery: WS-Discovery `Probe` multicast to `239.255.255.250:3702` using `tokio::net::UdpSocket` and
     `join_multicast_v4`; replies parsed with quick-xml, deduplicated by endpoint reference, capped at 64 replies and
     a 4 s window. Discovered addresses are suggestions that an operator confirms; they are never trusted blindly.
   - Camera quirks (ADR 0002): hdipc ONVIF is flaky, so every ONVIF call has a timeout and bounded retries, and ONVIF
     failure degrades a camera, it never blocks the RTSP video path.
2. `reqwest` without default features. Rejected: it works (0.13.5, MIT OR Apache-2.0, seanmonstar), but resolving it
   next to the chosen set raised the unique-crate count of a probe project from 119 to 163 (44 more, including the
   `url`/`idna`/ICU chain) for features we do not use (redirects, cookies, proxies, URL handling). We talk to five
   known hosts. Revisit if an ONVIF device needs HTTPS: that needs a TLS client and a provider, which is a new
   dependency decision and a `deny.toml` review of its licences.
3. A generic SOAP crate or the `onvif` crate. Rejected: `onvif` is a 0.0.0 placeholder; the SOAP crates that exist
   are unmaintained generators for WSDL we do not need.

### 8. Crate map and dependency direction

All crates are named `wardenlens-<name>` and live under `crates/` (ARCH-2). Direction: arrows point to what a crate
depends on. **`core` depends on no workspace crate**, `cli` depends on everything, and adapters never depend on each
other except `recorder -> mp4`.

| crate | responsibility (one line) | depends on (workspace) |
|---|---|---|
| core | Pure domain types, errors, policy and the traits (ports) for store, clock, sinks; no I/O | none |
| secrets | Encryption at rest and redacting wrappers for camera credentials (ADR 0006) | core |
| index | SQLite implementation of the core stores (cameras, recordings, tokens) | core |
| agentdvr | Parses an AgentDVR export into camera drafts; no network, no storage | core |
| onvif | ONVIF client and WS-Discovery (this ADR, section 7) | core |
| ingest | RTSP ingest with reconnect; emits timestamped frames in core types | core |
| mp4 | Passthrough fragmented-MP4 muxing, bytes in and bytes out (ADR 0005) | core |
| recorder | Per-camera loop turning frames into segments via core traits | core, mp4 |
| storage | Volumes, hot-to-archive mover, per-volume free-space floor, file I/O | core |
| api | axum routes, OpenAPI, token authentication; talks to core traits only | core |
| cli | Binary `wardenlens`: config, wiring, runtime, logging, `token` subcommands | all of the above |

```
          cli  (composition root: anyhow, clap, tracing-subscriber, tokio::main)
   ┌───┬───┬──┴──┬────────┬───────┬────────┬─────────┬─────┬─────┐
 api  index secrets agentdvr onvif ingest recorder storage  (mp4 via recorder)
   └───┴───┴─────┴────────┴───────┴────────┴────┬────┴─────┘
                                                 core   (depends on nothing)
```

Rules: `api` does not depend on `index`, `storage` or `recorder`; it receives them as core trait objects or
generics from `cli`, so handlers are testable with in-memory fakes (ARCH-3). `ingest` and `recorder` meet only through
core types, so neither depends on the other. Crates are created by the ticket that first needs them, not up front, and
the map is enforced by review of each crate's `Cargo.toml` (a mechanical check is a follow-up). Choice of `retina`,
`rusqlite`, an MP4 crate and the encryption crate belong to the tickets/ADRs 0005 and 0006 and are not decided here.

### 9. API authentication

**Threat model (LAN API).**

- Who is on the LAN: the household (laptops, phones), guests if they share the Wi-Fi, IoT devices, and the five
  cameras themselves, which are cheap SoCs running vendor firmware (ADR 0002) and should be treated as potentially
  compromised. A compromised laptop or a malicious web page loaded in a household browser can also send requests to
  LAN addresses, including DNS-rebinding and cross-site requests. The Wardenlens host is not reachable from the
  internet; no port forwarding is part of this design.
- What a token protects: read access to recordings (video of the inside and outside of the home), the camera list and
  storage state; with the `admin` role also camera registry changes and recording deletion. The API never returns camera
  credentials (SEC-6); a stolen token therefore reveals footage and metadata, not camera passwords.
- What plain HTTP exposes: anyone who can observe or alter LAN traffic (ARP spoofing, a compromised device on the same
  segment, Wi-Fi with a shared key) can read the video and the metadata in transit and replay the bearer token, and
  can modify responses. It does not expose camera credentials, which are never sent by the API.
- Why that is acceptable here: the same attackers can already read the plaintext RTSP streams from the cameras on the same
  LAN (ADR 0002 measured RTSP and ONVIF on plain ports), so plain HTTP between the NVR and a client adds no new
  confidentiality exposure beyond what the cameras already have; the stronger boundary is that the API is bound to
  loopback or a private LAN address only, never a public one. It would **not** be acceptable on a routed or public
  network, so remote access must go through a VPN or a TLS-terminating reverse proxy chosen by the operator.
- Browser attacks: the token is carried in an `Authorization` header, which browsers do not attach automatically, so
  cross-site requests and DNS rebinding get `401` without a token; no CORS headers are emitted (cross-origin
  browser use is out of scope for v1) and cookies are not used.
- Out of scope: an attacker with root on the NVR host (they hold the database and the secrets key anyway) and
  physical access.

**Decision: plain HTTP bound to loopback or a private address, with bearer tokens; no TLS in v1.**

Alternatives rejected for v1:
- In-process TLS with `rustls` (observed: stable 0.23.46 on 2026-11-12; `cargo info` reports 0.24.0-dev.3 as the newest
  line). Rejected for v1 because a certificate for a bare LAN IP has no public CA, the operator would have to install
  a private CA on every client (or click through warnings, which trains users to ignore them), and a crypto
  provider choice (`aws-lc-rs` needs a C toolchain, `ring`) must be reviewed against SEC-8 and ADR 0003's image.
  This is an explicit, recorded deferral, not an oversight: a follow-up ticket should add optional rustls or document
  the reverse-proxy recipe, and the bearer scheme does not change when TLS is added.
- No authentication on the LAN. Rejected: guests and compromised IoT devices are on the LAN.
- HTTP Basic or a shared password. Rejected: low-entropy, one credential for all clients, no per-client revocation.
- mTLS. Rejected: needs the same CA machinery as TLS.

**Bind address (LAN-only).** The default bind is `127.0.0.1:<port>` (loopback). To serve the LAN the operator sets an
explicit address. At startup the server **refuses** an address that is not loopback, RFC 1918 private, link-local or
IPv6 unique-local (`fc00::/7`). The unspecified addresses `0.0.0.0` and `::` are refused unless the operator also
sets `api.allow_unspecified_bind = true`, which exists for containers (inside Docker the process must listen on all
container interfaces; the compose file then publishes the port to one host LAN address, for example
`192.0.2.10:<port>`). The check is a pure function in `core`/`api`, unit tested with `192.0.2.x`, `10.x`, loopback and a
global address (which must be refused).

**Token format.** `wl_<id>_<secret>` where `<id>` is 8 random characters (lowercase base32, public; used for lookup,
logging and revocation) and `<secret>` is 32 random bytes from the operating system CSPRNG (`getrandom::fill`) encoded
as unpadded base64url, 43 characters, 256 bits. The `wl_` prefix lets secret scanners and humans recognise it.
Example shape (fake): `wl_abcdefgh_` followed by 43 characters.

**Generation and storage.** Tokens are created only locally by the operator with `wardenlens token create --name
<label> --role read|admin`, which prints the token **once** on stdout and stores
`{id, name, role, sha256(secret), created_at, last_used_at, revoked}` in the SQLite index (the `TokenStore` trait lives
in core). The plaintext token is never stored or logged. Because the secret has 256 bits of entropy, a fast hash
(SHA-256, RustCrypto `sha2`) is sufficient: there is nothing to brute-force, so a slow password hash (argon2) would only
cost CPU on every request. A copy of the database therefore cannot be turned into a working token, and the token store
does not need ADR 0006 encryption. Rotation is create-then-revoke; `wardenlens token revoke <id>` and `list` complete
the CLI. There is no API endpoint to mint tokens in v1 (a stolen admin token must not be able to mint more).

**Verification.** Clients send `Authorization: Bearer <token>`. The server rejects a header longer than 128 bytes before
parsing (SEC-2), parses `wl_<id>_<secret>`, loads the row by `<id>`, computes `sha256(secret)` and compares the 32-byte
digests with `subtle::ConstantTimeEq`. When the id is unknown or the token is revoked, the same hash and comparison run
against a fixed dummy digest so the response time does not reveal which ids exist. Every failure returns the same
`401` with `WWW-Authenticate: Bearer` and an empty-detail body; the log line records the peer address and, when
parsed, the token id. A `read` token is rejected with `403` on mutating routes. `last_used_at` is updated at most
once per minute per token to avoid write amplification.

**Unauthenticated endpoints.** Only `GET /healthz` (liveness: `200` with `ok`, no version, no camera data). Everything
else, including `GET /api/v1/openapi.json`, requires a valid token: the spec lists the full surface and is not
a secret worth publishing to every device on the LAN. Request bodies are capped (default 1 MiB), requests have a
timeout, and the number of concurrent connections is bounded, so an unauthenticated client cannot exhaust the host.

### 10. New dependencies

Observed 2026-11-23. "Defaults off" is the planned `default-features = false` use. The `cargo info` licence is the
SPDX expression; every one of them contains an entry that is in the `deny.toml` allow list (`OR` expressions only need
one allowed branch; `subtle` is `BSD-3-Clause`, `tokio`/`axum`/`quick-xml`/`hyper`/`hyper-util`/`http-body-util`/`tracing`/
`tracing-subscriber` are `MIT`). Maintainers are the crates.io owners.

| crate | version | licence | last release | owners (crates.io) | defaults off? (features used) | deny.toml change |
|---|---|---|---|---|---|---|
| tokio | 1.54.1 | MIT | 2026-10-21 | carllerche, Darksonn, tokio-rs core team | yes (`rt-multi-thread`, `net`, `time`, `sync`, `signal`, `macros`; default is empty) | no |
| axum | 0.8.9 | MIT | 2026-04-14 | carllerche, davidpdrsn, tokio-rs teams | yes (`http1`, `json`, `query`, `tokio`) | no |
| hyper | 1.12.0 | MIT | 2026-10-06 | seanmonstar, hyperium core team | yes (`client`, `http1`; via axum and hyper-util) | no |
| hyper-util | 0.1.21 | MIT | 2026-09-24 | seanmonstar | yes (`client-legacy`, `http1`, `tokio`; default is empty) | no |
| http-body-util | 0.1.5 | MIT | 2026-08-12 | seanmonstar | n/a (no features needed) | no |
| utoipa | 6.0.0 | MIT OR Apache-2.0 | 2026-09-22 | juhaku | yes (`macros` only) | no |
| utoipa-axum | 0.3.0 | MIT OR Apache-2.0 | 2026-09-22 | juhaku | n/a (only feature is `debug`) | no |
| clap | 4.6.9 | MIT OR Apache-2.0 | 2026-11-20 | kbknapp, rust-cli maintainers, clap-rs admins | no: defaults kept, plus `derive` | no |
| tracing | 0.1.44 | MIT | 2025-12-18 | carllerche, hawkw, tokio-rs publish team | no: defaults kept (`std`, `attributes`) | no |
| tracing-subscriber | 0.3.23 | MIT | 2026-03-13 | hawkw, davidbarsky, tokio-rs publish team | yes (`fmt`, `env-filter`, `std`) | no |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | 2026-09-23 | dtolnay | no features | no |
| anyhow | 1.0.104 | MIT OR Apache-2.0 | 2026-07-18 | dtolnay | defaults kept (`std`); binary only | no |
| quick-xml | 0.42.0 | MIT | 2026-08-22 | tafia, Mingun, dralley | yes (default is empty; none enabled) | no |
| sha1 | 0.11.0 | MIT OR Apache-2.0 | 2026-07-10 | tarcieri, newpavlov, RustCrypto hashes team | yes (drops `oid`; `alloc` not needed) | no |
| sha2 | 0.11.1 | MIT OR Apache-2.0 | 2026-10-12 | tarcieri, newpavlov, RustCrypto hashes team | yes (drops `oid`) | no |
| base64 | 0.23.1 | MIT OR Apache-2.0 | 2026-08-04 | alicemaz, marshallpierce | yes (`std` only; drops `simd-unsafe`) | no |
| subtle | 2.6.1 | BSD-3-Clause | 2024-06-24 | isislovecruft, dalek-cryptography subtle maintainers | no features | no |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | 2026-06-17 | dhardy, rust-random maintainers | defaults (none) | no |
| serde | 1.0.229 | MIT OR Apache-2.0 | 2026-07-18 | dtolnay, serde-rs publish team | yes (`derive` and `std`) | no |
| serde_json | 1.0.154 | MIT OR Apache-2.0 | 2026-10-11 | dtolnay, serde-rs publish team | defaults kept (`std`) | no |

Maintenance notes. All crates other than `subtle` released in 2026. `subtle` (2.6.1, 2024-06-24) is stable and
feature-complete, a tiny constant-time primitive used by the dalek and RustCrypto ecosystems; its age is not a concern,
but a vulnerability report would be the trigger to re-evaluate (alternative: `constant_time_eq`, or comparing in
`sha2`-derived `digest` types). `sha1`/`sha2` are only RustCrypto-owned; `sha1` appears only because of ONVIF.
`utoipa`/`utoipa-axum` have a single owner (bus factor 1); mitigated by the committed `docs/openapi.json` snapshot,
which keeps the contract if the generator must be swapped. `quick-xml` 0.x may break minor to minor; pin `0.42`.

**Licence and deny.toml check (executed).** In a scratch project (outside the repo) the exact set above was resolved
(119 packages in `cargo tree`) with the repo's `deny.toml` and `cargo deny check licenses advisories bans` was run:
`advisories ok`, `bans ok`. The licence check reported a failure for one package only, the scratch project
itself (it had no licence field; workspace crates are `publish = false`, which `private.ignore = true` exempts). Every
third-party crate in the resolved tree is covered by the existing allow list, so **`deny.toml` needs no change**.
`bans.multiple-versions = "warn"` produced no deny failure. The actual dependencies are added by the tickets that use
them, each of which re-runs `scripts/gate` (cargo-deny).

## Consequences

- Easier: one runtime and one HTTP stack for server and ONVIF client; the OpenAPI spec is generated from code;
  every library has a typed error and one logging facade; the auth scheme is small and independent of the transport,
  so TLS can be added later without changing clients.
- Harder / accepted risks:
  - Plain HTTP on the LAN: a LAN eavesdropper or ARP spoofer sees video and tokens and can replay a token (residual
    risk, equal to the existing plaintext RTSP exposure, not acceptable beyond a private network). Mitigation: private-address bind check, short
    lifetime by rotation, revocation, per-token roles.
  - A stolen token stays valid until revoked (no expiry in v1; add optional expiry later).
  - axum 0.8, utoipa 6, quick-xml 0.42 and utoipa-axum 0.3 are pre-1.0 or fresh majors; bumps need care.
  - ONVIF by hand is more code to test; mitigated by recorded real-device fixtures (ADR 0002 spike data) and fuzz-style
    tests for the XML reader.
  - No HTTPS ONVIF: a camera that requires it forces a new TLS-client decision.
- To do (follow-up tickets, not part of this ADR): optional rustls or reverse-proxy documentation; OpenAPI snapshot test;
  a mechanical check of the crate dependency direction; token expiry; `wardenlens token` subcommands and the
  `TokenStore` in the index; the bind-address validation function.
