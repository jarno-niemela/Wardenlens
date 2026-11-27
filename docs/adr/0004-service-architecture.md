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

`wardenlens-core` stays synchronous and runtime-free (ARCH-1). Core traits that do I/O in their implementations are
written `fn name(&self, ...) -> impl Future<Output = Result<..>> + Send` (not `async fn`, so the `Send` bound that
tokio's multi-thread runtime needs is explicit) and are consumed through generics, never `dyn`. This is the single
convention for every core trait, including `TokenStore`.

### 2. HTTP framework

1. **axum 0.8** (chosen; 0.8.9, MIT, tokio-rs). Pro: thin layer over hyper and tower, extractors, same org as tokio
   and tracing, and `utoipa-axum 0.3.0` requires `axum ^0.8.4` (checked in its crates.io dependency list). Con: pre-1.0,
   so minor bumps may break; pin `0.8` and bump deliberately.
2. actix-web. Rejected: its own runtime and ecosystem, a poorer fit with tokio-based `retina`/`hyper-util`.
3. warp / poem / rocket. Rejected: smaller or older ecosystems and no better OpenAPI integration than axum.

Features: `default-features = false` with `http1`, `json`, `query`, `tokio`. The defaults add `form`, `matched-path`,
`original-uri`, `tower-log`, `tracing`; none is needed. HTTP/2 is not used: a LAN API for a handful of clients gains
nothing from it. Note that serving uses `hyper_util::server::conn::auto::Builder` (section 9, limits), whose cargo
feature `server-auto` is defined as `[server, http1, http2]`, so the `h2` crate is still compiled (the scratch probe
shows `h2 v0.4.20` in the tree); the builder is switched to `http1_only()` at runtime, so HTTP/2 is never negotiated.
The framework serves the router; it does not own the accept loop (`axum::serve` is not used).

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
`env-filter`, `json`, `std`; the `ansi`, `tracing-log`, `smallvec` defaults are dropped). The `json` feature is kept:
`wardenlens-cli` offers `--log-format` (`json` or `text`) (#64). Pro: structured, async-aware, and axum/hyper-util already emit `tracing`. Rejected: `log` +
`env_logger` (no spans, so request and per-camera context is awkward). SEC-6 applies: spans use `skip_all` unless
fields are named explicitly, secrets are redacting newtypes (ADR 0006), and the API logs the token id, never the token.
Output goes to stderr through the subscriber (`print_stdout`/`print_stderr` lints stay on).

### 6. Errors

**thiserror 2** in library crates (ERR-2) and **anyhow 1** only in `wardenlens-cli` (ERR-3). Each library defines its
own error enum; crates never expose another crate's error type in a public signature unless wrapped with `#[source]`.
Messages follow ERR-5. `wardenlens-core` may depend on exactly five external crates, all pure parsing, derive or
wrapper crates with no I/O: `thiserror`, `serde` (derive only), `toml` (parse only, features `parse`, `serde`, `std`; the
`display` writer and the `unbounded` feature are not enabled) and, added by ADR 0006, `secrecy` and `zeroize`. #32 (camera catalogue) will parse TOML in core and #47
(service config) does the same for `wardenlens.toml`, so this keeps that parsing in the functional core (ARCH-1).
Nothing else (no async, no network, no filesystem crate) enters core as a normal dependency; the restriction does not
apply to `[dev-dependencies]`, which are unrestricted (test helpers never ship). Rejected: `anyhow` in libraries (callers cannot match),
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
   - Discovery: WS-Discovery `Probe` multicast to `239.255.255.250:3702` using `tokio::net::UdpSocket` (opened with
     `socket2` to pick the outgoing interface with `IP_MULTICAST_IF`; no group is joined, because replies are unicast) (multicast does not cross Docker's default bridge network, so in a container discovery needs
     `network_mode: host`; see the bind address rules in section 9); replies parsed with quick-xml, deduplicated by endpoint reference, capped at 64 replies and
     a 4 s default window (a caller may raise it to at most 10 s), and only plain `http://` XAddrs are kept (`https://`
     ones are dropped, because this client has no TLS). Discovered addresses are suggestions that an operator confirms;
     they are never trusted blindly (#53).
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
| core | Pure domain types, errors, policy, config parsing and the traits (ports) for stores (including `TokenStore`), clock, sinks; no I/O | none |
| secrets | Encryption at rest and redacting wrappers for camera credentials (ADR 0006) | core |
| index | SQLite implementation of the core stores (cameras, recordings, and `TokenStore`) | core |
| agentdvr | Parses an AgentDVR export into camera drafts; no network, no storage | core |
| onvif | ONVIF client and WS-Discovery (this ADR, section 7) | core |
| ingest | RTSP ingest with reconnect; emits timestamped frames in core types | core |
| mp4 | Passthrough fragmented-MP4 muxing, bytes in and bytes out (ADR 0005) | core |
| recorder | Per-camera loop turning frames into segments via core traits | core, mp4 |
| storage | Volumes, hot-to-archive mover, per-volume free-space floor, file I/O | core |
| api | axum routes, OpenAPI, token authentication; talks to core traits only | core |
| cli | Binary `wardenlens`: config loading, wiring, runtime, logging, `token create`, `list`, `revoke` (#65) | all of the above |

```
          cli  (composition root: anyhow, clap, tracing-subscriber, tokio::main)
   ┌───┬───┬──┴──┬────────┬───────┬────────┬─────────┬─────┬─────┐
 api  index secrets agentdvr onvif ingest recorder storage  (mp4 via recorder)
   └───┴───┴─────┴────────┴───────┴────────┴────┬────┴─────┘
                                                 core   (depends on nothing)
```

Rules: `api` does not depend on `index`, `storage` or `recorder`; it receives them from `cli` as generics, never `dyn`, so handlers are testable with in-memory fakes (ARCH-3). `ingest` and `recorder` meet only through
core types, so neither depends on the other. Crates are created by the ticket that first needs them, not up front, and
the map is enforced by review of each crate's `Cargo.toml` (a mechanical check is a follow-up). Choice of `retina`,
`rusqlite`, an MP4 crate and the encryption crate belong to the tickets/ADRs 0005 and 0006 and are not decided here.
ADR 0006 (proposed) decides the encryption crate and adds a `vault` crate (depends on core and secrets; only `cli` depends on it)
and narrows `secrets` to key handling and seal/open; `index` never depends on `vault` or `secrets`.

### 9. API authentication

**Threat model (LAN API).**

- Who is on the LAN: the household (laptops, phones), guests if they share the Wi-Fi, IoT devices, and the five
  cameras themselves, which are cheap SoCs running vendor firmware (ADR 0002) and should be treated as potentially
  compromised. A compromised laptop or a malicious web page loaded in a household browser can also send requests to
  LAN addresses, including DNS-rebinding and cross-site requests. The Wardenlens host is not reachable from the
  internet; no port forwarding is part of this design.
- What a token protects: read access to recordings (video of the inside and outside of the home), the camera list and
  storage state. Phase 1 has no mutating API routes (Phase 1 only reads cameras, recordings and storage), so in v1 a
  token confers read access and nothing else. The API never returns camera credentials (SEC-6); a stolen token therefore
  reveals footage and metadata, not camera passwords. Stream paths in responses are structurally
  redacted: in the query every `name=value` value (up to the next `&`) becomes `***`, and in the path part the rest of
  a `/` segment after an `=` becomes `***`, because a path's credential-name list can never be complete
  (`RtspPath::redacted_for_display`, #61).
- What plain HTTP exposes: anyone who can observe or alter LAN traffic (ARP spoofing, a compromised device on the same
  segment, Wi-Fi with a shared key) can read the video and the metadata in transit and replay the bearer token, and
  can modify responses. It does not expose camera credentials, which are never sent by the API.
- Integrity and replay residual risk: a bearer token captured from the wire is valid until revoked, so the attacker can
  replay it and read **historic** recordings, not only live footage, and an active attacker can alter a response in
  transit (for example hide an event from a viewer). This is **accepted** for v1 on a private LAN because the attacker
  must already be on the LAN, the cameras' own streams are equally exposed there, and the owner can revoke the token
  (`wardenlens token revoke <id>`) and rotate it. It is not accepted off the LAN.
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

**Bind address (LAN-only).** The default listen address is `127.0.0.1:<port>` (loopback). To serve the LAN the operator
sets an explicit address (config key `api.listen`; the rules are implemented by #47). At startup the server classifies
the address and **refuses** anything that is not in the allowed set:

- allowed: loopback (`127.0.0.0/8`, `::1`), RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`), IPv6 unique-local
  (`fc00::/7`) and link-local (`169.254/16`, `fe80::/10`, including addresses with a scope id such as `%eth0`, whose
  scope is ignored for classification);
- CGNAT `100.64.0.0/10` is refused unless a **second explicit opt-in**, `api.allow_cgnat_bind = true`, is set. VPN
  overlays such as Tailscale use this range, but ISP carrier-grade NAT space is shared with other subscribers, so it
  must not be accepted by default;
- IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is classified by its IPv4 form, so `::ffff:` plus a public IPv4 is refused;
- refused: TEST-NET-1 `192.0.2.0/24` (documentation space; it must never be a working config, which is also why the
  examples in this repository use it) and every other non-private address, global unicast and multicast included;
- the unspecified addresses `0.0.0.0`, `::` and `::ffff:0.0.0.0` are refused unless the operator also sets
  `api.allow_unspecified_bind = true`. That key exists for containers: on Docker's default bridge network the process
  must listen on all container interfaces and the compose file publishes the port to one host LAN address. WS-Discovery
  (section 7) does not work from the bridge network; if compose uses `network_mode: host` for discovery, the API must
  instead listen on a specific host LAN address and `allow_unspecified_bind` must stay `false` (#69 documents this in
  `docs/deploy.md`).

The check is a pure function in core (config validation), unit tested for each class above, including the
TEST-NET-1 rejection, CGNAT with and without `allow_cgnat_bind`, IPv4-mapped IPv6 (including `::ffff:0.0.0.0` as
unspecified) and a scoped link-local address.

**Token format.** `wl_<id>_<secret>`. `<id>` is 8 characters of lowercase base32 (alphabet `a-z2-7`, so it can never
contain `_`), random, public; used for lookup, logging and revocation. `<secret>` is 32 bytes from the operating system
CSPRNG (`getrandom::fill`) encoded as unpadded base64url, exactly 43 characters, which decodes to exactly 32 bytes (256
bits). The base64url alphabet contains `_`, so a parser must not split on every underscore: it uses `splitn(3, '_')`
(prefix, id, remainder) and then validates the remainder as the secret; anything not exactly this shape is rejected
(wrong prefix, id length or alphabet, secret length, non-canonical base64, trailing data). The `wl_` prefix lets secret
scanners and humans recognise it. Example shape (fake): `wl_abcdefgh_` followed by 43 characters.

**One token codec.** A single module, `wardenlens-api::token`, generates tokens, encodes and parses them, computes the
SHA-256 digest and performs the constant-time comparison (including the dummy-digest path). The cli (#65) reuses that
module for `token create`; no other crate hashes or compares tokens, so the format and the verification logic have
exactly one implementation. Core's `TokenStore` is **plain data access** and knows nothing about hashing:
`find(&TokenId) -> Option<TokenRecord { digest: [u8; 32], revoked }>` and nothing else (the API's verifier depends on
this lookup only). Token management is a second core trait, `TokenAdmin`: `insert`, `list`, `revoke` and
`touch_last_used`. The index implements both with SQL only.

**Generation and storage.** Tokens are created only locally by the operator with `wardenlens token create --name
<label>` (#65), which prints the token **once** on stdout. The index stores `{id, name, digest = sha256(decoded secret
bytes), created_at, last_used_at, revoked}`. The `id` column is `UNIQUE`; `token create` regenerates the id on a
collision, and a revoked id is never reused. There is **no role column in v1**: Phase 1 has no mutating API routes, so a
role would protect nothing (CHG-3). Roles are introduced together with the first mutating route (a scheme change at that
point means a schema change, accepted). The `TokenStore` and `TokenAdmin` traits are defined in **core**, the index crate implements them
and the api crate consumes it through generics (see section 1), so api never depends on index. The plaintext token is
never stored or logged. Because the secret has 256 bits of entropy, a fast hash (SHA-256, RustCrypto `sha2`) is
sufficient: there is nothing to brute-force, so a slow password hash (argon2) would only cost CPU on every request. A
copy of the database therefore cannot be turned into a working token, and the token store does not need ADR 0006
encryption. Rotation is create-then-revoke. `token list` shows ids and names, never secrets; `token revoke <id>` sets
`revoked` and keeps the row (audit trail). There is no API endpoint to mint tokens in v1 (a stolen token must not be
able to mint more).

**Verification.** Clients send `Authorization: Bearer <token>`. The server rejects a header longer than 128 bytes before
parsing (SEC-2), parses `wl_<id>_<secret>` as above, calls `TokenStore::find(&id)`, decodes the secret, computes
`sha256(secret bytes)` and compares the 32-byte digests with `subtle::ConstantTimeEq`. When the id is unknown or the
token is revoked, the same hash and comparison run against a fixed dummy digest so the response time does not reveal
which ids exist. Every failure returns the same `401` with `WWW-Authenticate: Bearer` and an empty-detail body; the log
line records the peer address and, when parsed, the token id. `last_used_at` is updated at most once per minute per
token to avoid write amplification.

**Unauthenticated endpoints.** Only `GET /api/v1/health` (#60): `200` with the body `{"status":"ok"}`. There is no
version, build or camera data in it. The compose healthcheck (#69) calls it through a `wardenlens health` subcommand
(a small probe added by #69), so the image does not need `curl`. Everything else, including
`GET /api/v1/openapi.json`, requires a valid token: the spec lists the full surface and is not a secret worth publishing
to every device on the LAN.

**Serving and resource limits.** Limits are split between two tickets, and each is a specific mechanism that is not
described as more than it is.

*Connection level, owned by #68 (`wardenlens serve` in the cli).* The API is served from a **hand-written
hyper-util accept loop, not `axum::serve`**: `hyper_util::server::conn::auto::Builder` restricted to HTTP/1 (`http1_only`),
with `.timer(hyper_util::rt::TokioTimer::new())` (without a timer, hyper's timeouts do not run), a
`header_read_timeout` of 10 s, an idle keep-alive timeout, and graceful shutdown (`server-graceful`). A
`tokio::sync::Semaphore` of **256 permits** is acquired per connection before it is served and released when the
connection closes, so the number of open connections is capped, which `ConcurrencyLimit` cannot do. At startup the soft
`RLIMIT_NOFILE` is raised to the hard limit and compose sets `ulimits.nofile` (#69), so 256 API connections plus
recording files and camera sockets do not exhaust descriptors. (Raising the limit without `unsafe`, which is forbidden,
needs a safe wrapper crate; #68 picks it and runs `cargo deny`; it is not decided here.) Integration test (#68): a
connection that sends partial headers and an idle connection are both closed within the timeout, and recording
continues while 300 such connections are held. In the scratch probe a loopback accept loop with this configuration
(2 s header timeout for the check) closed a partial-header connection after 2.0 s and answered a complete request with
`200`, which confirms that `TokioTimer` is what makes the timeout fire.

*Request level, owned by #60 (api crate router).*

| threat | mechanism | what it does |
|---|---|---|
| large request bodies | axum `DefaultBodyLimit` / `tower-http` `RequestBodyLimitLayer`: 64 KiB | rejects bodies over 64 KiB; Phase 1 has no upload routes, so nothing legitimate is larger |
| slow handlers | `tower-http` `TimeoutLayer::with_status_code` (`408`) | answers with the chosen status and drops the handler future after the deadline |
| request flood | `tower` `ConcurrencyLimitLayer` | caps the number of requests **in flight**; it is **not** a connection cap (that is the semaphore above) |
| token leakage in logs | `tower-http` `SetSensitiveRequestHeadersLayer` on `Authorization`, applied **outside** `TraceLayer` | marks the header sensitive before `TraceLayer` sees the request so tracing and Debug output redact it (SEC-6); #60 tests that the token is absent from the trace output |

The request timeout and `ConcurrencyLimit` only cover the time until the response future resolves, **not a streamed
response body**. Body streaming for recording downloads, with a per-download idle or write timeout and any crates it
needs (tokio `fs`/`io-util`, tower-http `fs`), belongs to #62. A LAN client can therefore not make the host buffer large
bodies, hold header reads open, or open more than 256 connections; an authenticated client can hold a download open
only until #62's idle timeout.

### 10. New dependencies

Observed 2026-11-23. "Defaults off" is the planned `default-features = false` use. The `cargo info` licence is the
SPDX expression; every one of them contains an entry that is in the `deny.toml` allow list (`OR` expressions only need
one allowed branch; `subtle` is `BSD-3-Clause`, `tokio`/`axum`/`quick-xml`/`hyper`/`hyper-util`/`http-body-util`/`tracing`/
`tracing-subscriber`/`tower`/`tower-http` are `MIT`; `toml` is `MIT OR Apache-2.0`). Maintainers are the crates.io owners.

| crate | version | licence | last release | owners (crates.io) | defaults off? (features used) | deny.toml change |
|---|---|---|---|---|---|---|
| tokio | 1.54.1 | MIT | 2026-10-21 | carllerche, Darksonn, tokio-rs core team | yes (`rt-multi-thread`, `net`, `time`, `sync`, `signal`, `macros`; default is empty) | no |
| axum | 0.8.9 | MIT | 2026-04-14 | carllerche, davidpdrsn, tokio-rs teams | yes (`http1`, `json`, `query`, `tokio`) | no |
| hyper | 1.12.0 | MIT | 2026-10-06 | seanmonstar, hyperium core team | yes (`server`, `client`, `http1`; default is empty; `http2` arrives through hyper-util `server-auto`, unused at runtime) | no |
| hyper-util | 0.1.21 | MIT | 2026-09-24 | seanmonstar | yes (`client-legacy`, `http1`, `tokio`, `server`, `server-auto`, `server-graceful`, `service`; default is empty) | no |
| http-body-util | 0.1.5 | MIT | 2026-08-12 | seanmonstar | n/a (no features needed) | no |
| utoipa | 6.0.0 | MIT OR Apache-2.0 | 2026-09-22 | juhaku | yes (`macros` only) | no |
| utoipa-axum | 0.3.0 | MIT OR Apache-2.0 | 2026-09-22 | juhaku | n/a (only feature is `debug`) | no |
| clap | 4.6.9 | MIT OR Apache-2.0 | 2026-11-20 | kbknapp, rust-cli maintainers, clap-rs admins | no: defaults kept, plus `derive` | no |
| tracing | 0.1.44 | MIT | 2025-12-18 | carllerche, hawkw, tokio-rs publish team | no: defaults kept (`std`, `attributes`) | no |
| tracing-subscriber | 0.3.23 | MIT | 2026-03-13 | hawkw, davidbarsky, tokio-rs publish team | yes (`fmt`, `env-filter`, `json`, `std`) | no |
| tower | 0.5.3 | MIT | 2026-01-12 | carllerche, seanmonstar, tower-rs publish team | yes (`util`, `timeout`, `limit`; default is empty) | no |
| tower-http | 0.7.1 | MIT | 2026-08-31 | carllerche, tower-rs publish team | yes (`trace`, `sensitive-headers`, `limit`, `timeout`; default is empty) | no |
| toml | 1.2.2 | MIT OR Apache-2.0 | 2026-11-21 | epage, toml-rs maintainers | yes (`parse`, `serde`, `std`; drops `display`); core, parse only | no |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | 2026-09-23 | dtolnay | no features | no |
| anyhow | 1.0.104 | MIT OR Apache-2.0 | 2026-07-18 | dtolnay | defaults kept (`std`); binary only | no |
| quick-xml | 0.42.0 | MIT | 2026-08-22 | tafia, Mingun, dralley | yes (default is empty; none enabled) | no |
| sha1 | 0.11.0 | MIT OR Apache-2.0 | 2026-07-10 | tarcieri, newpavlov, RustCrypto hashes team | yes (drops `oid`; `alloc` not needed) | no |
| sha2 | 0.11.1 | MIT OR Apache-2.0 | 2026-10-12 | tarcieri, newpavlov, RustCrypto hashes team | yes (drops `oid`) | no |
| base64 | 0.23.1 | MIT OR Apache-2.0 | 2026-08-04 | alicemaz, marshallpierce | yes (`std` only; drops `simd-unsafe`) | no |
| subtle | 2.6.1 | BSD-3-Clause | 2024-06-24 | isislovecruft, dalek-cryptography subtle maintainers | no features | no |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | 2026-06-17 | dhardy, rust-random maintainers | defaults (none) | no |
| serde | 1.0.229 | MIT OR Apache-2.0 | 2026-07-18 | dtolnay, serde-rs publish team | derive only in core (`derive`, `std`) | no |
| serde_json | 1.0.154 | MIT OR Apache-2.0 | 2026-10-11 | dtolnay, serde-rs publish team | defaults kept (`std`) | no |

Maintenance notes. All crates other than `subtle` released in 2026. `subtle` (2.6.1, 2024-06-24) is stable and
feature-complete, a tiny constant-time primitive used by the dalek and RustCrypto ecosystems; its age is not a concern,
but a vulnerability report would be the trigger to re-evaluate (alternative: `constant_time_eq`, or comparing in
`sha2`-derived `digest` types). `sha1`/`sha2` are only RustCrypto-owned; `sha1` appears only because of ONVIF.
`utoipa`/`utoipa-axum` have a single owner (bus factor 1); mitigated by the committed `docs/openapi.json` snapshot,
which keeps the contract if the generator must be swapped. `quick-xml` 0.x may break minor to minor; pin `0.42`.

**Licence and deny.toml check (executed, re-run after adding `tower`, `tower-http` and `toml`).** In a scratch
project outside the repo (given `license = "MIT"` so the project itself is not reported) the exact set above, with the
planned features, was resolved: 135 packages in `cargo tree -e normal`, none of them `reqwest`, `rustls`, `ring`,
`openssl` or `aws-*`. Running the repo's `deny.toml` with `cargo deny check licenses advisories bans sources` gave
`advisories ok, bans ok, licenses ok, sources ok`. The only warning was `bans.multiple-versions` for two versions of
`syn`, which is `warn`, not `deny`. Every crate in the resolved tree is covered by the existing allow list, so
**`deny.toml` needs no change**. (The first probe, 119 packages before `tower`, `tower-http`, `toml` and the
tracing-subscriber `json` feature, had the same outcome apart from the scratch project's own missing licence field.)
It was re-run a third time with hyper `server` and hyper-util `server`, `server-auto`, `server-graceful` and `service`
added, together with a compiled accept loop using `auto::Builder`, `TokioTimer` and a `Semaphore`: the build succeeded,
the tree stayed at 135 packages and the result was again `advisories ok, bans ok, licenses ok, sources ok`. The
crate used for `RLIMIT_NOFILE` (#68) is not in this probe.
The actual dependencies are added by the tickets that use them, each of which re-runs `scripts/gate` (cargo-deny).

## Decision

Summary of what this ADR fixes (details in sections 1-10):

| question | decision |
|---|---|
| runtime | tokio, minimal features; core stays runtime-free; core traits use `fn ... -> impl Future<Output = ..> + Send` with generics |
| HTTP | axum 0.8, `default-features = false`, HTTP/1 only |
| OpenAPI | utoipa 6 + utoipa-axum 0.3, spec generated from code, committed snapshot test |
| CLI / logging | clap 4 derive; tracing in libraries, tracing-subscriber (`fmt`, `env-filter`, `json`) in the binary only, `--log-format` (`json` or `text`) |
| errors | thiserror in libraries, anyhow only in the binary (ERR-2/3) |
| core dependencies | `thiserror`, `serde` (derive only), `toml` (parse only); nothing else |
| ONVIF | hand-rolled: quick-xml, hyper-util client over plain HTTP, sha1/base64 WS-Security digest, WS-Discovery on UDP 3702 |
| crates | core, secrets, index, agentdvr, onvif, ingest, mp4, recorder, storage, api, cli; core depends on nothing; adapters do not depend on each other except recorder to mp4 |
| transport | plain HTTP, no TLS in v1; `api.listen` defaults to loopback; only loopback, private, ULA and link-local addresses accepted; CGNAT only with `api.allow_cgnat_bind`; wildcard (`0.0.0.0`, `::`, `::ffff:0.0.0.0`) only with `api.allow_unspecified_bind` |
| auth | `wl_<id>_<secret>` bearer token, SHA-256 of the decoded secret stored, looked up by id, constant-time comparison; one codec module `wardenlens-api::token` reused by the cli; core's `TokenStore` is plain data access; no roles in v1 |
| unauthenticated | `GET /api/v1/health` only, body `{"status":"ok"}`, no version |
| serving and limits | hand-written hyper-util accept loop (not `axum::serve`): `auto::Builder` http1 only, `TokioTimer`, 10 s `header_read_timeout`, idle timeout, graceful shutdown, 256-permit connection semaphore, raised `RLIMIT_NOFILE`; 64 KiB body, `TimeoutLayer`, `ConcurrencyLimit` on in-flight requests, `Authorization` marked sensitive outside `TraceLayer`; streamed bodies are #62's |

## Downstream tickets

This ADR **overrides** ticket text written before it. Where a ticket and this ADR disagree, this ADR wins; the tickets
below carry an "Amended by ADR 0004" section that matches it.

| ticket | what the ADR fixes for it |
|---|---|
| #47 (service config in core) | config key `api.listen`; `api.allow_unspecified_bind` permits `0.0.0.0`, `::` and `::ffff:0.0.0.0`; CGNAT `100.64.0.0/10` refused unless `api.allow_cgnat_bind = true`; `serde` (derive) and `toml` (parse, never `unbounded`) in core; the classification in section 9 (TEST-NET-1 refused, IPv4-mapped IPv6 by its IPv4 form, link-local scope ids) |
| #53 (WS-Discovery) | at most 64 replies, 4 s default window capped at 10 s, plain `http://` XAddrs only |
| #60 (api crate) | `GET /api/v1/health` unauthenticated with `{"status":"ok"}` and no version; owns the single `wardenlens-api::token` module (generate, encode, parse, hash, constant-time compare, dummy digest) that the cli reuses; consumes core's `TokenStore` by generics; 64 KiB body limit; `tower`/`tower-http` request layers, `SetSensitiveRequestHeaders` outside `TraceLayer` with a test, `TimeoutLayer::with_status_code`; `openapi.json` needs a token; no roles. Connection limits are not here (#68) |
| #61 (cameras endpoints) | read-only, no roles; handlers take core traits through generics, never `dyn` |
| #62 (recordings endpoints) | owns body streaming and its limits: `ConcurrencyLimit` and the request timeout do not cover a streamed body, so a per-download idle or write timeout is required and new crates are recorded in the PR |
| #64 (cli skeleton) | tracing-subscriber keeps the `json` feature behind `--log-format` (`json` or `text`) |
| #65 (token CLI) | `token create`, `list`, `revoke` use `wardenlens-api::token`; the index implements `TokenStore` (`find`) and `TokenAdmin` (`insert`, `list`, `revoke`, `touch_last_used`) as plain data access with a `UNIQUE` id column; `token create` retries on id collision; `token revoke <id>` sets `revoked`, never deletes; no roles |
| #68 (`wardenlens serve`) | the hand-written accept loop and connection semaphore, `header_read_timeout` 10 s with `TokioTimer`, idle timeout, graceful shutdown, raised `RLIMIT_NOFILE`; the integration test with 300 stuck connections; uses `api.listen` and core's `TokenStore` |
| #69 (Docker and compose) | `wardenlens health` probe subcommand as the healthcheck (no `curl` in the image); `ulimits.nofile`; `api.allow_unspecified_bind` only on the bridge network; `network_mode: host` implies a specific LAN `api.listen`; documented in `docs/deploy.md` |

Each of these tickets carries an "Amended by ADR 0004" section that matches this table (read with `gh issue view`
on 2026-11-23; #47, #53, #60, #65, #68 and #69 also carry a "round 2 additions" subsection). Where a ticket body above
that section says otherwise, the amendment and this ADR win.

## Consequences

- Easier: one runtime and one HTTP stack for server and ONVIF client; the OpenAPI spec is generated from code;
  every library has a typed error and one logging facade; the auth scheme is small and independent of the transport,
  so TLS can be added later without changing clients.
- Harder / accepted risks:
  - Plain HTTP on the LAN: a LAN eavesdropper or ARP spoofer sees video and tokens and can replay a token (residual
    risk, equal to the existing plaintext RTSP exposure, not acceptable beyond a private network), including replay of
    a captured token to read historic recordings and in-transit modification of responses (see the threat model).
    Mitigation: bind-address check, rotation and revocation, read-only API in Phase 1.
  - A stolen token stays valid until revoked (no expiry in v1; add optional expiry later).
  - No roles in v1: when the first mutating route is added, token scopes and a schema change come with it.
  - `ConcurrencyLimit` bounds in-flight requests only. Open connections are capped separately by the 256-permit
    semaphore in the hand-written accept loop (#68), and slow or idle connections are closed by `header_read_timeout`
    and the idle timeout, at the cost of owning an accept loop instead of calling `axum::serve`.
  - `server-auto` pulls in the `h2` crate although only HTTP/1 is served (builder is `http1_only`); a plain
    `hyper::server::conn::http1` connection would avoid that and is the fallback if h2 advisories become a concern.
  - Streamed response bodies are outside the request timeout; #62 must bound them.
  - axum 0.8, utoipa 6, quick-xml 0.42 and utoipa-axum 0.3 are pre-1.0 or fresh majors; bumps need care.
  - ONVIF by hand is more code to test; mitigated by recorded real-device fixtures (ADR 0002 spike data) and fuzz-style
    tests for the XML reader.
  - No HTTPS ONVIF: a camera that requires it forces a new TLS-client decision.
- To do: the `token` subcommands and the index-backed `TokenStore` (#65), the bind-address validation (#47) and the api
  crate with the limits above (#60) already exist as tickets. Remaining follow-ups to be ticketed: optional rustls or
  reverse-proxy documentation; the OpenAPI snapshot test; a mechanical check of the crate dependency direction; token
  expiry.
