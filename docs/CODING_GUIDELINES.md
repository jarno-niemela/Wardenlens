# Rust Coding Guidelines

These rules are binding for humans and agents. Reviewers (the Opus verification
agents) cite them by ID, e.g. `[ERR-2]`. Lints in `Cargo.toml`/`clippy.toml`
enforce what can be enforced mechanically; this document covers the rest.

Goals, in priority order: **correct → secure → clear → maintainable → fast.**

---

## 1. Architecture & modularity (`ARCH`)

- **ARCH-1 Functional core, imperative shell.** Domain logic lives in
  `wardenlens-core` and is pure: no I/O, no clocks, no env vars, no global
  state. Side effects live in adapter crates (CLI, network, storage) that
  depend on core — never the reverse.
- **ARCH-2 One crate, one responsibility.** Add a crate under `crates/` when a
  concern has its own dependencies or could be replaced independently. Crates
  are named `wardenlens-<concern>`.
- **ARCH-3 Depend on traits at boundaries.** Core defines traits for what it
  needs (`trait Clock`, `trait Store`); adapters implement them. Tests use
  in-memory fakes, not mocks of concrete types.
- **ARCH-4 Small public surface.** Default to private; use `pub(crate)` before
  `pub`. Every `pub` item is a commitment and must be documented.
- **ARCH-5 Module size.** Aim for files under ~400 lines and functions under
  ~60 lines (clippy `too_many_lines` = 80). Split by concept, not by kind
  (prefer `parser/`, `policy/` over `structs.rs`, `utils.rs`). No `utils`,
  `helpers` or `common` modules.
- **ARCH-6 No cyclic module dependencies** within a crate. If two modules need
  each other, extract the shared concept.

## 2. Types & API design (`TYPE`)

- **TYPE-1 Make illegal states unrepresentable.** Use enums over boolean flags
  and `Option` combos; newtypes over bare primitives for domain values
  (`struct UserId(u64)`, not `u64`).
- **TYPE-2 Parse, don't validate.** Convert untrusted input into validated
  types once at the boundary (`TryFrom`, `FromStr`); inner code takes the
  validated type and does not re-check.
- **TYPE-3 Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)**:
  conversions are `as_`/`to_`/`into_`, getters have no `get_` prefix,
  constructors are `new`/`with_*`/`builder()`, implement common traits
  (`Debug`, `Clone`, `PartialEq`, `Default` where meaningful).
- **TYPE-4 Borrow in arguments, own in returns.** Take `&str`, `&[T]`,
  `impl AsRef<Path>`; return owned values. Avoid `clone()` to appease the
  borrow checker — restructure instead, or justify in a comment.
- **TYPE-5 `#[must_use]`** on functions whose result is meaningless to ignore
  (builders, pure computations returning new values).
- **TYPE-6 `#[non_exhaustive]`** on public enums and structs that may grow.
- **TYPE-7 No stringly-typed APIs.** Keys, states and kinds are enums.

## 3. Errors (`ERR`)

- **ERR-1 No panics in non-test code.** `unwrap`, `expect`, `panic!`, `todo!`,
  `unimplemented!`, unchecked indexing are denied by lint. The only allowed
  exception is a provably-unreachable invariant, documented with
  `#[expect(clippy::expect_used, reason = "...")]` stating the invariant (a bare
  `#[allow]` is forbidden, see DOC-6).
- **ERR-2 Libraries return typed errors.** Each library crate defines its own
  error enum (with `thiserror` once added as a dependency). Variants describe
  *what failed*, carry context, and wrap sources with `#[source]`.
- **ERR-3 Binaries may use `anyhow`-style context** at the top level only,
  adding `.context("while reading config {path}")` as errors cross layers.
- **ERR-4 Never discard errors silently.** `let _ = fallible()` requires a
  comment explaining why the failure is irrelevant.
- **ERR-5 Error messages** are lowercase, without trailing punctuation, and do
  not leak secrets or full untrusted payloads.

## 4. Security (`SEC`)

- **SEC-1 `unsafe` is forbidden** workspace-wide. Lifting this for a crate
  requires an ADR, `// SAFETY:` comments on every block, and a Miri job in CI.
- **SEC-2 Treat all external input as hostile**: files, env vars, CLI args,
  network, deserialised data. Bound every size: lengths, recursion depth,
  collection sizes, timeouts. No allocation proportional to an untrusted
  number without a cap.
- **SEC-3 Integer arithmetic on untrusted values** uses `checked_*`,
  `saturating_*` or `wrapping_*` explicitly. Release builds keep
  `overflow-checks = true`. Use `TryFrom` instead of `as` casts.
- **SEC-4 Paths:** canonicalise and verify containment before access; never
  join untrusted segments onto a base path without rejecting `..`, absolute
  paths and symlink escapes.
- **SEC-5 Processes:** never build shell strings. Use `std::process::Command`
  with separate args; never pass untrusted input to `sh -c`.
- **SEC-6 Secrets** never appear in logs, errors, `Debug` output or panics.
  Wrap them in a type with a redacting `Debug` (e.g. `secrecy::SecretString`)
  and zeroise when practical.
- **SEC-7 Cryptography:** never hand-roll. Use audited crates (`rustls`,
  `ring`/`aws-lc-rs`, RustCrypto). Compare secrets in constant time.
- **SEC-8 Dependencies** must pass `cargo deny check` (advisories, licenses,
  sources, bans). Every new dependency is justified in the PR: why it is
  needed, maintenance status, transitive cost. Prefer `std` and small,
  widely-used crates. Disable default features you do not use.
- **SEC-9 Concurrency:** no `static mut`; prefer message passing; hold locks
  for the shortest scope and never across `.await`.
- **SEC-10 One choke point, a pass-list where the good set is known, every
  entry point tested.** A rule that must hold everywhere (a refusal, redaction,
  authentication, a rate or concurrency cap, input classification) is enforced
  in the one function or layer every path goes through, never in a helper that
  most paths happen to call. Where the good set can be listed (printable
  characters, tree modes, echoable error kinds, routes), classify by a
  **pass-list of known-good forms** and fail closed on anything unknown, with no
  "everything else is a file" fallthrough. Where only the bad values are known
  exactly (vault values, ADR 0006 §7), match them exactly over every rendering
  (TEST-9). A shape heuristic is never the enforcement: it may exist only as a secondary layer behind the choke point (an advisory soft lint, ADR 0006 §7, or defence in depth behind unconditional redaction, such as the `RtspPath` name check). Never answer a finding by growing the heuristic instead of fixing the choke point. Two components that must agree on a set
  (a validator and a scanner, a needle collapse and a view collapse) call one
  shared predicate, and a test fails if they diverge. A test loops over every
  entry point (each subcommand, route, error kind, input form), including one
  that matches nothing. Examples: #94, #60, #75 r1-r2, #43 r1-r3, #117 r1-r2
  and r5, #32 r1-r5 (`defect-patterns` P10).

## 5. Testing (`TEST`)

- **TEST-1 Tests first.** Write a failing test that encodes the acceptance
  criterion, then make it pass. Every bug fix starts with a regression test.
- **TEST-2 Unit tests** live in a `#[cfg(test)] mod tests` next to the code.
  Integration tests in `crates/<name>/tests/` use only the public API.
- **TEST-3 Property tests** (`proptest`) for parsers, encoders, and any
  function with an invariant (round-trip, idempotence, ordering). Fuzz targets
  (`cargo fuzz`) for anything parsing untrusted bytes.
- **TEST-4 Test names state behaviour**: `rejects_path_with_parent_segment`,
  not `test_path_2`. One behaviour per test; arrange/act/assert.
- **TEST-5 Deterministic.** No real clocks, network or random seeds without
  injection. No sleeping in tests.
- **TEST-6 Test the edges**: empty, one, max, max+1, unicode, invalid UTF-8,
  negative/zero, duplicate, concurrent.
- **TEST-7 Doc examples compile and run** (`cargo test` runs doc-tests); they
  are part of the contract.
- **TEST-8 Every test can fail.** The tests for a behaviour, taken together
  (positive and negative cases), must fail if the code under test returned a
  constant or echoed its input, so compute expected values independently. A generator must reach the branch it targets. A test of a guard,
  an ordering or a redaction must fail when that guard is removed or reordered:
  mutation-check it once by hand and say so in the PR. A test that passes only
  because of scheduler timing is not deterministic (TEST-5).
- **TEST-9 Enumerate the whole surface before fixing.** For an invariant over an
  open-ended input space (every path a push publishes, every spelling a scanner
  must find, every input form of a parse type), write the full enumeration and a
  table-driven test, one row per element, **before** the fix, and show that it
  fails first. A brief or ticket states the invariant, not the reported
  example. Any proof an optimisation relies on (for example "every ancestor of a
  new tree is new") is checked in both directions: a new path can sit on an old
  tree (#117 r4). Prefer "walk everything and dedupe" to "skip what looks
  already handled", but only within the SEC-2/SEC-3 bounds: #128's unbounded
  `seen` set grew with the input. Examples: #117 r1-r5, #43 r2-r4, #32 rw1
  (`defect-patterns` P11).

## 6. Style & documentation (`DOC`)

- **DOC-1 `cargo fmt`** is the only style authority. Do not argue with it.
- **DOC-2 Every public item has rustdoc** with a one-line summary, and where
  relevant `# Errors`, `# Panics` (should be none), and `# Examples`.
- **DOC-3 Comments explain *why*, not *what*.** Delete commented-out code.
- **DOC-4 Naming:** `snake_case` functions, `CamelCase` types,
  `SCREAMING_SNAKE` consts; no abbreviations except universally known ones
  (`id`, `url`, `io`).
- **DOC-5 Significant decisions get an ADR** in `docs/adr/` (template there).
- **DOC-6 Suppress lints only with `#[expect(lint, reason = "...")]`.** A bare
  `#[allow]` is forbidden (`allow_attributes` warns, `allow_attributes_without_reason`
  denies); `#[expect]` flags itself once the suppression is no longer needed.

## 7. Performance (`PERF`)

- **PERF-1 Clarity first;** optimise only with a benchmark (`criterion`)
  proving the need, and keep the benchmark.
- **PERF-2 Avoid needless allocation** in hot paths (`&str` over `String`,
  iterators over intermediate `Vec`s, `with_capacity` when the size is known
  *and bounded*).
- **PERF-3 Async only at I/O boundaries.** Core stays synchronous. Never block
  inside async code.

## 8. Change hygiene (`CHG`)

- **CHG-1 One ticket, one PR, one concern.** Target < 400 changed lines
  excluding tests and lockfiles. Refactors and behaviour changes go in
  separate PRs.
- **CHG-2 Conventional commits:** `feat(core): ...`, `fix(cli): ...`,
  `refactor`, `test`, `docs`, `chore`, `ci`. Reference the issue:
  `Refs #12` in commits, `Closes #12` in the PR body.
- **CHG-3 No dead code, no speculative generality.** Do not add parameters,
  traits or features "for later".
- **CHG-4 `Cargo.lock` is committed**; builds use `--locked`.
- **CHG-5 Public API or behaviour changes** update docs and tests in the same PR.

---

## Reviewer checklist (used by the Opus verification agents)

1. Does the change satisfy every acceptance criterion of the linked ticket, with a test for each?
2. Does `scripts/gate` pass?
3. Any panic path, unchecked arithmetic, unbounded allocation or `as` cast on untrusted data?
4. Are trust boundaries explicit, and is input parsed into validated types there?
5. Is the module/crate boundary right (ARCH-1..6)? Is anything public that need not be?
6. Are error types precise and contextual, with no secret leakage?
7. Are tests deterministic, behaviour-named, and covering edges?
8. Any new dependency — justified and `cargo deny` clean?
9. Is anything here speculative, dead, or duplicated?
10. Is every cross-cutting policy at one choke point, by a pass-list or exact match (SEC-10), and is every open-ended invariant backed by an enumerated table test (TEST-9)?
