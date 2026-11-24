---
name: rust-guidelines
description: Project Rust conventions — architecture (functional core / adapter crates), error handling without panics, input validation and bounds, testing (tests first, proptest, edge cases), API design and dependency policy. Use whenever writing, refactoring or reviewing Rust code in this repository, or adding a crate or dependency.
---

# Rust guidelines (quick reference)

The binding source is `docs/CODING_GUIDELINES.md` — read the relevant section before writing code. This is the short version.

**Shape**
- Logic in `wardenlens-core` (pure, no I/O). Side effects in `crates/wardenlens-<adapter>`. Core defines traits; adapters implement them.
- Private by default → `pub(crate)` → `pub` (documented). No `utils`/`helpers` modules. Files < ~400 lines, fns < ~60.

**Types**
- Newtypes for domain values; enums instead of bool flags; `#[non_exhaustive]` on growing public types.
- Parse untrusted input into validated types once, at the boundary (`TryFrom`/`FromStr`).

**Errors**
- No `unwrap`/`expect`/`panic!`/indexing in non-test code (lint-denied). Per-crate `thiserror` enum; add context when crossing layers; never `let _ =` a `Result` without a comment.

**Security**
- No `unsafe`. Bound every size from input. `checked_*` arithmetic and `TryFrom` instead of `as`. No shell strings. Redacting `Debug` for secrets. New deps must pass `cargo deny check` and be justified.

**Tests**
- Failing test first; one behaviour per test, named for it; cover empty/max/unicode/invalid; proptest for invariants; deterministic.

**Most-missed in review** (details and self-tests: `.claude/skills/defect-patterns/SKILL.md`)
- Every input key is imported or reported, and uniqueness is checked over the union of sources (P1).
- A destructive action must restore a reachable goal; hold levels as absolute values; test minimality over many ticks (P2).
- Prove identity read-only before any write-capable open, for every entry point and sidecar (P3).
- No `str` slicing after a byte-length check; use `.get()` (P4). Use a monotonic clock for timeouts (P5).
- No `unwrap_or(false)` on I/O; one test per error variant (P6). Every test can fail (TEST-8, P7).
- Open foreign paths with `O_NOFOLLOW | O_NONBLOCK` (P3). Enforce a policy at its one choke point, as an allowlist, and test it over every entry point (P10).

**Workflow**
- `scripts/gate` before every push. Conventional commits with `Refs #N`. Suppress lints only with `#[expect(lint, reason = "...")]`; bare `#[allow]` is forbidden (ERR-1, DOC-6).

**New crate checklist**: add under `crates/`, `[lints] workspace = true`, inherit `workspace.package` fields, crate-level `//!` doc stating its responsibility and what it must not do, an ADR if it introduces a new boundary.
