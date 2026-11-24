---
name: defect-patterns
description: Catalogue of the defect classes the Opus verifiers (reviewer, security-auditor, adversary) have actually found in this repository, each with the rule, a real example and the self-test that would have caught it. Use before reporting DONE on any implementation or fix round, when writing a controller brief or design ruling, and as a seed list when reviewing or attacking a change.
---

# Defect patterns (learned from verification rounds)

Every entry cost at least one extra review round. Before reporting `DONE`, walk the
**checklist** at the end against your diff, and write the listed self-test for every
pattern your change touches. Patterns are ordered by how often they recur.
`docs/CODING_GUIDELINES.md` is still the binding rule set; this file is the field guide.
Keep it current with `/retro` (the `improve-skills` skill).

## P1. Silent loss or overwrite ("nothing is dropped silently")
- **Rule.** When several inputs feed one key space, check uniqueness over the **union**
  and refuse a duplicate with a typed error. Never rely on an upsert.
- **Rule.** Give generated ids their own namespace (`import-json-N`, `import-toml-N`) and
  reserve that prefix, so real ids can never take it.
- **Rule.** Every input key ends up either imported exactly once or **reported by name**:
  unknown, shadowed, empty, too long, or refused by validation.
- **Rule.** A mapper must run the sink's own validator. It must never emit a value the
  sink will refuse later.
- **Rule.** Report the key that actually failed (`password`, not `login`).
- **Example.** #74 (PR #97) rounds 1-4:
  - ordinal ids collided across the JSON and TOML files and within each file;
  - a `password` without a `login` vanished;
  - `name` and `display_name` overwrote each other;
  - over-long ids dropped fields;
  - an empty `login` produced a credential that `set` refused.
- **Self-test.**
  - A test that enumerates every key of a hostile fixture and asserts each is imported or reported.
  - A cross-source collision test, including a real id that looks like a generated one.
  - "Every emitted value is accepted by the sink."

## P2. Destructive actions that do not achieve their goal
- **Rule.** Only delete, evict or overwrite when doing so **restores a goal that is
  reachable**:
  - target if reachable, else floor, else **nothing**, and report the state;
  - apply the rule symmetrically to every tier or side.
- **Rule.** Hold steady state with an **absolute** level (a budget), not a per-tick
  relative amount. A relative amount drifts by one granule each tick and drains everything.
- **Rule.** Every "never" sentence in the ticket is an invariant, for example "never ENOSPC".
  Check that a fixed hold or budget cannot violate it, for instance through foreign data
  growth.
- **Example.** #44 (PR #101):
  - r1: the archive was wiped to chase an unreachable floor;
  - r2: hot video was deleted past the floor while chasing an unreachable target;
  - r3: the rolling buffer overshot by one segment each tick and drained;
  - r4: a fixed budget held hot video at 0 B free.
- **Self-test.**
  - A proptest of **minimality**: without the last delete, the goal would not be met.
  - A proptest that no delete is planned unless the end state meets its floor.
  - A **multi-tick** simulation (50-100 ticks) with mixed segment sizes and foreign growth.

## P3. Touching what is not yours (foreign files, sidecars, recovery)
- **Rule.** Before any write-capable operation, prove identity **read-only**:
  - write-capable means a read-write open, a pragma, `CREATE`, or SQLite's hot-journal or WAL recovery;
  - identity means exact schema, version and a keycheck under the supplied key, checked by an immutable probe.
  - Enumerate **every entry point** (`open`, `create`, `rekey`, the empty-file path) and every sidecar (`-wal`, `-journal`).
- **Rule.** Separate "foreign" from "mine, mid-write or crashed":
  - wait for a live writer up to the busy timeout;
  - let a proven own file recover;
  - otherwise return a distinct typed error.
  - Never return an error whose obvious fix destroys data. For example, `NotInitialized` invites deleting the journal.
- **Rule.** "Exact schema" means every `sqlite_master` row (tables, indexes, triggers and
  views), not just tables. A table name like `meta` is not identity.
- **Example.**
  - #74 r3-r5 (PR #97): `create`, and then `open`, ran `journal_mode` on a foreign WAL database before refusing it; the probe trusted any `meta` table.
  - #104 r1 (PR #106): the fix refused the vault's own `-journal`, which broke crash recovery and concurrent readers.
- **Self-test.** For each entry point:
  - a foreign WAL database, a database with a `meta` table, a leftover `-wal` and a hot `-journal`, each asserting the main file, the sidecar and the directory listing are **byte-identical**;
  - an own vault opened during a concurrent write, and after a crash mid-write and mid-rekey.

## P4. Panics and blow-ups on untrusted bytes
- **Rule.** A byte-length check followed by `str` slicing (`split_at`, `[a..b]`) panics
  on multibyte input. Check ASCII or digits first, or use `.get(a..b)`. Consider
  `clippy::string_slice`.
- **Rule.** Do not collect every match before processing. In #54, a `Vec` of start-code
  offsets reached about 22 MB on an 8 MiB input. Stream instead.
- **Rule.** Keep one source of truth for enumerations shared by a parser and a writer.
  In #54, H.264 profile 144 was in the avcC list but not in the SPS parser's.
- **Example.** #45 r1 (PR #102): `"cam/2024-01-01/aé123-042.mp4".parse::<RelPath>()` panicked.
  A `.*` proptest never generates this shape.
- **Self-test.**
  - A proptest that builds **well-formed** inputs and puts arbitrary characters, including multibyte ones, into each component.
  - Truncation sweeps over every prefix length.

## P5. Time, clocks and hostile timestamps
- **Rule.** Measure timeouts, deadlines and backoff on a **monotonic** clock. Heuristics
  that guess at wall-clock steps create new stalls (#46 r2 to r3).
- **Rule.** Never store a *clamped* value as "the last good" value. Keep the last
  unclamped step separately (#45 `last_good_step`).
- **Rule.** A hostile source can freeze or slowly reverse its clock. Bound the result
  in a second dimension (wall clock, bytes) and file an ADR amendment if the spec lacks
  one (#103).
- **Self-test.** A proptest over every tick cadence and failure latency, from 1 ms to
  60 s, that asserts liveness: the camera degrades, and retries keep coming.

## P6. Error typing that lies
- **Rule.** `fallible().unwrap_or(false)` or `.is_err()` turns an I/O error into a
  semantic answer. Map only the specific kinds, such as `UnexpectedEof` or
  `NotADatabase`, and pass everything else on as a typed error.
- **Rule.** A variant name must describe the cause. `AlreadyInitialized` for a foreign
  non-empty file is wrong; it should be `NotEmpty`.
- **Rule.** A pair of booleans or fields that can represent an impossible state should
  be one enum (TYPE-1):
  - `unsatisfiable` with `rolling_buffer`;
  - `Decision::Append` with `Some(error)`;
  - `set(.., bool) -> bool`.
- **Self-test.** One test per error variant that the new code can return. `grep` each
  variant in the tests; an untested variant is a finding.

## P7. Tests that cannot fail
- **Rule.** A tautological assertion does not count, for example
  `ended == started + duration` where `ended` is derived from those values. Compute
  the expected value independently.
- **Rule.** Check that a generator reaches the interesting path. Random `u32` RTP values
  re-base on every frame, so a proptest built on them never hits the hard maximum. Add
  bounded-delta strategies.
- **Rule.** A test that locks in wrong behaviour is a defect. Fix or rename tests and
  doc comments when behaviour changes; stale "Observed: stays in Connecting forever"
  notes were flagged.
- **Rule.** Boundaries mean exact, minus one and plus one, for every cap:
  8 MiB / 8 MiB + 1, 16 MiB, 600 000 ms, u32::MAX.

## P8. Missing acceptance criteria and spec drift
- **Rule.** Read the **whole** ticket. "Amended by ADR …" sections override the text
  above them, and items assigned to this ticket in an amendment are in scope. For
  example, the fragment caps belonged to #45 (r1 major).
- **Rule.** Public rustdoc must list **every** category or state the code can produce,
  such as every reason a key lands in `unknown_keys`.
- **Rule.** A deviation from the ADR or the brief goes in the report under
  NOTES FOR VERIFIERS with the reason. Verifiers accept a justified deviation; they
  block a silent one.

## P9. Workflow traps (controller and implementer)
- **Copied adversary tests:** run `cargo fmt --all` before committing them; the pre-commit hook rejects otherwise.
- **`Policy` literals:** a new field breaks every external struct literal in the test files. Add the field with a neutral value, not a semantics change.
- **CodeQL:** it flags synthetic keys and passwords in tests (`hard-coded-cryptographic-value`, `cleartext-logging`). Dismiss them with a reason; never weaken the test.
- **Merge conflicts:** almost every branch adds a `pub mod` line to `core/src/lib.rs`. Before verifying two PRs in parallel, trial-merge them; resolve conflicts by taking the union of both module lists.

## Checklist (run before reporting DONE)
1. **P8:** the ticket has been reread, including amendments, and every criterion maps to a named test.
2. **P1:** for each input key or source, imported or reported? Uniqueness checked over the union?
3. **P2:** for each delete or overwrite, does it restore a reachable goal? Is the goal absolute? Is every "never" invariant tested over many ticks?
4. **P3:** for each file touched, is identity proven read-only first? Have all entry points and sidecars been tried? Does own-file recovery still work?
5. **P4:** for each parse of untrusted bytes, is there any slicing? Is anything unbounded collected? Does the proptest generate well-formed input with hostile components?
6. **P5:** for each timeout, is it monotonic? Does a clamp leak into stored state?
7. **P6:** is every new error variant tested? Is there no `unwrap_or`/`is_err` collapsing an I/O error?
8. **P7:** is each assertion independent of the code under test? Do the generators reach the interesting branches? Are boundaries covered at -1, exact and +1?
9. Are deviations, assumptions and anything left undone listed in NOTES FOR VERIFIERS?
Last retro: 2026-11-24, covering PRs #93 #95 #97 #98 #101 #102 #106.
