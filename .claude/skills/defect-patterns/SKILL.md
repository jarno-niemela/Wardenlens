---
name: defect-patterns
description: Catalogue of the defect classes the Opus verifiers (reviewer, security-auditor, adversary) have actually found in this repository, each with the rule, a real example and the self-test that would have caught it. Use before reporting DONE on any implementation or fix round, when writing a controller brief or design ruling, and as a seed list when reviewing or attacking a change.
---

# Defect patterns (learned from verification rounds)

Most entries cost at least one extra review round; the rest were recurring minors. Before reporting `DONE`, walk the
**checklist** at the end against your diff, and write the listed self-test for every
pattern your change touches. Patterns are ordered by how often they recur.
`docs/CODING_GUIDELINES.md` is still the binding rule set; this file is the field guide.
Keep it current with `/retro` (the `retro` skill).

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
  - #43 (PR #127) r1-r3: a duplicate `CameraId` was never unified; legacy names with NBSP were dropped; names that normalise equal merged silently (first wins).
- **Self-test.**
  - A test that enumerates every key of a hostile fixture and asserts each is imported or reported.
  - A cross-source collision test, including a real id that looks like a generated one.
  - "Every emitted value is accepted by the sink."

## P2. Destructive actions that do not achieve their goal
- **Rule.** Only delete, evict or overwrite when doing so **restores a goal that is
  reachable**:
  - target if reachable, else floor;
  - if even the floor is unreachable, delete only what an **explicit absolute
    safety level** demands. In #44 that is the rolling-buffer budget and the emergency
    reserve that keep the "never ENOSPC" invariant. Otherwise delete nothing, and report
    the state;
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
No recurrence in #75, #117, #32, #43; kept compact.
- **Rule.** Before any write-capable operation (a read-write open, a pragma, `CREATE`, SQLite hot-journal or WAL recovery), prove identity **read-only**: exact schema (every `sqlite_master` row, not just tables), version and a keycheck under the supplied key, by an immutable probe. Cover **every entry point** (`open`, `create`, `rekey`, the empty-file path) and every sidecar (`-wal`, `-journal`).
- **Rule.** With a hot `-journal` the main file may be torn (a crash mid-rekey leaves the new keycheck page), so identify a **private rolled-back copy** (#104 r3). It is safe only with: copying through the verified descriptor, a 0700 scratch directory with `create_new` 0600 files, a size cap, removal on every return path, an `O_NOFOLLOW | O_NONBLOCK` journal open, and refusing a journal whose tail holds a super-journal pointer (PR #106, #119).
- **Rule.** Every open of a path the program discovered (sidecar, walk entry, path named inside a file) uses `O_NOFOLLOW | O_NONBLOCK`, rejects a non-regular `symlink_metadata` first, and re-checks `is_file` on the descriptor. Keep libraries from opening such paths themselves (#104 r3-r4 FIFO hangs). A path the owner names still opens with `O_NONBLOCK`.
- **Rule.** Separate "foreign" from "mine, mid-write or crashed": wait for a live writer up to the busy timeout, let a proven own file recover, else return a distinct typed error. Never return an error whose obvious fix destroys data (`NotInitialized` invites deleting the journal).
- **Example.** #74 r3-r5 (PR #97): `create`, then `open`, ran `journal_mode` on a foreign WAL database before refusing it. #104 r1 (PR #106): refusing the vault's own `-journal` broke crash recovery. #104 r2-r4: an immutable probe of a torn main file locked out the old key.
- **Self-test.** Per entry point: a foreign WAL database, a database with a `meta` table, a leftover `-wal` and a hot `-journal`, each asserting main file, sidecar and directory listing are **byte-identical**; an own vault during a concurrent write and after a crash mid-write and mid-rekey (the crash must leave the new keycheck page in the main file, #104 r2). **TEST-5:** coordinate the writer with a channel or barrier, never `sleep`.

## P4. Panics and blow-ups on untrusted bytes
- **Rule.** A byte-length check followed by `str` slicing (`split_at`, `[a..b]`) panics
  on multibyte input. Check ASCII or digits first, or use `.get(a..b)`.
  `clippy::string_slice` catches `&s[a..b]` but **not** `split_at`, so also grep the diff
  for `split_at`.
- **Rule.** Do not collect every match before processing. In #54, a `Vec` of start-code
  offsets reached about 22 MB on an 8 MiB input. Stream instead.
- **Rule.** Keep one source of truth for enumerations shared by a parser and a writer.
  In #54, H.264 profile 144 was in the avcC list but not in the SPS parser's.
- **Rule.** A line-oriented input contract (piped stdin, key files) is a table of forms: no newline, LF, CRLF, a trailing blank line, one line too few, one line too many. Each form is accepted or refused on purpose, and each is a test row (#94 r1-r2: a third line folded into the password; `user\n` stored an empty password).
- **Example.** #45 r1 (PR #102): `"cam/2024-01-01/aé123-042.mp4".parse::<RelPath>()` panicked.
  A `.*` proptest never generates this shape.
- **Self-test.**
  - A proptest that builds **well-formed** inputs and puts arbitrary characters, including multibyte ones, into each component.
  - Truncation sweeps over every prefix length.

## P5. Time, clocks and hostile timestamps
- **Rule.** Measure timeouts, deadlines and backoff on a **monotonic** clock. Heuristics
  that guess at wall-clock steps create new stalls.
- **Rule.** Never store a *clamped* value as "the last good" value. Keep the last
  unclamped step separately (`last_good_step`).
- **Rule.** A hostile source can freeze or slowly reverse its clock. Bound the result
  in a second dimension (wall clock, bytes) and file an ADR amendment if the spec lacks
  one (#103).
- **Example.**
  - #46 (PR #95) r2: wall-clock step heuristics stalled a hung camera at 7.5-15 s tick cadences. Fixed in r3 by moving to `MonoMs`.
  - #45 (PR #102) r1: a re-base reused a 1-tick clamped step. A frozen RTP clock keeps a segment open for hours (#103).
- **Self-test.** A proptest over every tick cadence and failure latency, from 1 ms to
  60 s, that asserts liveness: the camera degrades, and retries keep coming.

## P6. Error typing that lies
- **Rule.** `fallible().unwrap_or(false)` or `.is_err()` turns an I/O error into a
  semantic answer. Map only specific `io::ErrorKind`s such as `UnexpectedEof`, or
  SQLite codes such as `SQLITE_NOTADB`, and pass everything else on as a typed error.
- **Rule.** A variant name must describe the cause. `AlreadyInitialized` for a foreign
  non-empty file is wrong; it should be `NotEmpty`.
- **Rule.** A pair of booleans or fields that can represent an impossible state should
  be one enum (TYPE-1):
  - `unsatisfiable` with `rolling_buffer`;
  - `Decision::Append` with `Some(error)`;
  - `set(.., bool) -> bool`.
- **Example.**
  - #74 (PR #97) r3-r4: a foreign non-empty file reported as `AlreadyInitialized`; `has_meta(..).unwrap_or(false)`.
  - #74 (PR #97) r1: `set(.., force_unscannable: bool) -> bool` (TYPE-1).
  - #44 (PR #101) r1: the `unsatisfiable` / `rolling_buffer` bools.
  - #45 (PR #102) r2: `Decision` with `Option<PushError>` (#105).
  - #60 (PR #115) r1: store failures shared the auth-failure sampling counter and were logged as "authentication failed". Keep one counter and one message per failure kind.
  - #75 (PR #122) r2: exit 1 must mean only "hit found"; walk-limit and output errors had to exit 2. #117 (PR #125) r2: a `git ls-files` failure inside a process substitution failed open.
- **Self-test.** One test per error variant that the new code can return. `grep` each
  variant in the tests; an untested variant is a finding.

## P7. Tests that cannot fail (promoted to TEST-8)
- **Rule.** TEST-8 is the rule: compute expected values independently, make generators reach the target branch, mutation-check guards and orderings once, and never depend on timing. Fix or rename tests and doc comments when behaviour changes. Boundaries are exact, -1 and +1 for every cap.
- **Example.**
  - #45 (PR #102) r1 reviewer: the "sum of durations" proptest asserted `ended == started + duration`, which is true by construction. In r2: random-u32 RTP never reached the hard maximum.
  - #74 (PR #97) r1: `json_without_login_imports_no_credential` locked in the dropped password.
  - #46 (PR #95) r3 and #44 (PR #101) r5: stale adversary-test doc comments.
  - #60 (PR #115) r2: the slot-wait test passed with the layers swapped, because the permit is taken in `poll_ready`.
  - #104 (PR #106) r4: a kept adversary test relied on a writer thread winning a race, and flaked the gate on main (#116).
  - #32 (PR #71) rw1: the encoding test covered only `quirks[0]`, so a mutation dropping other fields survived. #117 (PR #125) r3: no deletion test.
- **Self-test.**
  - For each assertion, ask: "would this fail if the function returned a constant or its own input?"
  - For each proptest, count with a temporary counter how often the target branch is hit, and require more than 0.

## P8. Missing acceptance criteria and spec drift
- **Rule.** Read the **whole** ticket. "Amended by ADR …" sections override the text
  above them, and items assigned to this ticket in an amendment are in scope. For
  example, the fragment caps belonged to #45 (PR #102 r1 blocker).
- **Rule.** Public rustdoc must list **every** category or state the code can produce,
  such as every reason a key lands in `unknown_keys`.
- **Rule.** A deviation from the ADR or the brief goes in the report under
  NOTES FOR VERIFIERS with the reason. Verifiers accept a justified deviation; they
  block a silent one.
- **Rule.** When a fix round changes the design, update the ADR paragraph and the public rustdoc in the **same** round. A process or gate change goes into `docs/WORKFLOW.md`, the binding text, not only into a skill.
- **Example.** #74 (PR #97) r3: the `unknown_keys` rustdoc missed two categories. #110 r1: a ticket criterion (cap escalation) was left out. #104 (PR #106) r3: the ADR still described round-2 behaviour. #107 (PR #110) r2: the override existed in a skill but contradicted WORKFLOW.md. #43 (PR #127) r1: `Camera` lacked the model reference and `StreamSet`; r4: the ADR was stale. #75 (PR #122) r2: binary files over 8 MiB were refused, against ADR §7.
- **Self-test.** List each acceptance criterion with its test name or file evidence (the
  implementer report's CRITERIA block). A criterion with no evidence is unmet.

## P9. Workflow traps (controller and implementer; no code self-test, the gate and CI catch these)
- **Copied adversary tests:** run `cargo fmt --all` before committing them. **`Policy` literals:** a new field breaks every external struct literal in tests; add it with a neutral value.
- **CodeQL:** it flags synthetic keys and passwords in tests (`hard-coded-cryptographic-value`, `cleartext-logging`). The controller dismisses **test-path** alerts with a reason (PR #90). An alert in non-test code is a security finding for the auditor or the owner. Never weaken the test.
- **Guard hook quirks:**
  - The guard cannot resolve git after `cd $VAR` or a relative `cd`. Use `cd /abs/path &&` or `git -C /abs/path`, one worktree per Bash call.
  - Any command text containing the literal merge command without `--match-head-commit`, even inside a heredoc, is blocked. Write such text to a file with the Write tool.
  - Only dangerous `git -c` keys are blocked (for example hooks, push, alias, editor, `include.path`, `includeIf.*`, `extensions.worktreeconfig`); `user.name` and `user.email` pass.
  - These notes are for writing prose and briefs, never for getting a command past the guard.
- **Gate then push:** chain them with `&&`, never `;` (a failed gate still pushed on #75's branch).
- **Gate vs CI:** CI's shellcheck has no `-x`, the gate's does (#117). Run CI's exact command too.
- **Scratch git:** a failed `cd` let `git reset --hard` run in the main checkout (#117 r1). Use `git -C <abs temp path>`.
- **Verdicts:** record all three before `verify carry`; `carry` read a lagging status API and a verdict was once unrecorded (#117, #43).
- **Rework vs merge:** commit rework separately from merges of main (#32). A brief that widens scope into another crate (#43 into the scanner) should be split at r1.
- **Escapes in tool input:** `\uXXXX` text in a tool call can be decoded into the real character. Describe such escapes in words ("the JSON escape for U+2028").
- **Kept adversary tests:** `scripts/verify carry` accepts only `crates/*/tests/**` and `scripts/tests/**`. Tests in a `src/` test module need re-verification, so they go to the follow-up ticket instead (PR #115). Before committing kept tests, read them for sleeps or racing threads; a timing-dependent test goes to a follow-up, not to main (#116).
- **Merge conflicts:** almost every branch adds a `pub mod` line to `crates/wardenlens-core/src/lib.rs`. Before verifying two PRs in parallel, trial-merge them; resolve conflicts by taking the union of both module lists (PR #97, #101, #102). Resolving a conflict changes the head, so all three verifiers must run again.

## P10. A rule that must hold everywhere, enforced in only some places (promoted to SEC-10)
- **Rule.** SEC-10 is the rule: one choke point, an allowlist, every entry point tested, one shared predicate for two components that must agree. Know how the framework applies a layer: axum's `Router::layer` wraps each route separately, so wrap the finished router as one service.
- **Example.**
  - #94 (PR #109) r1-r3: `check-key <path>` skipped a refusal that lived only in `Env::paths()`; clap's echo was fixed per error kind until it became an allowlist. #60 (PR #115) r1: `Router::layer` gave every route its own pool of 64.
  - #75 (PR #122) r1-r2: the printable-character check was a denylist and missed `Cf` characters; redaction scanned the id and kind prefix and hid clean locations.
  - #117 (PR #125) r1-r3 and r5: hooks printed raw ref names before the scan; an unknown tree mode fell through to "file".
  - #43 (PR #127) r1, r3: core and vault validators disagreed; the vault's deletions and the scanner's squeeze were two predicates.
  - #32 (PR #71) r1-r5: a heuristic denylist guard was re-found each round (comments, query strings, quotes, XML, camelCase, CDATA); it became a soft lint over the exact-match scan.
- **Self-test.**
  - Loop over **every** entry point (each subcommand, route, method, error kind, input form, including one that matches nothing) and assert the policy holds.
  - For two components, assert `shared_set(a) == shared_set(b)`, or feed one generated input through both.

## P11. An open-ended input space fixed one instance per round (promoted to TEST-9)
- **Rule.** TEST-9 is the rule: write the full enumeration and a table-driven test before fixing, and check any "skip what is already handled" proof in both directions.
- **Example.**
  - #117 (PR #125), one more instance of "every path a push publishes is scanned" per round: r1 replace refs and tree-only pushes; r2 empty directories; r3 names joined across `/`; r4 old subtrees under renamed paths (the claim "every ancestor of a new tree is new" was assumed in one direction); r5 non-canonical modes (`40755`).
  - #43 (PR #127) r2-r5: spellings of a display name, found one at a time (decoded views not squeezed, boundary form, mixed encodings, two invisibles) until the matrix test of r5.
  - #32 (PR #71) rw1: TOML escapes the scanner does not decode (`\U` escapes, a line-ending backslash); fixed by refusing every backslash.
  - #75 (PR #122) r2: stored values with whitespace the views do not collapse were missed.
- **Self-test.** The table has one row per element of the written enumeration and fails before the fix. Review it for completeness: for each form git, JSON, percent-encoding or Unicode allows, is there a row? For each optimisation, is there a row where the skipped case is the bad one (an old subtree at a new path)?

## Checklist (run before reporting DONE)
1. **P8:** the ticket has been reread, including amendments, and every criterion maps to a named test.
2. **P1:** for each input key or source, imported or reported? Uniqueness checked over the union?
3. **P2:** for each delete or overwrite, does it restore a reachable goal? Is the goal absolute? Is every "never" invariant tested over many ticks?
4. **P3:** for each file touched, is identity proven read-only first? Have all entry points and sidecars been tried? Does own-file recovery still work? Does every open of a foreign path use `O_NOFOLLOW | O_NONBLOCK`?
5. **P4:** for each parse of untrusted bytes, is there any slicing? Is anything unbounded collected? Does the proptest generate well-formed input with hostile components?
6. **P5:** for each timeout, is it monotonic? Does a clamp leak into stored state?
7. **P6:** is every new error variant tested? Is there no `unwrap_or`/`is_err` collapsing an I/O error?
8. **P7:** is each assertion independent of the code under test? Do the generators reach the interesting branches? Are boundaries covered at -1, exact and +1?
9. **P10:** for each policy, is it enforced at one choke point, as an allowlist, and tested over every entry point? Do two components that must agree share one predicate?
10. **P11:** for an invariant over an open input space, is the enumeration written and table-tested, and is every skip-optimisation proven in both directions?
11. Are deviations, assumptions and anything left undone listed in NOTES FOR VERIFIERS?

Last retro: 2026-11-25, covering PRs #71 (rework), #122, #125 and #127 (retro #130). Earlier: 2026-11-24, PRs #93-#119. P10 recurred in all four PRs and is now SEC-10; P11 is new (TEST-9).
