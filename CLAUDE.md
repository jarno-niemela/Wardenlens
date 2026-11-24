# Wardenlens — agent instructions

Rust workspace developed through GitHub-issue tickets by a controller + subagent team.
Keep this file short; details live in the linked docs.

## Non-negotiables
- **No work without a ticket.** Every change maps to an issue (`type:task|bug|chore|spike`); tasks have `Epic: #N`.
- **Never push to `main`.** Branch `<type>/<issue>-<slug>`, PR with `Closes #N`, squash merge.
- **Labels must be truthful**: exactly one `status:*` per open issue. Use `scripts/ticket`, not hand-edits.
- **Sonnet implements, Opus verifies.** Production code is written by the `implementer` subagent; a PR merges only with SHA-bound `verify/quality`, `verify/security`, `verify/adversarial` statuses + green CI (`scripts/verify check`, then `gh pr merge --match-head-commit`).
- **`scripts/gate` passes before every push.** Never weaken lints, skip hooks (`--no-verify`) or delete tests to get green.
- Follow `docs/CODING_GUIDELINES.md` (cite rule IDs in reviews). No `unsafe`, no panics in non-test code.

## Map
- `crates/wardenlens-core` — pure domain logic (no I/O) · `crates/wardenlens-cli` — binary `wardenlens`
- `docs/WORKFLOW.md` — ticket lifecycle, labels, roles, merge gate · `docs/CODING_GUIDELINES.md` · `docs/adr/`
- `.claude/agents/` — implementer (sonnet), reviewer / security-auditor / adversary / planner (opus)
- `.claude/skills/` — `/work`, `/plan-epic`, `/new-ticket`, `/verify`, `/ticket-audit`, `rust-guidelines`, `defect-patterns` (read before DONE), `/retro` (`improve-skills`: turn review findings into skill updates)
- `.claude/hooks/` — Bash guard (no force-push / push to main / `--no-verify` / `--admin` / merge without `--match-head-commit`), rustfmt on edit
- `scripts/ticket` (create/claim/status/next/list/epic-progress/unblock), `scripts/ticket-audit`, `scripts/verify` (mark/check/carry the SHA-bound verification gate), `scripts/gate`, `scripts/labels.sh`

## Commands
```bash
scripts/gate                 # fmt, clippy -D warnings, tests, tooling tests, shellcheck, docs, cargo-deny
scripts/ticket next          # next ready ticket
scripts/ticket-audit         # neglected / mislabelled tickets
```

## Environment
Toolchain pinned in `rust-toolchain.toml`. If `cargo` is not on PATH: `source ~/.cargo/env`.
Git hooks: `git config core.hooksPath .githooks` — required, `scripts/gate` fails otherwise. `.githooks/pre-push` is the authoritative block on pushes to `main`, deletions and force pushes; never bypass it or set `WARDENLENS_ALLOW_REWRITE` (human-only).
