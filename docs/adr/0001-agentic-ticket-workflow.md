# 0001. Agentic, ticket-driven workflow with adversarial verification

- Status: accepted
- Date: 2026-11-22
- Ticket: see the "Agentic development workflow" epic

## Context
The project is developed primarily by AI agents. Agents lose context between
sessions, tend to approve their own work, and can quietly abandon tasks.
We need durable state, independent verification and neglect detection.

## Decision
- **GitHub Issues are the source of truth**: epics → tasks (`Epic: #N` line,
  plus native sub-issues for the UI), with a mutually-exclusive `status:*` label
  state machine (see `docs/WORKFLOW.md`).
- **Controller/subagent layout**: the main session (Opus) orchestrates via the
  `/work` skill. Subagents cannot nest, so orchestration cannot live in a subagent.
- **Model split**: a Sonnet `implementer` writes code (cheaper, fast, good at
  well-specified tasks); three Opus verifiers run in fresh contexts — `reviewer`
  (quality), `security-auditor`, and `adversary` (tries to break the change with
  failing tests). Separating writer and judge counters self-approval bias.
- **Gate bound to a commit**: each verdict is a commit status `verify/quality|security|adversarial`
  on the exact SHA verified (`scripts/verify mark`). `scripts/verify check` requires all three on the
  current head plus green CI, and the merge uses `--match-head-commit` with that SHA, so approval
  always refers to the final code. `verify:*` labels are display-only and are reset on every push
  by the `verify-labels-reset` workflow. Test-only follow-ups may carry verdicts forward
  (`scripts/verify carry`). CI enforces fmt/clippy/tests/docs/cargo-deny and the tooling tests.
- **Guard hook**: a fail-closed Bash hook blocks force pushes, pushes to main, hook bypass,
  `gh pr merge` without `--match-head-commit <sha|$var>`, merge/delete calls and status writes
  through `gh api`, and piping into a shell. It is a safety net against mistakes, not a security
  boundary. Accepted limitations: code inside interpreter string literals (`python3 -c`,
  `perl -e`, `node -e`, awk `system()`), `$'...'` quoting, `$(echo ...)` and variable
  indirection, and aliases.
- **Neglect detection**: `scripts/ticket-audit` (pure jq rules with offline tests)
  runs every `/work` iteration and daily in CI.
- **Tooling in bash + jq** for bootstrap; a Rust port is tracked as a ticket.

## Consequences
- Every change costs at least four agent runs; accepted for reliability.
- The repository is private on a plan without branch protection, so the gate is enforced by
  tooling (`scripts/verify check`, the guard hook), not by GitHub. Enable rulesets requiring the
  `verify/*` status contexts if the plan allows it; until then the gate binds the agents only.
- Label hygiene becomes critical; it is automated (`ticket-sync.yml`) and audited.
