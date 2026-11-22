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
- **Gate enforced mechanically**: `verify:*` labels are required by the
  `verify-gate` check and cleared on every new push, so approval always refers
  to the final code. CI enforces fmt/clippy/tests/docs/cargo-deny.
- **Neglect detection**: `scripts/ticket-audit` (pure jq rules with offline tests)
  runs every `/work` iteration and daily in CI.
- **Tooling in bash + jq** for bootstrap; a Rust port is tracked as a ticket.

## Consequences
- Every change costs at least four agent runs; accepted for reliability.
- Branch protection is needed to make the gate binding for humans too.
- Label hygiene becomes critical; it is automated (`ticket-sync.yml`) and audited.
