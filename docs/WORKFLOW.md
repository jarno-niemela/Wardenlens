# Agentic Development Workflow

GitHub Issues are the single source of truth for work. Agents never work on
anything that is not a ticket, and every ticket is always in exactly one
visible state.

## Roles

| Role | Who | Model | Does | Never does |
|---|---|---|---|---|
| **Controller** | Main Claude Code session running `/work` | Opus | Picks tickets, dispatches subagents, moves labels, opens and merges PRs | Writes production code itself |
| **Planner** | `planner` subagent | Opus | Splits an epic into small, ordered, testable tasks | Implements |
| **Implementer** | `implementer` subagent | **Sonnet** | Writes tests + code for one task on its branch, runs the gate, commits | Merges, edits other tickets, reviews its own work |
| **Reviewer** | `reviewer` subagent | **Opus** | Code-quality review against `CODING_GUIDELINES.md` | Edits code |
| **Security auditor** | `security-auditor` subagent | **Opus** | Threat-models the diff, checks deps and trust boundaries | Edits code |
| **Adversary** | `adversary` subagent | **Opus** | Tries to break the change: writes failing tests, hostile inputs | Fixes what it breaks |

Subagents cannot spawn subagents, so orchestration lives in the controller
(the main session). Verification runs in fresh contexts that never saw the
implementer's reasoning — they judge only the diff, the ticket and the code.

## Ticket hierarchy

```
Epic  (type:epic)          outcome-level, weeks
 └─ Task (type:task)       one PR, < ~400 lines, hours
     body starts with:     Epic: #<epic>
                           Blocked by: #a, #b        (optional)
```

`Epic: #N` in the task body is authoritative (it is what the tooling reads);
tasks are also attached as native GitHub sub-issues for the UI. Bugs
(`type:bug`), chores and spikes may stand alone.

## State machine (`status:*`, exactly one per open ticket)

```
backlog ──refine──▶ ready ──claim──▶ in-progress ──PR opened──▶ in-review ──all verify:* + CI green──▶ (merge) ──▶ done
                     ▲                    ▲                          │
                     │                    └──── changes-requested ◀──┘ (any verifier blocks)
   blocked ──blockers closed──┘
```

| Transition | Who | How |
|---|---|---|
| → ready | controller / human | `scripts/ticket status N ready` |
| ready → in-progress | controller | `scripts/ticket claim N` |
| → in-review | automation | `ticket-sync.yml` on PR open |
| → changes-requested | controller | after a blocking verifier finding |
| → done | automation | `ticket-sync.yml` on issue close |
| blocked → ready | controller | `scripts/ticket unblock` |

## Labels

- `type:` epic · task · bug · chore · spike
- `status:` backlog · ready · in-progress · in-review · changes-requested · blocked · done
- `priority:` p0 · p1 · p2 · p3 (required on tasks and bugs)
- `area:<name>` created on demand
- `agent:sonnet` — implemented by the Sonnet implementer; `agent:human` — needs a person
- On PRs, `verify:quality` · `verify:security` · `verify:adversarial` — added only by
  the controller after the matching Opus agent returns PASS. **Any new push to the
  PR removes all `verify:*` labels** (`verify-gate.yml`), so approval always refers to
  the final code. The `verify-gate` check fails until all three are present.

Run `scripts/labels.sh` to (re)create the taxonomy.

## Verification gate (merge rule)

A PR may be merged only when **all** hold:

1. CI is green (fmt, clippy `-D warnings`, tests, docs, cargo-deny).
2. `verify:quality`, `verify:security`, `verify:adversarial` are present.
3. The PR body has `Closes #N` for its ticket and ticks every acceptance criterion.
4. No unresolved blocker/major findings. Minor findings become follow-up tickets
   (`scripts/ticket task ...`), never silent TODOs.

Fix loop: a blocking finding → `status:changes-requested` → implementer resumes
with the findings verbatim → gate → re-verify (all three, from scratch). After
**3 failed rounds** the controller stops, labels the ticket `agent:human`, and
comments with a summary.

## No neglected tickets

`scripts/ticket-audit` checks every open issue and PR:

| Rule | Severity |
|---|---|
| missing/duplicate `type:` or `status:` label | error |
| task/bug without exactly one `priority:` | error |
| task without valid `Epic: #N` | error |
| `in-review`/`changes-requested` without an open PR | error |
| `blocked` without `Blocked by:` | error |
| PR that closes no issue | error |
| `in-progress` > `STALE_DAYS` (3) without PR, or unassigned | warn |
| blocked whose blockers are all closed | warn |
| ready with open blockers | warn |
| epic with no tasks / with all tasks closed | warn |
| PR open > `PR_DAYS` (2) without approval | warn |
| backlog untouched > `BACKLOG_DAYS` (30) | info |
| closed issue with stale `status:` label | info |

It runs: at the start and end of every `/work` iteration; in CI on every PR
(`--fail-on never`, informational); and daily via `ticket-audit.yml`, which
keeps a single "Ticket audit report" issue up to date (closing it when clean).

## Branches, commits, PRs

- Branch: `<type>/<issue>-<slug>`, e.g. `feat/12-config-parser`.
- Implementers work in a git worktree (`.claude/worktrees/`), so the controller's
  checkout stays clean and several tickets can progress in parallel.
- Conventional commits with `Refs #N`; PR body `Closes #N`; **squash merge**;
  branch deleted after merge.
- `main` is never pushed to directly (enforced by the Bash guard hook).

## Day-to-day commands

| Goal | Command |
|---|---|
| Plan a new epic | `/plan-epic <description>` |
| File one ticket | `/new-ticket <description>` |
| Work the queue | `/work` (next ticket) · `/work 12` · `/work --loop` |
| Re-verify a PR | `/verify <pr>` |
| Ticket hygiene | `/ticket-audit` |
| See status | `scripts/ticket list [state]` · `scripts/ticket epic-progress N` |
