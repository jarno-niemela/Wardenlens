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
backlog ──refine──▶ ready ──claim──▶ in-progress ──PR opened──▶ in-review ──all verify/* + CI green──▶ (merge) ──▶ done
                     ▲                    ▲                          │
                     │                    └──── changes-requested ◀──┘ (any verifier blocks)
   blocked ──blockers closed──┘
```

| Transition | Who | How |
|---|---|---|
| → ready | controller / human | `scripts/ticket status N ready` |
| ready → in-progress | controller | `scripts/ticket claim N` |
| → in-review | automation | `ticket-sync.yml` on PR open / ready for review |
| → in-progress (again) | automation | `ticket-sync.yml` when the PR is converted to draft |
| → changes-requested | controller | after a blocking verifier finding |
| → done | automation | `ticket-sync.yml` on issue close |
| blocked → ready | controller | `scripts/ticket unblock` |

## Labels

- `type:` epic · task · bug · chore · spike
- `status:` backlog · ready · in-progress · in-review · changes-requested · blocked · done
- `priority:` p0 · p1 · p2 · p3 (required on tasks and bugs)
- `area:<name>` created on demand
- `agent:sonnet` — implemented by the Sonnet implementer; `agent:human` — needs a person
- On PRs, `verify:quality` · `verify:security` · `verify:adversarial` are **display-only**
  mirrors of the verification statuses below. `scripts/verify mark` sets them only when the
  verdict is for the current head SHA, and the `verify-labels-reset` workflow removes all of
  them on every push. They are never the gate.

Run `scripts/labels.sh` to (re)create the taxonomy.

## Verification gate (merge rule)

The gate is a set of **SHA-bound commit statuses**, not labels. Each Opus verdict is recorded
for the exact commit it judged: `scripts/verify mark PR DIM pass|fail SHA` creates the status
`verify/quality`, `verify/security` or `verify/adversarial` on that SHA. A status on an old
commit never counts for a new head, so any push invalidates earlier approval by construction.

A PR may be merged only when **all** hold:

1. `scripts/verify check PR` succeeds: all three `verify/*` statuses are `success` on the
   PR's current head SHA, and CI is green. It prints the head SHA.
   - **Trusted statuses only.** A `verify/*` status counts only if its creator is the operator
     (`gh api user`), is not a Bot, and its description starts with `Opus <dim> verification`.
     Anything else (a workflow token, a collaborator, a hand-written status) is ignored: it
     neither passes nor overrides. The latest status per context is the one with the highest id.
   - **Named CI checks.** Every name in `REQUIRED_CHECKS` at the top of `scripts/verify` must be
     present with bucket `pass` and reported by the workflow named `CI` (a same-named check from
     another workflow does not count): `fmt · clippy · test · doc`, `cargo-deny`,
     `scripts (shellcheck + tooling tests + audit)`. A test asserts the list equals the job
     names in `ci.yml`, so renaming a job cannot silently stop gating. Missing, pending and
     failing all count as failing; `verify/*` contexts are not part of the CI evaluation.
2. The merge pins that SHA, so a push after verification cannot slip in:
   `sha=$(scripts/verify check PR) && gh pr merge PR --squash --delete-branch --match-head-commit "$sha"`.
   The Bash guard hook blocks `gh pr merge` without `--match-head-commit`, and always blocks `--admin`.
3. The PR body has `Closes #N` for its ticket and ticks every acceptance criterion.
4. No unresolved blocker/major findings. Minor findings become follow-up tickets
   (`scripts/ticket task ...`), never silent TODOs.

Test-only follow-up commits (adversary tests worth keeping) do not need re-verification:
`scripts/verify carry PR FROM_SHA` copies the success statuses to the new head, but only if
the diff since `FROM_SHA` only **adds or modifies** files under `crates/*/tests/**` and
`scripts/tests/**`, and every changed entry is a regular file (mode `100644` or `100755`:
symlinks and submodule gitlinks, deletions, type changes, renames and everything else are
refused; a git failure refuses too), and the head has no trusted non-success `verify/*` status.
Only trusted successes are carried. Carried test scripts run unreviewed on the operator's
machine (`scripts/gate` executes every `scripts/tests/**/*.sh`), so the controller must read
the carried files before running the gate.

A verified head is **not** re-verified after `main` moves: the merge pins the head SHA, not
the base. Accepted for now; updating the branch changes the head and therefore requires
re-verification.

The `verify-labels-reset` workflow (`pull_request_target`, no checkout) removes the display
labels on every push; it tolerates only HTTP 404 (label already absent).

**Limitation.** This repository is private on a plan without branch protection, so GitHub does
not enforce the gate: it is enforced by tooling (`scripts/verify check`, the guard hook, and
the `/work` procedure). A human or a tool outside that path can still merge. If the plan
allows it, enable rulesets that require the `verify/quality`, `verify/security`,
`verify/adversarial` status contexts and CI, which makes the gate binding for everyone.

Fix loop: a blocking finding → `status:changes-requested` → implementer resumes
with the findings verbatim → controller runs the gate → re-verify (all three, from scratch,
on the new SHA). After **3 failed rounds** the controller stops, labels the ticket
`agent:human`, and comments with a summary.

## Defence in depth (pushes and merges)

No single control is trusted alone. From strongest to weakest:

1. **`.githooks/pre-push`, authoritative for git pushes.** Git hands it the real ref updates, so
   it does not matter how the command was spelled (refspecs, `-c` config, aliases, wrappers,
   `git` under another path). It refuses any update of `refs/heads/main|master`, any deletion,
   a remote tip that is not present locally (fetch first) and any non-fast-forward update.
   Enable it with `git config core.hooksPath .githooks`; `scripts/gate` fails locally when
   `core.hooksPath` is not `.githooks` (only GitHub Actions, `GITHUB_ACTIONS=true`, skips that
   check), and CI runs `scripts/tests/pre-push.test.sh`. It also refuses any update or deletion
   of an existing remote tag; creating a new tag is allowed.
   - **Scope, stated precisely: the hook covers `git push` only.** It does NOT run under
     `--no-verify`, a `core.hooksPath` override, git plumbing (`send-pack`, `http-push`, remote
     helpers such as `git-remote-https`) or a branch whose committed hook was modified. The guard
     (item 2) denies those spellings on a best-effort basis. GitHub branch protection is
     unavailable on this plan and the owner accepted tooling-only enforcement (#11).
   - **PRs touching `.github/workflows/`, `.githooks/`, `.claude/hooks/` or `.claude/settings.json`
     need explicit security-auditor attention**: a PR could redefine the workflow named "CI" or
     weaken a hook, and the checks that would catch it are the ones being changed.
   - **Rewriting your own feature branch** (`--force-with-lease` after a rebase) is a legitimate
     human workflow, but a pre-push hook cannot tell a lease from a plain force. A non-fast-forward
     update of a `refs/heads/*` branch other than main/master is therefore allowed only when
     `WARDENLENS_ALLOW_REWRITE=1` is set. **Agents never rewrite pushed history**; the Bash guard
     denies any assignment or export of that variable, so only a human can set it.
2. **`.claude/hooks/guard-bash.sh`, best effort, for commands.** Parses each Bash command and
   blocks force pushes, pushes to main, hook bypass, merges without `--match-head-commit`,
   forged statuses and risky `gh api` calls. It catches mistakes early with a readable message;
   it is not a boundary (see ADR 0001 for what it deliberately does not catch).
3. **`scripts/verify`, the merge gate.** Nothing merges without trusted, SHA-bound
   `verify/*` statuses on the current head and green named CI checks.
4. **`.claude/settings.json` permissions.** The allow/deny lists restrict what agents may run
   at all, independently of the guard.

## No neglected tickets

`scripts/ticket-audit` checks every open issue and PR:

| Rule | Severity |
|---|---|
| `type-label` / `status-label`: missing or duplicate `type:` / `status:` label | error |
| `priority-label`: task/bug without exactly one `priority:` | error |
| `orphan-task`: task without an `Epic: #N` line (any line of the body) | error |
| `bad-epic`: `Epic:` points at a missing issue or one not labelled `type:epic` | error |
| `review-without-pr`: `in-review`/`changes-requested` without an open PR that closes it | error |
| `blocked-no-reason`: `blocked` without a `Blocked by: #N` line | error |
| `bad-blocker`: a blocker number that is neither an issue nor a PR (never reported as unblocked) | error |
| `self-blocker`: a ticket lists itself as a blocker | error |
| `pr-no-issue`: open PR that closes no issue (bots such as Dependabot are exempt) | error |
| `pr-bad-ref`: open PR closes a number that is not an issue | error |
| `stale-in-progress`: `in-progress` > `STALE_DAYS` (3) without an open PR | warn |
| `unassigned-in-progress`: `in-progress` with nobody assigned | warn |
| `unblocked`: `blocked` whose blockers (issues and PRs) are all closed | warn |
| `ready-but-blocked`: `ready` with open blockers | warn |
| `empty-epic`: epic with no tasks | warn |
| `epic-complete`: all of an epic's tasks closed; close the epic | warn |
| `closed-epic`: open task whose parent epic is closed | warn |
| `done-but-open`: labelled `status:done` but still open | warn |
| `stale-pr`: open non-draft PR > `PR_DAYS` (2) without approval (exempt when all three `verify:*` labels are set) | warn |
| `stale-backlog`: backlog untouched > `BACKLOG_DAYS` (30) | info |
| `closed-stale-status`: closed issue with a `status:` label other than `done` | info |

Closing references are read from the PR **body** only (GitHub does not link titles): the
keywords close/fix/resolve in any tense, followed by `#N`, `owner/repo#N` or an issue URL.
References (closing and `Blocked by`, including task-list lines such as `- [ ] Blocked by #2`)
count only when they point at **this** repository (exact owner/name, case-insensitive); other
repositories are ignored, and `ticket next` skips a ticket that is blocked by a foreign repo.
PR rules apply to open PRs only; merged and closed PRs are ignored. A blocker counts as open
if it is an open issue **or** an open PR.

It runs: at the start and end of every `/work` iteration; in CI (the `tooling` job runs
`scripts/ticket-audit --fail-on never`, informational only: it never fails the build); and
daily via `ticket-audit.yml`, which keeps a single "Ticket audit report" issue (created by the
bot with `agent:human`, `needs:triage`) up to date and closes it when there are no error or warn
findings. That issue is not a work item.

## Branches, commits, PRs

- Branch: `<type>/<issue>-<slug>`, e.g. `feat/12-config-parser`.
- Implementers work in a git worktree (`.claude/worktrees/`), so the controller's
  checkout stays clean and several tickets can progress in parallel.
- Conventional commits with `Refs #N`; PR body `Closes #N`; **squash merge**;
  branch deleted after merge.
- `main` is never pushed to directly (enforced by the Bash guard hook, which also blocks force pushes, hook bypass flags, merges without `--match-head-commit` and risky `gh api` calls; it fails closed if `jq` is missing).

## Day-to-day commands

| Goal | Command |
|---|---|
| Plan a new epic | `/plan-epic <description>` |
| File one ticket | `/new-ticket <description>` |
| Work the queue | `/work` (next ticket) · `/work 12` · `/work --loop` |
| Re-verify a PR | `/verify <pr>` |
| Merge gate status | `scripts/verify check <pr>` |
| Ticket hygiene | `/ticket-audit` |
| See status | `scripts/ticket list [state]` · `scripts/ticket epic-progress N` |
