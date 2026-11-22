---
name: work
description: Controller loop that drives a ticket from ready to merged — claims the next ready GitHub issue (or a given number), has the Sonnet implementer build it in a worktree, runs Opus reviewer + security-auditor + adversary verification, loops on findings, opens the PR, labels it, and squash-merges. Use when the user says work on tickets, /work, /work 12, /work --loop, or "continue development".
argument-hint: "[issue-number | --loop]"
---

# /work — controller loop

You are the **controller**. You orchestrate; you do not write production code. Delegate implementation to the `implementer` subagent and judgement to the Opus verifiers. Keep the ticket's labels truthful at every step. Read `docs/WORKFLOW.md` if you have not this session.

Arguments: `$ARGUMENTS` — an issue number, `--loop` (repeat until no ready tickets), or empty (one ticket).

## 0. Preflight
```bash
git fetch -q origin && git status --short          # controller checkout must be clean
scripts/ticket unblock                              # promote tickets whose blockers closed
scripts/ticket-audit --fail-on never                # surface neglect before choosing work
scripts/agents list                                 # agents left in flight by a previous session or a usage-limit stop
```
Inflight agents come **before** new work. Act on every row flagged `STALE` (relaunch at the new head) or `UNKNOWN` (check the PR by hand): resume or relaunch each one per "Usage-limit recovery" in `docs/WORKFLOW.md` (`SendMessage` "limit reset, continue", else relaunch from the saved prompt at the recorded SHA; if the PR head moved, relaunch at the new head). Their verdicts still bind only to the recorded SHA.
Fix hygiene findings you can resolve unambiguously (missing labels on tickets you can classify, stale status on closed issues). Report the rest to the user. Prefer finishing work already `in-review` / `changes-requested` / stale `in-progress` over starting new work — nothing gets abandoned.

## Recording agents (every launch, every step)
For every subagent: write its exact prompt to a file in the scratchpad, run `scripts/agents check PROMPT_FILE` first, save the prompt, launch, then `scripts/agents record ROLE REF SHA PROMPT_FILE AGENT_ID` with the id the launch returned (the `SendMessage` target for resume), e.g. launch returns `a1b2c3d4e5f60718` -> `scripts/agents record implementer '#29' $SHA "$SCRATCH/29-impl.prompt" a1b2c3d4e5f60718` (quote `#N`). REF = `#N` (ticket) for the implementer, the PR number for verifiers; SHA = the commit it works on or verifies. When its report arrives, run `scripts/agents done AGENT_ID`. If an agent dies with a rate-limit failure ("You've hit your 5-hour limit · resets HH:MM", HTTP 429), run `scripts/agents fail AGENT_ID rate_limit HH:MM`, do no other work that needs the model until the reset, then resume it. Never mark a `verify/*` status from a partial or interrupted report: re-run that verifier first.

## 1. Select and claim
- Ticket = the argument, else `scripts/ticket next`. If none: report "queue empty", show `scripts/ticket list`, stop.
- `gh issue view N` — read it fully. If acceptance criteria are missing or vague, refine the ticket body first (or label `agent:human` and ask) — never implement a vague ticket.
- `scripts/ticket claim N`
- Branch `<type>/<N>-<slug>` (type from conventional title: feat/fix/refactor/chore/docs/test).
```bash
git worktree add .claude/worktrees/N -b <branch> origin/main
```

## 2. Implement (Sonnet)
Dispatch the `implementer` subagent with: ticket number, full ticket body, worktree path, branch. Outcomes:
- `NEEDS_CLARIFICATION`: answer from the codebase/ticket if you can, else comment the questions on the issue, label it `agent:human`, return it to `status:backlog`, remove the worktree, and move on.
- `BLOCKED`: comment the blocker on the issue. If another ticket blocks it, `scripts/ticket status N blocked` and add a `Blocked by: #M` line to its body; otherwise label it `agent:human` and set `status:backlog`. Remove the worktree and continue with the next ticket.
- `DONE`: verify the claims yourself. **You** run `scripts/gate` in the worktree; do not trust the report alone.

The `Ticket audit report` issue is never a work item: do not claim it, route it to `/ticket-audit`.

## 3. Open the PR
```bash
git -C .claude/worktrees/N push -u origin <branch>
gh pr create --head <branch> --title "<conventional title> (#N)" --body-file <filled .github/pull_request_template.md with Closes #N>
gh pr edit <pr> --add-label agent:sonnet
```
`ticket-sync.yml` moves the issue to `status:in-review`. Record the commit under verification: `SHA=$(gh pr view <pr> --json headRefOid -q .headRefOid)`. Wait for CI on that SHA to start; the `verify-labels-reset` workflow only clears display labels on new pushes.

## 4. Verify (Opus, in parallel, fresh context)
The gate result comes from your own `scripts/gate` run (step 2); pass it to the verifiers instead of making them rerun it in a shared worktree. Give each verifier: PR number, ticket number + body, `SHA`, the gate result.
- `adversary`: its own detached worktree at the verified commit: `git worktree add --detach .claude/worktrees/N-adv $SHA`.
- `reviewer` and `security-auditor`: read the main worktree; they must not run the gate there.

Launch **in one message** `reviewer`, `security-auditor`, `adversary`. Do not pass the implementer's reasoning; verifiers judge the code, not the story.

Record each verdict (only from a complete report, never a partial or interrupted one) against the exact commit, one call per dimension:
```bash
scripts/verify mark <pr> quality|security|adversarial pass|fail $SHA
```
This sets the SHA-bound commit status `verify/DIM` (the actual merge gate) and, only if `$SHA` is still the PR head, the display label.

Collect verdicts:
- All PASS / SURVIVED: step 6.
- Any BLOCK / BROKEN (blocker or major): step 5.
- Minor findings: file follow-ups now: `scripts/ticket task <epic> "<title>" -p p3 -F body.md` (bugs: `-t bug`). Link them in a PR comment.

## 5. Fix loop (max 3 rounds)
1. `scripts/ticket status N changes-requested`; post the consolidated findings as a PR comment (`gh pr comment`).
2. Re-dispatch the `implementer` with the findings verbatim and the adversary's failing tests (tell it to commit those tests: they are now regression tests).
3. You run the gate, push, set `SHA` to the new head, and go back to step 4 with **all three** verifiers from scratch. `scripts/ticket status N in-review`. Statuses on the old SHA do not count for the new head.
4. After round 3 still failing: stop. Comment a summary, label issue and PR `agent:human`, leave it `changes-requested`, report to user, continue with the next ticket if `--loop`.

## 6. Keep adversary tests and merge
Passing adversary tests listed under WORTH KEEPING: copy them from the adversary worktree into the PR branch, commit them (test-only), run the gate, push, then:
```bash
scripts/verify carry <pr> $SHA        # refuses unless the diff since $SHA touches only crates/*/tests/** or scripts/tests/**
```
Then merge only on the exact verified head:
```bash
gh pr checks <pr> --watch --fail-fast
sha=$(scripts/verify check <pr>) && gh pr merge <pr> --squash --delete-branch --match-head-commit "$sha"
git worktree remove .claude/worktrees/N && git fetch -q origin
```
Remove the adversary worktree as its own step, only after its tests have been copied out: `git worktree remove --force .claude/worktrees/N-adv` (it holds untracked files, so `--force` is needed).
`scripts/verify check` succeeds only when all three `verify/*` statuses are `success` on the current head and every other check is green; the guard hook blocks `gh pr merge` without `--match-head-commit`. Never merge with a red or pending check, an unticked acceptance criterion or a head that changed after verification. Never use `--admin`.

## 7. Close out
- Confirm the issue closed and is `status:done` (`ticket-sync.yml`); fix if not.
- `scripts/ticket epic-progress <epic>`; if all tasks closed, verify the epic's acceptance criteria and close it.
- `scripts/ticket-audit --fail-on never`.
- Report: ticket, PR link, rounds needed, findings fixed, follow-ups filed.
- With `--loop`, go to step 0.
