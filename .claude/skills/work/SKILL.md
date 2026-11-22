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
```
Fix hygiene findings you can resolve unambiguously (missing labels on tickets you can classify, stale status on closed issues). Report the rest to the user. Prefer finishing work already `in-review` / `changes-requested` / stale `in-progress` over starting new work — nothing gets abandoned.

## 1. Select and claim
- Ticket = the argument, else `scripts/ticket next`. If none: report "queue empty", show `scripts/ticket list`, stop.
- `gh issue view N` — read it fully. If acceptance criteria are missing or vague, refine the ticket body first (or label `agent:human` and ask) — never implement a vague ticket.
- `scripts/ticket claim N`
- Branch `<type>/<N>-<slug>` (type from conventional title: feat/fix/refactor/chore/docs/test).
```bash
git worktree add .claude/worktrees/N -b <branch> origin/main
```

## 2. Implement (Sonnet)
Dispatch the `implementer` subagent with: ticket number, full ticket body, worktree path, branch. On `NEEDS_CLARIFICATION`: answer from the codebase/ticket if you can, else comment the questions on the issue, label it `agent:human`, return it to `status:backlog`, remove the worktree, and move on. On `DONE`: verify the claims yourself — run `scripts/gate` in the worktree; do not trust the report alone.

## 3. Open the PR
```bash
git -C .claude/worktrees/N push -u origin <branch>
gh pr create --head <branch> --title "<conventional title> (#N)" --body-file <filled .github/pull_request_template.md with Closes #N>
gh pr edit <pr> --add-label agent:sonnet
```
`ticket-sync.yml` moves the issue to `status:in-review`. Wait for the `verify-gate` run for the head SHA to finish (it strips stale `verify:*` labels) before you label anything.

## 4. Verify (Opus, in parallel, fresh context)
Launch **in one message** three subagents — `reviewer`, `security-auditor`, `adversary` — each given: PR number, ticket number + body, worktree path. Do not pass the implementer's reasoning; verifiers judge the code, not the story.

Collect verdicts:
- All PASS / SURVIVED → step 6.
- Any BLOCK / BROKEN (blocker or major) → step 5.
- Minor findings → file follow-ups now: `scripts/ticket task <epic> "<title>" -p p3 -F body.md` (bugs: `-t bug`). Link them in a PR comment.

## 5. Fix loop (max 3 rounds)
1. `scripts/ticket status N changes-requested`; post the consolidated findings as a PR comment (`gh pr comment`).
2. Re-dispatch the `implementer` with the findings verbatim and the adversary's failing tests (tell it to commit those tests — they are now regression tests).
3. Gate → push → back to step 4 with **all three** verifiers from scratch. `scripts/ticket status N in-review`.
4. After round 3 still failing: stop. Comment a summary, label issue and PR `agent:human`, leave it `changes-requested`, report to user, continue with the next ticket if `--loop`.

## 6. Label and merge
Adversary tests listed under WORTH KEEPING: have the implementer commit them (test-only), push, wait for CI. A test-only commit derived from the adversary's own output does not require re-verification — note this in a PR comment. Then:
```bash
gh pr edit <pr> --add-label verify:quality,verify:security,verify:adversarial
gh pr checks <pr> --watch --fail-fast                # CI + verify-gate must be green
gh pr merge <pr> --squash --delete-branch
git worktree remove .claude/worktrees/N && git fetch -q origin
```
Never merge with a red or pending check, missing `verify:*` label, or unticked acceptance criterion. Never use `--admin`.

## 7. Close out
- Confirm the issue closed and is `status:done` (`ticket-sync.yml`); fix if not.
- `scripts/ticket epic-progress <epic>`; if all tasks closed, verify the epic's acceptance criteria and close it.
- `scripts/ticket-audit --fail-on never`.
- Report: ticket, PR link, rounds needed, findings fixed, follow-ups filed.
- With `--loop`, go to step 0.
