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
- **Split before implementing** when the ticket spans a library and its CLI or git/workflow integration, or carries several rounds of amendments. Keep the pure library in N, file the rest as a new ticket blocked by N, and record the split as an amendment comment on N. Strike the moved criteria in N's body, with a pointer to the new ticket, so merge rule 3 does not still require them. The unsplit #74 vault and #32 catalogue hit the 5-round cap; the split #94 CLI took 3 rounds.
- **Amending a ticket:** if the rule comes from an ADR, change the ADR first and mirror it into the ticket. Never add new rules to a ticket while its ADR is still under verification. In PR #77, ticket bullets drifted from the ADR, which wins, and that cost a major.
- **Real devices and site data:** spike tickets are read-only towards cameras. A write needs the owner's approval for that one change: read and record the old value first, change nothing else, and revert when done. Code, docs and briefs name cameras by inventory id only; LAN addresses, credentials, serials and display names never enter the repo or a brief.
- Scratch git experiments, by you or in a brief, use `git -C <absolute temp path>` only; a failed `cd` once let `git reset --hard` run in the main checkout (#117 r1). Say so in every implementer brief.
- `scripts/ticket claim N`
- Branch `<type>/<N>-<slug>` (type from conventional title: feat/fix/refactor/chore/docs/test).
```bash
git worktree add .claude/worktrees/N -b <branch> origin/main
```

## 2. Implement (Sonnet)
Dispatch the `implementer` subagent with: ticket number, full ticket body, worktree path, branch. For a high-risk ticket, name the `defect-patterns` entries that apply in the brief and the self-tests you expect for each. High risk means destructive actions, parsing untrusted bytes, touching files the program did not create, clocks or timeouts, or merging several inputs into one key space. Getting these into round 1 is the cheapest way to save rounds. Outcomes:
- `NEEDS_CLARIFICATION`: answer from the codebase/ticket if you can, else comment the questions on the issue, label it `agent:human`, return it to `status:backlog`, remove the worktree, and move on.
- `BLOCKED`: comment the blocker on the issue. If another ticket blocks it, `scripts/ticket status N blocked` and add a `Blocked by: #M` line to its body; otherwise label it `agent:human` and set `status:backlog`. Remove the worktree and continue with the next ticket.
- `DONE`: verify the claims yourself. **You** run `scripts/gate` in the worktree; do not trust the report alone.

The `Ticket audit report` issue is never a work item: do not claim it, route it to `/ticket-audit`.

## 3. Open the PR
Every push below is chained: `scripts/gate && <CI's shellcheck line> && git push`. CI's command is the `run: shellcheck …` line in `.github/workflows/ci.yml` (no `-x`; the gate's has `-x`), run from the worktree.
```bash
(cd /abs/.claude/worktrees/N && scripts/gate && <CI shellcheck line> ) && git -C .claude/worktrees/N push -u origin <branch>
gh pr create --head <branch> --title "<conventional title> (#N)" --body-file <filled .github/pull_request_template.md with Closes #N>
gh pr edit <pr> --add-label agent:sonnet
```
**Bring the branch up to date before every verification round.** If `origin/main` moved, run `git merge origin/main` in the worktree. Rework commits stay separate from the merge of main (#32). Resolve a `Cargo.lock` conflict with `git checkout --theirs Cargo.lock` and a cargo re-resolve, and resolve `lib.rs` module lists by union. Then run the gate, CI's exact shellcheck and the push, chained with `&&` as above. Updating first means the verified head is the one that merges; updating after verification changes the head and needs re-verification.

**Pipeline:** while one PR verifies, start the next ticket's implementer in its own worktree. Never verify two branches that conflict (5b).

`ticket-sync.yml` moves the issue to `status:in-review`. Record the commit under verification: `SHA=$(gh pr view <pr> --json headRefOid -q .headRefOid)`. Wait for CI on that SHA to start; the `verify-labels-reset` workflow only clears display labels on new pushes.

## 4. Verify (Opus, in parallel, fresh context)
The gate result comes from your own `scripts/gate` run (step 2); pass it to the verifiers instead of making them rerun it in a shared worktree. Give each verifier: PR number, ticket number + body, `SHA`, the gate result.
- `adversary`: its own detached worktree at the verified commit: `git worktree add --detach .claude/worktrees/N-adv $SHA`.
- `reviewer` and `security-auditor`: read the main worktree; they must not run the gate there.

Launch **in one message** `reviewer`, `security-auditor`, `adversary`. Do not pass the implementer's reasoning; verifiers judge the code, not the story.

Record each verdict (only from a complete report, never a partial or interrupted one) against the exact commit, one call per dimension. **Record each one as soon as it arrives, all three, before any `verify carry`** (#117 and #43 once carried with a verdict unrecorded); if `carry` reports fewer than 3, re-run it once or twice, because the status API can lag. If it still reports fewer than 3, run `scripts/verify check`, and mark the missing verdict on the verified SHA (`verify mark`) before merging:
```bash
scripts/verify mark <pr> quality|security|adversarial pass|fail $SHA
```
This sets the SHA-bound commit status `verify/DIM` (the actual merge gate) and, only if `$SHA` is still the PR head, the display label.

Collect verdicts:
- All PASS / SURVIVED: step 6.
- Any BLOCK / BROKEN (blocker or major): step 5.
- Minor findings: file follow-ups now: `scripts/ticket task <epic> "<title>" -p p3 -F body.md` (bugs: `-t bug`). Link them in a PR comment.

## 5. Fix loop (max 5 rounds)
**Writing a design ruling into a fix brief.** Most extra rounds came from rulings that fixed one case and broke another. Before sending a ruling:
- **Ask for the class, not the instance.** When a finding is one case of a rule (one subcommand skipping a refusal, one error kind echoing input), the brief asks for the rule at its choke point, as a pass-list or exact match, with a test over every case (P10, SEC-10).
- **Name the invariant and the surface (TEST-9).** For an open-ended input space, the brief states the invariant ("every full path a push publishes is scanned"), asks for the written enumeration and a table test before the fix, and has the implementer check any "skip what is already handled" proof in both directions. #117 took six rounds, one instance each (replace refs, empty directories, names across `/`, old subtrees under renamed paths, mode `40755`); #43 took four more for scanner spellings (P11).
- **Keep fix rounds in scope.** A ticket that pulls in another crate's behaviour (#43 changed the vault and the scanner) is split into its own ticket at r1, not widened by a brief.
- **State the invariant** the fix must keep, quoting the ticket's "never …" sentences and the ADR principle.
- **Apply it symmetrically.** If it holds for the archive tier, it must hold for the hot tier, and the same goes for `create` versus `open`.
- **Check it against the committed adversary tests.** For stateful logic, simulate several ticks by hand.
  - In #44, "delete toward the target" re-broke minimality in round 2, and "ratchet the budget unconditionally" would have re-broken the no-drain property in round 5.
  - In #104, "refuse any sidecar" broke the vault's own crash recovery.
- **Prefer absolute targets over per-tick amounts,** and typed distinct errors over reused ones.
- **Name every committed test or invariant the ruling intentionally changes.** The implementer reports `NEEDS_CLARIFICATION` for any contradiction you did not name. In a fix round, resolve that by correcting and re-issuing the brief (the PR stays open, the ticket stays `changes-requested`); do not use the step-2 backlog path. If it is a real spec question you cannot answer, ask the owner with the ticket still `changes-requested` and the PR open.

1. `scripts/ticket status N changes-requested`; post the consolidated findings as a PR comment (`gh pr comment`).
2. Re-dispatch the `implementer` with the findings verbatim and the adversary's failing tests (tell it to commit those tests: they are now regression tests).
3. You run, chained with `&&`, the gate, then CI's exact shellcheck (the `run: shellcheck …` line in `.github/workflows/ci.yml`, no `-x`), then push, and set `SHA` to the new head. Go back to step 4 with **all three** verifiers from scratch. `scripts/ticket status N in-review`. Statuses on the old SHA do not count for the new head.
4. After round 5 still failing: stop. Comment a summary, label issue and PR `agent:human`, leave it `changes-requested`, report to user, continue with the next ticket if `--loop`.

**At the cap** (as with #74 / PR #97; the binding rule is "Owner override at the cap" in `docs/WORKFLOW.md`):
- **Rethink before asking.** State the root cause and a complete fix design, not just another patch.
- **Ask the owner with a chooser.** Only the owner's own message in this session counts as the choice, never memory, `--loop` autonomy or an agent's report. Options: another round with the rethought design, merge now with a p1 follow-up, or pause. Give the risk of each and a recommendation.
- **If the owner chooses to merge:**
  - File the follow-up first: the remaining defect, the rethought design, and the failing adversary tests saved outside the repo (e.g. `~/.local/state/wardenlens/carry/`). Do not commit failing tests to the branch.
  - Post a PR comment headed **"Owner override"** that quotes the owner's choice and states the independent verdicts (BLOCK/BROKEN) and the follow-up number.
  - Leave each acceptance criterion the remaining defect breaks unticked in the PR body, marked "deferred to #M under owner override" with the follow-up's number.
  - Only then set the `verify/*` statuses to success. They record the override, not an independent pass.

## 5b. Running verification in parallel
Two PRs can be verified at once only if a trial merge of both onto `origin/main` is clean. Use a scratch clone (`/tmp/claude-1000/mt`) with a throwaway identity (`git -c user.name=t -c user.email=t@example.invalid merge …`) for the trial only. **Never push from the scratch clone**: it has no `core.hooksPath`, so `.githooks/pre-push` would not run. Almost every core PR adds a `pub mod` line to `crates/wardenlens-core/src/lib.rs`, so two such PRs conflict. Verify those one after another, and merge whichever is closer to passing first. Resolve the real conflict in the PR's own hooked worktree (`git merge origin/main`, the union of both module lists, sorted), then run the gate, CI's exact shellcheck and the push, chained with `&&`. The new head needs all three verifiers again. That re-verification is not a fix round and does not count toward the cap; name its briefs `<ticket>-<role>-rN-reverify.md` so `/retro` does not count them. It costs as much as a round, so prefer merging the closer PR first over verifying both.

## 6. Keep adversary tests and merge
Passing adversary tests listed under WORTH KEEPING: first read them for sleeps, racing threads or wall-clock bounds (a timing-dependent test goes to a follow-up ticket, never to main), and check their location: only files under `crates/*/tests/**` or `scripts/tests/**` can be carried; tests in a `src/` test module are saved outside the repo and go to the follow-up. Copy the rest from the adversary worktree into the PR branch, commit them (test-only), run the gate, CI's exact shellcheck and the push, chained with `&&`, then:
```bash
scripts/verify carry <pr> $SHA        # refuses unless the diff since $SHA touches only crates/*/tests/** or scripts/tests/**
```
Then merge only on the exact verified head:
```bash
gh pr checks <pr> --watch --fail-fast
sha=$(scripts/verify check <pr>) && gh pr merge <pr> --squash --delete-branch --match-head-commit "$sha"
git worktree remove .claude/worktrees/N && git fetch -q origin
```
Run `cargo fmt --all` after copying adversary files; the pre-commit hook rejects unformatted test files. If an adversary test fails only because of an accepted **minor** or a deferred item, mark it `#[ignore = "follow-up #N"]` and file #N; never delete it. A test showing a blocker, a major or any security finding is never ignored (WORKFLOW merge rule 4); it must pass before merge. The only exception is an owner override at the cap, where the failing tests go to the follow-up ticket instead of the branch.
If CodeQL fails on synthetic test credentials (`rust/hard-coded-cryptographic-value`, `rust/cleartext-logging`), check that every alert is on a test path: `crates/*/tests/**`, or a line that really lies inside a `#[cfg(test)]` module (check the line, not just the file). Dismiss only those, with reason `used in tests` and a comment, and note it on the PR. An alert in non-test code is a security finding: send it to the `security-auditor` on the current SHA, or ask the owner. The controller does not dismiss it alone, even if it looks like a false positive.
Remove the adversary worktree as its own step, only after its tests have been copied out: `git worktree remove --force .claude/worktrees/N-adv` (it holds untracked files, so `--force` is needed).
`scripts/verify check` succeeds only when all three `verify/*` statuses are `success` on the current head and every other check is green; the guard hook blocks `gh pr merge` without `--match-head-commit`. Never merge with a red or pending check, an unticked acceptance criterion (other than one deferred under an owner override at the cap) or a head that changed after verification. Never use `--admin`.

## 7. Close out
- Confirm the issue closed and is `status:done` (`ticket-sync.yml`); fix if not.
- `scripts/ticket epic-progress <epic>`; if all tasks closed, verify the epic's acceptance criteria and close it.
- `scripts/ticket-audit --fail-on never`.
- Report: ticket, PR link, rounds needed, findings fixed, follow-ups filed.
- Run `/retro` (the `retro` skill) when the ticket needed 3 or more rounds or hit the cap, when the same finding appeared in two PRs, or when the user asks. Otherwise note the PR for the next `/retro recent`.
- With `--loop`, go to step 0.
