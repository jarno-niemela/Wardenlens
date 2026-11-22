---
name: verify
description: Run the Opus verification gate (reviewer, security-auditor, adversary in parallel) on a pull request or branch and record SHA-bound verify/* commit statuses for each dimension. Use for /verify <pr>, "review this PR", or re-verifying after manual changes.
argument-hint: "<pr-number | branch>"
---

# /verify

Input: `$ARGUMENTS` — PR number (preferred) or branch.

1. Resolve the PR and its ticket: `gh pr view <pr> --json number,headRefName,headRefOid,body,labels`; the ticket is the `Closes #N` reference (if missing, that is itself a blocking finding). Record `SHA=<headRefOid>`: every verdict is bound to this exact commit.
2. Fetch, then make a review checkout at the head: `git worktree add --detach .claude/worktrees/pr-<pr> $SHA`. The adversary gets its **own** detached worktree: `git worktree add --detach .claude/worktrees/pr-<pr>-adv $SHA`.
3. Run `scripts/gate` yourself in the review worktree and record the result; pass it to the verifiers (the reviewer does not rerun it in a shared worktree).
4. In **one message**, dispatch `reviewer`, `security-auditor` and `adversary`, each with the PR number, ticket body, `SHA`, the gate result and its worktree path.
5. Post one consolidated PR comment (`gh pr comment`): per-verifier verdict, blocker/major findings with file:line, minors as proposed follow-ups.
6. For each dimension run `scripts/verify mark <pr> quality|security|adversarial pass|fail $SHA`. This writes the commit status `verify/DIM` on `$SHA` (the merge gate) and updates the display-only `verify:DIM` label only if `$SHA` is still the PR head.
7. Leave the adversary's uncommitted tests in its worktree and list their paths; remove the worktrees only if there are none. Tests the controller keeps are committed into the PR, pushed, and then `scripts/verify carry <pr> $SHA` carries the verdicts (test-only diffs only).
8. Report the verdicts. Do not merge: that is `/work`'s job (`sha=$(scripts/verify check <pr>) && gh pr merge <pr> --squash --delete-branch --match-head-commit "$sha"`).
