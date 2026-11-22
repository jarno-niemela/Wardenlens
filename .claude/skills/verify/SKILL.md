---
name: verify
description: Run the Opus verification gate (reviewer, security-auditor, adversary in parallel) on a pull request or branch and apply verify:* labels for passing dimensions. Use for /verify <pr>, "review this PR", or re-verifying after manual changes.
argument-hint: "<pr-number | branch>"
---

# /verify

Input: `$ARGUMENTS` — PR number (preferred) or branch.

1. Resolve the PR and its ticket: `gh pr view <pr> --json number,headRefName,headRefOid,body,labels`; the ticket is the `Closes #N` reference — if missing, that is itself a blocking finding.
2. Ensure a worktree at the PR head: `git worktree add .claude/worktrees/pr-<pr> origin/<branch>` (fetch first; reuse if it exists and is at the head SHA).
3. Run `scripts/gate` there. Record the result.
4. In **one message**, dispatch `reviewer`, `security-auditor` and `adversary`, each with the PR number, ticket body and worktree path.
5. Post one consolidated PR comment (`gh pr comment`): per-verifier verdict, blocker/major findings with file:line, minors as proposed follow-ups.
6. For each verifier that passed, add its label (`verify:quality`, `verify:security`, `verify:adversarial`); remove labels for any that failed. Only label if the PR head SHA is unchanged since step 1.
7. Leave the adversary's uncommitted tests in the worktree and list their paths; remove the worktree only if there are none.
8. Report the verdicts. Do not merge — that is `/work`'s job.
