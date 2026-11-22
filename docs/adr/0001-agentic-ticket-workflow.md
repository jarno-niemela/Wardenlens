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
- **Pre-push hook (authoritative)**: `.githooks/pre-push` sees the real ref updates and refuses
  updates of main/master, deletions, unknown remote state and non-fast-forward updates, whatever
  the command looked like. Rewriting one's own feature branch needs `WARDENLENS_ALLOW_REWRITE=1`,
  which the guard denies in agent commands, so only a human can set it. `scripts/gate` checks that
  `core.hooksPath` is `.githooks`; the hook has real-push tests (`scripts/tests/pre-push.test.sh`). It also refuses any update or
  deletion of an existing remote tag. **Scope: the hook covers `git push` only.** It does not run
  under `--no-verify`, a `core.hooksPath` override, git plumbing (`send-pack`, `http-push`, remote
  helpers) or a branch whose committed hook was modified; the guard denies those on a best-effort
  basis. GitHub branch protection is unavailable on this plan; the owner accepted tooling-only
  enforcement (#11). PRs touching `.github/workflows/`, `.githooks/`, `.claude/hooks/` or
  `.claude/settings.json` need explicit security-auditor attention (a PR could redefine the
  workflow named "CI").
- **Guard hook (best effort)**: a fail-closed Bash hook blocks force pushes, pushes to main, hook
  bypass, `gh pr merge` without `--match-head-commit <sha|$var>`, merge/delete calls, GraphQL
  mutations and status writes through `gh api`, and piping into a shell. It is a safety net against
  mistakes, not a security boundary; because git spells a push in too many ways to match as text,
  the pre-push hook is what actually stops pushes. Accepted limitations (the guard does not catch
  these; where they push, the pre-push hook still does):
  - code inside interpreter string literals (`python3 -c`, `perl -e`, `node -e`, awk `system()`),
    `$'...'` quoting, `$(echo ...)` and variable indirection, aliases and scripts;
  - pipes into shells through wrappers with arguments (`timeout 10 bash`, `sudo -u x bash`,
    `nice -n 5 sh`, `busybox sh`, `tee >(bash)`);
  - `xargs ... git`;
  - git invoked through other paths (`/usr/lib/git-core/git`, `git-push`);
  - brace expansion (`git push origin {feat/x,main}`);
  - heredoc logical-line edge cases (`<<EOF \` continuation, quotes spanning lines) and
    `${x//<<X/}` being read as a heredoc;
  - `GIT_CONFIG_*` exported in an earlier command than the git invocation;
  - the same interpreter, brace-expansion and `/usr/lib/git-core/git` gaps apply to tamper
    protection of the enforcement files (`.git/`, `.githooks/`, `.claude/hooks/`,
    `.claude/settings*.json`, shell rc files); `git apply` and `patch` are denied outright because
    their patches cannot be inspected, and a read such as `cp .githooks/x /tmp/y` is a known false
    positive. The enforcement files are additionally protected by `permissions.deny` on the Edit
    and Write tools; the guard is best effort throughout;
  - `git checkout <rev> -- .` and `git reset --hard <old>` can restore an older committed hook;
    accepted because any older committed hook still refuses main and verification is SHA-bound;
  - variable indirection in git options (`git ${x}>...`), and `find -path <protected> ... -delete`
    style writes whose target is only reachable through patterns; a read-only `find -exec` of a
    command outside the guard's short read-only list (grep, cat, ls, ...) is a false positive;
  - workflows (`.github/workflows/`) are privileged files: the guard and `permissions.deny` block
    writes, `gh workflow run --ref <non-main>` and `gh api` writes to `actions/*` and
    `environments*`, and the pre-push hook refuses pushes whose commits change them unless a human
    sets `WARDENLENS_ALLOW_WORKFLOWS=1`. A new remote branch is judged against the commits not on any
    remote-tracking ref, so a push by URL with no remote configured examines the whole history.
- **Neglect detection**: `scripts/ticket-audit` (pure jq rules with offline tests)
  runs every `/work` iteration and daily in CI.
- **Tooling in bash + jq** for bootstrap; a Rust port is tracked as a ticket.

## Consequences
- Every change costs at least four agent runs; accepted for reliability.
- The repository is private on a plan without branch protection, so the gate is enforced by
  tooling (`scripts/verify check`, the guard hook), not by GitHub. Enable rulesets requiring the
  `verify/*` status contexts if the plan allows it; until then the gate binds the agents only.
- Label hygiene becomes critical; it is automated (`ticket-sync.yml`) and audited.
