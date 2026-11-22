---
name: new-ticket
description: File a single well-formed GitHub ticket (task, bug, chore or spike) with correct type/status/priority labels, parent epic link, dependencies and testable acceptance criteria. Use when the user reports a bug, asks to add a task/todo/ticket, or when a follow-up is discovered during work.
argument-hint: "<description>"
---

# /new-ticket

Input: `$ARGUMENTS`.

1. Classify: `task` (planned work in an epic), `bug` (defect), `chore` (tooling/CI/deps), `spike` (research → decision/ADR).
2. Find the parent epic: `scripts/ticket list | grep type:epic`. Tasks **must** have one; if none fits, ask the user whether to create a new epic (`/plan-epic`) — do not file orphans. Bugs/chores may be standalone; use `gh issue create` with labels `type:<t>,status:ready,priority:<p>` in that case.
3. Search for duplicates: `gh issue list --state all --search "<keywords>"`. Link instead of duplicating.
4. Write the body from `scripts/templates/task.md`: context, 2–6 testable acceptance criteria, test plan, out of scope, security notes. For bugs include reproduction steps and expected vs actual.
5. Priority: p0 broken main/security hole · p1 blocks other work · p2 normal · p3 nice to have.
6. File: `scripts/ticket task <epic> "<conventional title>" -t <type> -p <prio> [-a <area>] [-b <blockers>] -F <body.md>`.
7. Report the issue link.
