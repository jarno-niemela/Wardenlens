---
name: plan-epic
description: Turn a feature idea or an existing epic issue into a GitHub epic plus ordered, dependency-linked task tickets with testable acceptance criteria, using the Opus planner subagent. Use when the user asks to plan a feature, create an epic, break work down, or /plan-epic.
argument-hint: "<epic-number | feature description>"
---

# /plan-epic

Input: `$ARGUMENTS` — an existing epic number, or a free-text description.

1. **Epic.** If given a number, `gh issue view N` and confirm it has `type:epic`. Otherwise draft the epic body from `scripts/templates/epic.md` (goal, scope, acceptance criteria) and create it:
   `scripts/ticket epic "<Title>" -p <p0..p3> [-a <area>] -F <body.md>`
   If the goal is unclear, ask the user up to 3 sharp questions first.
2. **Plan.** Dispatch the `planner` subagent with the epic number and body. It returns JSON (`adrs`, `tasks`).
3. **Review the plan yourself** before filing: every task has testable criteria, is small, names its module, and the dependency order is acyclic. Push back to the planner once if not.
4. **File.** For each ADR question create a spike first: `scripts/ticket task <epic> "spike: <question>" -t spike -p p1`. Then each task in order, translating `blocked_by` indices to the issue numbers you just created:
   `scripts/ticket task <epic> "<title>" -p <prio> -a <area> [-b <n,m>] -F <body.md>`
   (write each body to a scratch file first).
5. `scripts/ticket status <epic> ready` once it has tasks; run `scripts/ticket epic-progress <epic>` and `scripts/ticket-audit --fail-on never`.
6. Report the epic link and the task list with dependencies. Suggest `/work --loop` to start.
