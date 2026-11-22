---
name: ticket-audit
description: Find and fix neglected or mis-labelled GitHub tickets and PRs — missing labels, orphan tasks, stale in-progress work, review states without PRs, resolved blockers, finished epics, PRs not linked to issues. Use for /ticket-audit, "check the backlog", "are any tickets neglected", or at the start/end of a work session.
---

# /ticket-audit

1. Run `scripts/ticket-audit` (human view) and `scripts/ticket-audit --json --fail-on never` (to act on).
2. Auto-fix only what is unambiguous:
   | Rule | Fix |
   |---|---|
   | `unblocked` | `scripts/ticket unblock` |
   | `closed-stale-status` | `scripts/ticket status N done` |
   | `epic-complete` | check the epic's acceptance criteria; close it if met, else file the missing task |
   | `review-without-pr` | look for a merged/closed PR; set `done`, `ready` or `in-progress` accordingly |
   | `done-but-open` | close it if its PR merged, else set the correct status |
   | `type-label` / `status-label` / `priority-label` | add labels when the classification is obvious from the title/body; otherwise label `needs:triage` and list it |
3. Never close or delete a ticket whose intent is unclear; ask the user.
4. Stale `in-progress` / stale PRs: resume them with `/work N` (preferred) or ask the user whether to return them to `ready`.
5. Re-run the audit and report: what was fixed, what remains and why, and a one-line queue summary (`scripts/ticket list`).
