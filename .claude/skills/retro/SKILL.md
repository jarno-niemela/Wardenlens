---
name: retro
description: Retrospective loop that turns verifier findings into better development skills, so later tickets pass verification in fewer rounds. Run it when a ticket needed 3 or more verification rounds or hit the round cap, when the same finding appears in two PRs, or when the user asks for /retro or to improve the dev skills.
---

# /retro — learn from review rounds

Input: a PR number, a ticket, or `recent` (every PR merged since the last retro; see the
`Last retro` line at the end of `.claude/skills/defect-patterns/SKILL.md`).

## 1. Collect
For each PR:
- **Rounds:** the highest `rN` among the briefs in `~/.local/state/wardenlens/agents/<ticket>-*-rN.md`. Completed agents leave `<agentId>.prompt.done` files there too. The ledger itself drops rows once done, and a commit's `verify/*` statuses only cover that one SHA.
- **Findings:** gather every **blocker and major** from:
  - the controller's fix briefs (`<ticket>-implementer-rN.md`), which quote the findings;
  - the per-round consolidated PR comments that `/work` step 5 requires (older PRs such as #95, #101, #102 have none, so the briefs are the main source);
  - the follow-up tickets.
- **Minors:** collect those that showed up in two or more PRs.
- **Controller mistakes:** note any brief or design ruling that caused a round. Example: #44 r2 "delete toward the target".

## 2. Classify
For each finding, ask four questions:
1. **Which pattern?** Does an existing `defect-patterns` entry already describe it?
   - If yes, add the example (ticket, PR and round, one line).
   - If not, write a new pattern with these parts: the rule, the example, and the self-test that would have caught it.
2. **Why wasn't it caught earlier?** Was the checklist item missing, too vague, or ignored? Did the brief lack it? Is the guideline missing?
3. **Where does the fix belong?** Pick the cheapest place that would have prevented it:
   - a guideline rule (`docs/CODING_GUIDELINES.md`, with a rule ID);
   - a checklist line in `defect-patterns`;
   - an implementer procedure step (`.claude/agents/implementer.md`);
   - a brief template line in the `work` skill;
   - a ticket template or acceptance-criteria prompt (`plan-epic` / `new-ticket`);
   - a lint or tooling check. This is the strongest option when the defect is mechanical. Check that the lint really catches the case: `clippy::string_slice` catches `&s[a..b]` but not `split_at`.
4. **Is it a spec problem?** If the ADR or ticket was wrong or silent, file an ADR amendment or follow-up ticket instead of a skill change.

## 3. Edit, keeping it lean
- Keep the change **small and concrete**: rules in the imperative, examples with ticket numbers, self-tests that can be run.
- Never add generic advice such as "be careful" or "write good tests".
- Merge duplicate patterns.
- Keep `defect-patterns` under about 200 lines. When a pattern has been prevented by tooling for 5 or more PRs, shrink it to one line.
- Promote a pattern into `docs/CODING_GUIDELINES.md` (with a new rule ID) once it has recurred in 3 or more PRs. Verifiers cite guideline IDs, so a promoted rule gets enforced.
- Update the `Last retro` line: date, and the PRs covered.

## 4. Ship it like any change
- This needs a ticket (`type:chore`, epic #10). Use branch `chore/<N>-retro-<topic>` and a PR with `Closes #N`, gated by `scripts/gate` and the normal verification.
- **Locked files:** never edit `.claude/hooks/**`, `.claude/settings*.json`, `.githooks/**` or `.github/workflows/**`. If a lesson needs a hook or workflow change, stage the file in the scratchpad and hand it to the owner.

## 5. Measure
Record in the PR body, per ticket: the rounds needed, and which pattern caused each extra round. The next retro checks whether those patterns recurred:
- **Recurred** means the fix was not strong enough. Escalate: checklist → guideline → lint.
- **Did not recur** means it worked. Leave it, and shrink it later.
