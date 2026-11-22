#!/usr/bin/env bash
# Sync the repository's label taxonomy (idempotent). Requires: gh.
# Usage: scripts/labels.sh [--prune-defaults]
set -euo pipefail

# name|color|description
LABELS=$(cat <<'EOF'
type:epic|5319e7|Large body of work broken into task issues
type:task|1d76db|Single mergeable unit of work belonging to an epic
type:bug|d73a4a|Defect in existing behaviour
type:chore|c5def5|Tooling, CI, dependency or housekeeping work
type:spike|fbca04|Time-boxed research; output is a decision or ADR
status:backlog|ededed|Accepted but not yet refined/ready
status:ready|0e8a16|Refined, unblocked, can be picked up
status:in-progress|fbca04|Claimed; implementer working on a branch
status:in-review|0052cc|PR open; awaiting Opus verification
status:changes-requested|e99695|Verification found issues; back to implementer
status:blocked|b60205|Waiting on another ticket (see 'Blocked by:' line)
status:done|cccccc|Merged and closed
priority:p0|b60205|Critical: drop everything
priority:p1|d93f0b|High
priority:p2|fbca04|Normal
priority:p3|c2e0c6|Low / nice to have
agent:sonnet|bfd4f2|Implemented by the Sonnet implementer subagent
agent:human|f9d0c4|Requires a human decision or action
verify:quality|0e8a16|PR passed Opus code-quality review
verify:security|0e8a16|PR passed Opus security audit
verify:adversarial|0e8a16|PR survived Opus adversarial testing
needs:triage|d876e3|New ticket that must be labelled and refined
EOF
)

while IFS='|' read -r name color desc; do
  [[ -z "$name" ]] && continue
  gh label create "$name" --color "$color" --description "$desc" --force >/dev/null
  echo "synced $name"
done <<<"$LABELS"

if [[ "${1:-}" == "--prune-defaults" ]]; then
  for l in bug documentation duplicate enhancement "help wanted" "good first issue" invalid question wontfix accessibility; do
    gh label delete "$l" --yes >/dev/null 2>&1 && echo "deleted $l" || true
  done
fi
