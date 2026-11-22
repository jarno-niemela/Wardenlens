#!/usr/bin/env bash
# Adversarial cases for `scripts/ticket next` (and epic-progress) with a stubbed gh.
# shellcheck disable=SC2046  # R() deliberately expands to several label arguments
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
# Serves $FIXTURE for `gh issue list`; filters by state like the real CLI.
if [[ "$1 $2" == "issue list" ]]; then
  state=open; for ((i=1;i<=$#;i++)); do [[ "${!i}" == --state ]] && { j=$((i+1)); state=${!j}; }; done
  if [[ $state == all ]]; then cat "$FIXTURE"; else jq '[.[] | select((.state // "OPEN") == "OPEN")]' "$FIXTURE"; fi
  exit 0
fi
if [[ "$1 $2" == "pr list" ]]; then
  if [[ -f "${PRFIXTURE:-/nonexistent}" ]]; then cat "$PRFIXTURE"; else echo '[]'; fi
  exit 0
fi
if [[ "$1 $2" == "repo view" ]]; then echo "jarno-niemela/Wardenlens"; exit 0; fi
echo "stub gh: unexpected $*" >&2; exit 1
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" FIXTURE="$tmp/f.json" PRFIXTURE="$tmp/p.json"
fail=0

iss() { # number state body labels...
  local n=$1 st=$2 body=$3; shift 3; local l; l=$(printf '%s\n' "$@" | jq -R '{name:.}' | jq -sc .)
  [[ $# -eq 0 ]] && l='[]'
  jq -nc --argjson n "$n" --arg st "$st" --arg b "$body" --argjson l "$l" \
    '{number:$n,title:"t\($n)",state:$st,labels:$l,body:$b,updatedAt:"2026-11-21T00:00:00Z",assignees:[]}'
}
next_is() { # name expected fixture-items...
  local name=$1 want=$2; shift 2
  printf '[%s]' "$(IFS=,; echo "$*")" >"$FIXTURE"
  local got; got=$("$root/scripts/ticket" next 2>"$tmp/err"); local rc=$?
  if [[ $rc -ne 0 ]]; then echo "FAIL [$name] crashed rc=$rc: $(head -c 200 "$tmp/err")"; fail=1
  elif [[ "$got" == "$want" ]]; then echo "ok   [$name] -> '${got}'"
  else echo "FAIL [$name] expected '$want' got '$got'"; fail=1; fi
}
R() { echo type:task status:ready "priority:$1"; }

next_is "priority beats number" 5 "$(iss 2 OPEN 'Epic: #1' $(R p2))" "$(iss 5 OPEN 'Epic: #1' $(R p0))"
next_is "tie broken by lowest number" 2 "$(iss 5 OPEN x $(R p1))" "$(iss 2 OPEN x $(R p1))"
next_is "missing priority sorts last" 7 "$(iss 3 OPEN x type:task status:ready)" "$(iss 7 OPEN x $(R p3))"
next_is "epics excluded" 4 "$(iss 1 OPEN x type:epic status:ready priority:p0)" "$(iss 4 OPEN x $(R p2))"
next_is "non-ready excluded" "" "$(iss 4 OPEN x type:task status:backlog priority:p0)"
next_is "open blocker filters" 6 "$(iss 2 OPEN x type:task status:in-progress priority:p2)" "$(iss 3 OPEN $'Epic: #1\nBlocked by: #2' $(R p0))" "$(iss 6 OPEN x $(R p2))"
next_is "closed blocker allows" 3 "$(iss 2 CLOSED x type:task status:done priority:p2)" "$(iss 3 OPEN $'Epic: #1\nBlocked by: #2' $(R p0))" "$(iss 6 OPEN x $(R p2))"
next_is "space-separated blockers" 6 "$(iss 2 OPEN x type:task status:in-progress priority:p2)" "$(iss 3 OPEN $'Blocked by: #9 #2' $(R p0))" "$(iss 6 OPEN x $(R p2))"
next_is "CRLF blocked-by line" 6 "$(iss 2 OPEN x type:task status:in-progress priority:p2)" "$(iss 3 OPEN $'Epic: #1\r\nBlocked by: #2\r\n' $(R p0))" "$(iss 6 OPEN x $(R p2))"
next_is "'blocked by #2' (no colon) still blocks" 6 "$(iss 2 OPEN x type:task status:in-progress priority:p2)" "$(iss 3 OPEN $'blocked by #2' $(R p0))" "$(iss 6 OPEN x $(R p2))"
next_is "ready+blocked double label not picked" 6 "$(iss 3 OPEN x type:task status:ready status:blocked priority:p0)" "$(iss 6 OPEN x $(R p2))"
next_is "null body" 3 "$(jq -c '.body=null' <<<"$(iss 3 OPEN x $(R p1))")"
next_is "empty list" ""
next_is "odd priority label does not crash" 6 "$(iss 3 OPEN x type:task status:ready priority:pX)" "$(iss 6 OPEN x $(R p2))"
next_is "bug/chore/spike eligible" 8 "$(iss 8 OPEN x type:chore status:ready priority:p0)" "$(iss 9 OPEN x type:spike status:ready priority:p1)"

next_is "agent:human excluded" 6 "$(iss 3 OPEN x $(R p0) agent:human)" "$(iss 6 OPEN x $(R p2))"
next_is "needs:triage excluded" 6 "$(iss 3 OPEN x $(R p0) needs:triage)" "$(iss 6 OPEN x $(R p2))"
next_is "unknown blocker excluded" 6 "$(iss 3 OPEN $'Blocked by: #999' $(R p0))" "$(iss 6 OPEN x $(R p2))"
echo '[{"number":30,"state":"OPEN"}]' >"$PRFIXTURE"
next_is "open PR blocker excludes" 6 "$(iss 3 OPEN $'Blocked by: #30' $(R p0))" "$(iss 6 OPEN x $(R p2))"
echo '[{"number":30,"state":"MERGED"}]' >"$PRFIXTURE"
next_is "merged PR blocker allows" 3 "$(iss 3 OPEN $'Blocked by: #30' $(R p0))" "$(iss 6 OPEN x $(R p2))"
rm -f "$PRFIXTURE"

# epic-progress must count a child whose Epic line is not the first line
printf '[%s,%s,%s]' "$(iss 1 OPEN g type:epic status:backlog)" "$(iss 2 CLOSED 'Epic: #1' type:task status:done)" \
  "$(iss 3 OPEN $'## Context\nEpic: #1' type:task status:ready)" >"$FIXTURE"
got=$("$root/scripts/ticket" epic-progress 1 2>&1 | head -1)
if [[ "$got" == "Epic #1: 1/2 tasks closed" ]]; then echo "ok   [epic-progress late Epic line]"; else echo "FAIL [epic-progress late Epic line] got '$got'"; fail=1; fi
exit $fail
