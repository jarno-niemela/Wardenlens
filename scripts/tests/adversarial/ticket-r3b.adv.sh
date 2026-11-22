#!/usr/bin/env bash
# Round 3b adversarial cases for scripts/ticket (argument validation, `next`) and the repo-scoped
# blocker/closing references in scripts/lib/common.jq. Offline: a stub gh serves canned JSON.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
ticket=$root/scripts/ticket
audit=$root/scripts/ticket-audit
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "gh $*" >>"$CALLS"
case "$1 $2" in
  "issue list") cat "$ISSUES" ;;
  "pr list") cat "$PRS" ;;
  "repo view") echo jarno-niemela/Wardenlens ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" CALLS=$tmp/calls ISSUES=$tmp/i.json PRS=$tmp/p.json
fail=0
L() { local s=""; for l in "$@"; do s+="${s:+,}{\"name\":\"$l\"}"; done; echo "[$s]"; }
iss() { jq -nc --argjson n "$1" --arg st "$2" --arg b "$3" --argjson l "$(L "${@:4}")" \
  '{number:$n,title:"t\($n)",state:$st,labels:$l,body:$b,updatedAt:"2026-11-21T00:00:00Z",assignees:[{login:"a"}]}'; }
E=$(iss 1 OPEN goal type:epic status:backlog priority:p1)
RDY=(type:task status:ready priority:p2)

next_is() {  # next_is NAME EXPECTED issues prs
  printf '%s' "$3" >"$ISSUES"; printf '%s' "$4" >"$PRS"
  local got; got=$("$ticket" next 2>"$tmp/err")
  if [[ "$got" == "$2" ]]; then echo "ok   [$1]"; else echo "FAIL [$1] expected '$2', got '$got' $(head -c 200 "$tmp/err")"; fail=1; fi
}
OPENPR='[{"number":9,"state":"OPEN"}]'
next_is "blocked by an open PR given as a /pull/ URL is not next" "" \
  "[$E,$(iss 5 OPEN $'Epic: #1\nBlocked by https://github.com/jarno-niemela/Wardenlens/pull/9' "${RDY[@]}")]" "$OPENPR"
next_is "blocked by an open issue via URL with capitalised host is not next" "" \
  "[$E,$(iss 4 OPEN x type:task status:in-progress priority:p2),$(iss 5 OPEN $'Epic: #1\nBlocked by https://GitHub.com/jarno-niemela/Wardenlens/issues/4' "${RDY[@]}")]" "[]"
next_is "self-blocked through a URL is not next" "" \
  "[$E,$(iss 5 OPEN $'Epic: #1\nBlocked by https://github.com/jarno-niemela/Wardenlens/issues/5' "${RDY[@]}")]" "[]"
next_is "best of several priority labels wins" 6 \
  "[$E,$(iss 5 OPEN 'Epic: #1' type:task status:ready priority:p1),$(iss 6 OPEN 'Epic: #1' type:task status:ready priority:p3 priority:p0)]" "[]"
next_is "malformed priority counts as 9" 5 \
  "[$E,$(iss 5 OPEN 'Epic: #1' type:task status:ready priority:p2),$(iss 6 OPEN 'Epic: #1' type:task status:ready priority:p00)]" "[]"
next_is "foreign blocker keeps it out" "" \
  "[$E,$(iss 5 OPEN $'Epic: #1\n- [ ] Blocked by other/repo#3' "${RDY[@]}")]" "[]"
next_is "blocker on a later line still counts" "" \
  "[$E,$(iss 4 OPEN x type:task status:in-progress priority:p2),$(iss 5 OPEN $'Epic: #1\n\nnotes\n* Blocked-by: #4' "${RDY[@]}")]" "[]"

# --- audit: a ready ticket blocked by an open PR URL must be flagged ---------------------------
printf '%s' "[$E,$(iss 5 OPEN $'Epic: #1\nBlocked by https://github.com/jarno-niemela/Wardenlens/pull/9' "${RDY[@]}")]" >"$ISSUES"
jq -nc '[{number:9,title:"pr",body:"Closes #7",state:"OPEN",createdAt:"2026-11-21T12:00:00Z",isDraft:false,reviewDecision:"",author:{login:"x",is_bot:false},labels:[]}]' >"$PRS"
out=$("$audit" --json --fail-on never --repo jarno-niemela/Wardenlens --issues-file "$ISSUES" --prs-file "$PRS" --now 1795305600 2>&1)
if jq -e 'any(.[]; .number == 5 and .rule == "ready-but-blocked")' <<<"$out" >/dev/null; then echo "ok   [audit: ready but blocked by open PR URL]"
else echo "FAIL [audit: ready but blocked by open PR URL] got $(jq -c 'map([.number,.rule])' <<<"$out")"; fail=1; fi

# --- argument validation --------------------------------------------------------------------------
rejects() {
  local d=$1; shift; rm -f "$CALLS"
  if "$ticket" "$@" >"$tmp/out" 2>"$tmp/err"; then echo "FAIL $d: accepted"; fail=1
  elif [[ -e "$CALLS" ]] && grep -q 'issue create' "$CALLS"; then echo "FAIL $d: created an issue"; fail=1
  elif [[ -e "$CALLS" ]]; then echo "FAIL $d: reached gh before rejecting: $(head -1 "$CALLS")"; fail=1
  else echo "ok   $d"; fi
}
# -b given twice: superseded by the brief (repeated -b accumulates); tested in scripts/tests/ticket.test.sh
rejects "task: -b with unicode digit"   task 1 "T" -b '٣'
rejects "epic: priority with unicode digit" epic "T" -p 'p٣'
rejects "task: -b with tab separator"   task 1 "T" -b $'2\t3'
rejects "status: number with sign"       status +3 ready
rejects "claim: option-looking number"    claim -3
exit $fail
