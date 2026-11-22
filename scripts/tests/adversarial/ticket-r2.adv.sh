#!/usr/bin/env bash
# Adversarial round 2 for scripts/ticket (argument validation, `next` selection) and
# scripts/lib/{common,audit}.jq (closing refs, blockers). Offline, stub gh on PATH.
# shellcheck disable=SC2046  # R() deliberately expands to several label arguments
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
  "issue list") cat "$FIXTURE" ;;
  "pr list") echo '[]' ;;
  "repo view") echo "jarno-niemela/Wardenlens" ;;
  "issue view") echo true ;;          # epic check passes
  "issue create") echo "https://github.com/o/r/issues/99" ;;
  "api repos/{owner}/{repo}/issues/99") echo 1 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" FIXTURE="$tmp/f.json" CALLS="$tmp/calls"
fail=0

# --- argument validation: must be rejected before any write reaches gh ---------------------
rejects() {  # rejects DESCRIPTION args...
  local d=$1; shift; : >"$CALLS"
  if "$ticket" "$@" >"$tmp/out" 2>"$tmp/err"; then echo "FAIL $d: accepted ($(grep -E 'create|edit' "$CALLS" | head -c 200))"; fail=1
  elif grep -qE 'issue (create|edit)' "$CALLS"; then echo "FAIL $d: wrote to GitHub: $(cat "$CALLS")"; fail=1
  else echo "ok   $d"; fi
}
rejects "status: two states in one word"    status 5 "ready in-progress"
rejects "status: leftover argument"         status 5 "done" extra
rejects "claim: leftover argument"          claim 5 extra
rejects "task: forgotten title (title=-p)"  task 5 -p
rejects "task: -b with no numbers"          task 5 "T" -b ","
rejects "task: -b #0 is not an issue"       task 5 "T" -b 0
rejects "task: -b newline drops 2nd blocker" task 5 "T" -b $'12\n13'

# --- next: priority parsing ----------------------------------------------------------------
iss() { # number state body labels...
  local n=$1 st=$2 body=$3; shift 3; local l; l=$(printf '%s\n' "$@" | jq -R '{name:.}' | jq -sc .)
  jq -nc --argjson n "$n" --arg st "$st" --arg b "$body" --argjson l "$l" \
    '{number:$n,title:"t\($n)",state:$st,labels:$l,body:$b,updatedAt:"2026-11-21T00:00:00Z",assignees:[]}'
}
next_is() { # name expected items...
  local name=$1 want=$2; shift 2
  printf '[%s]' "$(IFS=,; echo "$*")" >"$FIXTURE"
  local got; got=$("$ticket" next 2>"$tmp/err"); local rc=$?
  if [[ $rc -ne 0 ]]; then echo "FAIL [$name] crashed rc=$rc: $(head -c 200 "$tmp/err")"; fail=1
  elif [[ "$got" == "$want" ]]; then echo "ok   [$name] -> '$got'"
  else echo "FAIL [$name] expected '$want' got '$got'"; fail=1; fi
}
R() { echo type:task status:ready "priority:$1"; }
next_is "priority:p-1 does not outrank p0" 6 "$(iss 3 OPEN x $(R p-1))" "$(iss 6 OPEN x $(R p0))"
next_is "priority:p9 is not a real priority" 6 "$(iss 3 OPEN x $(R p9))" "$(iss 6 OPEN x $(R p3))"
next_is "two priority labels: best one counts" 3 "$(iss 3 OPEN x type:task status:ready priority:p3 priority:p0)" "$(iss 6 OPEN x $(R p1))"
next_is "cross-repo blocker o/r#2 is not local #2" 6 "$(iss 2 CLOSED x type:task status:done priority:p2)" "$(iss 3 OPEN 'Blocked by: other/repo#2' $(R p0))" "$(iss 6 OPEN x $(R p2))"
next_is "task-list blocker '- [ ] Blocked by #2' blocks" 6 "$(iss 2 OPEN x type:task status:ready priority:p3)" "$(iss 3 OPEN $'- [ ] Blocked by #2' $(R p0))" "$(iss 6 OPEN x $(R p2))"

# --- audit: closing refs to another repository -------------------------------------------
now=1795305600
epic1='{"number":1,"title":"e","state":"OPEN","labels":[{"name":"type:epic"},{"name":"status:backlog"},{"name":"priority:p1"}],"body":"goal","updatedAt":"2026-11-21T00:00:00Z","assignees":[{"login":"a"}]}'
L() { local s=""; for l in "$@"; do s+="${s:+,}{\"name\":\"$l\"}"; done; echo "[$s]"; }
aiss() { jq -nc --argjson n "$1" --arg st "$2" --arg b "$3" --argjson l "$(L "${@:4}")" \
  '{number:$n,title:"t\($n)",state:$st,labels:$l,body:$b,updatedAt:"2026-11-21T00:00:00Z",assignees:[{login:"a"}]}'; }
apr() { jq -nc --argjson n "$1" --arg b "$2" \
  '{number:$n,title:"pr",body:$b,state:"OPEN",createdAt:"2026-11-21T12:00:00Z",isDraft:false,reviewDecision:"",author:{login:"x",is_bot:false},labels:[]}'; }
has() { # name expect(1|0) issues prs number rule
  printf '%s' "$3" >"$tmp/i.json"; printf '%s' "$4" >"$tmp/p.json"
  local out; out=$("$audit" --json --fail-on never --issues-file "$tmp/i.json" --prs-file "$tmp/p.json" --now "$now" 2>&1) \
    || { echo "FAIL [$1] crashed: $out"; fail=1; return; }
  local got=0; jq -e --argjson n "$5" --arg r "$6" 'any(.[]; .number == $n and .rule == $r)' <<<"$out" >/dev/null && got=1
  if [[ $got == "$2" ]]; then echo "ok   [$1]"; else echo "FAIL [$1] expected=$2 for #$5 $6; got $(jq -c 'map([.number,.rule])' <<<"$out")"; fail=1; fi
}
REV=(type:task status:in-review priority:p2)
has "Closes other/repo#2 does not link local #2" 1 "[$epic1,$(aiss 2 OPEN 'Epic: #1' "${REV[@]}")]" "[$(apr 10 'Closes other/repo#2')]" 2 review-without-pr
has "Fixes other-repo URL does not link local #2" 1 "[$epic1,$(aiss 2 OPEN 'Epic: #1' "${REV[@]}")]" "[$(apr 10 'Fixes https://github.com/other/repo/issues/2')]" 2 review-without-pr
has "self-blocker is reported" 1 "[$epic1,$(aiss 5 OPEN $'Epic: #1\nBlocked by: #5' type:task status:blocked priority:p2)]" "[]" 5 self-blocker
# worth keeping (expected to pass): a known closed blocker next to an unknown one must not unblock
has "closed + unknown blocker: no unblocked" 0 "[$epic1,$(aiss 3 CLOSED 'Epic: #1' type:task status:done priority:p2),$(aiss 5 OPEN $'Epic: #1\nBlocked by: #3, #999' type:task status:blocked priority:p2)]" "[]" 5 unblocked
has "closed + unknown blocker: bad-blocker" 1 "[$epic1,$(aiss 3 CLOSED 'Epic: #1' type:task status:done priority:p2),$(aiss 5 OPEN $'Epic: #1\nBlocked by: #3, #999' type:task status:blocked priority:p2)]" "[]" 5 bad-blocker
has "blocked by open PR: no unblocked" 0 "[$epic1,$(aiss 5 OPEN $'Epic: #1\nBlocked by: #10' type:task status:blocked priority:p2)]" "[$(apr 10 'Closes #5')]" 5 unblocked

exit $fail
