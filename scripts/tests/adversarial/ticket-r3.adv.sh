#!/usr/bin/env bash
# Round 3: repository-qualified references in closing/blocker lines (scripts/lib/common.jq) and
# the self-blocker audit rule. Offline: scripts/ticket-audit with --issues-file/--prs-file.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
audit=$root/scripts/ticket-audit
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
now=1795305600
L() { local s=""; for l in "$@"; do s+="${s:+,}{\"name\":\"$l\"}"; done; echo "[$s]"; }
iss() { jq -nc --argjson n "$1" --arg st "$2" --arg b "$3" --argjson l "$(L "${@:4}")" \
  '{number:$n,title:"t\($n)",state:$st,labels:$l,body:$b,updatedAt:"2026-11-21T00:00:00Z",assignees:[{login:"a"}]}'; }
pr() { jq -nc --argjson n "$1" --arg b "$2" \
  '{number:$n,title:"pr",body:$b,state:"OPEN",createdAt:"2026-11-21T12:00:00Z",isDraft:false,reviewDecision:"",author:{login:"x",is_bot:false},labels:[]}'; }
has() { # name expect(1|0) issues prs number rule
  printf '%s' "$3" >"$tmp/i.json"; printf '%s' "$4" >"$tmp/p.json"
  local out; out=$("$audit" --json --fail-on never --repo jarno-niemela/Wardenlens --issues-file "$tmp/i.json" --prs-file "$tmp/p.json" --now "$now" 2>&1) \
    || { echo "FAIL [$1] crashed: $out"; fail=1; return; }
  local got=0; jq -e --argjson n "$5" --arg r "$6" 'any(.[]; .number == $n and .rule == $r)' <<<"$out" >/dev/null && got=1
  if [[ $got == "$2" ]]; then echo "ok   [$1]"; else echo "FAIL [$1] expected=$2 for #$5 $6; got $(jq -c 'map([.number,.rule])' <<<"$out")"; fail=1; fi
}
E=$(iss 1 OPEN goal type:epic status:backlog priority:p1)
REV=(type:task status:in-review priority:p2)
T2=$(iss 2 OPEN 'Epic: #1' "${REV[@]}")
has "Closes owner/name#N of this repo (any case) links" 0 "[$E,$T2]" "[$(pr 10 'Closes Jarno-Niemela/WARDENLENS#2')]" 2 review-without-pr
has "Closes URL of this repo links" 0 "[$E,$T2]" "[$(pr 10 'Closes https://github.com/jarno-niemela/wardenlens/issues/2')]" 2 review-without-pr
has "Closes superstring repo does not link" 1 "[$E,$T2]" "[$(pr 10 'Closes xjarno-niemela/Wardenlens#2')]" 2 review-without-pr
has "Closes repo suffix does not link" 1 "[$E,$T2]" "[$(pr 10 'Closes jarno-niemela/Wardenlens-fork#2')]" 2 review-without-pr
has "Closes foreign URL embedding our name does not link" 1 "[$E,$T2]" "[$(pr 10 'Closes https://github.com/evil/jarno-niemela/Wardenlens/issues/2')]" 2 review-without-pr
has "plain #N links" 0 "[$E,$T2]" "[$(pr 10 'Closes #2')]" 2 review-without-pr
B3=$(iss 3 CLOSED 'Epic: #1' type:task status:done priority:p2)
blk() { iss 5 OPEN $'Epic: #1\n'"$1" type:task status:blocked priority:p2; }
has "task-list blocker keeps it blocked" 0 "[$E,$(iss 4 OPEN x type:task status:ready priority:p2),$(iss 5 OPEN $'Epic: #1\n- [ ] Blocked by #4' type:task status:blocked priority:p2)]" "[]" 5 unblocked
has "task-list blocker closed: unblocked" 1 "[$E,$B3,$(iss 5 OPEN $'Epic: #1\n- [x] Blocked by #3' type:task status:blocked priority:p2)]" "[]" 5 unblocked
has "same-repo qualified blocker counts" 1 "[$E,$B3,$(blk 'Blocked by: jarno-niemela/Wardenlens#3')]" "[]" 5 unblocked
has "same-repo URL blocker counts" 1 "[$E,$B3,$(blk 'Blocked by https://github.com/jarno-niemela/Wardenlens/issues/3')]" "[]" 5 unblocked
has "foreign blocker is not local #3" 0 "[$E,$B3,$(blk 'Blocked by: other/repo#3')]" "[]" 5 unblocked
has "foreign blocker alone is not 'no reason'" 0 "[$E,$(blk 'Blocked by: other/repo#3')]" "[]" 5 blocked-no-reason
has "foreign blocker is not bad-blocker" 0 "[$E,$(blk 'Blocked by: other/repo#999')]" "[]" 5 bad-blocker
has "self-blocker reported" 1 "[$E,$(blk 'Blocked by: #5')]" "[]" 5 self-blocker
has "self-blocker via qualified ref" 1 "[$E,$(blk 'Blocked by: jarno-niemela/wardenlens#5')]" "[]" 5 self-blocker
has "no self-blocker for others" 0 "[$E,$B3,$(blk 'Blocked by: #3')]" "[]" 5 self-blocker
exit $fail
