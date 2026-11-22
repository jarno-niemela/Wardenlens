#!/usr/bin/env bash
# Adversarial cases for scripts/lib/audit.jq (via scripts/ticket-audit).
# Each case is a tiny self-contained fixture; FAIL lines are findings.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
audit=$root/scripts/ticket-audit
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
now=1795305600   # 2026-11-22T00:00:00Z
fail=0
T='"updatedAt":"2026-11-21T00:00:00Z","assignees":[{"login":"a"}]'
epic1='{"number":1,"title":"e","state":"OPEN","labels":[{"name":"type:epic"},{"name":"status:backlog"},{"name":"priority:p1"}],"body":"goal",'"$T"'}'
L() { local s=""; for l in "$@"; do s+="${s:+,}{\"name\":\"$l\"}"; done; echo "[$s]"; }
iss() { # number state body labels...
  local n=$1 st=$2 body=$3; shift 3
  jq -nc --argjson n "$n" --arg st "$st" --arg b "$body" --argjson l "$(L "$@")" \
    '{number:$n,title:"t\($n)",state:$st,labels:$l,body:$b,updatedAt:"2026-11-21T00:00:00Z",assignees:[{login:"a"}]}'
}
pr() { # number body [title]
  jq -nc --argjson n "$1" --arg b "$2" --arg t "${3:-pr}" \
    '{number:$n,title:$t,body:$b,state:"OPEN",createdAt:"2026-11-21T12:00:00Z",isDraft:false,reviewDecision:"",author:{login:"x",is_bot:false}}'
}
case_run() { # name issues-json prs-json -> sets $out (or empty + CRASH)
  printf '%s' "$2" >"$tmp/i.json"; printf '%s' "$3" >"$tmp/p.json"
  if ! out=$("$audit" --json --fail-on never --issues-file "$tmp/i.json" --prs-file "$tmp/p.json" --now "$now" 2>"$tmp/err"); then
    echo "FAIL [$1] audit crashed: $(head -c 200 "$tmp/err")"; fail=1; out=""; return 1
  fi
}
has()  { jq -e --argjson n "$2" --arg r "$3" 'any(.[]; .number == $n and .rule == $r)' <<<"$out" >/dev/null; }
expect() { case_run "$1" "$2" "$3" || return; if has "$1" "$4" "$5"; then echo "ok   [$1]"; else echo "FAIL [$1] expected #$4 $5; got $(jq -c 'map([.number,.rule])' <<<"$out")"; fail=1; fi; }
reject() { case_run "$1" "$2" "$3" || return; if has "$1" "$4" "$5"; then echo "FAIL [$1] unexpected #$4 $5"; fail=1; else echo "ok   [$1]"; fi; }
TASK=(type:task status:ready priority:p2)

# --- Epic: line parsing --------------------------------------------------
reject "epic line CRLF"            "[$epic1,$(iss 2 OPEN $'Epic: #1\r\n\r\nctx' "${TASK[@]}")]" "[]" 2 orphan-task
reject "epic:#1 no space"          "[$epic1,$(iss 2 OPEN 'epic:#1' "${TASK[@]}")]" "[]" 2 orphan-task
reject "epic line after leading blank lines" "[$epic1,$(iss 2 OPEN $'\n\nEpic: #1' "${TASK[@]}")]" "[]" 2 orphan-task
reject "epic line not first (heading before it)" "[$epic1,$(iss 2 OPEN $'## Context\nstuff\n\nEpic: #1' "${TASK[@]}")]" "[]" 2 orphan-task
reject "epic line not first, CRLF" "[$epic1,$(iss 2 OPEN $'Refs: x\r\nEpic: #1\r\n' "${TASK[@]}")]" "[]" 2 orphan-task
expect "Epic mid-sentence is not a link" "[$epic1,$(iss 2 OPEN 'see Epic: #1 for context' "${TASK[@]}")]" "[]" 2 orphan-task
# epic-complete must not fire when an open child's Epic line is not on line 1
reject "epic-complete false positive" \
  "[$epic1,$(iss 2 CLOSED 'Epic: #1' type:task status:done priority:p2),$(iss 3 OPEN $'ctx\nEpic: #1' "${TASK[@]}")]" "[]" 1 epic-complete
# several Epic lines: first wins, no crash
reject "two Epic lines" "[$epic1,$(iss 2 OPEN $'Epic: #1\nEpic: #77' "${TASK[@]}")]" "[]" 2 bad-epic

# --- Blocked by parsing --------------------------------------------------
B=(type:task status:blocked priority:p2)
R=(type:task status:ready priority:p2)
open3=$(iss 3 OPEN 'Epic: #1' "${R[@]}"); open4=$(iss 4 OPEN 'Epic: #1' "${R[@]}")
reject "Blocked by: #3 #4 (space list)" "[$epic1,$open3,$open4,$(iss 5 OPEN $'Epic: #1\nBlocked by: #3 #4' "${B[@]}")]" "[]" 5 blocked-no-reason
reject "Blocked by CRLF"               "[$epic1,$open3,$(iss 5 OPEN $'Epic: #1\r\nBlocked by: #3\r\n' "${B[@]}")]" "[]" 5 unblocked
expect "ready but 'blocked by #3' (no colon)" "[$epic1,$open3,$(iss 5 OPEN $'Epic: #1\nblocked by #3' "${R[@]}")]" "[]" 5 ready-but-blocked
expect "ready but 'Blocked-by: #3'"    "[$epic1,$open3,$(iss 5 OPEN $'Epic: #1\nBlocked-by: #3' "${R[@]}")]" "[]" 5 ready-but-blocked
expect "ready but '- Blocked by: #3' (list item)" "[$epic1,$open3,$(iss 5 OPEN $'Epic: #1\n- Blocked by: #3' "${R[@]}")]" "[]" 5 ready-but-blocked
# blocker that is an open PR (PRs share issue numbering) is still open work
reject "blocked by an open PR is not 'unblocked'" "[$epic1,$(iss 5 OPEN $'Epic: #1\nBlocked by: #30' "${B[@]}")]" "[$(pr 30 'Closes #1')]" 5 unblocked
# blocker that does not exist at all
expect "blocked by nonexistent #999 is bad-blocker" \
  "[$epic1,$(iss 5 OPEN $'Epic: #1\nBlocked by: #999' "${B[@]}")]" "[]" 5 bad-blocker
reject "blocked by nonexistent #999 is never 'unblocked'" \
  "[$epic1,$(iss 5 OPEN $'Epic: #1\nBlocked by: #999' "${B[@]}")]" "[]" 5 unblocked

# --- PR closing keywords --------------------------------------------------
in_review=$(iss 3 OPEN 'Epic: #1' type:task status:in-review priority:p2)
in_review4=$(iss 4 OPEN 'Epic: #1' type:task status:in-review priority:p2)
reject "Fixes: #3"                 "[$epic1,$in_review]" "[$(pr 30 'Fixes: #3')]" 3 review-without-pr
reject "closes #3 lowercase"       "[$epic1,$in_review]" "[$(pr 30 'closes #3')]" 3 review-without-pr
reject "Closes #3\r\n"             "[$epic1,$in_review]" "[$(pr 30 $'Closes #3\r\n')]" 3 review-without-pr
reject "Closes owner/repo#3 (GitHub links this)" "[$epic1,$in_review]" "[$(pr 30 'Closes jarno-niemela/Wardenlens#3')]" 3 review-without-pr
reject "Closes full issue URL (GitHub links this)" "[$epic1,$in_review]" "[$(pr 30 'Closes https://github.com/jarno-niemela/Wardenlens/issues/3')]" 3 review-without-pr
reject "Closes #3, closes #4"      "[$epic1,$in_review,$in_review4]" "[$(pr 30 'Closes #3, closes #4')]" 4 review-without-pr
# GitHub itself links "does not fix #3" (it only looks at the keyword), so we mirror it.
reject "'does not fix #3' counts as a closing ref (mirrors GitHub)" "[$epic1,$in_review]" "[$(pr 30 'Prep work; does not fix #3 yet.')]" 30 pr-no-issue
expect "title-only 'fix #3' (GitHub does not link titles)" "[$epic1,$in_review]" "[$(pr 30 'no refs' 'fix #3 crash')]" 30 pr-no-issue

# --- null / missing fields -----------------------------------------------
reject "null issue body"   "[$epic1,$(jq -c '.body=null' <<<"$(iss 2 OPEN x "${TASK[@]}")")]" "[]" 2 bogus
reject "null PR body"      "[$epic1]" "[$(jq -c '.body=null' <<<"$(pr 30 x)")]" 30 bogus
reject "null PR title+body" "[$epic1]" "[$(jq -c '.body=null|.title=null' <<<"$(pr 30 x)")]" 30 bogus
reject "PR author null"    "[$epic1]" "[$(jq -c '.author=null|.body="Closes #1"' <<<"$(pr 30 x)")]" 30 bogus
reject "labels missing"    "[$(jq -c 'del(.labels)' <<<"$(iss 2 OPEN x)")]" "[]" 2 bogus
reject "assignees null on in-progress" "[$epic1,$(jq -c '.assignees=null' <<<"$(iss 2 OPEN 'Epic: #1' type:task status:in-progress priority:p2)")]" "[]" 2 bogus
reject "fractional-second timestamp" "[$epic1,$(jq -c '.updatedAt="2026-11-01T00:00:00.123Z"' <<<"$(iss 2 OPEN 'Epic: #1' type:task status:backlog priority:p2)")]" "[]" 2 bogus
reject "empty arrays"      "[]" "[]" 0 bogus
reject "huge issue number" "[$epic1,$(iss 2 OPEN 'Epic: #99999999999999999999' "${TASK[@]}")]" "[]" 2 bogus

exit $fail
