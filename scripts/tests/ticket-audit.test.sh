#!/usr/bin/env bash
# Offline regression tests for scripts/ticket-audit rules.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fx=$root/scripts/tests/fixtures
now=$(date -d 2026-11-22T00:00:00Z +%s 2>/dev/null || date -j -f %Y-%m-%dT%H:%M:%SZ 2026-11-22T00:00:00Z +%s)
out=$("$root/scripts/ticket-audit" --json --fail-on never --issues-file "$fx/issues.json" --prs-file "$fx/prs.json" --now "$now")

fail=0
expect() {  # expect NUMBER RULE
  if jq -e --argjson n "$1" --arg r "$2" 'any(.[]; .number == $n and .rule == $r)' <<<"$out" >/dev/null; then
    echo "ok   #$1 $2"
  else
    echo "FAIL #$1 $2 not reported"; fail=1
  fi
}
reject() {  # reject NUMBER  (issue must produce no findings)
  if jq -e --argjson n "$1" 'any(.[]; .number == $n) | not' <<<"$out" >/dev/null; then
    echo "ok   #$1 clean"
  else
    echo "FAIL #$1 unexpectedly flagged: $(jq -c --argjson n "$1" 'map(select(.number == $n))' <<<"$out")"; fail=1
  fi
}

reject 1; reject 2; reject 11; reject 20; reject 22
expect 3 type-label; expect 3 status-label
expect 4 stale-in-progress; expect 4 unassigned-in-progress
expect 5 review-without-pr
expect 6 unblocked
expect 7 closed-stale-status
expect 8 ready-but-blocked
expect 9 empty-epic
expect 10 bad-epic; expect 10 status-label; expect 10 priority-label
expect 12 stale-backlog
expect 21 pr-no-issue; expect 21 stale-pr

# exit-code contract
if "$root/scripts/ticket-audit" --fail-on error --issues-file "$fx/issues.json" --prs-file "$fx/prs.json" --now "$now" >/dev/null; then
  echo "FAIL expected non-zero exit with errors present"; fail=1
else echo "ok   exit code on errors"; fi
echo '[]' >"${TMPDIR:-/tmp}/empty.$$.json"
if "$root/scripts/ticket-audit" --issues-file "${TMPDIR:-/tmp}/empty.$$.json" --prs-file "${TMPDIR:-/tmp}/empty.$$.json" >/dev/null; then
  echo "ok   clean exit"
else echo "FAIL clean input should exit 0"; fail=1; fi
rm -f "${TMPDIR:-/tmp}/empty.$$.json"
exit $fail
