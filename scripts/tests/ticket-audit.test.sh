#!/usr/bin/env bash
# Offline regression tests for scripts/ticket-audit rules.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fx=$root/scripts/tests/fixtures
now=$(date -d 2026-11-22T00:00:00Z +%s 2>/dev/null || date -j -f %Y-%m-%dT%H:%M:%SZ 2026-11-22T00:00:00Z +%s)
out=$("$root/scripts/ticket-audit" --json --fail-on never --repo jarno-niemela/Wardenlens --issues-file "$fx/issues.json" --prs-file "$fx/prs.json" --now "$now")

fail=0
expect() {  # expect NUMBER RULE
  if jq -e --argjson n "$1" --arg r "$2" 'any(.[]; .number == $n and .rule == $r)' <<<"$out" >/dev/null; then
    echo "ok   #$1 $2"
  else
    echo "FAIL #$1 $2 not reported"; fail=1
  fi
}
reject_rule() {  # reject_rule NUMBER RULE
  if jq -e --argjson n "$1" --arg r "$2" 'any(.[]; .number == $n and .rule == $r) | not' <<<"$out" >/dev/null; then
    echo "ok   #$1 no $2"
  else
    echo "FAIL #$1 unexpectedly reported $2"; fail=1
  fi
}
reject() {  # reject NUMBER  (issue must produce no findings)
  if jq -e --argjson n "$1" 'any(.[]; .number == $n) | not' <<<"$out" >/dev/null; then
    echo "ok   #$1 clean"
  else
    echo "FAIL #$1 unexpectedly flagged: $(jq -c --argjson n "$1" 'map(select(.number == $n))' <<<"$out")"; fail=1
  fi
}

# issues and PRs that must be clean
reject 1; reject 2; reject 11; reject 14; reject 19; reject 20; reject 22; reject 24; reject 25
reject 26; reject 28; reject 29; reject 35; reject 36; reject 38; reject 39; reject 31; reject 32
# every rule has a positive fixture
expect 3 type-label; expect 3 status-label
expect 4 stale-in-progress; expect 4 unassigned-in-progress
expect 5 review-without-pr
expect 6 unblocked
expect 7 closed-stale-status
expect 8 ready-but-blocked
expect 9 empty-epic
expect 10 bad-epic; expect 10 status-label; expect 10 priority-label
expect 12 stale-backlog
expect 13 orphan-task
expect 15 closed-epic
expect 16 blocked-no-reason
expect 17 done-but-open
expect 18 epic-complete
expect 23 bad-blocker
expect 21 pr-no-issue; expect 21 stale-pr
expect 27 pr-bad-ref
# a bot PR without closing refs is exempt; a human PR without refs is not
reject_rule 22 pr-no-issue
expect 34 pr-no-issue
# non-open PRs are ignored; a blocker that is an open PR keeps the ticket blocked
reject 35
reject_rule 24 unblocked
reject_rule 23 unblocked
# a fully verified PR is exempt from stale-pr; a partly verified one is not
reject_rule 36 stale-pr
expect 37 stale-pr
# a closing ref in the title only does not link the issue (GitHub ignores titles)
expect 30 review-without-pr
# Epic line mid-body, issue-form rendering and CRLF all count as an epic link
reject_rule 25 orphan-task; reject_rule 38 orphan-task; reject_rule 39 orphan-task
# owner/repo#N and URL closing refs link the issue
reject_rule 28 review-without-pr; reject_rule 29 review-without-pr
# the epic with only closed tasks is complete; epic 1 (open late-epic children) is not
reject_rule 1 epic-complete

# exit-code contract
if "$root/scripts/ticket-audit" --fail-on error --repo jarno-niemela/Wardenlens --issues-file "$fx/issues.json" --prs-file "$fx/prs.json" --now "$now" >/dev/null; then
  echo "FAIL expected non-zero exit with errors present"; fail=1
else echo "ok   exit code on errors"; fi
echo '[]' >"${TMPDIR:-/tmp}/empty.$$.json"
if "$root/scripts/ticket-audit" --repo jarno-niemela/Wardenlens --issues-file "${TMPDIR:-/tmp}/empty.$$.json" --prs-file "${TMPDIR:-/tmp}/empty.$$.json" >/dev/null; then
  echo "ok   clean exit"
else echo "FAIL clean input should exit 0"; fail=1; fi
rm -f "${TMPDIR:-/tmp}/empty.$$.json"

# repo detection: the live path asks `gh repo view` and uses its answer (no hard-coded default);
# offline mode without --repo is a usage error.
stubdir=$(mktemp -d); trap 'rm -rf "$stubdir"' EXIT
cat >"$stubdir/gh" <<'STUB'
#!/usr/bin/env bash
echo "gh $*" >>"$CALLS"
case "$1 $2" in
  "repo view") echo fork-owner/Wardenlens ;;
  "issue list") echo '[{"number":3,"title":"t","state":"OPEN","labels":[{"name":"type:task"},{"name":"status:in-review"},{"name":"priority:p2"}],"body":"Epic: #1","assignees":[],"updatedAt":"2026-11-21T00:00:00Z"},{"number":1,"title":"e","state":"OPEN","labels":[{"name":"type:epic"},{"name":"status:backlog"}],"body":"","assignees":[],"updatedAt":"2026-11-21T00:00:00Z"}]' ;;
  "pr list") echo '[{"number":9,"title":"p","body":"Closes fork-owner/Wardenlens#3","state":"OPEN","createdAt":"2026-11-21T00:00:00Z","isDraft":false,"reviewDecision":"","author":{"login":"x","is_bot":false},"labels":[]}]' ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$stubdir/gh"
export CALLS=$stubdir/calls
: >"$CALLS"
live=$(PATH="$stubdir:$PATH" "$root/scripts/ticket-audit" --json --fail-on never --now "$now")
if grep -q '^gh repo view' "$CALLS" && jq -e 'any(.[]; .rule == "review-without-pr") | not' <<<"$live" >/dev/null; then
  echo "ok   live path uses gh repo view (fork-owner/Wardenlens)"
else echo "FAIL live path did not use the repo from gh repo view"; fail=1; fi
: >"$CALLS"
live=$(PATH="$stubdir:$PATH" "$root/scripts/ticket-audit" --json --fail-on never --repo jarno-niemela/Wardenlens --now "$now")
if jq -e 'any(.[]; .rule == "review-without-pr")' <<<"$live" >/dev/null; then echo "ok   --repo overrides gh repo view"
else echo "FAIL --repo did not override"; fail=1; fi
rc=0; "$root/scripts/ticket-audit" --issues-file "$fx/issues.json" --prs-file "$fx/prs.json" --now "$now" >/dev/null 2>&1 || rc=$?
if [[ $rc -eq 2 ]]; then echo "ok   offline without --repo is a usage error"; else echo "FAIL offline without --repo exited $rc"; fail=1; fi
# one file only is not offline: it must use gh repo view and must not be a usage error
: >"$CALLS"
rc=0; PATH="$stubdir:$PATH" "$root/scripts/ticket-audit" --issues-file "$fx/issues.json" --now "$now" >/dev/null 2>&1 || rc=$?
if [[ $rc -ne 2 ]] && grep -q '^gh repo view' "$CALLS"; then echo "ok   one file only is not offline (uses gh repo view)"; else echo "FAIL one file only treated as offline"; fail=1; fi
exit $fail
