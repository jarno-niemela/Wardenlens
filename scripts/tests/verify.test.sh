#!/usr/bin/env bash
# Offline tests for scripts/verify: input validation, SHA binding and the carry path filter.
# A stub `gh` (on PATH) logs every call and serves canned data; git is real, in a throwaway repo.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
verify=$root/scripts/verify
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/statuses"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$GH_LOG"
case "$1 $2" in
  "pr view") printf '%s\n' "$HEAD" ;;
  "pr checks") cat "$CHECKS" ;;
  "pr edit") ;;
  "api -X") ;;   # POST status
  "api --paginate")
    for a in "$@"; do
      if [[ "$a" =~ commits/([0-9a-f]{40})/statuses ]]; then
        f=$STATUS_DIR/${BASH_REMATCH[1]}.json
        if [[ -f "$f" ]]; then cat "$f"; else echo '[]'; fi
      fi
    done ;;
  *) echo "stub gh: unexpected $*" >&2; exit 1 ;;
esac
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" GH_LOG="$tmp/gh.log" STATUS_DIR="$tmp/statuses" CHECKS="$tmp/checks.json"
fail=0

# --- a real repo: A (src) -> B (tests only) -> C (src change) --------------
repo=$tmp/repo
git init -q "$repo"
git -C "$repo" config user.email t@example.com
git -C "$repo" config user.name t
mkdir -p "$repo/crates/x/src" "$repo/crates/x/tests" "$repo/scripts/tests"
echo 1 >"$repo/crates/x/src/lib.rs"
git -C "$repo" add -A; git -C "$repo" commit -q -m a; A=$(git -C "$repo" rev-parse HEAD)
echo 1 >"$repo/crates/x/tests/t.rs"; echo 1 >"$repo/scripts/tests/t.sh"
git -C "$repo" add -A; git -C "$repo" commit -q -m b; B=$(git -C "$repo" rev-parse HEAD)
echo 2 >"$repo/crates/x/src/lib.rs"
git -C "$repo" add -A; git -C "$repo" commit -q -m c; C=$(git -C "$repo" rev-parse HEAD)
cd "$repo"

status_file() {  # status_file SHA context:state...
  local sha=$1; shift; local items="" i=0
  for cs in "$@"; do
    i=$((i + 1)); items+="${items:+,}{\"context\":\"${cs%%:*}\",\"state\":\"${cs##*:}\",\"description\":\"d\",\"created_at\":\"2026-11-2${i}T00:00:00Z\"}"
  done
  printf '[%s]\n' "$items" >"$STATUS_DIR/$sha.json"
}
ALL_OK='[{"name":"CI","bucket":"pass"},{"name":"lint","bucket":"skipping"}]'
reset() { : >"$GH_LOG"; rm -f "$STATUS_DIR"/*.json; printf '%s' "$ALL_OK" >"$CHECKS"; HEAD=$C; export HEAD; }
t_ok()   { local n=$1; shift; if "$@" >"$tmp/out" 2>"$tmp/err"; then echo "ok   $n"; else echo "FAIL $n: exit $?: $(head -c 300 "$tmp/err")"; fail=1; fi; }
t_fail() { local n=$1; shift; if "$@" >"$tmp/out" 2>"$tmp/err"; then echo "FAIL $n: expected failure"; fail=1; else echo "ok   $n"; fi; }
# shellcheck disable=SC2329  # invoked indirectly through check()
log_has()  { grep -q -- "$1" "$GH_LOG"; }
check() { local n=$1; shift; if "$@"; then echo "ok   $n"; else echo "FAIL $n"; fail=1; fi; }

# --- input validation: bad input must fail before gh is ever called -----------
reset
t_fail "mark: non-numeric PR"      "$verify" mark abc quality pass "$C"
t_fail "mark: unknown DIM"         "$verify" mark 7 style pass "$C"
t_fail "mark: short SHA"           "$verify" mark 7 quality pass abc123
t_fail "mark: uppercase SHA"       "$verify" mark 7 quality pass "${C^^}"
t_fail "mark: SHA with suffix"     "$verify" mark 7 quality pass "${C}x"
t_fail "mark: bad verdict"         "$verify" mark 7 quality maybe "$C"
t_fail "mark: missing SHA"         "$verify" mark 7 quality pass
t_fail "check: non-numeric PR"     "$verify" check '7;id'
t_fail "check: missing PR"         "$verify" check
t_fail "carry: bad FROM_SHA"       "$verify" carry 7 notasha
t_fail "carry: non-numeric PR"     "$verify" carry x "$A"
t_fail "unknown command"           "$verify" frobnicate
check  "validation made no gh calls" test ! -s "$GH_LOG"

# --- mark -------------------------------------------------------------------
reset
t_ok   "mark pass on head" "$verify" mark 7 quality pass "$C"
check  "  posts success status on that SHA" log_has "statuses/$C.*state=success.*context=verify/quality"
check  "  adds label on head" log_has "pr edit 7 --add-label verify:quality"
reset
t_ok   "mark fail on head" "$verify" mark 7 security fail "$C"
check  "  posts failure status" log_has "state=failure.*context=verify/security"
check  "  removes label" log_has "pr edit 7 --remove-label verify:security"
reset
t_ok   "mark pass on stale SHA" "$verify" mark 7 adversarial pass "$A"
check  "  records the status on the stale SHA" log_has "statuses/$A"
check  "  leaves labels alone" bash -c "! grep -q 'pr edit' '$GH_LOG'"

# --- check ------------------------------------------------------------------
reset
status_file "$C" verify/quality:success verify/security:success verify/adversarial:success
t_ok   "check: all verified on head" "$verify" check 7
check  "  prints the head SHA" test "$(cat "$tmp/out")" = "$C"
reset
status_file "$C" verify/quality:success verify/security:success
t_fail "check: one dimension missing" "$verify" check 7
check  "  names it" grep -q 'verify/adversarial is missing' "$tmp/err"
reset
status_file "$A" verify/quality:success verify/security:success verify/adversarial:success
t_fail "check: verified on an older SHA only" "$verify" check 7
reset
status_file "$C" verify/quality:success verify/security:success verify/adversarial:success verify/adversarial:failure
t_fail "check: latest status per context wins (success then failure)" "$verify" check 7
reset
status_file "$C" verify/quality:success verify/security:success verify/adversarial:failure verify/adversarial:success
t_ok   "check: latest status per context wins (failure then success)" "$verify" check 7
reset
status_file "$C" verify/quality:success verify/security:success verify/adversarial:success
printf '%s' '[{"name":"CI","bucket":"pending"}]' >"$CHECKS"
t_fail "check: pending CI counts as failure" "$verify" check 7
printf '%s' '[{"name":"CI","bucket":"fail"}]' >"$CHECKS"
t_fail "check: failing CI" "$verify" check 7
printf '%s' '[]' >"$CHECKS"
t_fail "check: no CI reported" "$verify" check 7

# --- carry ------------------------------------------------------------------
reset; HEAD=$B; export HEAD
status_file "$A" verify/quality:success verify/security:success verify/adversarial:failure
t_ok   "carry: test-only diff is allowed" "$verify" carry 7 "$A"
check  "  copies success statuses to head" log_has "statuses/$B.*context=verify/quality.*carried from"
check  "  does not copy the failure" bash -c "! grep -q 'statuses/$B.*context=verify/adversarial' '$GH_LOG'"
reset; HEAD=$C; export HEAD
status_file "$A" verify/quality:success verify/security:success verify/adversarial:success
t_fail "carry: source change is refused" "$verify" carry 7 "$A"
check  "  lists the offending file" grep -q 'crates/x/src/lib.rs' "$tmp/err"
check  "  posts nothing" bash -c "! grep -q 'statuses' '$GH_LOG'"

exit $fail
