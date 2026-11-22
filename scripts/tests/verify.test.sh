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
  "api user") echo jarno-niemela ;;
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
    i=$((i + 1)); items+="${items:+,}{\"context\":\"${cs%%:*}\",\"state\":\"${cs##*:}\",\"description\":\"Opus $(d=${cs%%:*}; echo "${d#verify/}") verification\",\"id\":$i,\"created_at\":\"2026-11-2${i}T00:00:00Z\",\"creator\":{\"login\":\"jarno-niemela\",\"type\":\"User\"}}"
  done
  printf '[%s]\n' "$items" >"$STATUS_DIR/$sha.json"
}
# The job names must match REQUIRED_CHECKS (and ci.yml; asserted below).
REQ1='fmt · clippy · test · doc'; REQ2='cargo-deny'; REQ3='scripts (shellcheck + tooling tests + audit)'
ALL_OK=$(jq -nc --arg a "$REQ1" --arg b "$REQ2" --arg c "$REQ3" '[{name:$a,bucket:"pass",workflow:"CI"},{name:$b,bucket:"pass",workflow:"CI"},{name:$c,bucket:"pass",workflow:"CI"},{name:"lint",bucket:"skipping",workflow:"CI"},{name:"verify/quality",bucket:"fail",workflow:"CI"}]')
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
jq -c --arg n "$REQ3" 'map(if .name == $n then .bucket = "pending" else . end)' <<<"$ALL_OK" >"$CHECKS"
t_fail "check: pending required check counts as failure" "$verify" check 7
jq -c --arg n "$REQ2" 'map(if .name == $n then .bucket = "fail" else . end)' <<<"$ALL_OK" >"$CHECKS"
t_fail "check: failing required check" "$verify" check 7
jq -c --arg n "$REQ1" 'map(select(.name != $n))' <<<"$ALL_OK" >"$CHECKS"
t_fail "check: required check missing" "$verify" check 7
check  "  names the missing check" grep -q "required check 'fmt" "$tmp/err"
printf '%s' '[{"name":"CI","bucket":"pass","workflow":"CI"}]' >"$CHECKS"
t_fail "check: an arbitrary passing check is not enough" "$verify" check 7
jq -c 'map(.workflow = "Other")' <<<"$ALL_OK" >"$CHECKS"
t_fail "check: required names from another workflow do not count" "$verify" check 7
check  "  names the missing check" grep -q "required check 'cargo-deny' is missing" "$tmp/err"
jq -c 'map(del(.workflow))' <<<"$ALL_OK" >"$CHECKS"
t_fail "check: checks without a workflow do not count" "$verify" check 7
printf '%s' '[]' >"$CHECKS"
t_fail "check: no CI reported" "$verify" check 7
printf '%s' "$ALL_OK" >"$CHECKS"
t_ok   "check: verify/* contexts are ignored in CI evaluation" "$verify" check 7

# REQUIRED_CHECKS must equal the job names in ci.yml, so a renamed job cannot silently stop gating.
want=$(grep -E '^    name: ' "$root/.github/workflows/ci.yml" | sed 's/^    name: //' | sort)
got=$(bash -c "$(sed -n '/^REQUIRED_CHECKS=(/,/^)/p' "$verify"); printf '%s\\n' \"\${REQUIRED_CHECKS[@]}\"" | sort)
check  "REQUIRED_CHECKS matches ci.yml job names" test "$want" = "$got"
# ...and every job must have a name: line, so an unnamed job cannot hide from the list
jobs=$(awk '/^jobs:/{j=1;next} j && /^  [A-Za-z0-9_-]+:[ ]*$/{n++} END{print n+0}' "$root/.github/workflows/ci.yml")
names=$(grep -cE '^    name: ' "$root/.github/workflows/ci.yml")
check  "ci.yml: every job has a name ($jobs jobs, $names names)" test "$jobs" -gt 0 -a "$jobs" = "$names"

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

# --- trust: creator, type and description; latest by id ------------------------------------
raw() {  # raw DIM STATE ID [LOGIN] [TYPE] [DESC] -> one status object
  jq -nc --arg d "$1" --arg s "$2" --argjson id "$3" --arg l "${4:-jarno-niemela}" --arg t "${5:-User}" --arg ds "${6:-Opus $1 verification}" \
    '{context:"verify/\($d)",state:$s,description:$ds,id:$id,created_at:"2026-11-22T00:00:00Z",creator:{login:$l,type:$t}}'
}
put() { local sha=$1; shift; printf '[%s]\n' "$(IFS=,; echo "$*")" >"$STATUS_DIR/$sha.json"; }
reset
put "$C" "$(raw quality success 1)" "$(raw security success 2)" "$(raw adversarial success 3 mallory)"
t_fail "check: status by another user is ignored" "$verify" check 7
put "$C" "$(raw quality success 1)" "$(raw security success 2)" "$(raw adversarial success 3 jarno-niemela Bot)"
t_fail "check: status by a Bot is ignored" "$verify" check 7
put "$C" "$(raw quality success 1)" "$(raw security success 2)" "$(raw adversarial success 3 jarno-niemela User 'looks good')"
t_fail "check: status with a foreign description is ignored" "$verify" check 7
put "$C" "$(raw quality success 1)" "$(raw security success 2)" "$(raw adversarial success 3)" "$(raw adversarial failure 4 mallory)"
t_ok   "check: untrusted failure neither overrides nor blocks" "$verify" check 7
put "$C" "$(raw quality success 1)" "$(raw security success 2)" "$(raw adversarial failure 9)" "$(raw adversarial success 3)"
t_fail "check: highest id wins regardless of listing order" "$verify" check 7
put "$C" "$(raw quality success 1)" "$(raw security success 2)" "$(raw adversarial success 9)" "$(raw adversarial failure 3)"
t_ok   "check: highest id wins (success newest)" "$verify" check 7

# --- DIM must be exact ---------------------------------------------------------------------
reset
t_fail "mark: DIM 'quality security'" "$verify" mark 7 "quality security" pass "$C"
t_fail "mark: DIM 'qual' (substring)" "$verify" mark 7 qual pass "$C"
check  "  nothing written" test ! -s "$GH_LOG"

# --- carry hardening -------------------------------------------------------------------------
reset; HEAD=$B; export HEAD
put "$A" "$(raw quality success 1)" "$(raw security success 2)" "$(raw adversarial success 3 mallory)"
t_ok   "carry: only trusted successes are carried" "$verify" carry 7 "$A"
check  "  carried quality" log_has "statuses/$B.*context=verify/quality"
check  "  did not carry the forged one" bash -c "! grep -q 'statuses/$B.*context=verify/adversarial' '$GH_LOG'"
reset; HEAD=$B; export HEAD
put "$A" "$(raw quality success 1)"
put "$B" "$(raw security failure 5)"
t_fail "carry: head with a trusted non-success status is refused" "$verify" carry 7 "$A"
check  "  posts nothing" bash -c "! grep -q 'statuses/' '$GH_LOG'"
reset; HEAD=$B; export HEAD
put "$A" "$(raw quality success 1)"
put "$B" "$(raw security failure 5 mallory)"
t_ok   "carry: an untrusted failure on the head does not block" "$verify" carry 7 "$A"
# a deleted test file is refused (D), even under a test path
git -C "$repo" checkout -q "$B"; git -C "$repo" rm -q crates/x/tests/t.rs; git -C "$repo" commit -q -m d; Dl=$(git -C "$repo" rev-parse HEAD)
reset; HEAD=$Dl; export HEAD
put "$B" "$(raw quality success 1)" "$(raw security success 2)" "$(raw adversarial success 3)"
t_fail "carry: deleting a test file is refused" "$verify" carry 7 "$B"

# --- carry: only regular files; fail closed when git cannot diff ----------------------------------
git -C "$repo" checkout -q "$B"
echo 1 >"$repo/scripts/tests/run.sh"; chmod +x "$repo/scripts/tests/run.sh"
git -C "$repo" add -A; git -C "$repo" commit -q -m exec; Ex=$(git -C "$repo" rev-parse HEAD)
reset; HEAD=$Ex; export HEAD
put "$B" "$(raw quality success 1)"
t_ok   "carry: an added executable test file (100755) is allowed" "$verify" carry 7 "$B"
git -C "$repo" checkout -q "$B"
ln -s /etc/passwd "$repo/scripts/tests/link"
git -C "$repo" add -A; git -C "$repo" commit -q -m symlink; Sl=$(git -C "$repo" rev-parse HEAD)
reset; HEAD=$Sl; export HEAD
put "$B" "$(raw quality success 1)"
t_fail "carry: a symlink under a test path (120000) is refused" "$verify" carry 7 "$B"
check  "  posts nothing" bash -c "! grep -q 'statuses/' '$GH_LOG'"
git -C "$repo" checkout -q "$B"
git -C "$repo" update-index --add --cacheinfo "160000,$A,scripts/tests/sub"
git -C "$repo" commit -q -m gitlink; Gl=$(git -C "$repo" rev-parse HEAD)
reset; HEAD=$Gl; export HEAD
put "$B" "$(raw quality success 1)"
t_fail "carry: a gitlink under a test path (160000) is refused" "$verify" carry 7 "$B"
check  "  posts nothing" bash -c "! grep -q 'statuses/' '$GH_LOG'"
mkdir -p "$tmp/gitfail"
real_git=$(command -v git)
printf '#!/usr/bin/env bash\nfor a in "$@"; do [[ "$a" == diff-tree ]] && { echo "fatal: simulated" >&2; exit 128; }; done\nexec %s "$@"\n' "$real_git" >"$tmp/gitfail/git"
chmod +x "$tmp/gitfail/git"
reset; HEAD=$B; export HEAD
put "$A" "$(raw quality success 1)"
t_fail "carry: fails closed when git diff-tree exits non-zero" env PATH="$tmp/gitfail:$PATH" "$verify" carry 7 "$A"
check  "  posts nothing" bash -c "! grep -q 'statuses/' '$GH_LOG'"

exit $fail
