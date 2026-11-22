#!/usr/bin/env bash
# Round 3b adversarial cases for scripts/verify: trust filtering, id ordering, required checks, carry.
# A stub gh serves canned data; git is real, in a throwaway repo.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
verify=$root/scripts/verify
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/statuses"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$GH_LOG"
case "$1 $2" in
  "pr view") [[ -n "${HEAD:-}" ]] || exit 1; printf '%s\n' "$HEAD" ;;
  "pr checks") cat "$CHECKS" ;;
  "pr edit") ;;
  "api -X") ;;
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

repo=$tmp/repo
git init -q "$repo"; git -C "$repo" config user.email t@example.com; git -C "$repo" config user.name t
mkdir -p "$repo/crates/x/src" "$repo/crates/x/tests" "$repo/scripts/tests"
echo 1 >"$repo/crates/x/src/lib.rs"
git -C "$repo" add -A; git -C "$repo" commit -q -m a; A=$(git -C "$repo" rev-parse HEAD)
echo 1 >"$repo/crates/x/tests/t.rs"
git -C "$repo" add -A; git -C "$repo" commit -q -m b; B=$(git -C "$repo" rev-parse HEAD)
chmod +x "$repo/crates/x/src/lib.rs"
git -C "$repo" add -A; git -C "$repo" commit -q -m c; C=$(git -C "$repo" rev-parse HEAD)
cd "$repo"

# st ID CONTEXT STATE [LOGIN] [TYPE] [DESCRIPTION] [CREATED_AT]
st() {
  local d=${2#verify/}
  jq -nc --argjson id "$1" --arg c "$2" --arg s "$3" --arg l "${4:-jarno-niemela}" --arg t "${5:-User}" \
    --arg desc "${6:-Opus $d verification}" --arg at "${7:-2026-11-20T00:00:00Z}" \
    '{id:$id,context:$c,state:$s,description:$desc,created_at:$at,creator:{login:$l,type:$t}}'
}
put() { local sha=$1; shift; printf '[%s]\n' "$(IFS=,; echo "$*")" >"$STATUS_DIR/$sha.json"; }
REQ1='fmt · clippy · test · doc'; REQ2='cargo-deny'; REQ3='scripts (shellcheck + tooling tests + audit)'
ALL_OK=$(jq -nc --arg a "$REQ1" --arg b "$REQ2" --arg c "$REQ3" '[{name:$a,bucket:"pass",workflow:"CI"},{name:$b,bucket:"pass",workflow:"CI"},{name:$c,bucket:"pass",workflow:"CI"}]')
reset() { : >"$GH_LOG"; rm -f "$STATUS_DIR"/*.json; printf '%s' "$ALL_OK" >"$CHECKS"; HEAD=$B; export HEAD; }
t_ok()   { local n=$1; shift; if "$@" >"$tmp/out" 2>"$tmp/err"; then echo "ok   $n"; else echo "FAIL $n: $(head -c 300 "$tmp/err")"; fail=1; fi; }
t_fail() { local n=$1; shift; if "$@" >"$tmp/out" 2>"$tmp/err"; then echo "FAIL $n: expected failure"; fail=1; else echo "ok   $n"; fi; }
t_gap()  { local n=$1; shift; if "$@" >"$tmp/out" 2>"$tmp/err"; then echo "FAIL $n: expected failure"; fail=1; elif grep -q "not mergeable" "$tmp/err"; then echo "ok   $n"; else echo "FAIL $n: failed for another reason: $(head -c 200 "$tmp/err")"; fail=1; fi; }
check()  { local n=$1; shift; if "$@"; then echo "ok   $n"; else echo "FAIL $n"; fail=1; fi; }
ALL3() { st 1 verify/quality success; st 2 verify/security success; st 3 verify/adversarial success; }

# --- check: trust and ordering --------------------------------------------------------------
reset; put "$B" "$(ALL3 | paste -sd,)"
t_ok   "check: baseline passes" "$verify" check 7
reset; put "$B" "$(ALL3 | paste -sd,)" "$(st 9 verify/security failure jarno-niemela User '' 2026-01-01T00:00:00Z)"
t_gap  "check: trusted failure with higher id but older created_at wins" "$verify" check 7
reset; put "$B" "$({ st 1 verify/quality success; st 2 verify/security success; st 3 verify/adversarial success other-user; } | paste -sd,)"
t_gap  "check: success from another user does not count" "$verify" check 7
reset; put "$B" "$({ st 1 verify/quality success; st 2 verify/security success; st 3 verify/adversarial success jarno-niemela Bot; } | paste -sd,)"
t_gap  "check: success from a Bot with the operator login does not count" "$verify" check 7
reset; put "$B" "$({ st 1 verify/quality success; st 2 verify/security success; st 3 verify/adversarial success jarno-niemela User 'Opus quality verification'; } | paste -sd,)"
t_gap  "check: description naming another dimension does not count" "$verify" check 7
reset; put "$B" "$(ALL3 | paste -sd,)" "$(st 9 verify/quality success other-user)" "$(st 8 verify/quality failure)"
t_gap  "check: untrusted newer success does not override a trusted failure" "$verify" check 7
# --- check: required checks -------------------------------------------------------------------
reset; put "$B" "$(ALL3 | paste -sd,)"
jq -c --arg n "$REQ2" '. + [{name:$n,bucket:"fail",workflow:"CI"}]' <<<"$ALL_OK" >"$CHECKS"
t_gap  "check: duplicate required name with one failing run" "$verify" check 7
jq -c --arg n "$REQ2" 'map(if .name == $n then .bucket = "skipping" else . end)' <<<"$ALL_OK" >"$CHECKS"
t_gap  "check: skipped required check is not a pass" "$verify" check 7
jq -c --arg n "$REQ2" 'map(if .name == $n then .bucket = "cancel" else . end)' <<<"$ALL_OK" >"$CHECKS"
t_gap  "check: cancelled required check is not a pass" "$verify" check 7
jq -c --arg n "$REQ2 " 'map(if .name == "cargo-deny" then .name = $n else . end)' <<<"$ALL_OK" >"$CHECKS"
t_gap  "check: near-miss name (trailing space) is not the required check" "$verify" check 7
printf 'not json' >"$CHECKS"
t_fail "check: garbage from gh pr checks fails closed" "$verify" check 7
# --- mark ---------------------------------------------------------------------------------------
reset; HEAD=""; export HEAD
t_fail "mark: unreadable PR head exits non-zero" "$verify" mark 7 quality pass "$B"
check  "  and posts no status" bash -c "! grep -q 'api -X POST' '$GH_LOG'"
reset
t_fail "mark: DIM with trailing space" "$verify" mark 7 'quality ' pass "$B"
t_fail "mark: DIM in other case" "$verify" mark 7 Quality pass "$B"
t_fail "mark: glob-like DIM" "$verify" mark 7 'qual*' pass "$B"
# --- carry --------------------------------------------------------------------------------------
reset; put "$A" "$(ALL3 | paste -sd,)"; put "$B" "$(st 5 verify/quality pending)"
t_fail "carry: refused when head has a trusted pending status" "$verify" carry 7 "$A"
check  "  because of the head status" grep -q "non-success" "$tmp/err"
reset; put "$A" "$(ALL3 | paste -sd,)"; put "$B" "$(st 5 verify/quality failure other-user)"
t_ok   "carry: untrusted failure on head does not block" "$verify" carry 7 "$A"
reset; put "$A" "$({ st 1 verify/quality success jarno-niemela Bot; st 2 verify/security success other; st 3 verify/adversarial success jarno-niemela User 'Opus adversarial verdict'; } | paste -sd,)"
t_ok   "carry: runs with only untrusted statuses on FROM" "$verify" carry 7 "$A"
check  "  carries none of them" bash -c "! grep -q 'api -X POST' '$GH_LOG'"
reset; put "$A" "$(ALL3 | paste -sd,)" "$(st 7 verify/quality failure)"
t_ok   "carry: superseded success on FROM" "$verify" carry 7 "$A"
check  "  is not carried" bash -c "! grep -q 'statuses/$B.*context=verify/quality' '$GH_LOG'"
reset; HEAD=$C; export HEAD; put "$B" "$(ALL3 | paste -sd,)"
t_fail "carry: mode-only change of a source file is refused" "$verify" carry 7 "$B"
check  "  because of the diff" grep -q "M crates/x/src/lib.rs" "$tmp/err"
reset; HEAD=$B; export HEAD; put "$C" "$(ALL3 | paste -sd,)"
t_fail "carry: backwards diff (FROM newer, source differs) is refused" "$verify" carry 7 "$C"
check  "  because of the diff" grep -q "crates/x/src/lib.rs" "$tmp/err"
exit $fail
