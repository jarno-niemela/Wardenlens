#!/usr/bin/env bash
# Adversarial round 2 for scripts/verify. Offline: stub `gh` on PATH serves canned data in the
# order the real API uses (statuses newest first); git is real, in throwaway repos.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
verify=$root/scripts/verify
real_git=$(command -v git)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/statuses" "$tmp/gitbin"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$GH_LOG"
case "$1 $2" in
  "pr view") [[ -n "${PR_VIEW_FAIL:-}" ]] && exit 1; printf '%s\n' "$HEAD" ;;
  "pr checks") cat "$CHECKS" ;;
  "pr edit") ;;
  "api user") echo jarno-niemela ;;
  "api -X") ;;
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
# git wrapper: `diff`/`diff-tree` fail like a partial clone that cannot lazy-fetch trees; all else is real git.
cat >"$tmp/gitbin/git" <<STUB
#!/usr/bin/env bash
for a in "\$@"; do [[ "\$a" == diff || "\$a" == diff-tree ]] && { echo "fatal: could not fetch tree" >&2; exit 128; }; done
exec "$real_git" "\$@"
STUB
chmod +x "$tmp/bin/gh" "$tmp/gitbin/git"
export PATH="$tmp/bin:$PATH" GH_LOG="$tmp/gh.log" STATUS_DIR="$tmp/statuses" CHECKS="$tmp/checks.json"
fail=0
ALL_OK=$(jq -nc '[{name:"fmt · clippy · test · doc",bucket:"pass",workflow:"CI"},{name:"cargo-deny",bucket:"pass",workflow:"CI"},{name:"scripts (shellcheck + tooling tests + audit)",bucket:"pass",workflow:"CI"}]')
reset() { : >"$GH_LOG"; rm -f "$STATUS_DIR"/*.json; printf '%s' "$ALL_OK" >"$CHECKS"; unset PR_VIEW_FAIL; }
t_ok()   { local n=$1; shift; if "$@" >"$tmp/out" 2>"$tmp/err"; then echo "ok   $n"; else echo "FAIL $n: exit $?: $(head -c 300 "$tmp/err")"; fail=1; fi; }
t_fail() { local n=$1; shift; if "$@" >"$tmp/out" 2>"$tmp/err"; then echo "FAIL $n: expected failure (out: $(head -c 200 "$tmp/out"))"; fail=1; else echo "ok   $n"; fi; }
# raw status JSON written verbatim (API order: newest first)
statuses() { printf '%s\n' "$2" >"$STATUS_DIR/$1.json"; }
# st DIM STATE CREATED [LOGIN] [ID]: ids default to a decreasing sequence so API order (newest first) holds
echo 1000 >"$tmp/sid"
st() { local sid; sid=$(($(<"$tmp/sid") - 1)); echo "$sid" >"$tmp/sid"; printf '{"context":"verify/%s","state":"%s","description":"Opus %s verification","id":%s,"created_at":"%s","creator":{"login":"%s"}}' "$1" "$2" "$1" "${5:-$sid}" "$3" "${4:-jarno-niemela}"; }

repo=$tmp/repo
git init -q "$repo"; git -C "$repo" config user.email t@e; git -C "$repo" config user.name t
mkdir -p "$repo/crates/x/src" "$repo/crates/x/tests" "$repo/scripts/tests"
echo 1 >"$repo/crates/x/src/lib.rs"; echo 1 >"$repo/crates/x/src/gone.rs"
git -C "$repo" add -A; git -C "$repo" commit -q -m a; A=$(git -C "$repo" rev-parse HEAD)
echo 2 >"$repo/crates/x/src/lib.rs"
git -C "$repo" add -A; git -C "$repo" commit -q -m b; B=$(git -C "$repo" rev-parse HEAD)   # src change
git -C "$repo" mv crates/x/src/gone.rs crates/x/tests/gone.rs
git -C "$repo" commit -q -m c; C=$(git -C "$repo" rev-parse HEAD)                          # src -> tests rename
git -C "$repo" checkout -q "$A"; chmod +x "$repo/crates/x/src/lib.rs"
git -C "$repo" commit -q -am d; D=$(git -C "$repo" rev-parse HEAD)                         # mode change only
git -C "$repo" checkout -q "$A"; mkdir -p "$repo/crates/x/tests"; echo t >"$repo/crates/x/tests/t.rs"
git -C "$repo" add -A; git -C "$repo" commit -q -m e; E=$(git -C "$repo" rev-parse HEAD)   # tests only
cd "$repo"
ALL3() { statuses "$1" "[$(st quality success "$2"),$(st security success "$2"),$(st adversarial success "$2")]"; }

# --- input validation -------------------------------------------------------------------
reset; HEAD=$E; export HEAD
t_fail "mark: DIM with two words is not a DIM" "$verify" mark 7 "quality security" pass "$E"
t_fail "mark: DIM with embedded newline"     "$verify" mark 7 $'quality\nsecurity' pass "$E"
t_fail "mark: PR with leading +"             "$verify" mark +7 quality pass "$E"
t_fail "check: extra argument"               "$verify" check 7 8
t_ok   "help does not print set -euo"        bash -c "'$verify' --help | grep -vq 'set -euo' && ! '$verify' --help | grep -q 'set -euo'"

# --- check: latest status per context --------------------------------------------------
# Same-second updates: the API lists newest first; failure is newest. sort_by is stable, so the
# older success ends up last and wins in from_entries.
reset; HEAD=$E
T=2026-11-22T10:00:00Z
statuses "$E" "[$(st adversarial failure $T),$(st adversarial success $T),$(st quality success $T),$(st security success $T)]"
t_fail "check: same-second fail after pass (API newest-first) is not success" "$verify" check 7
# Distinct timestamps, newest first, split over two pages (gh --paginate prints one array per page).
reset; HEAD=$E
printf '%s\n%s\n' "[$(st adversarial failure 2026-11-22T10:00:05Z),$(st quality success 2026-11-22T10:00:04Z)]" \
  "[$(st security success 2026-11-22T10:00:03Z),$(st adversarial success 2026-11-22T10:00:01Z)]" >"$STATUS_DIR/$E.json"
t_fail "check: paginated, newest failure on page 1 wins" "$verify" check 7
# Who wrote the status is never checked: a workflow token (github-actions[bot]) can forge the gate.
reset; HEAD=$E
statuses "$E" "[$(st quality success $T github-actions\[bot\]),$(st security success $T github-actions\[bot\]),$(st adversarial success $T github-actions\[bot\])]"
t_fail "check: statuses forged by a workflow token are not accepted" "$verify" check 7

# --- mark: head lookup failure --------------------------------------------------------
reset; HEAD=$E; PR_VIEW_FAIL=1; export PR_VIEW_FAIL
t_fail "mark: unreadable PR head is an error, not 'not the head'" "$verify" mark 7 quality pass "$E"
unset PR_VIEW_FAIL

# --- carry: path filter ----------------------------------------------------------------
reset; HEAD=$C; ALL3 "$A" $T
t_fail "carry: src->tests rename is refused" "$verify" carry 7 "$A"
reset; HEAD=$D; ALL3 "$A" $T
t_fail "carry: mode change on src is refused" "$verify" carry 7 "$A"
reset; HEAD=$B; ALL3 "$A" $T
t_fail "carry: refused from a subdirectory with diff.relative=true" \
  env -C crates/x/tests GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=diff.relative GIT_CONFIG_VALUE_0=true "$verify" carry 7 "$A"
reset; HEAD=$B; ALL3 "$A" $T
t_fail "carry: fails closed when git diff errors" env PATH="$tmp/gitbin:$PATH" "$verify" carry 7 "$A"
# Head already carries a newer failure verdict; carry must not paper over it with the old success.
reset; HEAD=$E; ALL3 "$A" $T
statuses "$E" "[$(st adversarial failure 2026-11-23T00:00:00Z)]"
"$verify" carry 7 "$A" >/dev/null 2>&1 || true
if grep -q "statuses/$E.*context=verify/adversarial" "$GH_LOG"; then
  echo "FAIL carry: overwrote a newer failure on the head"; fail=1
else echo "ok   carry: keeps a newer failure on the head"; fi

# --- carry: submodule pointer hidden by .gitmodules ignore=all ----------------------------
sub=$tmp/sub; git init -q "$sub"; git -C "$sub" -c user.email=t@e -c user.name=t commit -q --allow-empty -m s1
s1=$(git -C "$sub" rev-parse HEAD); git -C "$sub" -c user.email=t@e -c user.name=t commit -q --allow-empty -m s2
s2=$(git -C "$sub" rev-parse HEAD)
r2=$tmp/r2; git init -q "$r2"; git -C "$r2" config user.email t@e; git -C "$r2" config user.name t
printf '[submodule "vendor"]\n\tpath = vendor\n\turl = ../sub\n\tignore = all\n' >"$r2/.gitmodules"
git -C "$r2" add .gitmodules; git -C "$r2" update-index --add --cacheinfo "160000,$s1,vendor"
git -C "$r2" commit -q -m a; SA=$(git -C "$r2" rev-parse HEAD)
git -C "$r2" update-index --cacheinfo "160000,$s2,vendor"; git -C "$r2" commit -q -m b; SB=$(git -C "$r2" rev-parse HEAD)
cd "$r2"; reset; HEAD=$SB; ALL3 "$SA" $T
t_fail "carry: submodule bump hidden by ignore=all is refused" "$verify" carry 7 "$SA"

exit $fail
