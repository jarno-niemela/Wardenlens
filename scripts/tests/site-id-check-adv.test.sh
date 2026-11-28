#!/usr/bin/env bash
# Adversarial cases for scripts/site-id-check (#233). Synthetic ids and a synthetic tree only, never a real site
# list. Every check states what a correct gate does; FAIL lines are findings.
# shellcheck disable=SC2015,SC2016  # A && ok || bad: ok never fails; literal $ and backticks in fixtures
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tool=$root/scripts/site-id-check
tmp=$(mktemp -d); trap 'chmod -R u+rwX "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
t=$tmp/tree
fresh() { rm -rf "$t"; mkdir -p "$t/crates/a/src" "$t/scripts" "$t/spikes/s" "$t/docker"; printf 'clean\n' >"$t/scripts/clean.sh"; }
# run <list-file> -> sets rc and out
run() { out=$(WARDENLENS_SITE_IDS_FILE=$1 "$tool" "$t" 2>&1); rc=$?; }
plant() { printf '%s\n' "$2" >"$t/$1"; }

# --- list-file parsing: every id in the list must be checked -------------------------------------------------
fresh; plant scripts/x.sh 'echo zq-site-7'
printf 'zq-site-7' >"$tmp/no-eol"   # last (only) line without a trailing newline
run "$tmp/no-eol"
[[ $rc == 1 ]] && ok "the last id in a list without a trailing newline is still checked" \
  || bad "list without trailing newline: last id silently unchecked ($rc: $out)"

printf 'zz-other\nzq-site-7' >"$tmp/no-eol2"
run "$tmp/no-eol2"
[[ $rc == 1 ]] && ok "the last of several ids without a trailing newline is checked" \
  || bad "multi-line list without trailing newline: last id unchecked ($rc: $out)"

printf 'zq-site-7 \n' >"$tmp/trail-sp"
run "$tmp/trail-sp"
[[ $rc == 1 ]] && ok "an id with trailing whitespace in the list still matches (or is refused)" \
  || bad "trailing space in the list: id silently never matches ($rc: $out)"

printf 'zq-site-7\t\r\n' >"$tmp/trail-tab"
run "$tmp/trail-tab"
[[ $rc != 0 ]] && ok "an id with a trailing tab+CR still matches (or is refused)" \
  || bad "trailing tab in the list: id silently never matches ($rc: $out)"

printf 'zq-site-7\r\n' >"$tmp/crlf"
run "$tmp/crlf"
[[ $rc == 1 ]] && ok "a CRLF list matches" || bad "CRLF list ($rc: $out)"

# --- fail closed: a grep error must not turn into "ok" ------------------------------------------------------
fresh; plant scripts/x.sh 'echo zq-site-7'; printf 'zq-site-7\n' >"$tmp/ids"
printf 'unrelated\n' >"$t/docker/locked"; chmod 000 "$t/docker/locked"
run "$tmp/ids"
if [[ -r $t/docker/locked ]]; then ok "skipped: running as a user who can read mode-000 files"
else
  [[ $rc != 0 ]] && ok "an unreadable unrelated file does not hide an id found elsewhere" \
    || bad "unreadable unrelated file makes the whole check pass ($rc: $out)"
fi
chmod 644 "$t/docker/locked"

# --- whole-token matching: no false negatives on common source contexts --------------------------------------
fresh; printf 'zq-site-7\n' >"$tmp/ids"
for ctx in 'printf "a\nzq-site-7\n"' "CAMERAS=\$'a\\tzq-site-7'" '"cam:zq-site-7:host"' 'x/zq-site-7/y' '`zq-site-7`' \
           'zq-site-7.' '(zq-site-7)' '[cameras.zq-site-7]' 'id="zq-site-7"'; do
  fresh; plant scripts/x.sh "$ctx"
  run "$tmp/ids"
  [[ $rc == 1 ]] && ok "an id in context <$ctx> is found" || bad "id in context <$ctx> missed ($rc: $out)"
done
for ctx in 'zq-site-77' 'xzq-site-7' 'zq-site-7-b' 'zq-site-7_other'; do
  fresh; plant scripts/x.sh "$ctx"
  run "$tmp/ids"
  [[ $rc == 0 ]] && ok "a longer token <$ctx> is not a match" || bad "false positive on <$ctx> ($rc: $out)"
done

# --- regex metacharacters are literal -----------------------------------------------------------------------
fresh; plant docker/f 'axb'; printf 'a.b\n' >"$tmp/meta"
run "$tmp/meta"
[[ $rc == 0 ]] && ok "a . in an id is literal" || bad "'.' treated as a wildcard ($rc)"
plant docker/f 'a.b'; run "$tmp/meta"
[[ $rc == 1 ]] && ok "an id with . matches literally" || bad "literal a.b missed ($rc)"
for id in 'a(b' 'a[b' 'a*b' 'a|b' '-e' 'a\b' 'a$b' '^ab'; do
  fresh; printf '%s\n' "$id" >"$tmp/meta"
  plant docker/f "z $id z"
  run "$tmp/meta"
  [[ $rc == 1 ]] && ok "metachar id <$id> matches literally" || bad "metachar id <$id> ($rc: $out)"
  plant docker/f "z unrelated z"
  run "$tmp/meta"
  [[ $rc == 0 ]] && ok "metachar id <$id> does not match unrelated text" || bad "metachar id <$id> false positive ($rc: $out)"
done

# --- the id is never printed -------------------------------------------------------------------------------
fresh; plant spikes/s/zq-site-7.sh 'echo zq-site-7'; printf 'zq-site-7\n' >"$tmp/ids"
run "$tmp/ids"
[[ $rc == 1 && $out != *zq-site-7* ]] && ok "an id in a file name is not echoed" \
  || bad "the id is printed when it is part of a reported file name ($rc: $out)"

# --- list path handling -------------------------------------------------------------------------------------
fresh; printf 'zq-site-7\n' >"$tmp/ids"
out=$(cd "$tmp" && WARDENLENS_SITE_IDS_FILE=ids "$tool" "$t" 2>&1); rc=$?
[[ $rc == 0 ]] && ok "a relative list path is resolved before the cd to the root" \
  || bad "relative WARDENLENS_SITE_IDS_FILE: fails with rc $rc on a clean tree ($out)"

: >"$tmp/empty"
fresh; run "$tmp/empty"
[[ $rc != 1 ]] && ok "an empty list does not report a finding" || bad "empty list ($rc: $out)"

# A hostile list line is data, never shell.
fresh; printf '$(touch %s/PWNED)\n`touch %s/PWNED2`\n' "$tmp" "$tmp" >"$tmp/hostile"
run "$tmp/hostile"
[[ ! -e $tmp/PWNED && ! -e $tmp/PWNED2 && $rc == 0 ]] && ok "a hostile list line is not executed" || bad "hostile list ($rc: $out)"

# --- a NUL byte in a scanned text file must not hide an id --------------------------------------------------
fresh; printf 'echo zq-site-7\n\0\n' >"$t/scripts/x.sh"; printf 'zq-site-7\n' >"$tmp/ids"
run "$tmp/ids"
[[ $rc == 1 ]] && ok "a file with a NUL byte is still scanned" || bad "a NUL byte makes grep -I skip the file: id missed ($rc: $out)"

exit $fail
