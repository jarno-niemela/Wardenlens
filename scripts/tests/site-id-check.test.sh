#!/usr/bin/env bash
# Tests for scripts/site-id-check with a synthetic id list and a synthetic tree (never a real site list).
# shellcheck disable=SC2015  # A && ok || bad: ok never fails
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tool=$root/scripts/site-id-check
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
t=$tmp/tree
mkdir -p "$t/crates/a/src" "$t/crates/a/tests" "$t/scripts" "$t/spikes/s" "$t/docker"
printf '// uses cam-front and tapo-c110\n' >"$t/crates/a/src/lib.rs"
printf 'let x = "zz9";\n' >"$t/crates/a/tests/x.rs"
printf 'zz9\n' >"$t/crates/a/src/tests.rs"
printf '# synthetic ids\nzz9\n\nsite-cam-77\r\n' >"$tmp/ids"
unset WARDENLENS_SITE_IDS_FILE
out=$("$tool" "$t" 2>&1); rc=$?
[[ $rc == 0 && $out == *skipped* ]] && ok "unset list: skipped with a notice, exit 0" || bad "unset list ($rc: $out)"
export WARDENLENS_SITE_IDS_FILE=$tmp/ids
out=$("$tool" "$t" 2>&1); rc=$?
[[ $rc == 0 && $out == *ok* ]] && ok "ids only in tests and as part of a longer token: pass" || bad "clean tree ($rc: $out)"
for place in crates/a/src/lib.rs scripts/x.sh spikes/s/y.sh docker/z; do
  cp "$t/crates/a/src/lib.rs" "$tmp/keep"; printf 'echo site-cam-77\n' >>"$t/$place"
  out=$("$tool" "$t" 2>&1); rc=$?
  [[ $rc == 1 && $out == *"$place"* && $out != *site-cam-77* ]] && ok "an id in $place fails and the id is not echoed" || bad "id in $place ($rc: $out)"
  cp "$tmp/keep" "$t/crates/a/src/lib.rs"; [[ $place == crates/a/src/lib.rs ]] || rm -f "$t/$place"
done
printf 'x zz9.\n' >"$t/scripts/k.sh"
"$tool" "$t" >/dev/null 2>&1 && bad "an id before punctuation must match" || ok "an id before punctuation matches"
rm "$t/scripts/k.sh"
printf 'ok\n' >"$t/compose.yaml"; printf 'a\\Eb\n' >"$tmp/bad"
WARDENLENS_SITE_IDS_FILE=$tmp/bad "$tool" "$t" >/dev/null 2>&1; rc=$?; [[ $rc == 0 ]] && ok "an id containing \\E is literal (no match on an unrelated tree)" || bad "\\E id"
printf 'a\\Eb\n' >"$t/compose.yaml"
WARDENLENS_SITE_IDS_FILE=$tmp/bad "$tool" "$t" >/dev/null 2>&1; rc=$?; [[ $rc == 1 ]] && ok "an id containing \\E matches itself literally" || bad "\\E id literal match"
WARDENLENS_SITE_IDS_FILE=$tmp/none "$tool" "$t" >/dev/null 2>&1; [[ $? == 2 ]] && ok "a missing list file is an error" || bad "missing list"
# <id>_main / <id>_sub (spike stream names) match; other snake_case forms are a documented limit (not caught).
for ctx in zq-site-7_main zq-site-7_sub; do
  printf 'x %s\n' "$ctx" >"$t/scripts/s.sh"; printf 'zq-site-7\n' >"$tmp/ids7"
  WARDENLENS_SITE_IDS_FILE=$tmp/ids7 "$tool" "$t" >/dev/null 2>&1; rc=$?; [[ $rc == 1 ]] && ok "<$ctx> matches" || bad "<$ctx> ($rc)"
done
printf 'x zq-site-7_other\n' >"$t/scripts/s.sh"
WARDENLENS_SITE_IDS_FILE=$tmp/ids7 "$tool" "$t" >/dev/null 2>&1; rc=$?; [[ $rc == 0 ]] && ok "documented limit: zq-site-7_other is not caught" || bad "limit row ($rc)"
rm -f "$t/scripts/s.sh"
# A git tree: only tracked files are candidates; a tracked path with an id is reported, redacted.
g=$tmp/gt; mkdir -p "$g/scripts"; git -C "$g" init -q; printf 'clean\n' >"$g/scripts/a.sh"; printf 'echo zq-site-7\n' >"$g/scripts/untracked.sh"
git -C "$g" add scripts/a.sh
WARDENLENS_SITE_IDS_FILE=$tmp/ids7 "$tool" "$g" >/dev/null 2>&1; rc=$?; [[ $rc == 0 ]] && ok "git tree: an untracked file is not scanned" || bad "git untracked ($rc)"
printf 'clean\n' >"$g/scripts/zq-site-7.sh"; git -C "$g" add scripts/zq-site-7.sh
out=$(WARDENLENS_SITE_IDS_FILE=$tmp/ids7 "$tool" "$g" 2>&1); rc=$?; [[ $rc == 1 && $out != *zq-site-7* ]] && ok "git tree: a tracked path with an id is reported, redacted" || bad "git path ($rc: $out)"
exit $fail
