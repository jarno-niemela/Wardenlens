#!/usr/bin/env bash
# Adversarial round 2 for scripts/site-id-check (#233). Synthetic ids and a synthetic tree only.
# shellcheck disable=SC2015
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tool=$root/scripts/site-id-check
tmp=$(mktemp -d); trap 'chmod -R u+rwX "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
t=$tmp/tree
fresh() { rm -rf "$t"; mkdir -p "$t/crates/a/src" "$t/scripts" "$t/spikes/s" "$t/docker"; printf 'clean\n' >"$t/scripts/clean.sh"; }
run() { out=$(WARDENLENS_SITE_IDS_FILE=$1 "$tool" "$t" 2>&1); rc=$?; }
printf 'zq-site-7\n' >"$tmp/ids"

# A list saved with a UTF-8 BOM (Windows editors; CRLF is already handled) must not silently drop the first id.
fresh; printf 'echo zq-site-7\n' >"$t/scripts/x.sh"
printf '\xef\xbb\xbfzq-site-7\r\n' >"$tmp/bom"
run "$tmp/bom"
[[ $rc != 0 ]] && ok "a BOM-prefixed list still checks (or refuses) its first id" || bad "BOM list: first id silently unchecked, reports ok ($rc: $out)"

# An id carried only in a scanned file NAME (a result file named after a camera).
fresh; printf 'clean\n' >"$t/spikes/s/zq-site-7.tsv"
run "$tmp/ids"
[[ $rc == 1 ]] && ok "an id only in a scanned file name is found" || bad "an id in a file name (content clean) is not reported ($rc: $out)"
fresh; mkdir -p "$t/docker/zq-site-7"; printf 'clean\n' >"$t/docker/zq-site-7/env"
run "$tmp/ids"
[[ $rc == 1 ]] && ok "an id only in a scanned directory name is found" || bad "an id in a directory name (content clean) is not reported ($rc: $out)"

# Redaction: a reported path carrying a different list id must not print that id.
fresh; printf 'echo zq-site-8\n' >"$t/spikes/s/zq-site-7.sh"; printf 'zq-site-7\nzq-site-8\n' >"$tmp/two"
run "$tmp/two"
[[ $rc == 1 && $out != *zq-site-7* ]] && ok "a path holding another list id is redacted" || bad "path leaks another list id ($rc: $out)"

# Exclusions are by basename anywhere: a source module dir named results/ or target/ is real code.
for d in results target; do
  fresh; mkdir -p "$t/crates/a/src/$d"; printf 'const C: &str = "zq-site-7";\n' >"$t/crates/a/src/$d/mod.rs"
  run "$tmp/ids"
  [[ $rc == 1 ]] && ok "an id in crates/a/src/$d/mod.rs is found" || bad "crates/a/src/$d/ is silently excluded ($rc: $out)"
done
fresh; printf 'echo zq-site-7\n' >"$t/scripts/site-id-check"; mkdir -p "$t/spikes/s/x"; printf 'echo zq-site-7\n' >"$t/spikes/s/x/site-id-check"
run "$tmp/ids"
[[ $rc == 1 ]] && ok "a spike file also named site-id-check is still scanned" || bad "any file named site-id-check is excluded ($rc: $out)"

# A symlinked script in a scanned dir (grep -r does not follow it).
fresh; mkdir -p "$tmp/elsewhere"; printf 'echo zq-site-7\n' >"$tmp/elsewhere/real.sh"; ln -s "$tmp/elsewhere/real.sh" "$t/scripts/link.sh"
run "$tmp/ids"
[[ $rc != 0 ]] && ok "a symlinked file in a scanned dir is checked (or refused)" || bad "a symlinked file is skipped silently ($rc: $out)"

# A trailing NBSP in the list (C locale [:space:] does not include it).
fresh; printf 'echo zq-site-7\n' >"$t/scripts/x.sh"; printf 'zq-site-7\xc2\xa0\n' >"$tmp/nbsp"
run "$tmp/nbsp"
[[ $rc != 0 ]] && ok "an NBSP-padded id matches or is refused" || bad "NBSP-padded id silently unchecked ($rc: $out)"

# A missing root must be a usage error (2), not "an id was found" (1).
out=$(WARDENLENS_SITE_IDS_FILE=$tmp/ids "$tool" "$tmp/nope" 2>&1); rc=$?
[[ $rc == 2 ]] && ok "a missing root is a usage error" || bad "a missing root exits $rc ($out)"

# A tree with none of the scanned paths: grep -r with no operand would scan '.' (everything, tests too).
rm -rf "$t"; mkdir -p "$t/docs/tests"; printf 'zq-site-7\n' >"$t/docs/tests/f"
out=$(WARDENLENS_SITE_IDS_FILE=$tmp/ids "$tool" "$t" 2>&1); rc=$?
[[ $rc != 1 ]] && ok "a root with no scanned paths does not scan outside the scope" || bad "no targets: scans the whole root ($rc: $out)"
rm -rf "$t"; mkdir -p "$t/docs"; printf 'zq-site-7\n' >"$t/docs/f"
out=$(WARDENLENS_SITE_IDS_FILE=$tmp/ids "$tool" "$t" 2>&1); rc=$?
[[ $rc != 1 ]] && ok "a root with no scanned paths does not flag docs/" || bad "no targets: docs/ scanned, false positive ($rc: $out)"

# A non-UTF-8 / multi-byte id matches literally.
fresh; printf 'echo k\xc3\xa4m-1\n' >"$t/scripts/x.sh"; printf 'k\xc3\xa4m-1\n' >"$tmp/u8"
run "$tmp/u8"
[[ $rc == 1 ]] && ok "a multi-byte id matches" || bad "multi-byte id missed ($rc: $out)"
# Other escapes before an id. `\u{2f}` happens to be found (the id follows a non-token byte). `\x20`, `\e` and `%2F` are
# DOCUMENTED LIMITS (see the header of scripts/site-id-check; the ARCH-7 review checklist covers them): asserted as not caught.
for ctx in 'a\\x20zq-site-7' 'echo -e "\\ezq-site-7"' 'rtsp://h/%2Fzq-site-7'; do
  fresh; printf '%s\n' "$ctx" >"$t/scripts/x.sh"; run "$tmp/ids"
  [[ $rc == 0 ]] && ok "documented limit: id in <$ctx> is not caught" || bad "limit changed for <$ctx> ($rc: $out)"
done
fresh; printf '%s\n' '"\\u{2f}zq-site-7"' >"$t/scripts/x.sh"; run "$tmp/ids"
[[ $rc == 1 ]] && ok "id after a \\u{2f} escape is found" || bad "\\u{2f} escape ($rc: $out)"
exit $fail
