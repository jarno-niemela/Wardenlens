#!/usr/bin/env bash
# Adversarial round 3 for scripts/site-id-check (#233). Synthetic ids and a synthetic tree only.
# shellcheck disable=SC2015,SC2016
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tool=$root/scripts/site-id-check
tmp=$(mktemp -d); trap 'chmod -R u+rwX "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_CEILING_DIRECTORIES
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
t=$tmp/tree
printf 'zq-site-7\n' >"$tmp/ids"
g() { git -C "$t" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@" >/dev/null 2>&1; }
fresh_git() {
  chmod -R u+rwX "$t" 2>/dev/null; rm -rf "$t"; mkdir -p "$t/scripts" "$t/spikes/s"
  printf 'clean\n' >"$t/scripts/clean.sh"; g init -q; g add -A; g commit -qm init
}
run() { out=$(WARDENLENS_SITE_IDS_FILE=$tmp/ids "$tool" "$t" 2>&1); rc=$?; }

# Baseline: a tracked file with the id is found in a git root.
fresh_git; printf 'echo zq-site-7\n' >"$t/spikes/s/x.sh"; g add -A; g commit -qm x
run; [[ $rc == 1 ]] && ok "baseline: tracked id found" || bad "baseline: tracked id not found ($rc: $out)"

# The header: "2 a usage or tool error (... no file list ...). An error never counts as clean."
# A failing `git ls-files` (corrupt index) must not be read as an empty tree.
fresh_git; printf 'echo zq-site-7\n' >"$t/spikes/s/x.sh"; g add -A; g commit -qm x
printf 'garbage' >"$t/.git/index"
git -C "$t" rev-parse --show-toplevel >/dev/null 2>&1 && ! git -C "$t" ls-files >/dev/null 2>&1 || echo "note: setup did not break ls-files"
run; [[ $rc != 0 ]] && ok "a failing git ls-files is an error" || bad "git ls-files failed, yet exit 0 ($out)"

# A tracked, scanned file whose content cannot be read because its directory lacks search permission: the check must
# not report ok (the header: an unreadable file is a grep failure, exit 2).
fresh_git; mkdir -p "$t/spikes/s/d"; printf 'echo zq-site-7\n' >"$t/spikes/s/d/x.sh"; g add -A; g commit -qm x
chmod 0600 "$t/spikes/s/d"
run; chmod 0700 "$t/spikes/s/d"
[[ $rc != 0 ]] && ok "a tracked file in an unsearchable dir is not passed as clean" || bad "tracked file behind a 0600 dir: content skipped, exit 0 ($out)"

# Non-git root: find cannot enter a directory; the check must not report ok.
chmod -R u+rwX "$t"; rm -rf "$t"; mkdir -p "$t/spikes/s/d" "$t/scripts"; printf 'clean\n' >"$t/scripts/c.sh"
printf 'echo zq-site-7\n' >"$t/spikes/s/d/x.sh"; chmod 0000 "$t/spikes/s/d"
run; chmod 0700 "$t/spikes/s/d"
[[ $rc != 0 ]] && ok "non-git root: an unreadable dir is not passed as clean" || bad "non-git root: find error ignored, exit 0 ($out)"

# A tracked file that is not a regular file in the work tree (replaced by a directory): content cannot be vouched for.
fresh_git; printf 'echo zq-site-7\n' >"$t/spikes/s/x.sh"; g add -A; g commit -qm x
rm "$t/spikes/s/x.sh"; mkfifo "$t/spikes/s/x.sh"
run; [[ $rc != 0 ]] && ok "a tracked path that is a FIFO in the work tree is not clean" || bad "tracked file replaced by a FIFO: exit 0 ($out)"

# Staged content differs from the work tree: the id is staged (what gets committed) but the work tree is clean.
fresh_git; printf 'echo zq-site-7\n' >"$t/spikes/s/x.sh"; g add -A; printf 'clean\n' >"$t/spikes/s/x.sh"
# DOCUMENTED LIMIT (header of scripts/site-id-check): content is read from the work tree; staged-only content is not checked.
run; [[ $rc == 0 ]] && ok "documented limit: an id only in the index is not caught" || bad "limit changed: index-only id, rc $rc ($out)"

# Committed content differs from the work tree (what gets pushed).
fresh_git; printf 'echo zq-site-7\n' >"$t/spikes/s/x.sh"; g add -A; g commit -qm x; printf 'clean\n' >"$t/spikes/s/x.sh"
# DOCUMENTED LIMIT: HEAD-only content that differs from the work tree is not checked.
run; [[ $rc == 0 ]] && ok "documented limit: an id only in HEAD is not caught" || bad "limit changed: HEAD-only id, rc $rc ($out)"

# Gitlink (submodule) under spikes/: its files are never scanned.
fresh_git; mkdir -p "$tmp/sub"; git -C "$tmp/sub" init -q; printf 'echo zq-site-7\n' >"$tmp/sub/x.sh"
git -C "$tmp/sub" add -A; git -C "$tmp/sub" -c user.name=t -c user.email=t@t commit -qm s
cp -r "$tmp/sub" "$t/spikes/m"; g add spikes/m; g commit -qm m
run; [[ $rc != 0 ]] && ok "a submodule under spikes/ is checked or refused" || bad "submodule under spikes/: content not scanned, exit 0 ($out)"

# Regex metacharacters in an id: no false positive, no crash.
fresh_git; printf 'echo camX1\n' >"$t/spikes/s/x.sh"; g add -A; g commit -qm x
printf 'cam.1\ncam(1\ncam[1\ncam\\1\ncam$1\n' >"$tmp/meta"
out=$(WARDENLENS_SITE_IDS_FILE=$tmp/meta "$tool" "$t" 2>&1); rc=$?
[[ $rc == 0 ]] && ok "regex metacharacters are literal" || bad "metachar id: rc $rc ($out)"
printf 'echo "cam(1"\n' >"$t/spikes/s/x.sh"
out=$(WARDENLENS_SITE_IDS_FILE=$tmp/meta "$tool" "$t" 2>&1); rc=$?
[[ $rc == 1 ]] && ok "an id with ( is found literally" || bad "cam(1 missed: rc $rc ($out)"

# A file name with a newline carrying the id: found and redacted.
fresh_git; printf 'clean\n' >"$t/spikes/s/a
zq-site-7.sh"; g add -A; g commit -qm x
run; [[ $rc == 1 && $out != *zq-site-7* ]] && ok "newline file name with id: found and redacted" || bad "newline name: rc $rc ($out)"

# Id in a path component that is the git root's tracked dot-dir (e.g. spikes/.zq-site-7/)
fresh_git; mkdir -p "$t/spikes/.zq-site-7"; printf 'clean\n' >"$t/spikes/.zq-site-7/f"; g add -A; g commit -qm x
run; [[ $rc == 1 ]] && ok "id after a dot in a path is found" || bad "dot-prefixed dir: rc $rc ($out)"
# The spike's other stream-name form, `<id>-<kind>` (gop_sample.sh prints n"-"k; results/stream-params.tsv rows).
fresh_git; printf 'echo zq-site-7-main\n' >"$t/spikes/s/x.sh"; g add -A; g commit -qm x
# DOCUMENTED LIMIT: hyphen compounds (<id>-main, <id>-onvif.tsv) are not caught; the ARCH-7 review checklist covers them.
run; [[ $rc == 0 ]] && ok "documented limit: <id>-main is not caught" || bad "limit changed: <id>-main, rc $rc ($out)"
# Crate files outside src/ are scanned (build.rs, benches/, examples/, Cargo.toml).
for p in build.rs benches/b.rs examples/e.rs Cargo.toml; do
  fresh_git; mkdir -p "$t/crates/a/$(dirname "$p")"; printf 'x zq-site-7\n' >"$t/crates/a/$p"; g add -A; g commit -qm x
  run; [[ $rc == 1 ]] && ok "an id in crates/a/$p is found" || bad "crates/a/$p not scanned ($rc: $out)"
done
# A tracked path deleted from the work tree: its name is still checked, its content skipped, no error.
fresh_git; printf 'echo zq-site-7\n' >"$t/spikes/s/x.sh"; g add -A; g commit -qm x; rm "$t/spikes/s/x.sh"
run; [[ $rc == 0 ]] && ok "a tracked file deleted from the work tree is skipped (documented)" || bad "deleted tracked file: rc $rc ($out)"
fresh_git; printf 'clean\n' >"$t/spikes/s/zq-site-7.sh"; g add -A; g commit -qm x; rm "$t/spikes/s/zq-site-7.sh"
run; [[ $rc == 1 ]] && ok "a deleted tracked file's NAME is still checked" || bad "deleted file name: rc $rc ($out)"
# No root argument outside a git tree: a usage error (2), not git's 128.
out=$(cd "$tmp" && WARDENLENS_SITE_IDS_FILE=$tmp/ids "$tool" 2>&1); rc=$?
[[ $rc == 2 ]] && ok "no root outside a git tree exits 2" || bad "no root outside git: rc $rc ($out)"
exit $fail
