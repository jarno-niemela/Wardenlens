#!/usr/bin/env bash
# Tests for the vault step of scripts/gate (scripts/lib/vault.sh): skip rules, GITHUB_ACTIONS, the file list.
# The scanner is a stub that logs the files it was given; HOME is a throwaway directory, so no real vault is touched.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
export HOME="$tmp/home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
unset WARDENLENS_VAULT WARDENLENS_REQUIRE_VAULT GITHUB_ACTIONS
mkdir -p "$HOME/.local/share/wardenlens"
# shellcheck source=scripts/lib/vault.sh
. "$root/scripts/lib/vault.sh"
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check()  { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
checkf() { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }

# The stub scanner: `stub vault scan -- FILE...` appends the files (one per line) to $tmp/seen, exits $STUB_EXIT.
cat >"$tmp/stub" <<'STUB'
#!/usr/bin/env bash
[[ "$1 $2 $3" == "vault scan --" ]] || { echo "stub: unexpected arguments" >&2; exit 99; }
shift 3
printf '%s\n' "$@" >>"$STUB_LOG"
# A copied symlink target is read now: the scratch directory is gone when the step returns.
for f in "$@"; do case $f in */symlink-*) printf 'target-of-symlink: %s\n' "$(cat "$f")" >>"$STUB_LOG.links" ;; esac; done
exit "${STUB_EXIT:-0}"
STUB
chmod +x "$tmp/stub"
export STUB_LOG="$tmp/seen"

# A repository: tracked a.txt, b.txt, a symlink, a deleted tracked file, an ignored file and an untracked file.
repo=$tmp/repo
git init -q -b main "$repo"
cd "$repo" || exit 1
echo a >a.txt; echo b >b.txt; echo gone >gone.txt; ln -s a.txt link; echo '*.log' >.gitignore
git add -A; git -c user.name=t -c user.email=t@example.invalid commit -q -m init
rm gone.txt; echo new >untracked.txt; echo ignored >x.log

run() { : >"$STUB_LOG"; vault_scan_tree "$tmp/stub"; }
db=$HOME/.local/share/wardenlens/dev-vault.db

# No vault: skipped, and says so; the scanner is not run.
out=$(run 2>&1); rc=$?
check "no vault: skipped with exit 0" test $rc -eq 0
check "no vault: says SKIPPED and the path" bash -c "grep -q 'vault scan: SKIPPED (no vault at $db)' <<<\"\$1\"" _ "$out"
check "no vault: the scanner did not run" test ! -s "$STUB_LOG"
# GITHUB_ACTIONS does not change that (public CI has no vault), and does not skip when there is one.
out=$(GITHUB_ACTIONS=true run 2>&1); rc=$?
check "CI without a vault: skipped" bash -c "[[ $rc -eq 0 ]] && grep -q SKIPPED <<<\"\$1\"" _ "$out"
# REQUIRE_VAULT turns the skip into a failure.
checkf "no vault + WARDENLENS_REQUIRE_VAULT=1: fails" env WARDENLENS_REQUIRE_VAULT=1 bash -c ". '$root/scripts/lib/vault.sh'; vault_scan_tree '$tmp/stub'"
# WARDENLENS_VAULT points at the vault to look for.
mkdir -p "$tmp/elsewhere"
check "WARDENLENS_VAULT is honoured (absent: skipped)" bash -c "WARDENLENS_VAULT='$tmp/elsewhere/none.db' bash -c \". '$root/scripts/lib/vault.sh'; vault_scan_tree '$tmp/stub'\" | grep -q 'none.db'"

# A vault exists: it is scanned, in CI as well.
: >"$db"
for ci in "" true; do
  out=$(GITHUB_ACTIONS=$ci run 2>&1); rc=$?
  check "vault present (GITHUB_ACTIONS='$ci'): scanned, passes" test $rc -eq 0
  check "vault present (GITHUB_ACTIONS='$ci'): never SKIPPED" bash -c "! grep -q SKIPPED <<<\"\$1\"" _ "$out"
  check "vault present (GITHUB_ACTIONS='$ci'): scanner ran" test -s "$STUB_LOG"
done
run >/dev/null 2>&1
rm -f "$STUB_LOG.links"
run >/dev/null 2>&1
seen=$(grep -v '/symlink-' "$STUB_LOG" | LC_ALL=C sort | tr '\n' ' ')
check "tracked and untracked files are scanned" test "$seen" = ".gitignore a.txt b.txt untracked.txt "
check "ignored and deleted files are not" bash -c "! grep -qE 'x.log|gone' '$STUB_LOG'"
check "a tracked symlink is scanned through its target text" grep -qxF "target-of-symlink: a.txt" "$STUB_LOG.links"
out=$(run 2>&1)
check "a missing file is counted, not named" bash -c "grep -q '0 untracked symlink(s) and 1 missing' <<<\"\$1\" && ! grep -q 'gone.txt' <<<\"\$1\"" _ "$out"
# Scanner failure fails the step.
checkf "a scanner failure (exit 1) fails" env STUB_EXIT=1 bash -c ". '$root/scripts/lib/vault.sh'; vault_scan_tree '$tmp/stub'"
checkf "a scanner failure (exit 2) fails" env STUB_EXIT=2 bash -c ". '$root/scripts/lib/vault.sh'; vault_scan_tree '$tmp/stub'"
# A file name with a space, a newline and a leading dash is passed whole, after `--`.
printf 'x\n' >"-odd name
with newline"
git add -A
run >/dev/null 2>&1
check "an odd file name is passed whole" grep -qxF -- "-odd name" "$STUB_LOG"
# Untracked files over the limit only warn; tracked ones are handed to the scanner (which fails on them).
head -c 8388609 /dev/zero | tr '\0' a >big-untracked.txt
out=$(run 2>&1); rc=$?
check "untracked file over the limit: warning, still passes" bash -c "[[ $rc -eq 0 ]] && grep -q 'warning: 1 untracked file(s) over the 8 MiB limit' <<<\"\$1\"" _ "$out"
check "untracked file over the limit is not scanned" bash -c "! grep -q big-untracked '$STUB_LOG'"
git add big-untracked.txt
run >/dev/null 2>&1
check "tracked file over the limit is handed to the scanner" grep -qx big-untracked.txt "$STUB_LOG"
# The gate itself runs the step with the tree's own build, after the tests, and ignores nothing.
check "the gate runs the vault step" grep -q 'vault_scan_tree cargo run -q -p wardenlens-cli --locked --' "$root/scripts/gate"
check "the gate never consults GITHUB_ACTIONS for the vault step" bash -c "! grep -n 'GITHUB_ACTIONS' '$root/scripts/lib/vault.sh' | grep -v '^[0-9]*:#'"

exit $fail
