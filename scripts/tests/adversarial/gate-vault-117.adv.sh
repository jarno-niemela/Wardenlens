#!/usr/bin/env bash
# Adversarial tests (ticket #117) for the gate's vault step (scripts/lib/vault.sh, vault_scan_tree).
# "Failing to scan is never a pass" (ADR 0006 section 8): when the tracked-file listing cannot be produced, the
# step must fail, not report "nothing to scan". The scanner is a stub; HOME is a throwaway directory.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
export HOME="$tmp/home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
unset WARDENLENS_VAULT WARDENLENS_REQUIRE_VAULT GITHUB_ACTIONS GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
mkdir -p "$HOME/.local/share/wardenlens"; : >"$HOME/.local/share/wardenlens/dev-vault.db"
# shellcheck source=scripts/lib/vault.sh
. "$root/scripts/lib/vault.sh"
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
checkf() { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }

# A stub scanner that reports a hit on every file it is given.
printf '#!/usr/bin/env bash\nexit 1\n' >"$tmp/stub"; chmod +x "$tmp/stub"

repo=$tmp/repo
git init -q -b main "$repo"
echo "tracked" >"$repo/a.txt"; git -C "$repo" add a.txt
printf 'not an index\n' >"$tmp/garbage.idx"

# shellcheck disable=SC2329 # called through checkf
in_repo() { (cd "$repo" && "$@"); }
checkf "sanity: a hit in a tracked file fails the step" in_repo vault_scan_tree "$tmp/stub"
# shellcheck disable=SC2016 # expanded by the inner bash
checkf "an unreadable index fails the step (not 'nothing to scan')" \
  in_repo env GIT_INDEX_FILE="$tmp/garbage.idx" bash -c '. "$1"; vault_scan_tree "$2"' _ "$root/scripts/lib/vault.sh" "$tmp/stub"
exit $fail
