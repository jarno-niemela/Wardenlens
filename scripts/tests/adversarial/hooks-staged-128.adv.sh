#!/usr/bin/env bash
# Adversarial tests (#128) of the "nothing removed" check of the staged pre-push: only a refusal's detail may change.
# A removed line that holds a refusal also holds its CONDITION, so the check must reject a mutant that keeps the
# refusal text but disables the condition, or drops the refusal call. Mutants are written to a temp dir only.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
installed=$root/.githooks/pre-push
staged=$root/scripts/hooks-staged/pre-push
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
expect() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }

# The shipped check, from the shared helper (no private copy): 0 means "accepted".
# shellcheck disable=SC1091 # sourced helper
source "$root/scripts/tests/lib/hook-pairing.sh"
shipped_removed() { hook_pairing_gap "$installed" "$1"; }
strict_removed() { hook_pairing_gap "$installed" "$1"; }

mutant() {  # mutant NAME SED_EXPR -> path of the mutated copy
  local m=$tmp/$1
  sed "$2" "$staged" >"$m"
  if cmp -s "$m" "$staged"; then echo "MUTATION $1 DID NOT APPLY" >&2; fi
  echo "$m"
}

# Control: the shipped staged hook is accepted by both forms.
expect "control: the shipped check accepts the staged hook" test "$(shipped_removed "$staged")" -eq 0
expect "control: the strict check accepts the staged hook" test "$(strict_removed "$staged")" -eq 0

# Mutants that survive every behavioural suite (pre-push.test.sh and pre-push-*.adv.sh against HOOKS=<mutant>):
#  - the unknown-remote-state check is disabled (with WARDENLENS_ALLOW_REWRITE=1 an unfetched remote tip is then
#    rewritten instead of refused);
#  - a failure to inspect the pushed commits for workflow changes no longer refuses.
# shellcheck disable=SC2016 # the sed expressions are literal shell text
m1=$(mutant unknown-remote 's/git cat-file -e "\$rsha^{commit}" 2>\/dev\/null || refuse/true || refuse/')
m2=$(mutant wf-inspect 's/2>\/dev\/null) || refuse "cannot inspect/2>\/dev\/null) || true refuse "cannot inspect/')
# shellcheck disable=SC2016 # the sed expressions are literal shell text
m3=$(mutant ff-dropped 's/        refuse "non-fast-forward \/ force push" "ref:\$idx"/        true "non-fast-forward \/ force push"/')
for m in "$m1" "$m2" "$m3"; do
  n=$(basename "$m")
  expect "the strict check rejects mutant $n" test "$(strict_removed "$m")" -gt 0
  expect "the shipped check rejects mutant $n" test "$(shipped_removed "$m")" -gt 0
done

# A refusal printing the name with braces is rejected too (allow-list, not a denylist of names).
# shellcheck disable=SC2016 # the sed expressions are literal shell text
m4=$(mutant braced-name 's/refuse "non-fast-forward \/ force push" "ref:\$idx"/refuse "non-fast-forward \/ force push" "${rref}"/')
expect "the shipped check rejects a refusal printing \${rref}" test "$(shipped_removed "$m4")" -gt 0
exit $fail
