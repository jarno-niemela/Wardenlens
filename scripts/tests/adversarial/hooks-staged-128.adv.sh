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

# The check of scripts/tests/hooks-staged.test.sh is now the strict pairing (see strict_removed below); the round-1
# relaxation this file was written against (`grep -vc 'refuse "'`) is gone.
shipped_removed() { strict_removed "$1"; }

# A strict form: every removed line must equal an added line once the refusal's detail argument is ignored.
key() { sed -E 's/^(.*refuse "[^"]*").*$/\1/'; }
suffix() { sed -E 's/^.*"//'; }
has_key() {  # has_key KEY LINES: whether one of LINES has KEY
  local a
  while IFS= read -r a; do
    if [[ "$(key <<<"$a")|$(suffix <<<"$a")" == "$1" ]]; then return 0; fi
  done <<<"$2"
  return 1
}
strict_removed() {
  local d removed added n=0 line k
  d=$(diff -u "$installed" "$1")
  removed=$(grep '^-' <<<"$d" | grep -v '^---' | cut -c2-)
  added=$(grep '^+' <<<"$d" | grep -v '^+++' | cut -c2-)
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    k="$(key <<<"$line")|$(suffix <<<"$line")"
    if ! has_key "$k" "$added"; then n=$((n + 1)); fi
  done <<<"$removed"
  echo "$n"
}

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

# The shipped "no refusal prints a ref name" check, applied to a mutant that prints the name with braces.
# shellcheck disable=SC2016 # the patterns are literal shell text
shipped_names_ok() {
  ! grep 'refuse "' "$1" | grep -E 'refuse "[^"]*" "[^"]*[$](rref|lref|wf|[{](rref|lref|wf))'
}
expect "control: the shipped name check accepts the staged hook" shipped_names_ok "$staged"
# shellcheck disable=SC2016 # the sed expressions are literal shell text
m4=$(mutant braced-name 's/refuse "non-fast-forward \/ force push" "ref:\$idx"/refuse "non-fast-forward \/ force push" "${rref}"/')
if shipped_names_ok "$m4" >/dev/null; then bad "the shipped name check rejects a refusal printing \${rref}"; else ok "the shipped name check rejects a refusal printing \${rref}"; fi
exit $fail
