#!/usr/bin/env bash
# Adversarial tests (#128 round 2) of the strict pairing check in scripts/tests/hooks-staged.test.sh.
# norm_detail replaces everything from the detail's opening quote to the LAST quote on the line (greedy `".*"`), so
# shell code placed between the detail and a final empty-string argument is normalised away. A refusal piped into a
# command (`refuse ... | true ""`) runs in a subshell: its `exit 1` ends only that subshell and the hook goes on.
# Each mutant below keeps the message and condition text byte-identical, disables the refusal, and must be rejected.
# Mutants are written to a temp dir only.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
installed=$root/.githooks/pre-push
staged=$root/scripts/hooks-staged/pre-push
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# The shipped check, from the shared helper (no private copy).
# shellcheck disable=SC1091 # sourced helper
source "$root/scripts/tests/lib/hook-pairing.sh"
pairing_gap() { hook_pairing_gap "$@"; }

mutant() {  # mutant NAME SED_EXPR -> path of the mutated copy
  local m=$tmp/$1
  sed "$2" "$staged" >"$m"
  if cmp -s "$m" "$staged"; then echo "MUTATION $1 DID NOT APPLY" >&2; fi
  echo "$m"
}

if [[ "$(pairing_gap "$installed" "$staged")" -eq 0 ]]; then ok "control: the staged hook pairs"; else bad "control: the staged hook pairs"; fi

# shellcheck disable=SC2016 # the sed expressions are literal shell text
{
m_main=$(mutant pipe-main 's/refuse "never push to main; open a PR" "ref:\$idx" ;;/refuse "never push to main; open a PR" "ref:$idx" | true "" ;;/')
m_remote=$(mutant pipe-unknown-remote 's/refuse "unknown remote state; fetch first" "ref:\$idx at \$rsha"$/refuse "unknown remote state; fetch first" "ref:$idx at $rsha" | true ""/')
m_wf=$(mutant pipe-wf-inspect 's/refuse "cannot inspect the pushed commits for workflow changes" "ref:\$idx"$/refuse "cannot inspect the pushed commits for workflow changes" "ref:$idx" | true ""/')
m_exit=$(mutant exit-after-remote 's/refuse "unknown remote state; fetch first" "ref:\$idx at \$rsha"$/refuse "unknown remote state; fetch first" "ref:$idx at $rsha"; exit 0; : ""/')
}
for m in "$m_main" "$m_remote" "$m_wf" "$m_exit"; do
  n=$(basename "$m")
  bash -n "$m" || bad "mutant $n is not valid bash"
  g=$(pairing_gap "$installed" "$m")
  if [[ "$g" -gt 0 ]]; then ok "the pairing check rejects mutant $n"; else bad "the pairing check rejects mutant $n (gap $g)"; fi
done

# Behavioural proof that the pipe really disables a refusal: a push to main with the pipe-main mutant exits 0 past
# that refusal (driven directly, no repository needed: stdin is one update to refs/heads/main).
z=0000000000000000000000000000000000000000
fn_main=$(sed -n '/^refuse()/p' "$m_main")
line_main=$(grep -F 'refs/heads/main|refs/heads/master) refuse' "$m_main")
probe="$fn_main
rref=refs/heads/main; idx=0
case \"\$rref\" in
$line_main
esac
echo REACHED"
if [[ "$(bash -c "$probe" 2>/dev/null)" == REACHED ]]; then
  echo "note: the pipe-main mutant goes on past the main refusal (refusal disabled)"
fi

# Details that print a ref name through `$line` (both names) or `${line%% *}` (the local one) must be rejected: the
# check is an allow-list of the two literal details, not a denylist of variable names.
# shellcheck disable=SC2016 # the sed expressions are literal shell text
{
m_line=$(mutant line-detail 's/refuse "existing tags are immutable (no update or deletion, forward or rewrite)" "ref:\$idx"/refuse "existing tags are immutable (no update or deletion, forward or rewrite)" "$line"/')
m_pct=$(mutant line-prefix-detail 's/refuse "deleting remote branches requires the user" "ref:\$idx"/refuse "deleting remote branches requires the user" "${line%% *}"/')
}
for m in "$m_line" "$m_pct"; do
  n=$(basename "$m")
  g=$(pairing_gap "$installed" "$m")
  if [[ "$g" -gt 0 ]]; then ok "the pairing check rejects mutant $n"; else bad "the pairing check rejects mutant $n (gap $g)"; fi
done
: "$z"
exit $fail
