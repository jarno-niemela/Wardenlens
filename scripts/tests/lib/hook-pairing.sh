# shellcheck shell=bash
# Shared by scripts/tests/hooks-staged.test.sh and the adversarial tests of it. Sourced, never run.
#
# The staged pre-push is the installed one plus added lines; the only change to an existing line is the DETAIL argument of
# a refusal (#128: `ref:$idx`, never a ref name or a workflow path). hook_pairing_gap checks that POSITIONALLY and against
# an ALLOW-LIST:
#   - the installed (trusted) hook is normalised with the loose rule: the detail of a `refuse "msg" "detail"` call is
#     replaced by DETAIL, whatever it is;
#   - the staged hook is normalised ONLY where its detail is exactly `"ref:$idx"` or `"ref:$idx at $rsha"` and the refusal
#     is followed by nothing but one of the line endings the installed hook has (none, ` ;;`, `; fi`, `; fi ;;`);
#   - the two whole files are then diffed: any `-` line fails. A changed condition, a line moved elsewhere (a dead function),
#     code after the detail (`| true ""`, `& #"`, `; exit 0; : ""`) or any other detail leaves the staged line unnormalised,
#     so the installed line has no twin at its position and shows as a `-` line;
#   - the staged hook may add lines, but not a second definition of `refuse`.

# hook_norm_installed: the trusted hook, every refusal's detail replaced by DETAIL.
hook_norm_installed() { sed -E 's/^(.*refuse "[^"]*") ".*"(.*)$/\1 DETAIL\2/'; }

# hook_norm_staged: only the exact allow-listed details, only at the end of the line.
# shellcheck disable=SC2016 # the pattern is literal shell text
hook_norm_staged() { sed -E 's/^(.*refuse "[^"]*") "ref:\$idx( at \$rsha)?"( ;;|; fi ;;|; fi)?$/\1 DETAIL\3/'; }

# hook_pairing_gap INSTALLED STAGED: prints the number of problems (0 = accepted).
hook_pairing_gap() {
  local gone defs_i defs_s
  gone=$(diff -u <(hook_norm_installed <"$1") <(hook_norm_staged <"$2") | grep '^-' | grep -vc '^---' || true)
  defs_i=$(grep -cE '^[[:space:]]*refuse[[:space:]]*\(\)' "$1" || true)
  defs_s=$(grep -cE '(^|[;&|{][[:space:]]*)refuse[[:space:]]*\(\)' "$2" || true)
  if [[ "$defs_s" -ne "$defs_i" ]]; then gone=$((gone + 1)); fi
  echo "$gone"
}
