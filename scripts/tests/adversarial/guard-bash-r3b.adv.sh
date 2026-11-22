#!/usr/bin/env bash
# Round 3b adversarial cases for .claude/hooks/guard-bash.sh. Cases are data passed to the hook;
# nothing here executes them.
# shellcheck disable=SC2016  # single quotes are intentional: cases are literal command text
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
guard=$root/.claude/hooks/guard-bash.sh
fail=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git init -q -b main "$tmp/onmain"; git init -q -b feat/x "$tmp/onfeat"
mkdir -p "$tmp/home"

run() { jq -n --arg c "$1" --arg d "${2:-}" '{tool_input: {command: $c}} + (if $d == "" then {} else {cwd: $d} end)' | HOME=$tmp/home "$guard" >/dev/null 2>&1; }
allow() { if run "$1" "${2:-}"; then echo "ok   allow: $1"; else echo "FAIL should allow: $1"; fail=1; fi; }
deny()  { if run "$1" "${2:-}"; then echo "FAIL should deny: $(printf '%q' "$1")"; fail=1; else echo "ok   deny:  $(printf '%q' "$1")"; fi; }
F=$tmp/onfeat

# --- heredoc: an interpreter glued to << still runs the body -----------------------------------
deny  $'bash<<EOF\ngit push --force origin main\nEOF' "$F"
deny  $'sh<<\'EOF\'\ngit push --force origin main\nEOF' "$F"
deny  $'/bin/bash<<EOF\ngit push origin main\nEOF' "$F"
# --- heredoc: body begins after the *logical* line (continuation / multi-line quote) ------------
deny  $'cat <<EOF \\\n; git push --force origin main\nbody\nEOF' "$F"
deny  $'cat <<EOF; echo "\n"; git push --force origin main\nx\nEOF' "$F"
# --- heredoc: << inside ${...} is not a heredoc -------------------------------------------------
deny  $'echo ${x//<<X/}\ngit push --force origin main' "$F"
# --- redirections containing & are not separators ----------------------------------------------
deny  "git push 2>&1 origin main" "$F"
deny  "git push origin feat/x &>/dev/null main" "$F"
deny  "gh pr merge 7 --match-head-commit \$sha 2>&1 --admin"
# --- push: matching refspec ':' and empty-source deletion --------------------------------------
deny  "git push origin :" "$F"
deny  "git push origin :feat/y" "$F"
deny  "git push origin feat/x:refs/heads/main" "$F"
# --- push: brace expansion builds a main refspec ------------------------------------------------
deny  "git push origin {feat/x,main}" "$F"
# --- config overrides that act like --mirror / matching push ------------------------------------
deny  "git -c remote.origin.mirror=true push origin" "$F"
deny  "git config remote.origin.mirror true" "$F"
deny  "git -c push.default=matching push origin" "$F"
# --- core.hooksPath removed indirectly ---------------------------------------------------------
deny  "git config --remove-section core"
deny  "git config --rename-section core old"
deny  "git config --global --comment note core.hooksPath /dev/null"
deny  "git config include.path /tmp/evil.cfg"
# --- GIT_CONFIG_* exported in an earlier segment ------------------------------------------------
deny  "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null; git commit -m x"
# --- directory tracking -------------------------------------------------------------------------
deny  "(cd $F); git push" "$tmp/onmain"
deny  "pushd $F; popd; git push" "$tmp/onmain"
deny  "bash -c 'cd $F'; git push" "$tmp/onmain"
deny  "env -C $tmp/onmain git push" "$F"
deny  "export GIT_DIR=$tmp/onmain/.git; git push" "$F"
# --- gh api: combined short flags, other write paths --------------------------------------------
deny  "gh api -iX DELETE repos/o/r"
deny  "gh api -iXPOST repos/o/r/statuses/0123456789abcdef0123456789abcdef01234567 -f state=success -f context=verify/quality"
deny  "gh api -X PUT repos/o/r/contents/src/lib.rs -f message=x -f content=eA== -f branch=main"
deny  "gh api graphql -f query='mutation { mergeBranch(input: {repositoryId: \"R\", base: \"main\", head: \"feat/x\"}) { clientMutationId } }'"
deny  "gh api graphql -f query='mutation { updateRef(input: {refId: \"X\", oid: \"0000\", force: true}) { clientMutationId } }'"
# --- gh -R combined with merge flags ------------------------------------------------------------
deny  "gh -R o/r pr merge 7 --squash"
deny  "gh pr -R o/r merge 7"
deny  "gh pr merge --repo=o/r 7 --match-head-commit HEAD"
allow "gh -R o/r pr merge 7 --match-head-commit \"\$sha\""
allow "gh pr merge 7 --match-head-commit=0123456789abcdef0123456789abcdef01234567"
# --- pipes into shells through common wrappers --------------------------------------------------
deny  "echo 'git push --force origin main' | timeout 10 bash"
deny  "echo 'git push --force origin main' | sudo -u root bash"
deny  "echo 'git push --force origin main' | nice -n 5 sh"
deny  "echo 'git push --force origin main' | busybox sh"
deny  "echo 'git push --force origin main' | tee >(bash)"
deny  $'xargs -L1 git <<EOF\npush --force origin main\nEOF'
# --- git through non-*/bin/ paths ---------------------------------------------------------------
deny  "/usr/lib/git-core/git push --force origin feat/x"
deny  "/usr/lib/git-core/git-push --force origin feat/x"
# --- sanity: things that must stay allowed ------------------------------------------------------
allow "git push origin feat/x 2>&1" "$F"
allow "git config core.hooksPath .githooks"
allow $'cat <<EOF >notes.txt\ngit push --force origin main\nEOF'
allow "echo \$((1<<2)); git status"
exit $fail
