#!/usr/bin/env bash
# Round 8 adversarial cases for the pre-push workflow refusal. Real pushes into throwaway bare remotes.
# "refuse" means the remote ref did not move/appear; "allow" means it did.
# shellcheck disable=SC2016
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
hooks_src=${HOOKS:-$root/.githooks}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# Hermetic: no vault, no installed scanner, whatever this machine has (the hook under test may scan pushes).
export HOME="$tmp/home"; mkdir -p "$HOME"; unset WARDENLENS_VAULT WARDENLENS_REQUIRE_VAULT
hooks=$tmp/hooks; mkdir -p "$hooks"; ln -s "$hooks_src/pre-push" "$hooks/pre-push"
fail=0; n=0
unset GIT_DIR GIT_WORK_TREE WARDENLENS_ALLOW_REWRITE WARDENLENS_ALLOW_WORKFLOWS GIT_CONFIG_PARAMETERS
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0

setup() {  # remote: main (with a workflow), feat/x; local clone on feat/x, hooksPath set
  n=$((n + 1)); local d=$tmp/c$n
  git init -q --bare -b main "$d/remote.git"; r=$d/remote.git
  git clone -q "$r" "$d/w" 2>/dev/null; w=$d/w
  git -C "$w" config user.email t@e; git -C "$w" config user.name t
  git -C "$w" checkout -q -b main 2>/dev/null || true
  mkdir -p "$w/.github/workflows"; echo a >"$w/.github/workflows/ci.yml"; echo 1 >"$w/f"
  git -C "$w" add -A; git -C "$w" commit -q -m base; git -C "$w" push -q origin main
  git -C "$w" checkout -q -b feat/x; echo x >"$w/x"; git -C "$w" add x; git -C "$w" commit -q -m x
  git -C "$w" push -q origin feat/x
  git -C "$w" config core.hooksPath "$hooks"
}
rsha() { git -C "$r" rev-parse -q --verify "$1" 2>/dev/null || echo none; }
# expect allow|refuse NAME REF SCRIPT  (SCRIPT runs in the clone; REF is the remote ref to watch)
expect() {
  local want=$1 name=$2 ref=$3 script=$4 before after
  setup; before=$(rsha "$ref")
  (cd "$w" && r=$r tmp=$tmp bash -c "$script") >"$tmp/out" 2>&1
  after=$(rsha "$ref")
  if [[ $want == refuse && $before == "$after" ]] || [[ $want == allow && $before != "$after" ]]; then
    echo "ok   $want: $name"
  else echo "FAIL should $want: $name ($ref $before -> $after)"; sed 's/^/     /' "$tmp/out"; fail=1; fi
}
# human change on main: edit ci.yml (and a non-workflow file) on main, push bypassing the hook, back to feat/x
hmain='git checkout -q main && echo b >>.github/workflows/ci.yml && echo 2 >f && git commit -q -am hwf && git -c core.hooksPath=/dev/null push -q origin main && git checkout -q feat/x'
# a human second branch on the remote with another workflow
hother='git checkout -q -b other main && echo o >.github/workflows/o.yml && git add -A && git commit -q -m o && git -c core.hooksPath=/dev/null push -q origin other && git checkout -q feat/x'

# --- false positives: ordinary merges carrying human workflow changes ------------------------------
expect allow "merge origin/main (human wf change) then extra commit, push both" refs/heads/feat/x \
  "$hmain && git merge -q --no-edit origin/main && echo y >>x && git commit -q -am y && git push origin feat/x"
expect allow "octopus merge of origin/main and origin/other (both human wf changes)" refs/heads/feat/x \
  "$hmain && $hother && git merge -q --no-edit origin/main origin/other && git push origin feat/x"
expect allow "merge with conflict in f resolved, wf taken from main" refs/heads/feat/x \
  "$hmain && echo 3 >f && git commit -q -am f3 && (git merge -q --no-edit origin/main || true) && echo 9 >f && git add f && git commit -q --no-edit && git push origin feat/x"
expect allow "merge -X theirs origin/main" refs/heads/feat/x \
  "$hmain && echo 3 >f && git commit -q -am f3 && git merge -q --no-edit -X theirs origin/main && git push origin feat/x"
expect allow "new branch: feat/x merged with origin/main, pushed as new ref" refs/heads/feat/new \
  "$hmain && git checkout -q -b feat/new && git merge -q --no-edit origin/main && git push origin feat/new"
expect allow "fast-forward existing branch onto origin/main carrying human wf change" refs/heads/feat/ff \
  "git checkout -q -b feat/ff main && git push -q origin feat/ff && $hmain && git checkout -q feat/ff && git merge -q --ff-only origin/main && git push origin feat/ff"
expect allow "new branch from updated origin/main (empty base array path)" refs/heads/feat/n2 \
  "$hmain && git checkout -q -b feat/n2 origin/main && echo q >q && git add q && git commit -q -m q && git push origin feat/n2"
expect allow "odd ref name: unicode + nested slashes" "refs/heads/feat/ünï/a.b/c" \
  "echo y >>x && git commit -q -am y && git push origin 'HEAD:refs/heads/feat/ünï/a.b/c'"
expect allow "push to refs/heads/feat/x via explicit full refspec with + absent and HEAD detached" refs/heads/feat/x \
  "echo y >>x && git commit -q -am y && git checkout -q --detach && git push origin HEAD:refs/heads/feat/x"
expect allow "merge of a remote human branch whose only change is a workflow, -X ours irrelevant" refs/heads/feat/x \
  "$hother && git merge -q --no-edit -X ours origin/other && git push origin feat/x"

# --- false negatives: workflow changes introduced or kept by the pushed merge ----------------------
# The first three FAIL at 71d6a87: the merge keeps the feature's OLD ci.yml (equal to parent 1), so the
# combined diff hides it, yet the PR's diff against main now reverts the human's workflow change.
# The pre-r8 hook (-m, per-parent diffs) refused them.
expect refuse "merge -s ours origin/main: PR reverts the human workflow change" refs/heads/feat/x \
  "$hmain && git merge -q --no-edit -s ours origin/main && git push origin feat/x"
expect refuse "merge origin/main but restore the feature's (old) ci.yml in the resolution" refs/heads/feat/x \
  "$hmain && git merge -q --no-commit origin/main && git checkout HEAD -- .github/workflows/ci.yml && git commit -q --no-edit && git push origin feat/x"
expect refuse "new branch whose merge -s ours reverts the human workflow change" refs/heads/feat/new \
  "$hmain && git checkout -q -b feat/new && git merge -q --no-edit -s ours origin/main && git push origin feat/new"
expect refuse "evil merge: resolution edits ci.yml to new content" refs/heads/feat/x \
  "$hmain && git merge -q --no-commit origin/main && echo evil >.github/workflows/ci.yml && git add -A && git commit -q --no-edit && git push origin feat/x"
expect refuse "evil merge: resolution deletes ci.yml" refs/heads/feat/x \
  "$hmain && git merge -q --no-commit origin/main && git rm -q .github/workflows/ci.yml && git commit -q --no-edit && git push origin feat/x"
expect refuse "evil merge: resolution chmods ci.yml" refs/heads/feat/x \
  "$hmain && git merge -q --no-commit origin/main && git update-index --chmod=+x .github/workflows/ci.yml && git commit -q --no-edit && git push origin feat/x"
expect refuse "evil merge: resolution adds a new workflow" refs/heads/feat/x \
  "$hmain && git merge -q --no-commit origin/main && echo z >.github/workflows/new.yml && git add -A && git commit -q --no-edit && git push origin feat/x"
expect refuse "evil merge: resolution renames x into workflows" refs/heads/feat/x \
  "$hmain && git merge -q --no-commit origin/main && git mv x .github/workflows/x.yml && git commit -q --no-edit && git push origin feat/x"
expect refuse "merge of a local side branch that edits ci.yml" refs/heads/feat/x \
  "git checkout -q -b side && echo s >>.github/workflows/ci.yml && git commit -q -am s && git checkout -q feat/x && git merge -q --no-edit --no-ff side && git push origin feat/x"
expect refuse "evil octopus merge adding a workflow" refs/heads/feat/x \
  "$hmain && $hother && git merge -q --no-commit origin/main origin/other 2>/dev/null; echo z >.github/workflows/z.yml && git add -A && git commit -q --no-edit && git push origin feat/x"
exit $fail
