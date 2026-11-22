#!/usr/bin/env bash
# Round 7b adversarial cases for the pre-push workflow refusal. Real pushes into throwaway bare remotes.
# "refuse" means the remote ref did not move/appear; "allow" means it did.
# shellcheck disable=SC2016
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
hooks_src=${HOOKS:-$root/.githooks}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
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
human_wf='git -c core.hooksPath=/dev/null'   # a human change on the remote (bypasses the hook)

# --- false positives: routine merges/rebases of main after a human changed a workflow on main -------
expect allow "merge origin/main (human workflow change already on main) into feature" refs/heads/feat/x \
  "git checkout -q main && echo b >>.github/workflows/ci.yml && git commit -q -am wf && $human_wf push -q origin main \
   && git checkout -q feat/x && git merge -q --no-edit origin/main && git push origin feat/x"
expect allow "git pull origin main into feature (human workflow change on main)" refs/heads/feat/x \
  "git checkout -q main && echo b >>.github/workflows/ci.yml && git commit -q -am wf && $human_wf push -q origin main \
   && git checkout -q feat/x && git pull -q --no-rebase --no-edit origin main && git push origin feat/x"

# accepted (owner, hobby scope): fake remote-tracking refs hiding new-branch commits; see ticket

# --- renames / URL pushes / tags --------------------------------------------------------------------
expect refuse "rename a workflow out of .github/workflows" refs/heads/feat/x \
  "git mv .github/workflows/ci.yml ci.yml.bak && git commit -q -m mv && git push origin feat/x"
expect refuse "rename a file into .github/workflows" refs/heads/feat/x \
  "git mv x .github/workflows/x.yml && git commit -q -m mv && git push origin feat/x"
expect refuse "chmod-only change of a workflow" refs/heads/feat/x \
  "git update-index --chmod=+x .github/workflows/ci.yml && git commit -q -m mode && git push origin feat/x"
expect refuse "push new branch by URL" refs/heads/feat/new \
  "git checkout -q -b feat/new && echo z >.github/workflows/evil.yml && git add -A && git commit -q -m wf && git push \"\$r\" feat/new"
expect refuse "push existing branch by file:// URL" refs/heads/feat/x \
  "echo z >.github/workflows/evil.yml && git add -A && git commit -q -m wf && git push \"file://\$r\" feat/x"
expect refuse "new tag on a workflow commit" refs/tags/t1 \
  "echo z >.github/workflows/evil.yml && git add -A && git commit -q -m wf && git tag t1 && git push origin t1"
expect refuse "workflow via a symlinked .github dir replacement" refs/heads/feat/x \
  "git rm -q -r .github && mkdir -p gh/workflows && echo z >gh/workflows/ci.yml && ln -s gh .github && git add -A && git commit -q -m s && git push origin feat/x"
expect allow "routine feature push, workflows untouched" refs/heads/feat/x \
  "echo y >>x && git commit -q -am y && git push origin feat/x"
expect allow "routine new branch from main" refs/heads/feat/new \
  "git checkout -q -b feat/new origin/main && echo y >y && git add y && git commit -q -m y && git push -u origin feat/new"
exit $fail
