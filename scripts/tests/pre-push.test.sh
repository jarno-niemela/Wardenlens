#!/usr/bin/env bash
# Tests for .githooks/pre-push with real pushes into a temporary bare remote. Every case builds a fresh
# remote and clone (hooksPath -> this repo's hooks) on branch feat/x; main is one commit ahead of the
# remote's main so that matching/mirror pushes would really update it.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
hooks=${HOOKS:-$root/.githooks}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# Only pre-push is under test: a hooks dir holding just it keeps the repo's pre-commit (cargo fmt) out
# of commits made inside the throwaway clones.
hooks_src=$hooks; hooks=$tmp/hooks; mkdir -p "$hooks"; ln -s "$hooks_src/pre-push" "$hooks/pre-push"
fail=0
unset GIT_DIR GIT_WORK_TREE WARDENLENS_ALLOW_REWRITE WARDENLENS_ALLOW_WORKFLOWS GIT_CONFIG_PARAMETERS
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
n=0

setup() {  # setup -> sets $w (clone dir); remote has main, feat/x, feat/y; local main is ahead
  n=$((n + 1)); local d=$tmp/c$n
  git init -q --bare -b main "$d/remote.git"
  git clone -q "$d/remote.git" "$d/w" 2>/dev/null
  w=$d/w
  git -C "$w" config user.email t@example.com; git -C "$w" config user.name t
  git -C "$w" checkout -q -b main 2>/dev/null || true
  echo 1 >"$w/f"; git -C "$w" add f; git -C "$w" commit -q -m base
  git -C "$w" tag -a -m v1 v1
  git -C "$w" push -q origin main v1   # hooksPath not set yet
  git -C "$w" checkout -q -b feat/x; echo x >"$w/x"; git -C "$w" add x; git -C "$w" commit -q -m x
  git -C "$w" push -q origin feat/x
  git -C "$w" branch feat/y; git -C "$w" push -q origin feat/y
  git -C "$w" checkout -q main; echo 2 >"$w/f"; git -C "$w" commit -q -am ahead
  git -C "$w" checkout -q feat/x; echo x2 >"$w/x"; git -C "$w" commit -q -am x2
  git -C "$w" config core.hooksPath "$hooks"
}

skipref=none  # a ref the case itself moves on the remote (excluded from the state comparison)
refs() { git -C "$w/../remote.git" for-each-ref --format='%(refname) %(objectname)' | grep -v "^$skipref " | sort; }

# expect allow|refuse NAME GIT_ARGS... (run in the fresh clone; "refuse" must come from the hook)
expect() {
  local want=$1 name=$2; shift 2
  setup
  local rc=0 out before after
  before=$(refs)
  out=$(cd "$w" && "$@" 2>&1) || rc=$?
  after=$(refs)
  if [[ $want == allow ]]; then
    if ((rc == 0)); then echo "ok   allow:  $name"; else echo "FAIL allow: $name: $out"; fail=1; fi
  elif ((rc != 0)) && grep -q 'pre-push: refused' <<<"$out" && [[ "$before" == "$after" ]]; then echo "ok   refuse: $name"
  else echo "FAIL refuse: $name (rc=$rc): $out"; fail=1; fi
}
expect allow  "create a new tag"                 bash -c 'git tag -a -m n v2 && git push origin v2'
expect refuse "move existing tag forward"        bash -c 'git tag -f -a -m m v1 feat/x >/dev/null && git push --force origin v1'
expect refuse "re-push existing tag, same commit" bash -c 'git tag -f -a -m again v1 v1^{commit} >/dev/null && git push --force origin v1'
expect refuse "delete existing tag"              git push origin :refs/tags/v1
expect refuse "delete existing tag (--delete)"   git push --delete origin v1
expect refuse "tag move with WARDENLENS_ALLOW_REWRITE=1" \
  env WARDENLENS_ALLOW_REWRITE=1 bash -c 'git tag -f v1 feat/x >/dev/null && git push --force origin v1'
# shellcheck disable=SC2329  # passed to bash -c through declare -f
rewrite() { git reset -q --hard HEAD~2 && echo r >r && git add r && git -c core.hooksPath=/dev/null commit -q -m r; }  # drops the remote tip

expect allow  "push feat/x"                      git push origin feat/x
expect allow  "fast-forward push of feat/x"      git push -u origin feat/x
expect refuse "matching refspec ':'"             git push origin :
expect refuse "push main"                        git push origin main
expect refuse "HEAD:main"                        git push origin HEAD:main
expect refuse "+feat/x:main"                     git push origin +feat/x:main
expect refuse "feat/x:refs/heads/main"           git push origin feat/x:refs/heads/main
expect refuse "delete via :feat/y"               git push origin :feat/y
expect refuse "delete via --delete"              git push --delete origin feat/y
expect refuse "mirror via config"                git -c remote.origin.mirror=true push origin
expect refuse "push.default=matching"            git -c push.default=matching push origin
expect refuse "feat/x and main together"         git push origin feat/x main
expect refuse "force push, rewritten history"    bash -c "$(declare -f rewrite); rewrite; git push --force origin feat/x"
expect refuse "+refspec, rewritten history"      bash -c "$(declare -f rewrite); rewrite; git push origin +feat/x"
expect refuse "force-with-lease is not exempt"   bash -c "$(declare -f rewrite); rewrite; git push --force-with-lease origin feat/x"
expect allow  "force push with WARDENLENS_ALLOW_REWRITE=1" \
  env WARDENLENS_ALLOW_REWRITE=1 bash -c "$(declare -f rewrite); rewrite; git push --force origin feat/x"
expect refuse "WARDENLENS_ALLOW_REWRITE=1 never allows main" \
  env WARDENLENS_ALLOW_REWRITE=1 git push --force origin HEAD:main
expect refuse "WARDENLENS_ALLOW_REWRITE=1 does not allow deletion" \
  env WARDENLENS_ALLOW_REWRITE=1 git push origin :feat/y
skipref=refs/heads/feat/x   # this case pushes a competing commit to feat/x itself
# shellcheck disable=SC2016  # the script runs in the inner bash
expect refuse "unknown remote state (remote tip not fetched)" \
  bash -c 'other=$(mktemp -d); git clone -q "$(git remote get-url origin)" "$other/o" && git -C "$other/o" config user.email t@e && git -C "$other/o" config user.name t && git -C "$other/o" checkout -q feat/x && echo z >"$other/o/z" && git -C "$other/o" add z && git -C "$other/o" commit -q -m z && git -C "$other/o" push -q origin feat/x; rm -rf "$other"; git push origin feat/x'
skipref=none
if [[ -x /usr/lib/git-core/git ]]; then
  expect refuse "/usr/lib/git-core/git push --force" \
    bash -c "$(declare -f rewrite); rewrite; /usr/lib/git-core/git push --force origin feat/x"
else echo "skip /usr/lib/git-core/git case (not installed)"; fi

# --- workflows are privileged: commits touching .github/workflows/ are refused ------------------------
wf_add='mkdir -p .github/workflows && echo a >.github/workflows/ci.yml && git add -A && git commit -q -m wf'
nohook='git -c core.hooksPath=/dev/null push -q origin feat/x'   # puts a state on the remote without the hook
expect refuse "push a commit that adds a workflow"          bash -c "$wf_add && git push origin feat/x"
skipref=refs/heads/feat/x   # these two put a state on feat/x first
expect refuse "push a commit that edits a workflow"         bash -c "$wf_add && $nohook && echo b >>.github/workflows/ci.yml && git commit -q -am e && git push origin feat/x"
expect refuse "push a commit that deletes a workflow"       bash -c "$wf_add && $nohook && git rm -q .github/workflows/ci.yml && git commit -q -m d && git push origin feat/x"
skipref=none
expect refuse "workflow added then reverted in the range"   bash -c "$wf_add && git revert --no-edit HEAD >/dev/null && git push origin feat/x"
expect refuse "workflow change hidden in a merged side branch" \
  bash -c "git checkout -q -b side && $wf_add && git checkout -q feat/x && git merge -q -s ours --no-ff side -m m && git push origin feat/x"
expect allow  "merge origin/main that already carries a human workflow change" \
  bash -c "git checkout -q main && mkdir -p .github/workflows && echo a >.github/workflows/ci.yml && git add -A && git commit -q -m wf && git -c core.hooksPath=/dev/null push -q origin main && git checkout -q feat/x && git merge -q --no-edit origin/main && git push origin feat/x"
expect allow  "git pull --no-rebase origin main (workflow change already on main)" \
  bash -c "git checkout -q main && mkdir -p .github/workflows && echo a >.github/workflows/ci.yml && git add -A && git commit -q -m wf && git -c core.hooksPath=/dev/null push -q origin main && git checkout -q feat/x && git pull -q --no-rebase --no-edit origin main && git push origin feat/x"
expect refuse "merge commit that itself edits a workflow" \
  bash -c "git merge -q --no-ff --no-commit main && mkdir -p .github/workflows && echo a >.github/workflows/ci.yml && git add -A && git commit -q -m m && git push origin feat/x"
expect refuse "new branch whose history adds a workflow"   bash -c "git checkout -q -b feat/new && $wf_add && git push origin feat/new"
expect refuse "new branch, workflow in an older local commit" bash -c "git checkout -q -b feat/new && $wf_add && echo n >n && git add n && git commit -q -m n && git push origin feat/new"
expect refuse "WARDENLENS_ALLOW_WORKFLOWS=0 is not the switch" env WARDENLENS_ALLOW_WORKFLOWS=0 bash -c "$wf_add && git push origin feat/x"
expect refuse "WARDENLENS_ALLOW_REWRITE=1 does not allow workflows" env WARDENLENS_ALLOW_REWRITE=1 bash -c "$wf_add && git push origin feat/x"
expect refuse "WARDENLENS_ALLOW_WORKFLOWS=1 never allows main" env WARDENLENS_ALLOW_WORKFLOWS=1 bash -c "$wf_add && git push origin HEAD:main"
expect allow  "workflow change with WARDENLENS_ALLOW_WORKFLOWS=1" env WARDENLENS_ALLOW_WORKFLOWS=1 bash -c "$wf_add && git push origin feat/x"
expect allow  "new branch, workflow already on the remote" \
  bash -c "$wf_add && $nohook && git checkout -q -b feat/new && echo n >n && git add n && git commit -q -m n && git push origin feat/new"
expect allow  "push touching only other .github files"      bash -c "mkdir -p .github && echo a >.github/CODEOWNERS && git add -A && git commit -q -m co && git push origin feat/x"

# the hook script itself must be executable and the repo must point hooksPath at it
if [[ -x $hooks_src/pre-push ]]; then echo "ok   pre-push is executable"; else echo "FAIL pre-push not executable"; fail=1; fi
exit $fail
