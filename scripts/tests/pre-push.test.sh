#!/usr/bin/env bash
# Tests for .githooks/pre-push with real pushes into a temporary bare remote. Every case builds a fresh
# remote and clone (hooksPath -> this repo's hooks) on branch feat/x; main is one commit ahead of the
# remote's main so that matching/mirror pushes would really update it.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
hooks=$root/.githooks
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
unset GIT_DIR GIT_WORK_TREE WARDENLENS_ALLOW_REWRITE GIT_CONFIG_PARAMETERS
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

# the hook script itself must be executable and the repo must point hooksPath at it
if [[ -x $hooks/pre-push ]]; then echo "ok   pre-push is executable"; else echo "FAIL pre-push not executable"; fail=1; fi
exit $fail
