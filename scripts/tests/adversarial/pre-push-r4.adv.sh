#!/usr/bin/env bash
# Round 4 adversarial cases for .githooks/pre-push. Real pushes into a throwaway bare remote; the
# oracle is the remote's state afterwards (main untouched, nothing deleted, no tip lost), not the
# hook's message.
# shellcheck disable=SC2016  # inner bash -c scripts expand in the clone, not here
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
hooks=${HOOKS:-$root/.githooks}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0; n=0
unset GIT_DIR GIT_WORK_TREE WARDENLENS_ALLOW_REWRITE GIT_CONFIG_PARAMETERS
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0

setup() {  # remote: main, feat/x, feat/y, tag v1 (annotated, on base); local main ahead, feat/x ahead
  n=$((n + 1)); local d=$tmp/c$n
  git init -q --bare -b main "$d/remote.git"; r=$d/remote.git
  git clone -q "$r" "$d/w" 2>/dev/null; w=$d/w
  git -C "$w" config user.email t@example.com; git -C "$w" config user.name t
  git -C "$w" checkout -q -b main 2>/dev/null || true
  echo 1 >"$w/f"; git -C "$w" add f; git -C "$w" commit -q -m base
  git -C "$w" tag -a -m v1 v1
  git -C "$w" push -q origin main v1
  git -C "$w" checkout -q -b feat/x; echo x >"$w/x"; git -C "$w" add x; git -C "$w" commit -q -m x
  git -C "$w" push -q origin feat/x
  git -C "$w" branch feat/y; git -C "$w" push -q origin feat/y
  git -C "$w" checkout -q main; echo 2 >"$w/f"; git -C "$w" commit -q -am ahead
  git -C "$w" checkout -q feat/x; echo x2 >"$w/x"; git -C "$w" commit -q -am x2
  git -C "$w" config core.hooksPath "$hooks"
}
refs() { git -C "$r" for-each-ref --format='%(refname) %(objectname)' | sort; }

# safe NAME CMD...: after CMD, remote main is unchanged, no remote ref vanished, and every remote
# ref that existed still points at (a descendant of) its old value; tags may not move at all.
safe() {
  local name=$1; shift; setup
  local before after out bad=""
  before=$(refs)
  out=$(cd "$w" && "$@" 2>&1)
  after=$(refs)
  while read -r ref sha; do
    [[ -z $ref ]] && continue
    local now; now=$(awk -v r="$ref" '$1==r{print $2}' <<<"$after")
    if [[ -z $now ]]; then bad+=" deleted:$ref"
    elif [[ $now != "$sha" ]]; then
      case $ref in
        refs/heads/main|refs/heads/master|refs/tags/*) bad+=" moved:$ref" ;;
        *) git -C "$r" merge-base --is-ancestor "$sha" "$now" || bad+=" rewritten:$ref" ;;
      esac
    fi
  done <<<"$before"
  grep -q '^refs/heads/master ' <<<"$after" && ! grep -q '^refs/heads/master ' <<<"$before" && bad+=" created:master"
  if [[ -z $bad ]]; then echo "ok   safe: $name"; else echo "FAIL $name:$bad :: $(tr '\n' ' ' <<<"$out")"; fail=1; fi
}

safe "multiple refspecs incl. main"            git push origin feat/x feat/y:main
safe "--atomic with main"                       git push --atomic origin feat/x main
safe "tag-to-branch refspec onto main"          bash -c 'git tag t2 main && git push origin refs/tags/t2:refs/heads/main'
safe "tag object to new master"                 bash -c 'git tag -a -m t t3 main && git push origin t3:refs/heads/master'
safe "detached HEAD to main"                    bash -c 'git checkout -q --detach main && git push origin HEAD:main'
safe "detached HEAD to refs/heads/main"         bash -c 'git checkout -q --detach main && git push origin HEAD:refs/heads/main'
safe "--follow-tags with feat/x"                bash -c 'git tag -a -m t t4 HEAD && git push --follow-tags origin feat/x'
safe "remote HEAD as destination"               git push origin main:HEAD
safe "remote HEAD as destination, full name"    git push origin main:refs/heads/HEAD
safe "local symref to main"                     bash -c 'git symbolic-ref refs/heads/alias refs/heads/main && git push origin alias:main'
# removed: remote symref case (GitHub does not allow symrefs; accepted limitation)
safe "force-move annotated tag forward"         bash -c 'git tag -f -a -m moved v1 main >/dev/null && git push --force origin v1'
safe "force-recreate annotated tag same commit" bash -c 'git tag -f -a -m again v1 v1^{commit} >/dev/null && git push --force origin v1'
safe "ALLOW_REWRITE: tag move"                  env WARDENLENS_ALLOW_REWRITE=1 bash -c 'git tag -f v1 feat/x >/dev/null && git push --force origin v1'
safe "ALLOW_REWRITE: main via +refspec"         env WARDENLENS_ALLOW_REWRITE=1 git push origin +feat/y:main
safe "ALLOW_REWRITE: --mirror"                  env WARDENLENS_ALLOW_REWRITE=1 git push --mirror origin
safe "--prune deletes"                          git push --prune origin 'refs/heads/feat/x:refs/heads/feat/x' 'refs/heads/nope/*:refs/heads/*'
safe "missing remote sha, forced"               bash -c 'o=$(mktemp -d); git clone -q "$(git remote get-url origin)" "$o/o"; git -C "$o/o" -c user.email=a@b -c user.name=a commit -q --allow-empty -m z; git -C "$o/o" push -q origin HEAD:feat/y; rm -rf "$o"; git push --force origin feat/x:feat/y'
# removed: send-pack plumbing never runs the hook; the Bash guard denies it (guard-bash.test.sh)
safe "push to file path, not remote name"       bash -c 'git push "$(git remote get-url origin)" main'
exit $fail
