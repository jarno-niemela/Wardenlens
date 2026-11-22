#!/usr/bin/env bash
# Round 5 adversarial cases (tags) for .githooks/pre-push. Real pushes into a throwaway bare remote; the
# oracle is the remote's state afterwards (main untouched, nothing deleted, no tip lost), not the
# hook's message.
# shellcheck disable=SC2016  # inner bash -c scripts expand in the clone, not here
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
hooks=$root/.githooks
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


ok_new() {  # ok_new NAME REF CMD...: a new remote ref REF must exist afterwards (creation allowed)
  local name=$1 ref=$2; shift 2; setup
  (cd "$w" && "$@" >/dev/null 2>&1) || true
  if git -C "$r" rev-parse -q --verify "$ref" >/dev/null; then echo "ok   created: $name"; else echo "FAIL $name: $ref not created"; fail=1; fi
}

safe "delete tag with :refspec"                 git push origin :refs/tags/v1
safe "delete tag with --delete"                 git push --delete origin v1
safe "ALLOW_REWRITE: delete tag"                env WARDENLENS_ALLOW_REWRITE=1 git push origin :v1
safe "branch onto existing tag ref"             git push origin feat/x:refs/tags/v1
safe "+branch onto existing tag ref"            git push origin +feat/x:refs/tags/v1
safe "lightweight retag, --tags --force"        bash -c 'git tag -f v1 main >/dev/null && git push --force --tags origin'
safe "ALLOW_REWRITE: --tags --force"            env WARDENLENS_ALLOW_REWRITE=1 bash -c 'git tag -f v1 feat/x >/dev/null && git push --force --tags origin'
safe "tag peeled to lightweight same commit"    bash -c 'git tag -f v1 v1^{commit} >/dev/null && git push --force origin v1'
safe "--mirror without ALLOW_REWRITE"           git push --mirror origin
safe "--prune with tag refspec"                 git push --prune origin 'refs/tags/none*:refs/tags/*'
ok_new "new lightweight tag"   refs/tags/t9 bash -c 'git tag t9 && git push origin t9'
ok_new "new annotated tag"     refs/tags/t8 bash -c 'git tag -a -m t t8 && git push origin t8'
ok_new "feature branch push"   refs/heads/feat/new bash -c 'git checkout -q -b feat/new && git push origin feat/new'
exit $fail
