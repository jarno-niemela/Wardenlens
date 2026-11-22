#!/usr/bin/env bash
# Regression tests for .claude/hooks/guard-bash.sh. Cases are data passed to the hook; nothing here
# executes them. The bare-push-on-main cases use a throwaway repository on branch main.
# shellcheck disable=SC2016  # single quotes are intentional: cases are literal command text
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
guard=$root/.claude/hooks/guard-bash.sh
fail=0

run() { jq -n --arg c "$1" '{tool_input: {command: $c}}' | "$guard" >/dev/null 2>&1; }
allow() { if run "$1"; then echo "ok   allow: $1"; else echo "FAIL should allow: $1"; fail=1; fi; }
deny()  { if run "$1"; then echo "FAIL should deny: $1"; fail=1; else echo "ok   deny:  $1"; fi; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git init -q -b main "$tmp/onmain"
git init -q -b feat/x "$tmp/onfeat"

# --- allowed -------------------------------------------------------------
allow "git push -u origin feat/12-parser"
allow "git push --force-with-lease origin feat/12-parser"
allow "git push --force-with-lease --force-if-includes origin feat/12-parser"
allow "git push origin feat/maintenance"
allow "git -C $tmp/onfeat push origin feat/x"
allow "git -C $tmp/onfeat push"
allow "git commit -m 'feat: add parser'"
allow "git -C x commit -am wip"
allow "gh pr merge 7 --squash --match-head-commit 0123456789abcdef0123456789abcdef01234567"
allow 'gh pr merge 7 --squash --match-head-commit="$sha"'
allow 'gh pr merge 7 --squash --match-head-commit ${sha}'
allow 'gh -R o/r pr merge 7 --squash --match-head-commit "$sha"'
allow 'gh pr merge 7 --squash --delete-branch --match-head-commit "$sha"'
allow 'sha=$(scripts/verify check 7) && gh pr merge 7 --squash --match-head-commit "$sha"'
allow "gh api repos/o/r/issues/7/labels"
allow "gh api repos/o/r/commits/abc/statuses"
allow "cargo test --workspace"
allow "grep -rn -- '--no-verify' docs"
allow "git log --grep 'gh pr merge --admin'"
allow "echo 'gh repo delete is blocked'"
allow "git push origin feat/x # never main"
allow "git fetch origin main"
allow "git pull --rebase origin main"
allow ""
# heredoc bodies feeding non-interpreters are data
allow $'cat > doc.md <<\'EOF\'\nnever use git commit --no-verify or git push --force origin main\nEOF\necho done'
allow $'cat > doc.md <<-EOF\n\tgh pr merge 1 --admin\n\tEOF'
allow $'cat > a <<EOF\nEOF is a word\ngit push --force origin x\nEOF'
allow $'cat <<A >a; cat <<B >b\nx\nA\ngit push -f\nB'
allow $'gh pr create --title t --body "$(cat <<\'EOF\'\nThis blocks git push --force and gh pr merge --admin.\nEOF\n)"'

# --- force push ----------------------------------------------------------
deny  "git push --force origin feat/x"
deny  "git push -f"
deny  "git push -uf origin feat/x"
deny  "git push -fu origin feat/x"
deny  "git push origin feat/x -f"
deny  "git push origin +feat/x"
deny  "git push origin +HEAD:feat/x"
deny  "git -C x push --force"
deny  "git -c core.x=y push --force origin feat/x"
deny  "git --no-pager push -f origin feat/x"
deny  "cd wt && git push --force origin feat/x"
deny  "bash -c 'git push --force origin x'"
deny  'sudo git push -f'
deny  'echo "$(git push -f)"'
deny  "git push --mirror"
deny  "git push --all origin"
deny  "git push origin --delete feat/x"
deny  "git push origin :feat/x main"

# --- push to main --------------------------------------------------------
deny  "git push origin main"
deny  "git push origin master"
deny  "git push origin HEAD:main"
deny  "git push origin HEAD:refs/heads/main"
deny  "git push origin refs/heads/main"
deny  "git push origin feat/x:main"
deny  "git push origin main:main"
deny  "git push origin :main"
deny  "git push origin main;"
deny  "git push origin 'main'"
deny  'git push origin "main"'
deny  "git push --force-with-lease origin main"
deny  "git -C x push origin main"
deny  "git push origin feat/x && git push origin main"
deny  "git -C $tmp/onmain push"
deny  "git -C $tmp/onmain push origin"
deny  "git -C $tmp/onmain push -u origin HEAD"
deny  "cd $tmp/onmain && git push"

# --- hook bypass ---------------------------------------------------------
deny  "git commit --no-verify -m wip"
deny  "git commit -n -m wip"
deny  "git commit -nm wip"
deny  "git commit -anm wip"
deny  "git -C wt commit --no-verify -m wip"
deny  "git push origin feat/x --no-verify"
deny  "git merge --no-verify x"
deny  "git rebase --no-verify main"
deny  "git -c core.hooksPath=/dev/null commit -m x"
deny  "git -c core.hookspath=/dev/null push origin feat/x"
deny  "git --config-env=core.hooksPath=X commit -m x"

# --- gh ------------------------------------------------------------------
deny  "gh pr merge 7 --squash"
deny  "gh pr merge 7 --squash --match-head-commit abc"
deny  'gh pr merge 7 --squash --match-head-commit $(git rev-parse HEAD)'
deny  'gh pr merge 7 --squash --match-head-commit "$sha$x"'
deny  "gh api -X POST repos/o/r/statuses/abc -f state=success"
deny  "gh pr merge 3 --squash --delete-branch"
deny  "gh pr merge 3 --auto --squash"
deny  "gh pr merge 3 --admin --squash --match-head-commit abc"
deny  "gh repo delete owner/repo --yes"
deny  "gh issue delete 3 --yes"
deny  "gh api repos/o/r/pulls/7/merge -X PUT"
deny  "gh api --method PUT repos/o/r/pulls/7/merge"
deny  "gh api -X DELETE repos/o/r"
deny  "gh api --method=DELETE repos/o/r/git/refs/heads/x"
deny  "gh api -X PUT repos/o/r/branches/main/protection"
deny  "gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: \"x\"}) { clientMutationId } }'"

# --- heredoc handling ----------------------------------------------------
deny  $'cat > x <<EOF\nhello\nEOF\ngit push --force origin x'
deny  $'cat > a <<A\nhello\nA\ngit push origin main'
deny  $'git push --force origin x <<EOF\nhi\nEOF'
deny  $'bash <<EOF\ngit push --force origin x\nEOF'
deny  $'cat <<EOF | bash\ngit push -f\nEOF'
deny  $'sh -s <<\'EOF\'\ngit commit --no-verify -m x\nEOF'
deny  $'cat <<<"x"\ngit push --force origin x'
deny  $'cat <<<EOF\ngit push --force origin x'
deny  $'echo $((1<<EOF))\ngit push -f'

# --- round 4: human-only rewrite switch, config keys, refspecs, gh api forms ---------------------------
runc() { jq -n --arg c "$1" --arg d "$2" '{tool_input: {command: $c}, cwd: $d}' | "$guard" >/dev/null 2>&1; }
allow_in() { if runc "$1" "$2"; then echo "ok   allow: $1"; else echo "FAIL should allow: $1"; fail=1; fi; }
deny_in()  { if runc "$1" "$2"; then echo "FAIL should deny: $1"; fail=1; else echo "ok   deny:  $1"; fi; }
deny  "WARDENLENS_ALLOW_REWRITE=1 git push --force-with-lease origin feat/x"
deny  "export WARDENLENS_ALLOW_REWRITE=1"
deny  "env WARDENLENS_ALLOW_REWRITE=1 git push origin feat/x"
deny  "bash -c 'WARDENLENS_ALLOW_REWRITE=1 git push origin feat/x'"
deny  "declare -x WARDENLENS_ALLOW_REWRITE"
allow "git commit -m 'document WARDENLENS_ALLOW_REWRITE for humans'"
deny  "git -c Push.Default=Matching push origin feat/x"
deny  "git -c remote.origin.mirror=true status"
deny  "git -cremote.origin.mirror=true status"
deny  "git --config-env=push.default=X push origin feat/x"
deny  "git config alias.p push"
deny  "git config --unset alias.p"
deny  "git config includeIf.gitdir:/x.path /tmp/evil"
deny  "git config remove-section core"
deny  "git config rename-section core old"
deny  "git push origin :"
deny  "git push origin :feat/y"
allow "git config --get push.default"
allow "git push origin feat/x:refs/heads/feat/y"
deny  "gh api -X PUT repos/o/r/contents/a%2Fb -f message=m -f content=eA=="
deny  "gh api --method POST repos/o/r/git/refs%2Fheads -f ref=x"
deny  "gh api -X PUT repos/o/r/contents/x -F branch=master -f content=eA=="
deny  "gh api -X PUT repos/o/r/contents/x --field branch=main"
allow "gh api -X PUT repos/o/r/contents/x -f branch=feat/x -f content=eA=="
deny  "gh api -iX DELETE repos/o/r"
deny  "gh api graphql -f query='MUTATION { x }'"
deny  "gh api graphql --raw-field 'query=mutation{x}'"
allow "gh api graphql -f query='query { viewer { login } }'"
allow "gh api repos/o/r/issues/7/comments 2>&1"
deny  "gh pr merge 7 --squash 2>&1"
deny_in "popd; git push" "$tmp/onfeat"
deny_in "(cd /tmp); git push" "$tmp/onfeat"
deny_in "cd /tmp | cat; git push" "$tmp/onfeat"
deny_in "cd /tmp & git push" "$tmp/onfeat"
deny_in "echo \`cd /tmp\`; git push" "$tmp/onfeat"
deny_in "GIT_WORK_TREE=/tmp; git push" "$tmp/onfeat"
deny_in "git push 2>&1" "$tmp/onmain"
allow_in "git push" "$tmp/onfeat"
allow_in "git push 2>&1" "$tmp/onfeat"
allow_in "cd $tmp/onfeat && git push" "$tmp/onmain"
allow_in "(cd /tmp); git push origin feat/x" "$tmp/onmain"
deny  $'bash<<EOF\ngit push -f\nEOF'

# --- fail closed ---------------------------------------------------------
# With jq unavailable the guard must block (exit 2), not allow.
mkdir -p "$tmp/nojq"
for t in bash cat tr awk sed grep git; do ln -s "$(command -v "$t")" "$tmp/nojq/$t"; done
rc=0
printf '%s' '{"tool_input":{"command":"echo hi"}}' | PATH="$tmp/nojq" "$guard" >/dev/null 2>&1 || rc=$?
if [[ $rc -eq 2 ]]; then echo "ok   fail-closed without jq"; else echo "FAIL missing jq exited $rc, expected 2"; fail=1; fi
rc=0
printf '%s' 'not json' | "$guard" >/dev/null 2>&1 || rc=$?
if [[ $rc -eq 2 ]]; then echo "ok   fail-closed on unreadable input"; else echo "FAIL bad input exited $rc, expected 2"; fail=1; fi
exit $fail
