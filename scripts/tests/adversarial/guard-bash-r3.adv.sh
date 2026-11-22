#!/usr/bin/env bash
# Round 3 cases for .claude/hooks/guard-bash.sh: the brief's rules that the round-2 file does not cover.
# Cases are data passed to the hook; nothing here executes them.
# shellcheck disable=SC2016  # single quotes are intentional: cases are literal command text
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
guard=${GUARD:-$root/.claude/hooks/guard-bash.sh}
fail=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git init -q -b main "$tmp/onmain"; git init -q -b feat/x "$tmp/onfeat"
for r in onmain onfeat; do mkdir -p "$tmp/$r/.githooks"; : >"$tmp/$r/.githooks/pre-push"; chmod +x "$tmp/$r/.githooks/pre-push"; done  # the guard refuses pushes from a checkout without the hook
mkdir -p "$tmp/home"; git init -q -b main "$tmp/home/repo"

run() { jq -n --arg c "$1" --arg d "${2:-}" '{tool_input: {command: $c}} + (if $d == "" then {} else {cwd: $d} end)' | HOME=$tmp/home "$guard" >/dev/null 2>&1; }
allow() { if run "$1" "${2:-}"; then echo "ok   allow: $1"; else echo "FAIL should allow: $1"; fail=1; fi; }
deny()  { if run "$1" "${2:-}"; then echo "FAIL should deny: $(printf '%q' "$1")"; fail=1; else echo "ok   deny:  $1"; fi; }

# --- push: abbreviations, @, globs, redirections ---------------------------------------------
deny  "git push --forc origin feat/x"
deny  "git push --for origin feat/x"
deny  "git push --mirr origin"
deny  "git push --delet origin feat/x"
allow "git push --force-with-lease origin feat/x"
allow "git push --force-w origin feat/x"
allow "git push --force-with-lease=feat/x origin feat/x"
allow "git push --dry-run origin feat/x"
deny  "git push origin refs/heads/main"
deny  "git push origin HEAD:refs/heads/main"
deny  "git push origin feat/x:heads/master"
deny  "git push origin 'feat/*:refs/heads/*'"
deny  "git push origin feat/x:refs/heads/*"
deny  "git push origin +feat/x"
deny  "git push origin -- +feat/x"
deny  "git push origin feat/x 2>/dev/null main"      # redirection must not hide the refspec
deny  "git push origin main 2>&1"
deny  "git push origin main >> log"
deny  "git -C $tmp/onmain push origin HEAD"
allow "git -C $tmp/onfeat push origin @"
allow "git -C $tmp/onfeat push origin HEAD:feat/x"
allow "git push origin feat/x > out.txt"
# --- bare push: directory resolution is fail-closed -------------------------------------
deny  "cd /nonexistent/dir && git push"
deny  'cd "$SOMEWHERE" && git push'
deny  'git -C "$X" push'
deny  "cd ~ && cd repo && git push"
deny  'cd ${HOME}/repo && git push'
deny  "cd repo && git push" "$tmp/home"                 # hook input .cwd is the starting directory
deny  "git push" "$tmp/onmain"
allow "git push" "$tmp/onfeat"
allow "cd $tmp/onfeat && git push"
allow "git -C onfeat push" "$tmp"
deny  "git -C onmain push" "$tmp"
deny  "git --git-dir $tmp/onmain/.git push"
allow "git --git-dir=$tmp/onfeat/.git push" "$tmp/onmain"
# --- unknown git global options ---------------------------------------------------------------
deny  "git --future-flag commit -m x"
deny  "git --future-flag=1 push --force origin feat/x"
deny  "git --future-flag rebase main"
allow "git --future-flag log"
allow "git --no-pager log"
allow "git --no-pager push origin feat/x"
# --- config ---------------------------------------------------------------------------------
deny  "git config --global core.hooksPath /dev/null"
deny  "git config --local core.hookspath /tmp/h"
deny  "git config core.hooksPath ''"
deny  "git config --unset-all core.hooksPath"
deny  "git config --global --unset core.hooksPath"
deny  "git -c core.hooksPath=/dev/null commit -m x"
deny  "git -c remote.origin.push=refs/heads/x:refs/heads/main push origin feat/x"
deny  "git -c alias.p='!git push --force' p"
deny  "git config alias.x '!git push --force'"
allow "git config core.hooksPath .githooks"
allow "git config --local core.hooksPath .githooks"
allow "git config core.hooksPath"
allow "git config user.name x"
deny  "GIT_CONFIG_PARAMETERS=\"'core.hooksPath=/dev/null'\" git commit -m x"
deny  "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x"
allow "GIT_CONFIG_COUNT=0 echo hi"
# --- gh ------------------------------------------------------------------------------------
deny  "gh pr merge 7 --match-head-commit"
deny  'gh pr merge 7 --match-head-commit "$(scripts/verify check 7)"'
deny  'gh pr merge 7 --match-head-commit $a$b'
deny  "gh pr merge 7 --match-head-commit=abc123"
deny  "gh --repo=o/r pr merge 7"
deny  "gh pr --repo o/r merge 7 --admin --match-head-commit 0123456789abcdef0123456789abcdef01234567"
allow "gh -R o/r pr view 7"
allow "gh pr --repo o/r view 7"
deny  "gh api -X=PUT repos/o/r/pulls/7/merge"
deny  "gh api -XPUT repos/o/r/pulls/7/merge"
deny  "gh api --method=PUT repos/o/r/pulls/7/merge"
deny  "gh api https://api.github.com/repos/o/r/pulls/7/merge -X PUT"
deny  "gh api /repos/o/r/pulls/7/merge?x=1 -X PUT"
deny  "gh api -XDELETE repos/o/r"
deny  "gh api -X=DELETE repos/o/r/git/refs/heads/x"
deny  "gh api repos/o/r/statuses/abc -f state=success"          # implicit POST
deny  "gh api repos/o/r/statuses/abc -F state=success -f context=verify/quality"
deny  "gh api repos/o/r/statuses/abc --field state=success"
deny  "gh api repos/o/r/statuses/abc --raw-field=state=success"
deny  "gh api repos/o/r/statuses/abc --input body.json"
deny  "gh api -X PATCH repos/o/r/statuses/abc"
deny  "gh api https://api.github.com/repos/o/r/statuses/abc?x=1 -f state=success"
deny  "gh api repos/o/r/branches/main/protection -f x=1"
deny  "gh api -X POST repos/o/r/rulesets"
deny  "gh api -X PATCH repos/o/r/git/refs/heads/main -f sha=abc"
allow "gh api repos/o/r/commits/abc/statuses"
allow "gh api -X GET repos/o/r/statuses/abc"
allow "gh api repos/o/r/branches/main/protection"
allow "gh api graphql -f query='query { viewer { login } }'"
allow "gh api user -q .login"
# --- heredocs --------------------------------------------------------------------------------
deny  $'cat <<EOF"X"\ngit push --force origin feat/x\nEOFX'      # ambiguous delimiter
deny  $'cat <<"EO"F\ngit push -f origin x\nEOF'
allow $'cat <<"EOF"\nplain text\nEOF'
allow $'cat <<\'EOF\' > f\nplain text\nEOF'
deny  $'echo "x" # a <<EOF\ngit push --force origin feat/x'
deny  $'echo \'<<EOF\'\ngit push --force origin feat/x'
deny  $'x=$(( 1 << ( 2 + 3 ) ))\ngit push --force origin feat/x'
deny  $'(( (a<<1) + (b<<2) ))\ngit push --force origin feat/x'
allow $'echo $((1<<3))\necho done'
deny  $'bash <<<"git commit --no-verify -m x"'
deny  $'sh <<< "git push -f origin x"'
allow $'cat <<<"hello git push --force"'
# --- pipes into shells -----------------------------------------------------------------------
deny  "echo 'git push -f origin x' | zsh"
deny  "echo x | dash"
deny  "echo x | sh -s"
deny  "echo x | bash -s -- a"
deny  "cat f | /bin/bash"
deny  "cat f | sudo bash"
deny  "cat f | env FOO=1 bash"
deny  "cat f |& bash"
deny  "cat f | ( bash )"
deny  "source /dev/stdin"
deny  ". /dev/stdin"
deny  "bash /dev/stdin"
allow "echo a | grep bash"
allow "cat f || bash script.sh"
allow "bash scripts/gate"
allow "ls | wc -l"
allow "echo x | sh scripts/foo"
exit $fail
