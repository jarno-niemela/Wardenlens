#!/usr/bin/env bash
# Adversarial cases for .claude/hooks/guard-bash.sh.
# Each case states the behaviour a correct guard should have; FAIL lines are findings.
# Run from a feature branch (the bare-push-on-main rule depends on the current branch).
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
guard=${GUARD:-$root/.claude/hooks/guard-bash.sh}
fail=0

run() { jq -n --arg c "$1" '{tool_input: {command: $c}}' | "$guard" >/dev/null 2>&1; }
allow() { if run "$1"; then echo "ok   allow: $1"; else echo "FAIL should allow: $1"; fail=1; fi; }
deny()  { if run "$1"; then echo "FAIL should deny: $1"; fail=1; else echo "ok   deny:  $1"; fi; }

# --- push to main: refspec variants -------------------------------------
deny  "git push origin main:main"
deny  "git push origin refs/heads/main"
deny  "git push origin HEAD:refs/heads/main"
deny  "git push origin feat/x:main"
deny  "git push origin master"
deny  "git push origin main;"
deny  "git push origin main&&echo done"
deny  "git push origin 'main'"
deny  "git push origin \"main\""
deny  "git push origin :main"
deny  "git push origin --delete main"
deny  "git push --mirror"
deny  "git push --all origin"
allow "git push upstream feat/main"
allow "git push origin feat/maintenance"
allow "git push -u origin feat/7-main-menu"
allow "git fetch origin main"
allow "git pull --rebase origin main"
allow "git rebase origin/main"

# --- force push: flag variants -------------------------------------------
deny  "git -c core.x=y push --force origin feat/x"
deny  "git -C /tmp/wt push --force origin feat/x"
deny  "cd wt && git push --force origin feat/x"
deny  "git push -uf origin feat/x"
deny  "git push -fu origin feat/x"
deny  "git push origin feat/x -f"
deny  "git push origin +HEAD:feat/x"
deny  "git push origin +refs/heads/feat/x"
deny  "git push origin --force"
allow "git push --force-with-lease origin feat/x"
allow "git push --force-with-lease=feat/x origin feat/x"
allow "git push --force-with-lease --force-if-includes origin feat/x"
# lease on main is still a push to main
deny  "git push --force-with-lease origin main"
deny  "git push --force-with-lease=main:abc123 origin main"

# --- --no-verify ------------------------------------------------------------
deny  "git push origin feat/x --no-verify"
deny  "git commit -n -m wip"
deny  "git commit -nm wip"
deny  "git -c x=y commit --no-verify -m wip"
deny  "git -C wt commit --no-verify -m wip"

# --- gh ---------------------------------------------------------------------
deny  "gh pr merge --admin"
deny  "gh issue delete 3 --yes"
deny  "gh  repo   delete x"
deny  "gh pr merge 3 --auto --squash"   # merges need --match-head-commit
allow "gh issue view 3"

# --- chained / multiple commands -------------------------------------------
deny  "git push origin feat/x && git push origin main"
deny  "git status; git push --force origin feat/x"
deny  "true || git push -f"

# --- false positives: text mentioning forbidden commands --------------------
allow "git commit -m 'docs: explain why git push --force is blocked'"
allow "git commit -m 'docs: never git push origin main'"
allow "grep -rn -- '--no-verify' docs"
allow "git log --grep 'gh pr merge --admin'"
allow "echo 'gh repo delete is blocked'"
allow "git push origin feat/x # never main"
allow "gh pr create --title 'chore: guard' --body 'blocks git push --force and push to main'"

# --- heredoc handling -------------------------------------------------------
# indented terminator with <<- (tab)
allow $'cat > a <<-EOF\n\tgit push --force origin x\n\tEOF\necho ok'
# terminator with trailing text must NOT end the doc early (it is not the terminator)
allow $'cat > a <<EOF\nEOF is a word\ngit push --force origin x\nEOF'
# quoted terminator with spaces around <<
allow $'cat > a << "END"\ngit push -f\nEND'
# two heredocs in a row
allow $'cat > a <<A\ngit push -f\nA\ncat > b <<B\ngit commit --no-verify\nB'
# command after heredoc must still be checked
deny  $'cat > a <<A\nhello\nA\ngit push origin main'
# heredoc opened on the same line as a forbidden command
deny  $'git push --force origin x <<EOF\nhi\nEOF'
# two heredocs on one line: second body must also be ignored
allow $'cat <<A >a; cat <<B >b\nx\nA\ngit push -f\nB'
# here-string is not a heredoc: following lines are commands
deny  $'cat <<<EOF\ngit push --force origin x'
deny  $'cat <<< "hi"\ngit push --force origin x'
# heredoc body with unterminated doc should not hide later commands (bash would treat rest as body; ok either way)
# gh pr create body via heredoc (very common for agents)
allow $'gh pr create --title t --body "$(cat <<\'EOF\'\nThis blocks git push --force and gh pr merge --admin.\nEOF\n)"'
# arithmetic shift is not a heredoc
deny  $'echo $((1<<EOF))\ngit push -f'

# --- robustness -----------------------------------------------------------
allow ""
allow "git push origin feat/x"

exit $fail
