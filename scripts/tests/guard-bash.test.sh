#!/usr/bin/env bash
# Regression tests for .claude/hooks/guard-bash.sh.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
guard=$root/.claude/hooks/guard-bash.sh
fail=0

run() { jq -n --arg c "$1" '{tool_input: {command: $c}}' | "$guard" >/dev/null 2>&1; }
allow() { if run "$1"; then echo "ok   allow: $1"; else echo "FAIL should allow: $1"; fail=1; fi; }
deny()  { if run "$1"; then echo "FAIL should deny: $1"; fail=1; else echo "ok   deny:  $1"; fi; }

allow "git push -u origin feat/12-parser"
allow "git push --force-with-lease origin feat/12-parser"
allow "gh pr merge 3 --squash --delete-branch"
allow "cargo test --workspace"
allow $'cat > doc.md <<\'EOF\'\nnever use git commit --no-verify or git push --force origin main\nEOF\necho done'
allow $'cat > doc.md <<-EOF\n\tgh pr merge 1 --admin\n\tEOF'
deny  "git push --force origin feat/x"
deny  "git push -f"
deny  "git push origin +feat/x"
deny  "git push origin main"
deny  "git push origin HEAD:main"
deny  "git commit --no-verify -m wip"
deny  "gh pr merge 3 --admin --squash"
deny  "gh repo delete owner/repo --yes"
deny  $'cat > x <<EOF\nhello\nEOF\ngit push --force origin x'
exit $fail
