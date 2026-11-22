#!/usr/bin/env bash
# PreToolUse guard for Bash: blocks commands that bypass the workflow.
# A safety net against mistakes, not a security boundary.
# Exit 2 = block (stderr is shown to Claude).
set -euo pipefail
cmd=$(jq -r '.tool_input.command // ""')

block() { echo "Blocked by .claude/hooks/guard-bash.sh: $1" >&2; exit 2; }

# Drop heredoc bodies (file contents being written are data, not commands),
# then normalise whitespace.
code=$(awk '
  in_doc { if ($0 ~ "^[ \t]*" term "[ \t]*$") in_doc = 0; next }
  {
    print
    if (match($0, /<<-?[ \t]*["\047]?[A-Za-z_][A-Za-z0-9_]*["\047]?/)) {
      term = substr($0, RSTART, RLENGTH); gsub(/<<-?[ \t]*|["\047]/, "", term); in_doc = 1
    }
  }' <<<"$cmd")
c=$(tr -s '[:space:]' ' ' <<<"$code")

[[ "$c" =~ git\ push.*(--force([^-]|$)|\ -f(\ |$)|\ \+[a-zA-Z]) ]] && block "force push is not allowed (use --force-with-lease on your own feature branch)"
[[ "$c" =~ git\ push.*(\ |:)(main|master)(\ |$) ]] && block "never push to main; open a PR"
[[ "$c" =~ git\ (commit|push|merge|rebase).*--no-verify ]] && block "--no-verify skips the quality gate"
[[ "$c" =~ gh\ pr\ merge.*--admin ]] && block "--admin bypasses required checks"
[[ "$c" =~ gh\ (repo|issue)\ delete ]] && block "deleting repos/issues requires the user"

# Pushing while checked out on main (bare `git push`).
if [[ "$c" =~ (^|[;&|]\ ?)git\ push(\ |$) ]] && [[ ! "$c" =~ git\ -C ]] \
   && [[ "$(git branch --show-current 2>/dev/null)" == main ]]; then
  block "current branch is main; create a feature branch first"
fi
exit 0
