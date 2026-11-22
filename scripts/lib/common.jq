# Shared jq definitions for scripts/ticket and scripts/lib/audit.jq.
# Use with: jq -L scripts/lib 'include "common"; ...'
#
# All helpers tolerate null/missing fields and CRLF line endings, because issue
# bodies come from web forms, editors and API clients.

# Lines of the body, CR stripped.
def body_lines: (.body // "") | gsub("\r"; "") | split("\n")[];

# Parent epic number from the first "Epic: #N" line anywhere in the body
# (optionally a list item), or null. Matched per line so the issue-form
# rendering "### Epic\n\nEpic: #1" works.
def epic_ref:
  first(body_lines | capture("^\\s*(?:[-*]\\s*)?epic:\\s*#(?<n>[0-9]+)"; "i") | .n | tonumber) // null;

# True if the captured owner/name is this repository ($repo, "owner/name"), case-insensitively and
# exactly (never a substring). A null capture means a bare #N, which is local.
def local_repo($repo): . == null or (ascii_downcase == ($repo | ascii_downcase));

# [owner/name or null, N] for every reference on "Blocked by" lines (optionally task-list items such
# as "- [ ] Blocked by #2"): #N, owner/name#N or a github.com issue or pull request URL (the host is
# matched case-insensitively; a PR number is a known blocker, see audit.jq).
def blocker_refs:
  [ body_lines
    | select(test("^\\s*(?:[-*]\\s*(?:\\[[ xX]\\]\\s*)?)?blocked[ -]by\\b:?\\s*"; "i"))
    | scan("(?:https://github\\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:issues|pull)/|(?<![A-Za-z0-9_./-])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#|(?<![A-Za-z0-9_])#)([0-9]+)"; "i")
    | [(.[0] // .[1]), (.[2] | tonumber)] ];

# Issue numbers this repository's ticket is blocked by. References to other repositories are ignored here.
def blockers($repo): [blocker_refs[] | select(.[0] | local_repo($repo)) | .[1]];

# Blockers in other repositories cannot be checked from here; callers treat them as "still blocked".
def foreign_blockers($repo): [blocker_refs[] | select(.[0] | local_repo($repo) | not)];

# Issue numbers GitHub would close from a PR body. Titles are not linked by
# GitHub, so only the body counts. Accepts #N, owner/repo#N and issue URLs; references into
# other repositories are ignored.
def closing_refs($repo):
  [ (.body // "") | gsub("\r"; "")
    | scan("(?i)\\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\\s*:?\\s*(?:https://github\\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/issues/|([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#|#)([0-9]+)")
    | select((.[0] // .[1]) | local_repo($repo))
    | .[2] | tonumber ] | unique;

# Label helpers (labels may be null or missing).
def labelnames: [(.labels // [])[].name];
def haslabel($l): labelnames | index($l) != null;
def prefixed($p): labelnames | map(select(startswith($p)));

# ISO-8601 timestamp to epoch seconds; GitHub may add fractional seconds.
def ts: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
