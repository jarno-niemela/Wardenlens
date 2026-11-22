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

# Every #N mentioned on "Blocked by" lines.
def blockers:
  [ body_lines
    | select(test("^\\s*(?:[-*]\\s*)?blocked[ -]by\\b:?\\s*"; "i"))
    | scan("#([0-9]+)") | .[0] | tonumber ];

# Issue numbers GitHub would close from a PR body. Titles are not linked by
# GitHub, so only the body counts. Accepts #N, owner/repo#N and issue URLs.
def closing_refs:
  [ (.body // "") | gsub("\r"; "")
    | scan("(?i)\\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\\s*:?\\s*(?:https://github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#|#)([0-9]+)")
    | .[0] | tonumber ] | unique;

# Label helpers (labels may be null or missing).
def labelnames: [(.labels // [])[].name];
def haslabel($l): labelnames | index($l) != null;
def prefixed($p): labelnames | map(select(startswith($p)));

# ISO-8601 timestamp to epoch seconds; GitHub may add fractional seconds.
def ts: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
