# Ticket hygiene rules. Pure function of its inputs so it can be tested offline.
#
# Inputs (via --slurpfile / --argjson):
#   $issues        array from `gh issue list --state all --json number,title,state,labels,body,assignees,updatedAt`
#   $prs           array from `gh pr list --state all --json number,title,body,state,createdAt,isDraft,reviewDecision,author,labels`
#                  PR rules apply only to state == "OPEN". Bot-authored PRs (e.g. Dependabot) are
#                  exempt from the "closes an issue" rule. PR numbers count as known blockers.
# Shared helpers live in common.jq (included by scripts/ticket-audit).
#   $repo          this repository as "owner/name"; only references to it count
#   $now           epoch seconds
#   $stale_days    in-progress without a PR for longer than this is flagged
#   $backlog_days  backlog untouched for longer than this is flagged
#   $pr_days       open PR without approval for longer than this is flagged
#
# Output: array of {severity, number, title, rule, message}

def age_days($t): (($now - ($t | ts)) / 86400);
def finding($sev; $rule; $msg): {severity: $sev, number: .number, title: .title, rule: $rule, message: $msg};

($issues | map({key: (.number | tostring), value: .}) | from_entries) as $by
| ($prs | map({key: (.number | tostring), value: .}) | from_entries) as $pby
| [$prs[] | select(.state == "OPEN")] as $open_prs
| ([$open_prs[] | closing_refs($repo)[]] | unique) as $linked
| def issue($n): $by[$n | tostring];
  def pr($n): $pby[$n | tostring];
  def known($n): issue($n) != null or pr($n) != null;
  def is_open($n): (issue($n) != null and issue($n).state == "OPEN") or (pr($n) != null and pr($n).state == "OPEN");
[
  ( $issues[] | select(.state == "OPEN") | . as $i
    | prefixed("type:") as $t
    | prefixed("status:") as $s
    | ( if ($t | length) != 1 then finding("error"; "type-label"; "needs exactly one type:* label (has \($t | length))") else empty end ),
      ( if ($s | length) != 1 then finding("error"; "status-label"; "needs exactly one status:* label (has \($s | length))") else empty end ),
      ( if (haslabel("type:task") or haslabel("type:bug")) and (prefixed("priority:") | length) != 1
        then finding("error"; "priority-label"; "needs exactly one priority:* label") else empty end ),
      ( if haslabel("type:task") then
          epic_ref as $e
          | if $e == null then finding("error"; "orphan-task"; "task has no 'Epic: #N' line in its body")
            elif issue($e) == null then finding("error"; "bad-epic"; "Epic #\($e) does not exist")
            elif (issue($e) | haslabel("type:epic") | not) then finding("error"; "bad-epic"; "#\($e) is not labelled type:epic")
            elif issue($e).state == "CLOSED" then finding("warn"; "closed-epic"; "parent epic #\($e) is closed but this task is open")
            else empty end
        else empty end ),
      ( if haslabel("status:in-progress") then
          ( if ($linked | index($i.number)) == null and age_days($i.updatedAt) > $stale_days
            then finding("warn"; "stale-in-progress"; "in progress \(age_days($i.updatedAt) | floor)d with no open PR") else empty end ),
          ( if (.assignees | length) == 0 then finding("warn"; "unassigned-in-progress"; "in progress but nobody is assigned") else empty end )
        else empty end ),
      ( if (haslabel("status:in-review") or haslabel("status:changes-requested")) and ($linked | index($i.number)) == null
        then finding("error"; "review-without-pr"; "\($s | join(",")) but no open PR closes it") else empty end ),
      ( if haslabel("status:blocked") then
          blockers($repo) as $b
          | if ($b | length) == 0 and (foreign_blockers($repo) | length) > 0 then empty
            elif ($b | length) == 0 then finding("error"; "blocked-no-reason"; "blocked but has no 'Blocked by: #N' line")
            elif any($b[]; known(.) | not) then empty
            elif (foreign_blockers($repo) | length) > 0 then empty
            elif all($b[]; is_open(.) | not) then finding("warn"; "unblocked"; "all blockers are closed; move to status:ready")
            else empty end
        else empty end ),
      ( if (blockers($repo) | index($i.number)) != null then finding("error"; "self-blocker"; "lists itself as a blocker") else empty end ),
      ( blockers($repo)[] as $b | if known($b) | not then finding("error"; "bad-blocker"; "blocked by #\($b), which is neither an issue nor a PR") else empty end ),
      ( if haslabel("status:ready") and ([blockers($repo)[] | select(is_open(.))] | length) > 0
        then finding("warn"; "ready-but-blocked"; "status:ready but has open blockers") else empty end ),
      ( if haslabel("status:backlog") and age_days($i.updatedAt) > $backlog_days
        then finding("info"; "stale-backlog"; "untouched \(age_days($i.updatedAt) | floor)d in backlog") else empty end ),
      ( if haslabel("status:done") then finding("warn"; "done-but-open"; "labelled status:done but still open") else empty end ),
      ( if haslabel("type:epic") then
          [$issues[] | select(epic_ref == $i.number)] as $kids
          | if ($kids | length) == 0 then finding("warn"; "empty-epic"; "epic has no tasks")
            elif all($kids[]; .state == "CLOSED") then finding("warn"; "epic-complete"; "all \($kids | length) tasks closed; close the epic")
            else empty end
        else empty end )
  ),
  ( $issues[] | select(.state == "CLOSED")
    | (prefixed("status:") | map(select(. != "status:done"))) as $s
    | if ($s | length) > 0 then finding("info"; "closed-stale-status"; "closed but still labelled \($s | join(","))") else empty end
  ),
  ( $open_prs[]
    | ( if (closing_refs($repo) | length) == 0 and ((.author.is_bot // false) | not) then finding("error"; "pr-no-issue"; "PR does not close any issue (add 'Closes #N')") else empty end ),
      ( closing_refs($repo)[] as $n | if issue($n) == null then finding("error"; "pr-bad-ref"; "closes #\($n), which is not an issue") else empty end ),
      ( if (.isDraft | not) and age_days(.createdAt) > $pr_days and .reviewDecision != "APPROVED"
           and ((["verify:quality", "verify:security", "verify:adversarial"] - labelnames) | length) > 0
        then finding("warn"; "stale-pr"; "PR open \(age_days(.createdAt) | floor)d without approval") else empty end )
  )
]
| sort_by((if .severity == "error" then 0 elif .severity == "warn" then 1 else 2 end), .number)
