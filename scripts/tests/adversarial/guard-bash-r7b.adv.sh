#!/usr/bin/env bash
# Round 7b adversarial cases for .claude/hooks/guard-bash.sh. Cases are data passed to the hook.
# shellcheck disable=SC2016,SC2059  # literal command text; printf formats are the case templates
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
guard=${GUARD:-$root/.claude/hooks/guard-bash.sh}
fail=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for r in onfeat nohook; do git init -q -b feat/x "$tmp/$r"; done
F=$tmp/onfeat
mkdir -p "$F/.githooks" "$F/.claude/hooks" "$F/.github/workflows" "$F/sub/deep" "$F/crates/a" "$tmp/home/.config/systemd/user" \
  "$tmp/nohook/sub"
: >"$F/.githooks/pre-push"; chmod +x "$F/.githooks/pre-push"

run() { jq -n --arg c "$1" --arg d "${2:-}" '{tool_input: {command: $c}} + (if $d == "" then {} else {cwd: $d} end)' | HOME=$tmp/home "$guard" >/dev/null 2>&1; }
allow() { if run "$1" "${2:-}"; then echo "ok   allow: $1"; else echo "FAIL should allow: $(printf '%q' "$1")"; fail=1; fi; }
deny()  { if run "$1" "${2:-}"; then echo "FAIL should deny: $(printf '%q' "$1")"; fail=1; else echo "ok   deny:  $(printf '%q' "$1")"; fi; }

# --- override name: every form denied for REWRITE is denied for WORKFLOWS -------------------------
for form in 'printf -v %s 1' 'typeset -x %s=1' 'read %s <<<1; git push origin feat/x' 'export "%s=1"' \
            'echo "$(%s=1 git push origin feat/x)"' 'git push origin feat/x; export %s=1' 'declare -x %s=1' 'local -x %s=1' \
            '%s=1 scripts/gate' 'declare -gx %s=1'; do
  # shellcheck disable=SC2059
  rw=$(printf "$form" WARDENLENS_ALLOW_REWRITE); wf=$(printf "$form" WARDENLENS_ALLOW_WORKFLOWS)
  if run "$rw" "$F"; then echo "skip parity (REWRITE allowed too): $rw"; else deny "$wf" "$F"; fi
done

# --- git config editor / pager-like keys --------------------------------------------------------
deny  "git config core.Editor vim" "$F"
deny  "git config CORE.EDITOR vim" "$F"
deny  "git -c Core.Editor=x commit" "$F"
deny  "git config set core.editor vim" "$F"
deny  "git config edit" "$F"
deny  "git config --global edit" "$F"
deny  "git config --add core.editor x" "$F"
deny  "git config --replace-all sequence.editor x" "$F"
# accepted (owner, hobby scope): exported editor variables; see ticket
deny  "git config -f .git/config core.editor x" "$F"
deny  "git config --file=.git/config --edit" "$F"
deny  "git config core.HooksPath /tmp/h" "$F"
deny  "git -C . -c core.editor=x commit" "$F"
deny  "GIT_EDITOR=x git -C . rebase -i HEAD~2" "$F"
allow "git config user.name" "$F"
allow "git config --global user.email a@b.c" "$F"
allow "git config --get-regexp alias" "$F"
allow "git config --show-origin -l" "$F"
allow "git config get core.editor" "$F"
allow "git config list" "$F"
allow "git config pull.rebase true" "$F"

# --- named fd redirections -------------------------------------------------------------------
deny  "echo x {fd}>|.githooks/pre-push" "$F"
deny  "echo x {fd}> .githooks/pre-push" "$F"
deny  "exec {fd}>.githooks/pre-push" "$F"
deny  "exec {fd}>>.claude/hooks/guard-bash.sh" "$F"
deny  "echo x {fd}>../.githooks/pre-push" "$F/sub"
allow "exec {fd}>/tmp/x.log" "$F"
allow "cat {a,b}.txt >/tmp/ab.txt" "$F"
allow "echo \${x}>/tmp/out" "$F"

# --- parent-directory / protected writers ------------------------------------------------------
deny  "rm -r -- .claude" "$F"
deny  "rm -rf ./" "$F"
deny  "rm -rf .//" "$F"
deny  "rm -rf sub/.." "$F"
deny  "rm -rf sub/deep/../.." "$F"
deny  "rm -rf ~/" "$F"
deny  "rm -rf ../.." "$F/sub/deep"
deny  "mv .claude/ /tmp/c" "$F"
deny  "mv -t /tmp .github" "$F"
deny  "cp -r -t . /tmp/.githooks" "$F"
deny  "mv -t .claude /tmp/hooks" "$F"
deny  "cp -t .github/workflows /tmp/ci.yml" "$F"
# accepted (owner, hobby scope): cp -t / -rt into an ancestor; see ticket
deny  "cp --target-directory=.claude/hooks /tmp/guard-bash.sh" "$F"
deny  "install -t .githooks /tmp/pre-push" "$F"
deny  "mv -t .githooks /tmp/pre-push" "$F"
deny  "ln -st .claude/hooks /tmp/guard-bash.sh" "$F"
deny  "cp -rT /tmp/x .claude" "$F"
deny  "rsync -a /tmp/x/ ." "$F"
deny  "rsync -a /tmp/x/ ~" "$F"
deny  "chmod 000 ." "$F"
deny  "chmod -R a-x .githooks" "$F"
deny  "find .claude -name '*.sh' -exec chmod -x {} +" "$F"
# accepted (owner, hobby scope): pathless find -delete / -exec rm; see ticket
# accepted (owner, hobby scope): shred; see ticket
deny  "git rm .claude/hooks/guard-bash.sh" "$F"
deny  "git rm -r -q .githooks" "$F"
deny  "git mv .githooks hooks-old" "$F"
deny  "git rm -rf ." "$F"
deny  "truncate -s0 .githooks/pre-push" "$F"
deny  "unlink .githooks/pre-push" "$F"

# --- missing / unusable pre-push hook ---------------------------------------------------------
deny  "git push origin feat/x" "$tmp/nohook/sub"
deny  "cd sub && git push origin feat/x" "$tmp/nohook"
deny  "git -C sub push origin feat/x" "$tmp/nohook"
deny  "rm .githooks/pre-push; git push origin feat/x" "$F"
# accepted (owner, hobby scope): --git-dir/--work-tree with the missing-hook check; see ticket
allow "git push origin feat/x" "$F/sub/deep"
allow "git -C sub push -u origin feat/x" "$F"
allow "cd sub && git push" "$F"

# --- workflow dispatch ------------------------------------------------------------------------
deny  "gh workflow run ci.yml --ref main --ref feat/x" "$F"
deny  "gh workflow run ci.yml -r=feat/x" "$F"
deny  "gh workflow run --ref feat/x ci.yml" "$F"
deny  "gh api --method POST repos/o/r/actions/workflows/ci.yml/dispatches -f ref=x" "$F"
deny  "gh api -XPOST repos/o/r/actions/workflows/1/dispatches" "$F"
deny  "gh api repos/o/r/actions/workflows/1/enable -X PUT" "$F"
deny  "gh api /repos/o/r/environments/prod/secrets/X -X PUT" "$F"
allow "gh workflow run --ref main ci.yml" "$F"
allow "gh run list --limit 5" "$F"
allow "gh run view 123 --log-failed" "$F"
allow "gh run watch 123" "$F"
allow "gh pr checks 7" "$F"
allow "gh api repos/o/r/actions/runs/1/jobs" "$F"
allow "gh api repos/o/r/actions/workflows" "$F"

# --- routine developer commands (false positives) --------------------------------------------
for c in "cargo build --workspace" "cargo test -- --nocapture 2>&1 | tail -20" "cargo clippy --all-targets -- -D warnings" \
         "cargo fmt --all" "git status" "git diff --stat" "git log --oneline -5" "git add -A" 'git commit -m "feat: x"' \
         "git push -u origin HEAD" "git fetch origin" "git pull --rebase origin main" "git rebase origin/main" "git stash" \
         "git stash pop" "git switch -c task/12-thing" "git merge --no-edit origin/main" "rm -rf target" "mkdir -p crates/b/src" \
         "cp -r crates/a crates/b" "mv crates/a/x.rs crates/a/y.rs" "gh pr create --title t --body b" "gh pr view 7 --comments" \
         "gh issue list --label status:ready" "scripts/ticket next" "scripts/gate" "find . -name '*.rs' | xargs wc -l" \
         "grep -rn foo crates/" "ls -la ~/.config" "cat ~/.config/git/config" "tar czf /var/tmp/x.tgz ." "cp -r . /var/tmp/backup" \
         "rsync -a ./ /var/tmp/backup/" "rsync -a --exclude target ./ /var/tmp/backup/" "chmod +x scripts/*.sh" "rm -rf ~/.cache/foo" \
         "rm -rf ~/.config/foo" "find ~/.cargo -name '*.lock' -delete" "find . -path ./target -prune -o -type f -name '*.rs' -print" \
         "find . -path ./target -prune -o -type f -exec grep -l foo {} +" "find /var/tmp -maxdepth 1 -name 'tmp.*' -mtime +1 -exec rm -rf {} +" \
         "install -Dm755 target/release/wardenlens ~/.local/bin/wardenlens" "ln -sf ../a crates/b/a" "git worktree add ../wt feat/x" \
         "git worktree remove ../wt" "git branch -d feat/old" "git tag -l" "git checkout -- src/main.rs" "git restore crates/a/x.rs" \
         "touch crates/a/x.rs" "echo done >&2" "exec 3>/tmp/log; echo x >&3" "cargo run -p wardenlens-cli -- --help" \
         "git diff main...HEAD -- .github/workflows" "git log -p -- .claude/hooks" "rm -f crates/a/*.orig"; do
  allow "$c" "$F"
done
exit $fail
