#!/usr/bin/env bash
# Round 5 adversarial cases for .claude/hooks/guard-bash.sh: push plumbing, WARDENLENS_ALLOW_REWRITE,
# cd tracking, tamper protection. Cases are data passed to the hook; nothing here executes them.
# shellcheck disable=SC2016  # single quotes are intentional: cases are literal command text
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
guard=$root/.claude/hooks/guard-bash.sh
fail=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git init -q -b main "$tmp/onmain"; git init -q -b feat/x "$tmp/onfeat"
mkdir -p "$tmp/home" "$tmp/onfeat/.githooks"

run() { jq -n --arg c "$1" --arg d "${2:-}" '{tool_input: {command: $c}} + (if $d == "" then {} else {cwd: $d} end)' | HOME=$tmp/home "$guard" >/dev/null 2>&1; }
allow() { if run "$1" "${2:-}"; then echo "ok   allow: $1"; else echo "FAIL should allow: $1"; fail=1; fi; }
deny()  { if run "$1" "${2:-}"; then echo "FAIL should deny: $(printf '%q' "$1")"; fail=1; else echo "ok   deny:  $(printf '%q' "$1")"; fi; }
F=$tmp/onfeat; M=$tmp/onmain

# --- redirection between git and its subcommand hides the subcommand ---------------------------
deny  "git 2>/dev/null push --force origin feat/x" "$F"
deny  "git 2>/dev/null commit --no-verify -m x" "$F"
deny  "git >/dev/null push origin main" "$F"
deny  "git push>/dev/null --force origin feat/x" "$F"
deny  "git commit>/dev/null -n -m x" "$F"
deny  "git>/dev/null push --force origin feat/x" "$F"
deny  "git 2>/dev/null send-pack origin main" "$F"
deny  "git send-pack>/dev/null ../r.git main" "$F"
deny  "git 2>&1 config core.hooksPath /dev/null" "$F"

# --- push plumbing, plain spellings ------------------------------------------------------------
deny  "git send-pack ../r.git main" "$F"
deny  "git -C . send-pack ../r.git main" "$F"
deny  "git --no-pager http-push https://x/r.git main" "$F"
deny  "/usr/lib/git-core/git-remote-https origin https://x/r.git" "$F"
deny  "env git-receive-pack ../r.git" "$F"
deny  "git fetch-pack --stateless-rpc https://x/r.git" "$F"
deny  "bash -c 'git send-pack ../r.git main'" "$F"
allow "git fetch-pack ../r.git main" "$F"
allow "git remote -v" "$F"

# --- WARDENLENS_ALLOW_REWRITE ------------------------------------------------------------------
deny  "WARDENLENS_ALLOW_REWRITE+=1 git push --force-with-lease origin feat/x" "$F"
deny  "read WARDENLENS_ALLOW_REWRITE <<<1; export WARDENLENS_ALLOW_REWRITE" "$F"
deny  "declare -x WARDENLENS_ALLOW_REWRITE=1" "$F"
deny  "git push origin feat/x; export WARDENLENS_ALLOW_REWRITE=1" "$F"
deny  'echo "$(WARDENLENS_ALLOW_REWRITE=1 git push --force-with-lease origin feat/x)"' "$F"
deny  'git commit -m "$(export WARDENLENS_ALLOW_REWRITE=1)"' "$F"
allow 'git commit -m "docs: explain WARDENLENS_ALLOW_REWRITE"' "$F"

# --- cd tracking: a cd that may not run must make the directory unknown -------------------------
deny  $'if false; then\ncd '"$F"$'\nfi\ngit push' "$M"
deny  $'if false\nthen\ncd '"$F"$'\nfi; git push' "$M"
deny  $'while false; do\ncd '"$F"$'\ndone\ngit push' "$M"
deny  "case x in y) cd $F;; esac; git push" "$M"
deny  "test -d /nonexistent && cd $F; git push" "$M"
deny  "false || cd $F; git push" "$M"
deny  "{ cd $F; }; git push" "$M"
allow "cd $F && git push" "$M"

# --- tamper protection ------------------------------------------------------------------------
deny  "echo x >.githooks/pre-push" "$F"
deny  "echo x 1<>.githooks/pre-push" "$F"
deny  "echo x <>.githooks/pre-push" "$F"
deny  "cd .githooks && echo exit 0 > pre-push" "$F"
deny  "echo exit 0 > pre-push" "$F/.githooks"
deny  "cd .git && cp /tmp/c config" "$F"
deny  "cp /tmp/c config" "$F/.git"
deny  "echo '[core]' >> config" "$F/.git"
deny  "cat x | tee -a ~/.bashrc" "$F"
deny  'printf x >>"$HOME/.profile"' "$F"
deny  "ln -sf /tmp/x .githooks/pre-push" "$F"
deny  "sed -i s/exit/true/ .githooks/pre-push" "$F"
deny  "chmod -x .githooks/pre-push" "$F"
deny  "git checkout HEAD~1 -- .githooks/pre-push" "$F"
allow "cat .githooks/pre-push" "$F"
# accepted false positive (brief r6 s3): a read like `cp .githooks/x /tmp/y` stays denied (fail closed)
exit $fail
