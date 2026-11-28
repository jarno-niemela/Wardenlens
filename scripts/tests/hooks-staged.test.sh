#!/usr/bin/env bash
# Tests for the staged hooks in scripts/hooks-staged/ (waiting for the owner to install them into .githooks/, which
# agents cannot write). Every case is hermetic: HOME is a throwaway directory with a fake scanner at the fixed path
# $HOME/.cargo/bin/wardenlens, so no real vault, key or installed binary is ever touched.
#  1. the staged pre-push passes every existing pre-push test (nothing is weakened);
#  2. it only adds lines to the installed hook (nothing removed);
#  3. the vault behaviour of both hooks, with real commits and pushes.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
staged=$root/scripts/hooks-staged
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check()  { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
checkf() { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }

export HOME="$tmp/home"; mkdir -p "$HOME/.cargo/bin" "$HOME/.local/share/wardenlens"
unset WARDENLENS_VAULT WARDENLENS_VAULT_KEY WARDENLENS_VAULT_KEY_FILE WARDENLENS_REQUIRE_VAULT WARDENLENS_BIN GITHUB_ACTIONS
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE WARDENLENS_ALLOW_REWRITE WARDENLENS_ALLOW_WORKFLOWS GIT_CONFIG_PARAMETERS
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0

# 1 + 2: nothing weakened (no vault in this HOME, so the scan is skipped and the old behaviour is what is tested).
check "the staged pre-push passes every pre-push test" env HOOKS="$staged" "$root/scripts/tests/pre-push.test.sh"
for adv in "$root"/scripts/tests/adversarial/pre-push-*.adv.sh; do
  check "the staged pre-push passes $(basename "$adv")" env HOOKS="$staged" "$adv"
done
# Nothing is removed from the installed pre-push except the DETAIL argument of a refusal (#128): a POSITIONAL, ALLOW-LIST
# check in a helper shared with the adversarial tests (see scripts/tests/lib/hook-pairing.sh).
# shellcheck disable=SC1091 # sourced helper
source "$root/scripts/tests/lib/hook-pairing.sh"
check "the staged pre-push only adds lines to the installed one, or changes a refusal's detail alone" test "$(hook_pairing_gap "$root/.githooks/pre-push" "$staged/pre-push")" -eq 0
# Self-test: every mutant of a security-relevant line is rejected by the same check (mutants live in $tmp only).
# shellcheck disable=SC2329 # called through `check`
mut() { sed -E "$1" "$staged/pre-push" >"$tmp/mutant"; ! cmp -s "$tmp/mutant" "$staged/pre-push" || return 1; test "$(hook_pairing_gap "$root/.githooks/pre-push" "$tmp/mutant")" -gt 0; }
# shellcheck disable=SC2016 # the sed expressions are literal shell text
{
check "the pairing check rejects a disabled main condition" mut 's/refs\/heads\/main\|refs\/heads\/master\) refuse/refs\/heads\/main) refuse/'
check "the pairing check rejects a disabled tag condition" mut 's/then refuse "existing tags/then true "existing tags/'
check "the pairing check rejects true || refuse" mut 's/git cat-file -e "\$rsha\^\{commit\}" 2>\/dev\/null \|\| refuse/true || refuse/'
check "the pairing check rejects a workflow-inspection failure that no longer refuses" mut 's/2>\/dev\/null\) \|\| refuse "cannot inspect/2>\/dev\/null) || true refuse "cannot inspect/'
check "the pairing check rejects a dropped refusal" mut 's/^( +)refuse "non-fast-forward \/ force push" "ref:\$idx"/\1true "non-fast-forward \/ force push"/'
check "the pairing check rejects a refusal moved into a dead function" mut 's/^( +)(git cat-file -e .*)$/\1_dead() { \2; }/'
check "the pairing check rejects code after the detail: & #" mut 's/(refuse "unknown remote state; fetch first" "ref:\$idx at \$rsha")$/\1 \& #"/'
check "the pairing check rejects code after the detail: a piped refusal (main)" mut 's/(refuse "never push to main; open a PR" "ref:\$idx") ;;/\1 | true "" ;;/'
check "the pairing check rejects code after the detail: a piped refusal (unknown remote)" mut 's/(refuse "unknown remote state; fetch first" "ref:\$idx at \$rsha")$/\1 | true ""/'
check "the pairing check rejects code after the detail: a piped refusal (workflow inspection)" mut 's/(refuse "cannot inspect the pushed commits for workflow changes" "ref:\$idx")$/\1 | true ""/'
check "the pairing check rejects code after the detail: exit 0" mut 's/(refuse "unknown remote state; fetch first" "ref:\$idx at \$rsha")$/\1; exit 0; : ""/'
check "the pairing check rejects a redefinition of refuse" mut 's/(refuse "unknown remote state; fetch first" "ref:\$idx at \$rsha")$/\1; refuse() { :; }; : ""/'
check "the pairing check rejects a detail that prints the update line" mut 's/(refuse "existing tags are immutable[^"]*") "ref:\$idx"/\1 "$line"/'
check "the pairing check rejects a detail that prints the local ref" mut 's/(refuse "deleting remote branches requires the user") "ref:\$idx"/\1 "${line%% *}"/'
check "the pairing check rejects a detail that prints the remote ref" mut 's/(refuse "non-fast-forward \/ force push") "ref:\$idx"/\1 "${rref}"/'
}
removed=$(diff -u "$root/.githooks/pre-commit" "$staged/pre-commit" | grep '^-' | grep -vc '^---' || true)
check "the staged pre-commit only adds lines to the installed one" test "$removed" -eq 0
check "no WARDENLENS_BIN override in either hook" bash -c "! grep -q 'WARDENLENS_BIN' '$staged/pre-push' '$staged/pre-commit' || ! grep -v '^#' '$staged/pre-push' '$staged/pre-commit' | grep -q 'WARDENLENS_BIN'"
check "the hooks never consult GITHUB_ACTIONS" bash -c "! grep -v '^#' '$staged/pre-push' '$staged/pre-commit' | grep -q GITHUB_ACTIONS"
check "the scanner is the fixed installed path" bash -c "grep -q 'vault_bin=\$HOME/.cargo/bin/wardenlens' '$staged/pre-push' && grep -q 'vault_bin=\$HOME/.cargo/bin/wardenlens' '$staged/pre-commit'"

# 3: a fake scanner. It records its arguments and the vault variables it can see, prints a hit line, and exits $STUB_EXIT.
fake() {
  cat >"$HOME/.cargo/bin/wardenlens" <<STUB
#!/usr/bin/env bash
{ printf 'ARGS %s\n' "\$*"; printf 'ENV vault=%s keyfile=%s xdg=%s\n' "\${WARDENLENS_VAULT-unset}" "\${WARDENLENS_VAULT_KEY_FILE-unset}" "\${XDG_DATA_HOME-unset}"; } >>"$tmp/calls"
echo "e:x secret somewhere"
exit $1
STUB
  chmod +x "$HOME/.cargo/bin/wardenlens"
}
: >"$tmp/calls"
db=$HOME/.local/share/wardenlens/dev-vault.db

# A bare remote, a clone with the staged hooks, one pushed branch and one local commit on top.
mkdir -p "$tmp/hooks"; ln -s "$staged/pre-push" "$tmp/hooks/pre-push"; ln -s "$staged/pre-commit" "$tmp/hooks/pre-commit"
git init -q --bare -b main "$tmp/remote.git"
git clone -q "$tmp/remote.git" "$tmp/w" 2>/dev/null
w=$tmp/w
git -C "$w" config user.email t@example.com; git -C "$w" config user.name t
echo 1 >"$w/f"; git -C "$w" add f; git -C "$w" commit -q -m base
git -C "$w" push -q origin HEAD:refs/heads/main
git -C "$w" checkout -q -b feat/x; echo x >"$w/x"; git -C "$w" add x; git -C "$w" commit -q -m x
git -C "$w" push -q origin feat/x
git -C "$w" config core.hooksPath "$tmp/hooks"
mkdir -p "$tmp/fakebin"; printf '#!/bin/sh\nexit 0\n' >"$tmp/fakebin/cargo"; chmod +x "$tmp/fakebin/cargo"
export PATH="$tmp/fakebin:$PATH"
n=0
# A commit made only to have something to push: plumbing, so the hooks under test do not run for it.
more() {
  local tree c
  n=$((n + 1)); echo "more $n" >>"$w/x"; git -C "$w" add x
  tree=$(git -C "$w" write-tree); c=$(git -C "$w" commit-tree "$tree" -p HEAD -m "more $n")
  git -C "$w" update-ref HEAD "$c"
}
# shellcheck disable=SC2329 # called through `check`
push() { git -C "$w" push -q origin "$@" 2>"$tmp/push.err"; }

# no vault: skipped (printed once per push), pushes and commits go through.
more
check "pre-push, no vault: allowed" push feat/x
check "pre-push, no vault: says SKIPPED once" test "$(grep -c SKIPPED "$tmp/push.err")" -eq 1
check "pre-push, no vault: no scanner call" test ! -s "$tmp/calls"
echo y >"$w/y"; git -C "$w" add y
check "pre-commit, no vault: allowed and says SKIPPED" bash -c "git -C '$w' commit -m y 2>&1 | grep -q SKIPPED"
export WARDENLENS_REQUIRE_VAULT=1
more
checkf "pre-push, no vault + WARDENLENS_REQUIRE_VAULT=1: refused" push feat/x
echo z >"$w/z"; git -C "$w" add z
checkf "pre-commit, no vault + WARDENLENS_REQUIRE_VAULT=1: refused" git -C "$w" commit -m z
git -C "$w" reset -q --hard HEAD
unset WARDENLENS_REQUIRE_VAULT

# a vault but no installed scanner: refused (fails closed), with the install command.
: >"$db"
checkf "pre-push, vault but no scanner: refused" push feat/x
check "the refusal names the install command" grep -q 'cargo install --locked --path crates/wardenlens-cli' "$tmp/push.err"
echo z >"$w/z"; git -C "$w" add z
checkf "pre-commit, vault but no scanner: refused" git -C "$w" commit -m z

# a vault and a scanner.
fake 0
: >"$tmp/calls"
old=$(git -C "$w" rev-parse origin/feat/x); new=$(git -C "$w" rev-parse HEAD)
check "pre-push, scan clean: allowed" push feat/x
check "pre-push scans <remote sha>..<local sha> with the fixed options" grep -qx "ARGS vault scan --default-paths --range=$old..$new --remote=origin --ref=refs/heads/feat/x --ref=refs/heads/feat/x" "$tmp/calls"
check "pre-commit, scan clean: allowed" git -C "$w" commit -q -m z
check "pre-commit scans the staged blobs with the fixed options" grep -qx "ARGS vault scan --default-paths --staged" "$tmp/calls"
# a new branch: the all-zero remote sha.
git -C "$w" checkout -q -b feat/new
more
: >"$tmp/calls"
check "pre-push, new branch: allowed" push feat/new
check "a new branch is scanned from the all-zero sha" grep -qE "^ARGS vault scan --default-paths --range=0{40}\.\.[0-9a-f]{40} --remote=origin --ref=refs/heads/feat/new --ref=refs/heads/feat/new$" "$tmp/calls"
# the variables are ignored: the scanner never sees them.
: >"$tmp/calls"; more
check "pre-push with WARDENLENS_VAULT* and XDG_DATA_HOME set: allowed" env WARDENLENS_VAULT=/nonexistent WARDENLENS_VAULT_KEY_FILE=/nonexistent XDG_DATA_HOME=/nonexistent git -C "$w" push -q origin feat/new
check "the scanner does not see WARDENLENS_VAULT*, XDG_DATA_HOME" grep -q "^ENV vault=unset keyfile=unset xdg=unset$" "$tmp/calls"
# WARDENLENS_BIN is no override: a different scanner there never runs.
printf '#!/bin/sh\necho OTHER >>"%s/other"\nexit 0\n' "$tmp" >"$tmp/other-bin"; chmod +x "$tmp/other-bin"
more
check "WARDENLENS_BIN is ignored" env WARDENLENS_BIN="$tmp/other-bin" git -C "$w" push -q origin feat/new
check "the other binary never ran" test ! -e "$tmp/other"
# GITHUB_ACTIONS does not skip a scan when a vault exists.
: >"$tmp/calls"; more
check "pre-push with GITHUB_ACTIONS=true still scans" env GITHUB_ACTIONS=true git -C "$w" push -q origin feat/new
check "the scanner ran under GITHUB_ACTIONS" test -s "$tmp/calls"
# hits (exit 1) and a scan that could not run (exit 2) refuse; nothing is pushed.
for code in 1 2; do
  fake "$code"; more
  before=$(git -C "$tmp/remote.git" rev-parse refs/heads/feat/new)
  checkf "pre-push, scanner exit $code: refused" push feat/new
  check "pre-push, scanner exit $code: the remote is unchanged" test "$(git -C "$tmp/remote.git" rev-parse refs/heads/feat/new)" = "$before"
  check "pre-push, scanner exit $code: the hit line is shown" grep -q 'e:x secret somewhere' "$tmp/push.err"
  echo "z$code" >"$w/z$code"; git -C "$w" add "z$code"
  checkf "pre-commit, scanner exit $code: refused" git -C "$w" commit -q -m "z$code"
  git -C "$w" reset -q --hard
done
# a remote given as a URL is not a name: nothing is excluded, the scan still runs.
fake 0; : >"$tmp/calls"; more
check "pre-push to a URL: allowed" git -C "$w" push -q "$tmp/remote.git" feat/new
check "pre-push to a URL: no --remote option" bash -c "grep -q '^ARGS' '$tmp/calls' && ! grep -q -- '--remote=' '$tmp/calls'"
# an annotated tag: its object is scanned.
git -C "$w" tag -a -m v1 v1
: >"$tmp/calls"
check "pushing a new tag: allowed" git -C "$w" push -q origin v1
check "the tag object is the end of the range" grep -qE "^ARGS vault scan --default-paths --range=0{40}\.\.$(git -C "$w" rev-parse v1) .* --ref=refs/tags/v1 --ref=refs/tags/v1$" "$tmp/calls"

# a push of two refs: one scan per update, each given every remote ref name in input order, then the local names.
fake 0; git -C "$w" checkout -q feat/x; more
git -C "$w" branch -q -f feat/two HEAD; git -C "$w" update-ref refs/heads/feat/two "$(git -C "$w" rev-parse HEAD)"
: >"$tmp/calls"
oldx=$(git -C "$tmp/remote.git" rev-parse refs/heads/feat/x); newx=$(git -C "$w" rev-parse feat/x); newtwo=$(git -C "$w" rev-parse feat/two)
check "a two-ref push: allowed" git -C "$w" push -q origin feat/x feat/two
check "a two-ref push: one scan per update" test "$(grep -c '^ARGS' "$tmp/calls")" -eq 2
check "a two-ref push: every scan gets the remote refs in input order, then the local ones" test "$(grep -c -- ' --ref=refs/heads/feat/x --ref=refs/heads/feat/two --ref=refs/heads/feat/x --ref=refs/heads/feat/two$' "$tmp/calls")" -eq 2
ranges=$(grep '^ARGS' "$tmp/calls" | grep -o -- '--range=[^ ]*')
check "a two-ref push: the first scan is the first update's range" test "$(sed -n 1p <<<"$ranges")" = "--range=$oldx..$newx"
check "a two-ref push: the second scan is the second update's range" test "$(sed -n 2p <<<"$ranges")" = "--range=0000000000000000000000000000000000000000..$newtwo"
# the scan runs before a refusal can print a name: a hit refuses as ref:<index> with nothing else.
fake 1
checkf "a hit refuses a push to main before the policy message" git -C "$w" push -q origin feat/x:refs/heads/main
check "the refusal names the update by index, not by name" bash -c "git -C '$w' push -q origin feat/x:refs/heads/main 2>&1 | grep -q 'ref:0' && ! git -C '$w' push -q origin feat/x:refs/heads/main 2>&1 | grep -q 'never push to main'"

# a deletion is scanned over the empty range <rsha>..<rsha> (so the ref name is still checked), then refused by policy.
fake 0; : >"$tmp/calls"
rsha=$(git -C "$tmp/remote.git" rev-parse refs/heads/feat/two)
del=":refs/heads/feat/two"
checkf "a deletion with a clean scan: still refused by the policy" git -C "$w" push -q origin "$del"
check "a deletion is scanned over --range=<rsha>..<rsha>" grep -q -- "^ARGS vault scan --default-paths --range=$rsha\.\.$rsha " "$tmp/calls"

# every policy refusal names the update by index, never by ref name (#128), whatever the refusal is.
fake 0
name="zq-ref-name-mark"
git -C "$w" checkout -q -b "feat/$name"; more
git -C "$w" push -q origin "feat/$name" 2>/dev/null   # the remote now has the branch
git -C "$w" reset -q --hard HEAD~1; more   # the local branch no longer descends from the remote one
checkf "a force push is refused" git -C "$w" push -q --force origin "feat/$name"
check "a force push refusal says ref:0 and never the name" bash -c "! git -C '$w' push -q --force origin 'feat/$name' 2>&1 | grep -q '$name'"
check "a force push refusal names the update by index" bash -c "git -C '$w' push -q --force origin 'feat/$name' 2>&1 | grep -q 'ref:0'"
check "a push to main is refused by index, not by name of the local ref" bash -c "out=\$(git -C '$w' push -q origin 'feat/$name:refs/heads/main' 2>&1); grep -q 'ref:0' <<<\"\$out\" && ! grep -q '$name' <<<\"\$out\""
check "a deletion is refused by index, not by name" bash -c "out=\$(git -C '$w' push -q origin ':refs/heads/feat/$name' 2>&1); grep -q 'ref:0' <<<\"\$out\" && ! grep -q '$name' <<<\"\$out\""

# a workflow-change refusal on a value-like branch name names the update by index and never prints the name or the path.
fake 0
wfname="zq-wf-branch-mark"
git -C "$w" checkout -q -b "feat/$wfname"
mkdir -p "$w/.github/workflows"; echo "name: zq-wf-file-mark" >"$w/.github/workflows/zq-wf-file-mark.yml"
git -C "$w" add .github; tree=$(git -C "$w" write-tree); c=$(git -C "$w" commit-tree "$tree" -p HEAD -m wf); git -C "$w" update-ref HEAD "$c"
checkf "a workflow change is refused" git -C "$w" push -q origin "feat/$wfname"
check "the workflow refusal is the workflow one and says ref:0" bash -c "git -C '$w' push -q origin 'feat/$wfname' 2>&1 | grep -q 'workflows.*ref:0'"
check "the workflow refusal prints neither the branch name nor the file name" bash -c "! git -C '$w' push -q origin 'feat/$wfname' 2>&1 | grep -q 'zq-wf-'"

exit $fail
