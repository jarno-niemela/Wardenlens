# Staged git hooks (for the owner to install)

`.githooks/**` is a locked path: agents cannot write it. These two files are the intended new content of
`.githooks/pre-commit` and `.githooks/pre-push` for ADR 0006 section 9 (ticket #117). Nothing here is active until the
owner copies them in.

## What they add

- `pre-commit` runs `wardenlens vault scan --default-paths --staged`: the staged blobs (read from the index, not the working
  tree, binary blobs included) and their paths.
- `pre-push` runs, for every ref update it receives,
  `wardenlens vault scan --default-paths --range=<remote_sha>..<local_sha> --remote=<remote name> --ref=<ref> ...`
  (an all-zero remote sha is a new branch). That covers the blobs that are new to the remote, every path of every new
  commit (`git diff-tree -r --root -m`, so a renamed unchanged file and a second path of one blob are found), the raw
  commit and tag objects (every header, `mergetag` included, and the message) and the remote ref names (every ref of the push goes to each scan, in input order; a name with a hit is reported as
  `ref:<index>` and the hook's refusal never prints a ref name). "New to the
  remote" is computed against `--remotes=<destination>` only.
- The scanner is the **fixed installed binary** `$HOME/.cargo/bin/wardenlens`. There is no `WARDENLENS_BIN` override and
  a binary built from the working tree is never used (a hook that runs the code it checks can be edited out of the way
  by the change it checks).
- The vault and key are the **fixed default paths**. The hooks unset `WARDENLENS_VAULT`, `WARDENLENS_VAULT_KEY_FILE`,
  `WARDENLENS_VAULT_KEY`, `XDG_DATA_HOME` and `XDG_CONFIG_HOME` for the scanner and pass `--default-paths`, so a variable
  set for one `git commit` or `git push` cannot point the hook at an empty vault.
- No vault file: `vault scan: SKIPPED (no vault at <path>)` (once per push), and the commit or push goes on. With
  `WARDENLENS_REQUIRE_VAULT=1` in the environment it fails instead (put it in the shell profile of the development
  machine). A vault but no installed scanner, a hit (exit 1) or a scan that could not run (exit 2) always refuses.
- `GITHUB_ACTIONS` is never consulted: with a vault present a scan is never skipped.

## `pre-push`: the combined form

`scripts/hooks-staged/pre-push` is the **complete** new hook: the existing `.githooks/pre-push` with lines added and none
removed. Every existing refusal (main, tags, deletions, unknown remote state, force pushes, workflow changes) is
untouched and runs first. The vault scan is the last step for each ref update, so a refused push never reaches it. The
additions are:

1. a comment block describing the scan (after the exceptions list);
2. after `refuse()`: the variables `remote` (the hook's `$1`), `vault_db`, `vault_bin`, `vault_noted`, and the function
   `vault_scan_push LSHA RSHA RREF`;
3. one line at the end of the `while read` loop body, after the workflow check: `vault_scan_push "$lsha" "$rsha" "$rref"`.

Show the difference with `diff -u .githooks/pre-push scripts/hooks-staged/pre-push` (it has no `-` lines); the tests
check that (`scripts/tests/hooks-staged.test.sh`) and also run every existing `pre-push.test.sh` case against the staged
file.

## `pre-commit`: the combined form

The vault block comes first (it is cheap and decisive); the existing `cargo fmt` and `cargo clippy` lines follow unchanged.

## Install (owner)

```bash
# 1. The scanner, at the fixed path the hooks use (rebuild it after changing the scanner):
cargo install --locked --path crates/wardenlens-cli          # installs $HOME/.cargo/bin/wardenlens

# 2. The hooks, from a checkout that contains this directory (the PR branch or main after the merge):
cp scripts/hooks-staged/pre-commit .githooks/pre-commit
cp scripts/hooks-staged/pre-push   .githooks/pre-push
chmod +x .githooks/pre-commit .githooks/pre-push
git config core.hooksPath .githooks                          # as before

# 3. Optional but recommended, in the shell profile of the development machine:
export WARDENLENS_REQUIRE_VAULT=1

# 4. Check: no output from the diff means the staged copy and the installed hook agree.
diff -u .githooks/pre-push scripts/hooks-staged/pre-push
scripts/gate
```

After step 2 these staged copies can be deleted, or kept: `scripts/tests/hooks-staged.test.sh` keeps working either
way (a staged copy that is behind the installed hook fails its "only adds lines" check, which is the signal to refresh
it).
