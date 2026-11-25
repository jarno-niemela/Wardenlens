# shellcheck shell=bash
# Shared by scripts/gate and scripts/agents (ADR 0006 section 9). Sourced, never run.
#
# Where the vault is: WARDENLENS_VAULT (a path) or the fixed default. The git hooks do NOT use this file:
# they ignore WARDENLENS_VAULT* (see scripts/hooks-staged/).

# vault_db: the path of the vault file.
vault_db() { printf '%s' "${WARDENLENS_VAULT:-${HOME:?HOME must be set}/.local/share/wardenlens/dev-vault.db}"; }

# vault_check: 0 = a vault exists (scan), 10 = no vault (skip; message printed), 1 = no vault but
# WARDENLENS_REQUIRE_VAULT=1 (fail; message printed). GITHUB_ACTIONS is deliberately not consulted: with a
# vault present a scan is never skipped. Public CI skips only because it has no vault.
vault_check() {
  local db
  db=$(vault_db)
  if [[ -e "$db" || -L "$db" ]]; then return 0; fi
  if [[ "${WARDENLENS_REQUIRE_VAULT:-}" == 1 ]]; then
    echo "vault scan: FAILED (no vault at $db and WARDENLENS_REQUIRE_VAULT=1)" >&2
    return 1
  fi
  echo "vault scan: SKIPPED (no vault at $db)"
  return 10
}

# vault_scan_tree SCANNER...: run `SCANNER... vault scan -- FILES` over the tracked tree
# (`git ls-files --cached`) and the untracked, not-ignored files. Run it at the repository top.
#   - a tracked file over the size limit is passed on, and the scanner fails on it (exit 2);
#   - an untracked file over the limit only warns (it is not scanned);
#   - a tracked symlink is scanned through its target text (the index's blob, copied to a
#     temporary file named tracked-entry-N, N the entry's ordinal in `git ls-files --cached`); an untracked symlink is
#     counted, not scanned;
#   - files deleted from the work tree are not scanned (counted, never named);
#   - binary files get the scanner's own notice;
#   - a file listing that git cannot produce fails the step (never "nothing to scan").
# Returns 0 when the scan passed or was skipped, 1 otherwise. Names are never printed: a name can
# hold a value.
vault_scan_tree() {
  local rc=0
  vault_check || rc=$?
  case $rc in 0) ;; 10) return 0 ;; *) return 1 ;; esac
  local work
  work=$(mktemp -d) || { echo "vault scan: FAILED (no temporary directory)" >&2; return 1; }
  _vault_scan_tree_in "$work" "$@" || rc=$?
  rm -rf -- "$work"
  return "$rc"
}

# _vault_scan_tree_in WORKDIR SCANNER...: the body of vault_scan_tree; WORKDIR is a scratch directory.
_vault_scan_tree_in() {
  local work=$1 limit=8388608 f size skipped=0 big=0 links=0 ord=0
  shift
  local files=()
  # The listings go to files, not process substitutions: the exit status of a failed `git ls-files`
  # inside `< <(...)` is lost, and a failed listing must never read as an empty tree.
  git ls-files -z --cached >"$work/tracked" || { echo "vault scan: FAILED (cannot list the tracked files)" >&2; return 1; }
  git ls-files -z --others --exclude-standard >"$work/untracked" || { echo "vault scan: FAILED (cannot list the untracked files)" >&2; return 1; }
  while IFS= read -r -d '' f; do
    ord=$((ord + 1))
    if [[ -L "$f" ]]; then
      # The scanner names the copy it reads: name it by the entry's ordinal in `git ls-files --cached` (1-based), never by
      # the symlink's own name, which can hold a value.
      git cat-file blob ":0:$f" >"$work/tracked-entry-$ord" || { echo "vault scan: FAILED (cannot read a tracked symlink)" >&2; return 1; }
      files+=("$work/tracked-entry-$ord")
      continue
    fi
    if [[ -d "$f" ]]; then skipped=$((skipped + 1)); continue; fi
    if [[ ! -e "$f" ]]; then skipped=$((skipped + 1)); continue; fi
    files+=("$f")
  done <"$work/tracked"
  while IFS= read -r -d '' f; do
    if [[ -L "$f" ]]; then links=$((links + 1)); continue; fi
    size=$(stat -c %s -- "$f") || { skipped=$((skipped + 1)); continue; }
    if [[ "$size" -gt "$limit" ]]; then big=$((big + 1)); continue; fi
    files+=("$f")
  done <"$work/untracked"
  [[ $big -eq 0 ]] || echo "vault scan: warning: $big untracked file(s) over the 8 MiB limit were not scanned" >&2
  [[ $((links + skipped)) -eq 0 ]] || echo "vault scan: notice: $links untracked symlink(s) and $skipped missing or directory entries not scanned" >&2
  if [[ ${#files[@]} -eq 0 ]]; then echo "vault scan: nothing to scan"; return 0; fi
  if printf '%s\0' "${files[@]}" | xargs -0 -r "$@" vault scan --; then
    echo "vault scan: PASS (${#files[@]} files)"
  else
    echo "vault scan: FAILED (a vault value was found, or the scan could not run; see above)" >&2
    return 1
  fi
}
