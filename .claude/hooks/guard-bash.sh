#!/usr/bin/env bash
# PreToolUse guard for Bash: blocks commands that bypass the workflow.
# A safety net against mistakes, not a security boundary. Exit 2 = block (stderr is shown to Claude).
#
# How it works: heredoc bodies that feed a non-interpreter (file contents, PR bodies) are dropped, then
# the command is tokenised quote-aware, split into simple commands at ; & | ( ) newline, and each `git`
# / `gh` invocation is checked (git global options such as -C and -c are skipped). Quoted arguments of
# shells and wrappers (bash -c '...', eval, xargs, sudo ...) and $(...) substitutions are scanned too.
#
# Enforced: no force push (--force, -f, +refspec; --force-with-lease is fine), no --mirror/--all/--delete,
# no push to main/master (also when on main with a bare `git push`), no hook bypass (--no-verify, commit -n,
# core.hooksPath override), gh pr merge only with --match-head-commit and never --admin, no repo/issue
# deletion, no gh api merge/DELETE-repos/branch-protection calls.
#
# Known limits (accepted): a forbidden command written as plain words inside an unquoted argument, e.g.
# `echo git push --force`, or a forbidden string inside a separator-containing commit message, can be a
# false positive. Indirection (variables, aliases, scripts) is not followed. Fails closed: if jq is
# missing or the input is unreadable, the command is blocked.
set -Eeuo pipefail
trap 'echo "Blocked by .claude/hooks/guard-bash.sh: internal error (failing closed)" >&2; exit 2' ERR

if ! command -v jq >/dev/null 2>&1; then
  echo "Blocked by .claude/hooks/guard-bash.sh: jq is required to inspect commands (failing closed)" >&2
  exit 2
fi
cmd=$(jq -r '.tool_input.command // ""') || { echo "Blocked by .claude/hooks/guard-bash.sh: unreadable hook input" >&2; exit 2; }

block() { echo "Blocked by .claude/hooks/guard-bash.sh: $1" >&2; exit 2; }

# Drop heredoc bodies unless the line opening them starts a shell/interpreter (then the body is code).
# A here-string (<<<) and arithmetic shifts ($((1<<X))) are not heredocs.
strip_heredocs() {
  awk '
    BEGIN { interp = "(^|[ \t|;&(`\"/\047])(bash|sh|zsh|dash|ksh|eval|python[0-9.]*|perl|ruby|node|php)([ \t;&|)`\"\047]|$)" }
    in_doc {
      line = $0
      if (dash[cur]) sub(/^\t+/, "", line)
      if (line == term[cur]) { cur++; if (cur > n) in_doc = 0; next }
      if (keep_body) print $0
      next
    }
    {
      print
      t = $0
      gsub(/\$\(\([^)]*\)\)/, "", t)
      gsub(/<<</, "", t)
      n = 0
      while (match(t, /<<-?[ \t]*[\\"\047]?[A-Za-z_][A-Za-z0-9_]*["\047]?/)) {
        op = substr(t, RSTART, RLENGTH)
        t = substr(t, RSTART + RLENGTH)
        d = (op ~ /^<<-/)
        gsub(/^<<-?[ \t]*/, "", op); gsub(/[\\"\047]/, "", op)
        n++; term[n] = op; dash[n] = d
      }
      if (n > 0) { in_doc = 1; cur = 1; keep_body = ($0 ~ interp) }
    }' <<<"$1"
}

# Quote-aware tokeniser. Emits one line per token ("t"+text, or "q"+text if any part was quoted) and an
# "s" line at every simple-command separator (; & | ( ) newline backtick). Unquoted # starts a comment.
tokenize() {
  CMD=$1 awk '
    function flush() { if (intok) { print (quoted ? "q" : "t") tok }; tok = ""; intok = 0; quoted = 0 }
    BEGIN {
      s = ENVIRON["CMD"]; len = length(s); q = ""; tok = ""; intok = 0; quoted = 0
      for (i = 1; i <= len; i++) {
        c = substr(s, i, 1)
        if (q == "\047") { if (c == "\047") q = ""; else tok = tok (c == "\n" ? " " : c); continue }
        if (q == "\"") {
          if (c == "\"") q = ""
          else if (c == "\\" && i < len && index("\"\\$`", substr(s, i + 1, 1))) { i++; tok = tok substr(s, i, 1) }
          else tok = tok (c == "\n" ? " " : c)
          continue
        }
        if (c == "\047" || c == "\"") { q = c; intok = 1; quoted = 1; continue }
        if (c == "\\") { if (i < len) { i++; if (substr(s, i, 1) != "\n") { tok = tok substr(s, i, 1); intok = 1 } } continue }
        if (c == "#" && !intok) { while (i < len && substr(s, i + 1, 1) != "\n") i++; continue }
        if (c == " " || c == "\t") { flush(); continue }
        if (c == ";" || c == "&" || c == "|" || c == "(" || c == ")" || c == "\n" || c == "`") { flush(); print "s"; continue }
        tok = tok c; intok = 1
      }
      flush()
    }'
}

is_main_ref() {  # [+]src:dst | name | refs/heads/name -> true if the destination is main/master
  local r=${1#+}
  r=${r##*:}; r=${r#refs/heads/}
  [[ "$r" == main || "$r" == master ]]
}

current_branch() {  # current_branch DIR
  local d=${1:-.}
  git -C "$d" branch --show-current 2>/dev/null || true
}

check_commit_flags() {  # for `git commit`: -n / --no-verify; message/value flags consume the next token
  local skip=0 a
  for a in "$@"; do
    if ((skip)); then skip=0; continue; fi
    case "$a" in
      --no-v*) block "--no-verify skips the quality gate" ;;
      --message|--file|--author|--date|--reuse-message|--reedit-message|--template|--fixup|--squash|--cleanup|--trailer) skip=1 ;;
      --*) ;;
      -[a-zA-Z]*)
        [[ "$a" =~ ^-[a-zA-Z]+$ ]] || continue
        [[ "$a" == *n* ]] && block "commit -n (--no-verify) skips the quality gate" || true
        [[ "$a" =~ [mFCct]$ ]] && skip=1 || true ;;
    esac
  done
  return 0
}

check_push() {  # check_push DIR args...
  local dir=$1; shift
  local -a pos=()
  local skip=0 a
  for a in "$@"; do
    if ((skip)); then skip=0; continue; fi
    case "$a" in
      --force|--for|--forc) block "force push is not allowed (use --force-with-lease on your own feature branch)" ;;
      --force-with-lease*|--force-if-includes) ;;
      --mirror) block "git push --mirror is not allowed" ;;
      --all) block "git push --all would include main; push the branch explicitly" ;;
      --delete) block "deleting remote branches requires the user" ;;
      --repo|--receive-pack|--exec|--push-option) skip=1 ;;
      --*) ;;
      -o) skip=1 ;;
      -[a-zA-Z]*)
        if [[ "$a" =~ ^-[a-zA-Z]+$ ]]; then
          [[ "$a" == *f* ]] && block "force push is not allowed (use --force-with-lease on your own feature branch)" || true
          [[ "$a" == *d* ]] && block "deleting remote branches requires the user" || true
        fi ;;
      +*) block "force push (+refspec) is not allowed" ;;
      *) pos+=("$a") ;;
    esac
  done
  local i cur=""
  for ((i = 1; i < ${#pos[@]}; i++)); do
    if [[ "${pos[i]}" == HEAD || "${pos[i]#+}" == HEAD ]]; then
      cur=$(current_branch "$dir")
      [[ "$cur" == main || "$cur" == master ]] && block "HEAD is main; create a feature branch first" || true
    fi
    is_main_ref "${pos[i]}" && block "never push to main; open a PR"
  done
  if ((${#pos[@]} < 2)); then  # bare push: pushes the current branch
    cur=$(current_branch "$dir")
    [[ "$cur" == main || "$cur" == master ]] && block "current branch is $cur; create a feature branch first" || true
  fi
  return 0
}

check_git() {  # check_git INDEX ; reads seg_t, cwd
  local j=$(($1 + 1)) n=${#seg_t[@]} dir="" opt val
  while ((j < n)); do
    opt=${seg_t[j]}
    [[ "${opt,,}" == *core.hookspath* ]] && block "overriding core.hooksPath bypasses the git hooks" || true
    case "$opt" in
      -C) dir=${seg_t[j + 1]:-}; j=$((j + 2)) ;;
      -c|--config-env)
        val=${seg_t[j + 1]:-}
        [[ "${val,,}" == *core.hookspath* ]] && block "overriding core.hooksPath bypasses the git hooks" || true
        j=$((j + 2)) ;;
      --git-dir|--work-tree|--namespace|--exec-path|--super-prefix) j=$((j + 2)) ;;
      --*=*|--no-pager|--paginate|--bare|--no-replace-objects|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs|--no-optional-locks|--no-advice|-p|-P|-c?*) j=$((j + 1)) ;;
      *) break ;;
    esac
  done
  ((j < n)) || return 0
  local sub=${seg_t[j]}
  local -a args=("${seg_t[@]:j+1}")
  local d=${dir:-${cwd:-.}}
  [[ -n "$dir" && "$dir" != /* && -n "${cwd:-}" ]] && d=$cwd/$dir || true
  case "$sub" in
    commit|push|merge|rebase|pull|am|cherry-pick|revert)
      if [[ "$sub" != commit ]]; then
        local a
        for a in "${args[@]}"; do
          if [[ "$a" == --no-v* ]]; then block "--no-verify skips the quality gate"; fi
        done
      fi ;;&
    commit) check_commit_flags "${args[@]}" ;;
    push) check_push "$d" "${args[@]}" ;;
  esac
}

check_gh() {  # check_gh INDEX ; reads seg_t
  local n=${#seg_t[@]} i a1="" a2="" a3="" a
  local -a args=("${seg_t[@]:$1+1}")
  for a in "${args[@]}"; do
    [[ "$a" == -* ]] && continue || true
    if [[ -z "$a1" ]]; then a1=$a; elif [[ -z "$a2" ]]; then a2=$a; elif [[ -z "$a3" ]]; then a3=$a; fi
  done
  case "$a1 $a2" in
    "pr merge")
      local have=0
      for a in "${args[@]}"; do
        [[ "$a" == --admin ]] && block "--admin bypasses required checks" || true
        [[ "$a" == --match-head-commit || "$a" == --match-head-commit=* || "$a" == --disable-auto ]] && have=1 || true
      done
      ((have)) || block "gh pr merge needs --match-head-commit \$(scripts/verify check PR) so only the verified SHA merges" ;;
    "repo delete"|"issue delete") block "deleting repos/issues requires the user" ;;
    "api "*)
      local method="" ep="" prev=""
      for a in "${args[@]:1}"; do
        case "$a" in
          *mergePullRequest*|*enablePullRequestAutoMerge*) block "merging through the API bypasses the verification gate" ;;
        esac
        case "$prev" in
          -X|--method) method=$a; prev=""; continue ;;
          -f|-F|-H|-q|-t|--field|--raw-field|--header|--jq|--template|--input|--hostname|--cache|--preview|-p) prev=""; continue ;;
        esac
        case "$a" in
          -X?*) method=${a#-X}; continue ;;
          --method=*) method=${a#--method=}; continue ;;
          -*) prev=$a; continue ;;
        esac
        if [[ -z "$ep" ]]; then ep=$a; fi
      done
      method=${method^^}; ep=${ep#/}
      case "$ep" in
        */merge|*/merge/*|*/merges) block "merging through the API bypasses the verification gate" ;;
      esac
      [[ "$method" == DELETE && "$ep" == repos/* ]] && block "DELETE on repos requires the user" || true
      [[ "$ep" == */branches/*/protection* && "$method" != GET && -n "$method" ]] && block "changing branch protection requires the user" || true
      [[ "$ep" == */rulesets* && "$method" != GET && -n "$method" ]] && block "changing rulesets requires the user" || true ;;
  esac
  return 0
}

WRAPPERS=" bash sh zsh dash ksh eval xargs sudo env timeout nohup time exec watch ssh command builtin setsid nice python python3 perl ruby node "

scan() {  # scan TEXT DEPTH
  local text=$1 depth=$2 line kind
  local -a seg_t=() seg_q=()
  local code
  code=$(strip_heredocs "$text")
  while IFS= read -r line || [[ -n "$line" ]]; do
    kind=${line:0:1}
    if [[ "$kind" == s ]]; then check_segment "$depth"; seg_t=(); seg_q=(); else seg_t+=("${line:1}"); seg_q+=("$kind"); fi
  done < <(tokenize "$code")
  check_segment "$depth"
}

check_segment() {
  local depth=$1 n=${#seg_t[@]} i t wrapped=0
  ((n > 0)) || return 0
  if [[ "${seg_t[0]}" == cd && n -ge 2 ]]; then cwd=${seg_t[1]}; fi
  for ((i = 0; i < n; i++)); do
    t=${seg_t[i]}
    if [[ "${seg_q[i]}" == q && "$depth" -lt 4 ]]; then
      # shellcheck disable=SC2016  # matching the literal text $(
      if ((wrapped)) || [[ "$t" == *'$('* || "$t" == *'`'* ]]; then scan "$t" $((depth + 1)); fi
    fi
    case "$t" in
      git|*/bin/git) check_git "$i" ;;
      gh|*/bin/gh) check_gh "$i" ;;
    esac
    [[ "$WRAPPERS" == *" ${t##*/} "* ]] && wrapped=1 || true
  done
  return 0
}

cwd=""
scan "$cmd" 0
exit 0

