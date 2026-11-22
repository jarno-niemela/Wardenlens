#!/usr/bin/env bash
# PreToolUse guard for Bash: blocks commands that bypass the workflow.
# A safety net against mistakes, not a security boundary. Exit 2 = block (stderr is shown to Claude).
#
# How it works: heredoc bodies that feed a non-interpreter (file contents, PR bodies) are dropped, then
# the command is tokenised quote-aware, split into simple commands at ; & | ( ) newline, and each `git`
# / `gh` invocation is checked (git global options such as -C, -c and --git-dir are parsed).
# Redirections (N>, {name}>, >>, >|, &>, <>, >&, <<<; glued or not) are split off and removed from the
# segment before analysis; their targets are kept for the tamper check. Quoted arguments of shells and
# wrappers (bash -c '...', eval, xargs, sudo ...), $(...) substitutions and here-strings fed to a shell
# are scanned too. Heredoc detection ignores << inside quotes, comments and arithmetic ((...)).
#
# Enforced:
#  - git push: no force (--force, -f, +refspec, also unambiguous abbreviations; --force-with-lease is
#    fine except aimed at a tag), no --mirror/--all/--delete (also abbreviated), no push to main/master
#    (HEAD and @ resolved through the current branch; heads/main; glob refspecs are refused), a bare push
#    on main is refused, and a bare push whose directory/branch cannot be resolved is refused (fail
#    closed). An empty-source refspec (`:dst` deletion, `:` matching push) is refused. A push is refused
#    when <toplevel>/.githooks/pre-push is missing or not executable (known directory only).
#  - no hook bypass: --no-verify, commit -n, core.hooksPath (-c, config, anything but .githooks),
#    GIT_CONFIG_* assignments next to git, config keys remote.*.mirror, push.default, remote.*.push,
#    alias.*, core.hooksPath, core.editor, sequence.editor, include.path, includeIf.* (in -c, git config,
#    --config-env; also removing/renaming the core section), `git config -e/--edit`, GIT_EDITOR / EDITOR /
#    VISUAL / GIT_SEQUENCE_EDITOR assignments in front of git, and unknown git global options in front of
#    push/commit/merge/rebase.
#  - any assignment or export of WARDENLENS_ALLOW_REWRITE or WARDENLENS_ALLOW_WORKFLOWS (the human-only
#    switches of .githooks/pre-push).
#  - directory tracking fails closed: only a cd/pushd that is the very first command of the whole input
#    is followed. Any other cd/pushd/popd (later, in a subshell, pipeline, background job, backticks,
#    nested shell scan, if/{/case body), `env -C`, and GIT_DIR/GIT_WORK_TREE assignments make the
#    working directory unknown, and a bare push with an unknown directory is refused.
#  - gh pr merge only with --match-head-commit <40-hex SHA or one $variable>, never --admin; no
#    repo/issue deletion; gh workflow run only on main; gh api: no merges, no DELETE on repos, no
#    branch-protection/ruleset changes, no writes to */statuses/* (forging verification; scripts/verify
#    is the only writer and its internal calls are not inspected), no writes to */actions/* (workflow
#    dispatches, runs) or */environments*, no write to a percent-encoded endpoint, a contents write needs
#    an explicit `branch` field (exact spelling) that is not main/master/@file (and never --input), and
#    no GraphQL mutation (reading through graphql is fine).
#  - tamper protection: a redirect (any form), tee, cp, mv, install, ln, rm, unlink, chmod, chown, truncate,
#    dd, touch, rsync, sed -i, perl -i, find -delete/-exec, or git checkout/restore aimed at anything
#    under .git/, .githooks/, .github/workflows/, .claude/hooks/, .claude/settings(.local).json, ~/.bashrc,
#    ~/.profile, ~/.bash_profile, ~/.bash_login or ~/.config/systemd/user/ is refused. rm, mv, chmod,
#    chown and find -delete/-exec are also refused when a target is an ANCESTOR of such a path (.claude,
#    .github, the repository root and its parents, ~/.config, ~/.config/systemd, ~, /); cp, install, ln
#    and rsync when the DESTINATION is such a directory. find -exec of a read-only command (grep, cat,
#    ...) is not a writer; `find . -name PATTERN -delete` is allowed at the repository root when the
#    pattern matches no protected name. Paths are resolved against the tracked directory (// and /./ and
#    .. normalised); when the directory is unknown, a relative target named config, pre-push,
#    settings.json, rustfmt.sh, .claude, .github ... is refused. git apply and patch are refused (the
#    patch cannot be inspected), as are extensions.worktreeConfig and git config --worktree writes.
#    Reading with a writer word (cp .githooks/x /tmp/y) is a known false positive, as is
#    `find -path .git ...` with a writer. rsync --exclude values are patterns and ignored.
#  - piping into a shell (`| bash`, `| sh -s`, `source /dev/stdin`) hides commands: blocked.
#
# The authoritative push control is .githooks/pre-push; this guard is the first, best-effort line.
# Accepted limitations (see docs/adr/0001): code inside interpreter string literals (python3 -c,
# perl -e, node -e, awk system(), ...), $'...' quoting, $(echo ...) / variable indirection, aliases and
# scripts, pipes into shells through wrappers with arguments (timeout, sudo -u, nice, busybox,
# tee >(...)), xargs ... git, git under other paths (/usr/lib/git-core/git*), brace expansion, heredoc
# logical-line edge cases (<<EOF \, quotes spanning lines), ${x//<<X/}, and GIT_CONFIG_* exported in
# an earlier segment, `git checkout <rev> -- .` and `git reset --hard <old>`. A forbidden command
# written as plain words inside an unquoted argument, e.g. `echo git push --force`, can be a false
# positive. Fails closed: if jq is missing or the input is unreadable, the command is blocked.
set -Eeuo pipefail
export LC_ALL=C   # ASCII-only [0-9], [a-z] in every pattern below
trap 'echo "Blocked by .claude/hooks/guard-bash.sh: internal error (failing closed)" >&2; exit 2' ERR

if ! command -v jq >/dev/null 2>&1; then
  echo "Blocked by .claude/hooks/guard-bash.sh: jq is required to inspect commands (failing closed)" >&2
  exit 2
fi
input=$(cat) || { echo "Blocked by .claude/hooks/guard-bash.sh: unreadable hook input" >&2; exit 2; }
cmd=$(jq -r '.tool_input.command // ""' <<<"$input") || { echo "Blocked by .claude/hooks/guard-bash.sh: unreadable hook input" >&2; exit 2; }
cwd=$(jq -r '.cwd // ""' <<<"$input") || { echo "Blocked by .claude/hooks/guard-bash.sh: unreadable hook input" >&2; exit 2; }
cwd_unknown=0
cmd_seen=0   # set once the first command of the input has been seen (only that cd is tracked)

block() { echo "Blocked by .claude/hooks/guard-bash.sh: $1" >&2; exit 2; }

# Drop heredoc bodies unless the line opening them starts a shell/interpreter (then the body is code).
# Scans each line with quote, comment and arithmetic awareness so that << inside "...", '...', after an
# unquoted #, or in $((...)) / ((...)) is not a heredoc, and <<< is a here-string. A delimiter that mixes
# quoted and unquoted parts (<<EOF"X") is ambiguous: exit status 3.
strip_heredocs() {
  awk '
    BEGIN {
      interp = "(^|[ \t|;&(`\"/\047])(bash|sh|zsh|dash|ksh|eval|python[0-9.]*|perl|ruby|node|php)([ \t;&|)`<\"\047]|$)"
      q = ""; arith = 0; bad = 0; cs = 0
    }
    in_doc {
      line = $0
      if (dash[cur]) sub(/^\t+/, "", line)
      if (line == term[cur]) { cur++; if (cur > n) in_doc = 0; next }
      if (keep_body) print $0
      next
    }
    {
      print
      line = $0; len = length(line); n = 0; prev = " "
      for (i = 1; i <= len; i++) {
        c = substr(line, i, 1)
        if (q == "\047") { if (c == "\047") q = ""; prev = c; continue }
        if (q == "\"") {
          if (c == "\\") i++
          else if (c == "\"") q = ""
          else if (c == "$" && substr(line, i + 1, 1) == "(" && substr(line, i + 2, 1) != "(") {
            cs++; save[cs] = "\""; pd[cs] = 1; q = ""; i++; prev = "("; continue   # $( inside "...": code again
          }
          prev = c; continue
        }
        if (arith > 0) {
          if (c == "(") arith++
          else if (c == ")") arith--
          prev = c; continue
        }
        if (c == "\\") { i++; prev = "x"; continue }
        if (cs > 0 && c == "(" && substr(line, i + 1, 1) != "(") pd[cs]++
        else if (cs > 0 && c == ")") { pd[cs]--; if (pd[cs] == 0) { q = save[cs]; cs--; prev = ")"; continue } }
        if (c == "\047" || c == "\"") { q = c; prev = c; continue }
        if (c == "#" && (prev == " " || prev == "\t" || prev == ";" || prev == "&" || prev == "|" || prev == "(")) break
        if (c == "(" && substr(line, i + 1, 1) == "(") { arith = 2; i++; prev = c; continue }
        if (c == "<" && substr(line, i + 1, 1) == "<") {
          if (substr(line, i + 2, 1) == "<") { i += 2; prev = "<"; continue }
          j = i + 2; dashf = 0
          if (substr(line, j, 1) == "-") { dashf = 1; j++ }
          while (j <= len && (substr(line, j, 1) == " " || substr(line, j, 1) == "\t")) j++
          tt = ""; quoted = 0; plain = 0
          while (j <= len) {
            d = substr(line, j, 1)
            if (d == " " || d == "\t" || d == ";" || d == "&" || d == "|" || d == "(" || d == ")" || d == "<" || d == ">") break
            if (d == "\047" || d == "\"") {
              k = index(substr(line, j + 1), d)
              if (k == 0) { tt = tt substr(line, j + 1); j = len + 1; quoted = 1; break }
              tt = tt substr(line, j + 1, k - 1); j = j + k + 1; quoted = 1; continue
            }
            if (d == "\\") { tt = tt substr(line, j + 1, 1); j += 2; continue }
            tt = tt d; plain = 1; j++
          }
          if (quoted && plain) bad = 1
          if (tt != "") { n++; term[n] = tt; dash[n] = dashf }
          i = j - 1; prev = "x"; continue
        }
        prev = c
      }
      if (n > 0) { in_doc = 1; cur = 1; keep_body = ($0 ~ interp) }
    }
    END { if (bad) exit 3 }' <<<"$1"
}

# Quote-aware tokeniser. Emits one line per token ("t"+text, or "q"+text if any part was quoted) and an
# "s" line at every simple-command separator (; && || newline), "s&" for a single & (background), "s`" at
# a backtick, "o"/"c" at ( and ), "p" at a pipe (| or |&). A redirection operator (2>, {fd}>, >>, >|, &>,
# <>, >&, <<<, ...) is emitted as "r"+operator and split from its neighbours; the next token is its target.
# Unquoted # starts a comment.
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
        if (c == "|") {
          flush()
          if (substr(s, i + 1, 1) == "|") { i++; print "s|" }
          else { if (substr(s, i + 1, 1) == "&") i++; print "p" }
          continue
        }
        if (c == ">" || c == "<") {   # redirection operator: split off its word, emit "r"+[fd]operator
          if (substr(s, i + 1, 1) == "(") { tok = tok c; intok = 1; continue }   # <(...) / >(...)
          pre = ""
          if (intok && !quoted && (tok ~ /^[0-9]+$/ || tok == "&" || tok ~ /^\{[A-Za-z_][A-Za-z0-9_]*\}$/)) { pre = tok; tok = ""; intok = 0 } else flush()
          op = c; n2 = substr(s, i + 1, 1)
          if (c == ">") {
            if (n2 == ">") { op = ">>"; i++ }
            n2 = substr(s, i + 1, 1)
            if (n2 == "|" || n2 == "&") { op = op n2; i++ }
          } else if (n2 == ">") { op = "<>"; i++ }
          else if (n2 == "&") { op = "<&"; i++ }
          else if (n2 == "<") {
            op = "<<"; i++; n2 = substr(s, i + 1, 1)
            if (n2 == "<" || n2 == "-") { op = op n2; i++ }
          }
          print "r" pre op
          continue
        }
        if (c == "&") {   # &> is a redirection (handled above); otherwise a separator
          pc = (i > 1) ? substr(s, i - 1, 1) : ""
          if (substr(s, i + 1, 1) == ">") { flush(); tok = "&"; intok = 1; continue }
          flush(); print (pc == "&" || substr(s, i + 1, 1) == "&") ? "s" : "s&"; continue
        }
        if (c == "(") { flush(); print "o"; continue }
        if (c == ")") { flush(); print "c"; continue }
        if (c == "`") { flush(); print "s`"; continue }
        if (c == ";" || c == "\n") { flush(); print "s"; continue }
        tok = tok c; intok = 1
      }
      flush()
    }'
}

# --- path helpers -------------------------------------------------------------------------------

expand_home() {  # print P with a leading ~, $HOME or ${HOME} expanded; fail if anything else is dynamic
  local p=$1
  # shellcheck disable=SC2016,SC2088  # matching the literal text ~ and $HOME, not expanding them
  case "$p" in
    "~"|"~/"*) p="${HOME:-}${p#"~"}" ;;
    '$HOME'|'$HOME/'*) p="${HOME:-}${p#'$HOME'}" ;;
    '${HOME}'|'${HOME}/'*) p="${HOME:-}${p#'${HOME}'}" ;;
  esac
  [[ -n "$p" && "$p" != *'$'* && "$p" != *'`'* && "$p" != "~"* ]] || return 1
  printf '%s' "$p"
}

track_cd() {  # cd/pushd in the current segment: follow it so a later bare push is checked in the right place
  local k=1 tgt new
  while [[ "${seg_t[k]:-}" == -[PLe@] || "${seg_t[k]:-}" == -- ]]; do k=$((k + 1)); done
  tgt=${seg_t[k]:-'~'}
  if [[ "$tgt" == - ]]; then cwd_unknown=1; return 0; fi
  if ! new=$(expand_home "$tgt"); then cwd_unknown=1; return 0; fi
  if [[ "$new" == /* ]]; then cwd=$new; cwd_unknown=0; else cwd=${cwd:-.}/$new; fi
}

branch_of() {  # branch_of DIR GITDIR UNKNOWN: print the current branch, or block if it cannot be determined
  local d=$1 gd=$2 unk=$3 out gdx
  if ((unk)); then block "cannot resolve the repository directory of this git command (use a plain path in cd / -C)"; fi
  if [[ -n "$gd" ]]; then
    gdx=$(expand_home "$gd") || block "cannot resolve --git-dir '$gd'"
    out=$(git -C "$d" --git-dir="$gdx" branch --show-current 2>/dev/null) || block "cannot determine the current branch (git failed in '$d')"
  else
    out=$(git -C "$d" branch --show-current 2>/dev/null) || block "cannot determine the current branch (git failed in '$d')"
  fi
  printf '%s' "$out"
}

# --- git ----------------------------------------------------------------------------------------

is_main_ref() {  # [+]src:dst | name | refs/heads/name | heads/name -> true if the destination is main/master
  local r=${1#+}
  r=${r##*:}; r=${r#refs/}; r=${r#heads/}
  [[ "$r" == main || "$r" == master ]]
}

bad_key() {  # true for config keys that bypass hooks, hide commands or change what a push updates
  case "${1,,}" in
    remote.*.mirror|push.default|remote.*.push|alias.*|core.hookspath|core.editor|sequence.editor|include.path|includeif.*|extensions.worktreeconfig) return 0 ;;
  esac
  return 1
}

bad_cfg() {  # bad_cfg "key=value" | "-ckey=value" | "--config-env=key=ENV": true if the key is forbidden
  local s=${1,,}
  s=${s#-c}; s=${s#--config-env=}
  [[ "$s" == *core.hookspath* ]] && return 0
  bad_key "${s%%=*}"
}

plumbing_msg="git plumbing that pushes or serves pushes skips .githooks/pre-push; use git push"
is_push_plumbing() {  # is_push_plumbing NAME ARGS...: NAME without the git- prefix; true for write-capable plumbing
  local name=$1 a; shift
  case "$name" in
    send-pack|http-push|receive-pack|remote-*) return 0 ;;
    upload-pack|fetch-pack)
      for a in "$@"; do
        case "$a" in
          --stateless-rpc) return 0 ;;
          --advertise-refs|--http-backend-info-refs) [[ "$name" == upload-pack ]] && return 0 ;;
          *receive-pack*|*send-pack*|*push*) [[ "$name" == upload-pack ]] && return 0 ;;
        esac
      done ;;
  esac
  return 1
}

# --- tamper protection --------------------------------------------------------------------------

TAMPER_RE='(^|/)(\.git|\.githooks)(/|$)|(^|/)\.github/workflows(/|$)|(^|/)\.claude/(hooks(/|$)|settings(\.local)?\.json$)|(^|/)\.(bashrc|profile|bash_profile|bash_login)$|(^|/)\.config/systemd/user(/|$)'
TAMPER_MSG="writing to .git/, .githooks/, .github/workflows/, .claude/hooks, .claude/settings*.json or shell rc files is for the user (they are the push and tool controls); use the Edit/Write tools for other repository files"
NP=""
ANC=""

norm_path() {  # NP = P with //, /./, a trailing / and .. resolved lexically
  local p=$1 lead="" part
  local -a parts=() out=()
  [[ "$p" == /* ]] && lead=/
  local IFS=/
  read -ra parts <<<"$p" || true
  for part in "${parts[@]}"; do
    case "$part" in
      ""|.) ;;
      ..) if ((${#out[@]} > 0)) && [[ "${out[-1]}" != .. ]]; then unset 'out[-1]'; elif [[ -z "$lead" ]]; then out+=(..); fi ;;
      *) out+=("$part") ;;
    esac
  done
  NP="$lead${out[*]:-}"
}

tamper_hit() {  # tamper_hit PATH [BASE UNKNOWN]: true if PATH (resolved against BASE, default the tracked cwd) is protected
  local p=$1 base=${2-${cwd:-.}} unk=${3-$cwd_unknown} e
  [[ -n "$p" ]] || return 1
  if e=$(expand_home "$p"); then p=$e; fi
  norm_path "$p"; p=$NP
  if [[ "$p" != /* ]]; then
    if ((unk)); then
      case "${p##*/}" in
        config|config.worktree|pre-push|pre-commit|guard-bash.sh|rustfmt.sh|settings.json|settings.local.json|.bashrc|.profile|.bash_profile|.bash_login) return 0 ;;
      esac
    else
      norm_path "$base/$p"; p=$NP
    fi
  fi
  [[ "$p" =~ $TAMPER_RE ]]
}

tamper_anc() {  # tamper_anc PATH [BASE UNKNOWN]: true if PATH is a directory that is, or contains, a protected path
  # Sets ANC=root (the repository root, its parents or any directory holding .git/.githooks/.claude) or
  # ANC=dir (.claude, .github, ~/.config, ~/.config/systemd, ~ and its parents, /).
  local p=$1 base=${2-${cwd:-.}} unk=${3-$cwd_unknown} e h top
  ANC=""
  [[ -n "$p" ]] || return 1
  if e=$(expand_home "$p"); then p=$e; fi
  norm_path "$p"; p=$NP
  if [[ "$p" != /* ]]; then
    if ((unk)); then
      case "${p##*/}" in .claude|.github|.config) ANC=dir; return 0 ;; esac
      return 1
    fi
    norm_path "$base/$p"; p=$NP
  fi
  [[ "$p" == /* ]] || return 1
  if [[ "$p" == / ]]; then ANC=dir; return 0; fi
  case "${p##*/}" in .claude|.github) ANC=dir; return 0 ;; esac
  h=${HOME:-}
  if [[ -n "$h" ]]; then
    norm_path "$h"; h=$NP
    if [[ "$h" == "$p" || "$h" == "$p"/* || "$p" == "$h/.config" || "$p" == "$h/.config/systemd" ]]; then ANC=dir; return 0; fi
  fi
  if ((!unk)); then
    top=$(git -C "$base" rev-parse --show-toplevel 2>/dev/null) || top=""
    if [[ -n "$top" ]]; then
      norm_path "$top"; top=$NP
      if [[ "$top" == "$p" || "$top" == "$p"/* ]]; then ANC=root; return 0; fi
    fi
  fi
  if [[ -d "$p" ]] && [[ -e "$p/.git" || -e "$p/.githooks" || -e "$p/.claude" ]]; then ANC=root; return 0; fi
  return 1
}

# names a `find -name PATTERN -delete` must not be able to match (it would reach a protected path)
FIND_NAMES=(.git .githooks .github .claude hooks workflows pre-push pre-commit settings.json settings.local.json guard-bash.sh rustfmt.sh config .bashrc .profile .bash_profile .bash_login systemd user)

check_tamper() {  # redirects (rd_op/rd_tgt) and writer commands aimed at protected paths; reads seg_t
  local n=${#seg_t[@]} i k t p b nx writer=0 hit=0 cmdword="" wa=-1 isrsync=0 skipn=0 isfind=0 findw=0 hasor=0 safe=0 anc=0 last="" nm pat
  local -a pats=()
  for ((i = 0; i < ${#rd_op[@]}; i++)); do
    if [[ "${rd_op[i]}" == *'>'* ]] && tamper_hit "${rd_tgt[i]}"; then block "$TAMPER_MSG"; fi
  done
  for ((i = 0; i < n; i++)); do
    t=${seg_t[i]}; b=${t##*/}
    if ((skipn)); then skipn=0; continue; fi   # the value of an rsync --exclude: a pattern, not a target
    if [[ -z "$cmdword" && ! "$t" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      case "$b" in sudo|env|command|exec|nohup|time|nice|setsid|builtin|xargs|timeout|'{'|'!') ;; *) cmdword=$b ;; esac
    fi
    case "$b" in
      tee|unlink|truncate|dd|touch) writer=1 ;;
      rm|mv|chmod|chown) writer=1; ((wa >= 0)) || wa=$i ;;
      cp|install|ln) writer=1 ;;
      rsync) writer=1; isrsync=1 ;;
      sed|perl) for ((k = i + 1; k < n; k++)); do
                  if [[ "${seg_t[k]}" =~ ^-[a-zA-Z]*i || "${seg_t[k]}" == --in-place* ]]; then writer=1; fi
                done ;;
      find) isfind=1
            for ((k = i + 1; k < n; k++)); do
              case "${seg_t[k]}" in
                -delete|-fprint|-fprint0|-fprintf|-fls) findw=1 ;;
                -exec|-execdir|-ok|-okdir)
                  nx=${seg_t[k + 1]:-}; nx=${nx##*/}
                  case "$nx" in   # read-only commands run by find are not writers
                    grep|egrep|fgrep|rg|cat|ls|head|tail|wc|file|stat|sha256sum|sha1sum|md5sum|du|diff|cmp|echo|printf|test|basename|dirname|readlink|realpath) ;;
                    *) findw=1 ;;
                  esac ;;
                -o|-or) hasor=1 ;;
                -name|-iname) pats+=("${seg_t[k + 1]:-}") ;;
              esac
            done
            if ((findw)); then writer=1; ((wa >= 0)) || wa=$i; fi ;;
    esac
    if ((isrsync)) && [[ "$t" == --exclude* || "$t" == --include* || "$t" == --filter* ]]; then
      [[ "$t" == *=* ]] || skipn=1
      continue
    fi
    p=${t#of=}
    [[ "$p" == --*=* ]] && p=${p#*=}
    if [[ "$p" != -* ]] && tamper_hit "$p"; then hit=1; fi
  done
  if [[ "$cmdword" == patch ]]; then block "patch cannot be inspected and can rewrite protected files; use the Edit/Write tools"; fi
  if ((writer && hit)); then block "$TAMPER_MSG"; fi
  # ancestors: a write whose target is a directory containing a protected path
  if ((isfind && ${#pats[@]} > 0 && !hasor)); then
    safe=1
    for pat in "${pats[@]}"; do
      for nm in "${FIND_NAMES[@]}"; do
        # shellcheck disable=SC2053  # PATTERN is a glob on purpose
        if [[ "$nm" == $pat ]]; then safe=0; fi
      done
    done
  fi
  if ((wa >= 0)); then
    for ((k = wa + 1; k < n; k++)); do
      t=${seg_t[k]}
      case "$t" in -*|'{}'|'+'|';'|'!') continue ;; esac
      if tamper_anc "$t"; then
        if ((safe)) && [[ "$ANC" == root ]]; then continue; fi
        anc=1
      fi
    done
  fi
  case "$cmdword" in
    cp|install|ln|rsync)   # the destination is the last non-option argument
      for ((k = n - 1; k > 0; k--)); do
        if [[ "${seg_t[k]}" != -* ]]; then last=${seg_t[k]}; break; fi
      done
      if [[ -n "$last" ]] && tamper_anc "$last"; then anc=1; fi ;;
  esac
  if ((anc)); then block "$TAMPER_MSG (the target is, or contains, a protected path)"; fi
  if ((writer && !cwd_unknown)) && tamper_hit .; then block "$TAMPER_MSG"; fi
  return 0
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

check_config() {  # git config ARGS: core.hooksPath may only be set to .githooks; never unset
  local a key="" val="" have_val=0 np=0 unset_=0 skip=0 section=0 sec wt=0 rd=0 fl=0
  local -a pos=()
  for a in "$@"; do
    if ((skip)); then
      skip=0
      if ((fl)) && tamper_hit "$a"; then block "$TAMPER_MSG"; fi
      fl=0; continue
    fi
    case "$a" in
      --unset|--unset-all) unset_=1 ;;
      --remove-section|--rename-section) section=1 ;;
      --worktree) wt=1 ;;
      --get|--get-all|--get-regexp|--get-urlmatch|-l|--list) rd=1 ;;
      -f|--file) skip=1; fl=1 ;;
      --file=*) if tamper_hit "${a#--file=}"; then block "$TAMPER_MSG"; fi ;;
      --blob|--default|--type|--comment) skip=1 ;;
      --e|--ed|--edi|--edit) block "git config --edit runs an editor (core.editor) and can change any config key" ;;
      -[a-zA-Z]*) if [[ "$a" == *e* ]]; then block "git config -e runs an editor (core.editor) and can change any config key"; fi ;;
      -*) ;;
      *) pos+=("$a") ;;
    esac
  done
  if ((wt && !rd)); then block "writing the per-worktree git config can bypass hooks (extensions.worktreeConfig); use plain git config"; fi
  if [[ "${pos[0]:-}" == set || "${pos[0]:-}" == unset || "${pos[0]:-}" == remove-section || "${pos[0]:-}" == rename-section ]]; then
    [[ "${pos[0]}" == unset ]] && unset_=1 || true
    [[ "${pos[0]}" == remove-section || "${pos[0]}" == rename-section ]] && section=1 || true
    pos=("${pos[@]:1}")
  fi
  if [[ "${pos[0]:-}" == edit ]]; then block "git config edit runs an editor (core.editor) and can change any config key"; fi
  if ((section)); then  # removing/renaming a whole section drops core.hooksPath, aliases, push settings
    sec=${pos[0]:-}; case "${sec,,}" in
      core|alias|include|includeif.*|push|remote|remote.*|extensions|sequence) block "removing or renaming the '${pos[0]}' config section bypasses the git hooks" ;;
    esac
    return 0
  fi
  np=${#pos[@]}
  ((np > 0)) && key=${pos[0],,} || true
  ((np > 1)) && { val=${pos[1]}; have_val=1; } || true
  if [[ "$key" == core.hookspath ]]; then
    ((unset_)) && block "unsetting core.hooksPath bypasses the git hooks" || true
    if ((have_val)); then
      [[ "$val" == .githooks ]] || block "core.hooksPath may only be set to .githooks"
    fi
  fi
  if ((have_val || unset_)); then
    [[ "$key" != core.hookspath ]] && bad_key "$key" && block "changing $key can redirect pushes, hide commands or bypass hooks" || true
  fi
  return 0
}

check_push() {  # check_push DIR GITDIR UNKNOWN args...
  local d=$1 gd=$2 unk=$3; shift 3
  local -a pos=()
  local skip=0 end=0 a name r dst cur i lease=0 tags=0 top
  for a in "$@"; do
    if ((skip)); then skip=0; continue; fi
    [[ "$a" == +* ]] && block "force push (+refspec) is not allowed" || true
    if ((end)); then pos+=("$a"); continue; fi
    case "$a" in
      --) end=1 ;;
      --*)
        name=${a%%=*}
        case "$name" in
          --force-with-lease|--force-if-includes)
            lease=1
            [[ "$a" == *refs/tags/* ]] && block "force-with-lease aimed at a tag is not allowed (tags are immutable)" || true
            continue ;;
          --repo|--receive-pack|--exec|--push-option) [[ "$a" == *=* ]] || skip=1; continue ;;
          --tags) tags=1; continue ;;
        esac
        # git accepts any unambiguous prefix of a long option; refuse every prefix of the dangerous ones
        if ((${#name} >= 9)) && [[ "--force-with-lease" == "$name"* || "--force-if-includes" == "$name"* ]]; then lease=1; continue; fi
        if ((${#name} >= 3)); then
          [[ "--force" == "$name"* ]] && block "force push is not allowed (use --force-with-lease on your own feature branch)" || true
          [[ "--mirror" == "$name"* ]] && block "git push --mirror is not allowed" || true
          [[ "--all" == "$name"* ]] && block "git push --all would include main; push the branch explicitly" || true
          [[ "--delete" == "$name"* ]] && block "deleting remote branches requires the user" || true
          [[ "--tags" == "$name"* ]] && tags=1 || true
        fi ;;
      -o) skip=1 ;;
      -[a-zA-Z]*)
        if [[ "$a" =~ ^-[a-zA-Z]+$ ]]; then
          [[ "$a" == *f* ]] && block "force push is not allowed (use --force-with-lease on your own feature branch)" || true
          [[ "$a" == *d* ]] && block "deleting remote branches requires the user" || true
        fi ;;
      *) pos+=("$a") ;;
    esac
  done
  for ((i = 1; i < ${#pos[@]}; i++)); do
    r=${pos[i]#+}; dst=${r##*:}
    [[ "$r" == :* ]] && block "an empty-source refspec ('$r') deletes a remote ref or pushes all matching branches; requires the user" || true
    [[ "$dst" == *'*'* ]] && block "glob refspecs can push main; name the branch explicitly" || true
    if ((lease)) && [[ "$dst" == refs/tags/* || "$dst" == tags/* || "$r" == tag ]]; then block "force-with-lease aimed at a tag is not allowed (tags are immutable)"; fi
    if [[ "$r" == HEAD || "$r" == @ ]]; then
      cur=$(branch_of "$d" "$gd" "$unk") || exit 2
      [[ "$cur" == main || "$cur" == master ]] && block "HEAD is $cur; create a feature branch first" || true
    fi
    is_main_ref "${pos[i]}" && block "never push to main; open a PR"
  done
  if ((lease && tags)); then block "force-with-lease together with --tags can move tags; tags are immutable"; fi
  if ((${#pos[@]} < 2)); then  # bare push: pushes the current branch
    cur=$(branch_of "$d" "$gd" "$unk") || exit 2
    [[ "$cur" == main || "$cur" == master ]] && block "current branch is $cur; create a feature branch first" || true
  fi
  # the authoritative control is .githooks/pre-push: a push from a checkout without it is refused
  # (only when the directory is known; a missing cwd is "." and not checked)
  if ((!unk)) && [[ "$d" != . && -z "$gd" ]]; then
    top=$(git -C "$d" rev-parse --show-toplevel 2>/dev/null) || top=""
    if [[ -n "$top" && ! -x "$top/.githooks/pre-push" ]]; then
      block "$top/.githooks/pre-push is missing or not executable; the push would not be checked"
    fi
  fi
  return 0
}

check_git() {  # check_git INDEX ; reads seg_t, seg_q, cwd
  local idx=$1 j=$(($1 + 1)) n=${#seg_t[@]} opt val k tok
  local d=${cwd:-.} unk=$cwd_unknown gd=""
  for ((k = 0; k < idx; k++)); do
    if [[ "${seg_t[k]}" == GIT_DIR=* ]]; then gd=${seg_t[k]#GIT_DIR=}; fi
  done
  while ((j < n)); do
    opt=${seg_t[j]}
    if bad_cfg "$opt"; then block "overriding hooks, push or alias settings through git options is not allowed"; fi
    case "$opt" in
      -C)
        val=${seg_t[j + 1]:-}
        if tok=$(expand_home "$val"); then
          if [[ "$tok" == /* ]]; then d=$tok; else d=$d/$tok; fi
        else unk=1; fi
        j=$((j + 2)) ;;
      -c|--config-env)
        val=${seg_t[j + 1]:-}
        if bad_cfg "$val"; then block "overriding hooks, push or alias settings through git -c is not allowed"; fi
        j=$((j + 2)) ;;
      --git-dir) gd=${seg_t[j + 1]:-}; j=$((j + 2)) ;;
      --git-dir=*) gd=${opt#--git-dir=}; j=$((j + 1)) ;;
      --work-tree|--namespace|--super-prefix|--attr-source) j=$((j + 2)) ;;
      --config-env=*)
        if bad_cfg "$opt"; then block "overriding core.hooksPath / remote push / aliases through --config-env is not allowed"; fi
        j=$((j + 1)) ;;
      --work-tree=*|--namespace=*|--super-prefix=*|--attr-source=*|--exec-path=*) j=$((j + 1)) ;;
      --exec-path|--no-pager|--paginate|--bare|--no-replace-objects|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs|--no-optional-locks|--no-advice|--no-lazy-fetch|-p|-P|-c?*) j=$((j + 1)) ;;
      --*)
        for ((k = j + 1; k < n; k++)); do
          case "${seg_t[k]}" in
            send-pack|http-push|receive-pack|remote-*|upload-pack|fetch-pack) block "unknown git global option '$opt' before ${seg_t[k]}; remove it so the command can be checked" ;;
            push|commit|merge|rebase) block "unknown git global option '$opt' before ${seg_t[k]}; remove it so the command can be checked" ;;
          esac
        done
        return 0 ;;
      *) break ;;
    esac
  done
  ((j < n)) || return 0
  local sub=${seg_t[j]}
  local -a args=("${seg_t[@]:j+1}")
  if is_push_plumbing "$sub" "${args[@]}"; then block "$plumbing_msg"; fi
  case "$sub" in
    commit|push|merge|rebase|pull|am|cherry-pick|revert)
      if [[ "$sub" != commit ]]; then
        local a
        for a in "${args[@]}"; do
          if [[ "$a" == --no-v* ]]; then block "--no-verify skips the quality gate"; fi
        done
      fi ;;&
    commit) check_commit_flags "${args[@]}" ;;
    push) check_push "$d" "$gd" "$unk" "${args[@]}" ;;
    config) check_config "${args[@]}" ;;
    apply) block "git apply writes files from a patch that cannot be inspected (it can rewrite the hooks); use the Edit/Write tools" ;;
    checkout|restore)
      local a2
      if ((!unk)) && tamper_hit . "$d" 0; then block "$TAMPER_MSG"; fi
      for a2 in "${args[@]}"; do
        if tamper_hit "$a2" "$d" "$unk"; then block "git $sub of a protected path: $TAMPER_MSG"; fi
      done ;;
  esac
}

# --- gh -----------------------------------------------------------------------------------------

valid_head_val() {  # a 40-hex SHA or a single shell variable reference
  [[ "$1" =~ ^[0-9a-f]{40}$ || "$1" =~ ^\$[A-Za-z_][A-Za-z0-9_]*$ || "$1" =~ ^\$\{[A-Za-z_][A-Za-z0-9_]*\}$ ]]
}

check_gh() {  # check_gh INDEX ; reads seg_t
  local n=${#seg_t[@]} k a a1="" a2="" skip=0 idx1=-1
  for ((k = $1 + 1; k < n; k++)); do
    a=${seg_t[k]}
    if ((skip)); then skip=0; continue; fi
    case "$a" in
      -R|--repo) skip=1; continue ;;
      -*) continue ;;
    esac
    if [[ -z "$a1" ]]; then a1=$a; idx1=$k; elif [[ -z "$a2" ]]; then a2=$a; fi
  done
  case "$a1 $a2" in
    "pr merge")
      local have=0 want=0
      for ((k = idx1 + 1; k < n; k++)); do
        a=${seg_t[k]}
        [[ "$a" == --admin ]] && block "--admin bypasses required checks" || true
        if ((want)); then
          want=0
          if valid_head_val "$a"; then have=1; else block "--match-head-commit needs a 40-hex SHA or one \$variable (sha=\$(scripts/verify check PR))"; fi
          continue
        fi
        case "$a" in
          --match-head-commit) want=1 ;;
          --match-head-commit=*)
            if valid_head_val "${a#--match-head-commit=}"; then have=1; else block "--match-head-commit needs a 40-hex SHA or one \$variable (sha=\$(scripts/verify check PR))"; fi ;;
          --disable-auto) have=1 ;;
        esac
      done
      ((have)) || block "gh pr merge needs --match-head-commit \"\$sha\" with sha=\$(scripts/verify check PR) so only the verified SHA merges" ;;
    "repo delete"|"issue delete") block "deleting repos/issues requires the user" ;;
    "workflow run")
      local wk=0 wv wmsg="gh workflow run may only run on main (--ref main or no --ref): a branch can carry an edited workflow"
      for ((k = idx1 + 1; k < n; k++)); do
        a=${seg_t[k]}; wv=""
        if ((wk)); then wk=0; wv=$a
        else
          case "$a" in
            --ref|-r) wk=1; continue ;;
            --ref=*) wv=${a#--ref=} ;;
            -r?*) wv=${a#-r} ;;
            *) continue ;;
          esac
        fi
        wv=${wv#refs/}; wv=${wv#heads/}
        [[ "$wv" == main ]] || block "$wmsg"
      done
      ((!wk)) || block "$wmsg" ;;
    "api "*)
      local method="" ep="" prev="" haswrite=0 hasinput=0 all="" fld c rest ci br okbranch=0 key
      local -a fields=()
      for ((k = idx1 + 1; k < n; k++)); do
        a=${seg_t[k]}
        all+=" ${a,,}"
        case "$a" in
          *mergePullRequest*|*enablePullRequestAutoMerge*) block "merging through the API bypasses the verification gate" ;;
        esac
        if [[ -n "$prev" ]]; then
          case "$prev" in
            -X|--method) method=$a ;;
            -f|-F|--field|--raw-field) fields+=("$a") ;;
          esac
          prev=""; continue
        fi
        case "$a" in
          -X|--method) prev=$a ;;
          -X=*) method=${a#-X=} ;;
          -X?*) method=${a#-X} ;;
          --method=*) method=${a#--method=} ;;
          --input) haswrite=1; hasinput=1; prev=$a ;;
          -f|-F|--field|--raw-field) haswrite=1; prev=$a ;;
          -f?*) haswrite=1; fields+=("${a#-f}") ;;
          -F?*) haswrite=1; fields+=("${a#-F}") ;;
          --field=*|--raw-field=*) haswrite=1; fields+=("${a#*=}") ;;
          --input=*) haswrite=1; hasinput=1 ;;
          -H|--header|-q|--jq|-t|--template|--hostname|--cache|--preview|-p) prev=$a ;;
          -[A-Za-z][A-Za-z]*)
            # a cluster of short flags (-iX DELETE, -iXPOST): the first flag that takes a value ends it
            for ((ci = 1; ci < ${#a}; ci++)); do
              c=${a:ci:1}; rest=${a:ci+1}
              case "$c" in
                X) if [[ -n "$rest" ]]; then method=${rest#=}; else prev=-X; fi; break ;;
                f|F) haswrite=1; if [[ -n "$rest" ]]; then fields+=("$rest"); else prev=-f; fi; break ;;
                H|q|t|p) [[ -n "$rest" ]] || prev=-H; break ;;
              esac
            done ;;
          -*) ;;
          *) [[ -z "$ep" ]] && ep=$a || true ;;
        esac
      done
      method=${method#=}; method=${method^^}
      if [[ -z "$method" ]]; then if ((haswrite)); then method=POST; else method=GET; fi; fi
      ep=${ep#https://api.github.com/}; ep=${ep#http://api.github.com/}; ep=${ep#/}; ep=${ep%%\?*}; ep=${ep%%#*}; ep=${ep,,}
      while [[ "$ep" == *//* ]]; do ep=${ep//\/\//\/}; done   # collapse //, /./ and a trailing /
      while [[ "$ep" == */./* ]]; do ep=${ep//\/.\//\/}; done
      ep=${ep%/}
      case "$ep" in
        */merge|*/merge/*|*/merges) block "merging through the API bypasses the verification gate" ;;
      esac
      [[ "$ep" == graphql && "$all" == *mutation* ]] && block "GraphQL mutations can merge, push or change refs; use scripts/verify and plain gh commands" || true
      if [[ "$method" != GET && "$method" != HEAD ]]; then
        [[ "$ep" == *%* ]] && block "percent-encoded endpoint on a write request cannot be checked" || true
        if [[ "$ep" == repos/*/contents/* ]]; then
          ((hasinput)) && block "contents writes with --input cannot be checked; the branch is hidden in the body"
          for fld in "${fields[@]}"; do
            key=${fld%%=*}
            [[ "$fld" == *=* && "$key" == branch ]] || continue   # exactly `branch`, case-sensitive
            br=${fld#*=}
            [[ "$br" == @* ]] && block "a branch value read from a file/stdin (@...) cannot be checked"
            br=${br,,}; br=${br#refs/}; br=${br#heads/}
            [[ -n "$br" ]] || block "an empty branch value means the default branch (main); name a feature branch"
            if [[ "$br" == main || "$br" == master ]]; then block "writing files to main/master through the API requires the user"; fi
            okbranch=1
          done
          ((okbranch)) || block "a contents write through the API needs an explicit branch=<feature branch> field (the default branch is main)"
        fi
        [[ "$method" == DELETE && "$ep" == repos/* ]] && block "DELETE on repos requires the user" || true
        case "$ep" in
          */../*|*/..) block "path traversal in a write endpoint cannot be checked" ;;
          repos/*/contents/*) ;;   # a file path, not an API route (checked above)
          */branches/*/protection*) block "changing branch protection requires the user" ;;
          */rulesets*) block "changing rulesets requires the user" ;;
          */statuses|*/statuses/*) block "writing commit statuses forges verification; scripts/verify is the only writer" ;;
          */git/refs|*/git/refs/*|*/git/refs\?*) block "writing git refs through the API requires the user" ;;
          */actions|*/actions/*) block "writes to actions (workflow dispatches, runs, secrets, variables) require the user" ;;
          */environments*) block "changing deployment environments requires the user" ;;
        esac
      fi ;;
  esac
  return 0
}

# --- scanning -----------------------------------------------------------------------------------

WRAPPERS=" bash sh zsh dash ksh eval xargs sudo env timeout nohup time exec watch ssh command builtin setsid nice python python3 perl ruby node "
SHELLS=" bash sh zsh dash ksh ash csh tcsh fish "
PIPE_MSG="piping into a shell hides commands; write a script file and run that"

check_pipe_target() {  # the segment after a | must not start a shell
  local k t base n=${#seg_t[@]}
  for ((k = 0; k < n; k++)); do
    t=${seg_t[k]}
    if [[ "$t" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then continue; fi
    base=${t##*/}
    case "$base" in env|sudo|exec|command|nohup|time|nice|setsid|builtin|stdbuf|timeout|'{'|'!'|-*) continue ;; esac
    if [[ "$SHELLS" == *" $base "* ]]; then
      # a script file or -c string argument means stdin is not the program (-s says it is)
      local m has_script=0 has_s=0
      for ((m = k + 1; m < n; m++)); do
        case "${seg_t[m]}" in
          -s) has_s=1 ;;
          -*) ;;
          /dev/stdin|/dev/fd/0|/proc/self/fd/0) ;;
          *) has_script=1; break ;;
        esac
      done
      if ((has_s || !has_script)); then block "$PIPE_MSG"; fi
    fi
    break
  done
}

check_stdin_source() {  # source /dev/stdin, bash /dev/stdin ...
  local k t n=${#seg_t[@]} seen=0
  for ((k = 0; k < n; k++)); do
    t=${seg_t[k]}
    case "$t" in
      /dev/stdin|/dev/fd/0|/proc/self/fd/0) if ((seen)); then block "$PIPE_MSG"; fi ;;
      source|.) seen=1 ;;
      *) if [[ "$SHELLS" == *" ${t##*/} "* ]]; then seen=1; fi ;;
    esac
  done
}

check_git_env() {  # GIT_CONFIG_* and editor assignments in a segment that runs git inject config or commands
  local t i has_git=0 bad=0 ed=0
  for ((i = 0; i < ${#seg_t[@]}; i++)); do
    t=${seg_t[i]}
    case "$t" in git|*/bin/git) has_git=1 ;; esac
    if [[ "$t" =~ ^GIT_CONFIG_(COUNT|KEY_[0-9]+|VALUE_[0-9]+|PARAMETERS)= ]]; then bad=1; fi
    # an editor assignment in front of git (GIT_EDITOR=x git rebase -i, env EDITOR=x git ...) runs that program
    if ((!has_git)) && [[ "$t" =~ ^(GIT_EDITOR|EDITOR|VISUAL|GIT_SEQUENCE_EDITOR)= ]]; then ed=1; fi
  done
  if ((has_git && bad)); then block "GIT_CONFIG_* environment overrides git config (hooks, pushes) and is not allowed"; fi
  if ((has_git && ed)); then block "GIT_EDITOR / EDITOR / VISUAL / GIT_SEQUENCE_EDITOR in front of git runs an arbitrary program; not allowed"; fi
  return 0
}

scan() {  # scan TEXT DEPTH
  local text=$1 depth=$2 line kind code had pending=0 subdepth=0 bt=0 insub cond=0
  local -a seg_t=() seg_q=()
  if ! code=$(strip_heredocs "$text"); then
    block "ambiguous heredoc delimiter (mixed quoted and unquoted parts); use a plain <<'EOF'"
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    kind=${line:0:1}
    if [[ "$kind" == [spoc] ]]; then
      had=${#seg_t[@]}
      insub=$((subdepth > 0 || bt))
      # a command followed by | or a single & runs in a subshell
      if [[ "$kind" == p || "$line" == 's&' ]]; then insub=1; fi
      check_segment "$depth" "$pending" "$insub"
      seg_t=(); seg_q=()
      cond=0; [[ "$line" == 's|' ]] && cond=1 || true   # the next command runs only if this one failed
      if [[ "$kind" == p ]]; then pending=1; elif ((had > 0)); then pending=0; fi
      case "$kind" in
        o) subdepth=$((subdepth + 1)) ;;
        c) ((subdepth > 0)) && subdepth=$((subdepth - 1)) || true ;;
        s) [[ "$line" == 's`' ]] && bt=$((1 - bt)) || true ;;
      esac
    else
      seg_t+=("${line:1}"); seg_q+=("$kind")
    fi
  done < <(tokenize "$code")
  check_segment "$depth" "$pending" $((subdepth > 0 || bt))
}

scan_redirects() {  # scan_redirects DEPTH WRAPPED: here-strings fed to a shell and $(...) in quoted targets are code
  local depth=$1 wrapped=$2 i t
  ((depth < 4)) || return 0
  for ((i = 0; i < ${#rd_op[@]}; i++)); do
    t=${rd_tgt[i]}
    [[ "${rd_q[i]}" == q ]] || continue
    # shellcheck disable=SC2016  # matching the literal text $(
    if [[ "$t" == *'$('* || "$t" == *'`'* ]]; then scan "$t" $((depth + 1))
    elif [[ "${rd_op[i]}" == *'<<<' ]] && ((wrapped)); then scan "$t" $((depth + 1)); fi
  done
}

check_segment() {  # check_segment DEPTH PIPED SUB ; reads seg_t, seg_q (SUB=1: runs in a subshell)
  local depth=$1 piped=$2 sub=$3 n i k t pn wrapped=0 first=0
  local -a rd_op=() rd_tgt=() rd_q=() nt=() nq=()
  n=${#seg_t[@]}
  # redirections are removed here, before any analysis: `git 2>/dev/null push` is `git push`. Their
  # targets are kept for the tamper check.
  for ((i = 0; i < n; i++)); do
    if [[ "${seg_q[i]}" == r ]]; then
      rd_op+=("${seg_t[i]}"); rd_tgt+=("${seg_t[i + 1]:-}"); rd_q+=("${seg_q[i + 1]:-}"); i=$((i + 1))
    else
      nt+=("${seg_t[i]}"); nq+=("${seg_q[i]}")
    fi
  done
  seg_t=("${nt[@]}"); seg_q=("${nq[@]}"); n=${#seg_t[@]}
  if ((n == 0)); then check_tamper; scan_redirects "$depth" 0; return 0; fi
  if ((depth == 0 && !cmd_seen)); then first=1; fi
  if ((depth == 0)); then cmd_seen=1; fi
  # cwd tracking: only a cd/pushd that is the very first command of the whole input is followed (and not
  # in a subshell, pipeline, background job or after a ||). Any other cd/pushd/popd makes the directory
  # unknown for the rest of the input; a bare push with an unknown directory is refused.
  for ((i = 1; i < n; i++)); do
    case "${seg_t[i]}" in cd|pushd|popd) cwd_unknown=1 ;; esac
  done
  case "${seg_t[0]}" in
    cd|pushd) if ((depth > 0 || sub || cond || !first)); then cwd_unknown=1; else track_cd; fi ;;
    popd) cwd_unknown=1 ;;
  esac
  if ((piped)); then check_pipe_target; fi
  check_stdin_source
  check_git_env
  check_tamper
  ((piped)) && sub=1 || true
  for ((i = 0; i < n; i++)); do
    t=${seg_t[i]}
    # the names as a word in any segment (=, +=, read, export, declare, ...). A quoted mention in the text
    # of a git/gh command (commit message, PR body) is data and stays allowed.
    if [[ "$t" =~ (^|[^A-Za-z0-9_])WARDENLENS_ALLOW_(REWRITE|WORKFLOWS)($|[^A-Za-z0-9_]) ]]; then
      if [[ "${seg_q[i]}" != q || ( "${seg_t[0]}" != git && "${seg_t[0]}" != gh ) ]]; then
        block "WARDENLENS_ALLOW_REWRITE / WARDENLENS_ALLOW_WORKFLOWS are human-only switches (history rewrites, workflow changes); agents never set them"
      fi
    fi
    if [[ "$t" =~ ^(GIT_DIR|GIT_WORK_TREE)= ]]; then cwd_unknown=1; fi
    case "${t##*/}" in
      env) for ((k = i + 1; k < n; k++)); do   # env -C DIR / --chdir changes the directory of what follows
             case "${seg_t[k]}" in -C|-C?*|--chdir|--chdir=*) cwd_unknown=1 ;; -*|*=*) ;; *) break ;; esac
           done ;;
    esac
    if [[ "${seg_q[i]}" == q && "$depth" -lt 4 ]]; then
      # shellcheck disable=SC2016  # matching the literal text $(
      if ((wrapped)) || [[ "$t" == *'$('* || "$t" == *'`'* ]]; then scan "$t" $((depth + 1)); fi
    fi
    case "${t##*/}" in
      git-send-pack|git-http-push|git-receive-pack|git-remote-*|git-upload-pack|git-fetch-pack)
        pn=${t##*/}; if is_push_plumbing "${pn#git-}" "${seg_t[@]:i+1}"; then block "$plumbing_msg"; fi ;;
    esac
    case "$t" in
      git|*/bin/git) check_git "$i" ;;
      gh|*/bin/gh) check_gh "$i" ;;
    esac
    [[ "$WRAPPERS" == *" ${t##*/} "* ]] && wrapped=1 || true
  done
  scan_redirects "$depth" "$wrapped"
  return 0
}

scan "$cmd" 0
exit 0
