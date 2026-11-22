#!/usr/bin/env bash
# Offline tests for scripts/ticket argument handling. A stub gh that always fails proves that
# invalid input is rejected before anything is sent to GitHub.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ticket=$root/scripts/ticket
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
printf '#!/usr/bin/env bash\necho "gh $*" >>"%s/calls"\nexit 1\n' "$tmp" >"$tmp/bin/gh"
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH"
fail=0

rejects() {  # rejects DESCRIPTION args...  (must fail, and must not reach gh)
  local d=$1; shift
  rm -f "$tmp/calls"
  if "$ticket" "$@" >"$tmp/out" 2>"$tmp/err"; then echo "FAIL $d: accepted"; fail=1
  elif [[ -e "$tmp/calls" ]]; then echo "FAIL $d: reached gh: $(cat "$tmp/calls")"; fail=1
  else echo "ok   $d"; fi
}

rejects "epic: bad priority"        epic "T" -p p9
rejects "epic: priority injection"  epic "T" -p 'p1,type:epic'
rejects "epic: bad area"            epic "T" -a 'Bad Area'
rejects "epic: leftover argument"   epic "T" -p p1 stray
rejects "task: bad epic number"     task 'x;y' "T"
rejects "task: bad priority"        task 1 "T" -p high
rejects "task: bad type"            task 1 "T" -t epic
rejects "task: bad area"            task 1 "T" -a 'a,b'
rejects "task: bad blocker"         task 1 "T" -b 'abc'
rejects "task: bad blocker in list" task 1 "T" -b '2,x3'
rejects "task: leftover argument"   task 1 "T" extra
rejects "status: bad state"         status 3 shipped
rejects "status: bad number"        status x ready
rejects "unknown command"           frobnicate

# --help must not print the `set -euo` line
if "$ticket" --help | grep -q 'set -euo'; then echo "FAIL ticket --help leaks code"; fail=1; else echo "ok   ticket --help is clean"; fi
audit=$root/scripts/ticket-audit
if "$audit" --help | grep -q 'set -euo'; then echo "FAIL ticket-audit --help leaks code"; fail=1; else echo "ok   ticket-audit --help is clean"; fi
rc=0; "$audit" --fail-on >/dev/null 2>&1 || rc=$?
if [[ $rc -eq 2 ]]; then echo "ok   ticket-audit: missing option value exits 2"; else echo "FAIL ticket-audit missing value exited $rc"; fail=1; fi
rc=0; "$audit" --issues-file >/dev/null 2>&1 || rc=$?
if [[ $rc -eq 2 ]]; then echo "ok   ticket-audit: missing file value exits 2"; else echo "FAIL ticket-audit missing file value exited $rc"; fail=1; fi
exit $fail
