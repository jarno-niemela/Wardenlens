#!/usr/bin/env bash
# Adversarial tests for scripts/agents, round 3 (PR #31). Throwaway state + fake secret file; gh is a stub.
# shellcheck disable=SC2015  # A && ok || bad is the intended pass/fail idiom here
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
agents=$root/scripts/agents
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
printf '#!/usr/bin/env bash\nexit 1\n' >"$tmp/bin/gh"; chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH"
export WARDENLENS_AGENT_STATE="$tmp/state" WARDENLENS_SECRET_FILE="$tmp/secret.json"
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
refused()  { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
accepted() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
A=$(printf 'a%.0s' {1..40})
prompt() { local f; f=$(mktemp "$tmp/pXXXXXX"); printf '%s\n' "$1" >"$f"; echo "$f"; }
printf '[]' >"$tmp/secret.json"

# --- userinfo with password (round-2 fix) ---
for t in 'https://u:p/ss@host/x' 'https://u:p@ss@host' 'rtsp://admin:s3cr@t@cam.example/s' 'HTTPS://u:pw@h'; do
  refused "cred: '$t' refused" "$agents" check "$(prompt "$t")"
done
refused "cred: empty user with token password refused" "$agents" check "$(prompt 'https://:ghp_token123@github.com/x')"
accepted "cred: ssh git@host stays allowed" "$agents" check "$(prompt 'ssh://git@github.com/o/r.git')"
accepted "cred: plain host:port URL allowed" "$agents" check "$(prompt 'see https://example.com:8080/x then mail a@b.c')"

# --- RFC1918 partial forms (round-2 fix) ---
for t in '10.4/16' '10.4.*' '10.4.X' '192.168/16' '192.168.*' '172.20/12' '172.31.X' '10.0.0.0/8'; do
  refused "lan: '$t' refused" "$agents" check "$(prompt "$t")"
done

# --- check == record validation, incl. 1 MiB ---
big=$tmp/big; head -c 1048577 /dev/zero | tr '\0' a >"$big"
refused "check: >1 MiB refused" "$agents" check "$big"
refused "check: two args refused" "$agents" check "$(prompt ok)" extra
refused "check: directory refused" "$agents" check "$tmp"

# --- REASON sanitisation must not append a byte ---
"$agents" record reviewer 31 "$A" "$(prompt ok)" r1 >/dev/null
"$agents" fail r1 rate_limit 12:00 >/dev/null
got=$(awk -F'\t' '$5 == "r1" { print $9 }' "$tmp/state/inflight.tsv")
[[ "$got" == "rate_limit" ]] && ok "fail: reason stored verbatim" || bad "fail: reason stored verbatim (got '$got')"
"$agents" fail r1 'a b/c' >/dev/null
got=$(awk -F'\t' '$5 == "r1" { print $9 }' "$tmp/state/inflight.tsv")
[[ "$got" == "a_b_c" ]] && ok "fail: unsafe chars become _" || bad "fail: unsafe chars become _ (got '$got')"

# --- AGENT_ID matching must be exact string, not numeric ---
"$agents" record reviewer 31 "$A" "$(prompt ok)" 100 >/dev/null
accepted "id: 1e2 is distinct from 100 (record)" "$agents" record reviewer 31 "$A" "$(prompt ok)" 1e2
accepted "id: 0100 is distinct from 100 (record)" "$agents" record reviewer 31 "$A" "$(prompt ok)" 0100
"$agents" record reviewer 31 "$A" "$(prompt ok)" 12345678901234567 >/dev/null
accepted "id: 17-digit ids differing in last digit are distinct" \
  "$agents" record reviewer 31 "$A" "$(prompt ok)" 12345678901234568
"$agents" 'done' 12345678901234568 >/dev/null 2>&1 || true
grep -q $'\t12345678901234567\t' "$tmp/state/inflight.tsv" \
  && ok "done: removes only the exact id" || bad "done: removes only the exact id (sibling row dropped)"

# --- help ---
"$agents" --help | grep -q 'values are never printed' && ok "help: whole header" || bad "help: whole header"
"$agents" --help | grep -q 'set -euo' && bad "help: stops at code" || ok "help: stops at code"

exit $fail
