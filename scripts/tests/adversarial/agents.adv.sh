#!/usr/bin/env bash
# Adversarial tests for scripts/agents (PR #31). Throwaway state + fake secret file; gh is a stub.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
agents=$root/scripts/agents
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
[[ "$1 $2" == "pr view" ]] && { printf '%s\n' "$HEAD"; exit 0; }
exit 1
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH"
export WARDENLENS_AGENT_STATE="$tmp/state" WARDENLENS_SECRET_FILE="$tmp/secret.json"
# Hermetic: no vault (so the secret-file fallback is under test) whatever the machine has.
export HOME="$tmp/home"; mkdir -p "$HOME"; unset WARDENLENS_VAULT WARDENLENS_REQUIRE_VAULT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
refused() { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
accepted() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
A=$(printf 'a%.0s' {1..40}); B=$(printf 'b%.0s' {1..40})
n=0
# prompt TEXT -> path of a fresh prompt file (unique per call even from a subshell)
prompt() { local f; f=$(mktemp "$tmp/pXXXXXX"); printf '%s\n' "$1" >"$f"; echo "$f"; }

# Secret file in the real schema used by spikes/s1-cameras/lib.sh: array of cameras with
# name / login / password / onvif.
cat >"$tmp/secret.json" <<'JSON'
[{"name":"test-cam-a","login":"camoperator","password":"Hunter2Pass","onvif":"http://camoperator:Hunter2Pass@cam.example:8000/onvif"},
 {"name":"test-cam-b","login":"xrviewer","password":87654321}]
JSON

# --- secret scan: real schema keys ---
refused "secret: password value refused" "$agents" record reviewer 5 "$A" "$(prompt 'use Hunter2Pass')" s1
refused "secret: login (username) value refused" "$agents" record reviewer 5 "$A" "$(prompt 'log in as camoperator')" s2
refused "secret: numeric password refused" "$agents" record reviewer 5 "$A" "$(prompt 'pin is 87654321')" s3
accepted "secret: unrelated prompt allowed" "$agents" record reviewer 5 "$A" "$(prompt 'review PR 5')" s4
printf '{"tokens":["abcdef-token-xyz"]}' >"$tmp/secret2.json"
refused "secret: value inside an array under a credential key refused" \
  env WARDENLENS_SECRET_FILE="$tmp/secret2.json" "$agents" record reviewer 5 "$A" "$(prompt 'tok abcdef-token-xyz')" s5

# --- RFC1918 / 10.20. scan ---
printf '[]' >"$tmp/secret.json"
for t in 'cam 10.20.1.2' 'cams at 10.20.0.0/16' 'ip=10.20.4.20,' 'see 10.20.1.2.' 'http://10.20.1.2:554/x' \
         '[10.20.7.7]' '::ffff:10.20.1.2' 'host foo.10.20.1.2' 'list...10.20.1.2'; do
  n=$((n + 1)); refused "lan: '$t' refused" "$agents" record reviewer 5 "$A" "$(prompt "$t")" "lan$n"
done
refused "lan: address on CRLF line refused" "$agents" record reviewer 5 "$A" "$(prompt $'x 192.168.1.10\r')" crlf
accepted "lan: version string 1.10.20.1.2 allowed" "$agents" record reviewer 5 "$A" "$(prompt 'v 1.10.20.1.2.3')" ver

# --- fail: REASON/RESET must not break the TSV (awk -v escape processing) ---
rm -rf "$tmp/state"
"$agents" record reviewer 5 "$A" "$(prompt 'p')" ag1
"$agents" fail ag1 'rate\nlimit\tx' '14:30'
rows=$(wc -l <"$tmp/state/inflight.tsv")
if [[ $rows -eq 1 ]]; then ok "fail: backslash escapes in REASON keep one row"; else bad "fail: backslash escapes in REASON keep one row (rows=$rows)"; fi
"$agents" record reviewer 5 "$A" "$(prompt 'p')" ag2
"$agents" fail ag2 "x\n2026-01-01T00:00:00Z\treviewer\t5\t$A\tforged\trunning\t-\t/etc/passwd" '15:00'
if "$agents" list | grep -q forged; then bad "fail: REASON cannot forge an inflight row"; else ok "fail: REASON cannot forge an inflight row"; fi
refused "fail: forged id not recognised by done" "$agents" 'done' forged
"$agents" fail ag2 rate_limit '15:00\t\t'
nf=$(awk -F'\t' '$5=="ag2"{print NF}' "$tmp/state/inflight.tsv")
if [[ "$nf" == 9 ]]; then ok "fail: RESET escapes do not add columns"; else bad "fail: RESET escapes do not add columns (NF=$nf)"; fi

# --- lifecycle edge cases ---
rm -rf "$tmp/state"
"$agents" record reviewer 5 "$A" "$(prompt 'first')" re
"$agents" 'done' re
"$agents" record reviewer 5 "$A" "$(prompt 'second')" re
"$agents" 'done' re
if grep -rqx first "$tmp/state"; then ok "reused id keeps the earlier saved prompt"
else bad "reused id keeps the earlier saved prompt (first prompt overwritten)"; fi
refused "done twice fails" "$agents" 'done' re
refused "fail unknown id" "$agents" fail nope rate_limit
"$agents" record r 5 "$A" "$(prompt q)" x1; "$agents" fail x1 rate_limit
accepted "fail without RESET" grep -qP "x1\tlimited\t-\t" "$tmp/state/inflight.tsv"
for f in "$tmp/state"/* "$tmp/state/.lock"; do
  m=$(stat -c %a "$f"); [[ $m == 600 ]] || bad "mode 600 for $(basename "$f") (got $m)"
done; ok "all state files 0600"
# list --pr stale with fail-marked row
export HEAD=$B
if "$agents" list --pr 5 | grep -q 'x1.*STALE'; then ok "limited row flagged STALE"; else bad "limited row flagged STALE"; fi
# pre-existing loose permissions are tightened
chmod 755 "$tmp/state"; chmod 644 "$tmp/state/inflight.tsv"
"$agents" record r 5 "$A" "$(prompt q)" x2
if [[ $(stat -c %a "$tmp/state") == 700 && $(stat -c %a "$tmp/state/inflight.tsv") == 600 ]]; then ok "loose perms tightened"
else bad "loose perms tightened"; fi
# symlinked prompt refused, bad role refused
ln -s "$(prompt q)" "$tmp/link"
refused "symlink prompt refused" "$agents" record r 5 "$A" "$tmp/link" x3
refused "role with tab refused" "$agents" record $'r\tx' 5 "$A" "$(prompt q)" x4
refused "uppercase sha refused" "$agents" record r 5 "${A^^}" "$(prompt q)" x5
exit $fail
