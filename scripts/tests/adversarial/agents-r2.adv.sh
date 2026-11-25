#!/usr/bin/env bash
# Adversarial tests for scripts/agents, round 2 (PR #31). Throwaway state + fake secret file; gh is a stub.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
agents=$root/scripts/agents
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$GH_LOG"
[[ "$1 $2" == "pr view" ]] || exit 1
case "$3" in 7) printf '%s\n' "$HEAD7" ;; 8) printf 'not-a-sha\n' ;; *) exit 1 ;; esac
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" GH_LOG="$tmp/gh.log"
export WARDENLENS_AGENT_STATE="$tmp/state" WARDENLENS_SECRET_FILE="$tmp/secret.json"
# Hermetic: no vault (so the secret-file fallback is under test) whatever the machine has.
export HOME="$tmp/home"; mkdir -p "$HOME"; unset WARDENLENS_VAULT WARDENLENS_REQUIRE_VAULT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
refused()  { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
accepted() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
A=$(printf 'a%.0s' {1..40}); B=$(printf 'b%.0s' {1..40})
prompt() { local f; f=$(mktemp "$tmp/pXXXXXX"); printf '%s\n' "$1" >"$f"; echo "$f"; }
n=0; nid() { n=$((n + 1)); echo "id$n"; }

printf '[]' >"$tmp/secret.json"

# --- private addresses: other RFC1918 ranges and positions ---
for t in '172.16.0.1' '172.31.255.1' 'net 172.20.x.x' '192.168.x.1' 'a10.20.1.2' 'rtsp://cam@192.168.7.3/s' \
         'IP:10.0.0.1' '(172.18.1.1)' 'x_10.30.1.1' '"10.200.3.4"'; do
  refused "lan: '$t' refused" "$agents" check "$(prompt "$t")"
done
for t in '172.15.0.1' '172.32.0.1' 'v1.192.168.1.1' 'build 2.172.16.0.1' 'python 3.10.12' 'fe80::1' 'version 10.20'; do
  accepted "lan: '$t' allowed" "$agents" check "$(prompt "$t")"
done
for t in 'fd12:3456::1' 'FD00::1' '[fc00::1]' 'addr=fdab:cd::9'; do
  refused "ula: '$t' refused" "$agents" check "$(prompt "$t")"
done
refused "lan: address after NUL bytes refused" "$agents" check "$(f=$(mktemp "$tmp/pXXXXXX"); printf 'x\0y 192.168.7.9\n' >"$f"; echo "$f")"

# --- userinfo credentials ---
for t in 'rtsp://admin:s3cret@cam.example/x' 'HTTP://u:p@h' 'onvif+http://op:pw@h:80/' 'rtsp://admin:pa/ss@cam.example/x' \
         'rtsp://admin:p@ss@cam.example/x'; do
  refused "userinfo: '$t' refused" "$agents" check "$(prompt "$t")"
done
accepted "userinfo: user-only URL allowed" "$agents" check "$(prompt 'ssh://git@github.com/x')"

# --- secret scan edge cases ---
cat >"$tmp/secret.json" <<'JSON'
{"cams":[{"name":"FrontDoorCam","model":"IPC-T54","port":55443,"creds":{"user":"opuser01","pass":["k3yA","LongerSecret9"]},
 "multi":"line1short\nsecondline99","pin":123456789012,"flag":true,"none":null,"id":"deadbeefcafe"}]}
JSON
refused "secret: nested array value refused" "$agents" check "$(prompt 'try LongerSecret9')"
refused "secret: nested object value refused" "$agents" check "$(prompt 'user opuser01')"
refused "secret: second line of multi-line value refused" "$agents" check "$(prompt 'x secondline99')"
refused "secret: big integer refused" "$agents" check "$(prompt 'pin 123456789012')"
accepted "secret: allowlisted name allowed" "$agents" check "$(prompt 'camera FrontDoorCam')"
accepted "secret: allowlisted numeric port allowed" "$agents" check "$(prompt 'port 55443')"
accepted "secret: allowlisted id allowed" "$agents" check "$(prompt 'id deadbeefcafe')"
accepted "secret: short value (<6) allowed" "$agents" check "$(prompt 'k3yA')"
accepted "secret: booleans/null not turned into patterns" "$agents" check "$(prompt 'true null false')"
printf '{"name":{"password":"UnderName77"}}' >"$tmp/s2.json"
refused "secret: object under an allowlisted key is still scanned" \
  env WARDENLENS_SECRET_FILE="$tmp/s2.json" "$agents" check "$(prompt 'UnderName77')"
printf '{not json' >"$tmp/s3.json"
refused "secret: malformed secret file fails closed" env WARDENLENS_SECRET_FILE="$tmp/s3.json" "$agents" check "$(prompt 'hello')"
printf '{"password":"Unreadable1"}' >"$tmp/s4.json"; chmod 000 "$tmp/s4.json"
if [[ $(id -u) -ne 0 ]]; then
  refused "secret: unreadable secret file fails closed" env WARDENLENS_SECRET_FILE="$tmp/s4.json" "$agents" check "$(prompt 'hello')"
fi
chmod 600 "$tmp/s4.json"
out=$(env WARDENLENS_SECRET_FILE="$tmp/s4.json" "$agents" check "$(prompt 'Unreadable1')" 2>&1 || true)
if [[ "$out" == *Unreadable1* ]]; then bad "secret: refusal never echoes the value"; else ok "secret: refusal never echoes the value"; fi
printf '[]' >"$tmp/secret.json"

# --- check and record must agree (check runs before launch, record after) ---
big=$tmp/big.prompt; head -c 1100000 /dev/zero | tr '\0' 'a' >"$big"
c=0; "$agents" check "$big" >/dev/null 2>&1 || c=1
r=0; "$agents" record reviewer 7 "$A" "$big" "$(nid)" >/dev/null 2>&1 || r=1
if [[ $c -eq $r ]]; then ok "check/record agree on an oversize prompt"; else bad "check/record agree on an oversize prompt (check=$c record=$r)"; fi

# --- record failure leaves no trace ---
rm -rf "$tmp/state"
"$agents" record reviewer 7 "$A" "$(prompt 'fine')" keep1 >/dev/null
refused "record: refused prompt" "$agents" record reviewer 7 "$A" "$(prompt '10.20.1.1')" leak1
if [[ ! -e "$tmp/state/leak1.prompt" ]] && ! compgen -G "$tmp/state/.incoming*" >/dev/null; then ok "record: refusal leaves no prompt copy"; else bad "record: refusal leaves no prompt copy"; fi
if [[ $(wc -l <"$tmp/state/inflight.tsv") -eq 1 ]]; then ok "record: refusal adds no row"; else bad "record: refusal adds no row"; fi
perm=$(stat -c %a "$tmp/state/keep1.prompt")
if [[ $perm == 600 ]]; then ok "record: prompt saved 0600"; else bad "record: prompt saved 0600 ($perm)"; fi
refused "record: duplicate id refused" "$agents" record reviewer 7 "$A" "$(prompt 'again')" keep1
refused "record: id with slash refused" "$agents" record reviewer 7 "$A" "$(prompt 'x')" '../evil'
refused "record: id starting with dot refused" "$agents" record reviewer 7 "$A" "$(prompt 'x')" '.lock'
refused "record: uppercase sha refused" "$agents" record reviewer 7 "${A^^}" "$(prompt 'x')" up1
refused "record: REF with tab refused" "$agents" record reviewer $'7\t1' "$A" "$(prompt 'x')" tab1
ln -s "$(prompt 'x')" "$tmp/link.prompt"
refused "record: symlink prompt refused" "$agents" record reviewer 7 "$A" "$tmp/link.prompt" sym1

# --- done: id reuse keeps every earlier prompt ---
"$agents" 'done' keep1
"$agents" record reviewer 7 "$A" "$(prompt 'second')" keep1
"$agents" 'done' keep1
"$agents" record reviewer 7 "$A" "$(prompt 'third')" keep1
"$agents" 'done' keep1
cnt=$(find "$tmp/state" -name 'keep1.prompt.done*' | wc -l)
if [[ $cnt -eq 3 ]]; then ok "done: three reuses keep three prompts"; else bad "done: three reuses keep three prompts (found $cnt)"; fi

# --- fail: reason/reset hardening ---
"$agents" record reviewer 7 "$A" "$(prompt 'p')" f1
"$agents" fail f1 $'a\\tb\x1fc\vd' $'14:30\tX' 2>/dev/null
row=$(grep -P '\tf1\t' "$tmp/state/inflight.tsv")
cols=$(awk -F'\t' '{print NF}' <<<"$row")
if [[ $cols -eq 9 ]]; then ok "fail: row keeps 9 columns"; else bad "fail: row keeps 9 columns ($cols)"; fi
if [[ $(cut -f7 <<<"$row") == - ]]; then ok "fail: RESET with tab stored as -"; else bad "fail: RESET with tab stored as -"; fi
"$agents" fail f1 'again' '2026-11-22T14:30:00+02:00'
if [[ $(grep -P '\tf1\t' "$tmp/state/inflight.tsv" | cut -f7) == '2026-11-22T14:30:00+02:00' ]]; then ok "fail: ISO RESET kept"; else bad "fail: ISO RESET kept"; fi
if "$agents" fail f1 x 14:30 2>&1 | grep -q 'unescaped backslash'; then bad "fail: no tr warning on stderr"; else ok "fail: no tr warning on stderr"; fi
refused "fail: unknown id refused" "$agents" fail nosuch x
refused "fail: missing reason refused" "$agents" fail f1

# --- list: stale detection ---
rm -rf "$tmp/state"; : >"$GH_LOG"
export HEAD7=$B
"$agents" record reviewer 7 "$A" "$(prompt 'p')" r7a
"$agents" record adversary 7 "$A" "$(prompt 'p')" r7b
"$agents" record reviewer 8 "$A" "$(prompt 'p')" r8
"$agents" record implementer '#7' "$A" "$(prompt 'p')" i7
out=$("$agents" list)
if grep -P '\tr7a\t.*STALE' <<<"$out" >/dev/null; then ok "list: stale verifier flagged"; else bad "list: stale verifier flagged"; fi
if grep -P '\tr8\t.*UNKNOWN' <<<"$out" >/dev/null; then ok "list: non-sha gh output -> UNKNOWN"; else bad "list: non-sha gh output -> UNKNOWN"; fi
if grep -P '\ti7\t.*(STALE|UNKNOWN)' <<<"$out" >/dev/null; then bad "list: implementer row never PR-checked"; else ok "list: implementer row never PR-checked"; fi
calls=$(grep -c 'pr view 7' "$GH_LOG")
if [[ $calls -eq 1 ]]; then ok "list: one gh call per distinct PR"; else bad "list: one gh call per distinct PR ($calls)"; fi
export HEAD7=$A
if "$agents" list --pr 7 | grep -q 'STALE'; then bad "list --pr: current head not stale"; else ok "list --pr: current head not stale"; fi
refused "list --pr: gh garbage dies" "$agents" list --pr 8
refused "list --pr: non-numeric refused" "$agents" list --pr '7;id'
refused "list: extra arg refused" "$agents" list foo

# --- help documents the whole header ---
if "$agents" --help | grep -q 'values are never printed'; then ok "help: prints full header"; else bad "help: prints full header"; fi

exit $fail
