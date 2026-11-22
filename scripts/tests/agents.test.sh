#!/usr/bin/env bash
# Offline tests for scripts/agents. State and secret file are throwaway; gh is a stub.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
agents=$root/scripts/agents
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
[[ "$1 $2" == "pr view" ]] && { printf '%s\n' "$HEAD"; exit 0; }
echo "stub gh: unexpected $*" >&2; exit 1
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH"
export WARDENLENS_AGENT_STATE="$tmp/state" WARDENLENS_SECRET_FILE="$tmp/secret.json"
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }
checkf() { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
mode() { stat -c %a "$1"; }

A=$(printf 'a%.0s' {1..40}); B=$(printf 'b%.0s' {1..40})
printf 'review PR 5 at /home/x/wt\n' >"$tmp/p1"
printf '{"user":"cam-admin","password":"s3cretPass!","name":"short","nested":{"apiKey":"tok-123456789"}}' >"$tmp/secret.json"

"$agents" record reviewer 5 "$A" "$tmp/p1" ag1
check "record saves prompt 0600" test "$(mode "$tmp/state/ag1.prompt")" = 600
check "record tsv 0600" test "$(mode "$tmp/state/inflight.tsv")" = 600
check "state dir 0700" test "$(mode "$tmp/state")" = 700
check "row has role/ref/sha/id/running" grep -qP "^\S+\treviewer\t5\t$A\tag1\trunning\t-\t" "$tmp/state/inflight.tsv"
checkf "duplicate id refused" "$agents" record reviewer 5 "$A" "$tmp/p1" ag1
"$agents" record adversary 5 "$B" "$tmp/p1" ag2
check "list shows both" test "$("$agents" list | wc -l)" = 2

# stale detection
export HEAD=$B
out=$("$agents" list --pr 5)
check "stale flagged for old sha" bash -c "grep -qP 'ag1.*STALE' <<<\"\$1\"" _ "$out"
check "current sha not flagged" bash -c "! grep -qP 'ag2.*STALE' <<<\"\$1\"" _ "$out"
out=$("$agents" list --pr 9)
check "other PR not flagged" bash -c "! grep -q STALE <<<\"\$1\"" _ "$out"
checkf "list --pr rejects non-number" "$agents" list --pr x

# fail / done
"$agents" fail ag1 "rate_limit 429" "14:30"
check "fail marks limited with reset" grep -qP "ag1\tlimited\t14:30" "$tmp/state/inflight.tsv"
check "fail keeps prompt" test -f "$tmp/state/ag1.prompt"
"$agents" 'done' ag1
check "done removes row" bash -c "! grep -q ag1 \"\$1\"" _ "$tmp/state/inflight.tsv"
check "done keeps prompt as .done" test -f "$tmp/state/ag1.prompt.done"
check "done leaves other rows" grep -q ag2 "$tmp/state/inflight.tsv"
checkf "done unknown id fails" "$agents" 'done' nope
"$agents" 'done' ag2
check "empty list message" bash -c "[[ \$(\"\$1\" list) == 'no inflight agents' ]]" _ "$agents"

# validation
checkf "bad sha refused" "$agents" record reviewer 5 abc "$tmp/p1" ag3
checkf "path-traversal id refused" "$agents" record reviewer 5 "$A" "$tmp/p1" ../evil
checkf "missing prompt refused" "$agents" record reviewer 5 "$A" "$tmp/none" ag3

# secret scan
n=0
for ip in 10.1.2.3 172.20.0.5 192.168.50.7; do
  n=$((n + 1)); printf 'camera at %s:80\n' "$ip" >"$tmp/p2"
  checkf "private address $ip refused" "$agents" record reviewer 5 "$A" "$tmp/p2" "lan$n"
done
for ip in 3.0.0.4 203.0.113.9 172.32.0.1 1.10.1.2.3; do
  n=$((n + 1)); printf 'ver %s ok\n' "$ip" >"$tmp/p2"
  check "non-private $ip allowed" "$agents" record reviewer 5 "$A" "$tmp/p2" "pub$n"
done
printf 'login with s3cretPass! please\n' >"$tmp/p3"
checkf "secret value refused" "$agents" record reviewer 5 "$A" "$tmp/p3" ag5
printf 'key tok-123456789\n' >"$tmp/p4"
checkf "nested secret refused" "$agents" record reviewer 5 "$A" "$tmp/p4" ag6
err=$("$agents" record reviewer 5 "$A" "$tmp/p3" ag5 2>&1 || true)
check "secret value never printed" bash -c "! grep -q 's3cretPass' <<<\"\$1\"" _ "$err"
check "refused prompt leaves no file" test ! -e "$tmp/state/ag5.prompt"
printf 'the name is short\n' >"$tmp/p5"
check "short/non-credential values allowed" "$agents" record reviewer 5 "$A" "$tmp/p5" ag7
printf 'not json' >"$tmp/secret.json"
checkf "unreadable secret file fails closed" "$agents" record reviewer 5 "$A" "$tmp/p1" ag8

# more address / credential forms (non-owner private values)
printf '[]' >"$tmp/secret.json"
for t in 'host 192.168.7.' 'net 172.18.x' 'foo.10.20.1.2' 'v6 fd12:3456::1' 'url https://bob:pw1@example.org/x'; do
  n=$((n + 1)); printf '%s\n' "$t" >"$tmp/p2"
  checkf "refused: $t" "$agents" record reviewer 5 "$A" "$tmp/p2" "more$n"
done
printf 'v 1.10.20.1.2.3\n' >"$tmp/p2"
check "version string allowed" "$agents" record reviewer 5 "$A" "$tmp/p2" ver1

# secret scan: login, numeric password, array, allowlisted camera name
printf '[{"name":"Frontdoor","login":"camoperator","password":87654321,"keys":["arr-secret-1"]}]' >"$tmp/secret.json"
for v in camoperator 87654321 arr-secret-1; do
  printf 'x %s y\n' "$v" >"$tmp/p2"
  checkf "secret scalar $v refused" "$agents" record reviewer 5 "$A" "$tmp/p2" "sec$v"
done
printf 'camera Frontdoor\n' >"$tmp/p2"
check "allowlisted camera name accepted" "$agents" record reviewer 5 "$A" "$tmp/p2" camname

# fail edge cases, list without state, gh failure, implementer rows
checkf "fail unknown id refused" "$agents" fail nosuch rate_limit
"$agents" record implementer '#29' "$A" "$tmp/p1" impl1
check "implementer row has 9 columns" test "$(awk -F'\t' '$5=="impl1"{print NF}' "$tmp/state/inflight.tsv")" = 9
check "implementer row never STALE" bash -c "! \"\$1\" list | grep -P 'impl1.*(STALE|UNKNOWN)'" _ "$agents"
"$agents" fail impl1 "x\ny" 'bogus'
check "fail keeps 9 columns" test "$(awk -F'\t' '$5=="impl1"{print NF}' "$tmp/state/inflight.tsv")" = 9
"$agents" fail impl1 rate_limit 14:30
check "fail stores reason exactly" test "$(awk -F"\t" '$5=="impl1"{print $9}' "$tmp/state/inflight.tsv")" = rate_limit
"$agents" fail impl1 "a b/c"
check "fail sanitises to a_b_c" test "$(awk -F"\t" '$5=="impl1"{print $9}' "$tmp/state/inflight.tsv")" = a_b_c
check "list without state dir" bash -c "[[ \$(WARDENLENS_AGENT_STATE=\$1/none \"\$2\" list) == 'no inflight agents' ]]" _ "$tmp" "$agents"
"$agents" record reviewer 7 "$A" "$tmp/p1" pr7
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
exit 1
STUB
checkf "list --pr dies when gh fails" "$agents" list --pr 7
check "plain list marks UNKNOWN when gh fails" bash -c "\"\$1\" list | grep -qP 'pr7.*UNKNOWN'" _ "$agents"
"$agents" 'done' pr7; "$agents" record reviewer 7 "$A" "$tmp/p1" pr7; "$agents" 'done' pr7
check "reused id keeps earlier .done" test "$(find "$tmp/state" -name "pr7.prompt.done*" | wc -l)" = 2

# agents check: same validation as record, creates no state
rm -rf "$tmp/cstate"; printf '[]' >"$tmp/secret.json"
cs=(env WARDENLENS_AGENT_STATE="$tmp/cstate" "$agents" check)
printf 'clean prompt\n' >"$tmp/c1"; printf 'host 192.168.1.5\n' >"$tmp/c2"
check "check accepts clean prompt" "${cs[@]}" "$tmp/c1"
check "check creates nothing under state dir" test ! -e "$tmp/cstate"
checkf "check refuses RFC1918 prompt" "${cs[@]}" "$tmp/c2"
printf '{"password":"s3cretPass!"}' >"$tmp/secret.json"; printf 'pw s3cretPass!\n' >"$tmp/c3"
checkf "check refuses secret-file value" "${cs[@]}" "$tmp/c3"
printf '[]' >"$tmp/secret.json"
checkf "check refuses missing file" "${cs[@]}" "$tmp/none"
ln -s "$tmp/c1" "$tmp/clink"
checkf "check refuses symlink" "${cs[@]}" "$tmp/clink"
checkf "check with 0 args fails" "${cs[@]}"
checkf "check with 2 args fails" "${cs[@]}" "$tmp/c1" "$tmp/c1"
head -c 1100000 /dev/zero | tr '\0' a >"$tmp/cbig"
checkf "check refuses >1 MiB" "${cs[@]}" "$tmp/cbig"
for t in 'net 10.5/16' 'net 10.5.*' 'net 10.5.X' 'net 192.168/16' 'net 172.16/12' 'rtsp://u:p/w@h/x'; do
  printf '%s\n' "$t" >"$tmp/c4"; checkf "check refuses: $t" "${cs[@]}" "$tmp/c4"
done
printf 'ssh://git@host/x\n' >"$tmp/c4"; check "user-only URL allowed" "${cs[@]}" "$tmp/c4"

exit $fail
