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
printf 'camera at 10.99.1.2\n' >"$tmp/p2"
checkf "LAN address refused" "$agents" record reviewer 5 "$A" "$tmp/p2" ag4
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

exit $fail
