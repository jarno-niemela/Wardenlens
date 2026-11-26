#!/usr/bin/env bash
# Test helper, sourced by the S1 shell tests (needs $fx, a scratch directory): a stand-in `wardenlens` on PATH
# that serves `vault get <id> [--field f]` and `vault redact` from plain files under $fx/vault. Synthetic values
# only; the real vault and key are never touched. The real binary is tested by redact_real.test.sh.
# shellcheck shell=bash disable=SC2154  # fx is set by the sourcing test

VAULT_STUB="$fx/vault"; export VAULT_STUB
mkdir -p "$VAULT_STUB" "$fx/bin"
printf '[]' >"$VAULT_STUB/.redact"
cat >"$fx/bin/wardenlens" <<'S'
#!/usr/bin/env bash
# argv log: what the spike scripts pass to the binary (a value on argv would show here).
printf '%s\n' "$*" >>"$VAULT_STUB/.argv"
[[ ${1:-} == vault ]] || exit 2
[[ -e $VAULT_STUB/.broken ]] && { echo "error: vault unusable" >&2; exit 2; }
case ${2:-} in
  get)
    f="$VAULT_STUB/${3//:/_}"
    [[ ${4:-} == --field ]] && f="$f.${5:-}"
    [[ -f $f ]] || { echo "error: no entry with id ${3:-}" >&2; exit 1; }
    cat "$f" ;;
  redact)
    exec python3 -I -c '
import sys, json
d = sys.stdin.buffer.read()
for v in sorted(json.load(open(sys.argv[1])), key=len, reverse=True):
    if v:
        d = d.replace(v.encode(), b"[REDACTED]")
sys.stdout.buffer.write(d)' "$VAULT_STUB/.redact" ;;
  *) exit 2 ;;
esac
S
chmod +x "$fx/bin/wardenlens"
export PATH="$fx/bin:$PATH"

# stub_id <display name or id> -> inventory id (the mapping lib.sh's cam_id has).
stub_id() {
  case "$1" in
    IPC-BO) echo reolink-1 ;; "IPC-BO (2)") echo reolink-2 ;; XR) echo xr ;; C110) echo tapo ;; HDIPC) echo hdipc ;;
    *) echo "$1" ;;
  esac
}
# redact_add <value>: the stub's redact replaces this value.
redact_add() { jq --arg v "$1" '. + [$v]' "$VAULT_STUB/.redact" >"$VAULT_STUB/.r" && mv "$VAULT_STUB/.r" "$VAULT_STUB/.redact"; }
# vault_put <entry-id> <value>
vault_put() { printf '%s' "$2" >"$VAULT_STUB/${1//:/_}"; }
# cred <camera> <user> <password>: the credential entry (both fields); the password is also redacted.
cred() {
  local id; id="$(stub_id "$1")"
  printf '%s' "$2" >"$VAULT_STUB/cam_${id}_credential.username"
  printf '%s' "$3" >"$VAULT_STUB/cam_${id}_credential.password"
  [[ -z $3 ]] || redact_add "$3"
}
# host <camera> <host>
host() { vault_put "cam:$(stub_id "$1"):host" "$2"; }
# no_entries: an empty vault
no_entries() { find "$VAULT_STUB" -maxdepth 1 -type f ! -name '.*' -delete; }
