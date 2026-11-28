#!/usr/bin/env bash
# Adversarial round 2 for #233: rtsp_path argument handling. Stub vault under a temporary HOME only.
# shellcheck disable=SC2016,SC1091,SC2015
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
unset WARDENLENS_BIN WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY CAMERAS XDG_CONFIG_HOME XDG_DATA_HOME BASH_ENV ENV
fx=$(mktemp -d "${TMPDIR:-/tmp}/s1-model2.XXXXXX") || exit 1
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
export HOME="$fx/home"; mkdir -p "$HOME"
source "$here/tests/vault_stub.sh"
source "$here/lib.sh"
host c-1 192.0.2.1; model c-1 reolink/rlc-520a
for k in '' bogus MAIN 'main ' subx; do
  out=$(rtsp_path c-1 "$k" 2>/dev/null); rc=$?
  (( rc != 0 )) && [[ -z $out ]] && ok "stream kind <$k> is refused" || bad "stream kind <$k> accepted: rc $rc path $out"
done
out=$(rtsp_path c-1 2>/dev/null); rc=$?
(( rc != 0 )) && ok "a missing stream kind is refused" || bad "missing stream kind: rc $rc path $out"
# A vault failure is reported as such, distinct from a missing entry.
touch "$VAULT_STUB/.broken"
e1=$(rtsp_path c-1 main 2>&1 >/dev/null); rm -f "$VAULT_STUB/.broken"
host c-2 192.0.2.2
e2=$(rtsp_path c-2 main 2>&1 >/dev/null)
[[ ${e1//c-1/X} != "${e2//c-2/X}" ]] && ok "vault failure and missing model entry give different errors" \
  || bad "vault failure and missing entry are indistinguishable: <$e1> vs <$e2>"
exit $fail
