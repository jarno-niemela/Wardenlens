#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016,SC2034
# End-to-end test of lib.sh against the real `wardenlens` binary, a temporary HOME and a synthetic vault
# (documentation addresses, made-up credentials). The real ~/.config and ~/.local/share are never read.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
root=$(cd "$here/../.." && pwd)
fx=$(mktemp -d "${TMPDIR:-/tmp}/s1-real.XXXXXX") || exit 1
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

(cd "$root" && cargo build -q -p wardenlens-cli --locked --offline) || { echo "FAIL could not build wardenlens"; exit 1; }
tdir=$(cd "$root" && cargo metadata --no-deps --format-version 1 | jq -r .target_directory)
export WARDENLENS_BIN="$tdir/debug/wardenlens"
[[ -x $WARDENLENS_BIN ]] || { echo "FAIL no binary at $WARDENLENS_BIN"; exit 1; }

PW='Sy:nth/et1c%41-pw'
export HOME="$fx/home"; mkdir -p "$HOME"; chmod 700 "$HOME"
unset WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY
"$WARDENLENS_BIN" vault init >/dev/null 2>&1 || { echo "FAIL vault init"; exit 1; }
printf '192.0.2.44\n' | "$WARDENLENS_BIN" vault set cam:reolink-1:host --kind host >/dev/null 2>&1 || { echo "FAIL set host"; exit 1; }
printf 'operator-synthetic\n%s\n' "$PW" | "$WARDENLENS_BIN" vault set cam:reolink-1:credential --kind credential >/dev/null 2>&1 || { echo "FAIL set credential"; exit 1; }

# shellcheck source=../lib.sh
source "$here/lib.sh"
cam_creds reolink-1
check "cam_creds reads the credential from the real vault" '[[ $CAM_USER == operator-synthetic && $CAM_PASS == "$PW" ]]'
check "cam_host reads the host from the real vault" '[[ $(cam_host reolink-1) == 192.0.2.44 ]]'
u=$(rtsp_url reolink-1 /h264Preview_01_main)
r=$(printf 'ffprobe: %s: 401\nhost 192.0.2.44 ok\n' "$u" | redact); rc=$?
check "redact removes the URL userinfo, password and host (real filter)" \
  '[[ $rc == 0 && $r != *"$PW"* && $r != *"$(uri_enc "$PW")"* && $r != *operator-synthetic* && $r != *192.0.2.44* && $r == *"[REDACTED]"* ]]'
check "redact leaves unrelated text alone" '[[ $(echo "frame=1 fps=25" | redact) == "frame=1 fps=25" ]]'
big=$(head -c 3000000 /dev/zero | tr '\0' 'x')
check "redact streams a large input unchanged" '[[ $(printf "%s" "$big" | redact | wc -c) == 3000000 ]]'

# Fail closed: no vault at all.
r=$(HOME="$fx/empty" bash -c 'mkdir -p "$HOME"; source "$1/lib.sh"; printf "leak 192.0.2.44\n" | redact' _ "$here" 2>/dev/null); rc=$?
check "redact without a vault prints nothing and fails" '[[ -z $r && $rc != 0 ]]'
check "cam_creds without a vault fails" '! HOME="$fx/empty" bash -c "source \"$1/lib.sh\"; cam_creds reolink-1" _ "$here" 2>/dev/null'

exit "$fail"
