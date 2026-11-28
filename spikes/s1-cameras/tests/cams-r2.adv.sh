#!/usr/bin/env bash
# Round-2 adversarial cases for camera selection in spikes/s1-cameras (#190): the load_cams choke point and the
# rtsp_path error arm, end to end through every script that enumerates cameras. Synthetic data only, a temporary
# HOME, stub vault and stub ffprobe/ffmpeg; never contacts a camera. FAIL lines are findings.
# shellcheck disable=SC2016,SC2034,SC1091,SC2329
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Hermetic: nothing from the caller reaches the real vault, binary or a camera.
unset WARDENLENS_BIN WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY CAMERAS XDG_CONFIG_HOME XDG_DATA_HOME BASH_ENV ENV
while read -r v; do unset "$v"; done < <(compgen -e | grep "^ONVIF_" || true)
fx=$(mktemp -d "${TMPDIR:-/tmp}/s1-cams2.XXXXXX") || exit 1
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

export HOME="$fx/home"; mkdir -p "$HOME"
unset CAMERAS
# shellcheck source=vault_stub.sh
source "$here/tests/vault_stub.sh"
for c in cam-2 cam-6; do cred "$c" admin "pw-synth-$c"; done
host cam-2 192.0.2.1; host cam-6 192.0.2.2
model cam-2 reolink/rlc-520a; model cam-6 dahua/ipc-hfw4431r-z
# cam-x: a valid inventory id with a host and a credential, but no vendor RTSP path in rtsp_path.
cred cam-x admin pw-synth-x; host cam-x 192.0.2.9

for t in ffprobe ffmpeg; do
  printf '#!/usr/bin/env bash\nfor a in "$@"; do case "$a" in rtsp://*) printf "%%s\\n" "$a" >>%q;; esac; done\nexit 1\n' \
    "$fx/contacted" >"$fx/bin/$t"
  chmod +x "$fx/bin/$t"
done
contacted() { [[ -s $fx/contacted ]]; }
bare_host() { grep -q '@192\.0\.2\.9:554$' "$fx/contacted" 2>/dev/null; }
reset() { rm -f "$fx/contacted"; : >"$VAULT_STUB/.argv"; }

# ============================== rtsp_path error arm, end to end ==============================
reset; CAMERAS="cam-x" "$here/gop_sample.sh" 1 >/dev/null 2>&1; rc=$?
check "gop_sample.sh: an id with no vendor path is not opened at the bare host" '! bare_host'
check "gop_sample.sh: an id with no vendor path -> non-zero exit" '[[ $rc != 0 ]]'

mkdir -p "$fx/s1"; reset
CAMERAS="cam-x" timeout 60 "$here/stream_soak.sh" "$fx/s1" 1 >/dev/null 2>&1; rc=$?
check "stream_soak.sh: an id with no vendor path is not opened at the bare host" '! bare_host'
check "stream_soak.sh: the pre-flight check rejects an id with no vendor path (non-zero, nothing contacted)" \
  '[[ $rc != 0 ]] && ! contacted'

# Default selection (CAMERAS unset): a vault host entry for an id with no vendor path.
reset; "$here/gop_sample.sh" 1 >/dev/null 2>&1
check "gop_sample.sh (default selection): a vault host id with no vendor path is not opened at the bare host" '! bare_host'
mkdir -p "$fx/s2"; reset
timeout 60 "$here/stream_soak.sh" "$fx/s2" 1 >/dev/null 2>&1; rc=$?
check "stream_soak.sh (default selection): pre-flight fails before contacting any camera" '[[ $rc != 0 ]] && ! contacted'
reset; "$here/probe_streams.sh" >/dev/null 2>&1
check "probe_streams.sh (default selection): a vault host id with no vendor path is not opened at the bare host" '! bare_host'
no_entries
for c in cam-2 cam-6; do cred "$c" admin "pw-synth-$c"; done
host cam-2 192.0.2.1; host cam-6 192.0.2.2
model cam-2 reolink/rlc-520a; model cam-6 dahua/ipc-hfw4431r-z

# shellcheck source=../lib.sh
source "$here/lib.sh"

# ============================== load_cams ==============================
check "load_cams: whitespace-only CAMERAS fails, it does not fall back to every camera" \
  '! CAMERAS=" 	 " load_cams 2>/dev/null'
check "load_cams: CRLF-terminated CAMERAS entry is refused" '! CAMERAS=$'"'"'cam-6\r'"'"' load_cams 2>/dev/null'
check "load_cams: a duplicate across a newline/tab is refused" '! CAMERAS=$'"'"'cam-6\n\txr'"'"' load_cams 2>/dev/null'
check "load_cams: a duplicate leaves CAMS empty" '{ CAMERAS="cam-6 cam-2 cam-6" load_cams 2>/dev/null; (( ${#CAMS[@]} == 0 )); }'
check "load_cams: an invalid id leaves CAMS empty after an earlier success" \
  '{ CAMERAS="cam-6" load_cams; CAMERAS="cam-6 Bad" load_cams 2>/dev/null; (( ${#CAMS[@]} == 0 )); }'
check "load_cams: a second call replaces, not appends" \
  '{ CAMERAS="cam-6" load_cams; CAMERAS="cam-2" load_cams; [[ ${CAMS[*]} == cam-2 ]]; }'
check "load_cams: an invalid id after many valid ones is refused" \
  '! CAMERAS="cam-6 cam-2 a b c d e f g h Bad" load_cams 2>/dev/null'
check "load_cams: default selection is the vault host ids, each once" \
  '{ unset CAMERAS; load_cams && [[ $(printf "%s\n" "${CAMS[@]}" | sort | tr "\n" " ") == "cam-2 cam-6 " ]]; }'
touch "$VAULT_STUB/.broken"
check "load_cams: unusable vault -> non-zero, CAMS empty" '{ unset CAMERAS; ! load_cams 2>/dev/null && (( ${#CAMS[@]} == 0 )); }'
rm -f "$VAULT_STUB/.broken"
no_entries
check "load_cams: empty vault and no CAMERAS -> non-zero" '{ unset CAMERAS; ! load_cams 2>/dev/null; }'

exit "$fail"
