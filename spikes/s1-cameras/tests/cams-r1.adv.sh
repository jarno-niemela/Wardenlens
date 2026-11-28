#!/usr/bin/env bash
# Adversarial cases for camera selection in spikes/s1-cameras (#190): cam_id, cam_ids, selected_cams and the three
# scripts that enumerate cameras (probe_streams.sh, gop_sample.sh, stream_soak.sh). Synthetic data only, a temporary
# HOME, stub ffprobe/ffmpeg; never contacts a camera. FAIL lines are findings.
# shellcheck disable=SC2016,SC2034,SC1091,SC2329
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
root=$(cd "$here/../.." && pwd)
# Hermetic: nothing from the caller reaches the real vault, binary or a camera.
unset WARDENLENS_BIN WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY CAMERAS XDG_CONFIG_HOME XDG_DATA_HOME BASH_ENV ENV
while read -r v; do unset "$v"; done < <(compgen -e | grep "^ONVIF_" || true)
fx=$(mktemp -d "${TMPDIR:-/tmp}/s1-cams.XXXXXX") || exit 1
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# rustup/cargo keep their state under the real HOME: pin it before HOME is replaced.
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export HOME="$fx/home"; mkdir -p "$HOME"
unset CAMERAS
# shellcheck source=vault_stub.sh
source "$here/tests/vault_stub.sh"
for c in cam-2 cam-6 cam-5; do cred "$c" admin "pw-synth-$c"; done
host cam-2 192.0.2.1; host cam-6 192.0.2.2; host cam-5 192.0.2.3
model cam-2 reolink/rlc-520a; model cam-6 dahua/ipc-hfw4431r-z; model cam-5 tp-link/tapo-c110

# Stub ffprobe/ffmpeg: record every URL they were handed (a camera contact), then fail fast.
for t in ffprobe ffmpeg; do
  printf '#!/usr/bin/env bash\nfor a in "$@"; do case "$a" in rtsp://*) printf "%%s\\n" "$a" >>%q;; esac; done\nexit 1\n' \
    "$fx/contacted" >"$fx/bin/$t"
  chmod +x "$fx/bin/$t"
done
contacted() { [[ -s $fx/contacted ]]; }
reset() { rm -f "$fx/contacted"; : >"$VAULT_STUB/.argv"; }

# shellcheck source=../lib.sh
source "$here/lib.sh"

# ============================== selected_cams ==============================
check "selected_cams: default lists every vault host id" '[[ $(selected_cams | sort | tr "\n" " ") == "cam-2 cam-5 cam-6 " ]]'
check "selected_cams: CAMERAS picks exactly those ids, in order" '[[ $(CAMERAS="cam-6 cam-5" selected_cams | tr "\n" " ") == "cam-6 cam-5 " ]]'
check "selected_cams: a display name in CAMERAS is refused" '! CAMERAS="Front Door Cam" selected_cams >/dev/null 2>&1'
for v in 'cam-6;touch PWNED' '$(touch PWNED)' '`touch PWNED`' '../cam-6' 'CAM-X' 'Cam-Y1' 'cam-6:host' '-cam-6' 'cam-6_1' $'cam-6\x01'; do
  check "selected_cams: hostile CAMERAS entry refused, nothing run: $(printf %q "$v")" \
    '( cd "$fx" && ! CAMERAS="$v" selected_cams >/dev/null 2>&1 ) && [[ ! -e $fx/PWNED ]]'
done
# A glob character in CAMERAS must not be expanded against the current directory.
mkdir -p "$fx/cwd"; touch "$fx/cwd/cam-6" "$fx/cwd/cam-5"
check "selected_cams: CAMERAS='*' is refused, not glob-expanded to file names in the cwd" \
  '( cd "$fx/cwd" && ! CAMERAS="*" selected_cams >/dev/null 2>&1 )'
check "selected_cams: CAMERAS='?r' is refused, not glob-expanded" \
  '( cd "$fx/cwd" && ! CAMERAS="?r" selected_cams >/dev/null 2>&1 )'

# ============================== scripts fail closed ==============================
for s in probe_streams.sh gop_sample.sh; do
  reset; CAMERAS="cam-6 Front" "$here/$s" 1 >/dev/null 2>&1; rc=$?
  check "$s: one invalid id in CAMERAS aborts before contacting any camera" '[[ $rc != 0 ]] && ! contacted'
  reset; CAMERAS="ghost" "$here/$s" 1 >/dev/null 2>&1; rc=$?
  check "$s: an id with no vault entries -> non-zero, no camera contacted" '[[ $rc != 0 ]] && ! contacted'
  reset; touch "$VAULT_STUB/.broken"; "$here/$s" 1 >/dev/null 2>&1; rc=$?; rm -f "$VAULT_STUB/.broken"
  check "$s: unusable vault -> non-zero, no camera contacted" '[[ $rc != 0 ]] && ! contacted'
  reset; out=$(CAMERAS="cam-6" "$here/$s" 1 2>&1)
  check "$s: output and stub argv carry no credential or host" \
    '[[ $out != *pw-synth* && $out != *192.0.2.2* ]] && ! grep -qF -e pw-synth -e 192.0.2 "$VAULT_STUB/.argv"'
done
mkdir -p "$fx/soak1"; reset
CAMERAS="cam-6 Front" "$here/stream_soak.sh" "$fx/soak1" 1 >/dev/null 2>&1; rc=$?
check "stream_soak.sh: one invalid id in CAMERAS aborts before contacting any camera" '[[ $rc != 0 ]] && ! contacted'
reset; touch "$VAULT_STUB/.broken"; "$here/stream_soak.sh" "$fx/soak2" 1 >/dev/null 2>&1; rc=$?; rm -f "$VAULT_STUB/.broken"
check "stream_soak.sh: unusable vault -> non-zero, no camera contacted" '[[ $rc != 0 ]] && ! contacted'
# Duplicates: two parallel writers on the same <cam>_<kind>.log would interleave or truncate each other.
reset; CAMERAS="cam-6 cam-6" "$here/stream_soak.sh" "$fx/soak3" 1 >/dev/null 2>&1
check "stream_soak.sh: a duplicate id in CAMERAS is refused or de-duplicated (one summary row per stream)" \
  '[[ ! -e $fx/soak3/summary.tsv ]] || [[ $(grep -c "^cam-6_main" "$fx/soak3/summary.tsv") == 1 ]]'

# An id that passes cam_id but has no vendor path must not be opened at the bare host (rtsp://...@host:554).
cred cam-x admin pw-synth-x; host cam-x 192.0.2.9
check "rtsp_path: an id with no known vendor path is an error, not an empty path" '! p=$(rtsp_path cam-x main 2>/dev/null) || [[ -n $p ]]'
cred cam-y admin pw-synth-y; host cam-y 192.0.2.8; model cam-y acme/no-such-model
check "rtsp_path: a model with no known path is an error" '! p=$(rtsp_path cam-y main 2>/dev/null) || [[ -n $p ]]'
check "rtsp_path: model-based paths (rtt/reolink/tp-link/dahua), same for any id" \
  '[[ $(rtsp_path cam-2 sub) == /h264Preview_01_sub && $(rtsp_path cam-5 main) == /stream1 && $(rtsp_path cam-6 sub) == *subtype=1 ]]'
check "rtsp_path: the path follows the model, not the id (cam-2 re-modelled)" \
  '{ model cam-2 tp-link/tapo-c110; [[ $(rtsp_path cam-2 main) == /stream1 ]]; r=$?; model cam-2 reolink/rlc-520a; (( r == 0 )); }'
check "rtsp_path: a malformed model entry is refused" '{ model cam-2 "../x"; ! rtsp_path cam-2 main 2>/dev/null; r=$?; model cam-2 reolink/rlc-520a; (( r == 0 )); }'
reset; CAMERAS="cam-x" "$here/probe_streams.sh" >/dev/null 2>&1
check "probe_streams.sh: an id with no vendor path is not opened at the bare host" '! grep -q "@192.0.2.9:554$" "$fx/contacted" 2>/dev/null'
for s in gop_sample.sh stream_soak.sh; do
  reset; if [[ $s == stream_soak.sh ]]; then CAMERAS="cam-x" "$here/$s" "$fx/novp-$s" 1 >/dev/null 2>&1; else CAMERAS="cam-x" "$here/$s" 1 >/dev/null 2>&1; fi
  check "$s: an id with no vendor path is not opened at the bare host" '! grep -q "@192.0.2.9:554$" "$fx/contacted" 2>/dev/null'
done

# ============================== cam_ids against the real binary ==============================
(cd "$root" && timeout 600 cargo build -q -p wardenlens-cli --locked --offline) || { echo "FAIL could not build wardenlens"; exit 1; }
tdir=$(cd "$root" && cargo metadata --no-deps --format-version 1 | jq -r .target_directory)
real="$tdir/debug/wardenlens"
export HOME="$fx/realhome"; mkdir -p "$HOME"; chmod 700 "$HOME"
unset WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY
"$real" vault init >/dev/null 2>&1 || { echo "FAIL vault init"; exit 1; }
for id in cam:cam-2:host cam:cam-6:host cam:front_door:host cam:side.yard:host; do
  printf '192.0.2.77\n' | "$real" vault set "$id" --kind host >/dev/null 2>&1 || { echo "FAIL set $id"; exit 1; }
done
printf 'Synthetic Porch\n' | "$real" vault set cam:cam-6:name --kind display-name >/dev/null 2>&1
got=$(WARDENLENS_BIN="$real" bash -c 'source "$1/lib.sh"; cam_ids' _ "$here" 2>"$fx/ids.err" | sort | tr '\n' ' ')
check "cam_ids (real binary): lists the inventory host ids, ignores other kinds" '[[ $got == *"cam-2 "* && $got == *"cam-6 "* && $got != *name* ]]'
check "cam_ids (real binary): a vault host id it cannot use (cam:front_door:host, cam:side.yard:host) is reported, not dropped silently" \
  '[[ $got == *front_door* || -s $fx/ids.err ]]'
out=$(WARDENLENS_BIN="$real" bash -c 'source "$1/lib.sh"; cam_ids' _ "$here" 2>&1)
check "cam_ids (real binary): prints no value (host or display name)" '[[ $out != *192.0.2.77* && $out != *Synthetic* ]]'
check "selected_cams (no vault at all): fails" \
  '! HOME="$fx/none" WARDENLENS_BIN="$real" bash -c "mkdir -p \"\$HOME\"; source \"\$1/lib.sh\"; selected_cams" _ "$here" >/dev/null 2>&1'

exit "$fail"
