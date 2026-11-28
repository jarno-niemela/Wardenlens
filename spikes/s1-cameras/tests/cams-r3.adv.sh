#!/usr/bin/env bash
# Round-3 adversarial cases for #190: rtsp_url's path guard, the call sites, and the hermeticity of the spike
# tests that scripts/gate now runs. Synthetic data only, a temporary HOME, stub vault and stub tools; never contacts
# a camera and never reads the real vault. FAIL lines are findings.
# shellcheck disable=SC2016,SC2034,SC1091,SC2329
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Hermetic: nothing from the caller reaches the real vault, binary or a camera.
unset WARDENLENS_BIN WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY CAMERAS XDG_CONFIG_HOME XDG_DATA_HOME BASH_ENV ENV
while read -r v; do unset "$v"; done < <(compgen -e | grep "^ONVIF_" || true)
fx=$(mktemp -d "${TMPDIR:-/tmp}/s1-cams3.XXXXXX") || exit 1
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

export HOME="$fx/home"; mkdir -p "$HOME"
unset CAMERAS WARDENLENS_BIN
# shellcheck source=vault_stub.sh
source "$here/tests/vault_stub.sh"
for c in cam-2 cam-6 cam-5; do cred "$c" admin "pw-synth-$c"; done
host cam-2 192.0.2.1; host cam-6 192.0.2.2; host cam-5 192.0.2.3
model cam-2 reolink/rlc-520a; model cam-6 dahua/ipc-hfw4431r-z; model cam-5 tp-link/tapo-c110

for t in ffprobe ffmpeg; do
  printf '#!/usr/bin/env bash\nfor a in "$@"; do case "$a" in rtsp://*) printf "%%s\\n" "$a" >>%q;; esac; done\nexit 1\n' \
    "$fx/contacted" >"$fx/bin/$t"
  chmod +x "$fx/bin/$t"
done
contacted() { [[ -s $fx/contacted ]]; }
reset() { rm -f "$fx/contacted"; : >"$VAULT_STUB/.argv"; }

# shellcheck source=../lib.sh
source "$here/lib.sh"

# ============================== rtsp_url path guard ==============================
for p in '' 'h264Preview_01_main' ' /x' $'\n/x' '@evil/x' ':8554/x'; do
  reset
  check "rtsp_url: path $(printf %q "$p") is refused before any vault read" \
    '! rtsp_url cam-6 "$p" >/dev/null 2>&1 && [[ ! -s $VAULT_STUB/.argv ]]'
done
reset
check "rtsp_url: a missing path argument is refused (set -u safe)" \
  '! ( set -u; rtsp_url cam-6 >/dev/null 2>&1 ) && [[ ! -s $VAULT_STUB/.argv ]]'
check "rtsp_url: the host part is exactly the vault host (path cannot move the authority)" \
  '[[ $(rtsp_url cam-6 /x) == rtsp://*@192.0.2.2:554/x ]]'

# ============================== load_cams vendor-path check ==============================
cred cam-x admin pw-synth-x; host cam-x 192.0.2.9
check "load_cams: one id with no model entry among valid ones is refused, CAMS empty" \
  '{ ! CAMERAS="cam-6 cam-x cam-5" load_cams 2>/dev/null && (( ${#CAMS[@]} == 0 )); }'
check "load_cams (default selection): a vault host id with no model entry refuses the whole selection" \
  '{ unset CAMERAS; ! load_cams 2>/dev/null && (( ${#CAMS[@]} == 0 )); }'
for s in probe_streams.sh gop_sample.sh; do
  reset; CAMERAS="cam-6 cam-x" "$here/$s" 1 >/dev/null 2>&1; rc=$?
  check "$s: a no-vendor-path id after a valid one -> non-zero, no camera contacted at all" '[[ $rc != 0 ]] && ! contacted'
done
reset; CAMERAS="cam-6 cam-x" "$here/stream_soak.sh" "$fx/soak-mixed" 1 >/dev/null 2>&1; rc=$?
check "stream_soak.sh: a no-vendor-path id after a valid one -> non-zero, nothing contacted, no out dir" \
  '[[ $rc != 0 ]] && ! contacted && [[ ! -e $fx/soak-mixed ]]'
no_entries
for c in cam-2 cam-6 cam-5; do cred "$c" admin "pw-synth-$c"; done
host cam-2 192.0.2.1; host cam-6 192.0.2.2; host cam-5 192.0.2.3
model cam-2 reolink/rlc-520a; model cam-6 dahua/ipc-hfw4431r-z; model cam-5 tp-link/tapo-c110

# A vendor-path id whose host is missing: the pre-flight fails. It should not leave an out dir behind either.
cred cam-4 admin pw-synth-9; model cam-4 reolink/rlc-520a
reset; CAMERAS="cam-4" "$here/stream_soak.sh" "$fx/soak-nohost" 1 >/dev/null 2>&1; rc=$?
check "stream_soak.sh: a missing host -> non-zero, nothing contacted" '[[ $rc != 0 ]] && ! contacted'
check "stream_soak.sh: a failed pre-flight leaves no out dir behind" '[[ ! -e $fx/soak-nohost ]]'

# run_baichuan.sh passes "$(cam_host "$1")" as an argument: its exit status is lost there.
mkdir -p "$fx/copy/baichuan-probe/target/release"
cp "$here/lib.sh" "$here/run_baichuan.sh" "$fx/copy/"
printf '#!/usr/bin/env bash\nprintf "[%%s]\\n" "$1" >>%q\n' "$fx/probe.called" >"$fx/copy/baichuan-probe/target/release/baichuan-probe"
chmod +x "$fx/copy/baichuan-probe/target/release/baichuan-probe"
"$fx/copy/run_baichuan.sh" cam-4 1 >/dev/null 2>&1; rc=$?
check "run_baichuan.sh: a camera with no vault host -> non-zero, the probe is never started" \
  '[[ $rc != 0 && ! -e $fx/probe.called ]]'

# ============================== gate wiring: hermetic against the caller's environment ==============================
# The gate runs these tests in the developer's shell. A WARDENLENS_BIN there (the documented way to point lib.sh at
# a build) must not replace the stub: with WARDENLENS_VAULT/WARDENLENS_VAULT_KEY_FILE also set, that binary reads
# the real vault. A sentinel stands in for that binary and records every call.
cat >"$fx/sentinel" <<S
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$fx/sentinel.called"
exit 2
S
chmod +x "$fx/sentinel"
for t in lib.adv.sh lib-r2.adv.sh cams-r2.adv.sh; do
  rm -f "$fx/sentinel.called"
  WARDENLENS_BIN="$fx/sentinel" WARDENLENS_VAULT=/nonexistent/vault.db WARDENLENS_VAULT_KEY_FILE=/nonexistent/key \
    timeout 300 "$here/tests/$t" >"$fx/$t.out" 2>&1; rc=$?
  check "gate spike test $t: a WARDENLENS_BIN in the caller's environment is never invoked" '[[ ! -e $fx/sentinel.called ]]'
  check "gate spike test $t: still passes with WARDENLENS_BIN set in the caller's environment" '[[ $rc == 0 ]]'
done
# CAMERAS / ONVIF_* exported by the developer must not change what the tests exercise.
for t in lib.adv.sh lib-r2.adv.sh cams-r2.adv.sh; do
  CAMERAS="cam-5" ONVIF_PORT=8000 ONVIF_MEDIA_URL=http://192.0.2.200/m ONVIF_EVENTS_URL=http://192.0.2.200/e \
    timeout 300 "$here/tests/$t" >"$fx/$t.env.out" 2>&1; rc=$?
  check "gate spike test $t: passes with CAMERAS/ONVIF_* set in the caller's environment" '[[ $rc == 0 ]]'
done

exit "$fail"
