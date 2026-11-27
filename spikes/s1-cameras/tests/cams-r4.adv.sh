#!/usr/bin/env bash
# Round-4 adversarial cases for #190: hermeticity of the gated spike tests against the caller's XDG variables (which
# the real binary reads). Synthetic data only, temporary HOME and XDG directories; never contacts a camera and never
# reads the real vault. FAIL lines are findings.
# shellcheck disable=SC2016,SC2034,SC1091
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
unset WARDENLENS_BIN WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY CAMERAS XDG_CONFIG_HOME XDG_DATA_HOME BASH_ENV ENV
while read -r v; do unset "$v"; done < <(compgen -e | grep "^ONVIF_" || true)
fx=$(mktemp -d "${TMPDIR:-/tmp}/s1-cams4.XXXXXX") || exit 1
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# ============================== gate wiring: XDG variables from the caller ==============================
# The real `wardenlens` reads XDG_DATA_HOME / XDG_CONFIG_HOME and refuses when they do not match $HOME. cams-r1 (gated)
# swaps HOME for a temporary one, so a developer who exports XDG_CONFIG_HOME="$HOME/.config" (a common dotfile
# line, the default location) gets a red gate. Reproduce the gate's own invocation (its env -u list) with
# throw-away directories standing in for the developer's XDG directories.
mkdir -p "$fx/xdg/config" "$fx/xdg/data"
gate_env=(env -u WARDENLENS_BIN -u WARDENLENS_VAULT -u WARDENLENS_VAULT_KEY_FILE -u WARDENLENS_VAULT_KEY -u CAMERAS)
for var in XDG_CONFIG_HOME XDG_DATA_HOME; do
  d="$fx/xdg/config"; [[ $var == XDG_DATA_HOME ]] && d="$fx/xdg/data"
  "${gate_env[@]}" "$var=$d" timeout 900 "$here/tests/cams-r1.adv.sh" >"$fx/r1.$var.out" 2>&1; rc=$?
  check "gate spike test cams-r1.adv.sh: passes with $var exported by the caller" '[[ $rc == 0 ]]'
  check "gate spike test cams-r1.adv.sh: writes nothing into the caller's $var" '[[ -z $(ls -A "$d") ]]'
done

exit "$fail"
