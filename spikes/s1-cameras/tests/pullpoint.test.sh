#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016,SC2034
# Regression test for pullpoint_ok (lib.sh): the camera-chosen pull-point address must be on the configured
# host (any port) with no userinfo. Pure string checks with TEST-NET-1 addresses; never contacts anything.
set -uo pipefail
# Hermetic: nothing from the caller reaches the real vault, binary or a camera.
unset WARDENLENS_BIN WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY CAMERAS XDG_CONFIG_HOME XDG_DATA_HOME BASH_ENV ENV
while read -r v; do unset "$v"; done < <(compgen -e | grep "^ONVIF_" || true)
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../lib.sh
source "$here/lib.sh"
fail=0
t() { # <accept|refuse> <addr> <origin>
  local want="$1" rc=0
  pullpoint_ok "$2" "$3" || rc=$?
  if { [[ $want == accept ]] && ((rc == 0)); } || { [[ $want == refuse ]] && ((rc != 0)); }; then
    echo "ok   $want $2"
  else
    echo "FAIL $want $2 (against $3)"; fail=1
  fi
}
o="http://192.0.2.10:2020"
t accept "http://192.0.2.10:1024/event" "$o"
t accept "http://192.0.2.10/event" "$o"
t refuse "http://192.0.2.10:x@192.0.2.99:18089/pp" "$o"
t refuse "http://192.0.2.10@192.0.2.99/" "$o"
t refuse "http://192.0.2.100/" "$o"
t refuse "http://192.0.2.99:2020/" "$o"
t refuse "http://user:pw@192.0.2.10:1024/" "$o"
t refuse "ftp://192.0.2.10/" "$o"
t refuse "http://192.0.2.10.evil.example/" "$o"
t refuse "http://192.0.2.10:80a/" "$o"
t accept "http://192.0.2.10?@192.0.2.99/" "$o"  # the @ is in the query, authority is the camera
t refuse "" "$o"
t accept "https://[2001:db8::1]:8443/x" "http://[2001:db8::1]:2020"
t refuse "http://[2001:db8::2]:8443/x" "http://[2001:db8::1]:2020"
exit "$fail"
