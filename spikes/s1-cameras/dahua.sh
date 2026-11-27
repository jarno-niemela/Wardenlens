#!/usr/bin/env bash
# Read-only Dahua CGI probe (digest auth). Credentials go to curl via a config on a pipe, never argv.
# Usage: dahua.sh <camera-id> get <cgi-path-and-query>        one GET, body to stdout
#        dahua.sh <camera-id> attach <seconds> [codes]          long-poll eventManager attach
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"
name="$1"; mode="$2"; shift 2
cam_creds "$name"
host="$(cam_host "$name")"
# cfg_quote <value> -> value escaped for a double-quoted curl config string; refuses CR/LF.
cfg_quote() {
  case "$1" in *$'\n'* | *$'\r'*) echo "refusing credential containing a newline" >&2; return 1 ;; esac
  local v="$1"
  v="${v//\\/\\\\}"
  v="${v//\"/\\\"}"
  printf '%s' "$v"
}
user_q="$(cfg_quote "$CAM_USER")" || exit 1
pass_q="$(cfg_quote "$CAM_PASS")" || exit 1
dcurl() { curl -sS --digest -K <(printf 'user = "%s:%s"\n' "$user_q" "$pass_q") "$@" 2>&1 | redact; }
case "$mode" in
  get) dcurl --max-time 20 -w '\nHTTP %{http_code} %{time_total}s\n' "http://$host$1" ;;
  attach)
    secs="$1"; codes="${2:-[All]}"
    # -N: unbuffered; --max-time bounds the long-poll; -g: no URL globbing of [All]
    dcurl -N -g --max-time "$secs" -w '\nEND http=%{http_code} after=%{time_total}s\n' \
      "http://$host/cgi-bin/eventManager.cgi?action=attach&codes=$codes&heartbeat=${DAHUA_HEARTBEAT:-5}" ;;
  *) echo "bad mode" >&2; exit 2 ;;
esac
