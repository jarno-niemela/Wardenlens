#!/usr/bin/env bash
# Shared helpers for the S1 camera spike. Source this file; do not execute it.
# Hosts and credentials come from the Wardenlens vault (ADR 0006, #76) through `wardenlens vault get`: the
# entry id is on argv, the value is read from the command's stdout into a shell variable and never printed.
# Output that may contain a vault value goes through `redact` (`wardenlens vault redact`, exact match).
# The legacy secret JSON and inventory TOML are read only by `wardenlens vault import-legacy`, never here.
# shellcheck shell=bash

# The binary: `wardenlens` on PATH, or WARDENLENS_BIN (a path, for a build that is not installed).
wl() { command "${WARDENLENS_BIN:-wardenlens}" "$@"; }

# vault_value <entry-id> [field] -> prints the value with no trailing text. Fails (non-zero, nothing printed) if the
# vault, the key or the entry is missing. A failure is never turned into an empty or literal "null" value.
vault_value() { # <id> [username|password]
  if [[ -n "${2:-}" ]]; then wl vault get "$1" --field "$2"; else wl vault get "$1"; fi
}

# cam_id <inventory-id> -> the inventory id, checked (lower case, digits, hyphen). Display names are not accepted and
# no name->id mapping lives in the tree: site-specific names stay in the vault (docs/DEV_VAULT.md).
cam_id() {
  if [[ $1 =~ ^[a-z0-9][a-z0-9-]*$ ]]; then echo "$1"; else echo "unknown camera" >&2; return 1; fi
}

# cam_ids -> the inventory ids that have a host entry in the vault (cam:<id>:host), one per line. `vault list` prints
# ids and kinds, never values.
cam_ids() {
  local out
  out="$(wl vault list)" || return 1
  awk -F'\t' '$1 ~ /^cam:[a-z0-9][a-z0-9-]*:host$/ { split($1, p, ":"); print p[2] }' <<<"$out"
}

# selected_cams -> the inventory ids in $CAMERAS (space separated) if set, else cam_ids; one per line, each checked.
selected_cams() {
  local c
  if [[ -n ${CAMERAS:-} ]]; then for c in $CAMERAS; do cam_id "$c" || return 1; done; else cam_ids; fi
}

# cam_host <name> -> bare host from the vault (entry cam:<id>:host).
cam_host() {
  local id
  id="$(cam_id "$1")" || return 1
  vault_value "cam:$id:host"
}

# cam_onvif_url <name> -> ONVIF device service URL. The port is public configuration, not a vault value: it is
# ONVIF_PORT if set, else the optional vault entry cam:<id>:onvif_port (set it with `vault set --kind other`), else none.
cam_onvif_url() {
  local port="${ONVIF_PORT:-}" id host
  id="$(cam_id "$1")" || return 1
  if [[ -z "$port" ]]; then port="$(vault_value "cam:$id:onvif_port" 2>/dev/null || true)"; fi
  [[ -z "$port" || $port =~ ^[0-9]{1,5}$ ]] || { echo "onvif port is not a number" >&2; return 1; }
  host="$(cam_host "$1")" && [[ -n "$host" ]] || { echo "no host for camera: $1" >&2; return 1; }
  printf 'http://%s%s/onvif/device_service' "$host" "${port:+:$port}"
}

# pullpoint_ok <addr> <origin> -> 0 only if <addr> is an http(s) URL on exactly the host of <origin> (any port, no
# userinfo). The camera chooses the pull-point address; curl would send the WS-Security digest to whatever it names.
pullpoint_ok() {
  local re='^https?://([^/?#]*)' a o
  [[ $1 =~ $re ]] || return 1
  a="${BASH_REMATCH[1]}"
  [[ $2 =~ $re ]] || return 1
  o="${BASH_REMATCH[1]}"
  [[ $a != *@* && $o != *@* ]] || return 1
  [[ $o =~ ^(\[[0-9A-Fa-f:.]+\]|[^:]+)(:[0-9]+)?$ ]] || return 1
  local host="${BASH_REMATCH[1]}" port_re='^(:[0-9]+)?$' rest
  [[ $a == "$host"* ]] || return 1
  rest="${a#"$host"}"
  [[ $rest =~ $port_re ]]
}

# cam_creds <name> -> sets CAM_USER and CAM_PASS (shell variables only), from the vault entry cam:<id>:credential.
cam_creds() {
  local id
  CAM_USER="" CAM_PASS=""
  id="$(cam_id "$1")" || { echo "unknown camera: $1" >&2; return 1; }
  # A trailing "x" sentinel keeps trailing newlines, which $(...) would otherwise strip silently.
  CAM_USER="$(vault_value "cam:$id:credential" username && printf x)" || { echo "no credential in the vault for camera: $1" >&2; CAM_USER=""; return 1; }
  CAM_USER="${CAM_USER%x}"
  # A credential entry has both fields (the password may be empty); a failure here is a failure, not "".
  CAM_PASS="$(vault_value "cam:$id:credential" password && printf x)" || { echo "no password in the vault for camera: $1" >&2; CAM_USER="" CAM_PASS=""; return 1; }
  CAM_PASS="${CAM_PASS%x}"
}

# uri_enc <string> -> percent-encoded string. The value goes to jq on stdin, never on argv.
uri_enc() { printf '%s' "$1" | jq -rRs '@uri'; }

# rtsp_url <name> <path> -> full URL including credentials. Never print this;
# pass it only to a tool, and print redact()ed output. The URL is on the ffmpeg/ffprobe argv: the accepted
# spike-only exception of ADR 0002 (those tools take the credentials nowhere else).
rtsp_url() {
  local host
  cam_creds "$1" || return 1
  host="$(cam_host "$1")" && [[ -n "$host" ]] || { echo "no host for camera: $1" >&2; return 1; }
  printf 'rtsp://%s:%s@%s:554%s' "$(uri_enc "$CAM_USER")" "$(uri_enc "$CAM_PASS")" "$host" "$2"
}

# redact: stdin filter. Two layers, in this order:
#  1. `wardenlens vault redact`: every value in the vault (the percent, base64, hex and URL userinfo renderings and
#     every spelling of a stored address) becomes [REDACTED]. The enforcement; it is an exact match, not a guess.
#  2. Defence in depth behind it, the old shape masks: URL userinfo (up to the last "@" of the token, scheme kept),
#     IPv4/IPv6 addresses, MAC addresses and serial/hardware-id values. They catch what is not in the vault; they
#     are never the enforcement (a shape cannot know a value).
# Fails closed: pipefail, and layer 2 sees nothing if layer 1 fails, so if the binary or the vault is missing or
# unusable nothing is written and the status is non-zero. Unredacted output never reaches a log.
redact() {
  local h='[0-9A-Fa-f]{1,4}'
  (
    set -o pipefail
    wl vault redact | sed -uE \
      -e 's#(rtsps?|https?)://[^ ]*@#\1://***@#Ig' \
      -e 's#[0-9]{1,3}(\.[0-9]{1,3}){3}#<host>#g' \
      -e 's#([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}#<mac>#g' \
      -e "s#(^|[^0-9A-Za-z_:])($h:){7}$h#\1<ip6>#g" \
      -e "s#(^|[^0-9A-Za-z_:])($h:){1,7}:($h(:$h){0,6})?#\1<ip6>#g" \
      -e "s#(^|[^0-9A-Za-z_:])::$h(:$h){0,6}#\1<ip6>#g" \
      -e 's#(<[A-Za-z0-9_:]*(serial[ _]?number|hardware[ _]?id)[^<>]*>)[^<]+#\1<redacted>#Ig' \
      -e "s#((serial[ _]?number|hardware[ _]?id)[\"']? *[:=] *[\"']?)[^\"', }&<]+#\1<redacted>#Ig"
  ) || { echo "redact: filter unavailable; output suppressed" >&2; return 1; }
}

# Vendor RTSP paths (main|sub) by camera; takes an inventory id.
rtsp_path() { # <name> <main|sub>
  local id
  id="$(cam_id "$1")" || return 1
  case "$id" in
    reolink-*) [[ $2 == main ]] && echo /h264Preview_01_main || echo /h264Preview_01_sub ;;
    xr) [[ $2 == main ]] && echo '/cam/realmonitor?channel=1&subtype=0' || echo '/cam/realmonitor?channel=1&subtype=1' ;;
    tapo) [[ $2 == main ]] && echo /stream1 || echo /stream2 ;;
    hdipc) [[ $2 == main ]] && echo /11 || echo /12 ;; # from ONVIF GetStreamUri
  esac
}
