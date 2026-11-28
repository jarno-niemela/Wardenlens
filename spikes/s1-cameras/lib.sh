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
# ids and kinds, never values. A :host entry whose id is not a usable inventory id is reported on stderr, not dropped.
cam_ids() {
  local out
  out="$(wl vault list)" || return 1
  awk -F'\t' '
    $1 ~ /^cam:[a-z0-9][a-z0-9-]*:host$/ { split($1, p, ":"); print p[2]; next }
    $1 ~ /^cam:.*:host$/ { printf "cam_ids: skipping a vault host entry whose id is not a usable inventory id: %s\n", $1 > "/dev/stderr" }
  ' <<<"$out"
}

# selected_cams -> the inventory ids in $CAMERAS (whitespace separated, never glob-expanded) if set, else cam_ids; one
# per line. Non-zero, printing nothing, if any id is invalid.
selected_cams() {
  local c list=() all=""
  if [[ -n ${CAMERAS:-} ]]; then
    IFS=$' \t\n' read -r -d '' -a list <<<"$CAMERAS" || true
    for c in "${list[@]}"; do all+="$(cam_id "$c")"$'\n' || return 1; done
    printf '%s' "$all"
  else
    cam_ids
  fi
}

# load_cams -> fills the global array CAMS with the selected inventory ids. The one choke point for the scripts that
# enumerate cameras: non-zero (CAMS empty) on an invalid or duplicate id, an id with no model entry or no path for its model, a vault failure or an empty selection.
load_cams() {
  local out id
  declare -A seen=()
  CAMS=()
  out="$(selected_cams)" || { echo "no usable camera selection" >&2; return 1; }
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    if [[ -n ${seen[$id]:-} ]]; then CAMS=(); echo "duplicate camera id: $id" >&2; return 1; fi
    rtsp_path "$id" main >/dev/null || { CAMS=(); return 1; }
    seen[$id]=1; CAMS+=("$id")
  done <<<"$out"
  (( ${#CAMS[@]} > 0 )) || { echo "no cameras: set CAMERAS or add cam:<id>:host vault entries" >&2; return 1; }
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
  [[ ${2:-} == /* ]] || { echo "no RTSP path for camera: $1" >&2; return 1; }
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

# cam_model <id> -> the camera's catalogue slug "<vendor>/<model>" (cameras/<vendor>/<model>.toml), from the optional
# vault entry cam:<id>:model (`vault set --kind other`). Which camera is which model is a site fact and stays in the
# vault (ARCH-7); this file knows only model-level facts.
cam_model() {
  local id m
  id="$(cam_id "$1")" || return 1
  # A vault failure (stderr shown, say so) is reported separately from a missing or malformed entry.
  if ! m="$(vault_value "cam:$id:model")"; then
    echo "no model entry for camera: $id (the vault lookup of cam:$id:model failed; set it to <vendor>/<model>, e.g. reolink/rlc-520a)" >&2
    return 1
  fi
  [[ $m =~ ^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*$ ]] || {
    echo "malformed model entry for camera: $id (cam:$id:model must be <vendor>/<model>)" >&2
    return 1
  }
  echo "$m"
}

# Model RTSP paths (main|sub) by catalogue model; takes an inventory id and looks its model up (cam_model). A model
# with no known path is an error. Paths are the cameras/*.toml ones.
rtsp_path() { # <id> <main|sub>
  local id model
  [[ ${2:-} == main || ${2:-} == sub ]] || { echo "rtsp_path: the stream kind must be main or sub" >&2; return 1; }
  id="$(cam_id "$1")" || return 1
  model="$(cam_model "$id")" || return 1
  case "$model" in
    reolink/rlc-520a) [[ $2 == main ]] && echo /h264Preview_01_main || echo /h264Preview_01_sub ;;
    dahua/ipc-hfw4431r-z) [[ $2 == main ]] && echo '/cam/realmonitor?channel=1&subtype=0' || echo '/cam/realmonitor?channel=1&subtype=1' ;;
    tp-link/tapo-c110) [[ $2 == main ]] && echo /stream1 || echo /stream2 ;;
    rtt/rtt-8700) [[ $2 == main ]] && echo /11 || echo /12 ;; # from ONVIF GetStreamUri
    *) echo "no RTSP path for model: $model (camera $id)" >&2; return 1 ;;
  esac
}
