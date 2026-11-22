#!/usr/bin/env bash
# Shared helpers for the S1 camera spike. Source this file; do not execute it.
# Credentials are read from the secret file at runtime and never printed.
# shellcheck shell=bash

SECRET_FILE="${WARDENLENS_SECRET_FILE:-$HOME/.config/wardenlens/agentdvr-cameras.secret.json}"

# cam_field <name> <jq-field>  -> prints the raw field value; fails (non-zero) if the camera or the
# field is missing, so a missing value can never become the literal string "null".
cam_field() {
  jq -er --arg n "$1" --arg f "$2" '.[] | select(.name==$n) | .[$f] | select(. != null) | tostring' "$SECRET_FILE"
}

# Camera inventory (hosts) lives outside the repo; the path is configurable.
CAMERAS_FILE="${WARDENLENS_CAMERAS:-$HOME/.config/wardenlens/cameras.local.toml}"

# cam_id <secret-file-name> -> inventory id.
cam_id() {
  case "$1" in
    IPC-BO) echo reolink-1 ;;
    "IPC-BO (2)") echo reolink-2 ;;
    XR) echo xr ;;
    C110) echo tapo ;;
    HDIPC) echo hdipc ;;
    *) echo "unknown camera" >&2; return 1 ;;
  esac
}

# cam_toml <name> <key> -> value from the inventory (empty if absent).
cam_toml() {
  python3 -I -c '
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
print(d["cameras"][sys.argv[2]].get(sys.argv[3], ""))' "$CAMERAS_FILE" "$(cam_id "$1")" "$2"
}

# cam_host <name> -> bare host from the inventory.
cam_host() { cam_toml "$1" host; }

# cam_onvif_url <name> -> ONVIF device service URL (port from inventory, else from the secret file).
cam_onvif_url() {
  local port
  port="$(cam_toml "$1" onvif_port)"
  if [[ -z "$port" ]]; then
    port="$(cam_field "$1" onvif 2>/dev/null | sed -nE 's#^https?://[^:/]+:([0-9]+)/.*#\1#p' || true)"
  fi
  printf 'http://%s%s/onvif/device_service' "$(cam_host "$1")" "${port:+:$port}"
}

# cam_creds <name> -> sets CAM_USER and CAM_PASS (shell variables only).
cam_creds() {
  CAM_USER="" CAM_PASS=""
  CAM_USER="$(cam_field "$1" login)" || { echo "unknown camera or missing login: $1" >&2; return 1; }
  # A camera without a password is allowed (empty), but an unknown camera is not (caught above).
  CAM_PASS="$(cam_field "$1" password 2>/dev/null)" || CAM_PASS=""
}

# uri_enc <string> -> percent-encoded string. The value goes to jq on stdin, never on argv.
uri_enc() { printf '%s' "$1" | jq -rRs '@uri'; }

# rtsp_url <name> <path> -> full URL including credentials. Never print this;
# pass it only to a tool, and print redact()ed output.
rtsp_url() {
  cam_creds "$1"
  printf 'rtsp://%s:%s@%s:554%s' "$(uri_enc "$CAM_USER")" "$(uri_enc "$CAM_PASS")" "$(cam_host "$1")" "$2"
}

# redact: stdin filter. Masks URL userinfo (up to the last "@" of the token, case-insensitive scheme,
# scheme kept), IPv4/IPv6 addresses, MAC addresses and serial/hardware-id values.
redact() {
  local h='[0-9A-Fa-f]{1,4}'
  sed -uE \
    -e 's#(rtsps?|https?)://[^ ]*@#\1://***@#Ig' \
    -e 's#[0-9]{1,3}(\.[0-9]{1,3}){3}#<host>#g' \
    -e 's#([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}#<mac>#g' \
    -e "s#($h:){7}$h#<ip6>#g" \
    -e "s#($h:){1,7}:($h(:$h){0,6})?#<ip6>#g" \
    -e "s#::$h(:$h){0,6}#<ip6>#g" \
    -e 's#(<[A-Za-z0-9_:]*(serial ?number|hardware ?id)[^<>]*>)[^<]+#\1<redacted>#Ig' \
    -e "s#((serial ?number|hardware ?id)[\"']? *[:=] *[\"']?)[^\"', }&<]+#\1<redacted>#Ig"
}

# Vendor RTSP paths (main|sub) by camera name; the name list is the secret file's.
rtsp_path() { # <name> <main|sub>
  case "$1" in
    IPC-BO*) [[ $2 == main ]] && echo /h264Preview_01_main || echo /h264Preview_01_sub ;;
    XR) [[ $2 == main ]] && echo '/cam/realmonitor?channel=1&subtype=0' || echo '/cam/realmonitor?channel=1&subtype=1' ;;
    C110) [[ $2 == main ]] && echo /stream1 || echo /stream2 ;;
    HDIPC) [[ $2 == main ]] && echo /11 || echo /12 ;; # from ONVIF GetStreamUri
  esac
}
