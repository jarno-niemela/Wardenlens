#!/usr/bin/env bash
# ONVIF PullPoint event watcher (read-only). Creates a pull-point subscription and polls it.
# Usage: onvif_pull.sh <camera-name> <total-seconds>
# Prints one line per poll: time, HTTP status, and any notification topics and SimpleItem Name=Value pairs.
# Env: ONVIF_PULL_RAW_DIR keeps the first ONVIF_PULL_RAW_MAX (default 20) raw notification bodies, redacted.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
name="$1"; total="$2"
ev() { ONVIF_RAW=1 ONVIF_TIMEOUT=30 "$here/onvif.sh" "$name" "$@"; }
r="$(ev events "<tev:CreatePullPointSubscription><tev:InitialTerminationTime>PT$((total + 60))S</tev:InitialTerminationTime></tev:CreatePullPointSubscription>")"
addr="$(grep -oE 'Address[^>]*>http://[^<]*' <<<"$r" | head -1 | sed 's/.*>//')"
if [[ -z "$addr" ]]; then echo "no pullpoint address"; exit 1; fi
# The camera chooses this address; only follow it if it points back at the camera we configured.
# shellcheck source=lib.sh
source "$here/lib.sh"
base="$(cam_onvif_url "$name")"
origin="${base%/onvif/*}"
# Compare scheme and host only: Tapo hands out the pull point on a different port of the same camera.
hostpart() { sed -E 's#^(https?://)(\[[^]]+\]|[^/:]+).*#\1\2#' <<<"$1"; }
if [[ "$(hostpart "$addr")" != "$(hostpart "$origin")" ]]; then echo "pullpoint address does not point at the configured camera host; refusing"; exit 1; fi
echo "subscribed: pullpoint created"
end=$(( $(date +%s) + total ))
while (( $(date +%s) < end )); do
  body="$(ONVIF_FULL_URL="$addr" ev full '<tev:PullMessages><tev:Timeout>PT5S</tev:Timeout><tev:MessageLimit>20</tev:MessageLimit></tev:PullMessages>' || true)"
  status="$(grep -oE '^HTTP .*' <<<"$body" | tail -1 | tr -d '[:cntrl:]')"
  # Keep the topic text and every SimpleItem as Name=Value (Source and Data items both). Attribute order
  # varies by vendor: Tapo writes Value before Name, so handle both orders.
  items="$(printf '%s' "$body" | sed 's/></>\n</g' | grep -oE '>[^<]*</wsnt:Topic>|<([A-Za-z0-9]+:)?SimpleItem [^>]*>' \
    | sed -E -e 's#^>([^<]*)</wsnt:Topic>$# \1#' \
      -e '/SimpleItem /{s#.*Name="([^"]*)".*Value="([^"]*)".*# \1=\2#;t;s#.*Value="([^"]*)".*Name="([^"]*)".*# \2=\1#}' \
    | tr -d '\n' | tr -d '[:cntrl:]' | cut -c1-400 || true)"
  printf '%s %s %s\n' "$(date -u +%T)" "$status" "$items" | sed -E 's#[0-9]{1,3}(\.[0-9]{1,3}){3}#<host>#g'
  # Optional: keep the first few raw notification bodies (redacted) as evidence.
  if [[ -n "${ONVIF_PULL_RAW_DIR:-}" ]] && grep -q 'NotificationMessage' <<<"$body"; then
    n=$(( ${n:-0} + 1 ))
    if (( n <= ${ONVIF_PULL_RAW_MAX:-20} )); then
      printf '%s\n' "$body" | sed -n '/<?xml\|Envelope/,$p' | redact >"$ONVIF_PULL_RAW_DIR/notification-$n.xml"
    fi
  fi
done
