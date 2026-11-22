#!/usr/bin/env bash
# ONVIF PullPoint event watcher (read-only). Creates a pull-point subscription and polls it.
# Usage: onvif_pull.sh <camera-name> <total-seconds>
# Prints one line per poll: time, HTTP status, latency, and any notification topics/items.
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
norm() { sed -E -e 's#^(http://[^/:]+):80$#\1#' -e 's#^(https://[^/:]+):443$#\1#' <<<"$1"; }
addr_origin="$(sed -E 's#^(https?://[^/]+).*#\1#' <<<"$addr")"
if [[ "$(norm "$addr_origin")" != "$(norm "$origin")" ]]; then echo "pullpoint address does not match camera origin; refusing"; exit 1; fi
echo "subscribed: pullpoint created"
end=$(( $(date +%s) + total ))
while (( $(date +%s) < end )); do
  body="$(ONVIF_FULL_URL="$addr" ev full '<tev:PullMessages><tev:Timeout>PT5S</tev:Timeout><tev:MessageLimit>20</tev:MessageLimit></tev:PullMessages>' || true)"
  status="$(grep -oE '^HTTP .*' <<<"$body" | tail -1 | tr -d '[:cntrl:]')"
  items="$(printf '%s' "$body" | sed 's/></>\n</g' | grep -E 'wsnt:Topic|SimpleItem ' | sed -E 's/<[^>]*>//' | tr -d '\n' | tr -d '[:cntrl:]' | cut -c1-400 || true)"
  printf '%s %s %s\n' "$(date -u +%T)" "$status" "$items" | sed -E 's#[0-9]{1,3}(\.[0-9]{1,3}){3}#<host>#g'
done
