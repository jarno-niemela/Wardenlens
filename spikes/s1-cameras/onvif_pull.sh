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
echo "subscribed: pullpoint created"
end=$(( $(date +%s) + total ))
while (( $(date +%s) < end )); do
  body="$(ONVIF_FULL_URL="$addr" ev full '<tev:PullMessages><tev:Timeout>PT5S</tev:Timeout><tev:MessageLimit>20</tev:MessageLimit></tev:PullMessages>' || true)"
  status="$(grep -oE '^HTTP .*' <<<"$body" | tail -1)"
  items="$(printf '%s' "$body" | sed 's/></>\n</g' | grep -E 'wsnt:Topic|SimpleItem ' | sed -E 's/<[^>]*>//' | tr -d '\n' | cut -c1-400 || true)"
  printf '%s %s %s\n' "$(date -u +%T)" "$status" "$items" | sed -E 's#[0-9]{1,3}(\.[0-9]{1,3}){3}#<host>#g'
done
