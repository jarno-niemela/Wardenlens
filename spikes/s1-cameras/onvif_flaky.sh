#!/usr/bin/env bash
# Characterise ONVIF reliability of a flaky camera: N rounds of unauthenticated (GetSystemDateAndTime)
# and authenticated (GetDeviceInformation) requests with a 10 s timeout, fresh TCP connection each.
# Usage: onvif_flaky.sh <camera-id> <rounds> <sleep-seconds>
# Output TSV: round, request, http_code, seconds   (summarise with awk)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"
name="$1"; rounds="$2"; pause="$3"
url="$(cam_onvif_url "$name")"
printf 'round\trequest\thttp\tseconds\n'
for ((i = 1; i <= rounds; i++)); do
  r="$(curl -sS -o /dev/null --max-time 10 -w '%{http_code}\t%{time_total}' \
    -H 'Content-Type: application/soap+xml' \
    --data '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>' \
    "$url" 2>/dev/null || true)"
  printf '%s\tnoauth\t%s\n' "$i" "${r:-000	10}"
  out="$(ONVIF_TIMEOUT=10 "$here/onvif.sh" "$name" device '<tds:GetDeviceInformation/>' 2>&1 || true)"
  code="$(grep -oE '^HTTP [0-9]+ [0-9.]+' <<<"$out" | tail -1 | awk '{print $2"\t"$3}')"
  printf '%s\tauth\t%s\n' "$i" "${code:-000	10}"
  sleep "$pause"
done
