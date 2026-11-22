#!/usr/bin/env bash
# Minimal ONVIF SOAP client with WS-Security UsernameToken (PasswordDigest).
# Usage: onvif.sh <camera-name> <service-path-key> <soap-body-xml> [curl-extra...]
#   service key: device | media | events
# Prints the response body (and "HTTP <code> <seconds>s" on stderr). Read-only requests only.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"

name="$1"; svc="$2"; body="$3"; shift 3
cam_creds "$name"
base="$(cam_onvif_url "$name")"
origin="${base%/onvif/*}"
case "$svc" in
  device) url="$base" ;;
  media) url="${ONVIF_MEDIA_URL:-$origin/onvif/media_service}" ;;
  events) url="${ONVIF_EVENTS_URL:-$origin/onvif/event_service}" ;;
  full) url="$ONVIF_FULL_URL" ;;
  *) echo "bad service" >&2; exit 2 ;;
esac

nonce_hex="$(openssl rand -hex 16)"
created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
nonce_b64="$(printf '%s' "$nonce_hex" | xxd -r -p | base64)"
digest="$({ printf '%s' "$nonce_hex" | xxd -r -p; printf '%s%s' "$created" "$CAM_PASS"; } | openssl dgst -sha1 -binary | base64)"

envelope=$(cat <<XML
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
 xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
<s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<UsernameToken><Username>${CAM_USER}</Username>
<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">${digest}</Password>
<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${nonce_b64}</Nonce>
<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${created}</Created>
</UsernameToken></Security></s:Header>
<s:Body>${body}</s:Body></s:Envelope>
XML
)
# ONVIF_RAW=1 skips host masking (used by scripts that must parse addresses from responses).
filter() { if [[ -n "${ONVIF_RAW:-}" ]]; then cat; else redact; fi; }
curl -sS --max-time "${ONVIF_TIMEOUT:-15}" -H 'Content-Type: application/soap+xml; charset=utf-8' \
  -w '\nHTTP %{http_code} %{time_total}s\n' --data-binary "$envelope" "$@" "$url" 2>&1 | filter
