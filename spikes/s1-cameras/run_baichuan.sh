#!/usr/bin/env bash
# Run the Baichuan probe against a Reolink camera by name (read-only unless an action is given).
# Usage: run_baichuan.sh <camera-id> <listen-seconds> [abilities|https-on|https-off]
# Actions: abilities is read-only; https-on / https-off WRITE the camera's HTTPS port setting and need
# the camera owner's explicit approval first.
# Credentials are passed via environment only to the probe process.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"
cam_creds "$1"
BC_USER="$CAM_USER" BC_PASS="$CAM_PASS" \
  "$here/baichuan-probe/target/release/baichuan-probe" "$(cam_host "$1")" "${2:-60}" ${3:+"$3"} 2>&1 | redact
