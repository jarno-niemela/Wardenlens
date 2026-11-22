#!/usr/bin/env bash
# Run the read-only Baichuan probe against a Reolink camera by name.
# Usage: run_baichuan.sh <camera-name> <listen-seconds>
# Credentials are passed via environment only to the probe process.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"
cam_creds "$1"
BC_USER="$CAM_USER" BC_PASS="$CAM_PASS" \
  "$here/baichuan-probe/target/release/baichuan-probe" "$(cam_host "$1")" "${2:-60}" 2>&1 | redact
