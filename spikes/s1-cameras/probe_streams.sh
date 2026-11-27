#!/usr/bin/env bash
# One-shot ffprobe of each camera's main/sub RTSP stream: codec, resolution, fps, bitrate.
# Usage: [CAMERAS="id ..."] probe_streams.sh  (inventory ids; default: every camera with a vault host; output has credentials redacted)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"
load_cams || exit 1
for name in "${CAMS[@]}"; do
  for kind in main sub; do
    path="$(rtsp_path "$name" "$kind")" || exit 1
    url="$(rtsp_url "$name" "$path")" || exit 1
    printf '== %s %s\n' "$name" "$kind"
    timeout 25 ffprobe -v error -rtsp_transport tcp -select_streams v:0 \
      -show_entries stream=codec_name,profile,width,height,avg_frame_rate,r_frame_rate,bit_rate,pix_fmt,has_b_frames \
      -of default=nw=1 "$url" 2>&1 | redact || echo "probe failed"
  done
done
