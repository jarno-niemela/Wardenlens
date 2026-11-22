#!/usr/bin/env bash
# One-shot ffprobe of each camera's main/sub RTSP stream: codec, resolution, fps, bitrate.
# Usage: probe_streams.sh  (output has credentials redacted)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"
for name in "IPC-BO" "IPC-BO (2)" XR C110 HDIPC; do
  for kind in main sub; do
    path="$(rtsp_path "$name" "$kind")"
    url="$(rtsp_url "$name" "$path")"
    printf '== %s %s\n' "$name" "$kind"
    timeout 25 ffprobe -v error -rtsp_transport tcp -select_streams v:0 \
      -show_entries stream=codec_name,profile,width,height,avg_frame_rate,r_frame_rate,bit_rate,pix_fmt,has_b_frames \
      -of default=nw=1 "$url" 2>&1 | redact || echo "probe failed"
  done
done
