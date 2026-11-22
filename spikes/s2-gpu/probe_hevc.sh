#!/usr/bin/env bash
# HEVC NVDEC probe on this GPU (needs fixtures from gen_fixtures.sh). Output: results/hevc.txt
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
build_ffmpeg_image
{
  echo "# HEVC NVDEC on GM204"
  # shellcheck disable=SC2016 # expanded inside the container
  run_in_ffmpeg 'ffmpeg -v error -c:v hevc_cuvid -i /fx/hevc_1920x1080.mp4 -f null - 2>&1 || echo "hevc exit=$?"
ffmpeg -v error -c:v h264_cuvid -i /fx/main_1920x1080.mp4 -frames:v 10 -f null - && echo "h264 control exit=0"' 2>&1 || true
} | sed 's/ @ 0x[0-9a-f]*//' > "$S2_DIR/results/hevc.txt"
cat "$S2_DIR/results/hevc.txt"
