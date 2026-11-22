#!/usr/bin/env bash
# Shared helpers for the S2 GPU spike. GPU work always runs in Docker.
set -euo pipefail
S2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG_IMAGE=wl-s2-ffmpeg
GPU_ARGS=(--gpus all -e "NVIDIA_DRIVER_CAPABILITIES=compute,video,utility")

build_ffmpeg_image() { docker build -q -f "$S2_DIR/Dockerfile.ffmpeg" -t "$FFMPEG_IMAGE" "$S2_DIR" >/dev/null; }

# run_ffmpeg_container <args...>: run a shell snippet in the ffmpeg image with fixtures mounted at /fx.
run_in_ffmpeg() {
  docker run --rm "${GPU_ARGS[@]}" -v "$S2_DIR/fixtures:/fx" -v "$S2_DIR/results:/res" "$FFMPEG_IMAGE" bash -c "$1"
}
