#!/usr/bin/env bash
# GPU facts quoted in ADR 0003 (no UUID/serial). Output: results/gpu.txt
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
build_ffmpeg_image
run_in_ffmpeg 'nvidia-smi --query-gpu=name,driver_version,memory.total,power.limit,clocks.max.sm,compute_cap --format=csv' | tee "$S2_DIR/results/gpu.txt"
