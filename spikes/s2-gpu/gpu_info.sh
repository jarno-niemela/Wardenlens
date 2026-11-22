#!/usr/bin/env bash
# GPU and CPU facts quoted in ADR 0003 (no UUID/serial). Output: results/gpu.txt
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
build_ffmpeg_image
# shellcheck disable=SC2016 # expanded inside the container
run_in_ffmpeg 'nvidia-smi --query-gpu=name,driver_version,memory.total,power.limit,clocks.max.sm,compute_cap --format=csv
echo "host cpus: $(nproc)"
grep -m1 "model name" /proc/cpuinfo' | tee "$S2_DIR/results/gpu.txt"
