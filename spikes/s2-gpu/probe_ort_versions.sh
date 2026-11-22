#!/usr/bin/env bash
# Probe which onnxruntime-gpu versions load the CUDA EP and run a YOLO model on this GPU (sm_52).
# Usage: probe_ort_versions.sh <ort>:<cudnn> ...   e.g. 1.23.2:9.5.1.17   Output: results/ort_probe.txt (overwritten)
# A failing probe is the measurement, not a script error; its exit code is recorded in the output.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
res="$S2_DIR/results/ort_probe.txt"
: > "$res"
for spec in "$@"; do
  v=${spec%%:*}
  c=${spec##*:}
  tag="$v-cudnn$c"
  echo "=== onnxruntime-gpu $v + cudnn $c" | tee -a "$res"
  if ! docker build -q --build-arg ORT_VERSION="$v" --build-arg CUDNN_VERSION="$c" -f "$S2_DIR/Dockerfile.ort" -t "wl-s2-ort-$tag" "$S2_DIR" > /dev/null 2>&1; then
    echo "image build failed" | tee -a "$res"
    continue
  fi
  rc=0
  out=$(docker run --rm "${GPU_ARGS[@]}" -v "$S2_DIR:/s:ro" "wl-s2-ort-$tag" /opt/v/bin/python /s/ort_probe.py /s/models/yolov8n_320.onnx 2>&1) || rc=$?
  printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -E 'cudnn \(|onnxruntime |Failed to load|Require|session providers|run OK|rror' | cut -c1-400 | tee -a "$res" || true
  echo "probe exit code: $rc" | tee -a "$res"
  docker run --rm "wl-s2-ort-$tag" /opt/v/bin/pip freeze > "$S2_DIR/results/pip-freeze-ort-$tag.txt"
done
