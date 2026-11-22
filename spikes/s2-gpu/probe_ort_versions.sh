#!/usr/bin/env bash
# Probe which onnxruntime-gpu versions load the CUDA EP and run a YOLO model on this GPU (sm_52).
# Usage: probe_ort_versions.sh <ort>:<cudnn> ...   e.g. 1.23.2:9.5.1.17   Output appended to results/ort_probe.txt
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
for spec in "$@"; do
  v=${spec%%:*}; c=${spec##*:}; tag="$v-cudnn$c"
  echo "=== onnxruntime-gpu $v + cudnn $c" | tee -a "$S2_DIR/results/ort_probe.txt"
  docker build -q --build-arg ORT_VERSION="$v" --build-arg CUDNN_VERSION="$c" -f "$S2_DIR/Dockerfile.ort" -t "wl-s2-ort-$tag" "$S2_DIR" >/dev/null 2>&1 || { echo "build failed" | tee -a "$S2_DIR/results/ort_probe.txt"; continue; }
  docker run --rm "${GPU_ARGS[@]}" -v "$S2_DIR:/s:ro" "wl-s2-ort-$tag" /opt/v/bin/python /s/ort_probe.py /s/models/yolov8n_320.onnx 2>&1 \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'onnxruntime |session providers|run OK|Error|error|Require|arch|sm_|no kernel' | cut -c1-400 | tee -a "$S2_DIR/results/ort_probe.txt" || true
done
