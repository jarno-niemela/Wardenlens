#!/usr/bin/env bash
# YOLO FP32 benchmark: CUDA EP (ORT 1.20.2 + cuDNN 9.1.0.70) vs CPU EP. Output: results/yolo.tsv
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
img=wl-s2-ort-1.20.2-cudnn9.1.0.70
out="$S2_DIR/results/yolo.tsv"; : > "$out"
for m in yolov8n yolov8s yolo11n yolo11s; do for sz in 320 640; do for p in cuda cpu; do
  n=200; [ "$p" = cpu ] && n=30
  docker run --rm "${GPU_ARGS[@]}" -v "$S2_DIR:/s:ro" "$img" /opt/v/bin/python /s/ort_bench.py $p /s/models/${m}_$sz.onnx $n 2>&1 | grep -P '^(cuda|cpu)\t' | tee -a "$out"
done; done; done
