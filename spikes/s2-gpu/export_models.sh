#!/usr/bin/env bash
# Download YOLO weights (public ultralytics release) and export FP32 ONNX at 320 and 640. Output: models/ (gitignored).
# Records SHA-256 of weights and ONNX files in models/SHA256SUMS.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
docker build -q -f "$S2_DIR/Dockerfile.export" -t wl-s2-export "$S2_DIR" >/dev/null
mkdir -p "$S2_DIR/models"
docker run --rm -v "$S2_DIR/models:/models" --user "$(id -u):$(id -g)" -e HOME=/models -e YOLO_CONFIG_DIR=/models/.cfg wl-s2-export bash -c '
set -e
for m in yolov8n yolov8s yolo11n yolo11s; do
  [ -f $m.pt ] || curl -fsSL -o $m.pt https://github.com/ultralytics/assets/releases/download/v8.3.0/$m.pt
  for sz in 320 640; do
    [ -f ${m}_$sz.onnx ] && continue
    python -c "from ultralytics import YOLO; p=YOLO(\"$m.pt\").export(format=\"onnx\", imgsz=$sz, opset=19, simplify=True, dynamic=False, half=False); import os; os.replace(p, \"${m}_$sz.onnx\")"
  done
done
sha256sum *.pt *.onnx | tee SHA256SUMS
'
