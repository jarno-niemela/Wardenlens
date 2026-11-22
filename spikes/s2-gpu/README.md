# S2 GPU spike (ticket #21)

Benchmarks behind `docs/adr/0003-gpu-stack.md`. All GPU work runs in Docker
(`--gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,video,utility`); nothing changes host driver, clocks or runtime config.

| file | purpose |
|---|---|
| `Dockerfile.ffmpeg` | `nvidia/cuda:12.9.1-base-ubuntu24.04` + Ubuntu ffmpeg 6.1 (cuvid/NVDEC decoders) |
| `gen_fixtures.sh` | synthetic testsrc2 H.264 clips at the S1 camera resolutions/fps (+ one HEVC clip) into `fixtures/` (gitignored) |
| `bench_decode.sh`, `run_decode_matrix.sh` | concurrent NVDEC decode benchmark; fps per stream, total fps, VRAM, `nvidia-smi dmon` dec utilisation |
| `cuda-bgsub/` | standalone cudarc crate (own `[workspace]`): NVRTC-compiled sm_52 background-subtraction kernel, CPU-verified, throughput |
| `Dockerfile.export`, `export_models.sh` | export YOLOv8/YOLO11 n/s at 320 and 640 to FP32 ONNX (Ultralytics is AGPL-3.0, benchmark use only) |
| `Dockerfile.ort`, `ort_probe.py`, `probe_ort_versions.sh` | find which onnxruntime-gpu wheels run on sm_52 |
| `ort_bench.py`, `run_ort_bench.sh` | YOLO latency/fps/VRAM, CUDA EP vs CPU |
| `results/` | raw outputs quoted in the ADR; `models.sha256` = checksums of weights and ONNX files |

`fixtures/`, `models/` and `cuda-bgsub/target/` are gitignored (media and weights are not committed).
Build cuda-bgsub on the host (`cargo build --release`, dynamic loading) and run it in the CUDA container:
`docker run --rm --gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,video,utility -v $PWD/cuda-bgsub/target/release:/b:ro nvidia/cuda:12.9.1-devel-ubuntu24.04 /b/cuda-bgsub`.
The crate uses `unsafe` for kernel launch (cudarc API); it is a throwaway, never linked into the workspace.
Synthetic clips are not camera footage: decode throughput depends on bitrate and content, so treat numbers as
upper-bound-ish for static scenes and re-measure with real streams in Phase 1.
