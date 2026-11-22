# 0003. GPU stack for the GTX 970 (decode, kernels, inference)

- Status: accepted
- Date: 2026-11-23
- Ticket: #21 (epic #15)

## Context
The NVR box has one GeForce GTX 970 (GM204, sm_52, 4 GB, driver 580.178.04, 163 W, 1455 MHz max SM clock). Spike S1
(ADR 0002) fixed the stream parameters: 5 cameras, each with a main and a sub stream, all H.264.

| stream set | resolution @ fps (S1) | real-time demand |
|---|---|---|
| 5 sub | 640x480@10 (x2), 704x576@25, 640x360@15, 640x360@25 | 85 fps |
| 5 main | 2560x1920@~17 (x2), 2560x1440@25, 1920x1080@15, 1920x1080@~9 | 83 fps |

Plan: detect on sub streams (decoded), record main streams by passthrough (no decode). Questions: does NVDEC cope, does
HEVC work, can we run our own CUDA kernels on sm_52, and which inference runtime still supports Maxwell. Everything
below ran in Docker with `--gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,video,utility` on
`nvidia/cuda:12.9.1-*-ubuntu24.04` (CUDA 12.9.1 is the last CUDA 12.x; CUDA 13 dropped Maxwell). Scripts, Dockerfiles and raw
output are in `spikes/s2-gpu/`. The host had 541 MiB VRAM already in use (desktop), so "peak" VRAM below includes that baseline.

Method notes. Decode input is synthetic (`testsrc2`, libx264, GOP 2 s, bitrates comparable to S1) because recorded camera
samples would show the owner's property; synthetic content is simpler than real footage, so absolute numbers are
indicative. Decode ran with ffmpeg 6.1 `h264_cuvid` at maximum speed (no `-re`), output to the null muxer, so each run
also includes the device-to-host frame copy. Each stream loops a 20 s clip 6 to 21 times. Inference used random FP32
input (latency does not depend on content), 20 warm-up runs, 200 timed runs (30 on CPU, 4 intra-op threads on a 4-core host).

## Measurements

### (a) NVDEC H.264 decode on GM204
| scenario | per-stream fps | total fps | VRAM peak (baseline 541) | dec util avg/max |
|---|---|---|---|---|
| 1x 640x480 | 744 | 742 | 603 MiB | 17 / 25 % |
| 1x 704x576 | 968 | 967 | 613 MiB | 42 / 50 % |
| 1x 640x360 | 1869 | 1865 | 610 MiB | 50 / 59 % |
| 1x 2560x1920 | 224 | 224 | 675 MiB | 87 / 95 % |
| 1x 2560x1440 | 282 | 282 | 658 MiB | 88 / 92 % |
| 1x 1920x1080 | 389 | 389 | 635 MiB | 74 / 76 % |
| **5 sub streams (the S1 set)** | 380, 380, 648, 576, 671 | **2203** | 886 MiB (+345) | 87 / 98 % |
| **5 main streams (the S1 set)** | 67, 67, 89, 66, 68 | **317** | 1110 MiB (+569) | 97 / 100 % |
| 5 sub + 5 main together | sub 68-83, main 56-76 | 532 | 1454 MiB (+913) | 88 / 100 % |
| 10x 2560x1440 | 32 each | 319 | 1703 MiB | 92 / 100 % |
| 20x 640x480 | 116-140 each | 2321 | 1910 MiB | 91 / 100 % |
| 40x 640x480 | about 58 each | 2335 | 3280 MiB | 92 / 100 % |

The decoder saturates at roughly 2200-2300 fps of sub-stream pixels, about 320 fps at 1440p and about 220 fps at 2560x1920
(throughput scales with pixel rate, about 1.1 Gpixel/s). Real-time demand is 85 fps (subs) and 83 fps (mains), so the
5 sub streams use about 4 % of the decoder and even decoding all 5 mains would use about 26 %. VRAM grows about 70 MiB per
extra concurrent sub-stream decoder (40 streams reached 3.3 GB), so session count, not fps, is the VRAM driver.
Each count was measured at the maximum rate; no stall or error occurred in any run.

### (b) HEVC on GM204
Refuted. `hevc_cuvid -i hevc_1920x1080.mp4` fails immediately with `Codec hevc_cuvid is not supported` while the
`h264_cuvid` control on the same host/container succeeds (`spikes/s2-gpu/results/hevc.txt`). GM204 (2nd-gen Maxwell) NVDEC is
H.264 (plus MPEG-2, VC-1, VP8 per ffmpeg's decoder list); HEVC arrived with GM206/GP10x. Consequence: any camera
switched to H.265 must be decoded on the CPU (or the stream left on H.264). All five cameras currently deliver H.264.

### (c) CUDA kernel for sm_52 via cudarc
Works. `spikes/s2-gpu/cuda-bgsub` (cudarc `=0.19.10`, features `driver nvrtc dynamic-loading cuda-12090`) compiles a
frame-difference plus running-average background-subtraction kernel with NVRTC for `sm_52` at start-up and launches it on a
640x480 grey frame. Masks and counts are identical to a CPU reference over 30 frames. The binary is built on the host (no CUDA
toolkit needed, libraries are `dlopen`ed) and runs in the `nvidia/cuda:12.9.1-devel` container (it provides `libnvrtc`).

| measurement | result |
|---|---|
| kernel only, device-resident frame | 104,629 frames/s (9.6 us/frame) |
| end to end: pageable H2D upload + kernel + D2H of count | 5,153 frames/s (194 us/frame) |

One camera sub stream at 25 fps needs 25 of these; the upload copy, not the kernel, dominates.

### (d) ONNX Runtime CUDA execution provider on sm_52
Maxwell support was removed from the PyPI wheels after **1.20.2**. Test: load `yolov8n_320.onnx` with the CUDA EP and run once
(`spikes/s2-gpu/results/ort_probe.txt`).

| onnxruntime-gpu | cuDNN (pip) | result on GTX 970 |
|---|---|---|
| 1.32.0 (latest) | 9.28 | CUDA EP does not load: wheel is built for CUDA 13 (`libcublasLt.so.13`), silently falls back to CPU |
| 1.23.2 | 9.28 | `no kernel image is available` in cuDNN (Conv) |
| 1.23.2 | 9.1.0.70 / 9.5.1.17 | Conv passes cuDNN, then `cudaErrorNoKernelImageForDevice` in ORT's own `QuickGelu` kernel |
| 1.22.0, 1.21.1, 1.21.0 | 9.1.0.70 | same `QuickGelu` `no kernel image` failure (ORT kernels lack sm_52) |
| **1.20.2**, 1.19.2 | **9.1.0.70** | **runs on CUDAExecutionProvider** |

Conclusion: the newest usable wheel is `onnxruntime-gpu==1.20.2` (CUDA 12.x build) with cuDNN 9.1.0.70 and the CUDA 12.9
runtime libraries. 1.20.0/1.20.1 were not tested separately. Newer cuDNN (9.28) is not usable with it on this GPU. The ORT
session must be created with the CUDA EP only and asserted (`get_providers()[0] == CUDAExecutionProvider`), because ORT silently
falls back to the CPU EP; the first run of every probe above showed this fallback.

### (e) YOLO FP32, ORT 1.20.2 CUDA EP vs CPU (4 threads), batch 1
Models: Ultralytics YOLOv8n/s and YOLO11n/s exported to ONNX (opset 19, fixed shape, FP32, from release v8.3.0 weights); SHA-256 in
`spikes/s2-gpu/results/models.sha256`. VRAM = process total on the GPU after warm-up, including the 541 MiB host baseline.

| model | input | GPU mean / p95 ms | GPU fps | GPU VRAM total (delta) | CPU mean ms | CPU fps |
|---|---|---|---|---|---|---|
| YOLOv8n | 320 | 5.5 / 6.0 | 182 | 784 MiB (+243) | 15.3 | 65 |
| YOLOv8n | 640 | 10.4 / 11.3 | 96 | 688 MiB (+147) | 67.6 | 15 |
| YOLOv8s | 320 | 8.4 / 9.1 | 119 | 946 MiB (+405) | 38.8 | 26 |
| YOLOv8s | 640 | 20.9 / 22.3 | 48 | 880 MiB (+339) | 182.8 | 5.5 |
| YOLO11n | 320 | 6.3 / 6.7 | 158 | 784 MiB (+243) | 18.6 | 54 |
| YOLO11n | 640 | 11.4 / 12.2 | 88 | 688 MiB (+147) | 69.6 | 14 |
| YOLO11s | 320 | 8.9 / 9.4 | 113 | 944 MiB (+403) | 36.2 | 28 |
| YOLO11s | 640 | 21.5 / 22.6 | 47 | 752 MiB (+211) | 178.4 | 5.6 |

The GPU is 3-9x faster than the CPU. The VRAM delta is noisy and not monotone in input size (cuDNN workspace and the ORT arena
depend on the chosen convolution algorithms); budget about 0.4 GB per model session. The accuracy of these models was not evaluated.

## Options
1. **NVDEC (cuvid/NVDEC via ffmpeg or `nvcuvid`) for decode, custom CUDA via cudarc, ORT 1.20.2 CUDA EP** - measured above,
   everything works on sm_52; pins old software.
2. CPU decode and CPU inference - no GPU lock-in, but 4 cores: YOLOv8n 640 is 15 fps in total and the decode of 5 subs would
   compete with it; ruled out as the primary path, kept as fallback.
3. Newer ORT/TensorRT/CUDA 13 - not possible: CUDA 13 and ORT >= 1.21 drop sm_52. Building ORT from source with
   `CMAKE_CUDA_ARCHITECTURES=52` against CUDA 12.9 is the escape hatch if 1.20.2 becomes unacceptable (not tried).
4. OpenCV DNN with CUDA or a different runtime (for example NCNN/Vulkan) - not needed since ORT 1.20.2 works; recorded as the
   fallback if ORT pins become a problem.

## Decision
- **Decode**: NVDEC H.264 only, sub streams only. Main streams are recorded by passthrough (no decode). HEVC cameras are
  decoded on the CPU if they ever appear.
- **Custom kernels**: cudarc (`=0.19.10`), kernels as CUDA C source compiled with NVRTC for `sm_52` at start-up, libraries
  loaded dynamically. `unsafe` for kernel launch must be confined to one small gpu crate that the workspace unsafe policy
  explicitly allows (to be settled in that crate's ticket; this spike used `unsafe` in a throwaway crate outside the workspace).
- **Inference**: ONNX Runtime `onnxruntime-gpu==1.20.2` (CUDA EP), cuDNN `9.1.0.70`, FP32, YOLOv8n/YOLO11n at 640 (about 10 ms,
  headroom for several cameras) with 320 as the cheap pre-filter; s-size only if accuracy requires. In Rust via the `ort` crate
  pinned to an ONNX Runtime 1.20.x build (the version mapping and dynamic loading are for the integration ticket to verify).
  Fail hard if the CUDA EP is not the first provider.
- **Container**: `nvidia/cuda:12.9.1-{base|runtime|devel}-ubuntu24.04`, `NVIDIA_DRIVER_CAPABILITIES=compute,video,utility`.
  `spikes/s2-gpu/Dockerfile.*` are the pinned recipes.
- **Models**: not in the repo; `export_models.sh` regenerates them and `results/models.sha256` records checksums.

## Capacity plan (5 cameras)
| resource | demand | measured capacity | headroom |
|---|---|---|---|
| NVDEC, 5 sub streams (85 fps) | about 4 % of decoder | 2203 fps | 26x |
| NVDEC if all 5 mains were decoded (83 fps) | about 26 % | 317 fps | 3.8x (use for occasional snapshots or re-detect) |
| Detection, YOLOv8n 640 at 5 fps per camera | 25 inf/s, about 26 % of GPU time | 96 inf/s | 3.8x |
| Detection, YOLOv8s 640 at 5 fps per camera | 25 inf/s, about 52 % of GPU time | 48 inf/s | 1.9x |
| Motion kernel on 5 subs (125 fps total) | trivial | 5,153 fps end to end | 40x |
| VRAM (above the 541 MiB host baseline) | 5 sub decoders about 350 MiB + one 640 model about 150-400 MiB + CUDA context | 4096 MiB | about 3 GB spare, 3.5 GB if the desktop moves off the GPU |

Recommended operating point: all 5 subs decoded on NVDEC, motion kernel gates detection, YOLO at 640 with at most 5 fps per
camera (peak 25 inf/s). Combined decode plus inference was **not** measured together; both use the GPU but different engines
(NVDEC versus SMs), so contention should be small, to be confirmed in the first Phase 1 end-to-end test.

## Risks
- **Driver 580 end of life**: the 580 branch is the last to support Maxwell (R590 and later drop it). Pin the driver
  (hold the package) and plan for the day security updates stop; the CPU path is the exit.
- **Wheel and CUDA support**: ORT stops at 1.20.2 and cuDNN is pinned to 9.1.x; CUDA 12.9 is the last toolkit with sm_52 (CUDA
  13 drops it). We cannot adopt new ORT features or new model operators (for example fused ops introduced later). Mitigation: a
  source build of ORT with `52` in `CMAKE_CUDA_ARCHITECTURES`, or OpenCV DNN/NCNN as an alternative runtime; pin versions in the
  image and run `ort_probe.py` as a smoke test whenever anything changes.
- **Silent CPU fallback**: ORT falls back to the CPU EP when the CUDA libraries do not load; assert the active provider.
- **4 GB VRAM**: about 70 MiB per decoder session and 0.15-0.4 GB per model session; 40 concurrent decodes already used 3.3 GB. The
  desktop on the same GPU costs 541 MiB. Keep sessions few, share one model session across cameras, and do not run main-stream decodes
  continuously.
- **HEVC**: no NVDEC HEVC; switching a camera to H.265 moves its decode to the CPU.
- **Synthetic input**: decode numbers come from testsrc2 clips; real streams (variable bitrate, high motion) can be slower. The
  margins (26x and 3.8x) are large enough that this does not change the decision.
- **Model licence**: Ultralytics YOLO weights and exporter are AGPL-3.0; choose a model and licence before shipping (follow-up).

## Consequences
- Easier: a single known-good GPU stack with measured headroom; the decode path needs no CPU for the 5 sub streams.
- Harder: pinned, aging software (ORT 1.20.2, cuDNN 9.1, CUDA 12.9, driver 580); NVDEC is H.264-only.
- To do: Phase 1 tickets for the gpu crate (cudarc + NVRTC, unsafe policy), an ORT-1.20 integration (Rust `ort` version mapping
  or Python sidecar), a decode-plus-inference end-to-end benchmark with real streams, and a model licence decision.
