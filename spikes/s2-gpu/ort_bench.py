"""YOLO ONNX latency/fps benchmark. Usage: ort_bench.py <cuda|cpu> <model.onnx> [iters]
Random FP32 input (latency does not depend on content). Prints one TSV row: provider, model, mean/p50/p95 ms, fps."""
import sys, time, subprocess, numpy as np, onnxruntime as ort

prov, path = sys.argv[1], sys.argv[2]
iters = int(sys.argv[3]) if len(sys.argv) > 3 else 200
so = ort.SessionOptions(); so.log_severity_level = 3
if prov == "cpu":
    so.intra_op_num_threads = 4
provs = ["CUDAExecutionProvider"] if prov == "cuda" else ["CPUExecutionProvider"]
def vram():
    try:
        return int(subprocess.check_output(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"]).split()[0])
    except Exception:
        return -1
v0 = vram()
s = ort.InferenceSession(path, so, providers=provs)
assert s.get_providers()[0] == provs[0], f"provider fallback: {s.get_providers()}"
i = s.get_inputs()[0]
x = np.random.rand(*i.shape).astype(np.float32)
for _ in range(20):
    s.run(None, {i.name: x})
v1 = vram()
t = []
for _ in range(iters):
    a = time.perf_counter(); s.run(None, {i.name: x}); t.append((time.perf_counter() - a) * 1000)
t = np.array(t)
print(f"{prov}\t{path.split('/')[-1]}\tmean={t.mean():.1f}ms\tp50={np.percentile(t,50):.1f}ms\tp95={np.percentile(t,95):.1f}ms\tfps={1000/t.mean():.1f}\tvram_delta={v1-v0}MiB\tvram_total={v1}MiB")
