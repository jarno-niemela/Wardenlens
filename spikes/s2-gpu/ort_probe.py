"""Check whether the ORT CUDA EP loads and runs on this GPU (sm_52). Usage: ort_probe.py <model.onnx>"""
import sys, numpy as np, onnxruntime as ort
print("onnxruntime", ort.__version__, "providers", ort.get_available_providers())
so = ort.SessionOptions(); so.log_severity_level = 2
s = ort.InferenceSession(sys.argv[1], so, providers=["CUDAExecutionProvider", "CPUExecutionProvider"])
print("session providers:", s.get_providers())
i = s.get_inputs()[0]
x = np.random.rand(*i.shape).astype(np.float32)
y = s.run(None, {i.name: x})
print("run OK, output shape", y[0].shape)
