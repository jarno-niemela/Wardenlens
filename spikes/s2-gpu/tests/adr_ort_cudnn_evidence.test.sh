#!/usr/bin/env bash
# Adversarial (round 4, ticket #21): every onnxruntime-gpu + cuDNN combination the ADR states a result for must have a
# probe section in results/ort_probe.txt. No GPU.
set -uo pipefail
S2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADR="$S2/../../docs/adr/0003-gpu-stack.md"
PROBE="$S2/results/ort_probe.txt"
fails=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1: $2"; fails=$((fails + 1)); }
has_probe() { grep -q "^=== onnxruntime-gpu $1 + cudnn $2" "$PROBE"; }
# ADR (d) conclusion: "Newer cuDNN (9.28) is not usable with it [1.20.2] on this GPU".
if grep -q 'Newer cuDNN (9.28) is not usable with it' "$ADR"; then
  if has_probe 1.20.2 9.28; then ok ort_1_20_2_with_cudnn_9_28_has_probe; else
    bad ort_1_20_2_with_cudnn_9_28_has_probe "ADR says 1.20.2 + cuDNN 9.28 is unusable; ort_probe.txt has no 1.20.2 + cudnn 9.28 section"; fi
fi
# Table rows: "| <ort versions> | <cudnn versions> | ..." in section (d).
while IFS='|' read -r _ orts cudnns _; do
  orts=$(printf '%s' "$orts" | tr -d '*' | sed 's/(latest)//'); cudnns=$(printf '%s' "$cudnns" | tr -d '*')
  for o in $(printf '%s' "$orts" | tr ',' ' '); do
    for c in $(printf '%s' "$cudnns" | tr '/' ' '); do
      if has_probe "$o" "$c"; then ok "probe_$o+$c"; else bad "probe_$o+$c" "ADR table row without probe section"; fi
    done
  done
done < <(sed -n '/^| onnxruntime-gpu | cuDNN/,/^$/p' "$ADR" | grep -E '^\| \**1\.[0-9]')
[ "$fails" -eq 0 ]
