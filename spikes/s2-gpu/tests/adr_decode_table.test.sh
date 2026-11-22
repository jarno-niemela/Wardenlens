#!/usr/bin/env bash
# Adversarial (round 2, ticket #21): VRAM peak and dec utilisation in ADR 0003 table (a) match results/decode.tsv. No GPU.
set -uo pipefail
S2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADR="$S2/../../docs/adr/0003-gpu-stack.md"
TSV="$S2/results/decode.tsv"
fails=0
# label in decode.tsv, then the ADR table row prefix
while IFS='|' read -r label row; do
  peak=$(awk -F'\t' -v l="$label" '$1==l && $2=="TOTAL"{sub("vram_peak=","",$6); sub("MiB","",$6); print $6}' "$TSV")
  util=$(awk -v l="$label" '$0 ~ "^### " {cur=$3} /^dec util/ && cur==l {gsub(/[a-z=%(]/," "); print $1" / "$2}' "$TSV" \
    | tr -s ' ' | sed 's/^ //')
  line=$(grep -F "| $row |" "$ADR" | head -1)
  if [ -n "$line" ] && [[ "$line" == *"$peak MiB"* ]] && [[ "$line" == *"| $util % |"* ]]; then
    echo "ok   $label"
  else
    echo "FAIL $label: raw peak=$peak util=$util; ADR: $line"; fails=$((fails + 1))
  fi
done <<'T'
single-sub_640x480|1x 640x480
single-sub_704x576|1x 704x576
single-sub_640x360_25|1x 640x360
single-main_2560x1920|1x 2560x1920
single-main_2560x1440|1x 2560x1440
single-main_1920x1080|1x 1920x1080
5-substreams|**5 sub streams (the S1 set)**
5-mainstreams|**5 main streams (the S1 set)**
5sub+5main|5 sub + 5 main together
10x-main1440|10x 2560x1440
20x-sub480|20x 640x480
40x-sub480|40x 640x480
T
[ "$fails" -eq 0 ]
