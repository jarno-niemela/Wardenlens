#!/usr/bin/env bash
# Full decode matrix used in ADR 0003. Output: results/decode.tsv
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
out=results/decode.tsv
: > "$out"
# b <loops> <args...>: run bench_decode.sh, tee to $out; pipefail propagates a failing benchmark.
b() { local loops=$1; shift; echo "### $*" | tee -a "$out"; LOOPS=$loops "$@" 2>&1 | tee -a "$out"; }
rep() { local n=$1 c=$2 i; for ((i = 0; i < n; i++)); do printf '%s\n' "$c"; done; }
for c in sub_640x480 sub_704x576 sub_640x360_25 main_2560x1920 main_2560x1440 main_1920x1080; do
  b 10 ./bench_decode.sh "single-$c" h264_cuvid "$c"
done
SUBS=(sub_640x480 sub_640x480 sub_704x576 sub_640x360_15 sub_640x360_25)
MAINS=(main_2560x1920 main_2560x1920 main_2560x1440 main_1920x1080 main_1920x1080)
b 20 ./bench_decode.sh 5-substreams h264_cuvid "${SUBS[@]}"
b 10 ./bench_decode.sh 5-mainstreams h264_cuvid "${MAINS[@]}"
b 10 ./bench_decode.sh 5sub+5main h264_cuvid "${SUBS[@]}" "${MAINS[@]}"
mapfile -t M10 < <(rep 10 main_2560x1440)
mapfile -t S20 < <(rep 20 sub_640x480)
mapfile -t S40 < <(rep 40 sub_640x480)
b 10 ./bench_decode.sh 10x-main1440 h264_cuvid "${M10[@]}"
b 10 ./bench_decode.sh 20x-sub480 h264_cuvid "${S20[@]}"
b 10 ./bench_decode.sh 40x-sub480 h264_cuvid "${S40[@]}"
