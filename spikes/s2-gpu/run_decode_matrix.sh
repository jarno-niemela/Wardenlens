#!/usr/bin/env bash
# Full decode matrix used in ADR 0003. Output: results/decode.tsv
cd "$(dirname "${BASH_SOURCE[0]}")"
out=results/decode.tsv; : > "$out"
b() { echo "### $*" | tee -a "$out"; "$@" 2>&1 | tee -a "$out"; }
for c in sub_640x480 sub_704x576 sub_640x360_25 main_2560x1920 main_2560x1440 main_1920x1080; do
  LOOPS=10 b ./bench_decode.sh "single-$c" h264_cuvid $c
done
SUBS="sub_640x480 sub_640x480 sub_704x576 sub_640x360_15 sub_640x360_25"
MAINS="main_2560x1920 main_2560x1920 main_2560x1440 main_1920x1080 main_1920x1080"
LOOPS=20 b ./bench_decode.sh 5-substreams h264_cuvid $SUBS
LOOPS=10 b ./bench_decode.sh 5-mainstreams h264_cuvid $MAINS
LOOPS=10 b ./bench_decode.sh 5sub+5main h264_cuvid $SUBS $MAINS
LOOPS=10 b ./bench_decode.sh 10x-main1440 h264_cuvid $(printf 'main_2560x1440 %.0s' {1..10})
LOOPS=10 b ./bench_decode.sh 20x-sub480 h264_cuvid $(printf 'sub_640x480 %.0s' {1..20})
LOOPS=10 b ./bench_decode.sh 40x-sub480 h264_cuvid $(printf 'sub_640x480 %.0s' {1..40})
