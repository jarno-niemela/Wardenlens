#!/usr/bin/env bash
# NVDEC decode benchmark. Usage: bench_decode.sh <label> <codec_decoder> <clip>...   (clips run concurrently, max speed)
# Env: LOOPS (default 5) extra loops of each 20 s clip. Prints one TSV row per stream plus a summary row,
# and records nvidia-smi dmon (dec utilisation) and peak VRAM during the run.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
label=$1; dec=$2; shift 2
clips="$*"
run_in_ffmpeg "
loops=${LOOPS:-5}
nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits > /tmp/vram_before
nvidia-smi dmon -s u -d 1 > /tmp/dmon.txt &
dmon=\$!
( while true; do nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits >> /tmp/vram.txt; sleep 0.5; done ) &
vr=\$!
start=\$(date +%s.%N)
i=0; pids=''
for c in $clips; do
  i=\$((i+1))
  ( s=\$(date +%s.%N)
    ffmpeg -v error -nostats -progress pipe:1 -c:v $dec -stream_loop \$loops -i /fx/\$c.mp4 -f null - 2>/tmp/err\$i.txt | grep '^frame=' | tail -1 > /tmp/fr\$i.txt
    e=\$(date +%s.%N)
    echo \"\$i \$c \$(cut -d= -f2 /tmp/fr\$i.txt) \$(echo \"\$e - \$s\" | bc -l) \$(head -c 200 /tmp/err\$i.txt | tr '\n' ' ')\" > /tmp/out\$i.txt ) &
  pids=\"\$pids \$!\"
done
wait \$pids
end=\$(date +%s.%N)
kill \$dmon \$vr 2>/dev/null
before=\$(cat /tmp/vram_before)
peak=\$(sort -n /tmp/vram.txt | tail -1)
tot=0
for f in /tmp/out*.txt; do
  read id c frames secs err < \$f
  fps=\$(echo \"scale=1; \${frames:-0} / \$secs\" | bc -l)
  printf '$label\tstream\t%s\t%s frames\t%.1fs\t%s fps\t%s\n' \"\$c\" \"\${frames:-0}\" \"\$secs\" \"\$fps\" \"\$err\"
  tot=\$(echo \"\$tot + \${frames:-0}\" | bc -l)
done
wall=\$(echo \"\$end - \$start\" | bc -l)
printf '$label\tTOTAL\twall=%.1fs\ttotal_fps=%.1f\tvram_before=%sMiB\tvram_peak=%sMiB\n' \$wall \$(echo \"\$tot / \$wall\" | bc -l) \$before \$peak
echo '--- dmon (sm mem enc dec jpg ofa), steady-state rows'
awk 'NR>2 && \$1==0 {print}' /tmp/dmon.txt | head -40 | awk '{s+=\$5; n++; if(\$5>m)m=\$5} END{printf \"dec util avg=%.0f%% max=%d%% (n=%d samples)\n\", s/n, m, n}'
" 
