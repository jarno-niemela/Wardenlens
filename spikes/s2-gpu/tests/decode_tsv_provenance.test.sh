#!/usr/bin/env bash
# Adversarial (round 3, ticket #21): results/decode.tsv must be what the committed bench_decode.sh prints, and the
# ADR's dec-util method must be the one the committed script implements. No GPU.
set -uo pipefail
S2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADR="$S2/../../docs/adr/0003-gpu-stack.md"
TSV="$S2/results/decode.tsv"
fails=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1: $2"; fails=$((fails + 1)); }
# The dmon header line the script echoes (between the single quotes of: echo '--- dmon ...').
hdr=$(grep -o "echo '--- dmon[^']*'" "$S2/bench_decode.sh" | sed "s/^echo '//; s/'\$//")
if [ -z "$hdr" ]; then
  bad dmon_header_matches_script "no dmon header in bench_decode.sh"
elif [ "$(grep -c -- '^--- dmon' "$TSV")" -eq "$(grep -cxF -- "$hdr" "$TSV")" ] \
  && [ "$(grep -c -- '^--- dmon' "$TSV")" -gt 0 ] \
  && [ "$(grep -c -- '^--- dmon' "$TSV")" -eq "$(grep -c -- '^### ' "$TSV")" ]; then
  ok dmon_header_matches_script
else
  bad dmon_header_matches_script "script prints '$hdr'; decode.tsv has '$(grep -m1 -- '^--- dmon' "$TSV")'"
fi
# If the script averages every sample, the ADR must not say "first 40 samples only", and vice versa.
if grep -q 'head -40' "$S2/bench_decode.sh"; then script=first40; else script=all; fi
if grep -q 'first 40 samples only' "$ADR"; then adr=first40; else adr=all; fi
if [ "$script" = "$adr" ]; then ok adr_dec_util_method_matches_script; else
  bad adr_dec_util_method_matches_script "bench_decode.sh averages $script samples, ADR says $adr"; fi
# A run longer than 40 s must not report n=40 samples when the script averages all samples.
if [ "$script" = all ]; then
  capped=$(awk -F'\t' '$2=="TOTAL"{w=$3; sub("wall=","",w); sub("s","",w); wall[$1]=w+0}
    /^### /{split($0, h, " "); cur=h[3]} /^dec util/{n=$0; sub(/.*\(n=/,"",n); sub(/ .*/,"",n); if (wall[cur] > 45 && n == 40) print cur}' "$TSV" | tr '\n' ' ')
  if [ -z "$capped" ]; then ok long_runs_not_capped_at_40_samples; else
    bad long_runs_not_capped_at_40_samples "n=40 on runs longer than 45 s: $capped (made by the old head -40 script)"; fi
fi
[ "$fails" -eq 0 ]
