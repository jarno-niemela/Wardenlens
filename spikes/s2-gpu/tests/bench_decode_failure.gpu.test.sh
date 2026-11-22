#!/usr/bin/env bash
# Adversarial (round 2, ticket #21): a failing decode must fail bench_decode.sh, not produce a plausible-looking row.
# run_decode_matrix.sh relies on this ("pipefail propagates a failing benchmark").
# Needs Docker + GPU + the wl-s2-ffmpeg image; prints "skip" and exits 0 otherwise. Runs in about 2 s.
set -uo pipefail
S2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v docker >/dev/null || ! docker image inspect wl-s2-ffmpeg >/dev/null 2>&1; then
  echo "skip (no docker or wl-s2-ffmpeg image)"; exit 0
fi
fails=0
mkdir -p "$S2/fixtures" # otherwise the bind mount creates it root-owned
# A clip that does not exist: ffmpeg fails to open the input.
out=$(LOOPS=0 "$S2/bench_decode.sh" adv-missing h264_cuvid adv_clip_that_does_not_exist 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then echo "ok   missing_clip_exits_nonzero"; else echo "FAIL missing_clip_exits_nonzero (rc=0)"; fails=$((fails + 1)); fi
# The stream row's frames column must be an integer frame count, never a misparsed time value.
if printf '%s\n' "$out" | awk -F'\t' '$2=="stream"' | grep -qP '\t\.?[0-9]*\.[0-9]+ frames\t'; then
  echo "FAIL missing_clip_row_not_misparsed"; printf '%s\n' "$out" | sed 's/^/  /'; fails=$((fails + 1))
else
  echo "ok   missing_clip_row_not_misparsed"
fi
# A TOTAL row with a positive fps must not be reported when every stream failed.
if printf '%s\n' "$out" | grep -qP '\tTOTAL\t.*total_fps=0*[1-9]|\tTOTAL\t.*total_fps=0\.[0-9]*[1-9]'; then
  echo "FAIL failed_run_reports_no_positive_total_fps"; fails=$((fails + 1))
else
  echo "ok   failed_run_reports_no_positive_total_fps"
fi
[ "$fails" -eq 0 ]
