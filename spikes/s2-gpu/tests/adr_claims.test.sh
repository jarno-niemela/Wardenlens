#!/usr/bin/env bash
# Adversarial checks for ticket #21: ADR 0003 claims vs committed raw results, repo hygiene of the spike.
# No GPU needed. Usage: spikes/s2-gpu/tests/adr_claims.test.sh   (prints ok/FAIL per check, exit 1 on any FAIL)
set -uo pipefail
S2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$S2/../.." && pwd)"
ADR="$ROOT/docs/adr/0003-gpu-stack.md"
R="$S2/results"
fails=0
check() { local name=$1; shift; if "$@"; then echo "ok   $name"; else echo "FAIL $name"; fails=$((fails + 1)); fi; }

shellcheck_clean() { (cd "$S2" && shellcheck -x -P SCRIPTDIR ./*.sh tests/*.sh >/dev/null); }

# Every onnxruntime-gpu version named in the ADR ORT table has a probe section in ort_probe.txt.
ort_versions_have_raw_evidence() {
  local v ok=0
  while read -r v; do
    grep -q "=== onnxruntime-gpu $v" "$R/ort_probe.txt" || { echo "  no raw probe for onnxruntime-gpu $v" >&2; ok=1; }
  done < <(grep -E '^\| \**1\.[0-9]+' "$ADR" | awk -F'|' '{print $2}' | grep -oE '1\.[0-9]+\.[0-9]+' | sort -u)
  return $ok
}
cuda13_fallback_claim_has_raw_evidence() { grep -q 'libcublasLt.so.13' "$R/ort_probe.txt"; }

# Every decode stream row ran without error and decoded fps*20*k frames for an integer k (clip plays).
clip_fps() { case $1 in sub_640x480) echo 10;; sub_704x576|sub_640x360_25|main_2560x1440) echo 25;; sub_640x360_15|main_1920x1080) echo 15;; main_2560x1920) echo 17;; *) echo 0;; esac; }
plays() { awk -F'\t' '$2=="stream"{split($4,a," "); print $3, a[1], $7}' "$R/decode.tsv" | while read -r c fr err; do
  f=$(clip_fps "$c"); [ -n "${err:-}" ] && { echo "ERR $c $err"; continue; }; echo $((fr / (f * 20))) $((fr % (f * 20))); done; }
decode_rows_complete_and_error_free() { ! plays | grep -qvE '^[0-9]+ 0$'; }
# ADR: "Each stream loops a 20 s clip 11 to 21 times".
adr_loop_range_matches_raw() {
  local lo hi; lo=$(plays | cut -d' ' -f1 | sort -n | head -1); hi=$(plays | cut -d' ' -f1 | sort -n | tail -1)
  grep -q "loops a 20 s clip $lo to $hi times" "$ADR" || { echo "  raw: $lo to $hi plays" >&2; return 1; }
}

# Decode totals quoted in the ADR equal the TOTAL rows (rounded).
decode_totals_match() {
  local label want got ok=0
  while read -r label want; do
    got=$(awk -F'\t' -v l="$label" '$1==l && $2=="TOTAL"{sub("total_fps=","",$4); printf "%.0f", $4}' "$R/decode.tsv")
    [ "$got" = "$want" ] || { echo "  $label: raw $got, ADR $want" >&2; ok=1; }
  done <<'T'
single-sub_640x480 742
single-sub_704x576 967
single-sub_640x360_25 1865
single-main_2560x1920 224
single-main_2560x1440 282
single-main_1920x1080 389
5-substreams 2203
5-mainstreams 317
5sub+5main 532
10x-main1440 319
20x-sub480 2321
40x-sub480 2335
T
  return $ok
}
# ADR: "about 0.7 Gpixel/s for 640x480 frames, 0.8 at 1080p and 1.0 to 1.2 at 1440p and above" -> check each saturated run
# against its stated band (+-0.1 Gpx/s) and that the ADR sentence is present.
pixel_rate_claim_holds() {
  local ok=0 label px fps lo hi g
  grep -q 'about 0.7 Gpixel/s for 640x480 frames, 0.8 at 1080p and 1.0 to 1.2 at 1440p and above' "$ADR" \
    || { echo "  ADR pixel-rate sentence missing" >&2; ok=1; }
  while read -r label px lo hi; do
    fps=$(awk -F'\t' -v l="$label" '$1==l && $2=="TOTAL"{sub("total_fps=","",$4); print $4}' "$R/decode.tsv")
    g=$(echo "$px * $fps / 1000000000" | bc -l)
    if ! echo "$g >= $lo && $g <= $hi" | bc -l | grep -q 1; then printf '  %s: %.2f Gpx/s outside %s-%s\n' "$label" "$g" "$lo" "$hi" >&2; ok=1; fi
  done <<'T'
single-main_2560x1920 4915200 0.95 1.25
single-main_2560x1440 3686400 0.95 1.25
single-main_1920x1080 2073600 0.7 0.9
10x-main1440 3686400 0.95 1.25
20x-sub480 307200 0.6 0.8
40x-sub480 307200 0.6 0.8
T
  return $ok
}

# YOLO table: GPU mean ms and fps in ADR match yolo.tsv.
yolo_table_matches() {
  local ok=0 m sz mean fps
  while read -r m sz mean fps; do
    grep -qP "^cuda\t${m}_${sz}\.onnx\tmean=${mean}ms\t.*fps=${fps}" "$R/yolo.tsv" || { echo "  $m $sz" >&2; ok=1; }
  done <<'T'
yolov8n 320 5.5 182
yolov8n 640 10.4 95.8
yolov8s 320 8.4 119
yolov8s 640 20.9 47.8
yolo11n 320 6.3 158
yolo11n 640 11.4 88
yolo11s 320 8.9 112.5
yolo11s 640 21.5 46.6
T
  return $ok
}
bgsub_numbers_match() { grep -q '95806 frames/s' "$R/bgsub.txt" && grep -q '14367 frames/s' "$R/bgsub.txt" && grep -q 'identical' "$R/bgsub.txt"; }
hevc_refutation_has_control() { grep -q 'hevc_cuvid is not supported' "$R/hevc.txt" && grep -q 'h264 control exit=0' "$R/hevc.txt"; }

# pip-freeze files are excluded: dotted package versions (for example the curand one) look like IPv4 addresses.
no_private_ips_or_macs() {
  ! grep -rIEn '\b(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b|\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b' \
    "$S2" "$ADR" --exclude-dir=target --exclude-dir=fixtures --exclude-dir=models --exclude='pip-freeze-*'
}
no_media_committed() { ! git -C "$ROOT" ls-files spikes/s2-gpu | grep -qiE '\.(mp4|mkv|h264|h265|hevc|jpg|jpeg|png|pt|onnx|data)$'; }
spike_not_in_workspace() {
  grep -q '^\[workspace\]' "$S2/cuda-bgsub/Cargo.toml" && ! grep -q 'spikes' "$ROOT/Cargo.toml"
}

check shellcheck_clean shellcheck_clean
check ort_versions_have_raw_evidence ort_versions_have_raw_evidence
check cuda13_fallback_claim_has_raw_evidence cuda13_fallback_claim_has_raw_evidence
check decode_rows_complete_and_error_free decode_rows_complete_and_error_free
check adr_loop_range_matches_raw adr_loop_range_matches_raw
check decode_totals_match decode_totals_match
check pixel_rate_claim_holds pixel_rate_claim_holds
check yolo_table_matches yolo_table_matches
check bgsub_numbers_match bgsub_numbers_match
check hevc_refutation_has_control hevc_refutation_has_control
check no_private_ips_or_macs no_private_ips_or_macs
check no_media_committed no_media_committed
check spike_not_in_workspace spike_not_in_workspace
[ "$fails" -eq 0 ]
