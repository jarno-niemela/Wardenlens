#!/usr/bin/env bash
# Soak test: open every camera's main and sub RTSP stream in parallel (as an extra client next
# to AgentDVR) for DURATION seconds, counting frames, warning lines and restarts.
# Usage: [CAMERAS="id ..."] stream_soak.sh <out-dir> [duration-seconds]   (default 1800)
# Per-stream log: <out-dir>/<cam>_<kind>.log (credentials redacted); summary: <out-dir>/summary.tsv
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"
out="$1"; duration="${2:-1800}"
if [[ -e "$out" ]]; then
  [[ -d "$out" ]] || { echo "refusing to run: $out is not a directory" >&2; exit 1; }
  listing="$(ls -A "$out")" || { echo "refusing to run: cannot list $out" >&2; exit 1; }
  [[ -z "$listing" ]] || { echo "refusing to run: $out is not empty" >&2; exit 1; }
fi
mkdir -p "$out"
deadline=$(( $(date +%s) + duration ))

run_stream() { # <cam> <kind>
  local cam="$1" kind="$2" tag restarts=0 url left rc
  tag="$(printf '%s_%s' "${cam// /_}" "$kind" | tr -d '()')"
  url="$(rtsp_url "$cam" "$(rtsp_path "$cam" "$kind")")" || return 1
  : >"$out/$tag.log"; : >"$out/$tag.progress"
  while :; do
    left=$(( deadline - $(date +%s) ))
    (( left > 0 )) || break
    set +e
    ffmpeg -nostdin -hide_banner -loglevel warning -rtsp_transport tcp -timeout 15000000 \
      -i "$url" -t "$left" -map 0:v:0 -c copy -f null -progress "$out/$tag.progress" \
      -stats_period 30 - 2>&1 | redact >>"$out/$tag.log"
    rc=${PIPESTATUS[0]}
    set -e
    left=$(( deadline - $(date +%s) ))
    if (( left > 2 )); then
      restarts=$(( restarts + 1 ))
      echo "RESTART #$restarts rc=$rc at $(date -u +%T)" >>"$out/$tag.log"
      sleep 2
    fi
  done
  echo "$restarts" >"$out/$tag.restarts"
}

# Cameras: the inventory ids in CAMERAS (space separated), else every camera with a host in the vault.
mapfile -t ids < <(selected_cams)
(( ${#ids[@]} > 0 )) || { echo "no cameras: set CAMERAS or add cam:<id>:host vault entries" >&2; exit 1; }
streams=()
for id in "${ids[@]}"; do streams+=("$id:main" "$id:sub"); done
# Fail before starting anything if a URL cannot be built (unknown camera, missing host).
for s in "${streams[@]}"; do rtsp_url "${s%%:*}" "$(rtsp_path "${s%%:*}" "${s##*:}")" >/dev/null || exit 1; done
for s in "${streams[@]}"; do run_stream "${s%%:*}" "${s##*:}" & done
wait

printf 'stream\trestarts\tlast_frame_count_per_run\twarnings\n' >"$out/summary.tsv"
for s in "${streams[@]}"; do
  cam="${s%%:*}"; kind="${s##*:}"
  tag="$(printf '%s_%s' "${cam// /_}" "$kind" | tr -d '()')"
  restarts="$(cat "$out/$tag.restarts" 2>/dev/null || echo -)"
  frames="$(grep -E '^frame=' "$out/$tag.progress" 2>/dev/null | tail -1 | cut -d= -f2 || true)"
  warns="$(grep -cviE 'RESTART|^$' "$out/$tag.log" 2>/dev/null || true)"
  printf '%s\t%s\t%s\t%s\n' "$tag" "$restarts" "${frames:-0}" "${warns:-0}" >>"$out/summary.tsv"
done
