#!/usr/bin/env bash
# Sample each stream for SECS seconds (default 20) with ffprobe packet output and report
# keyframe interval (frames), measured fps and bitrate (kbit/s).
# Usage: [CAMERAS="id ..."] gop_sample.sh [secs]   (inventory ids; default: every camera with a vault host)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"
secs="${1:-20}"
printf 'stream\tpackets\tfps\tkbps\tgop_frames\tgop_seconds\n'
load_cams || exit 1
for name in "${CAMS[@]}"; do
  for kind in main sub; do
    path="$(rtsp_path "$name" "$kind")" || exit 1
    url="$(rtsp_url "$name" "$path")" || exit 1
    timeout $((secs + 30)) ffprobe -v error -rtsp_transport tcp -select_streams v:0 \
      -read_intervals "%+$secs" -show_entries packet=pts_time,size,flags -of csv=p=0 "$url" 2>/dev/null \
    | awk -F, -v n="$(cam_id "$name")" -v k="$kind" '
        NF>=3 { t=$1; sz+=$2; c++; if(!f){f=t}; l=t
                if ($3 ~ /K/) { if (last>=0 && c_at_last>=0) {gops[++g]=c-c_at_last}; c_at_last=c; last=c } }
        END { d=l-f; if (d<=0) { print n"-"k"\tno-data"; exit }
              s=0; for(i=1;i<=g;i++) s+=gops[i]; gop=(g? s/g : 0)
              printf "%s-%s\t%d\t%.1f\t%.0f\t%.0f\t%.2f\n", n, k, c, c/d, sz*8/d/1000, gop, (c/d>0? gop/(c/d):0) }
        BEGIN{last=-1; c_at_last=-1}'
  done
done
