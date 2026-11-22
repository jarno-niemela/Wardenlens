#!/usr/bin/env bash
# Adversarial (round 4, ticket #21): bench_decode.sh must reject blank clip names instead of hanging.
# An empty or whitespace-only clip argument passes the "$# -lt 3" check but word-splits to no clips inside the
# container, so the loop starts no decoder and the bare wait then waits on the dmon/VRAM samplers forever.
# Needs Docker + GPU + the wl-s2-ffmpeg image; prints "skip" and exits 0 otherwise. Runs in at most about 40 s.
set -uo pipefail
S2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v docker >/dev/null || ! docker image inspect wl-s2-ffmpeg >/dev/null 2>&1; then
  echo "skip (no docker or wl-s2-ffmpeg image)"; exit 0
fi
fails=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1: $2"; fails=$((fails + 1)); }
attempt() { # name clip-arg
  local before rc
  before=$(docker ps -q --filter ancestor=wl-s2-ffmpeg | sort)
  timeout 15 "$S2/bench_decode.sh" "adv-$1" h264_cuvid "$2" >/dev/null 2>&1; rc=$?
  # timeout kills the docker client, not the container: kill containers this case started
  comm -13 <(printf '%s\n' "$before") <(docker ps -q --filter ancestor=wl-s2-ffmpeg | sort) | xargs -r docker kill >/dev/null 2>&1
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then ok "$1"; else bad "$1" "rc=$rc (124 = still running after 15 s)"; fi
}
attempt empty_clip_name_fails_fast ""
attempt whitespace_clip_name_fails_fast "   "
[ "$fails" -eq 0 ]
