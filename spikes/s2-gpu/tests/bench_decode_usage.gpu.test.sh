#!/usr/bin/env bash
# Adversarial (round 3, ticket #21): bench_decode.sh counts frames exactly, fails mixed runs, and does not hang on misuse.
# Needs Docker + GPU + the wl-s2-ffmpeg image; prints "skip" and exits 0 otherwise. Runs in about 30 s.
set -uo pipefail
S2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v docker >/dev/null || ! docker image inspect wl-s2-ffmpeg >/dev/null 2>&1; then
  echo "skip (no docker or wl-s2-ffmpeg image)"; exit 0
fi
# shellcheck source=../lib.sh
source "$S2/lib.sh"
set +e # lib.sh turns on errexit; this test inspects exit codes
fails=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1: $2"; fails=$((fails + 1)); }
# 3 s at 10 fps = 30 frames per play.
run_in_ffmpeg '[ -f /fx/adv_ok.mp4 ] || ffmpeg -v error -y -f lavfi -i testsrc2=size=640x480:rate=10:duration=3 -c:v libx264 -g 20 -pix_fmt yuv420p -an /fx/adv_ok.mp4'
owner=$(stat -c %u "$S2/fixtures/adv_ok.mp4")
if [ "$owner" = "$(id -u)" ]; then ok fixture_owned_by_invoking_user; else bad fixture_owned_by_invoking_user "uid $owner"; fi
out=$(LOOPS=2 "$S2/bench_decode.sh" adv-ok h264_cuvid adv_ok adv_ok 2>&1); rc=$?
rows=$(printf '%s\n' "$out" | awk -F'\t' '$2=="stream" && $4=="90 frames"' | wc -l)
if [ "$rc" -eq 0 ] && [ "$rows" -eq 2 ] && printf '%s\n' "$out" | grep -qP '\tTOTAL\t'; then ok loops_counted_exactly; else
  bad loops_counted_exactly "rc=$rc rows_with_90_frames=$rows"; printf '%s\n' "$out" | sed 's/^/  /'; fi
out=$(LOOPS=0 "$S2/bench_decode.sh" adv-mixed h264_cuvid adv_ok adv_clip_that_does_not_exist 2>&1); rc=$?
if [ "$rc" -ne 0 ] && ! printf '%s\n' "$out" | grep -qP '\tTOTAL\t'; then ok one_failed_stream_fails_whole_run; else
  bad one_failed_stream_fails_whole_run "rc=$rc"; fi
# No clips: must exit non-zero promptly, not wait forever on the dmon/VRAM sampler jobs.
before=$(docker ps -q --filter ancestor=wl-s2-ffmpeg | sort)
timeout 30 "$S2/bench_decode.sh" adv-noclips h264_cuvid >/dev/null 2>&1; rc=$?
# timeout kills the docker client, not the container: kill containers this case started
comm -13 <(printf '%s\n' "$before") <(docker ps -q --filter ancestor=wl-s2-ffmpeg | sort) | xargs -r docker kill >/dev/null
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then ok no_clips_fails_fast; else
  bad no_clips_fails_fast "rc=$rc (124 = still running after 30 s)"; fi
[ "$fails" -eq 0 ]
