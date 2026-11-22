#!/usr/bin/env bash
# Generate synthetic H.264 fixtures (testsrc2) matching the S1 camera stream parameters, plus one HEVC clip.
# Output: spikes/s2-gpu/fixtures/*.mp4 (gitignored; regenerate any time).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
build_ffmpeg_image
run_in_ffmpeg '
set -e
gen() { # name size fps bitrate codec
  [ -f /fx/$1.mp4 ] && return
  ffmpeg -v error -y -f lavfi -i "testsrc2=size=$2:rate=$3:duration=20" -c:v $5 -b:v $4 -maxrate $4 -bufsize $4 \
    -g $(( $3 * 2 )) -pix_fmt yuv420p -an /fx/$1.mp4
}
# sub streams (S1: 640x480@10, 704x576@25, 640x360@15, 640x360@25)
gen sub_640x480   640x480   10 200k  libx264
gen sub_704x576   704x576   25 1M    libx264
gen sub_640x360_15 640x360  15 100k  libx264
gen sub_640x360_25 640x360  25 2M    libx264
# main streams (2560x1920@17, 2560x1440@25, 1920x1080@15, 1920x1080@9)
gen main_2560x1920 2560x1920 17 3M   libx264
gen main_2560x1440 2560x1440 25 4M   libx264
gen main_1920x1080 1920x1080 15 2M   libx264
# HEVC probe clip
gen hevc_1920x1080 1920x1080 15 2M   libx265
ls -l /fx
'
