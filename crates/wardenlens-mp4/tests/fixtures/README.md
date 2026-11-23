# Fixture provenance

`testsrc.h264` is a synthetic H.264 Annex-B elementary stream (35,432 bytes, under the 50 KiB limit):
2 seconds, 50 frames, 25 fps, 320x180 (the SPS carries cropping: 180 is not a multiple of 16), High profile,
no B-frames, a keyframe every 25 frames. It contains no camera data.

Generated with ffmpeg 8.0.1 (libx264):

```sh
ffmpeg -f lavfi -i testsrc2=size=320x180:rate=25 -t 2 \
  -c:v libx264 -profile:v high -bf 0 -g 25 -keyint_min 25 -sc_threshold 0 \
  -crf 32 -preset veryfast -threads 1 -f h264 testsrc.h264
```

Used only by the `#[ignore]` test in `tests/ffmpeg.rs`, which muxes it with this crate and checks it with
`ffprobe` and `ffmpeg` (run: `cargo test -p wardenlens-mp4 -- --ignored`).
