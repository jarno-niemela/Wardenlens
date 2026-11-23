# S1 camera spike probes (ticket #20)

Throwaway probes behind `docs/adr/0002-camera-integration.md`. **Read-only** toward the cameras, with one exception:
`run_baichuan.sh <camera> <secs> https-on|https-off` **WRITES** the camera's HTTPS service-port setting and needs the
camera owner's explicit approval each time (`https-off` disables it). The default mode and `abilities` only read.

Inputs (outside the repo, never committed):

- `~/.config/wardenlens/agentdvr-cameras.secret.json` (credentials, by camera name), override with `WARDENLENS_SECRET_FILE`
- `~/.config/wardenlens/cameras.local.toml` (hosts by camera id), override with `WARDENLENS_CAMERAS`

| script | purpose |
|---|---|
| `lib.sh` | shared helpers: inventory and credential lookup, RTSP URL builder, `redact` (masks userinfo, IPv4/IPv6, MAC, serials; it does NOT mask DNS hostnames) |
| `probe_streams.sh` | one-shot ffprobe of every main/sub stream |
| `stream_soak.sh <dir> [secs]` | all streams in parallel for 30 min: frames, warning lines, restarts |
| `gop_sample.sh [secs]` | fps, bitrate and GOP per stream |
| `onvif.sh` | minimal ONVIF SOAP client (WS-Security digest) |
| `onvif_pull.sh` | ONVIF PullPoint event watcher (Tapo); `ONVIF_PULL_RAW_DIR` saves redacted raw notifications |
| `onvif_flaky.sh` | ONVIF reliability measurement (hdipc) |
| `dahua.sh` | Dahua CGI GET and `eventManager` attach long-poll |
| `run_baichuan.sh` + `baichuan-probe/` | Reolink Baichuan login, service-port read, motion event push; optional action `abilities` (read) or `https-on`/`https-off` (WRITE, owner approval) |

`baichuan-probe` is not a workspace member and depends on `neolink_core` (AGPL-3.0): clone neolink at
commit `6e05e78`, apply `baichuan-probe/neolink-debug.patch`, link or copy it as `baichuan-probe/neolink`, and
`cargo build --release`. Spike only; never link it into Wardenlens.

`results/` holds the measured outputs quoted in the ADR (camera ids only); `results/events/` has the redacted live
event captures from #27.
Never print `rtsp_url` output; pipe tool output through `redact`.

Known spike-only risk: `ffmpeg`/`ffprobe` can take RTSP credentials only in the URL, so they appear on those
processes' argv while running (readable by other local users). Accepted for this single-user host; see ADR 0002
(open risk 11). Phase 1 uses `retina` in-process. `tests/lib.adv.sh` runs the helper and script tests against
fake config files only.
