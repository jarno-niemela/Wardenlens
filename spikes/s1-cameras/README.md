# S1 camera spike probes (ticket #20)

Throwaway probes behind `docs/adr/0002-camera-integration.md`. **Read-only** toward the cameras.

Inputs (outside the repo, never committed):

- `~/.config/wardenlens/agentdvr-cameras.secret.json` (credentials, by camera name), override with `WARDENLENS_SECRET_FILE`
- `~/.config/wardenlens/cameras.local.toml` (hosts by camera id), override with `WARDENLENS_CAMERAS`

| script | purpose |
|---|---|
| `lib.sh` | shared helpers: inventory and credential lookup, RTSP URL builder, `redact` (masks userinfo and IPv4) |
| `probe_streams.sh` | one-shot ffprobe of every main/sub stream |
| `stream_soak.sh <dir> [secs]` | all streams in parallel for 30 min: frames, drops, reconnects |
| `gop_sample.sh [secs]` | fps, bitrate and GOP per stream |
| `onvif.sh` | minimal ONVIF SOAP client (WS-Security digest) |
| `onvif_pull.sh` | ONVIF PullPoint event watcher (Tapo) |
| `onvif_flaky.sh` | ONVIF reliability measurement (hdipc) |
| `dahua.sh` | Dahua CGI GET and `eventManager` attach long-poll |
| `run_baichuan.sh` + `baichuan-probe/` | Reolink Baichuan login, service-port read, motion event push |

`baichuan-probe` is not a workspace member and depends on `neolink_core` (AGPL-3.0): clone neolink at
commit `6e05e78`, apply `baichuan-probe/neolink-debug.patch`, link or copy it as `baichuan-probe/neolink`, and
`cargo build --release`. Spike only; never link it into Wardenlens.

`results/` holds the measured outputs quoted in the ADR (camera ids only).
Never print `rtsp_url` output; pipe tool output through `redact`.
