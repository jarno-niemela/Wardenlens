# 0002. Camera integration (Phase 0 spike S1)

- Status: proposed
- Date: 2026-11-22
- Ticket: #20 (epic #15)

Cameras are referred to by inventory id only (`reolink-1`, `reolink-2`, `xr`, `tapo`, `hdipc`);
addresses and credentials are kept outside the repository. Everything below was measured against the
real cameras on the owner's LAN with AgentDVR running concurrently and pulling streams.
The probes are **read-only**: no camera setting was changed.

## Context

Wardenlens must ingest video and events from five cameras of four different vendors, without
exceeding what the cameras tolerate (cheap SoCs, a few concurrent clients) and without relying on
vendor clouds. The spike answers: do main and sub RTSP streams survive a second client, which
event channel should be used per vendor, and what does each vendor's local API require.

| id | model | notes |
|---|---|---|
| reolink-1, reolink-2 | Reolink RLC-520A (fw v3.0) | 2560x1920 H.264; Baichuan on 9000; HTTP disabled |
| xr | Dahua OEM IPC-HFW4431R-Z | 2560x1440 H.264; CGI with digest auth; 37777 open |
| tapo | Tapo C110 (fw 1.5) | 1080p H.264; ONVIF on 2020; HTTPS API on 443 |
| hdipc | RTT-8700 | 1080p H.264; ONVIF on 1018; ONVIF flaky |

## Measured results

### 1. Two-client RTSP tolerance (acceptance criterion 1: MET)

Method: `spikes/s1-cameras/stream_soak.sh` opened the main and the sub stream of every camera
(10 RTSP/TCP sessions) in parallel for 30 minutes with `ffmpeg -c copy -f null`, as a second client next to
AgentDVR, restarting a stream if ffmpeg exited. Results (`spikes/s1-cameras/results/soak-summary.tsv`):

| stream | frames in 1800 s | avg fps | expected at nominal fps | expected at measured fps | restarts | warning lines |
|---|---|---|---|---|---|---|
| reolink-1 main | 32933 | 18.3 | 54000 (30, advertised) | 30060 (16.7) | 0 | 0 |
| reolink-1 sub | 18001 | 10.0 | 18000 (10) | 18000 (10.0) | 0 | 0 |
| reolink-2 main | 29967 | 16.6 | 54000 (30, advertised) | 30060 (16.7) | 0 | 0 |
| reolink-2 sub | 17998 | 10.0 | 18000 (10) | 18180 (10.1) | 0 | 0 |
| xr main | 44992 | 25.0 | 45000 (25) | 45000 (25.0) | 0 | 0 |
| xr sub | 44993 | 25.0 | 45000 (25) | 45000 (25.0) | 0 | 105 |
| tapo main | 26991 | 15.0 | 27000 (15) | 27720 (15.4) | 0 | 8891 |
| tapo sub | 26996 | 15.0 | 27000 (15) | 26460 (14.7) | 0 | 8889 |
| hdipc main | 15292 | 8.5 | 18000 (10, ONVIF profile) | 15480 (8.6) | 0 | 0 |
| hdipc sub | 41491 | 23.0 | 45000 (25) | 44280 (24.6) | 0 | 0 |

"Measured fps" is the 20 s sample of section 1's second table, so it is a snapshot; the frame counts are
what ffmpeg wrote in 30 minutes. Every column means what was measured: ffmpeg restarts, and ffmpeg warning
lines. The test did **not** count dropped frames (stream copy to the null muxer reports `drop_frames=0`
unconditionally, so that field is not evidence). Reolink main is variable frame rate, so its count follows
the scene, not either expectation. hdipc sub delivered 7.8 % fewer frames than nominal and 6.3 % fewer than
its sampled rate: ffmpeg's progress shows the stream clock advanced in real time (`out_time` 30:00, speed 1x),
with no warnings and no restarts, so the camera sent fewer frames than 25 fps; the cause is **unexplained**
(open risk 5 below). The warning types per stream are in `results/soak-warnings.tsv` (a histogram with
numbers normalised; the raw logs were not committed).

All ten sessions ran the full 30 minutes with zero restarts (RTSP over TCP). Over TCP ffmpeg does not log
packet loss, so absence of warnings is not proof of no loss. The only log noise was ffmpeg's "non monotonically increasing dts" muxer
warning in stream-copy mode: 0 for most streams, 8891 and 8889 lines for tapo main/sub and 105 for
xr sub. This points to jittery camera RTP timestamps; Phase 1 must not trust camera timestamps blindly and should
stamp its own arrival clock. Limit of the test: it proves a second client with AgentDVR's sessions
present, not the camera's maximum client count.

Stream parameters (`gop_sample.sh`, 20 s sample, `results/stream-params.tsv`; all H.264 High profile
except where noted, yuv420p; xr uses full-range yuvj420p):

| stream | resolution | fps | bitrate | GOP |
|---|---|---|---|---|
| reolink-1/2 main | 2560x1920 | ~16.7 (30 advertised; variable) | ~2.9 Mbit/s | 32 frames (~1.9 s) |
| reolink-1/2 sub | 640x480 | 10 | 0.1-0.2 Mbit/s | 40 frames (4 s) |
| xr main | 2560x1440 | 25 | 4.3 Mbit/s (CBR, configured 4096) | 50 (2 s) |
| xr sub | 704x576 | 25 | 1.0 Mbit/s (CBR, configured 1024) | 50 (2 s) |
| tapo main | 1920x1080 | 15 | 0.19 Mbit/s (static scene) | 30 (~2 s) |
| tapo sub | 640x360 | 15 | 0.04 Mbit/s | 30 (~2 s) |
| hdipc main | 1920x1080 | 8.6 (ONVIF profile says 10) | 8.6 Mbit/s | 30 (3.5 s) |
| hdipc sub | 640x360 | 25 | 2.0 Mbit/s | 25 (1 s) |

Notes: Reolink main reports `r_frame_rate` 60-80 and avg 30 in the SDP but actually delivers variable
frame rate (about 17 fps in this scene). Bitrates vary with scene content; Reolink and Tapo are VBR.
RTSP paths: Reolink `/h264Preview_01_{main,sub}`; Dahua `/cam/realmonitor?channel=1&subtype={0,1}`;
Tapo `/stream1`, `/stream2`; hdipc `/11`, `/12` (discovered with ONVIF `GetStreamUri`; `/` returns 400).
The first RTSP connection to hdipc main failed once (25 s timeout in `probe_streams.sh`) and succeeded on retry
(same flakiness as its ONVIF port, see below).

### 2. Reolink (reolink-1, reolink-2)

Criterion "Baichuan login + event push proven": **login MET; event subscription MET; push of motion transitions MET (#27);
AI person push NOT observed** (see below).

- Tool: `spikes/s1-cameras/baichuan-probe` (standalone, not a workspace member), a thin wrapper over
  `neolink_core` (AGPL-3.0, so it is for the spike only and must not be linked into Wardenlens; a
  patch adds one debug print). Run through `run_baichuan.sh`, which feeds credentials via environment.
- Login on port 9000 succeeds (modern, encrypted BC login) on both cameras with the same account that
  AgentDVR uses. Device info: RLC-520A, firmware v3.0, resolution 2560x1920.
- Service ports (read with Baichuan `MSG_ID_GET_SERVICE_PORTS` = 37, read-only):

  | service | port | reolink-1 | reolink-2 |
  |---|---|---|---|
  | Baichuan | 9000 | enabled flag 0 (but the connection works) | same |
  | HTTP | 80 | **disabled** | **disabled** |
  | HTTPS | 443 | disabled | disabled |
  | RTSP | 554 | enabled | enabled |
  | RTMP | 1935 | disabled | enabled |
  | ONVIF | 8000 | enabled | enabled |

  Anomaly: port 80 of reolink-2 accepts TCP and answers `500 Internal Server Error` although HTTP is
  reported disabled; port 80 of reolink-1 is closed. The `enable` flag for the Baichuan port itself reads 0 while the
  port is demonstrably serving, so the flag is unreliable for that service.
- **HTTP API enable path (identified, not executed):** the Reolink HTTP API (`/api.cgi`, command
  `SetNetPort`) cannot be used to enable itself, because it is off. The same setting is writable over
  Baichuan with `MSG_ID_SET_SERVICE_PORTS` = 36 carrying the `HttpPort` XML (`httpPort` 80, `enable` 1);
  neolink implements it as `set_http` (and `set_https`, `set_rtsp`, `set_onvif`). Wardenlens should perform this write
  itself, later, behind its approve/revert flow: read the current `HttpPort`, show the diff, write `enable=1`, and keep the
  original XML to revert. Not performed in this spike.
- Event push: `MSG_ID_MOTION_REQUEST` (31) subscribes; the camera then pushes `MSG_ID_MOTION` (33) messages whose
  XML is `AlarmEventList/AlarmEvent` with fields `channelId`, `status` (`MD` while motion is active, `none`),
  `AItype` (`people` while a person is detected; per neolink `none` otherwise), `recording`, `timeStamp`.
  The subscription was accepted on both cameras and the camera immediately pushed the initial
  state message (`status=none`, `AItype=none`).
- **Live capture (#27, see `results/events/reolink-msg33-excerpt.log`):** three walks in front of one
  RLC-520A (listening 900 s, 1000 s and 1500 s) produced 32 MSG 33 pushes (17 + 7 + 8), 15 `status="MD"` starts, each followed by a
  `status="none"` stop. The probe prints the fields as `status`, `ai_type`, `channel_id`, `recording`, `timeStamp`.
  - Cadence: one push per transition only (no periodic repeats); `MD` to `none` took 2 to 12 s (2, 2, 3, 4, 4, 5, 11, 12 s
    in the first walk). `recording` and `timeStamp` were always 0, so the camera supplies no event time and Wardenlens
    must stamp arrivals itself.
  - **`ai_type` stayed `"none"` in all 32 pushes, including all 15 motion events.** No `people`, `vehicle` or `dog_cat`
    value was ever seen on Baichuan MSG 33, so vehicle and animal values on this firmware remain unknown.
  - The camera's AI configuration says person detection should work: with HTTPS temporarily enabled (owner-approved
    write over Baichuan `MSG_ID_SET_SERVICE_PORTS`, reverted afterwards; `enable` 0 to 1 to 0, confirmed by re-reading),
    `GetAiCfg` returned `AiDetectType` people=1, vehicle=1, dog_cat=1, face=0, and `GetAiState` returned `support`=1 for
    people, vehicle and dog_cat (face 0) with every `alarm_state` 0 (`results/events/reolink-GetAi*.json`).
  - **Open question for Phase 2:** why no AI type arrived. Candidates: (a) the walks did not trigger AI detection (distance,
    angle or posture, or detection needs a person-shaped target for several frames) while the pixel motion detector did;
    (b) AI alarms arrive on a different Baichuan message than MSG 33 (or only with a different subscription);
    (c) the AI state must be polled (`GetAiState` over HTTPS, or the Baichuan equivalent) instead of being pushed.
    Follow-up spike: #78; until then do not rely on Baichuan for person events.

### 3. Dahua (xr)

Criterion "eventManager attach long-poll proven; encoder/IVS config read": **MET**.

- `GET /cgi-bin/eventManager.cgi?action=attach&codes=[All]` with HTTP digest auth returns `200` with
  `multipart/x-mixed-replace; boundary=myboundary` and stays open. A first run held the connection 330 s with no
  event (quiet scene). A second 25 min watch delivered events, for example (3 start/stop pairs in total):
  `Code=VideoMotion;action=Start;index=0` ... `action=Stop`, `Code=VideoMotionInfo;action=State;index=0`, and
  `Code=RtspSessionDisconnect;action=Start|Stop` (this fires when another client's RTSP session ends,
  so it is a free client-presence signal). Each part is `Content-Type: text/plain`, `Content-Length`, then a
  `Code=..;action=..;index=..` line.
- The `heartbeat=` parameter did not produce visible heartbeat parts in 25 s; a dead connection must be detected via TCP
  keepalive plus a read timeout, or by a periodic cheap request.
- `curl` needs `-g` (no URL globbing) for `[All]`; the camera echoes the HTTP response header in the body (188 bytes).
- Encoder (`configManager.cgi?action=getConfig&name=Encode`): MainFormat 2560x1440 H.264 High 25 fps CBR 4096 kbit/s
  GOP 50; ExtraFormat[0] 704x576 H.264 High 25 fps CBR 1024 kbit/s GOP 50; audio disabled on both.
- IVS (`VideoAnalyseRule`, `VideoAnalyseModule`, `VideoAnalyseGlobal`): only HeatMap, FaceDetection and NumberStat rules exist, all disabled
  or unconfigured; no tripwire/intrusion rule is configured. `MotionDetect[0].Enable=true`, level 3. This firmware generation is
  classic motion detection; AI person/vehicle events (`SmartMotionHuman`) were not offered or observed.
- Other: `eventManager.cgi?action=getCaps` and `devVideoAnalyse.cgi?action=getCaps` return "Invalid Request" on this firmware;
  `magicBox.cgi?action=getSystemInfo` works. Port 37777 (Dahua private SDK) is open but was not used.
- Each CGI call takes 0.05-1.5 s (the first with digest handshake).

### 4. Tapo (tapo)

Criterion "what the local API needs documented": **MET** (partly from public knowledge, flagged below).

- ONVIF on port 2020 works with WS-Security UsernameToken digest using the *Camera Account*
  (the credentials created in the Tapo app under Advanced Settings > Camera Account): `GetCapabilities`
  lists Device, Media, Events, Imaging and Analytics at a single `/onvif/service` URL, with
  `WSPullPointSupport` and `WSSubscriptionPolicySupport` true. Responses take 6-9 ms.
- Event topics (`GetEventProperties`, all under `tns1:RuleEngine`): `Motion` (`IsMotion`), `People` (`IsPeople`), `Intrusion`
  (`IsIntrusion`), `LineCross` (`IsLineCross`), `Tamper` (`IsTamper`) and `TPSmartEvent` (`IsTPSmartEvent`).
  **No vehicle or animal topic is offered.**
- PullPoint: `CreatePullPointSubscription` works. `PullMessages` with `Timeout=PT10S` returns an empty reply
  (connection closed) whereas `PT5S` returns a normal 200 after about 5.9 s; 150 consecutive `PT5S` polls
  (15 min) all returned 200. The pull-point address the camera returns is on a **different port of the same host** as the
  ONVIF service, so a client must compare the host only (not the port) before following it (`onvif_pull.sh` does).
- **Live capture (#27, `results/events/tapo-*.xml`):** three watches (the owner walked in view of the camera). Across the watches 277 `Motion` and 29 `People` notification lines
  were logged. Observed format (`wsnt:NotificationMessage` in `tev:PullMessagesResponse`):
  - `wsnt:Topic` (dialect `ConcreteSet`): `tns1:RuleEngine/CellMotionDetector/Motion` or
    `tns1:RuleEngine/PeopleDetector/People`. Only these two topics were seen.
  - `tt:Message` attributes `PropertyOperation` (always `Initialized` in the captured raw set: 14 People, 6 Motion; no
    `Changed` was captured, so confirm the transition value in Phase 1) and `UtcTime` (camera clock).
  - `tt:Source` SimpleItems: `VideoSourceConfigurationToken`=`vsconf`, `VideoAnalyticsConfigurationToken`=`VideoAnalyticsToken`,
    `Rule`=`MyMotionDetectorRule` (Motion) or `MyPeopleDetectorRule` (People).
  - `tt:Data` SimpleItem: `IsMotion`=`true`, or `IsPeople`=`true`/`false` (13 true, 1 false in the raw set).
  - **Attribute order is `Value` before `Name`** (`<tt:SimpleItem Value="true" Name="IsPeople">`), the reverse of the ONVIF
    examples; parse by attribute name with a real XML parser, not by position or regex.
  - `IsPeople` was seen both true and false, so the AI person state works live on the C110; vehicle and animal never
    appeared (consistent with the topic list). Intrusion, LineCross, Tamper and TPSmartEvent were not triggered.
- The local non-ONVIF API (HTTPS on 443, JSON `securePassthrough`/KLAP handshake, used by `pytapo`, and a
  media port 8800 that is also open) needs the **TP-Link cloud account** credentials, not the Camera Account: the account name is fixed by the firmware
  and the password is the cloud account password (newer firmware hashes it, with the KLAP/TPAP
  handshake). An unauthenticated probe of 443 answered with a Tapo JSON error (`error_code -40413`), which
  confirms the endpoint exists. No login was attempted (account lockout risk and that password is not in the
  inventory); that requirement is documented from community implementations, not verified here.
- Recommendation: use ONVIF (Camera Account) only; do not store the cloud password.

### 5. HDIPC (hdipc)

Criterion "ONVIF retry/timeout behaviour characterised": **MET**.

Method: `onvif_flaky.sh`, 60 rounds, 5 s apart, one unauthenticated `GetSystemDateAndTime` and one authenticated
`GetDeviceInformation` per round, fresh TCP connection each, 10 s client timeout (`results/hdipc-onvif.tsv`).

| request | attempts | failed (10 s timeout) | successful latency |
|---|---|---|---|
| unauthenticated | 60 | 21 (35 %) | avg 278 ms, two successes at 5.1 s (consistent with a SYN retransmit) |
| authenticated | 60 | 26 (43 %) | avg 16 ms, max 58 ms |

Across both kinds, successful requests had p50 11 ms and p95 42 ms.

- Failures are TCP connect timeouts, not SOAP faults: the camera simply ignores the connection attempt for a
  while. Success is almost always fast (about 10-60 ms). Failures cluster: after a failure the next
  attempt (5 s later) fails again 11 of 25 times (auth) and 9 of 21 (unauth). Longest runs of consecutive
  failures: **auth 8** in a row (rounds 14-21, about 130 s of wall-clock including the 10 s timeouts and
  5 s pauses), **noauth 4** (rounds 43-46, about 55 s), and 4 in the combined time-ordered series
  (rounds 25-26, about 45 s). Durations are reconstructed from the per-request seconds plus the 5 s pause.
  Six attempts in a row can therefore fail, and a single outage can last a couple of minutes.
- Behaviour contract for the adapter, two levels:
  1. A single request retries quickly: connect timeout 2-3 s, a few attempts (up to 6) with a ~2-5 s backoff.
     Note: the 2-3 s connect timeout is untested (the spike used 10 s); it is tracked in #28.
  2. Beyond that, the driver has a total retry budget of **at least 3 minutes** (longer than the worst
     observed outage). It retries in the background, serves the last good result from cache and marks the camera
     *degraded* rather than failing; it never blocks the video path on ONVIF, and ONVIF is not relied on for
     long-lived state.
- ONVIF details: `GetCapabilities` works with a UsernameToken digest; media, events and PTZ are all served from
  the one `/onvif/device_service` URL; `GetStreamUri` returns `/11` (main, 1080p H.264 10 fps profile, G.711 audio) and `/12` (sub,
  640x360). Events are advertised (`WSSubscriptionPolicySupport`), but no event subscription was attempted because of the flakiness.
- The plain HTTP server on port 80 (thttpd) is also reachable at times; the RTSP port 554 shows the same
  occasional slow first connect.

## Capability matrix

| capability | reolink-1/2 | xr (Dahua) | tapo | hdipc |
|---|---|---|---|---|
| RTSP main + sub, 2nd client OK (30 min) | yes | yes | yes | yes (slow first connect) |
| Codec | H.264 | H.264 | H.264 | H.264 |
| Main resolution / fps | 2560x1920 / ~17 (VFR) | 2560x1440 / 25 | 1920x1080 / 15 | 1920x1080 / 8.6 |
| Sub resolution / fps | 640x480 / 10 | 704x576 / 25 | 640x360 / 15 | 640x360 / 25 |
| Audio | not checked | disabled | not checked | G.711 advertised |
| Native event channel | Baichuan push (9000) | CGI `eventManager` long-poll | ONVIF PullPoint | ONVIF (unreliable) |
| Motion | yes (`MD`, observed live) | yes (`VideoMotion`) | yes (`IsMotion`, observed live) | not tested |
| AI person | Baichuan `AItype=people`: **not seen live** (`ai_type` always `none`; camera AI cfg has people on), open question | not offered (no IVS rule) | `IsPeople` (observed live, true and false) | none |
| Other events | none seen (no vehicle/animal on MSG 33) | `RtspSessionDisconnect`, `VideoMotionInfo` | Intrusion, LineCross, Tamper, TPSmartEvent | n/a |
| ONVIF | yes (8000, enabled) | yes (80, not probed in depth) | yes (2020, works) | yes (1018, flaky) |
| Vendor HTTP API | disabled; enable via Baichuan SET_SERVICE_PORTS | CGI with digest, works | HTTPS 443 needs cloud password | thttpd, not used |
| Config read | Baichuan service ports | `configManager.cgi` Encode/IVS/MotionDetect | ONVIF profiles | ONVIF profiles |

## Options

1. ONVIF everywhere. Uniform, one adapter, but Reolink motion/AI over ONVIF is limited, hdipc ONVIF is
   unreliable, and Dahua ONVIF was not evaluated in depth.
2. Vendor-native event channel per vendor with ONVIF as the fallback; RTSP for video everywhere.
3. A third-party NVR (AgentDVR) as the event source. Rejected: it defeats the project.

## Decision

Option 2.

- **Video:** RTSP over TCP with the `retina` Rust crate (or ffmpeg as a fallback), main plus sub per camera. A second client is
  safe in all measured cases. Use a camera-clock-independent arrival timestamp (DTS noise on Tapo and Dahua sub).
- **Reolink:** Baichuan (port 9000) for events and for reading/writing service ports. Implement the small subset
  needed (login, MSG 31/33, MSG 36/37) natively in Rust. Do not link neolink (AGPL); use it as protocol reference.
  Enable the HTTP API only through the approve/revert flow, and only if a feature needs it.
- **Dahua:** CGI `eventManager.cgi?action=attach` long-poll with digest auth, reconnect with backoff, TCP
  keepalive and a read-idle timeout; `configManager.cgi` for config reads. AI person events need a different
  Dahua model or firmware; classic motion only for now.
- **Tapo:** ONVIF PullPoint with the Camera Account, 5 s PullMessages timeout; renew the subscription.
  Do not use the cloud-password API.
- **HDIPC:** RTSP for video (paths via ONVIF discovery, then cached). ONVIF only for one-off discovery with the
  retry contract above; motion via Wardenlens' own detection on the sub stream.

## Consequences

- Four small adapters behind one `EventSource` trait in a non-core crate (I/O stays out of `wardenlens-core`).
- Adapters must expose connection state and reconnect themselves; flaky hdipc is the test case.
- Wardenlens needs a per-camera connection budget and its own timestamps.

## Open risks and follow-ups

1. Reolink AI person events were not seen on Baichuan MSG 33 (`ai_type` always `none` in 15 motion events, though `GetAiCfg`
   people=1 and `GetAiState` support=1). Follow-up spike: #78 (see the Reolink section); #27 captured motion only.
2. Tapo `PropertyOperation` was `Initialized` for every captured notification; a `Changed` transition was not captured
   (also tracked with the Reolink AI question in #78).
   The pull-point address the camera returns is untrusted input: Phase 1 must parse it with a real URL parser, reject
   userinfo, and require the configured host (any port) before sending credentials to it.
3. Dahua `heartbeat` not honoured; dead-connection detection must be built and tested.
4. The 2-client test did not find the maximum client count; Wardenlens plus AgentDVR plus a probe worked, which is the
   Phase 1 migration scenario, but a third concurrent consumer on Reolink was only briefly exercised.
5. (#28) hdipc connectivity is flaky at the TCP level (about 40 % of connection attempts time out); the cause (connection slots, a
   network issue or the camera firmware) is unknown. Check whether it is the camera, the switch port or AgentDVR holding
   slots before relying on it. The 7.8 % frame shortfall on hdipc sub (section 1) is also unexplained; include it in #28.
6. Variable frame rate on Reolink main (about 17 fps against 30 advertised) and the DTS jitter on Tapo and Dahua sub
   affect any logic that assumes a constant fps.
7. Baichuan is proprietary and firmware-dependent; the `enable` flag for the Baichuan service reads 0 while it works.
8. neolink is AGPL-3.0; code must be written independently from the protocol description.
9. The HTTP enable write (`SET_SERVICE_PORTS`) was not executed, so its exact behaviour (reboot required or not) is untested.
10. Phase 1 items (the `EventSource` adapters, own arrival timestamps, per-camera connection budget, the retry
    contract above) are to be filed by `/plan-epic #16`.
11. **Accepted spike-only risk: credentials on argv.** `ffmpeg` and `ffprobe` accept RTSP credentials only inside
    the URL, so the spike scripts pass them on the command line, visible to other local users in
    `/proc/*/cmdline` while a probe runs. Accepted because the spike runs on a single-user host; everything
    else (curl config on a pipe, ONVIF envelope on stdin, jq stdin, Baichuan via environment) keeps secrets
    off argv, and all output goes through `redact`. Phase 1 uses `retina` in-process, so no credentials
    reach a child process.
