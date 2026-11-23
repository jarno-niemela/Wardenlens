# Supported cameras

<!-- Generated from cameras/*/*.toml. Do not edit by hand. Regenerate with:
WARDENLENS_BLESS=1 cargo test -p wardenlens-core --test catalogue -->

One row per camera model. Entry format: [FORMAT.md](FORMAT.md).
Events marked `*` are advertised by the camera but not yet seen live.

| Vendor | Model | Support | Firmware | Main stream | Events | Protocols | Configurable |
|---|---|---|---|---|---|---|---|
| Dahua | IPC-HFW4431R-Z (aka XR) | partial | - | 2560x1440 H.264 | motion, client_disconnect | rtsp, onvif, dahua_cgi | - |
| Reolink | RLC-520A | partial | 3.0 | 2560x1920 H.264 | motion*, person* | rtsp, onvif, baichuan | service_ports |
| RTT | RTT-8700 (aka HDIPC) | partial | - | 1920x1080 H.264 | - | rtsp, onvif | - |
| TP-Link | Tapo C110 | partial | 1.5 | 1920x1080 H.264 | motion*, person*, intrusion*, line_cross*, tamper*, smart_event* | rtsp, onvif, tapo_https | - |
