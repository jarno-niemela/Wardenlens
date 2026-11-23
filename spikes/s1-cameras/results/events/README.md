# Live event captures (ticket #27)

Redacted evidence quoted in ADR 0002. Cameras by role only.

- `tapo-*.xml`: Tapo C110 ONVIF PullPoint `PullMessagesResponse` bodies (`IsPeople` true and false, `IsMotion` true).
- `reolink-msg33-excerpt.log`: Reolink RLC-520A Baichuan `MSG_ID_MOTION` (33) pushes as parsed by `baichuan-probe`.
- `reolink-GetAiCfg.json`, `reolink-GetAiState.json`: Reolink HTTPS API reads (HTTPS was enabled temporarily with
  owner approval and reverted; see ADR 0002).
