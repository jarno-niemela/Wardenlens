# Camera catalogue format

One TOML file per camera **model**: `cameras/<vendor-slug>/<model-slug>.toml`. A slug is the
lowercased name with each run of non-alphanumerics replaced by `-` (`TP-Link` -> `tp-link`,
`Tapo C110` -> `tapo-c110`). `cameras/README.md` is generated; do not edit it by hand:

```bash
WARDENLENS_BLESS=1 cargo test -p wardenlens-core --test catalogue
```

The parser and the checks live in `wardenlens_core::catalogue` (`crates/wardenlens-core/src/catalogue/`),
and `cargo test` (so `scripts/gate`) loads every file, so unknown fields and site data fail the build.

## Public repository: what must never appear

Vendor, model and firmware `major.minor` are fine. Never write IP addresses (any dotted quad), IPv6
addresses, MAC addresses, serial numbers, credentials or `user:pass@host` URLs, email addresses, or
display names of cameras that identify a site. The validator rejects these in every string
field; its exact rules are in the `validate` module docs.

## Fields

| field | type | notes |
|---|---|---|
| `vendor`, `model` | string | required, non-empty |
| `aliases` | list of strings | OEM or retail names |
| `support` | `verified` / `partial` / `community` / `unsupported` | required |
| `firmware` | list of `"major.minor"` | tested families only, no patch level |
| `[[streams]]` | `role` (`main`/`sub`), `codec` (`h264`/`h265`), `width`, `height`, optional `fps`, `gop` (frames) | measured values |
| `[[protocols]]` | `kind` (`rtsp`/`onvif`/`baichuan`/`dahua_cgi`/`tapo_https`), optional `port`, `paths` | paths, never full URLs |
| `[[events]]` | `kind` (`motion`/`person`/`vehicle`/`intrusion`/`line_cross`/`tamper`/`smart_event`/`client_disconnect`), `source` (`onvif`/`baichuan`/`cgi`), `status` (`observed`/`advertised`) | `advertised` = documented or offered by the camera, not yet seen live |
| `configurable` | list (`service_ports`) | what the optimizer may change |
| `quirks` | list of strings | known behaviour that adapters must handle |
| `[[evidence]]` | `reference`, optional `section` | **at least one required**: ADR, spike result, issue or PR |

Unknown fields, unknown enum values and files over 64 KiB are rejected. Leave out anything not
measured instead of guessing.

## Use by drivers

The driver layer (Phase 1/2) is expected to read these entries as capability defaults. That is
done in the driver tickets, not here.
