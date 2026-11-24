# Camera catalogue format

One TOML file per camera **model**: `cameras/<vendor-slug>/<model-slug>.toml`. A slug is the
lowercased name with each run of non-alphanumerics replaced by `-` (`TP-Link` -> `tp-link`,
`Tapo C110` -> `tapo-c110`). `cameras/README.md` is generated; do not edit it by hand:

```bash
WARDENLENS_BLESS=1 cargo test -p wardenlens-core --test catalogue
```

The parser and the checks live in `wardenlens_core::catalogue` (`crates/wardenlens-core/src/catalogue/`),
and `cargo test` (so `scripts/gate`) loads every file, so unknown fields, bad structure and disallowed
characters fail the build.

## Public repository: what must never appear

Vendor, model and firmware `major.minor` are fine. Never write IP addresses, MAC addresses, serial
numbers, credentials, email addresses, private hostnames, or display names of cameras that identify
a site. Those live only in the encrypted vault (ADR 0006). Three layers apply:

1. **Exact-match scan (authoritative).** `wardenlens vault scan cameras/` matches every file against
   the real values of the vault, including their normalised and encoded forms, so the result does
   not depend on how a value is written. `crates/wardenlens-cli/tests/catalogue_scan.rs` runs it
   against a synthetic vault (with a planted-value control) and, when a vault exists at the default
   path, against the real one; the git hooks and `scripts/agents check` run it too.
2. **Structure (enforced).** Unknown fields, `://` or non-`/` protocol paths, files over 64 KiB, and
   characters outside the allow-list (ASCII without controls, plus alphabetic letters; no invisible
   or fullwidth characters) are rejected on every raw line, comments included.
3. **Soft lint (optional, never fails anything).** `catalogue::lint` and `catalogue::lint_source`
   return warnings for text that merely looks like an address, MAC, serial, credential or private
   hostname. It is advice for authors; its rules are in the `guard` module docs.

`cameras/` may hold only `README.md`, `FORMAT.md` and the vendor directories.

## Fields

| field | type | notes |
|---|---|---|
| `vendor`, `model` | string | required, non-empty |
| `aliases` | list of strings | OEM or retail names |
| `support` | `verified` / `partial` / `community` / `unsupported` | required |
| `firmware` | list of `"major.minor"` | tested families only, no patch level |
| `[[streams]]` | `role` (`main`/`sub`), `codec` (`h264`/`h265`), `width`, `height`, optional `fps`, `gop` (frames) | measured values |
| `[[protocols]]` | `kind` (`rtsp`/`onvif`/`baichuan`/`dahua_cgi`/`tapo_https`), optional `port`, `paths` | paths: start with `/`, no `://` |
| `[[events]]` | `kind` (`motion`/`person`/`vehicle`/`intrusion`/`line_cross`/`tamper`/`smart_event`/`client_disconnect`), `source` (`onvif`/`baichuan`/`cgi`), `status` (`observed`/`advertised`) | `advertised` = documented or offered by the camera, not yet seen live |
| `configurable` | list (`service_ports`) | what the optimizer may change |
| `quirks` | list of strings | known behaviour that adapters must handle |
| `[[evidence]]` | `reference`, optional `section` | **at least one required, reference not blank**: ADR, spike result, issue or PR |

Unknown fields, unknown enum values and files over 64 KiB are rejected. Leave out anything not
measured instead of guessing.

## Use by drivers

The driver layer (Phase 1/2) is expected to read these entries as capability defaults. That is
done in the driver tickets, not here.
