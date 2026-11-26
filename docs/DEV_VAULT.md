# Developer vault: site data and credentials

The owner's camera hosts, MAC addresses, serials, names and credentials live in the encrypted vault
([ADR 0006](adr/0006-sensitive-data-store.md)), never in loose files, the repo, prompts or notes. The spikes, the
tooling and the agents read them through `wardenlens vault get` and filter their output with `wardenlens vault redact`.
Entry ids are plain references such as `cam:reolink-1:host` and `cam:reolink-1:credential`; the values are never on
argv (`vault set` reads a prompt or stdin; `vault get` writes the value to a pipe or terminal only).

## One-time setup (owner)

1. `wardenlens vault init` creates `~/.local/share/wardenlens/dev-vault.db` and the key
   `~/.config/wardenlens/dev-vault.key`.
2. `wardenlens vault key export` (terminal) and keep the result in the password manager. Without that copy a lost
   key means a lost vault.
3. `wardenlens vault import-legacy` reads the two legacy plaintext files
   (`~/.config/wardenlens/agentdvr-cameras.secret.json`, `~/.config/wardenlens/cameras.local.toml`; or pass
   `--secret-json` and `--inventory`) and stores the mapped fields. It prints ids and counts, never values, and lists
   by name every key it did not import (classify those with `vault set`). Re-running it is safe. These two files and
   the `WARDENLENS_CAMERAS` / `WARDENLENS_SECRET_FILE` variables are **only** for `import-legacy`; no spike or tool
   reads them any more.
4. Check that the import worked: `wardenlens vault list`, then for a camera
   `wardenlens vault get cam:<id>:host` and `wardenlens vault get cam:<id>:credential --field username`.
5. **Delete the legacy files yourself**, only after step 2 and step 4. The import never deletes them: they are plaintext,
   so until they are gone the vault adds no protection. (`shred -u` does not help on a journaling or copy-on-write
   filesystem; remove them and treat any old backup of them as exposed.)

## Keep the key out of backups

The dev key (`~/.config/wardenlens/dev-vault.key`) and the dev database (`~/.local/share/wardenlens/dev-vault.db`)
are both under `$HOME`. A whole-home or whole-disk backup that holds both gives no protection at all. Exclude the key
path from every backup and rely on the password-manager copy (`vault key export`) for recovery:

```text
restic backup --exclude "$HOME/.config/wardenlens/dev-vault.key" "$HOME"
borg create --exclude "$HOME/.config/wardenlens/dev-vault.key" repo::name "$HOME"
rsync -a --exclude 'wardenlens/dev-vault.key' "$HOME/.config/" backup:config/
```

For a GUI backup tool, add `~/.config/wardenlens/dev-vault.key` to its exclude list; for a snapshot tool (btrfs, ZFS,
LVM) the key lives in the snapshot, so keep the snapshots on encrypted storage that only you can read or put
`~/.config/wardenlens` on a subvolume that is not snapshotted. Also keep the key out of cloud-synced folders. The
service key (`/etc/wardenlens/vault.key`) is covered by the deployment docs. Check a key file against the rules with
`wardenlens vault check-key`.

## Using the vault from scripts

- `wardenlens vault get cam:<id>:host`: the value on stdout, no trailing newline. Capture it with
  `host="$(wardenlens vault get cam:xr:host)"`, never put the result on a command line you print.
- `wardenlens vault get cam:<id>:credential --field username|password`.
- `command | wardenlens vault redact`: copies stdin to stdout and replaces every vault value (hosts, MACs, serials, names,
  passwords, the `user:password@` URL prefix, and the percent, base64, hex and XML renderings) with `[REDACTED]`. It is an
  exact match against the vault, not a guess at what looks like a secret, so a value that is not in the vault is not
  masked: add it with `vault set`. Matching ignores ASCII case. Overlapping or touching matches become one marker; the
  marker reveals no length. Entries too short to match safely (under 7 bytes) are listed on stderr and not replaced.
  Exit codes: 0 done, 1 an input or output error part way (what was written is redacted), 2 the vault or key could not
  be used (nothing is read or written, so nothing unredacted leaks).
- The S1 spike (`spikes/s1-cameras/lib.sh`) wraps these as `cam_creds`, `cam_host`, `rtsp_url` and `redact`, and
  `redact` fails closed: with no binary or vault it prints nothing and returns non-zero. Set `WARDENLENS_BIN` to a
  binary that is not on `PATH`. The ONVIF port is public configuration: set `ONVIF_PORT`, or store it as
  `cam:<id>:onvif_port` (`vault set ... --kind other`).
- The one accepted exception is the RTSP URL on the `ffmpeg`/`ffprobe` command line (those tools take credentials
  nowhere else; ADR 0002, open risk 11).
- The S2 GPU spike uses no site data (synthetic clips and public models), so it has nothing to read from the vault.
