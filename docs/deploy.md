# Deploying Wardenlens with Docker (#69)

Files: `docker/Dockerfile`, `compose.yaml`, `docker/entrypoint.sh`, `docker/env.example`, `docs/config.docker.toml`.
Decisions are in ADR 0003 (base image), 0004 (API, healthcheck), 0005 (volumes, seccomp, archive) and 0006 (key file).

## What the image is

A multi-stage build. The builder is `rust:1.100.0-slim-bookworm` (the version in `rust-toolchain.toml`) and runs
`cargo build --release --locked -p wardenlens-cli`; the C compiler for `rusqlite` `bundled` comes with that image. The runtime is
`nvidia/cuda:12.9.1-base-ubuntu24.04` with CA certificates and the `wardenlens` binary only, with
`NVIDIA_DRIVER_CAPABILITIES=compute,video,utility`. Both base images are **pinned by digest**; to update a pin, resolve the new
tag with `docker buildx imagetools inspect <image:tag>`, review it and edit `docker/Dockerfile`
(`scripts/tests/docker.test.sh` fails on an unpinned `FROM`). The service runs as the fixed non-root **uid/gid 10001**. There is no
`curl`: the healthcheck is `wardenlens health`.

No secret is in the image or in an environment variable. `.dockerignore` excludes `/secrets/`, `*.key`, `*.secret*`, `*.local.*` and
`.env*` at any depth (Docker matches its patterns from the context root, so the nested `**/` forms are listed too), and `.gitignore`
excludes `/secrets/`, `*.key`, `*.secret*`, `*.local.*` and `.env*`.

## Host preparation (once)

Everything the service writes must belong to the service uid (default 10001; set `WARDENLENS_UID` / `WARDENLENS_GID` in `.env` to
run as another user, and use that uid below). The floor arithmetic relies on a non-root user (ADR 0005).

```sh
sudo install -d -o 10001 -g 10001 -m 0700 /srv/wardenlens/state        # index and vault: private
sudo install -d -o 10001 -g 10001 -m 0750 /srv/wardenlens/recordings   # hot root
sudo install -d -o 10001 -g 10001 -m 0750 /srv/wardenlens/archive      # mount point; the archive disk is mounted onto it
sudo install -d -o root  -g root  -m 0755 /etc/wardenlens
sudo install -m 0644 docs/config.docker.toml /etc/wardenlens/wardenlens.toml   # then edit it
cp docker/env.example .env                                              # then edit it; .env is git-ignored
```

### The key file

The vault key is a raw 32-byte file, outside every work tree, in a **key directory owned by the service uid with mode 0700**. Compose
delivers it as the secret `wardenlens_vault_key`, a read-only bind mount at `/run/secrets/wardenlens_vault_key`; the config's
`secrets.key_file` is that path. The entrypoint reads the path from the config (`wardenlens config check`), refuses a
`WARDENLENS_VAULT_KEY_FILE` that names another path, and runs `wardenlens vault check-key` on it before `serve`; a refusal is fatal.

The strict key check requires a regular file, **owned by the uid the container runs as**, with no group or other permission bits,
exactly 32 bytes. Compose in non-swarm mode does **not** change owner or mode (the `uid:` and `mode:` options are ignored), so the
host file must already be owned by the container uid with mode `0400` or `0600`. A file owned by someone else, or mode `0644`, makes
the container refuse to start. Do not pre-create an empty file: `secrets init` never overwrites an existing file and a zero-byte key
is refused.

1. Get a `wardenlens` binary on the host (glibc 2.36 or later, e.g. Ubuntu 24.04), from the image. It, and the config below, must be readable by the service uid, so they go in `/tmp` (remove them afterwards):

   ```sh
   docker create --name wl-bin wardenlens:local && docker cp wl-bin:/usr/local/bin/wardenlens /tmp/wardenlens && docker rm wl-bin
   ```

2. Create the key directory and generate the key **as the service uid**, with a config whose `secrets.key_file` is the host path
   (`secrets init` creates the file with mode 0600 and never overwrites one):

   ```sh
   sudo install -d -o 10001 -g 10001 -m 0700 /etc/wardenlens/key
   sed 's#/run/secrets/wardenlens_vault_key#/etc/wardenlens/key/vault.key#' docs/config.docker.toml > /tmp/wl-host.toml
   chmod 0644 /tmp/wl-host.toml
   sudo -u '#10001' /tmp/wardenlens --config /tmp/wl-host.toml secrets init
   sudo -u '#10001' /tmp/wardenlens vault check-key /etc/wardenlens/key/vault.key   # what the entrypoint will run
   ```

   (Root alternative: create the file as root, then `chown 10001:10001` and `chmod 0400`.) Keep a copy in the password manager
   (`wardenlens vault key export`, on a terminal). The host path defaults to `/etc/wardenlens/key/vault.key`; override it with
   `WARDENLENS_KEY_FILE_HOST` in `.env`. It must never be inside the repository (`./secrets/` is refused; the key check also refuses a
   path inside a git work tree).

* **Exclude the key path (and the vault in the state directory) from backups.** A backup that holds the key and the vault gives no
  protection.
* **Rotation: stop, rekey, recreate.** `docker compose stop`, then run `rekey` **on the host as the service uid, on a terminal**, with the
  deploy paths (the vault is `vault.db` next to `database.path`):

  ```sh
  sudo -u '#10001' env WARDENLENS_VAULT=/srv/wardenlens/state/vault.db WARDENLENS_VAULT_KEY_FILE=/etc/wardenlens/key/vault.key \
      /tmp/wardenlens vault rekey
  docker compose up -d --force-recreate
  ```

  `rekey` takes a lock and creates `<key>.next` **in the key directory**, which is why that directory belongs to the service uid with
  mode 0700. It replaces the key file by rename, and a container keeps the old file mounted (the bind mount follows the old inode), so
  the container must be **recreated**, not just started. The container never rotates in place. The rotation procedure is exercised by
  the test `the_deploy_guide_key_procedure_yields_a_key_that_passes_check_key_and_rekeys` (temp paths, the current uid).

## Configuration

`docs/config.docker.toml` is the config for the container (mounted read-only at `/etc/wardenlens/wardenlens.toml`):

* `api.listen = "0.0.0.0:8080"` with `api.allow_unspecified_bind = true`. On Docker's default bridge network the process has to
  listen on all container interfaces; this is safe only because compose publishes the port on **one host address**, set by
  `WARDENLENS_LAN_ADDR` (default `127.0.0.1`). The publish address is never `0.0.0.0` by default. Set it to the host's LAN address in `.env`.
* **Host networking and WS-Discovery.** WS-Discovery multicast does not cross the default bridge network. If you use
  `network_mode: host` for discovery, remove the `ports:` entry, set `api.listen` to the host's specific LAN address and leave
  `allow_unspecified_bind = false`: the API must not bind `0.0.0.0` then.
* Paths are the in-container mount points: hot `/srv/wardenlens/hot`, archive `/srv/wardenlens/archive`, index and vault in
  `/var/lib/wardenlens` (not on a recordings volume).

## Volumes

| host (env var, default) | container | notes |
|---|---|---|
| `WARDENLENS_HOT_HOST`, `/srv/wardenlens/recordings` | `/srv/wardenlens/hot` | hot tier (SSD) |
| `WARDENLENS_ARCHIVE_HOST`, `/srv/wardenlens/archive` | `/srv/wardenlens/archive` | archive tier (HDD), `rslave` propagation |
| `WARDENLENS_STATE_HOST`, `/srv/wardenlens/state` | `/var/lib/wardenlens` | index, vault; mode 0700, owned by the uid |
| `WARDENLENS_CONFIG_HOST`, `/etc/wardenlens/wardenlens.toml` | `/etc/wardenlens/wardenlens.toml` | read-only |

### The archive mount

The archive must be a **separate filesystem** from the hot root (the directory created above is the mount point: mount the archive disk
onto it) and must carry the marker file `.wardenlens-archive` (a regular file in its root, owned by the service uid), or the service starts in `archive_unavailable` mode and keeps everything on the hot tier.
Create the marker once on the mounted archive: `sudo install -o 10001 -g 10001 -m 0644 /dev/null /srv/wardenlens/archive/.wardenlens-archive`
(the `wardenlens storage mark-archive` subcommand named in ADR 0005 does not exist yet).

The archive bind uses `rslave` propagation, so a disk mounted **after** the container started becomes visible (the host mount must be on a shared
or rshared mount point; systemd hosts default to shared). If you prefer, start the container after the archive is mounted
(`RequiresMountsFor=` in a unit, or `depends_on` in your orchestration).

**Unmounting the archive:** the service holds a directory handle on it. Stop the service first (`docker compose stop`), then unmount.
Unmounting under a running service leaves it holding the old directory and it reports the archive unavailable.

## Run

```sh
docker compose build
docker compose up -d
docker compose ps            # the health column turns "healthy" after the start period
docker compose exec wardenlens nvidia-smi   # the GPU is reserved (needs the NVIDIA container toolkit)
docker compose logs wardenlens
docker compose down
```

* **GPU.** `compose.yaml` reserves all NVIDIA GPUs (`deploy.resources.reservations.devices`). Phase 1 does not use the GPU in code.
* **Healthcheck.** `wardenlens health` reads the config, sends `GET /api/v1/health` (no token) to `api.listen` (loopback when the
  address is unspecified) with a 3 s deadline and exits 0 only on `200`.
* **Limits.** `ulimits.nofile` is 65536; Docker logs rotate at `10m` x 3 files (`logging.options`), so a flood of rejected requests
  cannot fill the disk with logs.
* **Hardening.** Read-only root filesystem, all capabilities dropped, `no-new-privileges`, `tmpfs` at `/tmp`. The default Docker seccomp
  profile allows `openat2` and `renameat2`, and the host kernel must be 5.6 or later.
* `restart: unless-stopped`, and `stop_grace_period: 15s`: on SIGTERM `serve` flushes the open segments and exits within 10 s, so Docker's
  default 10 s grace would SIGKILL it at the edge.

## Runtime self-test

`scripts/docker-selftest` builds the `selftest` target and runs the `wardenlens-fsutil` tests inside the image under the container
runtime's seccomp profile, on a bind-mounted directory: `openat2` refusing `..` and symlinks, and `renameat2(RENAME_NOREPLACE)` on that
filesystem. Run it after changing the base image, the Docker version or the seccomp profile. `scripts/tests/docker.test.sh` (part of
`scripts/gate`) checks the static properties: the ignore files, digest pins, a non-root numeric user, no `curl`, and the compose settings.

Building the image in CI needs a workflow change, which is human-only and a separate chore.
