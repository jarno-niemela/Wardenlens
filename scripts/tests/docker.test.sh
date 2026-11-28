#!/usr/bin/env bash
# Tooling test for the Docker files (#69): .dockerignore / .gitignore entries, base images pinned by digest, the
# Dockerfile and compose.yaml properties the tickets and ADRs require, and the container entrypoint. Static: no image is
# built and no container started. The checks take file paths, so the mutants below prove each one can fail.
# shellcheck disable=SC2329  # the check functions are called through expect_clean / expect_flagged
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
# yes NAME CMD...: passes when the command succeeds. no NAME CMD...: passes when it fails.
yes() { local n=$1; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }
no()  { local n=$1; shift; if "$@"; then bad "$n"; else ok "$n"; fi; }

# has FILE FIXED-LINE: the file has a line equal to the text.
has() { grep -qxF -- "$2" "$1"; }
# contains FILE REGEX: some line matches (extended regex).
contains() { grep -qE -- "$2" "$1"; }
# ncontains FILE REGEX: a non-comment line matches (a comment may name what the file avoids).
ncontains() { grep -vE '^[[:space:]]*#' "$1" | grep -qE -- "$2"; }

check_dockerignore() { # FILE -> prints one message per problem
  local f=$1 e
  for e in 'target/' 'spikes/' '.git' '*.secret*' '*.local.*' '/secrets/' '*.key' '.env'; do
    has "$f" "$e" || echo "dockerignore lacks $e"
  done
  for e in '**/secrets/' '**/*.key' '**/*.secret*' '**/*.local.*' '**/.env' '**/.env.*'; do
    has "$f" "$e" || echo "dockerignore lacks the nested form $e"
  done
  for e in 'cameras' 'cameras/' '/cameras' '/cameras/'; do
    has "$f" "$e" && echo "dockerignore excludes the camera catalogue ($e)"
  done
  for e in 'third_party' 'third_party/' '/third_party' '/third_party/' '**/third_party' '*.patch' '**/*.patch' 'third_party/**'; do
    has "$f" "$e" && echo "dockerignore excludes third_party/ (the patched retina) ($e)"
  done
}
check_gitignore() {
  local f=$1 e
  for e in '/secrets/' '*.key'; do has "$f" "$e" || echo "gitignore lacks $e"; done
}
check_dockerfile() {
  local f=$1 line n=0
  # Every external FROM is pinned by a 64-hex sha256 digest; a stage reference (FROM builder) is not external.
  local -a stages=()
  while read -r line; do
    n=$((n + 1))
    # shellcheck disable=SC2206  # intentional word splitting of one FROM line
    local w=($line)
    local img=${w[1]}
    local known=0 s
    for s in "${stages[@]}"; do [[ $img == "$s" ]] && known=1; done
    [[ ${w[2]:-} == AS || ${w[2]:-} == as ]] && stages+=("${w[3]}")
    [[ $known == 1 ]] && continue
    [[ $img =~ @sha256:[0-9a-f]{64}$ ]] || echo "FROM $img is not pinned by digest"
  done < <(grep -E '^FROM ' "$f")
  [[ $n -ge 2 ]] || echo "not a multi-stage build"
  contains "$f" '^FROM nvidia/cuda:12\.9\.1-base-ubuntu24\.04@sha256:[0-9a-f]{64}( |$)' || echo "base image is not nvidia/cuda:12.9.1-base-ubuntu24.04 pinned by digest"
  contains "$f" '^ENV NVIDIA_DRIVER_CAPABILITIES=compute,video,utility$' || echo "NVIDIA_DRIVER_CAPABILITIES missing"
  contains "$f" 'cargo build --release --locked -p wardenlens-cli' || echo "release locked build missing"
  contains "$f" '^COPY cameras( |/ )' || echo "the builder does not copy cameras/ (embedded catalogue)"
  contains "$f" '^COPY third_party( |/ )' || echo "the builder does not copy third_party/ (the patched retina)"
  contains "$f" '^COPY rust-toolchain\.toml ' || echo "rust-toolchain.toml not copied into the builder"
  # The default (last) stage runs as a fixed numeric non-root user.
  local last_user
  last_user=$(grep -E '^USER ' "$f" | tail -n1)
  [[ $last_user =~ ^USER\ [1-9][0-9]*(:[1-9][0-9]*)?$ ]] || echo "the runtime user is not a fixed non-root uid: ${last_user:-none}"
  ncontains "$f" 'curl|wget' && echo "the image must stay curl-free"
  contains "$f" '^ENTRYPOINT ' || echo "no ENTRYPOINT"
  grep -qiE 'password|secret_key|(^|[^a-z])token=' "$f" && echo "a secret-looking word in the Dockerfile"
  return 0
}
check_compose() {
  local f=$1
  contains "$f" 'restart: unless-stopped' || echo "restart policy missing"
  contains "$f" 'driver: nvidia' || echo "GPU reservation (driver nvidia) missing"
  contains "$f" 'capabilities: \[gpu\]' || echo "GPU capabilities missing"
  contains "$f" '^ +ulimits:' && contains "$f" '^ +nofile:' || echo "ulimits.nofile missing"
  contains "$f" 'max-size:' || echo "logging max-size missing"
  contains "$f" 'test: \["CMD", "wardenlens", "health"\]' || echo "healthcheck is not 'wardenlens health'"
  contains "$f" 'propagation: rslave' || echo "archive bind lacks rslave propagation"
  contains "$f" '^    read_only: true$' || echo "the service rootfs is not read_only"
  contains "$f" '^    stop_grace_period: 15s$' || echo "stop_grace_period 15s missing"
  ncontains "$f" 'privileged:|network_mode: *host' && echo "privileged or host network"
  contains "$f" '^        read_only: true$' || echo "the config mount is not read_only"
  contains "$f" '^ +file: \$\{WARDENLENS_KEY_FILE_HOST:-/etc/wardenlens/key/vault\.key\}$' || echo "key secret source is not \${WARDENLENS_KEY_FILE_HOST:-/etc/wardenlens/key/vault.key}"
  contains "$f" 'WARDENLENS_VAULT_KEY_FILE: /run/secrets/wardenlens_vault_key' || echo "WARDENLENS_VAULT_KEY_FILE missing"
  contains "$f" '^ +- "\$\{WARDENLENS_LAN_ADDR:-127\.0\.0\.1\}:' || echo "the published port is not on \${WARDENLENS_LAN_ADDR:-127.0.0.1}"
  ncontains "$f" '0\.0\.0\.0' && echo "compose.yaml names 0.0.0.0"
  ncontains "$f" '\./secrets|\./.*\.key' && echo "a secret source inside the work tree"
  ncontains "$f" 'WARDENLENS_VAULT_KEY[^_F]|WARDENLENS_VAULT_KEY:|WARDENLENS_VAULT_KEY=' && echo "key material in an environment variable"
  contains "$f" 'WARDENLENS_HOT_HOST:-/srv/wardenlens/recordings' || echo "hot host default missing"
  contains "$f" 'WARDENLENS_ARCHIVE_HOST:-/srv/wardenlens/archive' || echo "archive host default missing"
  contains "$f" 'target: /var/lib/wardenlens$' || echo "state volume missing"
  return 0
}

expect_clean() { local name=$1 out; shift; out=$("$@"); if [[ -z $out ]]; then ok "$name"; else bad "$name: $out"; fi; }
expect_flagged() { local name=$1 pat=$2 out; shift 2; out=$("$@"); if grep -q -- "$pat" <<<"$out"; then ok "$name"; else bad "$name (got: ${out:-nothing})"; fi; }

df=$root/docker/Dockerfile cf=$root/compose.yaml di=$root/.dockerignore gi=$root/.gitignore
expect_clean "the repository .dockerignore has every entry" check_dockerignore "$di"
expect_clean "the repository .gitignore has the secret entries" check_gitignore "$gi"
expect_clean "the Dockerfile is pinned, multi-stage, non-root and curl-free" check_dockerfile "$df"
expect_clean "compose.yaml carries every required setting" check_compose "$cf"

# Mutants: each check must be able to fail.
for e in '**/secrets/' '**/*.key' '**/*.secret*' '**/*.local.*' '**/.env' '**/.env.*'; do
  grep -vxF -- "$e" "$di" >"$tmp/di"
  expect_flagged "dockerignore without $e is flagged" "nested form" check_dockerignore "$tmp/di"
done
for e in 'target/' 'spikes/' '.git' '*.secret*' '*.local.*' '/secrets/' '*.key' '.env'; do
  grep -vxF -- "$e" "$di" >"$tmp/di"
  expect_flagged "dockerignore without $e is flagged" "lacks" check_dockerignore "$tmp/di"
done
grep -vxF -- '*.key' "$gi" >"$tmp/gi"
expect_flagged "gitignore without *.key is flagged" "lacks" check_gitignore "$tmp/gi"
sed -E 's/@sha256:[0-9a-f]{64}//' "$df" >"$tmp/df"
expect_flagged "an unpinned base is flagged" "not pinned" check_dockerfile "$tmp/df"
awk '/^FROM rust/ && !d {sub(/@sha256:[0-9a-f]+/, ""); d=1} {print}' "$df" >"$tmp/df"
expect_flagged "an unpinned builder is flagged" "rust" check_dockerfile "$tmp/df"
sed -E 's/@sha256:[0-9a-f]{64}/@sha256:abc/' "$df" >"$tmp/df"
expect_flagged "a short digest is flagged" "not pinned" check_dockerfile "$tmp/df"
sed -E 's/12\.9\.1-base-ubuntu24\.04/12.9.1-runtime-ubuntu24.04/' "$df" >"$tmp/df"
expect_flagged "another CUDA base is flagged" "base image" check_dockerfile "$tmp/df"
sed -E 's/^USER 10001:10001$/USER root/' "$df" >"$tmp/df"
expect_flagged "a root runtime is flagged" "non-root" check_dockerfile "$tmp/df"
sed -E 's/^USER 10001:10001$/USER 0/' "$df" >"$tmp/df"
expect_flagged "uid 0 is flagged" "non-root" check_dockerfile "$tmp/df"
grep -v '^COPY cameras' "$df" >"$tmp/df"
expect_flagged "a builder without cameras/ is flagged" "cameras" check_dockerfile "$tmp/df"
{ cat "$di"; echo 'cameras/'; } >"$tmp/di"
expect_flagged "a dockerignore excluding cameras/ is flagged" "camera catalogue" check_dockerignore "$tmp/di"
grep -v '^COPY third_party' "$df" >"$tmp/df"
expect_flagged "a builder without third_party/ is flagged" "third_party" check_dockerfile "$tmp/df"
{ cat "$di"; echo 'third_party/'; } >"$tmp/di"
expect_flagged "a dockerignore excluding third_party/ is flagged" "patched retina" check_dockerignore "$tmp/di"
{ cat "$di"; echo '*.patch'; } >"$tmp/di"
expect_flagged "a dockerignore excluding *.patch is flagged" "patched retina" check_dockerignore "$tmp/di"
sed -E 's/ --locked -p wardenlens-cli/ -p wardenlens-cli/' "$df" >"$tmp/df"
expect_flagged "an unlocked build is flagged" "locked build" check_dockerfile "$tmp/df"
{ cat "$df"; echo 'RUN apt-get install -y curl'; } >"$tmp/df"
expect_flagged "curl in the image is flagged" "curl-free" check_dockerfile "$tmp/df"
sed -E '/^ENV NVIDIA_DRIVER_CAPABILITIES/d' "$df" >"$tmp/df"
expect_flagged "missing driver capabilities are flagged" "NVIDIA_DRIVER_CAPABILITIES" check_dockerfile "$tmp/df"
for pat in 'restart: unless-stopped' 'driver: nvidia' 'nofile:' 'max-size:' 'propagation: rslave' 'stop_grace_period: 15s'; do
  grep -vF -- "$pat" "$cf" >"$tmp/cf"
  expect_flagged "compose without '$pat' is flagged" "missing\|lacks\|nofile\|max-size" check_compose "$tmp/cf"
done
sed -E 's/^    stop_grace_period: 15s$/    stop_grace_period: 10s/' "$cf" >"$tmp/cf"
expect_flagged "a 10 s grace period is flagged" "stop_grace_period" check_compose "$tmp/cf"
grep -vxF '    read_only: true' "$cf" >"$tmp/cf"
expect_flagged "a writable rootfs is flagged although the config mount is read_only" "rootfs" check_compose "$tmp/cf"
sed -E 's/^    restart: unless-stopped$/    restart: unless-stopped\n    privileged: true/' "$cf" >"$tmp/cf"
expect_flagged "privileged is flagged" "privileged" check_compose "$tmp/cf"
sed -E 's/^    restart: unless-stopped$/    restart: unless-stopped\n    network_mode: host/' "$cf" >"$tmp/cf"
expect_flagged "host networking is flagged" "host network" check_compose "$tmp/cf"
sed -E 's/\$\{WARDENLENS_LAN_ADDR:-127\.0\.0\.1\}/0.0.0.0/' "$cf" >"$tmp/cf"
expect_flagged "a 0.0.0.0 publish is flagged" "0.0.0.0" check_compose "$tmp/cf"
sed -E 's#file: \$\{WARDENLENS_KEY_FILE_HOST:-/etc/wardenlens/key/vault.key\}#file: ./secrets/vault.key#' "$cf" >"$tmp/cf"
expect_flagged "a key inside the work tree is flagged" "work tree" check_compose "$tmp/cf"
sed -E 's#test: \["CMD", "wardenlens", "health"\]#test: ["CMD", "curl", "-f", "http://localhost:8080/api/v1/health"]#' "$cf" >"$tmp/cf"
expect_flagged "a curl healthcheck is flagged" "healthcheck" check_compose "$tmp/cf"
sed -E 's#^( +WARDENLENS_VAULT_KEY_FILE: .*)#\1\n      WARDENLENS_VAULT_KEY: x#' "$cf" >"$tmp/cf"
expect_flagged "key material in the environment is flagged" "environment" check_compose "$tmp/cf"

# If Docker Compose is installed, it must accept the file and resolve the defaults safely (no daemon needed).
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  if resolved=$(env -i PATH="$PATH" HOME="$tmp" docker compose --project-directory "$root" --env-file /dev/null -f "$cf" config 2>&1); then
    ok "docker compose config accepts compose.yaml"
  else
    bad "docker compose config: $resolved"
  fi
  yes "the port defaults to 127.0.0.1" grep -q 'host_ip: 127.0.0.1' <<<"$resolved"
  yes "the key source defaults to /etc/wardenlens/key/vault.key" grep -q '/etc/wardenlens/key/vault.key' <<<"$resolved"
  no "the resolved config never names 0.0.0.0" grep -q '0\.0\.0\.0' <<<"$resolved"
else
  echo "skip docker compose config (docker compose is not installed)"
fi

# The entrypoint: the key path is the config's secrets.key_file; check-key first, serve only when it passes.
ep=$root/docker/entrypoint.sh
mkdir -p "$tmp/bin"
cat >"$tmp/bin/wardenlens" <<'STUB'
#!/bin/sh
echo "$*" >>"$STUB_LOG"
case "$1 $2" in
  "config check")
    [ "${STUB_CONFIG:-ok}" = ok ] || exit 1
    printf 'listen: 0.0.0.0:8080\nkey_file: %s\n' "${STUB_KEY-/run/secrets/k}" ;;
  "vault check-key") [ "${STUB_CHECK:-ok}" = ok ] || exit 1 ;;
esac
exit 0
STUB
chmod +x "$tmp/bin/wardenlens"
run_ep() { : >"$tmp/log"; env -i PATH="$tmp/bin:/usr/bin:/bin" STUB_LOG="$tmp/log" "$@" sh "$ep" serve 2>/dev/null; }
run_ep_args() { : >"$tmp/log"; env -i PATH="$tmp/bin:/usr/bin:/bin" STUB_LOG="$tmp/log" sh "$ep" "$@" >/dev/null 2>&1; }
logged() { [[ $(cat "$tmp/log") == "$1" ]]; }
yes "the entrypoint starts with a good key" run_ep WARDENLENS_VAULT_KEY_FILE=/run/secrets/k
yes "the entrypoint checks the configured key, then serves" logged $'config check\nvault check-key /run/secrets/k\nserve'
yes "the key path comes from the config when the variable is unset" run_ep
yes "check-key got the config's path" logged $'config check\nvault check-key /run/secrets/k\nserve'
no "a refused key makes the entrypoint fail" run_ep WARDENLENS_VAULT_KEY_FILE=/run/secrets/k STUB_CHECK=bad
yes "a refused key stops before serve" logged $'config check\nvault check-key /run/secrets/k'
no "a config that differs from WARDENLENS_VAULT_KEY_FILE is refused" run_ep WARDENLENS_VAULT_KEY_FILE=/run/secrets/other
yes "nothing was checked or served on drift" logged 'config check'
no "an invalid config stops the entrypoint" run_ep STUB_CONFIG=bad
yes "an invalid config stops before check-key" logged 'config check'
no "no key_file line stops the entrypoint" run_ep STUB_KEY=
yes "an empty key path is never checked" logged 'config check'
# refuses EP ARGS...: the entrypoint exits non-zero and runs nothing.
refuses() { local e=$1; shift; : >"$tmp/log"; ! env -i PATH="$tmp/bin:/usr/bin:/bin" STUB_LOG="$tmp/log" sh "$e" "$@" >/dev/null 2>&1 && [[ ! -s $tmp/log ]]; }
yes "a forwarded --config is refused" refuses "$ep" --config /other.toml serve
yes "a forwarded --config=PATH is refused" refuses "$ep" serve --config=/other.toml
# Mutant: the same entrypoint without the refusal loop must be flagged.
sed '/^for arg in/,/^done$/d' "$ep" >"$tmp/ep-mutant.sh"
no "an entrypoint without the --config refusal is flagged" refuses "$tmp/ep-mutant.sh" --config /other.toml serve
yes "an argument merely containing config is accepted" run_ep_args config check
yes "the entrypoint is executable" test -x "$ep"

exit $fail
