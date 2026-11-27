#!/usr/bin/env bash
# Adversarial tests for compose.yaml hardening (#69): scripts/tests/docker.test.sh accepts a compose file with the
# rootfs read_only, cap_drop, no-new-privileges, the /tmp tmpfs and the non-root user all removed (its `read_only: true`
# check is also satisfied by the config mount alone). These checks pin each setting at the service level, with mutants.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cf=$root/compose.yaml
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
# shellcheck disable=SC2016  # the literal compose text, not a shell expansion
# Service-level keys sit at four spaces of indentation under services.wardenlens.
lines=(
  '    read_only: true'
  '    cap_drop: [ALL]'
  '    security_opt: ["no-new-privileges:true"]'
  '    tmpfs: ["/tmp:size=16m,mode=1777"]'
  '    user: "${WARDENLENS_UID:-10001}:${WARDENLENS_GID:-10001}"'
)
check() { local f=$1 l; for l in "${lines[@]}"; do grep -qxF -- "$l" "$f" || echo "missing: ${l#    }"; done; }
out=$(check "$cf"); if [[ -z $out ]]; then ok "compose.yaml has every hardening setting"; else bad "$out"; fi
for l in "${lines[@]}"; do
  grep -vxF -- "$l" "$cf" >"$tmp/cf"
  if [[ -n $(check "$tmp/cf") ]]; then ok "removing '${l#    }' is flagged"; else bad "removing '${l#    }' is not flagged"; fi
done
# The resolved file (if Compose is installed): defaults give a non-root user and a read-only rootfs.
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  resolved=$(env -i PATH="$PATH" HOME="$tmp" docker compose --project-directory "$root" --env-file /dev/null -f "$cf" config 2>&1)
  if grep -q 'user: 10001:10001' <<<"$resolved"; then ok "the resolved user is 10001:10001"; else bad "resolved user: $resolved"; fi
  if grep -q 'privileged: true' <<<"$resolved"; then bad "the resolved service is privileged"; else ok "the resolved service is not privileged"; fi
  # An empty WARDENLENS_LAN_ADDR in .env must still fall back to loopback, never all interfaces.
  printf 'WARDENLENS_LAN_ADDR=\n' >"$tmp/env"
  resolved=$(env -i PATH="$PATH" HOME="$tmp" docker compose --project-directory "$root" --env-file "$tmp/env" -f "$cf" config 2>&1)
  if grep -q 'host_ip: 127.0.0.1' <<<"$resolved"; then ok "an empty LAN address falls back to 127.0.0.1"; else bad "empty LAN address: $resolved"; fi
else
  echo "skip docker compose config (docker compose is not installed)"
fi
exit $fail
