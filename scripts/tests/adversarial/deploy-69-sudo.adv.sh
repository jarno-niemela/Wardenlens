#!/usr/bin/env bash
# Adversary #69 round 2: docs/deploy.md runs the key steps as `sudo -u '#10001'`, but never creates a host account for
# uid 10001 (the Dockerfile creates it only inside the image). Both sudo (1.9, runas_allow_unknown_id off by default) and
# sudo-rs refuse a uid that has no passwd entry, before any authentication, so the documented procedure cannot run.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
doc=$root/docs/deploy.md
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
if grep -qF -- "-u '#" "$doc"; then
  bad "deploy.md still has a sudo -u '#UID' form (sudo refuses a uid with no passwd entry)"
else
  ok "deploy.md's run-as-uid steps do not need a passwd entry the guide never creates"
fi
# Live evidence, advisory only (it depends on the host's sudo and passwd): it prints and never fails the gate.
if command -v sudo >/dev/null && ! getent passwd 10001 >/dev/null; then
  msg=$(sudo -n -u '#10001' true 2>&1)
  echo "info this host's sudo says for '#10001': ${msg:-nothing}"
fi
# The replacement the guide uses must be named, and the old form must be gone.
if grep -qF 'setpriv --reuid=10001 --regid=10001 --clear-groups' "$doc"; then ok "deploy.md uses setpriv for the uid switch"; else bad "deploy.md does not use setpriv"; fi
exit $fail
