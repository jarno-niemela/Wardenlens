#!/usr/bin/env bash
# Adversarial tests for the Docker files (#69). Static: no image is built.
# Docker matches .dockerignore patterns from the context root (Go filepath.Match plus `**`), unlike
# .gitignore: `*.key` excludes ./x.key only, never crates/x.key or cameras/x.key. The Dockerfile copies
# crates/ and cameras/ into the builder, so a nested secret-looking file must be excluded with `**/`.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
di=$root/.dockerignore
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
for e in '*.key' '*.secret*' '*.local.*' '.env' '.env.*'; do
  if grep -qxF -- "**/$e" "$di"; then ok "nested $e is excluded from the build context"
  else bad "nested $e is not excluded from the build context (needs **/$e)"; fi
done
# The deploy guide claims .gitignore excludes *.secret* and *.local.* as well.
for e in '*.secret*' '*.local.*'; do
  if grep -qxF -- "$e" "$root/.gitignore" || grep -qxF -- "**/$e" "$root/.gitignore"; then ok ".gitignore has $e (docs/deploy.md says so)"
  else bad ".gitignore lacks $e although docs/deploy.md says it excludes it"; fi
done
exit $fail
