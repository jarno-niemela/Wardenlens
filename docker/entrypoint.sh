#!/bin/sh
# Container entrypoint (#69, ADR 0006 section 6): refuse to start unless the mounted key file passes the strict
# key checks (regular file, owned by this uid, no group/other bits, 32 bytes). The key path is the one `serve` will
# use, `secrets.key_file` of the config, read through `wardenlens config check`, so the two cannot drift apart. If
# WARDENLENS_VAULT_KEY_FILE (compose sets it to the secret path) names another path, that is refused too. The key is
# never read from an environment variable and never printed.
set -eu
# `config check` below reads the config named by WARDENLENS_CONFIG; a --config among the arguments would make the exec'd command
# read another config than the one whose key was checked. Refuse it; set WARDENLENS_CONFIG instead.
for arg in "$@"; do
  case "$arg" in
    --config | --config=*)
      echo "error: --config is not allowed in the container command; set WARDENLENS_CONFIG instead" >&2
      exit 1
      ;;
  esac
done
summary=$(wardenlens config check)
key=$(printf '%s\n' "$summary" | sed -n 's/^key_file: //p')
if [ -z "$key" ]; then
  echo "error: the config names no key file" >&2
  exit 1
fi
if [ -n "${WARDENLENS_VAULT_KEY_FILE:-}" ] && [ "$WARDENLENS_VAULT_KEY_FILE" != "$key" ]; then
  echo "error: secrets.key_file in the config differs from WARDENLENS_VAULT_KEY_FILE" >&2
  exit 1
fi
wardenlens vault check-key "$key"
exec wardenlens "$@"
