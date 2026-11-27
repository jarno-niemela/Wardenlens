#!/bin/sh
# Container entrypoint (#69, ADR 0006 section 6): refuse to start unless the mounted key file passes the strict
# key checks (regular file, owned by this uid, no group/other bits, 32 bytes). The key is a compose secret at
# $WARDENLENS_VAULT_KEY_FILE; it is never read from an environment variable and never printed.
set -eu
: "${WARDENLENS_VAULT_KEY_FILE:?WARDENLENS_VAULT_KEY_FILE must name the mounted key file}"
wardenlens vault check-key "$WARDENLENS_VAULT_KEY_FILE"
exec wardenlens "$@"
