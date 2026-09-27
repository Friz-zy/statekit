#!/bin/sh
set -eu
: "${STATEKIT_PSQL_DISPATCH_MARKER:?}"
psql_binary="${STATEKIT_PSQL_BINARY:-/usr/bin/psql}"
printf 'called\n' >> "$STATEKIT_PSQL_DISPATCH_MARKER"
exec "$psql_binary" "$@"
