#!/bin/sh
# In-container fixture driver (plans/testing.md).
#
# Expected mounts inside the container:
#   /usr/local/bin/statekit       compiled statekit binary
#   /usr/local/bin/fixture-runner compiled runner (built by setup-statekit)
#   /fixtures                     tests/fixtures tree
#   /junit                        writable output directory for JUnit XML
#
# Usage: run-fixtures.sh [--suite NAME]... (default: every suite)
# POSIX sh so the script also runs under Alpine's busybox ash.
set -eu

BIN="${STATEKIT_BIN:-/usr/local/bin/statekit}"
RUNNER="${RUNNER_BIN:-/usr/local/bin/fixture-runner}"
FIXTURES="${FIXTURES_DIR:-/fixtures}"
OUT="${JUNIT_DIR:-/junit}"

if [ ! -x "$BIN" ]; then
    echo "run-fixtures: statekit binary not found at $BIN" >&2
    exit 2
fi
if [ ! -d "$FIXTURES" ]; then
    echo "run-fixtures: fixtures directory not found at $FIXTURES" >&2
    exit 2
fi
mkdir -p "$OUT"

exec "$RUNNER" \
    --bin "$BIN" \
    --fixtures "$FIXTURES" \
    --junit "$OUT/results.xml" \
    "$@"
