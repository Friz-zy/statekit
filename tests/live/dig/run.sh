#!/usr/bin/env bash
# Host controller only; compilation/tests run in inspected containers.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
case "${1:---ci}" in
  --ci|--preflight-only) (( $# <= 1 )) || exit 2 ;;
  *) printf '%s\n' 'usage: run.sh [--ci|--preflight-only]' >&2; exit 2 ;;
esac
if [[ "${1:---ci}" == --preflight-only ]]; then
  exec /usr/bin/python3 -I "$ROOT/tests/live/dig/orchestration.py" --runner-preflight
fi
exec /bin/bash "$ROOT/tests/live/postgres/ci.sh" --dig-contract-only
