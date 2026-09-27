#!/usr/bin/env python3
"""Trusted controller-side live-report validation before publication.

Executed by ci.sh only after the payload container has exited and been
removed and teardown is verified, and before any artifact copy. This
validator is deliberately independent of the payload harness
(tests/live/postgres/run.py): the schema, ordered case inventory, and
versions are duplicated here so a compromised payload cannot influence its
own publication gate. It never prints report content; every failure emits
exactly one fixed category.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys

MAX_BYTES = 64 << 10
FIXED_CATEGORY = "postgres-report-validation-failed"
POSTGRES_MAJOR = "16"
POSTGRES_VERSION = "16.15"
CASE_IDS = (
    "postgres-readiness-authenticated-select-1",
    "postgres-query-select-statekit",
    "postgres-query-select-native-observation",
    "postgres-query-multiline-csv-statekit",
    "postgres-query-multiline-csv-native-observation",
    "postgres-query-zero-rows",
    "postgres-query-write-false-insert-returning",
    "postgres-query-write-false-native-persisted",
    "postgres-query-write-true-update-returning",
    "postgres-query-write-true-native-committed",
    "postgres-query-zero-row-write-framing",
    "postgres-query-invalid-write-positive-exit",
    "postgres-query-invalid-write-native-classification",
    "postgres-query-invalid-auth-empty",
    "postgres-query-invalid-auth-native-classification",
    "postgres-query-unavailable-host-empty",
    "postgres-query-unavailable-host-native-classification",
    "postgres-query-oversize-no-dispatch",
    "postgres-query-output-cap-no-partial",
    "postgres-query-cleanup-native-absent",
)
FIXED_LINES = (
    "schema: postgres-live-v1",
    "source: ubuntu-24.04-runner-bundled-postgresql",
    f"postgres_major: {POSTGRES_MAJOR}",
    f"postgres_version: {POSTGRES_VERSION}",
    "cases_total: 20",
    "cases_passed: 20",
    "cases_failed: 0",
    "cases_skipped: 0",
    "status: pass",
    "execution: complete",
    "cleanup: pass",
    "scope: production postgres.psql_query and independent native psql "
    "against an owned disposable database",
    "write_false: not read-only; INSERT RETURNING persists and is "
    "independently observed",
    "egress: per-test-user IPv4/IPv6 OUTPUT chains are installed and "
    "structurally verified; only loopback PostgreSQL 5432 is accepted, with "
    "IPv6 loopback allowed only when the service binds it, and the "
    "dependency fetch allows only pinned proxy/sum/storage addresses over "
    "TCP/443 plus the exact loopback resolver; all other egress defaults to "
    "DROP; no independent external probe is performed",
    "external_ci: this_run",
    "limitations: no live Salt differential parity; local mock tests are "
    "not live evidence; runner image may change and the job fails closed "
    "unless PostgreSQL tools are exactly 16.15; project build and tests run "
    "in a rootless manifest-closed rootfs while the main-only controller "
    "remains trusted; runner loss can prevent cleanup or report publication",
)


def report_is_valid(path: Path) -> bool:
    """Strict value-free validation; returns False without explanation."""
    try:
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or not 0 < metadata.st_size <= MAX_BYTES):
            return False
        with path.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
    except OSError:
        return False
    if len(data) != metadata.st_size or len(data) > MAX_BYTES:
        return False
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError:
        return False
    if not text.endswith("\n"):
        return False
    lines = text.splitlines()
    if len(lines) != len(FIXED_LINES) + len(CASE_IDS):
        return False
    if tuple(lines[:len(FIXED_LINES)]) != FIXED_LINES:
        return False
    return tuple(lines[len(FIXED_LINES):]) == tuple(
        f"case: {case_id}=pass" for case_id in CASE_IDS
    )


def main() -> int:
    if len(sys.argv) != 2:
        print(FIXED_CATEGORY, file=sys.stderr)
        return 2
    if not report_is_valid(Path(sys.argv[1])):
        print(FIXED_CATEGORY, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
