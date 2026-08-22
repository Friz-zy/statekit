#!/usr/bin/env python3
"""Validate every fixture against tests/fixtures/schema.json.

Family rule (plans/testing.md — "Every fixture references its Salt origin"):
fixtures outside the cli/ suite must carry a `salt:` reference block; cli
contract fixtures exercise the harness itself and are exempt.

Requires: pyyaml, jsonschema (pinned in the CI job).
"""
from __future__ import annotations

import json
import pathlib
import sys

import jsonschema
import yaml

ROOT = pathlib.Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
SCHEMA = FIXTURES / "schema.json"
EXEMPT_SUITE = "cli"


def main() -> int:
    schema = json.loads(SCHEMA.read_text())
    validator = jsonschema.Draft7Validator(schema)

    failures: list[str] = []
    seen_ids: dict[str, str] = {}

    fixtures = sorted(p for p in FIXTURES.rglob("*.yaml"))
    if not fixtures:
        print(f"error: no fixtures found under {FIXTURES}", file=sys.stderr)
        return 2

    for path in fixtures:
        rel = path.relative_to(FIXTURES)
        suite = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            failures.append(f"{rel}: invalid YAML: {exc}")
            continue

        for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
            location = "/".join(str(part) for part in err.path) or "(root)"
            failures.append(f"{rel}: schema: {location}: {err.message}")

        fixture_id = doc.get("id", "") if isinstance(doc, dict) else ""
        if fixture_id:
            if fixture_id in seen_ids:
                failures.append(f"{rel}: duplicate id {fixture_id!r} (also in {seen_ids[fixture_id]})")
            seen_ids[fixture_id] = str(rel)

        if suite != EXEMPT_SUITE and isinstance(doc, dict) and not doc.get("salt"):
            failures.append(f"{rel}: missing salt origin reference (salt.source)")

    if failures:
        print(f"FAILED: {len(failures)} fixture problem(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"OK: {len(fixtures)} fixtures valid against schema ({len(seen_ids)} unique ids)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
