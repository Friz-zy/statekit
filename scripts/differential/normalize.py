#!/usr/bin/env python3
"""Normalize and compare Salt vs StateKit outputs for one scenario.

Inputs via argv: scenario JSON (id/compare), salt JSON file, statekit JSON file.
Exit 0 = parity, 1 = mismatch. Writes a markdown verdict to stdout.

Normalization strips declared environment-dependent fields (duration_ms,
provider paths) and unwraps Salt's {"local": ...} envelope.
"""
from __future__ import annotations

import json
import sys


def unwrap(payload: dict) -> dict | None:
    """Salt wraps returns as {"local": {...}}; state functions nest under a tag key."""
    local = payload.get("local")
    if isinstance(local, dict):
        # state.single style: single entry keyed by the rendered state tag.
        for value in local.values():
            if isinstance(value, dict) and "result" in value:
                return value
        return None
    if isinstance(local, dict) and "result" in local:
        return local
    return payload if isinstance(payload, dict) else None


def strip_env_fields(node):
    if isinstance(node, dict):
        return {
            k: strip_env_fields(v)
            for k, v in node.items()
            if k not in ("duration_ms", "duration", "provider", "pid")
        }
    if isinstance(node, list):
        return [strip_env_fields(v) for v in node]
    return node


def main() -> int:
    scenario = json.loads(sys.argv[1])
    salt_payload = json.load(open(sys.argv[2]))
    kit_payload = json.load(open(sys.argv[3]))

    compares = scenario.get("compare", ["result"])
    kind = scenario.get("kind", "state")

    problems: list[str] = []

    if kind == "exec":
        salt_norm = strip_env_fields(salt_payload.get("local"))
        kit_norm = strip_env_fields(kit_payload)
        if "output_equal" in compares and salt_norm != kit_norm:
            problems.append(f"outputs differ: salt={salt_norm!r} statekit={kit_norm!r}")
    else:
        salt_res = unwrap(salt_payload)
        kit_res = kit_payload if isinstance(kit_payload, dict) else None

        def field(res, name):
            return (res or {}).get(name)

        if "result" in compares:
            s, k = field(salt_res, "result"), field(kit_res, "result")
            if s != k and not (s is None and k is None):
                problems.append(f"result differs: salt={s!r} statekit={k!r}")
        if "changed_parity" in compares:
            s = bool(field(salt_res, "changes"))
            k = bool(field(kit_res, "changes"))
            if s != k:
                problems.append(f"changed parity differs: salt={s} statekit={k}")
        if "comment_class" in compares:
            s = bool(str(field(salt_res, "comment") or "").strip())
            k = bool(str(field(kit_res, "comment") or "").strip())
            if s != k:
                problems.append(f"comment presence differs: salt={s} statekit={k}")

    print(f"### {scenario['id']}")
    if problems:
        print("MISMATCH")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print("PARITY")
    return 0


if __name__ == "__main__":
    sys.exit(main())
