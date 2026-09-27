"""Fail-closed validation of the effective rootless Podman container config."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any


class PolicyError(Exception):
    """Fixed inspection failure without echoing container environment values."""


PODMAN_DEFAULT_CAPABILITIES = frozenset({
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
    "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP",
    "CAP_SETUID", "CAP_SYS_CHROOT",
})


def _require(condition: bool) -> None:
    if not condition:
        raise PolicyError("podman-container-policy-failed")


def _integer(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    _require(type(value) is int)
    return value


def verify_inspect(
    snapshot: dict[str, Any],
    *,
    expected_user: str,
    expected_network: str,
    expected_rootfs: Path,
    expected_manifest_sha256: str,
    expected_binds: dict[str, tuple[Path, bool]],
    expected_tmpfs: dict[str, tuple[str, ...]],
    expected_env_names: set[str],
    memory_bytes: int,
    nano_cpus: int,
    pids_limit: int,
    shm_bytes: int = 64 << 20,
) -> None:
    config = snapshot.get("Config")
    host = snapshot.get("HostConfig")
    mounts = snapshot.get("Mounts")
    labels = config.get("Labels") if isinstance(config, dict) else None
    _require(isinstance(config, dict) and isinstance(host, dict) and isinstance(mounts, list))
    _require(config.get("User") == expected_user)
    _require(isinstance(labels, dict))
    _require(labels.get("io.statekit.rootfs.path") == str(expected_rootfs))
    _require(labels.get("io.statekit.rootfs.manifest-sha256") == expected_manifest_sha256)

    environment = config.get("Env")
    _require(isinstance(environment, list) and all(isinstance(item, str) for item in environment))
    env_items = dict(item.split("=", 1) for item in environment if "=" in item)
    env_names = set(env_items)
    _require(len(env_items) == len(environment) and len(env_names) == len(environment))
    extras = env_names - expected_env_names
    _require(expected_env_names <= env_names and extras <= {"container", "HOSTNAME"})
    phase = env_items.get("STATEKIT_ROOTFS_ROLE")
    bind_matrix = {
        "fetch": {"/deps", "/modules"},
        "build": {"/workspace", "/modules", "/out"},
        "mock": {"/workspace"},
        "live": {"/artifact/statekit", "/out"},
    }
    _require(phase in bind_matrix and set(expected_binds) == bind_matrix[phase])
    _require(expected_network == ("host" if phase in ("fetch", "live") else "none"))
    if "container" in extras:
        _require(env_items["container"] == "podman")
    if "HOSTNAME" in extras:
        container_id = snapshot.get("Id")
        _require(isinstance(container_id, str) and env_items["HOSTNAME"] == container_id[:12]
                 and config.get("Hostname") == env_items["HOSTNAME"])
    _require(not ({"PGPASSWORD", "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN",
                  "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "AWS_ACCESS_KEY_ID",
                  "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "SSH_AUTH_SOCK",
                  "CONTAINER_HOST", "DOCKER_HOST", "PODMAN_HOST",
                  "REGISTRY_AUTH_FILE"} & env_names))

    _require(host.get("Privileged") is False)
    _require(host.get("ReadonlyRootfs") is True)
    security_opts = host.get("SecurityOpt")
    _require(isinstance(security_opts, list) and any(
        item in ("no-new-privileges", "no-new-privileges=true") for item in security_opts
    ))
    cap_drop = host.get("CapDrop")
    cap_add = host.get("CapAdd")
    _require(isinstance(cap_drop, list)
             and frozenset(str(item).upper() for item in cap_drop) == PODMAN_DEFAULT_CAPABILITIES)
    _require(cap_add in (None, []))
    _require(snapshot.get("EffectiveCaps") in (None, []))
    _require(snapshot.get("BoundingCaps") in (None, []))
    _require(host.get("NetworkMode") == expected_network)
    _require(host.get("UsernsMode") in ("private", "keep-id"))
    try:
        expected_uid, expected_gid = (int(value) for value in expected_user.split(":", 1))
    except (ValueError, TypeError):
        raise PolicyError("podman-container-policy-failed") from None
    id_mappings = host.get("IDMappings")
    _require(isinstance(id_mappings, dict))
    uid_map = id_mappings.get("UidMap")
    gid_map = id_mappings.get("GidMap")
    _require(isinstance(uid_map, list) and isinstance(gid_map, list)
             and all(isinstance(item, str) for item in uid_map + gid_map))
    _require(f"{expected_uid}:0:1" in uid_map and f"{expected_gid}:0:1" in gid_map)
    _require(host.get("IpcMode") == "private")
    _require(host.get("PidMode") == "private")
    _require(host.get("UTSMode") == "private")
    _require(host.get("Devices") in (None, []))
    _require(host.get("PortBindings") in (None, {}, []))
    _require(host.get("VolumesFrom") in (None, []))
    _require(_integer(host, "Memory") == memory_bytes)
    _require(_integer(host, "NanoCpus") == nano_cpus)
    _require(_integer(host, "PidsLimit") == pids_limit)
    _require(_integer(host, "ShmSize") == shm_bytes)

    configured_binds = host.get("Binds") or []
    _require(isinstance(configured_binds, list) and len(configured_binds) == len(expected_binds))
    actual_bind_mounts: dict[str, tuple[str, bool]] = {}
    for mount in mounts:
        _require(isinstance(mount, dict))
        mount_type = mount.get("Type")
        destination = mount.get("Destination")
        _require(isinstance(destination, str) and destination.startswith("/"))
        if mount_type == "bind":
            source = mount.get("Source")
            _require(isinstance(source, str) and destination not in actual_bind_mounts)
            _require(destination in expected_binds and type(mount.get("RW")) is bool)
            options = mount.get("Options")
            _require(isinstance(options, list) and all(isinstance(item, str) for item in options))
            option_set = set(options)
            _require({"nosuid", "nodev"} <= option_set)
            _require(mount.get("Propagation") == "rprivate")
            _require(("noexec" in option_set) == (destination != "/artifact/statekit"))
            _require(("rw" not in option_set) if mount.get("RW") is False
                     else ("ro" not in option_set))
            if destination == "/artifact/statekit":
                # Podman may omit default ro/exec option strings: RW=False
                # and absence of noexec are the effective mount controls.
                _require(mount.get("RW") is False)
                artifact = expected_rootfs.parent / "artifacts/statekit"
                _require(source == str(artifact)
                         and expected_binds[destination] == (artifact, False))
                metadata = artifact.lstat()
                _require(stat.S_ISREG(metadata.st_mode) and bool(metadata.st_mode & 0o111))
                target = expected_rootfs / "artifact/statekit"
                _require(stat.S_ISREG(target.lstat().st_mode))
            actual_bind_mounts[destination] = (source, mount.get("RW") is True)
        elif mount_type == "tmpfs":
            _require(destination in expected_tmpfs or destination in ("/dev", "/dev/shm"))
            _require(mount.get("RW") is True)
            options = mount.get("Options")
            _require(isinstance(options, list) and all(isinstance(item, str) for item in options))
            option_set = set(options)
            _require({"nosuid", "nodev"} <= option_set)
            _require(("noexec" in option_set) == (destination != "/tmp"))
        else:
            expected_rw = {
                ("proc", "/proc"): True,
                ("devpts", "/dev/pts"): True,
                ("mqueue", "/dev/mqueue"): True,
                ("sysfs", "/sys"): False,
            }
            _require((mount_type, destination) in expected_rw)
            _require(mount.get("RW") is expected_rw[(mount_type, destination)])
    _require(set(actual_bind_mounts) == set(expected_binds))
    for destination, (expected_source, expected_read_write) in expected_binds.items():
        source, read_write = actual_bind_mounts[destination]
        _require(Path(source).resolve(strict=True) == expected_source.resolve(strict=True))
        _require(read_write is expected_read_write)

    tmpfs = host.get("Tmpfs") or {}
    _require(isinstance(tmpfs, dict) and set(tmpfs) == set(expected_tmpfs))
    for destination, required_options in expected_tmpfs.items():
        options = tmpfs.get(destination)
        _require(isinstance(options, str))
        tokens = set(options.split(","))
        _require(set(required_options) <= tokens)

    # Authoritative rootfs proof: at least one known rootfs-source field must
    # be present and every present one must match the expected root path.
    # Labels are user-suppliable consistency hints, never proof, and a missing
    # authoritative field fails closed. The exact libpod inspect schema is not
    # observed on GitHub yet: if the runtime names the field differently, the
    # gate rejects the runtime rather than trusting labels.
    rootfs_candidates: list[tuple[str, str]] = []
    for field_name in ("RootfsPath", "Rootfs"):
        value = snapshot.get(field_name)
        if isinstance(value, str) and value:
            rootfs_candidates.append((field_name, value))
    graph_driver = snapshot.get("GraphDriver")
    if isinstance(graph_driver, dict):
        driver_data = graph_driver.get("Data")
        if isinstance(driver_data, dict):
            merged = driver_data.get("MergedDir")
            if isinstance(merged, str) and merged:
                rootfs_candidates.append(("GraphDriver.Data.MergedDir", merged))
    _require(bool(rootfs_candidates))
    for _, value in rootfs_candidates:
        _require(Path(value).resolve(strict=False)
                 == expected_rootfs.resolve(strict=False))


def _bind_argument(value: str) -> tuple[str, tuple[Path, bool]]:
    destination, separator, source_mode = value.partition("=")
    source, mode_separator, mode = source_mode.rpartition(":")
    _require(bool(separator and mode_separator and destination.startswith("/")
                  and source.startswith("/") and mode in ("ro", "rw")))
    return destination, (Path(source), mode == "rw")


def _tmpfs_argument(value: str) -> tuple[str, tuple[str, ...]]:
    destination, separator, options = value.partition("=")
    _require(bool(separator and destination.startswith("/") and options))
    return destination, tuple(options.split(","))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True)
    parser.add_argument("--network", choices=("none", "host"), required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--bind", action="append", default=[])
    parser.add_argument("--tmpfs", action="append", default=[])
    parser.add_argument("--env-name", action="append", default=[])
    parser.add_argument("--memory", type=int, required=True)
    parser.add_argument("--nano-cpus", type=int, required=True)
    parser.add_argument("--pids", type=int, required=True)
    args = parser.parse_args()
    try:
        if re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256) is None:
            raise PolicyError("podman-container-policy-failed")
        bind_items = dict(_bind_argument(item) for item in args.bind)
        tmpfs_items = dict(_tmpfs_argument(item) for item in args.tmpfs)
        _require(len(bind_items) == len(args.bind) and len(tmpfs_items) == len(args.tmpfs))
        snapshot = json.load(sys.stdin)
        if isinstance(snapshot, list):
            _require(len(snapshot) == 1)
            snapshot = snapshot[0]
        _require(isinstance(snapshot, dict))
        verify_inspect(
            snapshot, expected_user=args.user, expected_network=args.network,
            expected_rootfs=args.rootfs,
            expected_manifest_sha256=args.manifest_sha256,
            expected_binds=bind_items, expected_tmpfs=tmpfs_items,
            expected_env_names=set(args.env_name), memory_bytes=args.memory,
            nano_cpus=args.nano_cpus, pids_limit=args.pids,
        )
    except (PolicyError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
