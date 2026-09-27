#!/usr/bin/env python3
"""Build a manifest-closed rootfs from trusted runner tool files."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterable


MAX_ENTRIES = 200_000
MAX_BYTES = 4 << 30
LD_LIBRARY_ROOTS = (
    Path("/lib"), Path("/lib64"), Path("/usr/lib"), Path("/usr/lib64"),
    Path("/usr/local/lib"), Path("/usr/local/lib64"),
)
ELF_MAGIC = b"\x7fELF"
TEST_UTILITIES = ("timeout", "mktemp", "stat", "id", "rm", "sha256sum")
EXEC_TMPFS_SIZE_BYTES = 4 << 30
MOUNT_OPTION_ALLOWLIST = frozenset({
    "rw", "exec", "nosuid", "nodev", "relatime", "seclabel", "inode64",
})
EXEC_MOUNT_CHILDREN = frozenset({"rootfs", "rootfs-fetch"})
ROOTFS_PROFILES = frozenset({"live-executable", "dependency-fetch", "mock-only"})
MANIFEST_RELATIVE_PATH = "etc/statekit-rootfs.manifest"
# The staged manifest file is the one node that cannot list itself: the
# builder records every other node, and the manifest digest pins its bytes.
MANIFEST_SELF_EXCEPTION = {f"/{MANIFEST_RELATIVE_PATH}"}

# Trusted in-rootfs preflight entrypoint. It is generated into every staged
# rootfs (manifest-hashed), checks the real /proc privilege/mount state —
# absent status fields are failures, never zeros — revalidates the manifest
# digest, and only then execs the payload command. Failure output is a fixed
# value-free category.
PREFLIGHT_SCRIPT = b"""#!/usr/bin/bash
# statekit in-rootfs preflight entrypoint (value-free, fail-closed).
set -euo pipefail

fail() { printf '%s\\n' "$1" >&2; exit 1; }

expected_uid="${STATEKIT_TEST_UID:?}"
expected_gid="${STATEKIT_TEST_GID:?}"
expected_digest="${STATEKIT_ROOTFS_MANIFEST_SHA256:?}"
role="${STATEKIT_ROOTFS_ROLE:?}"

uid_line='' gid_line='' groups_line='' nnp_line=''
cap_inh_line='' cap_prm_line='' cap_eff_line='' cap_bnd_line='' cap_amb_line=''
while IFS= read -r status_line; do
  case "$status_line" in
    'Uid:'*) uid_line="$status_line" ;;
    'Gid:'*) gid_line="$status_line" ;;
    'Groups:'*) groups_line="$status_line" ;;
    'NoNewPrivs:'*) nnp_line="$status_line" ;;
    'CapInh:'*) cap_inh_line="$status_line" ;;
    'CapPrm:'*) cap_prm_line="$status_line" ;;
    'CapEff:'*) cap_eff_line="$status_line" ;;
    'CapBnd:'*) cap_bnd_line="$status_line" ;;
    'CapAmb:'*) cap_amb_line="$status_line" ;;
  esac
done < /proc/self/status

[[ -n "$uid_line" && -n "$gid_line" && -n "$groups_line" && -n "$nnp_line" ]] || \\
  fail preflight-status-fields-missing
[[ -n "$cap_inh_line" && -n "$cap_prm_line" && -n "$cap_eff_line" \\
   && -n "$cap_bnd_line" && -n "$cap_amb_line" ]] || \\
  fail preflight-capability-fields-missing

read -r _ uid_real uid_eff uid_saved uid_fs <<< "$uid_line"
read -r _ gid_real gid_eff gid_saved gid_fs <<< "$gid_line"
read -r _ groups_value <<< "$groups_line"
read -r _ nnp_value <<< "$nnp_line"
[[ "$uid_real" == "$expected_uid" && "$uid_eff" == "$expected_uid" \\
   && "$uid_saved" == "$expected_uid" && "$uid_fs" == "$expected_uid" \\
   && "$uid_real" != 0 ]] || fail preflight-uid-invalid
[[ "$gid_real" == "$expected_gid" && "$gid_eff" == "$expected_gid" \\
   && "$gid_saved" == "$expected_gid" && "$gid_fs" == "$expected_gid" ]] || \\
  fail preflight-gid-invalid
[[ -z "$groups_value" || "$groups_value" == "$expected_gid" ]] || \\
  fail preflight-groups-invalid
[[ "$nnp_value" == 1 ]] || fail preflight-no-new-privs-invalid
for capability_line in "$cap_inh_line" "$cap_prm_line" "$cap_eff_line" \\
                       "$cap_bnd_line" "$cap_amb_line"; do
  read -r _ capability_value <<< "$capability_line"
  [[ -n "$capability_value" && "$capability_value" == 0* \\
     && "$capability_value" != *[!0]* ]] || fail preflight-capabilities-invalid
done

has_option() {
  case ",$1," in (*",$2,"*) return 0 ;; esac
  return 1
}
require_options() {
  local options="$1" token
  shift
  for token in "$@"; do
    has_option "$options" "$token" || return 1
  done
}
forbid_options() {
  local options="$1" token
  shift
  for token in "$@"; do
    has_option "$options" "$token" && return 1
  done
  return 0
}

# mountinfo roots are relative to the separately mounted exec tmpfs, not
# to its host mountpoint. Linux represents exec by the absence of noexec.
expected_root=/rootfs
[[ "$role" != fetch ]] || expected_root=/rootfs-fetch
exec_mount_dev=''
artifact_path=/artifact/statekit
workspace_re='^/statekit-pg-[0-9a-f]{20}\\.[A-Za-z0-9]{8}'
saw_root=0 saw_tmp=0 saw_shm=0 saw_workspace=0 saw_artifact=0
saw_out=0 saw_modules=0 saw_deps=0
while read -r mount_id mount_parent mount_dev mount_root mount_point \\
                mount_options mount_rest; do
  mount_fstype='' mount_source=''
  rest_tokens=($mount_rest)
  rest_index=0
  while (( rest_index < ${#rest_tokens[@]} )); do
    if [[ "${rest_tokens[rest_index]}" == "-" ]]; then
      mount_fstype="${rest_tokens[rest_index+1]:-}"
      mount_source="${rest_tokens[rest_index+2]:-}"
      break
    fi
    rest_index=$((rest_index + 1))
  done
  case "$mount_point" in
    /)
      saw_root=1
      [[ "$mount_fstype" == tmpfs && "$mount_source" == tmpfs \\
         && "$mount_root" == "$expected_root" ]] || \\
        fail preflight-root-mount-identity-invalid
      exec_mount_dev="$mount_dev"
      require_options "$mount_options" ro nosuid nodev || \\
        fail preflight-root-mount-policy-invalid
      forbid_options "$mount_options" rw noexec || \\
        fail preflight-root-mount-policy-invalid
      ;;
    /tmp)
      saw_tmp=1
      [[ "$mount_fstype" == tmpfs ]] || fail preflight-tmp-mount-identity-invalid
      require_options "$mount_options" rw nosuid nodev || \\
        fail preflight-tmp-mount-policy-invalid
      forbid_options "$mount_options" ro noexec || \\
        fail preflight-tmp-mount-policy-invalid
      ;;
    /dev/shm)
      saw_shm=1
      require_options "$mount_options" rw nosuid nodev noexec || \\
        fail preflight-shm-mount-policy-invalid
      forbid_options "$mount_options" ro || \\
        fail preflight-shm-mount-policy-invalid
      ;;
    /workspace)
      saw_workspace=1
      [[ "$role" == build || "$role" == mock ]] || \\
        fail preflight-unexpected-mount
      require_options "$mount_options" ro nosuid nodev noexec || \\
        fail preflight-workspace-mount-policy-invalid
      forbid_options "$mount_options" rw || \\
        fail preflight-workspace-mount-policy-invalid
      ;;
    /artifact/statekit)
      [[ "$saw_artifact" == 0 ]] || fail preflight-artifact-mount-identity-invalid
      saw_artifact=1
      [[ "$role" == live && "$mount_fstype" == tmpfs \\
         && "$mount_source" == tmpfs && "$mount_root" == /artifacts/statekit \\
         && -n "$exec_mount_dev" && "$mount_dev" == "$exec_mount_dev" ]] || \\
        fail preflight-artifact-mount-identity-invalid
      [[ -f "$artifact_path" && -x "$artifact_path" && ! -L "$artifact_path" ]] || \\
        fail preflight-artifact-file-invalid
      require_options "$mount_options" ro nosuid nodev || \\
        fail preflight-artifact-mount-policy-invalid
      forbid_options "$mount_options" rw noexec || \\
        fail preflight-artifact-mount-policy-invalid
      ;;
    /out)
      saw_out=1
      if [[ "$role" == build ]]; then
        [[ "$mount_fstype" == tmpfs && "$mount_source" == tmpfs \\
           && "$mount_root" == /artifacts && "$mount_dev" == "$exec_mount_dev" ]] || \\
          fail preflight-out-mount-identity-invalid
      elif [[ "$role" == live ]]; then
        [[ "$mount_fstype" == tmpfs \\
           && "$mount_root" =~ ${workspace_re}/run/live-output$ ]] || \\
          fail preflight-out-mount-identity-invalid
      else
        fail preflight-unexpected-mount
      fi
      require_options "$mount_options" rw nosuid nodev noexec || \\
        fail preflight-out-mount-policy-invalid
      forbid_options "$mount_options" ro || \\
        fail preflight-out-mount-policy-invalid
      ;;
    /modules)
      saw_modules=1
      [[ "$role" == build || "$role" == fetch ]] || fail preflight-unexpected-mount
      [[ "$mount_fstype" == tmpfs \\
         && "$mount_root" =~ ${workspace_re}/run/gomodcache$ ]] || \\
        fail preflight-modules-mount-identity-invalid
      require_options "$mount_options" nosuid nodev noexec || \\
        fail preflight-modules-mount-policy-invalid
      if [[ "$role" == build ]]; then
        require_options "$mount_options" ro || \\
          fail preflight-modules-mount-policy-invalid
        forbid_options "$mount_options" rw || \\
          fail preflight-modules-mount-policy-invalid
      else
        require_options "$mount_options" rw || \\
          fail preflight-modules-mount-policy-invalid
        forbid_options "$mount_options" ro || \\
          fail preflight-modules-mount-policy-invalid
      fi
      ;;
    /deps)
      saw_deps=1
      [[ "$role" == fetch && "$mount_fstype" == tmpfs \\
         && "$mount_root" =~ ${workspace_re}/manifests$ ]] || \\
        fail preflight-deps-mount-identity-invalid
      require_options "$mount_options" ro nosuid nodev noexec || \\
        fail preflight-deps-mount-policy-invalid
      forbid_options "$mount_options" rw || \\
        fail preflight-deps-mount-policy-invalid
      ;;
    /proc|/sys|/sys/fs/cgroup|/dev|/dev/pts|/dev/mqueue|/etc/resolv.conf|\\
    /etc/hosts|/etc/hostname|/run/.containerenv)
      ;;
    *)
      fail preflight-unexpected-mount
      ;;
  esac
done < /proc/self/mountinfo

[[ "$saw_root" == 1 && "$saw_tmp" == 1 && "$saw_shm" == 1 ]] || \\
  fail preflight-required-mount-missing
case "$role" in
  fetch) [[ "$saw_modules" == 1 && "$saw_deps" == 1 ]] || \\
    fail preflight-required-mount-missing ;;
  build) [[ "$saw_workspace" == 1 && "$saw_modules" == 1 && "$saw_out" == 1 ]] || \\
    fail preflight-required-mount-missing ;;
  mock) [[ "$saw_workspace" == 1 ]] || fail preflight-required-mount-missing ;;
  live) [[ "$saw_artifact" == 1 && "$saw_out" == 1 ]] || \\
    fail preflight-required-mount-missing ;;
  *) fail preflight-role-invalid ;;
esac

manifest_path=/etc/statekit-rootfs.manifest
[[ -f "$manifest_path" && ! -L "$manifest_path" ]] || \\
  fail preflight-manifest-unavailable
manifest_digest="$(sha256sum -- "$manifest_path")"
manifest_digest="${manifest_digest%% *}"
[[ "$manifest_digest" == "$expected_digest" ]] || \\
  fail preflight-manifest-mismatch

(( $# )) || fail preflight-command-missing
exec "$@"
"""
PREFLIGHT_RELATIVE_PATH = "usr/bin/statekit-rootfs-preflight"


class RootfsError(Exception):
    """Fixed rootfs-construction failure; source values are not echoed."""


@dataclass(frozen=True)
class MountRecord:
    target: str
    source: str
    fstype: str
    options: tuple[str, ...]


@dataclass(frozen=True)
class Mapping:
    source: Path
    target: Path
    category: str


def _find_mount(mountpoint: Path) -> MountRecord | None:
    try:
        result = subprocess.run(
            [
                "/usr/bin/findmnt", "--vfs-all", "--noheadings", "--raw",
                "--output", "TARGET,SOURCE,FSTYPE,OPTIONS", "--mountpoint",
                str(mountpoint),
            ],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise RootfsError("mount-table-inspection-failed") from None
    if result.returncode == 1 and not result.stdout.strip():
        return None
    if result.returncode != 0:
        raise RootfsError("mount-table-inspection-failed")
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        raise RootfsError("mount-table-identity-invalid")
    fields = lines[0].split()
    if len(fields) != 4 or not fields[3]:
        raise RootfsError("mount-table-identity-invalid")
    options = tuple(fields[3].split(","))
    if not options or any(not option for option in options) or len(set(options)) != len(options):
        raise RootfsError("mount-options-invalid")
    return MountRecord(fields[0], fields[1], fields[2], options)


def _mount_record(
    mountpoint: Path,
    mount_probe: Callable[[Path], MountRecord | None] | None,
) -> MountRecord | None:
    record = (mount_probe or _find_mount)(mountpoint)
    if record is not None and "noexec" not in record.options and "exec" not in record.options:
        # Kernel mount tables omit default exec; expose its effective state only
        # when noexec is absent, then independently confirm it with statvfs.
        record = MountRecord(
            record.target, record.source, record.fstype, (*record.options, "exec"),
        )
    return record


def _valid_mountpoint_name(mountpoint: Path) -> bool:
    return (
        mountpoint.is_absolute()
        and mountpoint.parent == Path("/dev/shm")
        and re.fullmatch(r"statekit-exec-[0-9a-f]{20}", mountpoint.name) is not None
        and mountpoint == Path("/dev/shm") / mountpoint.name
    )


def _verify_noexec_parent(
    mount_probe: Callable[[Path], MountRecord | None] | None,
) -> None:
    parent = Path("/dev/shm")
    try:
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError:
        raise RootfsError("rootfs-scratch-parent-invalid") from None
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
            or resolved != parent or stat.S_IMODE(metadata.st_mode) != 0o1777):
        raise RootfsError("rootfs-scratch-parent-invalid")
    record = _mount_record(parent, mount_probe)
    if (record is None or record.target != str(parent) or record.fstype != "tmpfs"
            or not {"rw", "nosuid", "nodev", "noexec"} <= set(record.options)
            or "exec" in record.options or "ro" in record.options):
        raise RootfsError("rootfs-scratch-parent-not-noexec-tmpfs")


def preflight_exec_mountpoint(
    mountpoint: Path,
    *,
    mount_probe: Callable[[Path], MountRecord | None] | None = None,
) -> None:
    """Validate the noexec parent and reserve an unused direct-child path."""
    if not _valid_mountpoint_name(mountpoint):
        raise RootfsError("exec-mountpoint-path-invalid")
    _verify_noexec_parent(mount_probe)
    if os.path.lexists(mountpoint) or _mount_record(mountpoint, mount_probe) is not None:
        raise RootfsError("exec-mountpoint-collision")


def _size_bytes(option: str) -> int | None:
    match = re.fullmatch(r"size=([0-9]+)([kmgtpe]?)(?:i?b)?", option, re.IGNORECASE)
    if match is None:
        return None
    suffix = match.group(2).lower()
    exponent = "kmgtpe".find(suffix) + 1 if suffix else 0
    return int(match.group(1)) << (10 * exponent)


def _mode_value(option: str) -> int | None:
    match = re.fullmatch(r"mode=([0-7]{3,4})", option)
    return int(match.group(1), 8) if match else None


def _verify_exec_options(options: tuple[str, ...]) -> None:
    option_set = set(options)
    if (len(option_set) != len(options)
            or not {"rw", "exec", "nosuid", "nodev"} <= option_set
            or {"ro", "noexec", "suid", "dev"} & option_set):
        raise RootfsError("exec-tmpfs-options-invalid")
    for option in options:
        if option.startswith("size="):
            if _size_bytes(option) != EXEC_TMPFS_SIZE_BYTES:
                raise RootfsError("exec-tmpfs-size-invalid")
        elif option.startswith("mode="):
            if _mode_value(option) != 0o700:
                raise RootfsError("exec-tmpfs-mode-invalid")
        elif option not in MOUNT_OPTION_ALLOWLIST:
            raise RootfsError("exec-tmpfs-option-unexpected")
    if sum(option.startswith("size=") for option in options) != 1 \
            or sum(option.startswith("mode=") for option in options) != 1:
        raise RootfsError("exec-tmpfs-options-incomplete")


def verify_exec_mount(
    mountpoint: Path,
    *,
    uid: int,
    gid: int,
    mount_probe: Callable[[Path], MountRecord | None] | None = None,
    vfs_flags_probe: Callable[[Path], int] | None = None,
) -> None:
    """Require the exact owned executable tmpfs below noexec /dev/shm."""
    if uid <= 0 or gid <= 0 or not _valid_mountpoint_name(mountpoint):
        raise RootfsError("exec-mountpoint-path-invalid")
    _verify_noexec_parent(mount_probe)
    try:
        metadata = mountpoint.lstat()
        resolved = mountpoint.resolve(strict=True)
    except OSError:
        raise RootfsError("exec-mountpoint-unavailable") from None
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
            or resolved != mountpoint or metadata.st_uid != uid or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise RootfsError("exec-mountpoint-owner-or-path-invalid")
    record = _mount_record(mountpoint, mount_probe)
    if (record is None or record.target != str(mountpoint)
            or record.source != "tmpfs" or record.fstype != "tmpfs"):
        raise RootfsError("exec-tmpfs-identity-invalid")
    _verify_exec_options(record.options)
    try:
        flags = (vfs_flags_probe or (lambda path: os.statvfs(path).f_flag))(mountpoint)
    except OSError:
        raise RootfsError("exec-tmpfs-flags-unverifiable") from None
    for flag_name, must_be_set in (("ST_NOEXEC", False), ("ST_NOSUID", True), ("ST_NODEV", True)):
        flag = getattr(os, flag_name, 0)
        if flag and bool(flags & flag) != must_be_set:
            raise RootfsError("exec-tmpfs-flags-invalid")


def prepare_exec_mount_cleanup(
    mountpoint: Path,
    *,
    uid: int,
    gid: int,
    mount_probe: Callable[[Path], MountRecord | None] | None = None,
    vfs_flags_probe: Callable[[Path], int] | None = None,
) -> None:
    """Check ownership, exact mount identity, and emptiness before unmount."""
    verify_exec_mount(
        mountpoint, uid=uid, gid=gid, mount_probe=mount_probe,
        vfs_flags_probe=vfs_flags_probe,
    )
    try:
        if next(mountpoint.iterdir(), None) is not None:
            raise RootfsError("exec-mount-not-empty")
    except OSError:
        raise RootfsError("exec-mount-inspection-failed") from None


def finish_exec_mount_cleanup(
    mountpoint: Path,
    *,
    runner_uid: int,
    runner_gid: int,
    mount_probe: Callable[[Path], MountRecord | None] | None = None,
) -> None:
    """Prove the exact mount is gone, then remove its empty mountpoint."""
    if not _valid_mountpoint_name(mountpoint):
        raise RootfsError("exec-mountpoint-path-invalid")
    _verify_noexec_parent(mount_probe)
    if _mount_record(mountpoint, mount_probe) is not None:
        raise RootfsError("exec-tmpfs-still-mounted")
    try:
        metadata = mountpoint.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
                or mountpoint.resolve(strict=True) != mountpoint
                or metadata.st_uid != runner_uid or metadata.st_gid != runner_gid
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or next(mountpoint.iterdir(), None) is not None):
            raise RootfsError("exec-mountpoint-removal-identity-invalid")
        mountpoint.rmdir()
    except OSError:
        raise RootfsError("exec-mountpoint-removal-failed") from None
    if os.path.lexists(mountpoint):
        raise RootfsError("exec-mountpoint-removal-unverified")


def cleanup_exec_mount(
    mountpoint: Path,
    *,
    uid: int,
    gid: int,
    runner_uid: int,
    runner_gid: int,
    mount_probe: Callable[[Path], MountRecord | None] | None = None,
    vfs_flags_probe: Callable[[Path], int] | None = None,
    unmount: Callable[[Path], None],
) -> None:
    """Exercise the verified cleanup state machine with an injected unmount."""
    prepare_exec_mount_cleanup(
        mountpoint, uid=uid, gid=gid, mount_probe=mount_probe,
        vfs_flags_probe=vfs_flags_probe,
    )
    unmount(mountpoint)
    finish_exec_mount_cleanup(
        mountpoint, runner_uid=runner_uid, runner_gid=runner_gid,
        mount_probe=mount_probe,
    )


class RootfsBuilder:
    def __init__(
        self,
        destination: Path,
        *,
        uid: int,
        gid: int,
        require_exec_mount: bool,
        exec_mount: Path | None = None,
        ldd: Callable[[Path], Iterable[Path]] | None = None,
        test_source_roots: tuple[Path, ...] = (),
    ) -> None:
        if uid <= 0 or gid <= 0:
            raise RootfsError("invalid-rootfs-identity")
        if not destination.is_absolute() or destination == Path("/"):
            raise RootfsError("invalid-rootfs-destination")
        parent = destination.parent
        try:
            if parent.is_symlink() or parent.resolve(strict=True) != parent:
                raise RootfsError("invalid-rootfs-parent")
            if require_exec_mount:
                if exec_mount is None or parent != exec_mount \
                        or destination.name not in EXEC_MOUNT_CHILDREN \
                        or destination != exec_mount / destination.name:
                    raise RootfsError("rootfs-outside-exec-mount")
                verify_exec_mount(exec_mount, uid=uid, gid=gid)
            if destination.exists() or destination.is_symlink():
                raise RootfsError("rootfs-destination-exists")
        except OSError:
            raise RootfsError("invalid-rootfs-destination") from None
        self.destination = destination
        self.uid = uid
        self.gid = gid
        self.exec_mount = exec_mount
        self.require_exec_mount = require_exec_mount
        self.ldd = ldd or self._trusted_ldd
        if test_source_roots and require_exec_mount:
            raise RootfsError("test-source-override-forbidden")
        self.test_source_roots = tuple(
            root.resolve(strict=True) for root in test_source_roots
        )
        self.mappings: list[Mapping] = []
        self.records: dict[str, dict[str, object]] = {}
        self.sources: dict[str, Path] = {}
        self.ldd_subjects: set[Path] = set()
        self.byte_count = 0
        self.node_count = 0
        self.stage: Path | None = None

    @staticmethod
    def _within(path: Path, roots: Iterable[Path]) -> bool:
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            return False
        return any(resolved == root or root in resolved.parents for root in roots)

    @classmethod
    def _validate_runtime_paths(
        cls,
        *,
        python_executable: Path | None,
        bash_executable: Path,
        sh_executable: Path,
        go_root: Path | None,
        psql_executable: Path | None,
        python_stdlib: tuple[Path, ...],
        test_utilities: tuple[Path, ...],
        require_full_runtime: bool,
        test_source_roots: tuple[Path, ...] = (),
    ) -> None:
        public_bins = (Path("/usr/bin"), Path("/usr/local/bin"))
        public_libs = (
            Path("/usr/lib"), Path("/usr/lib64"),
            Path("/usr/local/lib"), Path("/usr/local/lib64"),
        )
        if test_source_roots:
            public_bins = test_source_roots
            public_libs = test_source_roots
        executable_roots = test_source_roots or public_bins
        stdlib_roots = test_source_roots or public_libs
        if python_executable is not None and not cls._within(python_executable, executable_roots):
            raise RootfsError("runtime-executable-outside-allowlist")
        for executable in (bash_executable, sh_executable):
            if not cls._within(executable, executable_roots):
                raise RootfsError("runtime-executable-outside-allowlist")
        if any(not cls._within(tool, executable_roots) for tool in test_utilities):
            raise RootfsError("test-utility-outside-allowlist")
        if any(not cls._within(root, stdlib_roots) for root in python_stdlib):
            raise RootfsError("python-standard-library-outside-allowlist")
        if require_full_runtime:
            go_roots = test_source_roots or (
                Path("/usr/local/go"), Path("/opt/hostedtoolcache/go/1.26.8/x64"),
            )
            if go_root is None or not cls._within(go_root, go_roots):
                raise RootfsError("go-toolchain-outside-allowlist")
            if psql_executable is None:
                return
            pg_roots = test_source_roots or (Path("/usr/lib/postgresql/16/bin"),)
            if not cls._within(psql_executable, pg_roots) \
                    or psql_executable.name != "psql":
                raise RootfsError("postgres-client-outside-allowlist")

    @staticmethod
    def _trusted_ldd(binary: Path) -> Iterable[Path]:
        try:
            result = subprocess.run(
                ["/usr/bin/ldd", str(binary)],
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=15, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise RootfsError("runtime-dependency-inspection-failed") from None
        text = result.stdout + result.stderr
        if "not a dynamic executable" in text or "statically linked" in text:
            return ()
        if result.returncode != 0 or "not found" in text:
            raise RootfsError("runtime-dependency-inspection-failed")
        dependencies: set[Path] = set()
        for line in text.splitlines():
            if "=>" in line:
                match = re.match(r"^\s*\S+\s+=>\s+(/[^\s]+)(?:\s+\(.*\))?\s*$", line)
                if match:
                    dependencies.add(Path(match.group(1)))
            else:
                match = re.match(r"^\s*(/[^\s]+)(?:\s+\(.*\))?\s*$", line)
                if match:
                    dependencies.add(Path(match.group(1)))
        return tuple(sorted(dependencies, key=str))

    def add_mapping(self, source: Path, target: Path, category: str) -> Mapping:
        try:
            if source.is_symlink() or not source.is_dir():
                raise RootfsError("runtime-source-root-invalid")
            canonical = source.resolve(strict=True)
        except OSError:
            raise RootfsError("runtime-source-root-invalid") from None
        for item in self.mappings:
            if item.source == canonical:
                if item.target != target:
                    raise RootfsError("runtime-source-mapping-conflict")
                return item
        mapping = Mapping(canonical, target, category)
        self.mappings.append(mapping)
        self.mappings.sort(key=lambda item: (-len(item.source.parts), str(item.source)))
        return mapping

    def _mapping_for(self, source: Path) -> tuple[Mapping, Path]:
        try:
            resolved = source.resolve(strict=True)
        except OSError:
            raise RootfsError("runtime-symlink-target-missing") from None
        for mapping in self.mappings:
            try:
                relative = resolved.relative_to(mapping.source)
                return mapping, relative
            except ValueError:
                continue
        raise RootfsError("runtime-path-outside-allowlist")

    def _target_for_test_source(self, source: Path) -> Path:
        try:
            canonical = source.resolve(strict=True)
        except OSError:
            raise RootfsError("runtime-source-root-invalid") from None
        for root in self.test_source_roots:
            try:
                return Path("/") / canonical.relative_to(root)
            except ValueError:
                continue
        return canonical

    @staticmethod
    def _target_path(mapping: Mapping, relative: Path) -> Path:
        target = mapping.target / relative
        if not target.is_absolute() or target == Path("/"):
            raise RootfsError("runtime-target-path-invalid")
        return target

    def add_path(self, mapping: Mapping, relative: Path) -> None:
        if relative.is_absolute() or ".." in relative.parts:
            raise RootfsError("runtime-manifest-path-invalid")
        if mapping.category == "python-standard-library" and (
            "__pycache__" in relative.parts or relative.suffix == ".pyc"
        ):
            return
        source = mapping.source / relative
        target = self._target_path(mapping, relative)
        key = str(target)
        try:
            metadata = source.lstat()
        except OSError:
            raise RootfsError("runtime-manifest-source-missing") from None
        mode = metadata.st_mode
        prior = self.records.get(key)
        if prior is not None:
            previous_source = self.sources.get(key)
            try:
                same_source = previous_source is not None and \
                    source.resolve(strict=True) == previous_source.resolve(strict=True)
            except OSError:
                same_source = False
            if same_source:
                return
            raise RootfsError("runtime-manifest-path-collision")
        if stat.S_ISLNK(mode):
            self.node_count += 1
            if self.node_count > MAX_ENTRIES:
                raise RootfsError("runtime-manifest-entry-limit")
            try:
                resolved = source.resolve(strict=True)
                target_mapping, target_relative = self._mapping_for(resolved)
                resolved_target = self._target_path(target_mapping, target_relative)
                link_text = os.readlink(source)
            except OSError:
                raise RootfsError("runtime-symlink-closure-invalid") from None
            if os.path.isabs(link_text):
                normalized_link = str(resolved_target)
            else:
                normalized_link = os.path.relpath(resolved_target, target.parent)
            record = {
                "path": key, "type": "symlink", "target": normalized_link,
                "source": mapping.category,
            }
            output = self._output_path(target)
            output.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(normalized_link, output)
            self._record(record, source)
            self.add_path(target_mapping, target_relative)
            return
        if stat.S_ISDIR(mode):
            self.node_count += 1
            if self.node_count > MAX_ENTRIES:
                raise RootfsError("runtime-manifest-entry-limit")
            output = self._output_path(target)
            output.mkdir(parents=True, exist_ok=True, mode=0o755)
            output.chmod(0o755)
            record = {"path": key, "type": "directory", "mode": "0755", "source": mapping.category}
            self._record(record, source)
            try:
                children = sorted(source.iterdir(), key=lambda item: item.name)
            except OSError:
                raise RootfsError("runtime-directory-read-failed") from None
            for child in children:
                self.add_path(mapping, relative / child.name)
            return
        if not stat.S_ISREG(mode) or mode & 0o7000 or metadata.st_nlink != 1:
            raise RootfsError("runtime-node-type-rejected")
        self.node_count += 1
        if self.node_count > MAX_ENTRIES or self.byte_count + metadata.st_size > MAX_BYTES:
            raise RootfsError("runtime-manifest-size-limit")
        output = self._output_path(target)
        output.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        file_size = 0
        descriptor = -1
        try:
            descriptor = os.open(
                source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino):
                raise RootfsError("runtime-file-identity-changed")
            with os.fdopen(descriptor, "rb") as input_file, output.open("xb") as output_file:
                descriptor = -1
                while True:
                    chunk = input_file.read(1 << 20)
                    if not chunk:
                        break
                    file_size += len(chunk)
                    if self.byte_count + file_size > MAX_BYTES:
                        raise RootfsError("runtime-manifest-size-limit")
                    digest.update(chunk)
                    output_file.write(chunk)
                output_file.flush()
                os.fsync(output_file.fileno())
            if file_size != metadata.st_size:
                raise RootfsError("runtime-file-size-changed")
        except RootfsError:
            output.unlink(missing_ok=True)
            raise
        except OSError:
            output.unlink(missing_ok=True)
            raise RootfsError("runtime-file-read-failed") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        self.byte_count += file_size
        executable = bool(mode & 0o111)
        normalized_mode = "0755" if executable else "0644"
        record = {
            "path": key, "type": "file", "mode": normalized_mode,
            "sha256": digest.hexdigest(), "source": mapping.category,
        }
        self._record(record, source)
        output.chmod(0o755 if executable else 0o644)

    def add_ldd_subject(self, mapping: Mapping, relative: Path) -> None:
        if relative.is_absolute() or ".." in relative.parts:
            raise RootfsError("runtime-manifest-path-invalid")
        source = mapping.source / relative
        try:
            if not stat.S_ISREG(source.stat().st_mode):
                raise RootfsError("runtime-elf-source-invalid")
        except OSError:
            raise RootfsError("runtime-elf-source-invalid") from None
        self.ldd_subjects.add(source)

    def _record(self, record: dict[str, object], source: Path) -> None:
        key = str(record["path"])
        prior = self.records.get(key)
        if prior is not None:
            comparable = {field: value for field, value in record.items() if field != "source"}
            previous = {field: value for field, value in prior.items() if field != "source"}
            if comparable != previous:
                raise RootfsError("runtime-manifest-path-collision")
            return
        self.records[key] = record
        self.sources[key] = source

    def _output_path(self, absolute: Path) -> Path:
        if self.stage is None or not absolute.is_absolute():
            raise RootfsError("rootfs-stage-unavailable")
        output = self.stage / absolute.relative_to("/")
        if self.stage not in output.parents:
            raise RootfsError("runtime-target-path-invalid")
        return output

    def add_alias(self, path: str, target: str) -> None:
        if f"/{path}" in self.records:
            return
        output = self._output_path(Path("/") / path)
        output.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, output)
        self._record({
            "path": f"/{path}", "type": "symlink", "target": target,
            "source": "rootfs-layout",
        }, Path("/"))

    def add_system_alias(self, name: str) -> None:
        source = Path("/") / name
        expected = {
            "bin": (Path("/usr/bin"),),
            "lib": (Path("/usr/lib"), Path("/usr/lib64")),
            "lib64": (Path("/usr/lib64"), Path("/usr/lib")),
        }
        if name not in expected or not source.is_symlink():
            raise RootfsError("system-runtime-layout-unavailable")
        try:
            resolved = source.resolve(strict=True)
            if not any(resolved == root or root in resolved.parents for root in expected[name]):
                raise RootfsError("system-runtime-layout-invalid")
            target = os.path.relpath(resolved, source.parent)
        except OSError:
            raise RootfsError("system-runtime-layout-invalid") from None
        self.add_alias(name, target)

    def ensure_system_alias_target(self, name: str) -> None:
        source = Path("/") / name
        try:
            target = source.resolve(strict=True)
        except OSError:
            raise RootfsError("system-runtime-layout-invalid") from None
        output = self._output_path(target)
        if output.exists() or output.is_symlink():
            if output.is_symlink() or not output.is_dir():
                raise RootfsError("system-runtime-layout-invalid")
        else:
            output.mkdir(parents=True, mode=0o755)
        if str(target) not in self.records:
            self._record({
                "path": str(target), "type": "directory", "mode": "0755",
                "source": "rootfs-layout",
            }, Path("/"))

    def _add_ldd_closure(self) -> None:
        for source in sorted(self.ldd_subjects, key=str):
            try:
                if not stat.S_ISREG(source.stat().st_mode):
                    continue
                with source.open("rb") as item:
                    if item.read(4) != ELF_MAGIC:
                        continue
            except OSError:
                raise RootfsError("runtime-elf-read-failed") from None
            for dependency in self.ldd(source):
                try:
                    resolved_parent = dependency.parent.resolve(strict=True)
                except OSError:
                    raise RootfsError("runtime-dependency-source-invalid") from None
                mapping, parent_relative = self._mapping_for(resolved_parent)
                if mapping.category != "system-library":
                    raise RootfsError("runtime-dependency-source-invalid")
                self.add_path(mapping, parent_relative / dependency.name)

    def _write_generated(self, path: str, content: bytes, mode: int = 0o644) -> None:
        target = Path("/") / path
        output = self._output_path(target)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
        output.chmod(mode)
        record = {
            "path": str(target), "type": "file", "mode": f"0{mode:o}",
            "sha256": hashlib.sha256(content).hexdigest(), "source": "generated",
        }
        self._record(record, Path("/"))

    def _write_generated_directory(self, path: str) -> None:
        target = Path("/") / path
        output = self._output_path(target)
        output.mkdir(parents=True, exist_ok=True, mode=0o755)
        output.chmod(0o755)
        self._record({
            "path": str(target), "type": "directory", "mode": "0755",
            "source": "generated",
        }, Path("/"))

    def _record_parent_directories(self) -> None:
        for key in tuple(self.records):
            parent = Path(key).parent
            while parent != Path("/"):
                parent_key = str(parent)
                prior = self.records.get(parent_key)
                if prior is not None:
                    if prior.get("type") != "directory":
                        raise RootfsError("runtime-manifest-path-collision")
                else:
                    output = self._output_path(parent)
                    if output.is_symlink() or not output.is_dir():
                        raise RootfsError("runtime-directory-closure-invalid")
                    self._record({
                        "path": parent_key, "type": "directory", "mode": "0755",
                        "source": "rootfs-parent",
                    }, Path("/"))
                parent = parent.parent

    def build(
        self,
        *,
        python_executable: Path | None,
        bash_executable: Path,
        sh_executable: Path,
        go_root: Path | None = None,
        psql_executable: Path | None = None,
        python_stdlib: tuple[Path, ...] = (),
        test_utilities: tuple[Path, ...] = (),
        require_full_runtime: bool = False,
        runtime_profile: str | None = None,
        resolv_source: Path | None = None,
        certs_source: Path | None = None,
    ) -> Path:
        profile = runtime_profile or (
            "live-executable" if self.require_exec_mount else "mock-only"
        )
        if profile not in ROOTFS_PROFILES:
            raise RootfsError("rootfs-profile-invalid")
        if profile == "dependency-fetch":
            if not self.require_exec_mount or go_root is None:
                raise RootfsError("rootfs-profile-invalid")
        include_python = python_executable is not None
        if not include_python and python_stdlib:
            raise RootfsError("python-standard-library-invalid")
        try:
            self._validate_runtime_paths(
                python_executable=python_executable,
                bash_executable=bash_executable,
                sh_executable=sh_executable,
                go_root=go_root,
                psql_executable=psql_executable,
                python_stdlib=python_stdlib,
                test_utilities=test_utilities,
                require_full_runtime=require_full_runtime,
                test_source_roots=self.test_source_roots,
            )
            self.stage = Path(tempfile.mkdtemp(prefix=f".{self.destination.name}.", dir=self.destination.parent))
            self.stage.chmod(0o755)
            if require_full_runtime:
                if go_root is None:
                    raise RootfsError("required-runtime-source-missing")
                if profile == "dependency-fetch" and psql_executable is not None:
                    raise RootfsError("required-runtime-source-missing")
                if profile != "dependency-fetch" and psql_executable is None:
                    raise RootfsError("required-runtime-source-missing")
                self.add_mapping(go_root, Path("/opt/go"), "go-toolchain")
                if psql_executable is not None:
                    pg_bindir = psql_executable.parent
                    self.add_mapping(
                        pg_bindir, self._target_for_test_source(pg_bindir), "postgres-client",
                    )

            if include_python:
                python_root = python_executable.parent
                python_bin = self.add_mapping(
                    python_root, self._target_for_test_source(python_root), "python-runtime",
                )
                self.add_path(python_bin, Path(python_executable.name))
                self.add_ldd_subject(python_bin, Path(python_executable.name))
            bash_root = bash_executable.parent
            bash_mapping = self.add_mapping(
                bash_root, self._target_for_test_source(bash_root), "test-runtime",
            )
            self.add_path(bash_mapping, Path(bash_executable.name))
            self.add_ldd_subject(bash_mapping, Path(bash_executable.name))
            sh_root = sh_executable.parent
            sh_mapping = self.add_mapping(
                sh_root, self._target_for_test_source(sh_root), "test-runtime",
            )
            self.add_path(sh_mapping, Path(sh_executable.name))
            self.add_ldd_subject(sh_mapping, Path(sh_executable.name))
            for utility in test_utilities:
                utility_root = utility.parent
                utility_mapping = self.add_mapping(
                    utility_root, self._target_for_test_source(utility_root), "test-runtime",
                )
                self.add_path(utility_mapping, Path(utility.name))
                self.add_ldd_subject(utility_mapping, Path(utility.name))

            for library_root in LD_LIBRARY_ROOTS:
                if not library_root.exists():
                    continue
                resolved_root = library_root.resolve(strict=True)
                self.add_mapping(resolved_root, resolved_root, "system-library")
            for stdlib_root in python_stdlib:
                if not stdlib_root.is_dir() or stdlib_root.is_symlink():
                    raise RootfsError("python-standard-library-invalid")
                stdlib = self.add_mapping(
                    stdlib_root, self._target_for_test_source(stdlib_root),
                    "python-standard-library",
                )
                self.add_path(stdlib, Path("."))
                extension_dir = stdlib_root / "lib-dynload"
                if extension_dir.is_dir():
                    for extension in sorted(extension_dir.glob("*.so"), key=str):
                        self.add_ldd_subject(stdlib, extension.relative_to(stdlib_root))

            if require_full_runtime:
                if go_root is None:
                    raise RootfsError("go-toolchain-root-missing")
                go = next(item for item in self.mappings if item.category == "go-toolchain")
                for name in ("bin/go", "bin/gofmt", "pkg/tool", "pkg/include", "src", "VERSION"):
                    candidate = go_root / name
                    if candidate.exists() or candidate.is_symlink():
                        self.add_path(go, Path(name))
                for relative in (Path("bin/go"), Path("bin/gofmt")):
                    candidate = go_root / relative
                    if candidate.exists() or candidate.is_symlink():
                        self.add_ldd_subject(go, relative)
                tool_root = go_root / "pkg/tool"
                if tool_root.is_dir():
                    for candidate in sorted(tool_root.rglob("*"), key=str):
                        if candidate.is_file() and os.access(candidate, os.X_OK):
                            self.add_ldd_subject(go, candidate.relative_to(go_root))
                zoneinfo = go_root / "lib/time/zoneinfo.zip"
                if zoneinfo.exists() or zoneinfo.is_symlink():
                    self.add_path(go, Path("lib/time/zoneinfo.zip"))
                if psql_executable is not None:
                    pg = next(item for item in self.mappings if item.category == "postgres-client")
                    self.add_path(pg, Path(psql_executable.name))
                    self.add_ldd_subject(pg, Path(psql_executable.name))

            if profile == "dependency-fetch":
                # The fetch rootfs resolves modules over an allowlisted network
                # exception: it gets only the loopback resolver configuration
                # and the public CA bundle, never credentials or host paths.
                self._write_generated("etc/resolv.conf", _fetch_resolv_conf(resolv_source))
                if certs_source is None:
                    raise RootfsError("fetch-certificate-source-missing")
                try:
                    certs_root = certs_source.resolve(strict=True)
                except OSError:
                    raise RootfsError("fetch-certificate-source-missing") from None
                certs = self.add_mapping(certs_root, Path("/etc/ssl/certs"), "system-certs")
                self.add_path(certs, Path("."))
            elif resolv_source is not None or certs_source is not None:
                raise RootfsError("rootfs-profile-invalid")

            if profile != "dependency-fetch":
                # Only these two reviewed sources enter the closed runtime;
                # never copy their parent checkout or the host report validator.
                harness_parent = Path(__file__).resolve().parent
                for name in ("run.py", "psql-probe.sh"):
                    source = harness_parent / name
                    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    with os.fdopen(descriptor, "rb") as handle:
                        metadata = os.fstat(handle.fileno())
                        if (source.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                                or metadata.st_nlink != 1
                                or stat.S_IMODE(metadata.st_mode) not in (0o644, 0o755)
                                or metadata.st_size > (1 << 20)):
                            raise RootfsError("harness-source-invalid")
                        contents = handle.read((1 << 20) + 1)
                    if len(contents) != metadata.st_size:
                        raise RootfsError("harness-source-invalid")
                    self._write_generated("opt/statekit/repo/tests/live/postgres/" + name,
                                          contents, stat.S_IMODE(metadata.st_mode))

            self._add_ldd_closure()
            for alias in ("bin", "lib", "lib64"):
                self.ensure_system_alias_target(alias)
                self.add_system_alias(alias)
            for directory in (
                "artifact", "dev", "dev/pts", "dev/shm", "modules", "out", "proc",
                "run", "sys", "tmp", "workspace",
            ):
                self._write_generated_directory(directory)
            self._write_generated("artifact/statekit", b"", 0o644)
            self._write_generated(
                PREFLIGHT_RELATIVE_PATH, PREFLIGHT_SCRIPT, 0o755,
            )
            self._write_generated(
                "etc/passwd",
                f"root:x:0:0:root:/root:/usr/sbin/nologin\nstatekit:x:{self.uid}:{self.gid}:statekit:/tmp:/usr/sbin/nologin\n".encode(),
            )
            self._write_generated(
                "etc/group",
                f"root:x:0:\nstatekit:x:{self.gid}:\n".encode(),
            )
            self._record_parent_directories()
            if len(self.records) > MAX_ENTRIES:
                raise RootfsError("runtime-manifest-entry-limit")
            manifest = {
                "format": "statekit-rootfs-v1",
                "runtime_profile": profile,
                "go_version": "go1.26.8" if require_full_runtime else None,
                "postgres_version": "16.15" if profile == "live-executable" else None,
                "library_path": sorted({
                    str(Path(str(record["path"])).parent)
                    for record in self.records.values()
                    if record.get("source") == "system-library"
                    and record.get("type") in ("file", "symlink")
                }),
                "entries": [self.records[key] for key in sorted(self.records)],
            }
            manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
            self._write_generated("etc/statekit-rootfs.manifest", manifest_bytes)
            if self.node_count > MAX_ENTRIES or self.byte_count > MAX_BYTES:
                raise RootfsError("runtime-manifest-size-limit")
            self.stage.rename(self.destination)
            self.stage = None
            return self.destination
        except RootfsError:
            self._discard_stage()
            raise
        except (OSError, StopIteration, ValueError):
            self._discard_stage()
            raise RootfsError("rootfs-construction-failed") from None

    def _discard_stage(self) -> None:
        if self.stage is not None:
            shutil.rmtree(self.stage, ignore_errors=True)
            self.stage = None


def python_standard_library(python_executable: Path) -> tuple[Path, ...]:
    probe = (
        "import json,sysconfig; "
        "print(json.dumps(sorted(set((sysconfig.get_path('stdlib'), "
        "sysconfig.get_path('platstdlib'))))))"
    )
    try:
        result = subprocess.run(
            [str(python_executable), "-S", "-c", probe],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONPATH": ""},
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=10, check=False,
        )
        paths = json.loads(result.stdout) if result.returncode == 0 else []
        roots = tuple(
            Path(item) for item in paths
            if isinstance(item, str) and item and Path(item).is_dir()
        )
        if not roots or any(not root.is_absolute() or root.is_symlink() for root in roots):
            raise RootfsError("python-standard-library-unavailable")
        return tuple(dict.fromkeys(roots))
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        raise RootfsError("python-standard-library-unavailable") from None


def build_full_rootfs(
    *, destination: Path, uid: int, gid: int, go_root: Path,
    psql_executable: Path, python_executable: Path,
    bash_executable: Path, sh_executable: Path, exec_mount: Path,
    test_utilities: tuple[Path, ...] | None = None,
) -> Path:
    builder = RootfsBuilder(
        destination, uid=uid, gid=gid, require_exec_mount=True,
        exec_mount=exec_mount,
    )
    return builder.build(
        go_root=go_root, psql_executable=psql_executable,
        python_executable=python_executable, bash_executable=bash_executable,
        sh_executable=sh_executable,
        python_stdlib=python_standard_library(python_executable),
        test_utilities=test_utilities or tuple(
            Path("/usr/bin") / name for name in TEST_UTILITIES
        ),
        require_full_runtime=True,
    )


def build_mock_rootfs(
    *, destination: Path, uid: int, gid: int, python_executable: Path,
    bash_executable: Path, sh_executable: Path,
    test_utilities: tuple[Path, ...] | None = None,
) -> Path:
    """Build a mock-only rootfs without asserting live exec-mount readiness."""
    builder = RootfsBuilder(
        destination, uid=uid, gid=gid, require_exec_mount=False,
    )
    return builder.build(
        python_executable=python_executable, bash_executable=bash_executable,
        sh_executable=sh_executable,
        python_stdlib=python_standard_library(python_executable),
        test_utilities=test_utilities or tuple(
            Path("/usr/bin") / name for name in TEST_UTILITIES
        ),
    )


def _fetch_resolv_conf(source: Path | None) -> bytes:
    """Return a validated loopback-only resolver configuration copy."""
    if source is None:
        raise RootfsError("fetch-resolv-source-missing")
    try:
        text = source.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise RootfsError("fetch-resolv-source-missing") from None
    if len(text) > 4096 or not text.endswith("\n"):
        raise RootfsError("fetch-resolv-source-invalid")
    nameservers = 0
    for line in text.splitlines():
        if line.startswith("nameserver "):
            address = line.split(" ", 1)[1].strip()
            try:
                packed = ipaddress.ip_address(address)
            except ValueError:
                raise RootfsError("fetch-resolv-source-invalid") from None
            if not packed.is_loopback:
                raise RootfsError("fetch-resolv-source-invalid")
            nameservers += 1
        elif not (line.startswith("search ") or line.startswith("options ")
                  or line.startswith("#") or not line.strip()):
            raise RootfsError("fetch-resolv-source-invalid")
    if nameservers == 0:
        raise RootfsError("fetch-resolv-source-invalid")
    return text.encode("ascii")


def build_fetch_rootfs(
    *, destination: Path, uid: int, gid: int, go_root: Path,
    bash_executable: Path, sh_executable: Path, exec_mount: Path,
    test_utilities: tuple[Path, ...] | None = None,
    resolv_source: Path | None = None,
    certs_source: Path | None = None,
) -> Path:
    """Build the network-bounded dependency-fetch rootfs (Go toolchain only)."""
    builder = RootfsBuilder(
        destination, uid=uid, gid=gid, require_exec_mount=True,
        exec_mount=exec_mount,
    )
    return builder.build(
        python_executable=None, bash_executable=bash_executable,
        sh_executable=sh_executable, go_root=go_root,
        python_stdlib=(),
        test_utilities=test_utilities or tuple(
            Path("/usr/bin") / name for name in TEST_UTILITIES
        ),
        require_full_runtime=True,
        runtime_profile="dependency-fetch",
        resolv_source=resolv_source or Path("/etc/resolv.conf"),
        certs_source=certs_source or Path("/etc/ssl/certs"),
    )


def verify_staged_rootfs(
    destination: Path,
    *,
    manifest_sha256: str,
    profile: str,
    exec_mount: Path | None = None,
) -> None:
    """Independently revalidate the staged rootfs tree against its manifest.

    Called immediately before every container create/start: canonical root
    and parent, manifest digest, exact entry list (no unlisted files, dirs,
    sockets, or devices), per-entry type/mode/hash, and symlink targets that
    stay inside the staged root.
    """
    if re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None:
        raise RootfsError("rootfs-manifest-digest-invalid")
    if profile not in ROOTFS_PROFILES:
        raise RootfsError("rootfs-profile-invalid")
    if not destination.is_absolute() or destination.parent == destination:
        raise RootfsError("rootfs-destination-invalid")
    try:
        if destination.is_symlink() or destination.resolve(strict=True) != destination:
            raise RootfsError("rootfs-destination-invalid")
        parent = destination.parent
        if parent.is_symlink() or parent.resolve(strict=True) != parent:
            raise RootfsError("rootfs-parent-invalid")
        if exec_mount is not None:
            if parent != exec_mount or destination.name not in EXEC_MOUNT_CHILDREN:
                raise RootfsError("rootfs-outside-exec-mount")
    except OSError:
        raise RootfsError("rootfs-destination-invalid") from None

    manifest_path = destination / MANIFEST_RELATIVE_PATH
    try:
        manifest_metadata = manifest_path.lstat()
        if (stat.S_ISLNK(manifest_metadata.st_mode)
                or not stat.S_ISREG(manifest_metadata.st_mode)
                or manifest_metadata.st_nlink != 1):
            raise RootfsError("rootfs-manifest-unavailable")
        manifest_bytes = manifest_path.read_bytes()
    except OSError:
        raise RootfsError("rootfs-manifest-unavailable") from None
    if hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256:
        raise RootfsError("rootfs-manifest-digest-mismatch")
    if len(manifest_bytes) > (64 << 20):
        raise RootfsError("rootfs-manifest-unavailable")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise RootfsError("rootfs-manifest-invalid") from None
    if not isinstance(manifest, dict) or manifest.get("format") != "statekit-rootfs-v1" \
            or manifest.get("runtime_profile") != profile:
        raise RootfsError("rootfs-manifest-invalid")
    expected_go = "go1.26.8" if profile in ("live-executable", "dependency-fetch") else None
    expected_pg = "16.15" if profile == "live-executable" else None
    if manifest.get("go_version") != expected_go \
            or manifest.get("postgres_version") != expected_pg:
        raise RootfsError("rootfs-manifest-invalid")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RootfsError("rootfs-manifest-invalid")
    records: dict[str, dict[str, object]] = {}
    entry_paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise RootfsError("rootfs-manifest-invalid")
        key = entry.get("path")
        if not isinstance(key, str):
            raise RootfsError("rootfs-manifest-invalid")
        candidate = Path(key)
        if (not key.startswith("/") or key != str(candidate) or candidate == Path("/")
                or ".." in candidate.parts or "." in candidate.parts
                or "//" in key or key in records):
            raise RootfsError("rootfs-manifest-invalid")
        records[key] = entry
        entry_paths.append(key)
    if entry_paths != sorted(entry_paths):
        raise RootfsError("rootfs-manifest-invalid")

    harness_prefix = "/opt/statekit/repo/"
    harness_files = {harness_prefix + "tests/live/postgres/" + name
                     for name in ("run.py", "psql-probe.sh")}
    actual_harness = {key for key, entry in records.items()
                      if key.startswith(harness_prefix) and entry.get("type") != "directory"}
    if actual_harness != (set() if profile == "dependency-fetch" else harness_files):
        raise RootfsError("rootfs-harness-closure-invalid")
    allowed_harness_paths = harness_files | {
        "/opt/statekit/repo", "/opt/statekit/repo/tests",
        "/opt/statekit/repo/tests/live", "/opt/statekit/repo/tests/live/postgres",
    }
    if {key for key in records if key == harness_prefix.rstrip("/") or key.startswith(harness_prefix)} != (
            set() if profile == "dependency-fetch" else allowed_harness_paths):
        raise RootfsError("rootfs-harness-closure-invalid")
    for key in actual_harness:
        if records[key].get("type") != "file" or records[key].get("mode") not in ("0644", "0755"):
            raise RootfsError("rootfs-harness-entry-invalid")

    staged_paths: set[str] = set()
    pending = [destination]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as children:
                for child in children:
                    staged = destination / (Path(child.path).relative_to(destination))
                    key = "/" + str(staged.relative_to(destination))
                    metadata = child.stat(follow_symlinks=False)
                    mode = metadata.st_mode
                    if stat.S_ISSOCK(mode) or stat.S_ISCHR(mode) \
                            or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode):
                        raise RootfsError("rootfs-unlisted-node-type")
                    if key in staged_paths:
                        raise RootfsError("rootfs-staged-tree-invalid")
                    staged_paths.add(key)
                    if stat.S_ISDIR(mode):
                        record = records.get(key)
                        if record is not None and (
                                record.get("type") != "directory"
                                or record.get("mode") not in ("0755",)
                                or stat.S_IMODE(mode) != 0o755):
                            raise RootfsError("rootfs-staged-node-mismatch")
                        pending.append(staged)
                    elif stat.S_ISLNK(mode):
                        record = records.get(key)
                        if record is not None:
                            if record.get("type") != "symlink":
                                raise RootfsError("rootfs-staged-node-mismatch")
                            try:
                                target = os.readlink(child.path)
                            except OSError:
                                raise RootfsError("rootfs-staged-tree-invalid") from None
                            if target != record.get("target"):
                                raise RootfsError("rootfs-symlink-target-mismatch")
                        try:
                            resolved = staged.resolve(strict=True)
                            root_resolved = destination.resolve(strict=True)
                        except OSError:
                            raise RootfsError("rootfs-symlink-target-missing") from None
                        if resolved == root_resolved or root_resolved not in resolved.parents \
                                or root_resolved == resolved:
                            raise RootfsError("rootfs-symlink-escape")
                        resolved_key = "/" + str(resolved.relative_to(root_resolved))
                        if resolved_key not in records:
                            raise RootfsError("rootfs-symlink-target-missing")
                    elif stat.S_ISREG(mode):
                        record = records.get(key)
                        if record is not None:
                            if record.get("type") != "file":
                                raise RootfsError("rootfs-staged-node-mismatch")
                            recorded_mode = record.get("mode")
                            if recorded_mode not in ("0755", "0644") \
                                    or stat.S_IMODE(mode) != int(str(recorded_mode), 8) \
                                    or mode & 0o7000 or metadata.st_nlink != 1:
                                raise RootfsError("rootfs-staged-node-mismatch")
                            digest = hashlib.sha256()
                            size = 0
                            try:
                                descriptor = os.open(
                                    child.path, os.O_RDONLY
                                    | getattr(os, "O_NOFOLLOW", 0)
                                    | getattr(os, "O_CLOEXEC", 0),
                                )
                                opened = os.fstat(descriptor)
                                if not stat.S_ISREG(opened.st_mode) \
                                        or opened.st_dev != metadata.st_dev \
                                        or opened.st_ino != metadata.st_ino:
                                    raise RootfsError("rootfs-file-identity-changed")
                                with os.fdopen(descriptor, "rb") as source_file:
                                    while True:
                                        chunk = source_file.read(1 << 20)
                                        if not chunk:
                                            break
                                        size += len(chunk)
                                        digest.update(chunk)
                            except OSError:
                                raise RootfsError("rootfs-file-read-failed") from None
                            if size != metadata.st_size \
                                    or digest.hexdigest() != record.get("sha256"):
                                raise RootfsError("rootfs-file-hash-mismatch")
                        # Unlisted regular nodes (including the manifest's
                        # self-exception) are resolved by the exact set
                        # comparison after the walk, never silently accepted.
                    else:
                        raise RootfsError("rootfs-unlisted-node-type")
        except OSError:
            raise RootfsError("rootfs-staged-tree-invalid") from None

    if staged_paths - set(records) != MANIFEST_SELF_EXCEPTION:
        raise RootfsError("rootfs-unlisted-entry")
    if set(records) - staged_paths:
        raise RootfsError("rootfs-missing-entry")
    for key in records:
        parent_key = str(Path(key).parent)
        if parent_key != "/" and records.get(parent_key, {}).get("type") != "directory":
            raise RootfsError("rootfs-manifest-invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("full", "mock"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--destination", type=Path, required=True)
        sub.add_argument("--uid", type=int, required=True)
        sub.add_argument("--gid", type=int, required=True)
        sub.add_argument("--python", type=Path, required=None)
        sub.add_argument("--bash", type=Path, required=True)
        sub.add_argument("--sh", type=Path, required=True)
        sub.add_argument("--test-utility", action="append", type=Path, default=[])
        if command == "full":
            sub.add_argument("--profile", choices=("live", "fetch"), default="live")
            sub.add_argument("--exec-mount", type=Path, required=True)
            sub.add_argument("--go-root", type=Path, required=True)
            sub.add_argument("--psql", type=Path, required=None)
            sub.add_argument("--resolv", type=Path, required=None)
            sub.add_argument("--certs", type=Path, required=None)
    preflight = subparsers.add_parser("preflight-mount")
    preflight.add_argument("--mountpoint", type=Path, required=True)
    verify = subparsers.add_parser("verify-mount")
    verify.add_argument("--mountpoint", type=Path, required=True)
    verify.add_argument("--uid", type=int, required=True)
    verify.add_argument("--gid", type=int, required=True)
    verify_rootfs = subparsers.add_parser("verify")
    verify_rootfs.add_argument("--destination", type=Path, required=True)
    verify_rootfs.add_argument("--manifest-sha256", required=True)
    verify_rootfs.add_argument(
        "--profile", choices=tuple(sorted(ROOTFS_PROFILES)), required=True,
    )
    verify_rootfs.add_argument("--exec-mount", type=Path, required=None)
    cleanup = subparsers.add_parser("verify-cleanup")
    cleanup.add_argument("--mountpoint", type=Path, required=True)
    cleanup.add_argument("--uid", type=int, required=True)
    cleanup.add_argument("--gid", type=int, required=True)
    finish = subparsers.add_parser("finish-cleanup")
    finish.add_argument("--mountpoint", type=Path, required=True)
    finish.add_argument("--runner-uid", type=int, required=True)
    finish.add_argument("--runner-gid", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == "preflight-mount":
            preflight_exec_mountpoint(args.mountpoint)
        elif args.command == "verify-mount":
            verify_exec_mount(args.mountpoint, uid=args.uid, gid=args.gid)
        elif args.command == "verify-cleanup":
            prepare_exec_mount_cleanup(args.mountpoint, uid=args.uid, gid=args.gid)
        elif args.command == "finish-cleanup":
            finish_exec_mount_cleanup(
                args.mountpoint, runner_uid=args.runner_uid,
                runner_gid=args.runner_gid,
            )
        elif args.command == "verify":
            verify_staged_rootfs(
                args.destination,
                manifest_sha256=args.manifest_sha256,
                profile=args.profile,
                exec_mount=args.exec_mount,
            )
        elif args.command == "full" and args.profile == "fetch":
            if args.python is not None or args.psql is not None:
                raise RootfsError("rootfs-profile-invalid")
            build_fetch_rootfs(
                destination=args.destination, uid=args.uid, gid=args.gid,
                go_root=args.go_root, bash_executable=args.bash,
                sh_executable=args.sh, exec_mount=args.exec_mount,
                test_utilities=tuple(args.test_utility) or tuple(
                    Path("/usr/bin") / name for name in TEST_UTILITIES
                ),
                resolv_source=args.resolv, certs_source=args.certs,
            )
        elif args.command == "full":
            if args.python is None or args.psql is None:
                raise RootfsError("required-runtime-source-missing")
            build_full_rootfs(
                destination=args.destination, uid=args.uid, gid=args.gid,
                go_root=args.go_root, psql_executable=args.psql,
                python_executable=args.python, bash_executable=args.bash,
                sh_executable=args.sh, exec_mount=args.exec_mount,
                test_utilities=tuple(args.test_utility) or tuple(
                    Path("/usr/bin") / name for name in TEST_UTILITIES
                ),
            )
        else:
            if args.python is None:
                raise RootfsError("required-runtime-source-missing")
            build_mock_rootfs(
                destination=args.destination, uid=args.uid, gid=args.gid,
                python_executable=args.python, bash_executable=args.bash,
                sh_executable=args.sh,
                test_utilities=tuple(args.test_utility) or tuple(
                    Path("/usr/bin") / name for name in TEST_UTILITIES
                ),
            )
    except RootfsError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
