#!/usr/bin/env python3
"""Runner-native PostgreSQL/production-binary gate; mock checks stay offline."""

from __future__ import annotations

from collections.abc import Iterable
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import BinaryIO


POSTGRES_MAJOR = 16
POSTGRES_VERSION = "16.15"
GO_VERSION = "go1.26.8"
MAX_CAPTURE = 6 << 20
ROOT = Path(__file__).resolve().parents[3]
ROOTFS_REPO = Path("/opt/statekit/repo")
HARNESS_FILES = ("tests/live/postgres/run.py", "tests/live/postgres/psql-probe.sh")
MAX_CREDENTIAL_BYTES = 4096
REPORT = ROOT / "artifacts/postgres-live/report.txt"
REMOTE_OR_AUTH_ENV = (
    "CONTAINER_HOST", "DOCKER_HOST", "PODMAN_HOST", "CONTAINER_CONNECTION",
    "DOCKER_CONFIG", "DOCKER_AUTH_CONFIG", "REGISTRY_AUTH_FILE",
    "CONTAINERS_AUTH_FILE", "SSH_AUTH_SOCK", "CONTAINER_SSHKEY",
)
SENSITIVE_ENV_NAMES = frozenset({
    "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
    "PGPASSWORD", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
})
CREDENTIAL_ENV_PREFIXES = (
    "ACTIONS_ID_TOKEN_", "AWS_", "AZURE_", "GOOGLE_", "GCP_",
)


def credential_env_names(names: Iterable[str]) -> set[str]:
    return {
        name for name in names
        if name in SENSITIVE_ENV_NAMES or name.startswith(CREDENTIAL_ENV_PREFIXES)
        or name.endswith(("_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIALS", "_PRIVATE_KEY"))
    }
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

MULTILINE = 'comma, "quoted"\nsecond line'
OVERSIZE_SQL = "SELECT '" + "x" * ((256 << 10) - len("SELECT ''") + 1) + "'"
MULTILINE_SQL = "SELECT 1 AS id, 'comma, \"quoted\"' || chr(10) || 'second line' AS note"
NATIVE_MULTILINE_HEX_SQL = (
    "SELECT encode(convert_to('comma, \"quoted\"' || chr(10) || 'second line', 'UTF8'), 'hex')"
)
INSERT_SQL = (
    "WITH inserted AS (INSERT INTO observations (id, note) VALUES (1, 'start') "
    "RETURNING id, note) SELECT id, note FROM inserted"
)
UPDATE_SQL = (
    "WITH updated AS (UPDATE observations SET note='committed' WHERE id=1 "
    "RETURNING id, note) SELECT id, note FROM updated"
)
EMPTY_UPDATE_SQL = (
    "WITH updated AS (UPDATE observations SET note='unexpected' WHERE id=999 "
    "RETURNING id, note) SELECT id, note FROM updated"
)
PROBE_COMPLETED = "probe: production-binary-completed"
PROBE_DISPATCHED = "probe: dispatched"
PROBE_NOT_DISPATCHED = "probe: not-dispatched"


class GateError(Exception):
    """Fixed value-free failure category; never carries SQL or credentials."""


def require(condition: bool, category: str) -> None:
    if not condition:
        raise GateError(category)


def command_result(argv: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[bytes]:
    """Run a fixed preflight command with a small, secret-free environment."""
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LC_ALL": "C"}
    try:
        return subprocess.run(
            argv, capture_output=True, timeout=timeout, check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GateError("runner-tool-preflight-failed") from None


def require_live_preflight() -> None:
    """Check GitHub-hosted context and the exact allowed event before mutation."""
    expected = {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "GITHUB_REPOSITORY": "friz-zy/statekit",
    }
    require(all(os.environ.get(key) == value for key, value in expected.items()),
            "github-hosted-runner-required")
    require(all(key not in os.environ for key in REMOTE_OR_AUTH_ENV)
            and not credential_env_names(os.environ),
            "remote-or-credential-runtime-environment")
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "/missing"))
    try:
        require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink()
                and workspace.resolve(strict=True) == ROOT.resolve(strict=True),
                "github-workspace-mismatch")
    except OSError:
        raise GateError("github-workspace-mismatch") from None
    event = os.environ.get("GITHUB_EVENT_NAME")
    ref = os.environ.get("GITHUB_REF", "")
    require(
        event in ("push", "workflow_dispatch", "schedule")
        and ref == "refs/heads/main",
        "untrusted-event-ref",
    )


def output_for(argv: list[str], *, timeout: int = 15) -> str:
    result = command_result(argv, timeout=timeout)
    require(result.returncode == 0, "runner-tool-preflight-failed")
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError:
        raise GateError("runner-tool-preflight-failed") from None


def postgres_tool_version(version_output: str) -> str:
    match = re.search(r"PostgreSQL\)?\s+(\d+(?:\.\d+){1,2})(?=\s|\(|$)", version_output)
    require(match is not None, "postgres-tool-version-unverifiable")
    return match.group(1)


def validate_runner_tool_paths(tools: dict[str, str]) -> None:
    """Disallow PATH-shadowed admin utilities outside the runner OS packages."""
    system_roots = (
        Path("/usr/bin").resolve(), Path("/usr/sbin").resolve(),
        Path(f"/usr/lib/postgresql/{POSTGRES_MAJOR}/bin").resolve(),
    )
    try:
        go_roots = [Path("/usr/local/go").resolve()]
        tool_cache = os.environ.get("RUNNER_TOOL_CACHE", "")
        if tool_cache:
            cache_root = Path(tool_cache)
            require(cache_root.is_absolute(), "runner-tool-path-mismatch")
            go_roots.append(cache_root.resolve(strict=False))
        go_path = Path(tools["go"]).resolve(strict=False)
        require(any(root == go_path or root in go_path.parents for root in go_roots),
                "runner-tool-path-mismatch")
        for name, value in tools.items():
            if name == "go":
                continue
            resolved = Path(value).resolve(strict=False)
            require(any(root == resolved or root in resolved.parents for root in system_roots),
                    "runner-tool-path-mismatch")
    except OSError:
        raise GateError("runner-tool-path-mismatch") from None


def require_runner_toolchain() -> dict[str, str]:
    """Validate unprivileged runner tools; admin inspection is ci.sh-owned."""
    require(os.name == "posix" and os.geteuid() != 0, "unprivileged-runner-required")
    required = (
        "go", "pg_config", "pg_ctlcluster", "pg_lsclusters", "pg_conftool",
        "iptables", "ip6tables", "ss", "useradd", "userdel", "groupdel",
        "usermod", "pkill", "pgrep", "getent", "id", "chown", "chmod", "stat", "install",
        "mktemp", "timeout", "setpriv", "env", "python3", "podman", "ldd",
        "sha256sum", "bash", "sh",
    )
    tools = {name: shutil.which(name) or "" for name in required}
    require(all(tools.values()), "runner-tools-unavailable")
    validate_runner_tool_paths(tools)
    require(all(tools[name] == f"/usr/bin/{name}" for name in (
        "timeout", "setpriv", "env", "python3", "podman", "ldd", "sha256sum", "bash",
    )),
            "runner-tool-path-mismatch")

    go_version = output_for([tools["go"], "version"])
    require(re.search(rf"\b{re.escape(GO_VERSION)}(?:\s|$)", go_version) is not None,
            "go-toolchain-version-mismatch")
    pg_config_version = output_for([tools["pg_config"], "--version"])
    bindir = output_for([tools["pg_config"], "--bindir"])
    psql_bin = str(Path(bindir) / "psql")
    require(Path(psql_bin).is_file() and not Path(psql_bin).is_symlink()
            and os.access(psql_bin, os.X_OK), "postgres-client-binary-unavailable")
    psql_version = output_for([psql_bin, "--version"])
    postgres_bin = str(Path(bindir) / "postgres")
    require(Path(postgres_bin).is_file() and os.access(postgres_bin, os.X_OK),
            "postgres-server-binary-unavailable")
    server_version = output_for([postgres_bin, "--version"])
    require(
        postgres_tool_version(pg_config_version) == POSTGRES_VERSION
        and postgres_tool_version(psql_version) == POSTGRES_VERSION
        and postgres_tool_version(server_version) == POSTGRES_VERSION,
        "postgres-tool-version-mismatch",
    )

    try:
        postgres_uid = pwd.getpwnam("postgres").pw_uid
    except KeyError:
        raise GateError("postgres-os-user-unavailable") from None
    require(postgres_uid != 0, "postgres-os-user-must-not-be-root")

    clusters = output_for([tools["pg_lsclusters"], "--no-header"])
    cluster_rows = [line.split() for line in clusters.splitlines() if line.strip()]
    cluster_version = str(POSTGRES_MAJOR)
    selected = [row for row in cluster_rows if len(row) >= 6 and row[0:2] == [cluster_version, "main"]]
    require(
        len(selected) == 1 and selected[0][2] == "5432"
        and selected[0][4] == "postgres" and selected[0][3] in ("online", "down"),
        "postgres-cluster-preflight-failed",
    )
    data_dir = Path(selected[0][5])
    require(data_dir == Path(f"/var/lib/postgresql/{POSTGRES_MAJOR}/main"),
            "postgres-cluster-identity-mismatch")
    require(data_dir.is_dir() and not data_dir.is_symlink(), "postgres-data-directory-invalid")

    config = output_for([tools["pg_conftool"], cluster_version, "main", "show", "listen_addresses"])
    if config:
        if "=" in config:
            config = config.split("=", 1)[1].strip()
        listen_addresses = config.strip().strip("'\"")
    else:
        # PostgreSQL's compiled default is localhost when the setting is absent.
        listen_addresses = "localhost"
    addresses = [part.strip() for part in listen_addresses.split(",")]
    require(
        bool(addresses) and all(address in {"localhost", "127.0.0.1", "::1"}
                                for address in addresses),
        "postgres-listen-config-not-loopback",
    )
    shm = Path("/dev/shm")
    require(shm.is_dir() and not shm.is_symlink() and os.access(shm, os.W_OK | os.X_OK),
            "ephemeral-workspace-unavailable")
    config_file = f"/etc/postgresql/{POSTGRES_MAJOR}/main/postgresql.conf"
    require(Path(config_file).is_file() and not Path(config_file).is_symlink(),
            "postgres-config-file-unavailable")
    verified_tools = {
        "go": tools["go"], "psql": psql_bin, "pg_config": tools["pg_config"],
        "pg_bindir": bindir, "postgres": postgres_bin,
        "pg_ctlcluster": tools["pg_ctlcluster"], "pg_lsclusters": tools["pg_lsclusters"],
        "pg_conftool": tools["pg_conftool"], "ss": tools["ss"],
        "pg_config_file": config_file, "pg_cluster_status": selected[0][3],
        "pg_datadir": str(data_dir),
        "python3": tools["python3"], "env": tools["env"],
    }
    if selected[0][3] == "down":
        listeners = output_for([tools["ss"], "-H", "-ltnp", "sport", "=", ":5432"])
        require(not listeners, "postgres-port-already-in-use")
    return verified_tools


def postmaster_pid_lines(snapshot: dict[str, object], data_dir: Path) -> list[str]:
    lines = snapshot.get("pid_lines")
    require(isinstance(lines, list) and all(isinstance(line, str) for line in lines)
            and len(lines) >= 4 and lines[1] == str(data_dir),
            "postgres-postmaster-pid-unverifiable")
    return lines


def process_snapshot(
    pid: str, snapshot: dict[str, object],
) -> tuple[tuple[int, ...], str, tuple[str, ...]]:
    """Validate the value-free process snapshot supplied on ci.sh stdin."""
    try:
        process = snapshot.get("process")
        require(isinstance(process, dict) and process.get("pid") == pid,
                "postgres-process-identity-unverifiable")
        uids = process.get("uids")
        executable = process.get("exe")
        argv = process.get("argv")
        require(type(uids) is list and all(type(uid) is int for uid in uids)
                and type(argv) is list and all(type(arg) is str for arg in argv)
                and type(executable) is str,
                "postgres-process-identity-unverifiable")
        return tuple(uids), executable, tuple(argv)
    except (GateError, OSError, StopIteration, ValueError, TypeError, UnicodeError):
        raise GateError("postgres-process-identity-unverifiable") from None


def verify_server_process(tools: dict[str, str], snapshot: dict[str, object]) -> None:
    """Bind ci.sh's privileged, read-only snapshot to the loopback listener."""
    require_live_preflight()
    try:
        postgres_uid = pwd.getpwnam("postgres").pw_uid
    except KeyError:
        raise GateError("postgres-process-identity-unverifiable") from None
    data_dir = Path(tools["pg_datadir"])
    config_file = Path(tools["pg_config_file"])
    pid_lines = postmaster_pid_lines(snapshot, data_dir)
    require(len(pid_lines) >= 4 and pid_lines[0].isdecimal(),
            "postgres-postmaster-pid-unverifiable")
    postmaster_pid = pid_lines[0]
    require(pid_lines[1] == str(data_dir)
            and pid_lines[3] == "5432", "postgres-cluster-identity-mismatch")

    process_uids, executable, argv = process_snapshot(postmaster_pid, snapshot)
    require(postgres_uid != 0, "postgres-process-must-not-be-root")
    require(len(process_uids) == 4 and all(uid == postgres_uid for uid in process_uids),
            "postgres-process-identity-mismatch")
    require(Path(executable).resolve() == Path(tools["postgres"]).resolve(),
            "postgres-process-executable-mismatch")
    has_data_dir = any(
        (arg == "-D" and index + 1 < len(argv) and argv[index + 1] == str(data_dir))
        or arg == f"-D{data_dir}"
        for index, arg in enumerate(argv)
    )
    require(has_data_dir and f"config_file={config_file}" in argv,
            "postgres-process-config-mismatch")

    listeners = snapshot.get("listeners")
    require(isinstance(listeners, str), "postgres-listener-unverifiable")
    local_addresses: list[str] = []
    listener_pids: set[str] = set()
    for line in listeners.splitlines():
        fields = line.split()
        require(len(fields) >= 5, "postgres-listener-unverifiable")
        local_addresses.append(fields[3])
        match = re.search(r'users:\(\("postgres",pid=([1-9][0-9]*),fd=[0-9]+\)\)', line)
        require(match is not None, "postgres-listener-pid-unverifiable")
        listener_pids.add(match.group(1))
    require(
        "127.0.0.1:5432" in local_addresses
        and set(local_addresses) <= {"127.0.0.1:5432", "[::1]:5432"}
        and listener_pids == {postmaster_pid},
        "postgres-listener-not-loopback-only",
    )


CLIENT_ENV_KEYS = frozenset({
    "PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "LD_LIBRARY_PATH", "LC_ALL", "GOENV",
    "GOTOOLCHAIN", "GOWORK", "GOPROXY", "GOSUMDB", "GOPRIVATE", "GONOPROXY",
    "GONOSUMDB", "CGO_ENABLED", "STATEKIT_BIN", "STATEKIT_REPORT_PATH",
    "STATEKIT_PG_DATABASE", "STATEKIT_PG_USER", "STATEKIT_PG_PASSFILE",
    "STATEKIT_PG_BINDIR", "STATEKIT_PSQL_BIN", "STATEKIT_PG_WORKSPACE",
    "STATEKIT_WORKSPACE_UID", "STATEKIT_TEST_UID", "STATEKIT_TEST_GID",
    "STATEKIT_TOOL_ALLOWLIST", "STATEKIT_NO_SUDO_AUTHORIZATION",
    "STATEKIT_ROOTFS_RUNTIME", "STATEKIT_ROOTFS_MANIFEST_SHA256",
    "STATEKIT_ROOTFS_ROLE",
})
ROOTFS_MANIFEST_PATH = Path("/etc/statekit-rootfs.manifest")


def process_privilege_state() -> dict[str, object]:
    """Return effective process identity and Linux privilege indicators.

    Every capability field must be present in /proc/self/status: an absent
    field is reported as -1 and fails the policy, never as an implicit zero.
    """
    try:
        fields = {}
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        return {
            "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
            "egid": os.getegid(), "groups": tuple(os.getgroups()),
            "no_new_privs": int(fields.get("NoNewPrivs", "-1")),
            "cap_inh": int(fields.get("CapInh", "-1"), 16),
            "cap_prm": int(fields.get("CapPrm", "-1"), 16),
            "cap_eff": int(fields.get("CapEff", "-1"), 16),
            "cap_bnd": int(fields.get("CapBnd", "-1"), 16),
            "cap_amb": int(fields.get("CapAmb", "-1"), 16),
        }
    except (OSError, ValueError):
        raise GateError("test-user-privilege-state-unverifiable") from None


def require_zero_effective_capabilities(state: dict[str, object]) -> None:
    for key in ("cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb"):
        require(state.get(key) == 0, "test-user-privilege-policy-failed")


def verify_rootfs_manifest_digest() -> None:
    """Revalidate the in-rootfs manifest digest from the running container."""
    expected = os.environ.get("STATEKIT_ROOTFS_MANIFEST_SHA256", "")
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
            "rootfs-manifest-digest-missing")
    try:
        metadata = ROOTFS_MANIFEST_PATH.lstat()
        data = ROOTFS_MANIFEST_PATH.read_bytes()
    except OSError:
        raise GateError("rootfs-manifest-unavailable") from None
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_nlink == 1 and len(data) <= (64 << 20),
            "rootfs-manifest-unavailable")
    import hashlib
    require(hashlib.sha256(data).hexdigest() == expected,
            "rootfs-manifest-digest-mismatch")


def verify_rootfs_runtime_manifest() -> None:
    """Check the sealed live profile, never the host checkout or GitHub env.

    The controller verifies the entire closed tree before create/start. Its
    read-only rootfs and pinned manifest are rechecked here, including the only
    two repository files permitted in the payload.
    """
    verify_rootfs_manifest_digest()
    require(ROOT == ROOTFS_REPO and os.environ.get("STATEKIT_ROOTFS_ROLE") == "live",
            "rootfs-harness-location-invalid")
    try:
        manifest = json.loads(ROOTFS_MANIFEST_PATH.read_bytes())
        require(isinstance(manifest, dict) and manifest.get("format") == "statekit-rootfs-v1"
                and manifest.get("runtime_profile") == "live-executable",
                "rootfs-profile-invalid")
        entries = manifest.get("entries")
        require(isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries),
                "rootfs-manifest-invalid")
        require(all(isinstance(entry.get("path"), str) for entry in entries), "rootfs-manifest-invalid")
        records = {entry["path"]: entry for entry in entries}
        require(len(records) == len(entries), "rootfs-manifest-invalid")
        expected = {"/opt/statekit/repo/" + relative for relative in HARNESS_FILES}
        actual = {key for key, entry in records.items()
                  if key.startswith("/opt/statekit/repo/") and entry.get("type") != "directory"}
        require(actual == expected, "rootfs-harness-closure-invalid")
        allowed_paths = expected | {
            "/opt/statekit/repo", "/opt/statekit/repo/tests",
            "/opt/statekit/repo/tests/live", "/opt/statekit/repo/tests/live/postgres",
        }
        require({key for key in records if key == "/opt/statekit/repo"
                 or key.startswith("/opt/statekit/repo/")} == allowed_paths,
                "rootfs-harness-closure-invalid")
        for relative in HARNESS_FILES:
            path = ROOT / relative
            entry = records["/opt/statekit/repo/" + relative]
            metadata = path.lstat()
            require(path.resolve(strict=True) == path and stat.S_ISREG(metadata.st_mode)
                    and metadata.st_nlink == 1 and entry.get("type") == "file"
                    and entry.get("mode") in ("0644", "0755")
                    and stat.S_IMODE(metadata.st_mode) == int(entry["mode"], 8)
                    and hashlib.sha256(path.read_bytes()).hexdigest() == entry.get("sha256"),
                    "rootfs-harness-mismatch")
    except (OSError, ValueError, TypeError, KeyError):
        raise GateError("rootfs-manifest-invalid") from None


def read_credential_envelope(stream: BinaryIO) -> str:
    """One bounded stdin envelope; errors never contain input or parser text."""
    def unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            require(key not in result, "credential-envelope-invalid")
            result[key] = value
        return result

    try:
        data = stream.read(MAX_CREDENTIAL_BYTES + 1)
        require(isinstance(data, bytes) and len(data) <= MAX_CREDENTIAL_BYTES,
                "credential-envelope-invalid")
        envelope = json.loads(data.decode("utf-8"), object_pairs_hook=unique_fields)
        require(isinstance(envelope, dict) and set(envelope) == {"password"},
                "credential-envelope-invalid")
        password = envelope["password"]
        require(isinstance(password, str) and 1 <= len(password.encode("utf-8")) <= 1024
                and not any(value in password for value in ("\r", "\n", "\0")),
                "credential-envelope-invalid")
        return password
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        raise GateError("credential-envelope-invalid") from None


def create_private_passfile(path: Path, user: str, password: str) -> None:
    require(re.fullmatch(r"statekit_user_[0-9a-f]{20}", user) is not None,
            "passfile-format-invalid")
    require(isinstance(password, str) and password
            and not any(value in password for value in ("\r", "\n", "\0")),
            "passfile-format-invalid")
    escaped = password.replace("\\", "\\\\").replace(":", "\\:")
    created = False
    try:
        parent = path.parent.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                and stat.S_IMODE(parent.st_mode) == 0o700,
                "passfile-directory-policy")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as target:
            os.fchmod(target.fileno(), 0o600)
            target.write(f"127.0.0.1:5432:*:{user}:{escaped}\n".encode("utf-8"))
            target.flush()
            metadata = os.fstat(target.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    and metadata.st_uid == os.geteuid() and metadata.st_gid == os.getegid()
                    and stat.S_IMODE(metadata.st_mode) == 0o600, "passfile-permission-policy")
    except (OSError, UnicodeError, GateError):
        if created:
            remove_private_passfile(path)
        raise GateError("passfile-create-failed") from None


def remove_private_passfile(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
        require(not path.exists() and not path.is_symlink(), "passfile-cleanup-failed")
    except OSError:
        raise GateError("passfile-cleanup-failed") from None


def require_no_extra_sockets_or_devices() -> None:
    """Reject nonstandard open socket/device descriptors in the client process."""
    try:
        with os.scandir("/proc/self/fd") as descriptors:
            for descriptor in descriptors:
                if not descriptor.name.isdecimal() or int(descriptor.name) <= 2:
                    continue
                mode = descriptor.stat(follow_symlinks=True).st_mode
                require(not (stat.S_ISSOCK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode)),
                        "test-user-socket-or-device-descriptor")
    except OSError:
        raise GateError("test-user-descriptor-state-unverifiable") from None


def verify_rootfs_library_path() -> None:
    """Keep dynamic-loader search directories inside the staged public runtime."""
    value = os.environ.get("LD_LIBRARY_PATH", "")
    directories = value.split(":")
    require(bool(value) and all(directories) and directories == sorted(set(directories)),
            "test-rootfs-library-path-invalid")
    roots = tuple(Path(path) for path in (
        "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib",
        "/usr/local/lib64", "/usr/lib/postgresql/16",
    ))
    try:
        allowed_roots = tuple(root.resolve(strict=True) for root in roots if root.exists())
    except OSError:
        raise GateError("test-rootfs-library-path-invalid") from None
    for value in directories:
        directory = Path(value)
        require(directory.is_absolute() and "." not in directory.parts
                and ".." not in directory.parts and directory.is_dir()
                and not directory.is_symlink(), "test-rootfs-library-path-invalid")
        try:
            resolved = directory.resolve(strict=True)
            require(any(resolved == root or root in resolved.parents for root in allowed_roots),
                    "test-rootfs-library-path-invalid")
        except OSError:
            raise GateError("test-rootfs-library-path-invalid") from None


def require_test_user_runtime_guard() -> None:
    """Fail closed in the client process without discovering admin tools."""
    require(set(os.environ) == CLIENT_ENV_KEYS, "test-user-environment-not-sanitized")
    require(all(key not in os.environ for key in REMOTE_OR_AUTH_ENV)
            and not credential_env_names(os.environ),
            "test-user-credential-environment-present")
    require(os.environ.get("STATEKIT_TOOL_ALLOWLIST") == "psql",
            "test-user-tool-allowlist-invalid")
    require(os.environ.get("PATH") == os.environ.get("STATEKIT_PG_BINDIR"),
            "test-user-path-not-allowlisted")
    require(os.environ.get("STATEKIT_NO_SUDO_AUTHORIZATION") == "verified",
            "test-user-sudo-policy-unverified")
    require(os.environ.get("STATEKIT_ROOTFS_RUNTIME") in ("0", "1"),
            "test-rootfs-runtime-mode-invalid")
    require(os.environ.get("STATEKIT_ROOTFS_ROLE") in ("build", "mock", "live", "fetch"),
            "test-rootfs-role-invalid")
    verify_rootfs_library_path()
    require_no_extra_sockets_or_devices()
    verify_rootfs_manifest_digest()
    try:
        expected_uid = int(os.environ["STATEKIT_TEST_UID"])
        expected_gid = int(os.environ["STATEKIT_TEST_GID"])
    except (KeyError, ValueError):
        raise GateError("test-user-identity-unverifiable") from None
    state = process_privilege_state()
    require(
        expected_uid > 0 and state["uid"] == expected_uid and state["euid"] == expected_uid
        and state["gid"] == expected_gid and state["egid"] == expected_gid
        and state["groups"] in ((), (expected_gid,))
        and state["no_new_privs"] == 1,
        "test-user-privilege-policy-failed",
    )
    require_zero_effective_capabilities(state)


def require_rootless_container_privileges() -> None:
    """Verify effective UID, groups, NNP, and CapBnd before offline code runs."""
    try:
        expected_uid = int(os.environ["STATEKIT_TEST_UID"])
        expected_gid = int(os.environ["STATEKIT_TEST_GID"])
    except (KeyError, ValueError):
        raise GateError("test-user-identity-unverifiable") from None
    require(not credential_env_names(os.environ)
            and all(not os.environ.get(key) for key in REMOTE_OR_AUTH_ENV),
            "test-user-credential-environment-present")
    verify_rootfs_library_path()
    require_no_extra_sockets_or_devices()
    verify_rootfs_manifest_digest()
    state = process_privilege_state()
    require(
        expected_uid > 0 and state["uid"] == expected_uid and state["euid"] == expected_uid
        and state["gid"] == expected_gid and state["egid"] == expected_gid
        and state["groups"] in ((), (expected_gid,))
        and state["no_new_privs"] == 1,
        "test-user-privilege-policy-failed",
    )
    require_zero_effective_capabilities(state)


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def verify_test_source_read_only() -> None:
    """Check every checkout path is non-writable by this dedicated UID."""
    require(ROOT.is_dir() and not ROOT.is_symlink(), "source-tree-unavailable")
    try:
        if os.statvfs(ROOT).f_flag & os.ST_RDONLY:
            return
    except OSError:
        raise GateError("source-read-only-preflight-failed") from None
    pending = [ROOT]
    try:
        while pending:
            directory = pending.pop()
            require(not os.access(directory, os.W_OK, effective_ids=True),
                    "source-tree-not-read-only")
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    if entry.name == ".git" and entry.is_dir(follow_symlinks=False):
                        continue
                    require(not os.access(path, os.W_OK, effective_ids=True),
                            "source-tree-not-read-only")
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
    except (OSError, PermissionError):
        raise GateError("source-read-only-preflight-failed") from None


def verify_test_workspace() -> None:
    """Verify the host scratch workspace or private in-container tmpfs."""
    workspace = Path(os.environ.get("STATEKIT_PG_WORKSPACE", "/missing"))
    in_rootfs = os.environ.get("STATEKIT_ROOTFS_RUNTIME") == "1"
    expected_parent = Path("/tmp") if in_rootfs else Path("/dev/shm")
    require(workspace.parent == expected_parent and not expected_parent.is_symlink(),
            "test-workspace-location-invalid")
    match = re.fullmatch(r"statekit-pg-([0-9a-f]{20})\.[A-Za-z0-9]{8}", workspace.name)
    require(match is not None and workspace.is_dir() and not workspace.is_symlink(),
            "test-workspace-identity-invalid")
    nonce = match.group(1)
    try:
        workspace_stat = workspace.lstat()
        workspace_uid = int(os.environ["STATEKIT_WORKSPACE_UID"])
        test_uid = int(os.environ["STATEKIT_TEST_UID"])
        test_gid = int(os.environ["STATEKIT_TEST_GID"])
    except (OSError, KeyError, ValueError):
        raise GateError("test-workspace-identity-invalid") from None
    require(workspace_stat.st_uid == workspace_uid
            and stat.S_IMODE(workspace_stat.st_mode) == (0o700 if in_rootfs else 0o750),
            "test-workspace-owner-or-mode-invalid")
    require(os.environ.get("STATEKIT_PG_DATABASE") == f"statekit_pg_{nonce}"
            and os.environ.get("STATEKIT_PG_USER") == f"statekit_user_{nonce}",
            "test-workspace-resource-identity-mismatch")

    run_dir = workspace / "run"
    expected_paths = {
        "HOME": run_dir / "home", "TMPDIR": run_dir / "tmp",
        "GOCACHE": run_dir / "gocache", "GOMODCACHE": run_dir / "gomodcache",
    }
    if in_rootfs:
        expected_paths["STATEKIT_BIN"] = Path("/artifact/statekit")
        expected_paths["STATEKIT_REPORT_PATH"] = Path("/out/report.txt")
    else:
        expected_paths["STATEKIT_BIN"] = run_dir / "statekit"
        expected_paths["STATEKIT_REPORT_PATH"] = run_dir / "report.txt"
    expected_paths["STATEKIT_PG_PASSFILE"] = workspace / ".pgpass"
    for key, expected in expected_paths.items():
        actual = Path(os.environ.get(key, "/missing"))
        require(actual == expected, "test-writable-path-outside-workspace")
        if not (in_rootfs and key in ("STATEKIT_BIN", "STATEKIT_REPORT_PATH")):
            require(_path_is_within(actual, workspace), "test-writable-path-outside-workspace")
    for path in (run_dir, run_dir / "home", run_dir / "tmp",
                 run_dir / "gocache", run_dir / "gomodcache"):
        try:
            metadata = path.lstat()
        except OSError:
            raise GateError("test-workspace-directory-unavailable") from None
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == test_uid
                and metadata.st_gid == test_gid and stat.S_IMODE(metadata.st_mode) == 0o700,
                "test-workspace-directory-policy")

    passfile = Path(os.environ["STATEKIT_PG_PASSFILE"])
    try:
        metadata = passfile.lstat()
    except OSError:
        raise GateError("passfile-unavailable") from None
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == test_uid
            and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o600,
            "passfile-permission-policy")
    if in_rootfs:
        binary = Path(os.environ["STATEKIT_BIN"])
        try:
            binary_metadata = binary.lstat()
        except OSError:
            raise GateError("production-binary-artifact-invalid") from None
        require(binary == Path("/artifact/statekit") and stat.S_ISREG(binary_metadata.st_mode)
                and binary_metadata.st_nlink == 1
                and not stat.S_IMODE(binary_metadata.st_mode) & 0o222
                and os.access(binary, os.X_OK)
                and not os.access(binary, os.W_OK, effective_ids=True),
                "production-binary-artifact-invalid")
        output_dir = Path("/out")
        try:
            output_metadata = output_dir.lstat()
        except OSError:
            raise GateError("report-output-directory-invalid") from None
        require(stat.S_ISDIR(output_metadata.st_mode) and output_metadata.st_uid == test_uid
                and output_metadata.st_gid == test_gid
                and stat.S_IMODE(output_metadata.st_mode) == 0o700
                and not Path(os.environ["STATEKIT_REPORT_PATH"]).exists()
                and not Path(os.environ["STATEKIT_REPORT_PATH"]).is_symlink(),
                "report-output-directory-invalid")

    try:
        pending = [workspace]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    metadata = path.lstat()
                    require(not stat.S_ISLNK(metadata.st_mode)
                            and (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode))
                            and metadata.st_uid in (workspace_uid, test_uid)
                            and not stat.S_IMODE(metadata.st_mode) & 0o022,
                            "test-workspace-node-policy")
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(path)
    except OSError:
        raise GateError("test-workspace-inspection-failed") from None


def require_test_user_preflight() -> None:
    """Preflight the non-sudo client without probing runner-admin commands."""
    require_test_user_runtime_guard()
    if os.environ.get("STATEKIT_ROOTFS_RUNTIME") == "1":
        verify_rootfs_runtime_manifest()
    else:
        verify_test_source_read_only()
    verify_test_workspace()


def parse_json_result(result: "Result", expected: object, dispatch: bool = True) -> None:
    """Require the real production command and exact typed JSON, not markers alone."""
    markers = (PROBE_DISPATCHED if dispatch else PROBE_NOT_DISPATCHED, PROBE_COMPLETED)
    lines = result.stderr.decode("utf-8", errors="replace").splitlines()
    require(len(lines) >= 2 and tuple(lines[-2:]) == markers, "missing-production-proof")
    require(result.returncode == 0 and len(lines) == 2, "statekit-result-exit")
    try:
        actual = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise GateError("statekit-result-json") from None
    require(type(actual) is type(expected) and actual == expected, "statekit-result-shape")


def parse_failure(result: "Result", category: str, dispatch: bool) -> None:
    markers = (PROBE_DISPATCHED if dispatch else PROBE_NOT_DISPATCHED, PROBE_COMPLETED)
    lines = result.stderr.decode("utf-8", errors="replace").splitlines()
    require(tuple(lines[-2:]) == markers and result.returncode == 1, "statekit-failure-exit")
    require(not result.stdout and len(lines) == 3, "partial-result-or-mixed-error")
    require(lines[0] == category, "statekit-failure-classification")


class Result:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _limit_child_resources() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_CAPTURE, MAX_CAPTURE))


def bounded_process(
    argv: list[str], *, input_data: bytes | None, env: dict[str, str],
    timeout: int, temp_dir: Path,
) -> Result:
    """Run a local child with bounded wall time, CPU, and captured regular files."""
    require(all(isinstance(arg, str) and "\x00" not in arg for arg in argv),
            "invalid-process-arguments")
    try:
        with tempfile.TemporaryFile(dir=temp_dir) as stdout_file, tempfile.TemporaryFile(dir=temp_dir) as stderr_file:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=env,
                close_fds=True,
                preexec_fn=_limit_child_resources,
            )
            try:
                process.communicate(input=input_data, timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise GateError("client-timeout") from None
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(MAX_CAPTURE + 1)
            stderr = stderr_file.read(MAX_CAPTURE + 1)
    except GateError:
        raise
    except (OSError, subprocess.SubprocessError):
        raise GateError("client-process-failed") from None
    require(len(stdout) <= MAX_CAPTURE and len(stderr) <= MAX_CAPTURE,
            "client-output-limit")
    return Result(process.returncode, stdout, stderr)


class Gate:
    def __init__(self, binary: Path, report: Path = REPORT) -> None:
        require_test_user_preflight()
        self.binary = binary
        self.report = report
        self.db = os.environ.get("STATEKIT_PG_DATABASE", "")
        self.user = os.environ.get("STATEKIT_PG_USER", "")
        self.passfile = Path(os.environ.get("STATEKIT_PG_PASSFILE", "/missing"))
        self.pg_bindir = os.environ.get("STATEKIT_PG_BINDIR", "")
        self.psql_bin = os.environ.get("STATEKIT_PSQL_BIN", "")
        self.temp_dir = Path(os.environ.get("TMPDIR", "/missing"))
        self.home = os.environ.get("HOME", "")
        require(re.fullmatch(r"statekit_pg_[0-9a-f]{20}", self.db) is not None,
                "database-identity-invalid")
        require(re.fullmatch(r"statekit_user_[0-9a-f]{20}", self.user) is not None,
                "database-role-identity-invalid")
        require(self.binary.is_file() and not self.binary.is_symlink()
                and os.access(self.binary, os.X_OK), "production-binary-unavailable")
        require(self.passfile.is_file() and not self.passfile.is_symlink(),
                "passfile-unavailable")
        pass_stat = self.passfile.stat()
        require(stat.S_IMODE(pass_stat.st_mode) == 0o600
                and pass_stat.st_uid == os.geteuid() and pass_stat.st_nlink == 1,
                "passfile-permission-policy")
        require(self.temp_dir.is_dir() and not self.temp_dir.is_symlink()
                and self.temp_dir.stat().st_uid == os.geteuid()
                and stat.S_IMODE(self.temp_dir.stat().st_mode) & 0o077 == 0,
                "temporary-directory-policy")
        require(Path(self.pg_bindir).is_dir() and not Path(self.pg_bindir).is_symlink(),
                "postgres-client-path-invalid")
        require(Path(self.psql_bin).is_file() and not Path(self.psql_bin).is_symlink()
                and Path(self.psql_bin).resolve().parent == Path(self.pg_bindir).resolve()
                and os.access(self.psql_bin, os.X_OK),
                "postgres-client-unavailable")
        require(postgres_tool_version(output_for([self.psql_bin, "--version"])) == POSTGRES_VERSION,
                "postgres-tool-version-mismatch")
        self.password = self._read_password()
        self.bad_password = secrets.token_hex(24)
        self.results: list[tuple[str, str]] = []
        self.sequence = 0
        self.cleanup_ok = True
        self.db_verified_absent = False
        self.execution_complete = False
        self._temporary_passfiles: set[Path] = set()

    def _read_password(self) -> str:
        try:
            contents = self.passfile.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise GateError("passfile-unavailable") from None
        lines = contents.split("\n")
        require(len(lines) == 2 and lines[1] == "" and "\r" not in contents,
                "passfile-format-invalid")
        fields = [""]
        escaped = False
        for character in lines[0]:
            if escaped:
                require(character in (":", "\\"), "passfile-format-invalid")
                fields[-1] += character
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == ":":
                fields.append("")
            else:
                fields[-1] += character
        require(
            len(fields) == 5 and fields[:4] == ["127.0.0.1", "5432", "*", self.user]
            and bool(fields[4]) and "\0" not in fields[4] and not escaped,
            "passfile-format-invalid",
        )
        return fields[4]

    def _base_env(self, passfile: Path | None = None) -> dict[str, str]:
        return {
            "PATH": self.pg_bindir,
            "LD_LIBRARY_PATH": os.environ["LD_LIBRARY_PATH"],
            "HOME": self.home,
            "TMPDIR": str(self.temp_dir),
            "LC_ALL": "C",
            "GOENV": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOPROXY": "off",
            "GOSUMDB": "sum.golang.org",
            "GOPRIVATE": "",
            "GONOPROXY": "",
            "GONOSUMDB": "",
            "CGO_ENABLED": "0",
            "PGPASSFILE": str(passfile or self.passfile),
            "PGCONNECT_TIMEOUT": "5",
            "PGSSLMODE": "disable",
        }

    def _new_passfile(self, password: str) -> Path:
        path = self.temp_dir / f"pgpass-{secrets.token_hex(8)}"
        create_private_passfile(path, self.user, password)
        self._temporary_passfiles.add(path)
        return path

    def native(
        self, sql: str, *, database: str | None = None,
        host: str = "127.0.0.1", port: str = "5432", bad_auth: bool = False,
    ) -> Result:
        require_test_user_runtime_guard()
        require(host == "127.0.0.1" and port in ("5432", "5433"),
                "native-endpoint-invalid")
        target_db = database or self.db
        require(target_db in (self.db, "postgres"), "native-database-invalid")
        passfile = self._new_passfile(self.bad_password) if bad_auth else self.passfile
        env = self._base_env(passfile)
        try:
            return bounded_process(
                [
                    self.psql_bin, "--no-psqlrc", "--no-password", "--host", host,
                    "--port", port, "--username", self.user, "--dbname", target_db,
                    "--set=ON_ERROR_STOP=on", "--set=VERBOSITY=sqlstate",
                    "--tuples-only", "--no-align", "--file", "-",
                ],
                input_data=sql.encode("utf-8"), env=env, timeout=40, temp_dir=self.temp_dir,
            )
        finally:
            if bad_auth:
                try:
                    passfile.unlink(missing_ok=True)
                    require(not passfile.exists() and not passfile.is_symlink(),
                            "temporary-passfile-cleanup-failed")
                    self._temporary_passfiles.discard(passfile)
                except OSError:
                    raise GateError("temporary-passfile-cleanup-failed") from None

    def native_equals(self, sql: str, expected: str, **kwargs: object) -> None:
        result = self.native(sql, **kwargs)
        require(
            result.returncode == 0 and result.stdout.decode("utf-8").strip() == expected
            and not result.stderr,
            "native-postcondition",
        )

    def statekit(
        self, sql: str, *, write: bool = False, port: str = "5432",
        password: str | None = None,
    ) -> Result:
        require_test_user_runtime_guard()
        request = {
            "query": sql, "user": self.user, "host": "127.0.0.1", "port": port,
            "maintenance_db": self.db, "password": password or self.password,
            "write": write,
        }
        data = json.dumps(request, separators=(",", ":")).encode("utf-8")
        with tempfile.TemporaryDirectory(prefix="statekit-postgres-call-", dir=self.temp_dir) as directory:
            call_dir = Path(directory)
            wrapper_dir = call_dir / "bin"
            wrapper_dir.mkdir(mode=0o700)
            marker = call_dir / "psql-dispatch"
            probe = ROOT / "tests/live/postgres/psql-probe.sh"
            wrapper = wrapper_dir / "psql"
            wrapper.write_text(
                "#!/bin/sh\n"
                f"STATEKIT_PSQL_DISPATCH_MARKER={shlex.quote(str(marker))}\n"
                f"STATEKIT_PSQL_BINARY={shlex.quote(self.psql_bin)}\n"
                "export STATEKIT_PSQL_DISPATCH_MARKER STATEKIT_PSQL_BINARY\n"
                f"exec /bin/sh {shlex.quote(str(probe))} \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            env = self._base_env()
            env["PATH"] = f"{wrapper_dir}:{env['PATH']}"
            result = bounded_process(
                [str(self.binary), "exec", "postgres.psql_query", "--stdin", "--output", "json"],
                input_data=data, env=env, timeout=65, temp_dir=self.temp_dir,
            )
            dispatched = False
            if marker.exists() and not marker.is_symlink():
                try:
                    dispatched = marker.read_bytes() == b"called\n"
                except OSError:
                    raise GateError("dispatch-probe-unreadable") from None
            marks = (PROBE_DISPATCHED if dispatched else PROBE_NOT_DISPATCHED)
            stderr = result.stderr
            if stderr and not stderr.endswith(b"\n"):
                stderr += b"\n"
            result.stderr = stderr + f"{marks}\n{PROBE_COMPLETED}\n".encode()
            return result

    def verify_server(self) -> None:
        self.native_equals(
            "SELECT current_setting('server_version_num')::int / 10000 || '|' || "
            "inet_server_addr()::text || '|' || inet_server_port()::text",
            "16|127.0.0.1|5432",
        )
        self.native_equals(
            "SELECT CASE WHEN rolsuper OR rolcreatedb OR rolcreaterole "
            "THEN 'privileged' ELSE 'least-privilege' END FROM pg_roles "
            "WHERE rolname = current_user",
            "least-privilege",
        )
        version = self.native("SELECT current_setting('server_version_num')::int / 10000")
        require(version.returncode == 0 and version.stdout.strip() == b"16",
                "postgres-major-version-mismatch")

    def case(self, case_id: str) -> None:
        if case_id == CASE_IDS[0]:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                try:
                    self.native_equals("SELECT 1", "1")
                    return
                except GateError:
                    time.sleep(2)
            raise GateError("postgres-readiness-timeout")
        if case_id == CASE_IDS[1]:
            parse_json_result(self.statekit("SELECT 7 AS value"), [{"value": "7"}])
        elif case_id == CASE_IDS[2]:
            self.native_equals("SELECT 7 AS value", "7")
        elif case_id == CASE_IDS[3]:
            parse_json_result(self.statekit(MULTILINE_SQL), [{"id": "1", "note": MULTILINE}])
        elif case_id == CASE_IDS[4]:
            self.native_equals(NATIVE_MULTILINE_HEX_SQL, MULTILINE.encode().hex())
        elif case_id == CASE_IDS[5]:
            parse_json_result(self.statekit("SELECT 7 AS value WHERE false"), [])
        elif case_id == CASE_IDS[6]:
            parse_json_result(self.statekit(INSERT_SQL, write=False), [{"id": "1", "note": "start"}])
        elif case_id == CASE_IDS[7]:
            self.native_equals("SELECT note FROM observations WHERE id=1", "start")
        elif case_id == CASE_IDS[8]:
            parse_json_result(self.statekit(UPDATE_SQL, write=True), [{"id": "1", "note": "committed"}])
        elif case_id == CASE_IDS[9]:
            self.native_equals("SELECT note FROM observations WHERE id=1", "committed")
        elif case_id == CASE_IDS[10]:
            parse_json_result(self.statekit(EMPTY_UPDATE_SQL, write=True), [])
        elif case_id == CASE_IDS[11]:
            parse_json_result(self.statekit("THIS IS NOT VALID SQL", write=True), [])
        elif case_id == CASE_IDS[12]:
            result = self.native("THIS IS NOT VALID SQL")
            require(result.returncode == 3 and not result.stdout and b"42601" in result.stderr,
                    "native-syntax-classification")
        elif case_id == CASE_IDS[13]:
            parse_json_result(self.statekit("SELECT 1", password=self.bad_password), [])
        elif case_id == CASE_IDS[14]:
            result = self.native("SELECT 1", bad_auth=True)
            marker = f'password authentication failed for user "{self.user}"'.encode()
            require(
                result.returncode != 0 and not result.stdout and marker in result.stderr
                and b"Connection refused" not in result.stderr,
                "native-auth-classification",
            )
        elif case_id == CASE_IDS[15]:
            parse_json_result(self.statekit("SELECT 1", port="5433"), [])
        elif case_id == CASE_IDS[16]:
            result = self.native("SELECT 1", port="5433")
            require(result.returncode != 0 and not result.stdout
                    and b"Connection refused" in result.stderr and b"28P01" not in result.stderr,
                    "native-connection-classification")
        elif case_id == CASE_IDS[17]:
            parse_failure(self.statekit(OVERSIZE_SQL),
                          "statekit: runtime: command input exceeds limit", dispatch=False)
        elif case_id == CASE_IDS[18]:
            parse_failure(self.statekit("SELECT repeat('x', 5000000) AS value"),
                          "statekit: process: output limit exceeded", dispatch=True)
        elif case_id == CASE_IDS[19]:
            self.drop_database()
        else:
            raise GateError("unknown-case-id")

    def drop_database(self) -> None:
        require(re.fullmatch(r"statekit_pg_[0-9a-f]{20}", self.db) is not None,
                "database-ownership-unverifiable")
        result = self.native(f"DROP DATABASE {self.db}", database="postgres")
        require(result.returncode == 0 and not result.stderr, "database-drop-failed")
        self.native_equals(
            f"SELECT COUNT(*) FROM pg_database WHERE datname='{self.db}'",
            "0", database="postgres",
        )
        self.db_verified_absent = True

    def run_cases(self) -> None:
        require(not self.results, "case-inventory-integrity")
        for index, case_id in enumerate(CASE_IDS):
            try:
                if index == 1:
                    result = self.native("CREATE TABLE observations (id integer PRIMARY KEY, note text)")
                    require(result.returncode == 0 and not result.stderr,
                            "disposable-table-setup-failed")
                self.case(case_id)
                self.results.append((case_id, "pass"))
            except GateError:
                self.results.append((case_id, "fail"))
        self.execution_complete = True

    def cleanup(self) -> None:
        require_test_user_runtime_guard()
        if not self.db_verified_absent:
            try:
                self.drop_database()
            except GateError:
                self.cleanup_ok = False
        for path in tuple(self._temporary_passfiles):
            try:
                path.unlink(missing_ok=True)
                require(not path.exists() and not path.is_symlink(), "passfile-cleanup-failed")
            except (OSError, GateError):
                self.cleanup_ok = False
        self._temporary_passfiles.clear()
        self.password = ""
        self.bad_password = ""
        self.cleanup_ok = self.cleanup_ok and self.db_verified_absent

    def report_contents(self) -> tuple[bool, str]:
        valid = (
            len(self.results) == len(CASE_IDS)
            and tuple(case_id for case_id, _ in self.results) == CASE_IDS
            and all(result in ("pass", "fail") for _, result in self.results)
        )
        passed = sum(result == "pass" for _, result in self.results)
        failed = sum(result == "fail" for _, result in self.results)
        success = bool(
            valid and self.execution_complete and self.cleanup_ok
            and passed == len(CASE_IDS) and failed == 0
        )
        lines = [
            "schema: postgres-live-v1",
            "source: ubuntu-24.04-runner-bundled-postgresql",
            "postgres_major: 16",
            f"postgres_version: {POSTGRES_VERSION}",
            f"cases_total: {len(CASE_IDS)}", f"cases_passed: {passed}",
            f"cases_failed: {failed}", "cases_skipped: 0",
            f"status: {'pass' if success else 'fail'}",
            f"execution: {'complete' if self.execution_complete else 'incomplete'}",
            f"cleanup: {'pass' if self.cleanup_ok else 'fail'}",
            "scope: production postgres.psql_query and independent native psql against an owned disposable database",
            "write_false: not read-only; INSERT RETURNING persists and is independently observed",
            "egress: per-test-user IPv4/IPv6 OUTPUT chains are installed and structurally verified; only loopback PostgreSQL 5432 is accepted, with IPv6 loopback allowed only when the service binds it, and the dependency fetch allows only pinned proxy/sum/storage addresses over TCP/443 plus the exact loopback resolver; all other egress defaults to DROP; no independent external probe is performed",
            "external_ci: this_run",
            "limitations: no live Salt differential parity; local mock tests are not live evidence; runner image may change and the job fails closed unless PostgreSQL tools are exactly 16.15; project build and tests run in a rootless manifest-closed rootfs while the main-only controller remains trusted; runner loss can prevent cleanup or report publication",
        ]
        lines.extend(f"case: {case_id}={result}" for case_id, result in self.results)
        return success, "\n".join(lines) + "\n"

    def write_report(self) -> bool:
        require_test_user_runtime_guard()
        success, contents = self.report_contents()
        require(not self.report.parent.is_symlink(), "unsafe-report-path")
        require(not self.report.exists() and not self.report.is_symlink(), "stale-report-rejected")
        self.report.parent.mkdir(parents=True, exist_ok=True)
        require(not self.report.parent.is_symlink(), "unsafe-report-path")
        try:
            fd = os.open(
                self.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0), 0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(contents)
                output.flush()
                os.fsync(output.fileno())
        except OSError:
            raise GateError("report-write-failed") from None
        return success


def initialize_rootfs_workspace() -> Path:
    """Create bounded writable state on the container's private tmpfs only."""
    require(os.environ.get("STATEKIT_ROOTFS_RUNTIME") == "1",
            "rootfs-runtime-not-enabled")
    require_rootless_container_privileges()
    verify_rootfs_runtime_manifest()
    if "container" in os.environ:
        require(os.environ.get("container") == "podman", "test-rootfs-runtime-mode-invalid")
        os.environ.pop("container")
    if "HOSTNAME" in os.environ:
        require(re.fullmatch(r"[0-9a-f]{12}", os.environ["HOSTNAME"]) is not None,
                "test-rootfs-runtime-mode-invalid")
        os.environ.pop("HOSTNAME")
    database = os.environ.get("STATEKIT_PG_DATABASE", "")
    role = os.environ.get("STATEKIT_PG_USER", "")
    match = re.fullmatch(r"statekit_pg_([0-9a-f]{20})", database)
    require(match is not None and role == f"statekit_user_{match.group(1)}",
            "database-identity-invalid")
    try:
        expected_uid = int(os.environ["STATEKIT_TEST_UID"])
        expected_gid = int(os.environ["STATEKIT_TEST_GID"])
    except (KeyError, ValueError):
        raise GateError("test-user-identity-unverifiable") from None
    require(os.getuid() == expected_uid == os.geteuid()
            and os.getgid() == expected_gid == os.getegid()
            and not os.getgroups(), "test-user-identity-unverifiable")
    scratch = Path("/tmp")
    require(scratch.is_dir() and not scratch.is_symlink(), "test-workspace-location-invalid")
    workspace = scratch / f"statekit-pg-{match.group(1)}.{secrets.token_hex(4)}"
    try:
        workspace.mkdir(mode=0o700)
        run_dir = workspace / "run"
        run_dir.mkdir(mode=0o700)
        for name in ("home", "tmp", "gocache", "gomodcache"):
            (run_dir / name).mkdir(mode=0o700)
        os.chmod(workspace, 0o700)
        os.chmod(run_dir, 0o700)
    except OSError:
        raise GateError("test-workspace-creation-failed") from None
    os.environ.update({
        "PATH": "/usr/lib/postgresql/16/bin",
        "HOME": str(run_dir / "home"), "TMPDIR": str(run_dir / "tmp"),
            "GOCACHE": str(run_dir / "gocache"),
            "GOMODCACHE": str(run_dir / "gomodcache"),
            "LD_LIBRARY_PATH": os.environ.get("LD_LIBRARY_PATH", ""),
        "LC_ALL": "C", "GOENV": "off", "GOTOOLCHAIN": "local",
        "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "sum.golang.org",
        "GOPRIVATE": "", "GONOPROXY": "", "GONOSUMDB": "", "CGO_ENABLED": "0",
        "STATEKIT_BIN": "/artifact/statekit",
        "STATEKIT_REPORT_PATH": "/out/report.txt",
        "STATEKIT_PG_PASSFILE": str(workspace / ".pgpass"),
        "STATEKIT_PG_BINDIR": "/usr/lib/postgresql/16/bin",
        "STATEKIT_PSQL_BIN": "/usr/lib/postgresql/16/bin/psql",
        "STATEKIT_PG_WORKSPACE": str(workspace),
        "STATEKIT_WORKSPACE_UID": str(expected_uid),
        "STATEKIT_TEST_UID": str(expected_uid), "STATEKIT_TEST_GID": str(expected_gid),
        "STATEKIT_TOOL_ALLOWLIST": "psql",
        "STATEKIT_NO_SUDO_AUTHORIZATION": "verified",
    })
    passfile = workspace / ".pgpass"
    try:
        try:
            password = read_credential_envelope(sys.stdin.buffer)
        finally:
            sys.stdin.close()
        create_private_passfile(passfile, role, password)
        password = ""
        return passfile
    except (GateError, KeyboardInterrupt):
        remove_private_passfile(passfile)
        raise


def validate_report(path: Path) -> bool:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 << 10:
            return False
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    lines = text.splitlines()
    if len(lines) != 16 + len(CASE_IDS):
        return False
    expected_prefix = [
        "schema: postgres-live-v1",
        "source: ubuntu-24.04-runner-bundled-postgresql",
        "postgres_major: 16",
        f"postgres_version: {POSTGRES_VERSION}",
        "cases_total: 20",
        "cases_passed: 20",
        "cases_failed: 0",
        "cases_skipped: 0",
        "status: pass",
        "execution: complete",
        "cleanup: pass",
        "scope: production postgres.psql_query and independent native psql against an owned disposable database",
        "write_false: not read-only; INSERT RETURNING persists and is independently observed",
        "egress: per-test-user IPv4/IPv6 OUTPUT chains are installed and structurally verified; only loopback PostgreSQL 5432 is accepted, with IPv6 loopback allowed only when the service binds it, and the dependency fetch allows only pinned proxy/sum/storage addresses over TCP/443 plus the exact loopback resolver; all other egress defaults to DROP; no independent external probe is performed",
        "external_ci: this_run",
        "limitations: no live Salt differential parity; local mock tests are not live evidence; runner image may change and the job fails closed unless PostgreSQL tools are exactly 16.15; project build and tests run in a rootless manifest-closed rootfs while the main-only controller remains trusted; runner loss can prevent cleanup or report publication",
    ]
    # Sixteen fixed fields plus exactly twenty ordered, all-pass case records.
    return lines[:16] == expected_prefix and lines[16:] == [
        f"case: {case_id}=pass" for case_id in CASE_IDS
    ]


def main() -> int:
    args = sys.argv[1:]
    if args == ["--list-cases"]:
        print("\n".join(CASE_IDS))
        return 0
    if args == ["--assert-container-privileges"]:
        require_rootless_container_privileges()
        return 0
    if len(args) == 2 and args[0] == "--validate-report":
        return 0 if validate_report(Path(args[1])) else 1
    require(args in ([], ["--run-cases"], ["--preflight-only"], ["--verify-server"],
                     ["--cluster-state"], ["--assert-cluster-down"]), "invalid-arguments")
    if args in (["--preflight-only"], ["--verify-server"],
                ["--cluster-state"], ["--assert-cluster-down"]):
        require_live_preflight()
        tools = require_runner_toolchain()
        if args == ["--preflight-only"]:
            return 0
        if args == ["--cluster-state"]:
            print(tools["pg_cluster_status"])
            return 0
        if args == ["--assert-cluster-down"]:
            require(tools["pg_cluster_status"] == "down", "postgres-cluster-still-running")
            return 0
        try:
            snapshot_bytes = sys.stdin.buffer.read((1 << 20) + 1)
            require(len(snapshot_bytes) <= 1 << 20,
                    "postgres-process-snapshot-unverifiable")
            snapshot = json.loads(snapshot_bytes.decode("utf-8", errors="strict"))
        except (OSError, ValueError, TypeError):
            raise GateError("postgres-process-snapshot-unverifiable") from None
        require(isinstance(snapshot, dict), "postgres-process-snapshot-unverifiable")
        verify_server_process(tools, snapshot)
        return 0

    if os.environ.get("STATEKIT_ROOTFS_RUNTIME") == "1":
        require(args == ["--run-cases"], "invalid-arguments")
        passfile = None
        try:
            passfile = initialize_rootfs_workspace()
            return run_payload_cases()
        finally:
            if passfile is not None:
                remove_private_passfile(passfile)
    require(args == [], "invalid-arguments")
    return run_payload_cases()


def run_payload_cases() -> int:
    binary = Path(os.environ.get("STATEKIT_BIN", ROOT / "dist/statekit"))
    report = Path(os.environ.get("STATEKIT_REPORT_PATH", REPORT))
    require(not report.parent.is_symlink() and not report.exists() and not report.is_symlink(),
            "unsafe-or-stale-report")
    gate = Gate(binary, report=report)
    try:
        gate.verify_server()
        version = bounded_process(
            [str(binary), "version", "--output", "json"], input_data=None,
            env=gate._base_env(), timeout=15, temp_dir=gate.temp_dir,
        )
        require(version.returncode == 0 and bool(version.stdout), "production-binary-version-check-failed")
        gate.run_cases()
    except (GateError, KeyboardInterrupt):
        completed = dict(gate.results)
        gate.results = [(case_id, completed.get(case_id, "fail")) for case_id in CASE_IDS]
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        gate.cleanup()
    if os.environ.get("STATEKIT_ROOTFS_RUNTIME") == "1":
        # The primary native credential must be gone before report creation,
        # not merely left for container destruction. main also covers errors.
        remove_private_passfile(gate.passfile)
    success = gate.write_report()
    if success:
        require(validate_report(report), "postgres-report-validation-failed")
    return 0 if success else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        sys.exit(main())
    except (GateError, KeyboardInterrupt):
        # No external command output, credentials, SQL, or event text is logged.
        sys.exit(1)
    except Exception:
        # Unexpected runtime errors also remain value-free in workflow logs.
        sys.exit(1)
