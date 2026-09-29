"""Value-free static/mock checks; these tests never start PostgreSQL."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import podman_policy
import rootfs as rootfs_builder


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tests/live/postgres/run.py"
VALIDATOR_PATH = ROOT / "tests/live/postgres/validate_report.py"
WORKFLOW = ROOT / ".github/workflows/integration-services.yml"
CI_SCRIPT = ROOT / "tests/live/postgres/ci.sh"
spec = importlib.util.spec_from_file_location("pg_live", MODULE_PATH)
assert spec and spec.loader
pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pg)
validator_spec = importlib.util.spec_from_file_location("pg_report_validator", VALIDATOR_PATH)
assert validator_spec and validator_spec.loader
controller_validator = importlib.util.module_from_spec(validator_spec)
validator_spec.loader.exec_module(controller_validator)

EXPECTED_CASES = (
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
HOSTED = {
    "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "Linux", "GITHUB_REPOSITORY": "friz-zy/statekit",
    "GITHUB_WORKSPACE": str(ROOT),
    "RUNNER_TOOL_CACHE": "/opt/hostedtoolcache",
    "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
}
CLIENT_ENV = {
    "PATH": "/usr/lib/postgresql/16/bin", "HOME": "/dev/shm/statekit-pg-test/home",
    "TMPDIR": "/dev/shm/statekit-pg-test/tmp", "GOCACHE": "/dev/shm/statekit-pg-test/gocache",
    "GOMODCACHE": "/dev/shm/statekit-pg-test/gomodcache", "LC_ALL": "C",
    "LD_LIBRARY_PATH": "/usr/lib64",
    "GOENV": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off",
    "GOSUMDB": "sum.golang.org", "GOPRIVATE": "", "GONOPROXY": "",
    "GONOSUMDB": "", "CGO_ENABLED": "0",
    "STATEKIT_BIN": "/dev/shm/statekit-pg-test/run/statekit",
    "STATEKIT_REPORT_PATH": "/dev/shm/statekit-pg-test/run/report.txt",
    "STATEKIT_PG_DATABASE": "statekit_pg_aaaaaaaaaaaaaaaaaaaa",
    "STATEKIT_PG_USER": "statekit_user_aaaaaaaaaaaaaaaaaaaa",
    "STATEKIT_PG_PASSFILE": "/dev/shm/statekit-pg-test/.pgpass",
    "STATEKIT_PG_BINDIR": "/usr/lib/postgresql/16/bin",
    "STATEKIT_PSQL_BIN": "/usr/lib/postgresql/16/bin/psql",
    "STATEKIT_PG_WORKSPACE": "/dev/shm/statekit-pg-aaaaaaaaaaaaaaaaaaaa.abcdefgh",
    "STATEKIT_WORKSPACE_UID": "1001", "STATEKIT_TEST_UID": "2001",
    "STATEKIT_TEST_GID": "2001", "STATEKIT_TOOL_ALLOWLIST": "psql",
    "STATEKIT_NO_SUDO_AUTHORIZATION": "verified",
    "STATEKIT_ROOTFS_RUNTIME": "0",
    "STATEKIT_ROOTFS_MANIFEST_SHA256": "a" * 64,
    "STATEKIT_ROOTFS_ROLE": "live",
}
TEST_PRIVILEGES = {
    "uid": 2001, "euid": 2001, "gid": 2001, "egid": 2001,
    "groups": (), "no_new_privs": 1, "cap_inh": 0, "cap_prm": 0,
    "cap_eff": 0, "cap_bnd": 0, "cap_amb": 0,
}


def result(value: object, *, rc: int = 0, dispatch: bool = True,
           error: str = "") -> pg.Result:
    marker = pg.PROBE_DISPATCHED if dispatch else pg.PROBE_NOT_DISPATCHED
    stdout = (json.dumps(value) + "\n").encode() if rc == 0 else b""
    stderr = (error + ("\n" if error else "") + marker + "\n" + pg.PROBE_COMPLETED + "\n").encode()
    return pg.Result(rc, stdout, stderr)


def mock_gate() -> pg.Gate:
    gate = object.__new__(pg.Gate)
    gate.db = "statekit_pg_" + "a" * 20
    gate.user = "statekit_user_" + "a" * 20
    gate.password = "mock-correct-password"
    gate.bad_password = "mock-invalid-password"
    gate.results = []
    gate.sequence = 0
    gate.cleanup_ok = True
    gate.db_verified_absent = False
    gate.execution_complete = False
    return gate


class PostgresOrchestrationTests(unittest.TestCase):
    def test_exact_ordered_inventory_without_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--list-cases"], cwd=directory,
                check=True, capture_output=True, text=True,
            )
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(tuple(completed.stdout.splitlines()), EXPECTED_CASES)
        self.assertEqual(tuple(pg.CASE_IDS), EXPECTED_CASES)
        self.assertEqual(len(EXPECTED_CASES), 20)
        self.assertEqual(completed.stderr, "")

    def test_local_and_unknown_entry_points_fail_without_side_effects(self) -> None:
        prefix = CI_SCRIPT.read_text(encoding="utf-8").split("readonly ROOT", 1)[0]
        completed = subprocess.run(["bash", "-c", '''
python3() { [[ "$*" == 'tests/live/postgres/run.py --preflight-only' ]]; }
set -- --preflight-only
''' + prefix + "\nexit 77\n"], capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        with tempfile.TemporaryDirectory() as directory:
            for args in ([], ["--run-cases"], ["--preflight-only"], ["--verify-server"], ["--unknown"]):
                completed = subprocess.run(
                    [sys.executable, str(MODULE_PATH), *args], cwd=directory,
                    env={"PATH": os.environ.get("PATH", "")}, check=False,
                    capture_output=True, text=True,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, "")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_verified_runner_event_and_ref_allowlist(self) -> None:
        for event in ("push", "workflow_dispatch", "schedule"):
            with self.subTest(event=event), mock.patch.dict(os.environ, {
                **HOSTED, "GITHUB_EVENT_NAME": event,
            }, clear=True):
                pg.require_live_preflight()
        pr_env = {
            **HOSTED, "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/pull/42/merge",
        }
        denied = [
            {"GITHUB_ACTIONS": "false"}, {"RUNNER_ENVIRONMENT": "self-hosted"},
            {"RUNNER_OS": "Windows"}, {"GITHUB_REPOSITORY": "other/statekit"},
            {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/42/merge"},
            {"GITHUB_EVENT_NAME": "pull_request_target"},
            {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/dev"},
            {"GITHUB_EVENT_NAME": "schedule", "GITHUB_REF": "refs/heads/dev"},
            {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/tags/main"},
            {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/42/head"},
            {"CONTAINER_HOST": "ssh://example.invalid"}, {"REGISTRY_AUTH_FILE": ""},
            {"GITHUB_TOKEN": ""},
        ]
        for change in denied:
            with self.subTest(change=change), mock.patch.dict(os.environ, {
                **pr_env, **change,
            }, clear=True), self.assertRaises(pg.GateError):
                pg.require_live_preflight()

    def test_runner_toolchain_requires_exact_go_and_postgres_16_15(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bindir = Path(directory) / "pgbin"
            bindir.mkdir()
            postgres = bindir / "postgres"
            psql = bindir / "psql"
            datadir = Path("/var/lib/postgresql/16/main")
            names = (
                "go", "psql", "pg_config", "pg_ctlcluster", "pg_lsclusters", "pg_conftool",
                "iptables", "ip6tables", "ss", "useradd", "userdel", "groupdel",
                "pkill", "pgrep", "getent", "id", "chown", "chmod", "stat", "install",
                "usermod", "mktemp", "timeout", "setpriv", "env", "python3",
                "podman", "ldd", "sha256sum", "bash", "sh",
            )
            outputs = {
                "go_version": "go version go1.26.8 linux/amd64",
                "pg_config_version": "PostgreSQL 16.15",
                "psql_version": "psql (PostgreSQL) 16.15",
                "server_version": "postgres (PostgreSQL) 16.15",
                "--bindir": str(bindir),
                "--no-header": f"16 main 5432 down postgres {datadir} /var/log/postgresql.log",
                "listen_addresses": "listen_addresses = 'localhost'",
                "effective_listen_addresses": "localhost",
            }

            def output_for(argv: list[str], **_kwargs: object) -> str:
                key = argv[-1]
                if argv[0] == "/opt/hostedtoolcache/go/1.26.8/x64/bin/go":
                    return outputs["go_version"]
                if argv[0] == "/usr/bin/pg_config" and key == "--bindir":
                    return outputs["--bindir"]
                if argv[0] == "/usr/bin/pg_config":
                    return outputs["pg_config_version"]
                if argv[0] == str(psql):
                    return outputs["psql_version"]
                if argv[0] == "/usr/bin/pg_lsclusters":
                    return outputs["--no-header"]
                if argv[0] == "/usr/bin/pg_conftool":
                    return outputs["listen_addresses"]
                if argv[0] == "/usr/bin/ss":
                    return ""
                if argv[0] == str(postgres):
                    return outputs["server_version"]
                return outputs["server_version"]

            sbin_names = {"iptables", "ip6tables", "useradd", "usermod", "userdel", "groupdel"}
            which = {
                name: ("/opt/hostedtoolcache/go/1.26.8/x64/bin/go" if name == "go" else
                       f"/usr/sbin/{name}" if name in sbin_names else f"/usr/bin/{name}")
                for name in names
            }
            real_is_file = Path.is_file
            real_is_dir = Path.is_dir
            real_access = os.access

            def is_file(path: Path) -> bool:
                return path in (postgres, psql, Path("/etc/postgresql/16/main/postgresql.conf")) or real_is_file(path)

            def is_dir(path: Path) -> bool:
                return path == datadir or real_is_dir(path)

            def is_executable(path: str | Path, mode: int) -> bool:
                return (path in (str(postgres), str(psql)) and mode == os.X_OK) or real_access(path, mode)

            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.os, "geteuid", return_value=1001),
                  mock.patch.object(pg.shutil, "which", side_effect=lambda name: which.get(name)),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)),
                  mock.patch.object(pg, "output_for", side_effect=output_for),
                  mock.patch.object(Path, "is_file", autospec=True, side_effect=is_file) as is_file_check,
                  mock.patch.object(Path, "is_dir", autospec=True, side_effect=is_dir),
                  mock.patch.object(pg.os, "access", side_effect=is_executable) as executable_check):
                tools = pg.require_runner_toolchain()
            self.assertEqual(tools["pg_bindir"], str(bindir))
            self.assertEqual(tools["psql"], str(psql))
            self.assertEqual(tools["pg_cluster_status"], "down")
            is_file_check.assert_any_call(postgres)
            executable_check.assert_any_call(str(postgres), os.X_OK)
            outputs["go_version"] = "go version go1.26.7 linux/amd64"
            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.os, "geteuid", return_value=1001),
                  mock.patch.object(pg.shutil, "which", side_effect=lambda name: which.get(name)),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)),
                  mock.patch.object(pg, "output_for", side_effect=output_for),
                  self.assertRaisesRegex(pg.GateError, "go-toolchain-version-mismatch")):
                pg.require_runner_toolchain()
            outputs["go_version"] = "go version go1.26.8 linux/amd64"
            outputs["pg_config_version"] = "PostgreSQL 16.16"
            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.os, "geteuid", return_value=1001),
                  mock.patch.object(pg.shutil, "which", side_effect=lambda name: which.get(name)),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)),
                  mock.patch.object(pg, "output_for", side_effect=output_for),
                  mock.patch.object(Path, "is_file", autospec=True, side_effect=is_file),
                  mock.patch.object(Path, "is_dir", autospec=True, side_effect=is_dir),
                  mock.patch.object(pg.os, "access", side_effect=is_executable),
                  self.assertRaisesRegex(pg.GateError, "postgres-tool-version-mismatch")):
                pg.require_runner_toolchain()
            outputs["pg_config_version"] = "PostgreSQL 16.15"
            outputs["psql_version"] = "psql (PostgreSQL) 16.15.1"
            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.os, "geteuid", return_value=1001),
                  mock.patch.object(pg.shutil, "which", side_effect=lambda name: which.get(name)),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)),
                  mock.patch.object(pg, "output_for", side_effect=output_for),
                  mock.patch.object(Path, "is_file", autospec=True, side_effect=is_file),
                  mock.patch.object(Path, "is_dir", autospec=True, side_effect=is_dir),
                  mock.patch.object(pg.os, "access", side_effect=is_executable),
                  self.assertRaisesRegex(pg.GateError, "postgres-tool-version-mismatch")):
                pg.require_runner_toolchain()
            outputs["psql_version"] = "psql (PostgreSQL) 16.15"
            outputs["server_version"] = "postgres (PostgreSQL) 16.14"
            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.os, "geteuid", return_value=1001),
                  mock.patch.object(pg.shutil, "which", side_effect=lambda name: which.get(name)),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)),
                  mock.patch.object(pg, "output_for", side_effect=output_for),
                  mock.patch.object(Path, "is_file", autospec=True, side_effect=is_file),
                  mock.patch.object(Path, "is_dir", autospec=True, side_effect=is_dir),
                  mock.patch.object(pg.os, "access", side_effect=is_executable),
                  self.assertRaisesRegex(pg.GateError, "postgres-tool-version-mismatch")):
                pg.require_runner_toolchain()
            outputs["server_version"] = "postgres (PostgreSQL) 16.15"
            outputs["listen_addresses"] = "listen_addresses = 'localhost'"
            outputs["server_version"] = "postgres (PostgreSQL) 16.15"
            outputs["listen_addresses"] = "listen_addresses = '*'"
            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.os, "geteuid", return_value=1001),
                  mock.patch.object(pg.shutil, "which", side_effect=lambda name: which.get(name)),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)),
                  mock.patch.object(pg, "output_for", side_effect=output_for),
                  mock.patch.object(Path, "is_file", autospec=True, side_effect=is_file),
                  mock.patch.object(Path, "is_dir", autospec=True, side_effect=is_dir),
                  mock.patch.object(pg.os, "access", side_effect=is_executable),
                  self.assertRaisesRegex(pg.GateError, "postgres-listen-config-not-loopback")):
                pg.require_runner_toolchain()
            self.assertIn("sudo_bounded -u postgres", CI_SCRIPT.read_text(encoding="utf-8"))
            self.assertNotIn('tools["sudo"]', MODULE_PATH.read_text(encoding="utf-8"))

    def test_test_user_preflight_checks_identity_caps_nnp_and_no_sudo(self) -> None:
        with (mock.patch.dict(os.environ, CLIENT_ENV, clear=True),
              mock.patch.object(pg, "process_privilege_state", return_value=TEST_PRIVILEGES),
              mock.patch.object(pg, "verify_test_source_read_only"),
              mock.patch.object(pg, "verify_test_workspace"),
              mock.patch.object(pg, "verify_rootfs_manifest_digest"),
              mock.patch.object(pg.shutil, "which", side_effect=AssertionError("tool discovery"))):
            pg.require_test_user_preflight()

        cases = (
            ("uid", 0), ("euid", 0), ("groups", (27,)),
            ("no_new_privs", 0), ("cap_bnd", 1), ("cap_inh", 1),
            ("cap_prm", 1), ("cap_eff", 1), ("cap_amb", 1),
        )
        for key, value in cases:
            with self.subTest(key=key), mock.patch.dict(os.environ, CLIENT_ENV, clear=True), \
                 mock.patch.object(pg, "process_privilege_state", return_value={
                     **TEST_PRIVILEGES, key: value,
                 }), mock.patch.object(pg, "verify_rootfs_manifest_digest"), \
                 self.assertRaises(pg.GateError):
                pg.require_test_user_runtime_guard()
        # An absent capability field is reported as -1 and must fail closed
        # rather than being treated as zero.
        for key in ("cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb"):
            with self.subTest(key=f"{key}-missing"), \
                 mock.patch.dict(os.environ, CLIENT_ENV, clear=True), \
                 mock.patch.object(pg, "process_privilege_state", return_value={
                     key: -1, **{other: value for other, value in TEST_PRIVILEGES.items()
                                 if other != key},
                 }), mock.patch.object(pg, "verify_rootfs_manifest_digest"), \
                 self.assertRaises(pg.GateError):
                pg.require_test_user_runtime_guard()
        with (mock.patch.dict(os.environ, CLIENT_ENV, clear=True),
              mock.patch.object(pg, "process_privilege_state", return_value={
                  **TEST_PRIVILEGES, "groups": (2001,),
              }),
              mock.patch.object(pg, "verify_rootfs_manifest_digest")):
            pg.require_test_user_runtime_guard()
        for key, value in (
            ("STATEKIT_TOOL_ALLOWLIST", "sudo"),
            ("STATEKIT_NO_SUDO_AUTHORIZATION", "unverified"),
            ("STATEKIT_ROOTFS_ROLE", "payload"),
        ):
            with self.subTest(key=key), mock.patch.dict(os.environ, {
                **CLIENT_ENV, key: value,
            }, clear=True), mock.patch.object(pg, "process_privilege_state", return_value=TEST_PRIVILEGES), \
                 mock.patch.object(pg, "verify_rootfs_manifest_digest"), \
                 self.assertRaises(pg.GateError):
                pg.require_test_user_runtime_guard()
        with mock.patch.dict(os.environ, {**CLIENT_ENV, "PGPASSWORD": ""}, clear=True), \
             mock.patch.object(pg, "process_privilege_state", return_value=TEST_PRIVILEGES), \
             mock.patch.object(pg, "verify_rootfs_manifest_digest"), \
             self.assertRaises(pg.GateError):
            pg.require_test_user_runtime_guard()
        # The in-process manifest revalidation itself: digest must match the
        # staged manifest exactly; a malformed env digest, mismatch,
        # truncation, and symlinking all fail closed.
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "statekit-rootfs.manifest"
            payload = b'{"format":"statekit-rootfs-v1"}\n'
            manifest.write_bytes(payload)
            digest = __import__("hashlib").sha256(payload).hexdigest()
            with (mock.patch.dict(os.environ, {
                      **CLIENT_ENV, "STATEKIT_ROOTFS_MANIFEST_SHA256": digest,
                  }, clear=True),
                  mock.patch.object(pg, "ROOTFS_MANIFEST_PATH", manifest)):
                pg.verify_rootfs_manifest_digest()
            with (mock.patch.dict(os.environ, {
                      **CLIENT_ENV, "STATEKIT_ROOTFS_MANIFEST_SHA256": "short",
                  }, clear=True),
                  mock.patch.object(pg, "ROOTFS_MANIFEST_PATH", manifest),
                  self.assertRaisesRegex(pg.GateError, "rootfs-manifest-digest-missing")):
                pg.verify_rootfs_manifest_digest()
            with (mock.patch.dict(os.environ, {
                      **CLIENT_ENV, "STATEKIT_ROOTFS_MANIFEST_SHA256": "b" * 64,
                  }, clear=True),
                  mock.patch.object(pg, "ROOTFS_MANIFEST_PATH", manifest),
                  self.assertRaisesRegex(pg.GateError, "rootfs-manifest-digest-mismatch")):
                pg.verify_rootfs_manifest_digest()
            manifest.unlink()
            manifest.symlink_to(Path(directory) / "elsewhere")
            with (mock.patch.dict(os.environ, {
                      **CLIENT_ENV, "STATEKIT_ROOTFS_MANIFEST_SHA256": digest,
                  }, clear=True),
                  mock.patch.object(pg, "ROOTFS_MANIFEST_PATH", manifest),
                  self.assertRaisesRegex(pg.GateError, "rootfs-manifest-unavailable")):
                pg.verify_rootfs_manifest_digest()

    def test_runner_preflight_rejects_path_shadowed_admin_tools(self) -> None:
        pg.validate_runner_tool_paths({"sudo": "/usr/bin/sudo", "go": "/usr/local/go/bin/go"})
        with self.assertRaisesRegex(pg.GateError, "runner-tool-path-mismatch"):
            pg.validate_runner_tool_paths({"sudo": "/tmp/controller/sudo", "go": "/tmp/go"})

    def test_client_source_and_workspace_are_read_only_and_private(self) -> None:
        pg.verify_test_source_read_only()
        nonce = os.urandom(10).hex()
        workspace = Path("/dev/shm") / f"statekit-pg-{nonce}.{os.urandom(4).hex()}"
        run_dir = workspace / "run"
        try:
            workspace.mkdir(mode=0o750)
            workspace.chmod(0o750)
            run_dir.mkdir(mode=0o700)
            run_dir.chmod(0o700)
            for name in ("home", "tmp", "gocache", "gomodcache"):
                path = run_dir / name
                path.mkdir(parents=True, mode=0o700)
                path.chmod(0o700)
            passfile = workspace / ".pgpass"
            passfile.write_text("fixture\n", encoding="ascii")
            passfile.chmod(0o600)
            uid = str(os.getuid())
            gid = str(os.getgid())
            environment = {
                **CLIENT_ENV,
                "HOME": str(run_dir / "home"), "TMPDIR": str(run_dir / "tmp"),
                "GOCACHE": str(run_dir / "gocache"), "GOMODCACHE": str(run_dir / "gomodcache"),
                "STATEKIT_BIN": str(run_dir / "statekit"),
                "STATEKIT_REPORT_PATH": str(run_dir / "report.txt"),
                "STATEKIT_PG_PASSFILE": str(passfile),
                "STATEKIT_PG_WORKSPACE": str(workspace),
                "STATEKIT_PG_DATABASE": f"statekit_pg_{nonce}",
                "STATEKIT_PG_USER": f"statekit_user_{nonce}",
                "STATEKIT_WORKSPACE_UID": uid, "STATEKIT_TEST_UID": uid,
                "STATEKIT_TEST_GID": gid,
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                pg.verify_test_workspace()
                escape = workspace / "escape"
                escape.symlink_to("/etc/passwd")
                with self.assertRaisesRegex(pg.GateError, "test-workspace-node-policy"):
                    pg.verify_test_workspace()
                escape.unlink()
                socket_path = workspace / "unexpected.sock"
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    listener.bind(str(socket_path))
                    with self.assertRaisesRegex(pg.GateError, "test-user-socket-or-device-descriptor"):
                        pg.require_no_extra_sockets_or_devices()
                    with self.assertRaisesRegex(pg.GateError, "test-workspace-node-policy"):
                        pg.verify_test_workspace()
                finally:
                    listener.close()
                    socket_path.unlink(missing_ok=True)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_runtime_server_binds_cluster_pid_executable_config_and_listener_pid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            config_file = Path("/etc/postgresql/16/main/postgresql.conf")
            (data_dir / "postmaster.pid").write_text(
                f"4321\n{data_dir}\n1727160000\n5432\n/tmp\nlocalhost\n",
                encoding="ascii",
            )
            tools = {
                "pg_datadir": str(data_dir), "pg_config_file": str(config_file),
                "postgres": "/usr/lib/postgresql/16/bin/postgres",
            }
            process = {
                "pid": "4321", "uids": [999, 999, 999, 999],
                "exe": tools["postgres"],
                "argv": ["postgres", "-D", str(data_dir), "-c", f"config_file={config_file}"],
            }
            listeners = (
                "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* "
                'users:(("postgres",pid=4321,fd=5))'
            )
            snapshot = {
                "pid_lines": ["4321", str(data_dir), "1727160000", "5432"],
                "process": process, "listeners": listeners,
            }
            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999))):
                pg.verify_server_process(tools, snapshot)

            mismatches = []
            for field, value in (
                ("uids", [1000, 1000, 1000, 1000]),
                ("exe", "/wrong/postgres"),
                ("argv", ["postgres", "-D", str(data_dir)]),
                ("pid", "9876"),
            ):
                bad_process = {**process, field: value}
                mismatches.append({**snapshot, "process": bad_process})
            for bad_snapshot in mismatches:
                with self.subTest(snapshot=bad_snapshot), \
                     mock.patch.dict(os.environ, HOSTED, clear=True), \
                     mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)), \
                     self.assertRaises(pg.GateError):
                    pg.verify_server_process(tools, bad_snapshot)

            wrong_pid_listener = listeners.replace("pid=4321", "pid=9876")
            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)),
                  self.assertRaisesRegex(pg.GateError, "postgres-listener-not-loopback-only")):
                pg.verify_server_process(tools, {**snapshot, "listeners": wrong_pid_listener})

            nonloopback = listeners.replace("127.0.0.1:5432", "0.0.0.0:5432")
            with (mock.patch.dict(os.environ, HOSTED, clear=True),
                  mock.patch.object(pg.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=999)),
                  self.assertRaisesRegex(pg.GateError, "postgres-listener-not-loopback-only")):
                pg.verify_server_process(tools, {**snapshot, "listeners": nonloopback})

    def test_report_is_value_free_exact_order_and_rejects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.txt"
            gate = mock_gate()
            gate.report = report_path
            gate.results = [(case_id, "pass") for case_id in EXPECTED_CASES]
            gate.password = "mock-password-that-must-not-be-reported"
            gate.bad_password = "mock-invalid-password-that-must-not-be-reported"
            gate.execution_complete = True
            gate.cleanup_ok = True
            success, text = gate.report_contents()
            self.assertTrue(success)
            self.assertIn("cases_passed: 20\ncases_failed: 0\ncases_skipped: 0\nstatus: pass", text)
            self.assertEqual(
                [line.removeprefix("case: ") for line in text.splitlines() if line.startswith("case: ")],
                [f"{case_id}=pass" for case_id in EXPECTED_CASES],
            )
            self.assertIn("write_false: not read-only", text)
            self.assertNotIn(pg.MULTILINE, text)
            self.assertNotIn(gate.password, text)
            self.assertNotIn(gate.bad_password, text)
            report_path.write_text(text, encoding="utf-8")
            self.assertTrue(pg.validate_report(report_path))
            # The independent controller-side validator accepts the exact
            # generated bytes only under its strict file policy.
            os.chmod(report_path, 0o600)
            self.assertTrue(controller_validator.report_is_valid(report_path))
            os.chmod(report_path, 0o644)
            self.assertFalse(controller_validator.report_is_valid(report_path))
            os.chmod(report_path, 0o600)
            report_path.write_text(text.replace("cases_passed: 20", "cases_passed: 19"), encoding="utf-8")
            self.assertFalse(pg.validate_report(report_path))
            self.assertFalse(controller_validator.report_is_valid(report_path))
            report_path.write_text(text.replace("postgres_version: 16.15", "postgres_version: 16.16"), encoding="utf-8")
            self.assertFalse(controller_validator.report_is_valid(report_path))
            report_path.write_text(text, encoding="utf-8")
            report_path.unlink()
            report_path.symlink_to(Path(directory) / "missing")
            self.assertFalse(pg.validate_report(report_path))
            self.assertFalse(controller_validator.report_is_valid(report_path))

    def test_write_false_is_not_read_only_and_native_observation_is_independent(self) -> None:
        gate = mock_gate()
        statekit_calls: list[tuple[str, bool]] = []
        native_calls: list[tuple[str, str]] = []

        def statekit(sql: str, *, write: bool = False, **_kwargs: object) -> pg.Result:
            statekit_calls.append((sql, write))
            expected = {
                pg.INSERT_SQL: [{"id": "1", "note": "start"}],
                pg.UPDATE_SQL: [{"id": "1", "note": "committed"}],
                pg.EMPTY_UPDATE_SQL: [],
            }
            return result(expected[sql])

        def native_equals(sql: str, expected: str, **_kwargs: object) -> None:
            native_calls.append((sql, expected))

        gate.statekit = statekit
        gate.native_equals = native_equals
        for index in (6, 7, 8, 9, 10):
            gate.case(EXPECTED_CASES[index])
        self.assertEqual(statekit_calls, [
            (pg.INSERT_SQL, False), (pg.UPDATE_SQL, True), (pg.EMPTY_UPDATE_SQL, True),
        ])
        self.assertEqual(native_calls, [
            ("SELECT note FROM observations WHERE id=1", "start"),
            ("SELECT note FROM observations WHERE id=1", "committed"),
        ])
        self.assertIn("INSERT INTO observations", pg.INSERT_SQL)
        self.assertIn("RETURNING id, note", pg.INSERT_SQL)

    def test_auth_and_unavailable_endpoint_classification(self) -> None:
        password = "synthetic:back\\slash"
        envelope = json.dumps({"password": password}).encode()
        self.assertEqual(pg.read_credential_envelope(io.BytesIO(envelope)), password)
        for value in (b"x" * 4097, b"\xff", b"{", b"[]", b'{}', b'{"password":7}',
                      b'{"password":""}', b'{"password":"one","password":"two"}',
                      b'{"password":"one","extra":true}',
                      *(json.dumps({"password": value}).encode() for value in
                        ("a\nb", "a\rb", "a\x00b", "x" * 1025))):
            with self.subTest(envelope_length=len(value)), self.assertRaises(pg.GateError):
                pg.read_credential_envelope(io.BytesIO(value))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".pgpass"
            user = "statekit_user_" + "a" * 20
            pg.create_private_passfile(path, user, password)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual(path.read_text(), f"127.0.0.1:5432:*:{user}:synthetic\\:back\\\\slash\n")
            reader = object.__new__(pg.Gate)
            reader.passfile, reader.user = path, user
            self.assertEqual(reader._read_password(), password)
            reader.pg_bindir = "/usr/lib/postgresql/16/bin"
            reader.home = directory
            reader.temp_dir = Path(directory)
            with mock.patch.dict(os.environ, {"LD_LIBRARY_PATH": "/usr/lib64"}, clear=True):
                native_env = reader._base_env()
            self.assertEqual(native_env["PGPASSFILE"], str(path))
            self.assertNotIn("PGPASSWORD", native_env)
            self.assertNotIn(password, json.dumps(native_env))
            with self.assertRaises(pg.GateError):
                pg.create_private_passfile(path, user, password)
            pg.remove_private_passfile(path)
            self.assertFalse(path.exists())
            pg.remove_private_passfile(path)
            real_fstat = os.fstat
            def wrong_owner(descriptor: int) -> object:
                metadata = real_fstat(descriptor)
                return types.SimpleNamespace(st_mode=metadata.st_mode, st_nlink=metadata.st_nlink,
                                             st_uid=metadata.st_uid + 1, st_gid=metadata.st_gid)
            with mock.patch.object(pg.os, "fstat", side_effect=wrong_owner), self.assertRaises(pg.GateError):
                pg.create_private_passfile(path, user, password)
            self.assertFalse(path.exists())
            path.symlink_to(Path(directory) / "outside")
            with self.assertRaises(pg.GateError):
                pg.create_private_passfile(path, user, password)
            path.unlink()
        with mock.patch.dict(os.environ, {**CLIENT_ENV, "STATEKIT_ROOTFS_RUNTIME": "1"}, clear=True), \
             mock.patch.object(pg, "require_test_user_runtime_guard"), \
             mock.patch.object(pg, "verify_rootfs_runtime_manifest") as manifest_check, \
             mock.patch.object(pg, "verify_test_workspace"), \
             mock.patch.object(pg, "verify_test_source_read_only", side_effect=AssertionError("checkout accessed")):
            pg.require_test_user_preflight()
            manifest_check.assert_called_once_with()
        stream = io.TextIOWrapper(io.BytesIO(envelope), encoding="utf-8")
        workspace = None
        try:
            with mock.patch.dict(os.environ, {**CLIENT_ENV, "STATEKIT_ROOTFS_RUNTIME": "1",
                                               "STATEKIT_TEST_UID": str(os.getuid()),
                                               "STATEKIT_TEST_GID": str(os.getgid())}, clear=True), \
                 mock.patch.object(pg, "require_rootless_container_privileges") as privileges, \
                 mock.patch.object(pg, "verify_rootfs_runtime_manifest") as manifest_check, \
                 mock.patch.object(pg.os, "getgroups", return_value=[]), \
                 mock.patch.object(sys, "stdin", stream):
                received_passfile = pg.initialize_rootfs_workspace()
                workspace = received_passfile.parent
                self.assertEqual(workspace.parent, Path("/tmp"))
                self.assertEqual(received_passfile.stat().st_mode & 0o777, 0o600)
                self.assertEqual(received_passfile.stat().st_uid, os.getuid())
                self.assertEqual(os.environ["STATEKIT_PG_PASSFILE"], str(received_passfile))
                self.assertNotIn("GITHUB_WORKSPACE", os.environ)
                self.assertNotIn("PGPASSWORD", os.environ)
                self.assertNotIn(password, json.dumps(dict(os.environ)))
                self.assertTrue(stream.closed)
                privileges.assert_called_once_with()
                manifest_check.assert_called_once_with()
                pg.remove_private_passfile(received_passfile)
                self.assertFalse(received_passfile.exists())
        finally:
            stream.close()
            if workspace is not None:
                shutil.rmtree(workspace)
        # The top-level payload controller must erase its passfile both before
        # report generation and if Gate construction fails after receiving it.
        for failure in ("none", "constructor", "cleanup"):
            with self.subTest(payload_failure=failure), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / ".pgpass"
                path.write_text("synthetic-only", encoding="utf-8")
                report = Path(directory) / "report.txt"
                gate = mock.Mock()
                gate.temp_dir = Path(directory)
                gate.passfile = path
                def write_report() -> bool:
                    self.assertFalse(path.exists())
                    report.write_text("value-free-report\n", encoding="ascii")
                    return True
                gate.write_report.side_effect = write_report
                if failure == "cleanup":
                    gate.cleanup.side_effect = pg.GateError("fixed-cleanup-failure")
                with mock.patch.dict(os.environ, {"STATEKIT_ROOTFS_RUNTIME": "1",
                                                  "STATEKIT_REPORT_PATH": str(report)}, clear=True), \
                     mock.patch.object(sys, "argv", [str(MODULE_PATH), "--run-cases"]), \
                     mock.patch.object(pg, "initialize_rootfs_workspace", return_value=path), \
                     mock.patch.object(pg, "Gate", side_effect=pg.GateError("fixed-constructor-failure")
                                       if failure == "constructor" else None, return_value=gate), \
                     mock.patch.object(pg, "bounded_process", return_value=pg.Result(0, b"version", b"")), \
                     mock.patch.object(pg, "validate_report", return_value=True), \
                     mock.patch.object(pg.signal, "signal"):
                    if failure == "none":
                        self.assertEqual(pg.main(), 0)
                        self.assertEqual(report.read_text(), "value-free-report\n")
                    else:
                        with self.assertRaises(pg.GateError):
                            pg.main()
                        self.assertFalse(report.exists())
                    self.assertFalse(path.exists())
        gate = mock_gate()
        gate.native = lambda *_args, **_kwargs: pg.Result(
            2, b"", f'FATAL: password authentication failed for user "{gate.user}"\n'.encode(),
        )
        gate.case(EXPECTED_CASES[14])
        gate.native = lambda *_args, **_kwargs: pg.Result(0, b"1\n", b"")
        with self.assertRaises(pg.GateError):
            gate.case(EXPECTED_CASES[14])
        refused = (
            b'psql: error: connection to server at "127.0.0.1", port 5433 failed: '
            b"Connection refused\n"
        )
        gate.native = lambda *_args, **_kwargs: pg.Result(2, b"", refused)
        gate.case(EXPECTED_CASES[16])
        gate.native = lambda *_args, **_kwargs: pg.Result(0, b"1\n", b"")
        with self.assertRaises(pg.GateError):
            gate.case(EXPECTED_CASES[16])
        for error in (
            b'psql: error: connection to server at "127.0.0.1", port 5433 failed: '
            b"connection refused\n",
            b"psql: error: could not connect to server: Connection timed out\n",
            b"FATAL: password authentication failed (28P01)\n",
        ):
            gate.native = lambda *_args, error=error, **_kwargs: pg.Result(2, b"", error)
            with self.subTest(error=error), self.assertRaises(pg.GateError):
                gate.case(EXPECTED_CASES[16])
        # R92T-BACKEND-FINAL-01: the live firewall synthesizes the refusal
        # with one exact owner-scoped tcp-reset REJECT on loopback
        # 127.0.0.1:5433 ahead of the terminal DROP, so both clients
        # deterministically observe ECONNREFUSED instead of a DROP timeout:
        # native psql reports the exact "Connection refused" diagnostic the
        # strict classifier above requires, and StateKit keeps its pinned
        # positive-retcode mapping (an empty row list with a zero exit) for
        # the closed endpoint. The classifier is not weakened: a generic
        # execution error from the closed endpoint still fails the case.
        gate.statekit = lambda *_args, **_kwargs: result([])
        gate.case(EXPECTED_CASES[15])
        gate.statekit = lambda *_args, **_kwargs: result(
            None, rc=1, error="statekit: postgres: query failed")
        with self.assertRaises(pg.GateError):
            gate.case(EXPECTED_CASES[15])

    def test_all_twenty_mock_cases_execute_in_order_without_a_live_service(self) -> None:
        gate = mock_gate()
        observations: list[str] = []
        dispatched: list[str] = []

        def native(sql: str, *, database: str | None = None, host: str = "127.0.0.1",
                   port: str = "5432", bad_auth: bool = False) -> pg.Result:
            observations.append("native:" + sql[:24])
            if bad_auth:
                return pg.Result(2, b"", f'FATAL: password authentication failed for user "{gate.user}"\n'.encode())
            if port == "5433":
                return pg.Result(
                    2, b"",
                    b'psql: error: connection to server at "127.0.0.1", port 5433 failed: '
                    b"Connection refused\n",
                )
            if sql == "THIS IS NOT VALID SQL":
                return pg.Result(3, b"", b"ERROR: 42601\n")
            if sql.startswith("CREATE TABLE") or sql.startswith("DROP DATABASE"):
                return pg.Result(0, b"", b"")
            raise AssertionError("unreviewed native operation")

        def native_equals(sql: str, expected: str, **_kwargs: object) -> None:
            observations.append("native-equals:" + sql[:24])
            valid = {
                "SELECT 1": "1", "SELECT 7 AS value": "7",
                pg.NATIVE_MULTILINE_HEX_SQL: pg.MULTILINE.encode().hex(),
                "SELECT note FROM observations WHERE id=1": ("start", "committed"),
                f"SELECT COUNT(*) FROM pg_database WHERE datname='{gate.db}'": "0",
            }
            self.assertIn(sql, valid)
            self.assertIn(expected, (valid[sql],) if isinstance(valid[sql], str) else valid[sql])

        def statekit(sql: str, *, write: bool = False, port: str = "5432",
                     password: str | None = None) -> pg.Result:
            observations.append("statekit:" + sql[:24])
            if len(sql.encode("utf-8")) > 256 << 10:
                return result(None, rc=1, dispatch=False,
                              error="statekit: runtime: command input exceeds limit")
            dispatched.append(sql[:24])
            if port == "5433" or password == gate.bad_password or sql == "THIS IS NOT VALID SQL":
                return result([])
            if sql.startswith("SELECT repeat("):
                return result(None, rc=1, error="statekit: process: output limit exceeded")
            expected = {
                "SELECT 7 AS value": [{"value": "7"}],
                pg.MULTILINE_SQL: [{"id": "1", "note": pg.MULTILINE}],
                "SELECT 7 AS value WHERE false": [],
                pg.INSERT_SQL: [{"id": "1", "note": "start"}],
                pg.UPDATE_SQL: [{"id": "1", "note": "committed"}],
                pg.EMPTY_UPDATE_SQL: [],
            }
            self.assertIn(sql, expected)
            if sql == pg.INSERT_SQL:
                self.assertFalse(write)
            if sql in (pg.UPDATE_SQL, pg.EMPTY_UPDATE_SQL):
                self.assertTrue(write)
            return result(expected[sql])

        gate.native = native
        gate.native_equals = native_equals
        gate.statekit = statekit
        with mock.patch.object(pg, "require_test_user_runtime_guard"):
            gate.run_cases()
        self.assertEqual(gate.results, [(case_id, "pass") for case_id in EXPECTED_CASES])
        self.assertTrue(gate.execution_complete)
        self.assertTrue(gate.db_verified_absent)
        self.assertGreater(len(observations), 20)
        self.assertEqual(len(dispatched), 10)
        self.assertNotIn(pg.OVERSIZE_SQL[:24], dispatched)

    def test_prod_result_matchers_require_completion_and_exact_values(self) -> None:
        pg.parse_json_result(result([{"id": "1", "note": pg.MULTILINE}]),
                             [{"id": "1", "note": pg.MULTILINE}])
        pg.parse_json_result(result([]), [])
        with self.assertRaises(pg.GateError):
            pg.parse_json_result(result(1), True)
        with self.assertRaises(pg.GateError):
            pg.parse_json_result(result([{"id": "1", "note": "wrong"}]),
                                 [{"id": "1", "note": pg.MULTILINE}])
        with self.assertRaises(pg.GateError):
            pg.parse_json_result(result([]), [], dispatch=False)
        with self.assertRaises(pg.GateError):
            pg.parse_json_result(pg.Result(0, b"[]", b""), [])
        limit = "statekit: runtime: command input exceeds limit"
        output = "statekit: process: output limit exceeded"
        pg.parse_failure(result(None, rc=1, dispatch=False, error=limit), limit, False)
        pg.parse_failure(result(None, rc=1, error=output), output, True)

    def test_workflow_uses_runner_platform_without_images_or_services(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  postgres-live:", workflow)
        self.assertIn("on:\n  pull_request:", workflow)
        job = workflow.split("  postgres-live:", 1)[1]
        self.assertEqual(
            re.findall(r"(?m)^    if: (.+)$", job),
            ["${{ (github.event_name == 'push' || github.event_name == 'workflow_dispatch' || "
             "github.event_name == 'schedule') && github.ref == 'refs/heads/main' }}"],
        )
        self.assertNotRegex(job, r"(?m)^    if:.*\bpull_request\b")
        self.assertIn("runs-on: ubuntu-24.04", job)
        self.assertIn("timeout-minutes: 30", job)
        self.assertIn("permissions:\n      contents: read", job)
        self.assertIn("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", job)
        self.assertIn("actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4", job)
        self.assertIn("persist-credentials: false", job)
        self.assertIn("tests/live/postgres/ci.sh", job)
        self.assertIn("if-no-files-found: error", job)
        self.assertIn("if: success()", job)
        self.assertIn("e5-postgres-live-report", job)
        self.assertIn("rootless Podman", job)
        self.assertNotIn("services:", job)
        self.assertNotIn("ports:", job)
        self.assertNotIn("podman pull", job.lower())
        self.assertNotIn("postgres:", job.lower())
        self.assertNotIn("id-token: write", job)
        self.assertIsNone(re.search(r"\$\{\{\s*secrets\.", job))
        self.assertIsNone(re.search(r"\bsecrets\.[A-Za-z_]", job))
        self.assertNotIn("${{ github.event.pull_request", job)
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("  mysql-live:", workflow)
        self.assertIn("  sqlite-live:", workflow)
        self.assertIsNone(re.search(r"^\s+pull_request_target:", workflow, flags=re.MULTILINE))

    def test_workspace_creator_cleanup_and_identity_guard_are_exercised(self) -> None:
        completed = subprocess.run(
            ["bash", str(CI_SCRIPT), "--workspace-self-test"], cwd=ROOT,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
            check=False, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

    def test_ci_is_native_pinned_fetch_then_offline_build_and_firewall(self) -> None:
        script = CI_SCRIPT.read_text(encoding="utf-8")
        rootfs_source = (ROOT / "tests/live/postgres/rootfs.py").read_text(encoding="utf-8")
        syntax = subprocess.run(["bash", "-n", str(CI_SCRIPT)], check=False, capture_output=True)
        self.assertIn('--dig-contract-only)', script)
        self.assertIn('rootfs_profile_args=(--profile dig-contract)', script)
        self.assertIn('build_go_cache=/out/gocache', script)
        self.assertIn('--env "GOCACHE=$build_go_cache"', script)
        self.assertIn('[[ "$cgroup_mode" == enabled ]] || return 1', script)
        self.assertIn('go test -tags=dns_contract -count=1 ./modules/exec/dig ./internal/cli ./tests/differential ./modules/exec/dnsutil', script)
        self.assertLess(script.index("'dig-contract-offline-passed'"), script.index('cluster_state="$(bounded_timeout 60 python3'))
        for helper in ('cleanup_database_and_role', 'cleanup_cluster'):
            self.assertIn(helper + '() {\n  (( ${dig_contract_only:-0} == 0 )) || return 0', script)
        with mock.patch.object(rootfs_builder, 'RootfsBuilder') as builder, \
                mock.patch.object(rootfs_builder, 'python_standard_library', return_value=()):
            rootfs_builder.build_full_rootfs(
                destination=Path('/fixture/rootfs'), uid=1000, gid=1000,
                go_root=Path('/usr/local/go'), psql_executable=None,
                python_executable=Path('/usr/bin/python3'), bash_executable=Path('/usr/bin/bash'),
                sh_executable=Path('/usr/bin/sh'), exec_mount=Path('/fixture'),
                runtime_profile='dig-contract')
            arguments = builder.return_value.build.call_args.kwargs
            self.assertEqual(arguments['runtime_profile'], 'dig-contract')
            self.assertIsNone(arguments['psql_executable'])
            self.assertTrue(arguments['require_full_runtime'])
        self.assertEqual(syntax.returncode, 0, syntax.stderr.decode(errors="replace"))
        commands = [line.strip() for line in script.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(commands[0], "set -euo pipefail")
        self.assertIn("python3 tests/live/postgres/run.py --preflight-only", script)
        preflight_call = script.index("preflight_exec_mount_plan || fixed_error")
        self.assertLess(script.index("python3 tests/live/postgres/run.py --preflight-only"),
                        preflight_call)
        self.assertLess(preflight_call, script.index('PG_BINDIR="$(pg_config --bindir)"'))
        self.assertLess(preflight_call,
                        script.index("useradd --system"))
        self.assertLess(preflight_call, script.index("/opt/go/bin/go mod download"))
        self.assertIn("statekit-exec-", script)
        self.assertIn('EXEC_TMPFS_OPTIONS="rw,exec,nosuid,nodev,size=4g,mode=0700"', script)
        self.assertIn('"$SUDO_BIN" -n -l -- "$MOUNT_BIN"', script)
        self.assertIn('"$SUDO_BIN" -n -l -- "$UMOUNT_BIN"', script)
        self.assertIn("findmnt", script)
        self.assertIn("rootfs.py preflight-mount", script)
        self.assertIn("--exec-mount \"$exec_mountpoint\"", script)
        self.assertIn('rootfs_dir="$exec_mountpoint/rootfs"', script)
        self.assertIn('fetch_rootfs_dir="$exec_mountpoint/rootfs-fetch"', script)
        self.assertIn('exec_artifacts_dir="$exec_mountpoint/artifacts"', script)
        self.assertIn("rootfs.py verify-mount", script)
        self.assertIn("rootfs.py verify \\", script)
        self.assertIn("--manifest-sha256 \"$digest\"", script)
        self.assertIn("--workspace-self-test", script)
        self.assertIn("--container-lifecycle-self-test", script)
        self.assertIn("container_state", script)
        self.assertIn("container_must_be_absent", script)
        self.assertNotIn("container_exists()", script)
        # R92T-INDEPENDENT-01: a candidate container name is not ownership.
        # Removal iterates only the ownership receipt, re-verifies identity,
        # and removes by canonical ID; by-name removal no longer exists.
        self.assertIn("container_receipt_claim", script)
        self.assertIn("container_receipt_release", script)
        self.assertIn("cleanup_owned_container", script)
        self.assertIn("reconcile_partial_create", script)
        self.assertIn("create_failed_reconcile", script)
        self.assertIn("cleanup_phase_container fetch", script)
        self.assertIn('rm --force "$canonical_id"', script)
        # R92T-FRESH-01: any unowned/foreign/ambiguous observation latches a
        # monotonic destructive-teardown block; the private store must be
        # proven empty before the first create; and every create site is
        # preceded by a name reserve, so no later phase can reuse an unowned
        # object (each observation fails the run immediately).
        self.assertIn("mark_unowned_resource", script)
        self.assertIn("unowned_or_unknown_resource=1", script)
        self.assertIn("destructive_teardown_blocked=1", script)
        self.assertIn("verify_container_store_empty", script)
        self.assertIn("'podman-store-not-empty'", script)
        self.assertLess(script.index("verify_container_store_empty || fixed_error"),
                        script.index('fetch_container="statekit-pg-fetch-$nonce"'))
        for container in ("fetch_container", "build_container", "mock_container", "live_container"):
            self.assertLess(script.index(f'container_must_be_absent "${container}"'),
                            script.index(f'--name "${container}"'),
                            f"reserve must precede create for {container}")
        self.assertIn("io.statekit.run.nonce", script)
        self.assertIn("--label \"io.statekit.phase=fetch\"", script)
        self.assertIn("--label \"io.statekit.phase=build\"", script)
        self.assertIn("--label \"io.statekit.phase=mock\"", script)
        self.assertIn("--label \"io.statekit.phase=live\"", script)
        self.assertIn("'podman-create-partial-object-unowned'", script)
        self.assertIn("'container-ownership-receipt-invalid'", script)
        self.assertNotIn("cleanup_podman_container", script)
        self.assertNotIn('rm --force "$fetch_container"', script)
        self.assertNotIn('rm --force "$build_container"', script)
        self.assertNotIn('rm --force "$mock_container"', script)
        self.assertNotIn('rm --force "$live_container"', script)
        self.assertIn("workspace_identity_matches", script)
        self.assertIn("cleanup_workspace", script)
        self.assertIn("[A-Za-z0-9]{8}", script)
        self.assertIn("podman_as_test_user create --rootfs \\\n", script)
        self.assertIn('--env "LD_LIBRARY_PATH=$rootfs_library_path"', script)
        self.assertIn('"$rootfs_dir" "${build_command[@]}"', script)
        self.assertIn('"$rootfs_dir" "${mock_command[@]}"', script)
        self.assertIn('"$rootfs_dir" "${live_command[@]}"', script)
        self.assertIn('"$fetch_rootfs_dir" \\\n  /usr/bin/statekit-rootfs-preflight', script)
        self.assertIn("/usr/bin/statekit-rootfs-preflight /bin/bash -euo pipefail -c", script)
        self.assertIn("/usr/bin/python3 -B /opt/statekit/repo/tests/live/postgres/run.py --run-cases", script)
        self.assertIn("--userns=keep-id", script)
        self.assertIn("--network=none", script)
        self.assertIn("--network=host", script)
        self.assertIn("--cap-drop=ALL", script)
        self.assertIn("--read-only", script)
        self.assertIn("--pids-limit 256", script)
        self.assertIn("--tmpfs /tmp:rw,nosuid,nodev", script)
        self.assertIn("--tmpfs /dev/shm:rw,nosuid,nodev,noexec,size=64m", script)
        self.assertIn("podman_policy.py", script)
        self.assertLess(script.index('verify_podman_container "$build_container"'),
                        script.index('podman_as_test_user start --attach "$build_container"'))
        self.assertLess(script.index('verify_podman_container "$fetch_container"'),
                        script.index('podman_as_test_user start --attach "$fetch_container"'))
        self.assertLess(script.index('verify_podman_container "$live_container"'),
                        script.index('podman_as_test_user start --attach --interactive "$live_container"'))
        # SEC-02: every create and every start is preceded by an independent
        # manifest/tree revalidation, not by label inspection.
        for container in ("fetch_container", "build_container", "mock_container", "live_container"):
            self.assertLess(
                script.index(f'verify_rootfs_authoritative "$fetch_rootfs_dir" dependency-fetch'
                             if container == "fetch_container" else
                             f'verify_rootfs_authoritative "$rootfs_dir" live-executable'),
                script.index(f'podman_as_test_user start --attach '
                             + ('--interactive ' if container == 'live_container' else '')
                             + f'"${container}"'),
            )
            phase = container.removesuffix("_container")
            root = "$fetch_rootfs_dir" if phase == "fetch" else "$rootfs_dir"
            digest = "$fetch_manifest_sha256" if phase == "fetch" else "$rootfs_manifest_sha256"
            profile = "dependency-fetch" if phase == "fetch" else "live-executable"
            for boundary in (f'podman_as_test_user create --rootfs \\\n  --name "${container}"',
                             f'podman_as_test_user start --attach '
                             + ('--interactive ' if phase == 'live' else '')
                             + f'"${container}"'):
                preceding = script.split(boundary, 1)[0].rsplit("verify_rootfs_authoritative ", 1)[1]
                self.assertTrue(preceding.startswith(f'"{root}" {profile} \\\n  "{digest}"'), boundary)
            verifier_call = script.split(f'verify_podman_container "${container}"', 1)[1].split(" ||", 1)[0]
            self.assertIn(f'"{root}" "{digest}"', verifier_call)
        self.assertNotIn("podman pull", script.lower())
        self.assertNotIn("podman build", script.lower())
        self.assertNotIn("Containerfile", script)
        self.assertNotRegex(script, r"(?m)^\s*(?:apt|apt-get)\s+(?:install|update)")
        # SEC-03: the fetch sandbox never executes `go mod download` on the
        # host and mounts no checkout source; only manifests and one writable
        # module-cache output cross the boundary.
        self.assertNotIn('"$GO_BIN" mod download', script)
        self.assertNotIn("go_env_fetch", script)
        self.assertIn("--profile fetch", script)
        self.assertIn("--env GOPROXY=https://proxy.golang.org", script)
        self.assertIn("--env GOSUMDB=sum.golang.org", script)
        self.assertIn("--env GOMODCACHE=/modules", script)
        self.assertIn("--volume \"$work_dir/manifests:/deps:ro,nosuid,nodev,noexec,rprivate\"", script)
        self.assertIn("--volume \"$run_dir/gomodcache:/modules:rw,nosuid,nodev,noexec,rprivate\"", script)
        fetch_block = script.split('fetch_container="statekit-pg-fetch-$nonce"', 1)[1] \
                         .split("ipv4-fetch-egress-cleanup-failed", 1)[0]
        self.assertNotIn('/workspace', fetch_block)
        self.assertNotIn('"$ROOT"', fetch_block)
        self.assertIn("--env GOPROXY=off", script)
        self.assertIn("--env GOSUMDB=sum.golang.org", script)
        self.assertIn("--env GOTOOLCHAIN=local", script)
        self.assertIn("--env GOWORK=off", script)
        self.assertNotIn(",direct", script)
        self.assertIn("mod download", script)
        self.assertIn("mod verify", script)
        self.assertIn("go build -trimpath -buildvcs=false -o /out/statekit ./cmd/statekit", script)
        self.assertIn("go test ./...", script)
        self.assertIn("tests/live/postgres/test_orchestration.py", script)
        self.assertIn("resolve_fetch_endpoints", script)
        self.assertIn("storage.googleapis.com", script)
        # Both families install and verify unconditionally; an empty
        # resolved set must never skip the IPv6 filter.
        self.assertIn("install_fetch_firewall_family iptables 127.0.0.53/32", script)
        self.assertIn("install_fetch_firewall_family ip6tables ::1/128", script)
        self.assertNotIn("proxy_addresses_v6[@]} > 0", script)
        self.assertIn("firewall_fetch4_created", script)
        self.assertIn("firewall_fetch6_created", script)
        self.assertIn("--dport 443 -j ACCEPT", script)
        self.assertIn("verify_effective_fetch_firewall_family", script)
        self.assertIn("FWC_MODE=fetch", script)
        self.assertIn("FWC_MODE=live", script)
        fetch_v6_checks = [
            match.start() for match in re.finditer(
                r"verify_effective_fetch_firewall_family ip6tables ::1/128", script)
        ]
        self.assertEqual(len(fetch_v6_checks), 2, fetch_v6_checks)
        self.assertLess(fetch_v6_checks[1],
                        script.index('podman_as_test_user start --attach "$fetch_container"'))
        self.assertIn("-j DROP", script)
        # R92T-BACKEND-FINAL-01: exactly one owner-scoped tcp-reset REJECT
        # for the intentionally unavailable loopback endpoint
        # 127.0.0.1:5433, ahead of the terminal DROP. 5433 is never
        # ACCEPTed, and the IPv6 family carries no 5433 rule because no
        # case dials ::1:5433. Comment lines are excluded from the counts.
        code_only = "\n".join(
            line for line in script.splitlines() if not line.lstrip().startswith("#"))
        self.assertIn("-p tcp --dport 5433 -j REJECT --reject-with tcp-reset", code_only)
        self.assertEqual(code_only.count("--reject-with"), 2)
        self.assertEqual(code_only.count("--dport 5433"), 1)
        self.assertIn("FWC_REJECT", code_only)
        live_installer = script.split("install_live_firewall_family() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(live_installer.index("--dport 5432 -j ACCEPT"),
                        live_installer.index("--dport 5433 -j REJECT"))
        self.assertLess(live_installer.index("--dport 5433 -j REJECT"),
                        live_installer.index("-j DROP"))
        # Live egress: IPv6 loopback is allowed only when the service binds
        # it; otherwise that family default-drops for the test UID.
        self.assertIn("postgres_binds_ipv6_loopback", script)
        self.assertIn("ipv6_allow6='::1/128'", script)
        self.assertIn(
            "install_live_firewall_family iptables firewall4_created 127.0.0.1/32 127.0.0.1/32",
            script)
        self.assertIn(
            'install_live_firewall_family ip6tables firewall6_created "$ipv6_allow6" \'\'', script)
        self.assertIn('-o lo -d "$allow_address"', script)
        self.assertIn("--dport 5432 -j ACCEPT", script)
        self.assertIn("ip6tables", script)
        live_v6_checks = [
            match.start() for match in re.finditer(
                r'verify_effective_live_firewall_family ip6tables "\$ipv6_allow6"', script)
        ]
        self.assertEqual(len(live_v6_checks), 2, live_v6_checks)
        self.assertLess(live_v6_checks[1],
                        script.index('podman_as_test_user start --attach --interactive "$live_container"'))
        self.assertIn("CREATE ROLE \"$db_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE", script)
        self.assertIn("CREATE DATABASE \"$db_name\" OWNER \"$db_role\"", script)
        self.assertIn(r"\password $db_role", script)
        self.assertNotIn("PASSWORD '$password'", script)
        self.assertIn('printf \'{"password":"%s"}\\n\' "$password"', script)
        self.assertNotIn("PGPASSWORD=$password", script)
        self.assertNotIn("--password \"$password\"", script)
        self.assertNotIn("--command \"SELECT", script)
        self.assertNotIn("$pgpass_file", script)
        self.assertIn("/dev/shm/statekit-pg-", script)
        self.assertNotIn('rootfs_dir="/dev/shm/statekit-rootfs-', script)
        # The sealed rootfs carries the two reviewed harness files; no source
        # directory or credential file is a live bind mount.
        self.assertNotIn("harness_dir=", script)
        live_block = script.split('live_container="statekit-pg-live-$nonce"', 1)[1] \
                          .split('report_source=', 1)[0]
        self.assertNotIn('"$ROOT:/workspace', live_block)
        self.assertNotIn("/workspace", live_block)
        self.assertNotIn("/run/pgpass", live_block)
        self.assertIn("--interactive", live_block)
        self.assertNotIn("/.git", script)
        # Independent controller-side report validation happens after the
        # payload container is removed and teardown is verified, and before
        # the artifact copy.
        self.assertIn('bounded_timeout 30 python3 tests/live/postgres/validate_report.py '
                      '"$report_source"', script)
        self.assertLess(script.index("cleanup_exec_files || fixed_error"),
                        script.index('validate_report.py "$report_source"'))
        self.assertLess(script.index('validate_report.py "$report_source"'),
                        script.index("install -m 0644"))
        self.assertIn("pkill -KILL -u \"$test_uid\"", script)
        self.assertIn("NoNewPrivs", MODULE_PATH.read_text(encoding="utf-8"))
        self.assertIn("CapBnd", MODULE_PATH.read_text(encoding="utf-8"))
        self.assertIn("CapEff", rootfs_source)
        self.assertIn("CapPrm", rootfs_source)
        self.assertIn("CapAmb", rootfs_source)
        self.assertIn("STATEKIT_NO_SUDO_AUTHORIZATION=verified", script)
        self.assertIn("STATEKIT_TOOL_ALLOWLIST=psql", script)
        self.assertIn("PGPASSFILE", script)
        self.assertIn("--env STATEKIT_ROOTFS_MANIFEST_SHA256=", script)
        self.assertIn("--env STATEKIT_ROOTFS_ROLE=fetch", script)
        self.assertIn("--env STATEKIT_ROOTFS_ROLE=build", script)
        self.assertIn("--env STATEKIT_ROOTFS_ROLE=mock", script)
        self.assertIn("--env STATEKIT_ROOTFS_ROLE=live", script)
        # SEC-04: the rootless bootstrap must not cripple the setuid mapping
        # helpers; payload controls stay on the containers themselves.
        bootstrap = script.split("podman_as_test_user() {", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("--no-new-privs", bootstrap)
        self.assertNotIn("--bounding-set", bootstrap)
        payload_wrapper = script.split("run_as_test_user() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("--no-new-privs", payload_wrapper)
        self.assertIn("--bounding-set=-all", payload_wrapper)
        self.assertIn("verify_rootless_helpers", script)
        self.assertIn("/usr/bin/newuidmap", script)
        self.assertIn("/usr/bin/newgidmap", script)
        bootstrap_env = bootstrap.split("/usr/bin/env -i", 1)[1]
        for credential in ("GITHUB_TOKEN", "PGPASSWORD", "SSH_AUTH_SOCK", "DOCKER_CONFIG",
                           "AWS_ACCESS_KEY_ID", "XDG_RUNTIME_DIR=bogus"):
            self.assertNotIn(f"{credential}=", bootstrap_env.split("PODMAN_BIN")[0])
        # SEC-05: the compiled binary lives in the verified exec tmpfs, is
        # digest-checked before live create/start, mounted read-only, and is
        # never executed on the host.
        self.assertIn('--volume "$exec_artifacts_dir:/out:rw,nosuid,nodev,noexec,rprivate"', script)
        self.assertIn('--volume "$statekit_artifact:/artifact/statekit:ro,exec,nosuid,nodev,rprivate"', script)
        self.assertIn('statekit_artifact="$exec_artifacts_dir/statekit"', script)
        self.assertIn("statekit_artifact_digest", script)
        self.assertIn("sudo_bounded", script)
        self.assertIn("--assert-cluster-down", script)
        self.assertNotIn('"$statekit_artifact" exec', script)
        self.assertNotIn('python3 tests/live/postgres/run.py --validate-report "$report_source"', script)

        cleanup = script.split("cleanup() {", 1)[1].split("\n}", 1)[0]
        # R92T-FRESH-01: the destructive-teardown block is checked before
        # the UID-wide kill and before any exec-file or identity teardown.
        self.assertLess(cleanup.index("destructive_teardown_blocked == 1"),
                        cleanup.index("stop_test_user_processes"))
        self.assertLess(cleanup.index("destructive_teardown_blocked == 1"),
                        cleanup.index("cleanup_exec_files"))
        self.assertLess(cleanup.index("destructive_teardown_blocked == 1"),
                        cleanup.index("cleanup_database_and_role"))
        self.assertLess(cleanup.index("cleanup_all_containers"), cleanup.index("cleanup_exec_files"))
        self.assertLess(cleanup.index("cleanup_exec_files"), cleanup.index("cleanup_identity_and_files"))
        # R92T-FRESH-01 residual: a cluster-wide stop is unreachable while
        # the destructive-teardown block is latched — the blocked EXIT
        # branch never calls the stop helper, the common tail calls it only
        # with both latch flags clear, and the helper itself is a fixed
        # value-free no-op refusal placed ahead of pg_ctlcluster.
        self.assertIn("cluster-stop-skipped-unowned-resource", script)
        cluster_helper = script.split("cleanup_cluster() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(cluster_helper.index("destructive_teardown_blocked"),
                        cluster_helper.index("pg_ctlcluster"))
        blocked_branch = cleanup.split(
            "if (( destructive_teardown_blocked == 1 )); then", 1)[1].split(
            "elif cleanup_all_containers", 1)[0]
        self.assertNotIn("cleanup_cluster", blocked_branch)
        self.assertIn("destructive_teardown_blocked == 0 && unowned_or_unknown_resource == 0",
                      cleanup)
        file_cleanup = script.split("cleanup_exec_files() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(file_cleanup.index("remove_rootfs"), file_cleanup.index("remove_exec_mount"))
        self.assertLess(file_cleanup.index("remove_fetch_rootfs"), file_cleanup.index("remove_exec_mount"))
        self.assertLess(file_cleanup.index("remove_exec_artifacts"), file_cleanup.index("remove_exec_mount"))
        remove_mount = script.split("remove_exec_mount() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(remove_mount.index("verify_containers_absent"),
                        remove_mount.index("verify-cleanup --mountpoint"))
        self.assertLess(remove_mount.index("verify-cleanup --mountpoint"),
                        remove_mount.index('"$UMOUNT_BIN" --'))
        self.assertLess(remove_mount.index('"$UMOUNT_BIN" --'),
                        remove_mount.index("finish-cleanup"))
        self.assertIn("exec-mount-cleanup-failed", script)
        self.assertIn("exec-tmpfs-still-mounted", rootfs_source)
        self.assertNotRegex(script, r"(?m)^\s*(?:sudo\s+)?umount\s+[^\n]*\$[A-Za-z_][A-Za-z0-9_]*\s*$")

    def test_no_obsolete_postgres_images_or_old_podman_harness_references(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        rootfs_source = (ROOT / "tests/live/postgres/rootfs.py").read_text(encoding="utf-8")
        script = CI_SCRIPT.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8").split("  postgres-live:", 1)[1]
        self.assertNotIn("docker.io/library/postgres", source + script + workflow)
        self.assertIn("--rootfs", script)
        self.assertIn("rootfs.py", script)
        self.assertIn("podman_policy.py", script)
        self.assertNotIn("podman pull", script.lower())
        self.assertNotIn("podman build", script.lower())
        self.assertIn('"mock-only"', rootfs_source)
        self.assertIn('"live-executable"', rootfs_source)
        self.assertIn("source: ubuntu-24.04-runner-bundled-postgresql", source)
        self.assertIn("postgres_major: 16", source)
        self.assertIn("runner image may change", source)
        self.assertFalse((ROOT / "tests/live/postgres/Containerfile.client").exists())
        self.assertFalse((ROOT / "tests/live/postgres/Containerfile.python-check").exists())
        self.assertFalse((ROOT / "tests/live/postgres/client.sh").exists())
        self.assertTrue((ROOT / "tests/live/postgres/psql-probe.sh").is_file())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            runner = fixture / "runner"
            go_root = runner / "go/1.26.8/x64"
            pg_bin = runner / "usr/lib/postgresql/16/bin"
            python_bin = runner / "usr/bin/python3"
            bash_bin = runner / "usr/bin/bash"
            dash_bin = runner / "usr/bin/dash"
            sh_bin = runner / "usr/bin/sh"
            stdlib = runner / "usr/lib/python3.14"
            fake_files = {
                go_root / "bin/go": "go-tool-fixture",
                go_root / "bin/gofmt": "gofmt-fixture",
                go_root / "pkg/tool/linux_amd64/compile": "compiler-fixture",
                go_root / "pkg/include/textflag.h": "header-fixture",
                go_root / "src/runtime/runtime.go": "runtime-fixture",
                go_root / "VERSION": "go1.26.8\n",
                go_root / "lib/time/zoneinfo.zip": "tz-fixture",
                pg_bin / "psql": "psql-16.15-fixture",
                python_bin: "python-fixture",
                bash_bin: "bash-fixture",
                dash_bin: "sh-fixture",
                stdlib / "os.py": "python-stdlib-fixture",
            }
            for path, contents in fake_files.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
                if path in (
                    go_root / "bin/go", go_root / "bin/gofmt",
                    go_root / "pkg/tool/linux_amd64/compile", pg_bin / "psql",
                    python_bin, bash_bin, dash_bin,
                ):
                    path.chmod(0o755)
            sh_bin.symlink_to("dash")
            host_secret = fixture / "host-only-fixture.txt"
            host_secret.write_text("host-only-fixture-value", encoding="utf-8")
            destination = fixture / "mock-rootfs"

            def build_fixture(target: Path) -> Path:
                builder = rootfs_builder.RootfsBuilder(
                    target, uid=2001, gid=2001, require_exec_mount=False,
                    ldd=lambda _binary: (), test_source_roots=(runner,),
                )
                return builder.build(
                    go_root=go_root, psql_executable=pg_bin / "psql",
                    python_executable=python_bin, bash_executable=bash_bin,
                    sh_executable=sh_bin, python_stdlib=(stdlib,),
                    test_utilities=(), require_full_runtime=True,
                )

            build_fixture(destination)
            manifest_path = destination / "etc/statekit-rootfs.manifest"
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            self.assertEqual(manifest["format"], "statekit-rootfs-v1")
            self.assertEqual(manifest["runtime_profile"], "mock-only")
            self.assertNotEqual(manifest["runtime_profile"], "live-executable")
            self.assertEqual(manifest["go_version"], "go1.26.8")
            # PostgreSQL version is recorded only for the live-executable
            # profile; the mock fixture explicitly does not claim it.
            self.assertIsNone(manifest["postgres_version"])
            self.assertEqual(manifest["library_path"], [])
            entries = manifest["entries"]
            manifest_paths = {item["path"] for item in entries}
            self.assertEqual(len(manifest_paths), len(entries))
            self.assertNotIn("/etc/statekit-rootfs.manifest", manifest_paths)
            expected_paths = {
                "/opt/go/bin/go", "/opt/go/bin/gofmt",
                "/opt/go/pkg/tool/linux_amd64/compile", "/opt/go/pkg/include/textflag.h",
                "/opt/go/src/runtime/runtime.go", "/opt/go/VERSION",
                "/opt/go/lib/time/zoneinfo.zip", "/usr/lib/postgresql/16/bin/psql",
                "/usr/bin/python3", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/sh",
                "/usr/lib/python3.14/os.py", "/etc/passwd", "/etc/group",
                "/artifact/statekit", "/bin", "/lib", "/lib64",
                "/out", "/workspace", "/modules", "/proc", "/dev", "/sys", "/tmp",
                "/usr/bin/statekit-rootfs-preflight",
                "/opt/statekit/repo/tests/live/postgres/run.py",
                "/opt/statekit/repo/tests/live/postgres/psql-probe.sh",
            }
            self.assertTrue(expected_paths <= manifest_paths)
            harness_paths = {"/opt/statekit/repo/tests/live/postgres/" + name
                             for name in ("run.py", "psql-probe.sh")}
            self.assertEqual({entry["path"] for entry in entries
                              if entry["path"].startswith("/opt/statekit/repo/")
                              and entry["type"] != "directory"}, harness_paths)
            for key in harness_paths:
                staged = destination / key.lstrip("/")
                source = CI_SCRIPT.parent / Path(key).name
                self.assertEqual(staged.read_bytes(), source.read_bytes())
                self.assertEqual(staged.stat().st_mode & 0o777, source.stat().st_mode & 0o777)
            # Validate missing/tampered harness files against the pinned tree.
            verification_manifest = dict(manifest, go_version=None)
            verified_bytes = json.dumps(verification_manifest, sort_keys=True).encode()
            manifest_path.write_bytes(verified_bytes)
            verified_digest = __import__("hashlib").sha256(verified_bytes).hexdigest()
            for key in harness_paths:
                staged = destination / key.lstrip("/")
                original = staged.read_bytes()
                for mutation in ("missing", "tampered", "mode", "symlink"):
                    with self.subTest(harness_file=key, mutation=mutation):
                        staged.unlink()
                        if mutation == "tampered":
                            staged.write_bytes(original + b"\n# changed\n")
                        elif mutation == "mode":
                            staged.write_bytes(original)
                            staged.chmod(0o777)
                        elif mutation == "symlink":
                            staged.symlink_to(source)
                        with self.assertRaises(rootfs_builder.RootfsError):
                            rootfs_builder.verify_staged_rootfs(
                                destination, manifest_sha256=verified_digest, profile="mock-only")
                        staged.unlink(missing_ok=True)
                        staged.write_bytes(original)
                        staged.chmod(0o644)
            rootfs_builder.verify_staged_rootfs(
                destination, manifest_sha256=verified_digest, profile="mock-only")
            git_directory = destination / "opt/statekit/repo/.git"
            git_directory.mkdir()
            extra_manifest = dict(verification_manifest, entries=sorted(
                [*entries, {"path": "/opt/statekit/repo/.git", "type": "directory", "mode": "0755"}],
                key=lambda entry: entry["path"]))
            extra_bytes = json.dumps(extra_manifest).encode()
            manifest_path.write_bytes(extra_bytes)
            with self.assertRaises(rootfs_builder.RootfsError):
                rootfs_builder.verify_staged_rootfs(destination,
                    manifest_sha256=__import__("hashlib").sha256(extra_bytes).hexdigest(), profile="mock-only")
            git_directory.rmdir()
            # Exercise the actual in-rootfs preflight with no GitHub variables.
            runtime_manifest = dict(manifest, runtime_profile="live-executable", postgres_version="16.15")
            runtime_bytes = json.dumps(runtime_manifest, sort_keys=True).encode()
            manifest_path.write_bytes(runtime_bytes)
            runtime_repo = destination / "opt/statekit/repo"
            with mock.patch.object(pg, "ROOT", runtime_repo), \
                 mock.patch.object(pg, "ROOTFS_REPO", runtime_repo), \
                 mock.patch.object(pg, "ROOTFS_MANIFEST_PATH", manifest_path), \
                 mock.patch.dict(os.environ, {
                     "STATEKIT_ROOTFS_ROLE": "live", "STATEKIT_ROOTFS_RUNTIME": "1",
                     "STATEKIT_ROOTFS_MANIFEST_SHA256": __import__("hashlib").sha256(runtime_bytes).hexdigest(),
                 }, clear=True):
                pg.verify_rootfs_runtime_manifest()
                staged_run = runtime_repo / "tests/live/postgres/run.py"
                original = staged_run.read_bytes()
                staged_run.write_bytes(original + b"\n# tampered\n")
                with self.assertRaises(pg.GateError):
                    pg.verify_rootfs_runtime_manifest()
                staged_run.write_bytes(original)
                wrong_profile = dict(runtime_manifest, runtime_profile="dependency-fetch")
                wrong_bytes = json.dumps(wrong_profile).encode()
                manifest_path.write_bytes(wrong_bytes)
                os.environ["STATEKIT_ROOTFS_MANIFEST_SHA256"] = __import__("hashlib").sha256(wrong_bytes).hexdigest()
                with self.assertRaises(pg.GateError):
                    pg.verify_rootfs_runtime_manifest()
            manifest_path.write_bytes(manifest_bytes)
            self.assertTrue((destination / "usr/lib/postgresql/16/bin/psql").is_file())
            for entry in entries:
                staged = destination / entry["path"].lstrip("/")
                if entry["type"] == "directory":
                    self.assertTrue(staged.is_dir() and not staged.is_symlink())
                elif entry["type"] == "symlink":
                    self.assertTrue(staged.is_symlink())
                    self.assertEqual(os.readlink(staged), entry["target"])
                else:
                    self.assertEqual(
                        __import__("hashlib").sha256(staged.read_bytes()).hexdigest(),
                        entry["sha256"],
                    )
            self.assertFalse(any(
                host_secret.read_bytes() in path.read_bytes()
                for path in destination.rglob("*") if path.is_file()
            ))
            self.assertNotIn(str(runner).encode(), manifest_bytes)

            rootfs_hash = __import__("hashlib").sha256(manifest_bytes).hexdigest()
            inspect = {
                "Rootfs": str(destination),
                "EffectiveCaps": [], "BoundingCaps": [],
                "Config": {
                    "User": "2001:2001",
                    "Labels": {
                        "io.statekit.rootfs.path": str(destination),
                        "io.statekit.rootfs.manifest-sha256": rootfs_hash,
                    },
                    "Env": ["PATH=/usr/bin", "HOME=/tmp", "STATEKIT_ROOTFS_ROLE=mock"],
                },
                "HostConfig": {
                    "Privileged": False, "ReadonlyRootfs": True,
                    "SecurityOpt": ["no-new-privileges"],
                    "CapDrop": sorted(podman_policy.PODMAN_DEFAULT_CAPABILITIES),
                    "CapAdd": [], "NetworkMode": "none", "UsernsMode": "keep-id",
                    "IDMappings": {
                        "UidMap": ["0:1:2001", "2001:0:1"],
                        "GidMap": ["0:1:2001", "2001:0:1"],
                    },
                    "IpcMode": "private", "PidMode": "private", "UTSMode": "private",
                    "Devices": [], "PortBindings": {}, "VolumesFrom": [],
                    "Memory": 4 << 30, "NanoCpus": 2_000_000_000,
                    "PidsLimit": 256, "ShmSize": 64 << 20,
                    "Binds": ["/workspace:/workspace:ro"],
                    "Tmpfs": {
                        "/tmp": "rw,nosuid,nodev,size=2g,mode=1777",
                        "/dev/shm": "rw,nosuid,nodev,noexec,size=64m,mode=1777",
                    },
                },
                "Mounts": [
                    {"Type": "bind", "Source": str(ROOT),
                     "Destination": "/workspace", "RW": False,
                     "Options": ["rbind", "nosuid", "nodev", "noexec"],
                     "Propagation": "rprivate"},
                    {"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True,
                     "Options": ["rw", "nosuid", "nodev", "size=2g"]},
                    {"Type": "tmpfs", "Source": "tmpfs", "Destination": "/dev/shm", "RW": True,
                     "Options": ["rw", "nosuid", "nodev", "noexec", "size=64m"]},
                    {"Type": "proc", "Source": "proc", "Destination": "/proc", "RW": True},
                    {"Type": "devpts", "Source": "devpts", "Destination": "/dev/pts", "RW": True},
                    {"Type": "sysfs", "Source": "sysfs", "Destination": "/sys", "RW": False},
                    {"Type": "mqueue", "Source": "mqueue", "Destination": "/dev/mqueue", "RW": True},
                ],
            }
            policy_args = {
                "expected_user": "2001:2001", "expected_network": "none",
                "expected_rootfs": destination, "expected_manifest_sha256": rootfs_hash,
                "expected_binds": {"/workspace": (ROOT, False)},
                "expected_tmpfs": {
                    "/tmp": ("rw", "nosuid", "nodev", "size=2g", "mode=1777"),
                    "/dev/shm": ("rw", "nosuid", "nodev", "noexec", "size=64m", "mode=1777"),
                },
                "expected_env_names": {"PATH", "HOME", "STATEKIT_ROOTFS_ROLE"}, "memory_bytes": 4 << 30,
                "nano_cpus": 2_000_000_000, "pids_limit": 256,
            }
            podman_policy.verify_inspect(inspect, **policy_args)
            bad_inspect = json.loads(json.dumps(inspect))
            bad_inspect["Mounts"].append({
                "Type": "bind", "Source": "/", "Destination": "/host", "RW": True,
            })
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(bad_inspect, **policy_args)
            bad_environment = json.loads(json.dumps(inspect))
            bad_environment["Config"]["Env"].append("CONTAINER_HOST=forbidden-fixture")
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(bad_environment, **policy_args)
            bad_network = json.loads(json.dumps(inspect))
            bad_network["HostConfig"]["NetworkMode"] = "host"
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(bad_network, **policy_args)
            # SEC-02: labels are never rootfs proof. A snapshot without an
            # authoritative Rootfs/RootfsPath/GraphDriver source fails closed,
            # a wrong one fails, and a matching GraphDriver source is accepted.
            no_rootfs = json.loads(json.dumps(inspect))
            del no_rootfs["Rootfs"]
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(no_rootfs, **policy_args)
            wrong_rootfs = json.loads(json.dumps(inspect))
            wrong_rootfs["Rootfs"] = str(fixture / "not-the-rootfs")
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(wrong_rootfs, **policy_args)
            graph_only = json.loads(json.dumps(inspect))
            del graph_only["Rootfs"]
            graph_only["GraphDriver"] = {
                "Name": "vfs",
                "Data": {"MergedDir": str(destination)},
            }
            podman_policy.verify_inspect(graph_only, **policy_args)

            artifact = fixture / "artifacts/statekit"
            artifact.parent.mkdir()
            artifact.write_bytes(b"executable-fixture")
            artifact.chmod(0o555)
            artifact_inspect = json.loads(json.dumps(inspect))
            artifact_inspect["Config"]["Env"][-1] = "STATEKIT_ROOTFS_ROLE=live"
            artifact_inspect["HostConfig"]["NetworkMode"] = "host"
            artifact_inspect["Mounts"][0]["Destination"] = "/out"
            artifact_inspect["Mounts"][0]["RW"] = True
            artifact_inspect["HostConfig"]["Binds"].append(f"{artifact}:/artifact/statekit:ro,exec,nosuid,nodev")
            artifact_inspect["Mounts"].append({
                "Type": "bind", "Source": str(artifact), "Destination": "/artifact/statekit",
                "RW": False, "Options": ["rbind", "nosuid", "nodev"],
                "Propagation": "rprivate",
            })
            artifact_args = {**policy_args, "expected_network": "host", "expected_binds": {
                "/out": (ROOT, True), "/artifact/statekit": (artifact, False),
            }}
            podman_policy.verify_inspect(artifact_inspect, **artifact_args)
            for field, value in (
                ("Destination", "/artifact"), ("Destination", "/unknown"),
                ("Source", str(artifact.parent)), ("RW", True), ("RW", None),
                ("Options", ["nosuid", "nodev", "noexec"]),
                ("Options", ["nosuid", "nodev", "rw"]),
                ("Options", ["nodev"]), ("Options", ["nosuid"]),
            ):
                with self.subTest(artifact_field=field, value=value):
                    bad = json.loads(json.dumps(artifact_inspect))
                    bad["Mounts"][-1][field] = value
                    with self.assertRaises(podman_policy.PolicyError):
                        podman_policy.verify_inspect(bad, **artifact_args)
            artifact.chmod(0o444)
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(artifact_inspect, **artifact_args)
            artifact.unlink()
            artifact.mkdir()
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(artifact_inspect, **artifact_args)
            artifact.rmdir()
            artifact.symlink_to(destination / "usr/bin/bash")
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(artifact_inspect, **artifact_args)
            artifact.unlink()
            artifact.write_bytes(b"executable-fixture")
            artifact.chmod(0o555)
            target = destination / "artifact/statekit"
            target.unlink()
            target.mkdir()
            with self.assertRaises(podman_policy.PolicyError):
                podman_policy.verify_inspect(artifact_inspect, **artifact_args)
            target.rmdir()
            target.touch(mode=0o644)

            # Exercise the real shell verifier with phase-specific inspect
            # snapshots, not just a search for the right call-site spelling.
            controller = CI_SCRIPT.read_text(encoding="utf-8")
            verifier = "verify_podman_container() {" + controller.split(
                "verify_podman_container() {", 1
            )[1].split("\n}", 1)[0] + "\n}\n"
            verifier = verifier.replace("/usr/bin/python3", shlex.quote(sys.executable))
            if os.environ.get("STATEKIT_DEBUG_POLICY"):
                verifier = verifier.replace(">/dev/null 2>&1; then", "; then")
            snapshot_path = fixture / "inspect.json"
            deps_dir = fixture / "deps"
            modules_dir = fixture / "modules"
            out_dir = fixture / "out"
            for directory in (deps_dir, modules_dir, out_dir):
                directory.mkdir()
            phase_binds: dict[str, dict[str, tuple[Path, bool]]] = {
                "fetch": {"/deps": (deps_dir, False), "/modules": (modules_dir, True)},
                "build": {"/workspace": (ROOT, False), "/modules": (modules_dir, False),
                          "/out": (out_dir, True)},
                "mock": {"/workspace": (ROOT, False)},
                # Only the executable and dedicated report directory cross
                # the live boundary. Harness and credentials are not binds.
                "live": {"/artifact/statekit": (artifact, False),
                         "/out": (out_dir, True)},
            }

            def phase_snapshot(binds: dict[str, tuple[Path, bool]]) -> dict[str, object]:
                snapshot = json.loads(json.dumps(inspect))
                snapshot["HostConfig"]["Binds"] = [
                    f"{source}:{destination}:{'rw' if read_write else 'ro'}"
                    for destination, (source, read_write) in binds.items()
                ]
                preserved = [mount for mount in snapshot["Mounts"]
                             if mount["Type"] != "bind"]
                bind_mounts = []
                for destination, (source, read_write) in binds.items():
                    options = ["rbind", "nosuid", "nodev"]
                    if destination != "/artifact/statekit":
                        options.append("noexec")
                    bind_mounts.append({
                        "Type": "bind", "Source": str(source),
                        "Destination": destination, "RW": read_write,
                        "Options": options, "Propagation": "rprivate",
                    })
                snapshot["Mounts"] = preserved + bind_mounts
                return snapshot

            def run_verifier(snapshot: dict[str, object], phase: str,
                             phase_root: Path, phase_digest: str, network: str) -> None:
                snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
                policy_identity = fixture / "policy-identity"
                policy_identity.unlink(missing_ok=True)
                binds_fixture = [
                    f"{destination}={source}:{'rw' if read_write else 'ro'}"
                    for destination, (source, read_write) in phase_binds[phase].items()
                ]
                command = verifier + f'''
verify_exec_mount_identity() {{ return 0; }}
podman_as_test_user() {{
  local snapshot_line=''
  while IFS= read -r snapshot_line || [[ -n "$snapshot_line" ]]; do
    printf '%s\n' "$snapshot_line"
  done < "$SNAPSHOT"
}}
run_as_test_user() {{
  printf '%s' "$test_uid:$test_gid" > "$POLICY_IDENTITY"
  shift
  "$@"
}}
ROOT="$PWD"
test_uid=2001 test_gid=2001
rootfs_dir=/wrong-global-rootfs rootfs_manifest_sha256=wrong-global-digest
env_names_fixture=(PATH HOME STATEKIT_ROOTFS_ROLE)
binds_fixture=({shlex.join(binds_fixture)})
verify_podman_container fixture "$NETWORK" env_names_fixture binds_fixture "$EXPECTED_ROOT" "$EXPECTED_DIGEST"
'''
                completed = subprocess.run(
                    ["bash", "-euc", command], cwd=ROOT,
                    env={"PATH": os.environ["PATH"], "SNAPSHOT": str(snapshot_path),
                         "NETWORK": network, "EXPECTED_ROOT": str(phase_root),
                         "EXPECTED_DIGEST": phase_digest,
                         "POLICY_IDENTITY": str(policy_identity)},
                    capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertTrue(policy_identity.exists(),
                                "policy must inspect private paths as their owner")
                self.assertEqual(policy_identity.read_text(encoding="utf-8"), "2001:2001")

            for phase in ("fetch", "build", "mock", "live"):
                # The live phase carries the /artifact/statekit file bind, so
                # its expected rootfs must be the really staged tree (which
                # contains the staged target file); other phases use
                # fabricated roots because no file-bind branch applies.
                phase_root = (destination if phase == "live"
                              else fixture / ("rootfs-fetch" if phase == "fetch" else "rootfs"))
                phase_digest = ("f" if phase == "fetch" else "a") * 64
                network = "host" if phase in ("fetch", "live") else "none"
                snapshot = phase_snapshot(phase_binds[phase])
                snapshot["Config"]["Env"][-1] = f"STATEKIT_ROOTFS_ROLE={phase}"
                snapshot["Rootfs"] = str(phase_root)
                snapshot["Config"]["Labels"] = {
                    "io.statekit.rootfs.path": str(phase_root),
                    "io.statekit.rootfs.manifest-sha256": phase_digest,
                }
                snapshot["HostConfig"]["NetworkMode"] = network
                with self.subTest(phase=phase):
                    run_verifier(snapshot, phase, phase_root, phase_digest, network)
                if phase == "live":
                    for forbidden in ("/workspace", "/run/pgpass"):
                        bad_binds = {**phase_binds[phase], forbidden: (ROOT, False)}
                        bad = phase_snapshot(bad_binds)
                        bad["Config"]["Env"][-1] = "STATEKIT_ROOTFS_ROLE=live"
                        bad["HostConfig"]["NetworkMode"] = "host"
                        with self.assertRaises(podman_policy.PolicyError):
                            podman_policy.verify_inspect(bad, **{
                                **policy_args, "expected_network": "host", "expected_binds": bad_binds})
                for mismatch in ("rootfs", "digest"):
                    with self.subTest(phase=phase, mismatch=mismatch):
                        bad = json.loads(json.dumps(snapshot))
                        if mismatch == "rootfs":
                            bad["Rootfs"] = str(fixture / "other-rootfs")
                        else:
                            bad["Config"]["Labels"]["io.statekit.rootfs.manifest-sha256"] = "b" * 64
                        snapshot_path.write_text(json.dumps(bad), encoding="utf-8")
                        policy_identity = fixture / "policy-identity"
                        policy_identity.unlink(missing_ok=True)
                        binds_fixture = [
                            f"{destination}={source}:{'rw' if read_write else 'ro'}"
                            for destination, (source, read_write) in phase_binds[phase].items()
                        ]
                        command = verifier + f'''
verify_exec_mount_identity() {{ return 0; }}
podman_as_test_user() {{
  local snapshot_line=''
  while IFS= read -r snapshot_line || [[ -n "$snapshot_line" ]]; do
    printf '%s\n' "$snapshot_line"
  done < "$SNAPSHOT"
}}
run_as_test_user() {{
  printf '%s' "$test_uid:$test_gid" > "$POLICY_IDENTITY"
  shift
  "$@"
}}
ROOT="$PWD"
test_uid=2001 test_gid=2001
rootfs_dir=/wrong-global-rootfs rootfs_manifest_sha256=wrong-global-digest
env_names_fixture=(PATH HOME STATEKIT_ROOTFS_ROLE)
binds_fixture=({shlex.join(binds_fixture)})
verify_podman_container fixture "$NETWORK" env_names_fixture binds_fixture "$EXPECTED_ROOT" "$EXPECTED_DIGEST"
'''
                        completed = subprocess.run(
                            ["bash", "-euc", command], cwd=ROOT,
                            env={"PATH": os.environ["PATH"], "SNAPSHOT": str(snapshot_path),
                                 "NETWORK": network, "EXPECTED_ROOT": str(phase_root),
                                 "EXPECTED_DIGEST": phase_digest,
                                 "POLICY_IDENTITY": str(policy_identity)},
                            capture_output=True, text=True, timeout=15,
                        )
                        self.assertEqual(completed.returncode, 1, completed.stderr)
            # The inspect policy must reject a live container that still
            # receives the checkout: swapped in instead of the staged
            # harness, or attached as one extra bind alongside it.
            for checkout_case in ("instead", "extra"):
                with self.subTest(live_checkout_bind=checkout_case):
                    bad = phase_snapshot(phase_binds["live"])
                    bad["Config"]["Env"][-1] = "STATEKIT_ROOTFS_ROLE=live"
                    bad["Rootfs"] = str(destination)
                    bad["Config"]["Labels"] = {
                        "io.statekit.rootfs.path": str(destination),
                        "io.statekit.rootfs.manifest-sha256": "a" * 64,
                    }
                    bad["HostConfig"]["NetworkMode"] = "host"
                    forbidden_destination = "/workspace" if checkout_case == "instead" else "/checkout"
                    bad["HostConfig"]["Binds"].append(f"{ROOT}:{forbidden_destination}:ro")
                    bad["Mounts"].append({
                            "Type": "bind", "Source": str(ROOT),
                            "Destination": forbidden_destination, "RW": False,
                            "Options": ["rbind", "nosuid", "nodev", "noexec"],
                            "Propagation": "rprivate",
                        })
                    snapshot_path.write_text(json.dumps(bad), encoding="utf-8")
                    binds_fixture = [
                        f"{destination}={source}:{'rw' if read_write else 'ro'}"
                        for destination, (source, read_write) in phase_binds["live"].items()
                    ]
                    command = verifier + f'''
verify_exec_mount_identity() {{ return 0; }}
podman_as_test_user() {{
  local snapshot_line=''
  while IFS= read -r snapshot_line || [[ -n "$snapshot_line" ]]; do
    printf '%s\n' "$snapshot_line"
  done < "$SNAPSHOT"
}}
run_as_test_user() {{
  printf '%s' "$test_uid:$test_gid" > "$POLICY_IDENTITY"
  shift
  "$@"
}}
ROOT="$PWD"
test_uid=2001 test_gid=2001
env_names_fixture=(PATH HOME STATEKIT_ROOTFS_ROLE)
binds_fixture=({shlex.join(binds_fixture)})
verify_podman_container fixture host env_names_fixture binds_fixture "{destination}" {"a" * 64}
'''
                    completed = subprocess.run(
                        ["bash", "-euc", command], cwd=ROOT,
                        env={"PATH": os.environ["PATH"], "SNAPSHOT": str(snapshot_path)},
                        capture_output=True, text=True, timeout=15,
                    )
                    self.assertEqual(completed.returncode, 1, completed.stderr)

            (go_root / "src/runtime/runner-home-link").symlink_to(host_secret)
            rejected_destination = fixture / "escape-rootfs"
            with self.assertRaises(rootfs_builder.RootfsError):
                build_fixture(rejected_destination)
            self.assertFalse(rejected_destination.exists())

        # Mount records are synthetic: this exercises an exec child mount over
        # a noexec /dev/shm parent without mounting anything in the test suite.
        nonce = os.urandom(10).hex()
        mountpoint = Path("/dev/shm") / f"statekit-exec-{nonce}"
        mountpoint.mkdir(mode=0o700)
        mountpoint.chmod(0o700)
        uid, gid = os.getuid(), os.getgid()
        parent = rootfs_builder.MountRecord(
            "/dev/shm", "shm", "tmpfs",
            ("rw", "nosuid", "nodev", "noexec", "relatime", "size=65536k", "inode64"),
        )
        valid_child = rootfs_builder.MountRecord(
            str(mountpoint), "tmpfs", "tmpfs",
            ("rw", "nosuid", "nodev", "relatime", "size=4194304k", "mode=700", "inode64"),
        )
        flags = getattr(os, "ST_NOSUID", 0) | getattr(os, "ST_NODEV", 0)
        exec_flags = lambda _path: flags
        try:
            records = {Path("/dev/shm"): parent, mountpoint: valid_child}

            def probe(path: Path) -> rootfs_builder.MountRecord | None:
                return records.get(path)

            rootfs_builder.verify_exec_mount(
                mountpoint, uid=uid, gid=gid, mount_probe=probe,
                vfs_flags_probe=exec_flags,
            )
            self.assertIn("exec", rootfs_builder._mount_record(mountpoint, probe).options)
            rootfs_builder.preflight_exec_mountpoint(
                Path("/dev/shm") / f"statekit-exec-{os.urandom(10).hex()}",
                mount_probe=probe,
            )

            bad_children = (
                rootfs_builder.MountRecord(
                    str(mountpoint), "tmpfs", "ext4", valid_child.options,
                ),
                rootfs_builder.MountRecord(
                    str(mountpoint), "/dev/shm", "tmpfs", valid_child.options,
                ),
                rootfs_builder.MountRecord(
                    str(mountpoint), "tmpfs", "tmpfs",
                    tuple("ro" if option == "rw" else option for option in valid_child.options),
                ),
                rootfs_builder.MountRecord(
                    str(mountpoint), "tmpfs", "tmpfs",
                    (*valid_child.options, "noexec"),
                ),
                rootfs_builder.MountRecord(
                    str(mountpoint), "tmpfs", "tmpfs",
                    tuple("mode=777" if option == "mode=700" else option
                          for option in valid_child.options),
                ),
                rootfs_builder.MountRecord(
                    str(mountpoint), "tmpfs", "tmpfs",
                    tuple(option for option in valid_child.options if option != "nosuid"),
                ),
                rootfs_builder.MountRecord(
                    str(mountpoint), "tmpfs", "tmpfs",
                    tuple("size=1g" if option.startswith("size=") else option
                          for option in valid_child.options),
                ),
            )
            for bad_child in bad_children:
                with self.subTest(options=bad_child.options), \
                     self.assertRaises(rootfs_builder.RootfsError):
                    rootfs_builder.verify_exec_mount(
                        mountpoint, uid=uid, gid=gid,
                        mount_probe=lambda path, child=bad_child:
                            parent if path == Path("/dev/shm") else child,
                        vfs_flags_probe=exec_flags,
                    )
            with self.assertRaises(rootfs_builder.RootfsError):
                rootfs_builder.verify_exec_mount(
                    mountpoint, uid=uid + 1, gid=gid, mount_probe=probe,
                    vfs_flags_probe=exec_flags,
                )
            with self.assertRaises(rootfs_builder.RootfsError):
                rootfs_builder.verify_exec_mount(
                    mountpoint / "escape", uid=uid, gid=gid, mount_probe=probe,
                    vfs_flags_probe=exec_flags,
                )
            bad_parent = rootfs_builder.MountRecord(
                "/dev/shm", "shm", "tmpfs",
                ("rw", "nosuid", "nodev", "exec", "relatime"),
            )
            with self.assertRaises(rootfs_builder.RootfsError):
                rootfs_builder.preflight_exec_mountpoint(
                    Path("/dev/shm") / f"statekit-exec-{os.urandom(10).hex()}",
                    mount_probe=lambda _path: bad_parent,
                )

            symlink = Path("/dev/shm") / f"statekit-exec-{os.urandom(10).hex()}"
            symlink.symlink_to(mountpoint, target_is_directory=True)
            try:
                with self.assertRaises(rootfs_builder.RootfsError):
                    rootfs_builder.verify_exec_mount(
                        symlink, uid=uid, gid=gid,
                        mount_probe=lambda path:
                            parent if path == Path("/dev/shm") else valid_child,
                        vfs_flags_probe=exec_flags,
                    )
            finally:
                symlink.unlink()

            cleanup_events: list[tuple[str, Path]] = []
            mounted = True

            def cleanup_probe(path: Path) -> rootfs_builder.MountRecord | None:
                cleanup_events.append(("findmnt", path))
                if path == Path("/dev/shm"):
                    return parent
                return valid_child if mounted else None

            def fake_unmount(path: Path) -> None:
                nonlocal mounted
                cleanup_events.append(("umount", path))
                mounted = False

            rootfs_builder.cleanup_exec_mount(
                mountpoint, uid=uid, gid=gid, runner_uid=uid, runner_gid=gid,
                mount_probe=cleanup_probe, vfs_flags_probe=exec_flags,
                unmount=fake_unmount,
            )
            self.assertEqual(
                [event[0] for event in cleanup_events],
                ["findmnt", "findmnt", "umount", "findmnt", "findmnt"],
            )
            self.assertEqual(cleanup_events[2], ("umount", mountpoint))
            self.assertEqual(cleanup_events[4], ("findmnt", mountpoint))
            self.assertFalse(mountpoint.exists())

            mountpoint.mkdir(mode=0o700)
            mountpoint.chmod(0o700)
            mounted = True
            with self.assertRaises(rootfs_builder.RootfsError):
                rootfs_builder.cleanup_exec_mount(
                    mountpoint, uid=uid, gid=gid, runner_uid=uid, runner_gid=gid,
                    mount_probe=cleanup_probe, vfs_flags_probe=exec_flags,
                    unmount=lambda _path: None,
                )
            self.assertTrue(mountpoint.is_dir())
        finally:
            if mountpoint.exists() and not mountpoint.is_symlink():
                mountpoint.rmdir()

    def test_container_existence_tri_state_lifecycle(self) -> None:
        # SEC-01 / R92T-INDEPENDENT-01 behavioral check: the controller's
        # tri-state `container exists` handling and ownership-receipt
        # lifecycle are exercised for present/absent/unknown through
        # reserve, create, reconcile, receipt-only removal by canonical ID,
        # repeated cleanup, and mount teardown with a mocked Podman client
        # inside the controller's own self-test mode.
        completed = subprocess.run(
            ["bash", str(CI_SCRIPT), "--container-lifecycle-self-test"], cwd=ROOT,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
            check=False, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

        controller = CI_SCRIPT.read_text(encoding="utf-8")
        # Define the real controller functions, but never enter its live body.
        definitions = "readonly ROOT" + controller.split("readonly ROOT", 1)[1].split(
            '\ncase "$self_test_mode" in', 1
        )[0]
        normal_teardown = controller.split("# Teardown is verified before report publication.", 1)[1].split(
            'sudo_bounded chown "$RUNNER_UID:$RUNNER_GID" "$run_dir"', 1
        )[0]
        # Discard the remainder of the introductory comment's first line.
        normal_teardown = normal_teardown[normal_teardown.index("\n"):]
        mocks = r'''
test_user=fixture-user test_uid=2001 test_gid=2001
run_nonce=0123456789abcdef0123
work_dir="$FIXTURE/owned-workspace"
live_container=live mock_container=mock build_container=build fetch_container=fetch
cluster_started=1
fetch_id="$(printf '%064d' 1)" build_id="$(printf '%064d' 2)"
mock_id="$(printf '%064d' 3)" live_id="$(printf '%064d' 4)"
fetch_digest="$(printf '%064d' 5)" build_digest="$(printf '%064d' 6)"
mock_digest="$(printf '%064d' 7)" live_digest="$(printf '%064d' 8)"
container_receipt=(
  "$fetch_id|fetch|fetch|$fetch_digest|$run_nonce"
  "$build_id|build|build|$build_digest|$run_nonce"
  "$mock_id|mock|mock|$mock_digest|$run_nonce"
  "$live_id|live|live|$live_digest|$run_nonce"
)
seed_identity() {
  printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$run_nonce" "$3" "$4" > "$FIXTURE/identity-$1"
}
seed_identity "$fetch_id" fetch fetch "$fetch_digest"
seed_identity "$build_id" build build "$build_digest"
seed_identity "$mock_id" mock mock "$mock_digest"
seed_identity "$live_id" live live "$live_digest"
rootfs_dir="$FIXTURE/rootfs" fetch_rootfs_dir="$FIXTURE/rootfs-fetch"
exec_artifacts_dir="$FIXTURE/artifacts" exec_mountpoint="$FIXTURE/exec"
trace() { printf '%s\n' "$*" >> "$FIXTURE/trace"; }
podman_as_test_user() {
  trace "podman:$test_uid:$*"
  [[ -n "$test_uid" && ! -e "$FIXTURE/user-deleted" ]] || return 125
  case "$1 $2" in
    'container exists')
      [[ "$FAIL_STAGE" != unknown ]] || return 125
      [[ ! -e "$FIXTURE/absent-$3" ]] ;;
    'rm --force')
      [[ "$FAIL_STAGE" != containers ]] || return 1
      : > "$FIXTURE/absent-$3" ;;
    'inspect --format')
      local id_='' name_='' nonce_='' phase_='' digest_=''
      [[ "$3" == "$CONTAINER_OWNERSHIP_FORMAT" ]] || return 125
      IFS='|' read -r id_ name_ nonce_ phase_ digest_ < "$FIXTURE/identity-$4" || return 1
      [[ "$FAIL_STAGE" != ownership ]] || nonce_=ffffffffffffffffffff
      printf '%s|%s|%s|%s|%s\n' "$id_" "$name_" "$nonce_" "$phase_" "$digest_" ;;
    'ps --all')
      [[ ! -e "$FIXTURE/ps-error" ]] || return 125
      [[ ! -e "$FIXTURE/ps-listing" ]] || printf '%064d\n' 9
      return 0 ;;
    *) return 125 ;;
  esac
}
bounded_timeout() {
  shift
  case "$1 $2" in
    'getent passwd')
      [[ ! -e "$FIXTURE/user-deleted" ]] || return 2
      printf 'fixture-user:x:2001:2001::%s/home:/usr/sbin/nologin\n' "$work_dir" ;;
    'getent group')
      [[ ! -e "$FIXTURE/group-deleted" ]] || return 2
      printf 'fixture-user:x:2001:\n' ;;
    'pgrep -u') [[ "$FAIL_STAGE" == processes ]] ;;
    'python3 tests/live/postgres/run.py')
      [[ "$3" == "--assert-cluster-down" ]] || return 1 ;;
    *) "$@" ;;
  esac
}
sudo_bounded() {
  case "$1" in
    pkill) trace "stop:$test_uid" ;;
    pg_ctlcluster) trace cluster-stop ;;
    userdel)
      trace "identity:$test_uid"
      [[ "$FAIL_STAGE" != identity ]] || return 1
      : > "$FIXTURE/user-deleted" ;;
    groupdel) : > "$FIXTURE/group-deleted" ;;
    *) trace "unexpected-sudo:$1"; return 1 ;;
  esac
}
remove_rootfs() {
  trace rootfs
  [[ "$FAIL_STAGE" != rootfs ]] || return 1
  rm -r -- "$rootfs_dir"
}
remove_fetch_rootfs() {
  trace fetch-rootfs
  [[ "$FAIL_STAGE" != fetch-rootfs ]] || return 1
  rm -r -- "$fetch_rootfs_dir"
}
remove_exec_artifacts() {
  trace artifacts
  [[ "$FAIL_STAGE" != artifacts ]] || return 1
  rm -r -- "$exec_artifacts_dir"
}
remove_exec_mount() {
  trace exec-mount
  verify_containers_absent || return 1
  [[ ! -e "$rootfs_dir" && ! -e "$fetch_rootfs_dir" && ! -e "$exec_artifacts_dir" ]] || return 1
  [[ "$FAIL_STAGE" != exec-mount ]] || return 1
  rm -r -- "$exec_mountpoint"
}
cleanup_workspace() {
  trace workspace
  [[ -e "$FIXTURE/user-deleted" && -e "$FIXTURE/group-deleted" ]] || return 1
  [[ "$FAIL_STAGE" != workspace ]] || return 1
  rm -r -- "$1"
}
trap cleanup EXIT
# A previously published report must be invalidated by any cleanup failure.
artifact_created=1
'''
        for failure in ("none", "containers", "unknown", "ownership", "processes",
                        "rootfs", "fetch-rootfs", "artifacts", "exec-mount", "identity",
                        "workspace"):
            with self.subTest(cleanup_failure=failure), tempfile.TemporaryDirectory() as directory:
                fixture = Path(directory)
                for name in ("rootfs", "rootfs-fetch", "artifacts", "exec", "owned-workspace"):
                    (fixture / name).mkdir()
                # Keep report publication separate from the mocked exec artifacts.
                workspace = fixture / "workspace"
                report = workspace / "artifacts/postgres-live/report.txt"
                report.parent.mkdir(parents=True)
                report.write_text("value-free-report\n", encoding="utf-8")
                command = "set -euo pipefail\n" + definitions + mocks + normal_teardown + '''
cleanup_identity_and_files
[[ "$cleanup_failed" == 0 ]] || fixed_error 'test-workspace-cleanup-failed'
'''
                completed = subprocess.run(
                    ["bash", "-c", command], cwd=ROOT,
                    env={"PATH": os.environ["PATH"], "FIXTURE": str(fixture),
                         "FAIL_STAGE": failure, "GITHUB_WORKSPACE": str(workspace)},
                    capture_output=True, text=True, timeout=30,
                )
                events = (fixture / "trace").read_text(encoding="utf-8").splitlines()
                self.assertFalse(any(event.startswith("unexpected-sudo:") for event in events), events)
                self.assertEqual(completed.returncode, 0 if failure == "none" else 1,
                                 completed.stderr + repr(events))
                self.assertEqual(report.exists(), failure == "none", events)
                # R92T-FRESH-01 residual: with a cluster start attempt
                # recorded, the cluster-wide stop runs exactly once on every
                # unblocked path and never once the block latches.
                self.assertEqual(
                    events.count("cluster-stop"),
                    0 if failure in ("unknown", "ownership") else 1, events)
                receipt_ids = tuple(digit.zfill(64) for digit in "1234")
                if failure == "none":
                    for stage in ("rootfs", "fetch-rootfs", "artifacts", "exec-mount", "identity:2001", "workspace"):
                        self.assertEqual(events.count(stage), 1, events)
                    self.assertLess(events.index("fetch-rootfs"), events.index("exec-mount"))
                    self.assertLess(events.index("exec-mount"), events.index("identity:2001"))
                    self.assertFalse(any(event.startswith("podman:")
                                         for event in events[events.index("identity:2001") + 1:]), events)
                    # Every receipt-held container was removed by canonical ID.
                    for canonical_id in receipt_ids:
                        self.assertTrue((fixture / f"absent-{canonical_id}").exists(), events)
                elif failure in ("containers", "unknown", "ownership"):
                    self.assertFalse(any(event in ("rootfs", "fetch-rootfs", "artifacts", "exec-mount")
                                         or event.startswith(("identity:", "stop:")) for event in events), events)
                    self.assertFalse((fixture / "user-deleted").exists())
                    # rm failure, unknown existence, and foreign labels all
                    # preserve every object instead of deleting by name.
                    for canonical_id in receipt_ids:
                        self.assertFalse((fixture / f"absent-{canonical_id}").exists(), events)
                elif failure == "processes":
                    self.assertFalse(any(event in ("rootfs", "fetch-rootfs", "artifacts", "exec-mount")
                                         or event.startswith("identity:") for event in events), events)
                    self.assertFalse((fixture / "user-deleted").exists())
                elif failure not in ("identity", "workspace"):
                    self.assertNotIn("identity:2001", events)
                    self.assertFalse((fixture / "user-deleted").exists())
                if failure == "workspace":
                    self.assertTrue((fixture / "user-deleted").exists())
                    self.assertFalse(any(event.startswith("podman:")
                                          for event in events[events.index("identity:2001") + 1:]), events)

        # R92T-INDEPENDENT-01 behavior-level mocks with a mocked Podman
        # client: a candidate container name is not ownership. Removal acts
        # only on receipt-held canonical IDs whose inspected identity still
        # matches the receipt; every foreign or ambiguous object is
        # preserved and the run fails closed.
        owner_mock = r'''
FIXTURE_DIR="${FIXTURE:?}"
run_nonce=0123456789abcdef0123
probe_name=probe-name
probe_id="$(printf '%064d' 1)"
other_id="$(printf '%064d' 2)"
owned_digest="$(printf '%064d' 3)"
foreign_digest="$(printf '%064d' 4)"
containers_cleaned=0
container_receipt=()
state_of() {
  local value=''
  if IFS= read -r value < "$1" 2>/dev/null && [[ "$value" == present || "$value" == absent ]]; then
    printf '%s\n' "$value"
  else
    printf 'unknown\n'
  fi
}
seed() {
  # $1 id, $2 name, $3 phase, $4 digest, $5 nonce: one present container
  # visible under both its canonical ID and its name.
  printf 'present\n' > "$FIXTURE_DIR/state-$1"
  printf 'present\n' > "$FIXTURE_DIR/state-$2"
  printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$5" "$3" "$4" > "$FIXTURE_DIR/identity-$1"
  printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$5" "$3" "$4" > "$FIXTURE_DIR/identity-$2"
}
podman_as_test_user() {
  case "$1 $2" in
    'container exists')
      case "$(state_of "$FIXTURE_DIR/state-$3")" in
        present) return 0 ;;
        absent) return 1 ;;
        *) return 125 ;;
      esac ;;
    'inspect --format')
      local line=''
      [[ "$3" == "$CONTAINER_OWNERSHIP_FORMAT" ]] || return 125
      IFS= read -r line < "$FIXTURE_DIR/identity-$4" || return 1
      printf '%s\n' "$line" ;;
    'ps --all')
      if [[ -e "$FIXTURE_DIR/ps-error" ]]; then return 125; fi
      if [[ -e "$FIXTURE_DIR/ps-listing" ]]; then printf '%064d\n' 9; fi
      return 0 ;;
    'rm --force')
      [[ ! -e "$FIXTURE_DIR/rm-fail" ]] || return 1
      local held_id='' held_name=''
      if IFS='|' read -r held_id held_name _ _ _ < "$FIXTURE_DIR/identity-$3" 2>/dev/null; then
        printf 'absent\n' > "$FIXTURE_DIR/state-$held_id"
        printf 'absent\n' > "$FIXTURE_DIR/state-$held_name"
      fi
      printf 'absent\n' > "$FIXTURE_DIR/state-$3"
      printf '%s\n' "$3" >> "$FIXTURE_DIR/rm-log" ;;
    *) return 125 ;;
  esac
}
'''

        def run_owner(body: str, fixture: Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", "-c", "set -euo pipefail\n" + definitions + owner_mock + body],
                cwd=ROOT,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
                     "FIXTURE": str(fixture)},
                capture_output=True, text=True, timeout=60,
            )

        scenarios: tuple[tuple[str, str], ...] = (
            ("preexisting collision preserved through cleanup", '''
seed "$other_id" "$probe_name" live "$foreign_digest" ffffffffffffffffffff
container_must_be_absent "$probe_name" && exit 9
[[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || exit 15
verify_containers_absent || exit 10
cleanup_all_containers || exit 11
[[ "$(state_of "$FIXTURE_DIR/state-$other_id")" == present ]] || exit 12
[[ "$(state_of "$FIXTURE_DIR/state-$probe_name")" == present ]] || exit 13
[[ ! -e "$FIXTURE_DIR/rm-log" ]] || exit 14
'''),
            ("same-name unknown object preserved", '''
seed "$other_id" "$probe_name" live "$foreign_digest" ffffffffffffffffffff
rm -f "$FIXTURE_DIR/state-$probe_name" "$FIXTURE_DIR/state-$other_id"
container_must_be_absent "$probe_name" && exit 9
[[ "$unowned_or_unknown_resource" == 1 ]] || exit 12
cleanup_all_containers || exit 10
[[ ! -e "$FIXTURE_DIR/rm-log" ]] || exit 11
'''),
            ("created container later failed cleaned by canonical id", '''
seed "$other_id" foreign-snap live "$foreign_digest" ffffffffffffffffffff
seed "$probe_id" "$probe_name" mock "$owned_digest" "$run_nonce"
container_receipt_claim "$probe_id" "$probe_name" mock "$owned_digest" "$run_nonce" || exit 9
cleanup_all_containers || exit 10
[[ "$(state_of "$FIXTURE_DIR/state-$probe_id")" == absent ]] || exit 11
[[ "$(state_of "$FIXTURE_DIR/state-$other_id")" == present ]] || exit 12
mapfile -t entries < "$FIXTURE_DIR/rm-log"
(( ${#entries[@]} == 1 )) || exit 13
[[ "${entries[0]}" == "$probe_id" ]] || exit 14
cleanup_all_containers || exit 15
verify_containers_absent || exit 16
[[ "$unowned_or_unknown_resource" == 0 && "$destructive_teardown_blocked" == 0 ]] || exit 17
'''),
            ("partial create with matching ownership cleaned", '''
seed "$probe_id" "$probe_name" fetch "$owned_digest" "$run_nonce"
reconcile_partial_create "$probe_name" fetch "$owned_digest" || exit 9
[[ "${container_receipt[0]}" == "$probe_id|$probe_name|fetch|$owned_digest|$run_nonce" ]] || exit 10
cleanup_all_containers || exit 11
[[ "$(state_of "$FIXTURE_DIR/state-$probe_id")" == absent ]] || exit 12
mapfile -t entries < "$FIXTURE_DIR/rm-log"
(( ${#entries[@]} == 1 )) || exit 13
[[ "${entries[0]}" == "$probe_id" ]] || exit 14
'''),
            ("partial create mismatch and inspect failure preserved", '''
seed "$probe_id" "$probe_name" fetch "$foreign_digest" "$run_nonce"
status=0
reconcile_partial_create "$probe_name" fetch "$owned_digest" || status=$?
[[ "$status" == 2 ]] || exit 9
seed "$probe_id" "$probe_name" fetch "$owned_digest" ffffffffffffffffffff
status=0
reconcile_partial_create "$probe_name" fetch "$owned_digest" || status=$?
[[ "$status" == 2 ]] || exit 10
rm -f "$FIXTURE_DIR/identity-$probe_name" "$FIXTURE_DIR/identity-$probe_id"
status=0
reconcile_partial_create "$probe_name" fetch "$owned_digest" || status=$?
[[ "$status" == 2 ]] || exit 11
printf 'present\n' > "$FIXTURE_DIR/state-$probe_name"
printf 'shortid|%s|%s|fetch|%s\n' "$probe_name" "$run_nonce" "$owned_digest" > "$FIXTURE_DIR/identity-$probe_name"
status=0
reconcile_partial_create "$probe_name" fetch "$owned_digest" || status=$?
[[ "$status" == 2 ]] || exit 12
printf '%s|other-name|%s|fetch|%s\n' "$probe_id" "$run_nonce" "$owned_digest" > "$FIXTURE_DIR/identity-$probe_name"
status=0
reconcile_partial_create "$probe_name" fetch "$owned_digest" || status=$?
[[ "$status" == 2 ]] || exit 13
printf 'absent\n' > "$FIXTURE_DIR/state-$probe_name"
status=0
reconcile_partial_create "$probe_name" fetch "$owned_digest" || status=$?
[[ "$status" == 1 ]] || exit 14
(( ${#container_receipt[@]} == 0 )) || exit 15
[[ ! -e "$FIXTURE_DIR/rm-log" ]] || exit 16
'''),
            ("rm failure preserved and cleanup fails closed", '''
seed "$probe_id" "$probe_name" mock "$owned_digest" "$run_nonce"
container_receipt_claim "$probe_id" "$probe_name" mock "$owned_digest" "$run_nonce" || exit 9
: > "$FIXTURE_DIR/rm-fail"
cleanup_all_containers && exit 10
[[ "$(state_of "$FIXTURE_DIR/state-$probe_id")" == present ]] || exit 11
[[ ! -e "$FIXTURE_DIR/rm-log" ]] || exit 12
[[ "$containers_cleaned" == 0 ]] || exit 13
[[ "$unowned_or_unknown_resource" == 0 ]] || exit 14
'''),
            ("unknown owned container preserved", '''
seed "$probe_id" "$probe_name" mock "$owned_digest" "$run_nonce"
container_receipt_claim "$probe_id" "$probe_name" mock "$owned_digest" "$run_nonce" || exit 9
rm -f "$FIXTURE_DIR/state-$probe_id" "$FIXTURE_DIR/state-$probe_name"
cleanup_all_containers && exit 10
[[ ! -e "$FIXTURE_DIR/rm-log" ]] || exit 11
[[ "$unowned_or_unknown_resource" == 1 ]] || exit 12
'''),
            ("foreign-label identity at cleanup preserved", '''
seed "$probe_id" "$probe_name" mock "$owned_digest" ffffffffffffffffffff
container_receipt_claim "$probe_id" "$probe_name" mock "$owned_digest" "$run_nonce" || exit 9
cleanup_all_containers && exit 10
[[ "$(state_of "$FIXTURE_DIR/state-$probe_id")" == present ]] || exit 11
[[ ! -e "$FIXTURE_DIR/rm-log" ]] || exit 12
[[ "$unowned_or_unknown_resource" == 1 ]] || exit 13
'''),
            ("receipt rejects duplicate and cross-phase claims", '''
container_receipt_claim "$probe_id" first-name mock "$owned_digest" "$run_nonce" || exit 9
container_receipt_claim "$probe_id" second-name live "$owned_digest" "$run_nonce" && exit 10
container_receipt_claim "$other_id" first-name live "$owned_digest" "$run_nonce" && exit 11
container_receipt_claim "$other_id" second-name mock "$owned_digest" "$run_nonce" && exit 12
container_receipt_claim not-canonical third-name live "$owned_digest" "$run_nonce" && exit 13
container_receipt_claim "$other_id" third-name live "$owned_digest" ffffffffffffffffffff && exit 14
container_receipt_release mock
(( ${#container_receipt[@]} == 0 )) || exit 15
'''),
            ("per-phase cleanup removes and releases its record", '''
seed "$probe_id" "$probe_name" fetch "$owned_digest" "$run_nonce"
container_receipt_claim "$probe_id" "$probe_name" fetch "$owned_digest" "$run_nonce" || exit 9
cleanup_phase_container fetch || exit 10
(( ${#container_receipt[@]} == 0 )) || exit 11
[[ "$(state_of "$FIXTURE_DIR/state-$probe_id")" == absent ]] || exit 12
cleanup_phase_container fetch && exit 13
exit 0
'''),
            ("empty receipt cleanup idempotent and absence verified", '''
cleanup_all_containers || exit 9
cleanup_all_containers || exit 10
containers_cleaned=0
verify_containers_absent || exit 11
'''),
            ("empty run-scoped store accepted unmarked", '''
verify_container_store_empty || exit 9
[[ "$unowned_or_unknown_resource" == 0 && "$destructive_teardown_blocked" == 0 ]] || exit 10
'''),
            ("listed run-scoped store preserved and marked", '''
printf x > "$FIXTURE_DIR/ps-listing"
verify_container_store_empty && exit 9
[[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || exit 10
[[ -e "$FIXTURE_DIR/ps-listing" ]] || exit 11
'''),
            ("unverifiable run-scoped store marked", '''
: > "$FIXTURE_DIR/ps-error"
verify_container_store_empty && exit 9
[[ "$unowned_or_unknown_resource" == 1 ]] || exit 10
'''),
        )
        for label, body in scenarios:
            with self.subTest(ownership_scenario=label), tempfile.TemporaryDirectory() as directory:
                fixture = Path(directory)
                completed = run_owner(body, fixture)
                self.assertEqual(completed.returncode, 0, f"{label}: {completed.stderr}")
                self.assertEqual(completed.stdout, "")

        # R92T-FRESH-01: full EXIT-path behavior once the destructive
        # teardown block is latched. Owned receipt containers are still
        # removed by canonical ID, but no cluster-wide stop, UID-wide kill,
        # user deletion, store/workspace removal, or tmpfs unmount runs; the
        # unowned object is preserved for investigation with no later-phase
        # reuse, the report artifact is invalidated, the failure output
        # stays one fixed class, and a repeated blocked cleanup stays
        # idempotent. A recorded cluster start attempt (`cluster_started=1`
        # in the mocks) rides along with every scenario.
        def run_exit(body: str, fixture: Path, fail_stage: str = "none",
                     workspace: Path | None = None) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", "-c", "set -euo pipefail\n" + definitions + mocks + body],
                cwd=ROOT,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
                     "FIXTURE": str(fixture), "FAIL_STAGE": fail_stage,
                     "GITHUB_WORKSPACE": str(workspace or fixture / "workspace")},
                capture_output=True, text=True, timeout=60,
            )

        def exit_fixture(directory: Path) -> tuple[Path, Path]:
            fixture = directory
            for name in ("rootfs", "rootfs-fetch", "artifacts", "exec", "owned-workspace",
                         "owned-workspace/run/podman-root", "owned-workspace/run/podman-runroot"):
                (fixture / name).mkdir(parents=True)
            workspace = fixture / "workspace"
            report = workspace / "artifacts/postgres-live/report.txt"
            report.parent.mkdir(parents=True)
            report.write_text("value-free-report\n", encoding="utf-8")
            return fixture, report

        def assert_blocked_preserved(label: str, completed: subprocess.CompletedProcess[str],
                                     fixture: Path, report: Path, stderr_line: str,
                                     removed: tuple[str, ...],
                                     preserved: tuple[str, ...]) -> None:
            events = (fixture / "trace").read_text(encoding="utf-8").splitlines()
            self.assertEqual(completed.returncode, 1, f"{label}: {completed.stderr}{events!r}")
            self.assertEqual(completed.stderr, stderr_line, f"{label}: fixed output")
            self.assertFalse(report.exists(), f"{label}: report must stay unpublished")
            # R92T-FRESH-01 residual: a recorded cluster start attempt never
            # authorizes a cluster-wide stop while the block is latched.
            self.assertFalse(any(event.startswith(("stop:", "identity:", "unexpected-sudo:",
                                                   "cluster-stop"))
                                 for event in events), events)
            for stage in ("rootfs", "fetch-rootfs", "artifacts", "exec-mount", "workspace"):
                self.assertNotIn(stage, events, events)
            self.assertFalse((fixture / "user-deleted").exists(), events)
            # No cluster stop, UID kill, user deletion, recursive store
            # removal, or unmount: identity, store, mount, workdir, and the
            # cluster state all survive.
            self.assertTrue((fixture / "owned-workspace").is_dir())
            self.assertTrue((fixture / "owned-workspace/run/podman-root").is_dir())
            self.assertTrue((fixture / "owned-workspace/run/podman-runroot").is_dir())
            self.assertTrue((fixture / "exec").is_dir())
            for selector in removed:
                self.assertTrue((fixture / f"absent-{selector}").exists(), events)
            # Preserved selectors were never removed or reused later.
            for selector in preserved:
                self.assertFalse((fixture / f"absent-{selector}").exists(), events)

        exit_scenarios: tuple[tuple[str, str, str], ...] = (
            ("preexisting name collision", "none", '''
foreign_id="$(printf '%064d' 9)"
foreign_digest="$(printf '%064d' 55)"
printf '%s|%s|%s|%s|%s\\n' "$foreign_id" live ffffffffffffffffffff live "$foreign_digest" \\
  > "$FIXTURE/identity-live"
: > "$FIXTURE/absent-$live_id"
container_must_be_absent live && exit 20
[[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || exit 21
fixed_error 'podman-container-name-collision'
'''),
            ("unknown podman status", "unknown", '''
container_must_be_absent live && exit 20
[[ "$destructive_teardown_blocked" == 1 ]] || exit 21
fixed_error 'podman-container-name-collision'
'''),
            ("foreign partial create", "none", '''
partial_id="$(printf '%064d' 9)"
partial_name="statekit-pg-fetch-$run_nonce"
printf '%s|%s|%s|%s|%s\\n' "$partial_id" "$partial_name" ffffffffffffffffffff fetch "$fetch_digest" \\
  > "$FIXTURE/identity-$partial_name"
create_failed_reconcile "$partial_name" fetch "$fetch_digest" 'fetch-container-create-failed'
'''),
            ("ownership receipt claim failure", "none", '''
claimed_id="$(printf '%064d' 9)"
container_receipt_claim "$claimed_id" claimed-name live "$live_digest" ffffffffffffffffffff && exit 20
[[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || exit 21
fixed_error 'container-ownership-receipt-invalid'
'''),
            ("non-empty store preflight", "none", '''
: > "$FIXTURE/ps-listing"
verify_container_store_empty && exit 20
[[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || exit 21
fixed_error 'podman-store-not-empty'
'''),
            ("latch raised during cleanup_all_containers", "none", '''
rm -f "$FIXTURE/identity-$fetch_id"
cleanup_all_containers && exit 20
[[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || exit 21
fixed_error 'container-cleanup-failed'
'''),
            ("inspect identity mismatch at cleanup", "ownership", '''
fixed_error 'isolated-build-or-mock-tests-failed'
'''),
        )
        receipt_ids = tuple(digit.zfill(64) for digit in "1234")
        for label, fail_stage, body in exit_scenarios:
            with self.subTest(unowned_exit=label), tempfile.TemporaryDirectory() as directory:
                fixture, report = exit_fixture(Path(directory))
                workspace = fixture / "workspace"
                completed = run_exit(body, fixture, fail_stage, workspace)
                if label == "preexisting name collision":
                    foreign = "9".zfill(64)
                    assert_blocked_preserved(
                        label, completed, fixture, report,
                        "podman-container-name-collision\n",
                        removed=receipt_ids[:3], preserved=(foreign, "live"))
                    # No later-phase reuse: across the whole run the foreign
                    # name was touched exactly once, by the failing reserve.
                    events = (fixture / "trace").read_text(encoding="utf-8").splitlines()
                    self.assertEqual(
                        [event for event in events if event.endswith(" live")],
                        ["podman:2001:container exists live"], events)
                    # Idempotence: a second blocked EXIT over the same state
                    # preserves everything again with the same fixed class.
                    completed = run_exit(body, fixture, fail_stage, workspace)
                    assert_blocked_preserved(
                        f"{label} (repeat)", completed, fixture, report,
                        "podman-container-name-collision\n",
                        removed=receipt_ids[:3], preserved=(foreign, "live"))
                    events = (fixture / "trace").read_text(encoding="utf-8").splitlines()
                    self.assertEqual(
                        [event for event in events if event.endswith(" live")],
                        ["podman:2001:container exists live"] * 2, events)
                elif label == "unknown podman status":
                    assert_blocked_preserved(
                        label, completed, fixture, report,
                        "podman-container-name-collision\n",
                        removed=(), preserved=receipt_ids + ("live",))
                elif label == "foreign partial create":
                    partial_name = "statekit-pg-fetch-0123456789abcdef0123"
                    assert_blocked_preserved(
                        label, completed, fixture, report,
                        "podman-create-partial-object-unowned\n",
                        removed=receipt_ids, preserved=("9".zfill(64), partial_name))
                elif label == "ownership receipt claim failure":
                    assert_blocked_preserved(
                        label, completed, fixture, report,
                        "container-ownership-receipt-invalid\n",
                        removed=receipt_ids, preserved=("9".zfill(64),))
                elif label == "non-empty store preflight":
                    assert_blocked_preserved(
                        label, completed, fixture, report,
                        "podman-store-not-empty\n",
                        removed=receipt_ids, preserved=("9".zfill(64),))
                elif label == "latch raised during cleanup_all_containers":
                    assert_blocked_preserved(
                        label, completed, fixture, report,
                        "container-cleanup-failed\n",
                        removed=receipt_ids[1:], preserved=(receipt_ids[0],))
                else:
                    assert_blocked_preserved(
                        label, completed, fixture, report,
                        "isolated-build-or-mock-tests-failed\n",
                        removed=(), preserved=receipt_ids + ("live",))

        # Owned partial create plus successful cleanup: the block never
        # latches, the claimed object is removed by canonical ID, the
        # recorded cluster start is restored by exactly one cluster stop,
        # and the normal full teardown (kill, identity, workspace, unmount)
        # runs.
        with self.subTest(unowned_exit="owned partial create with successful cleanup"), \
                tempfile.TemporaryDirectory() as directory:
            fixture, report = exit_fixture(Path(directory))
            completed = run_exit('''
container_receipt=()
partial_id="$(printf '%064d' 9)"
partial_name="statekit-pg-fetch-$run_nonce"
printf '%s|%s|%s|%s|%s\\n' "$partial_id" "$partial_name" "$run_nonce" fetch "$fetch_digest" \\
  > "$FIXTURE/identity-$partial_id"
printf '%s|%s|%s|%s|%s\\n' "$partial_id" "$partial_name" "$run_nonce" fetch "$fetch_digest" \\
  > "$FIXTURE/identity-$partial_name"
reconcile_partial_create "$partial_name" fetch "$fetch_digest" || exit 20
[[ "${container_receipt[0]}" == "$partial_id|$partial_name|fetch|$fetch_digest|$run_nonce" ]] || exit 21
[[ "$unowned_or_unknown_resource" == 0 && "$destructive_teardown_blocked" == 0 ]] || exit 22
fixed_error 'fetch-container-create-failed'
''', fixture)
            events = (fixture / "trace").read_text(encoding="utf-8").splitlines()
            self.assertEqual(completed.returncode, 1, completed.stderr + repr(events))
            self.assertEqual(completed.stderr, "fetch-container-create-failed\n")
            self.assertFalse(report.exists(), events)
            self.assertTrue((fixture / f"absent-{'9'.zfill(64)}").exists(), events)
            self.assertEqual(events.count("cluster-stop"), 1, events)
            for stage in ("rootfs", "fetch-rootfs", "artifacts", "exec-mount",
                          "stop:2001", "identity:2001", "workspace"):
                self.assertIn(stage, events, events)
            self.assertTrue((fixture / "user-deleted").exists(), events)
            self.assertFalse((fixture / "owned-workspace").exists(), events)
            self.assertFalse((fixture / "exec").exists(), events)

        # R92T-FRESH-01 residual: the cluster-stop helper itself refuses a
        # stop under the latch with one fixed value-free class, no stop is
        # attempted, and the recorded start attempt is not consumed; the
        # blocked EXIT afterwards still never stops the cluster.
        with self.subTest(unowned_exit="cluster-stop helper guard"), \
                tempfile.TemporaryDirectory() as directory:
            fixture, report = exit_fixture(Path(directory))
            completed = run_exit('''
mark_unowned_resource
cluster_skip_class="$(cleanup_cluster 2>&1)" || exit 20
[[ "$cluster_skip_class" == cluster-stop-skipped-unowned-resource ]] || exit 21
[[ "$cluster_started" == 1 ]] || exit 22
fixed_error 'podman-container-name-collision'
''', fixture)
            events = (fixture / "trace").read_text(encoding="utf-8").splitlines()
            self.assertEqual(completed.returncode, 1, completed.stderr + repr(events))
            self.assertEqual(completed.stderr, "podman-container-name-collision\n")
            self.assertNotIn("cluster-stop", events, events)
            self.assertFalse(report.exists(), events)

    def test_controller_report_validator_is_independent_and_value_free(self) -> None:
        """The trusted controller-side publication gate.

        The validator duplicates the schema and inventory on purpose (no
        shared code with the payload harness), accepts exactly the generated
        all-pass report under a strict file policy, rejects every mutation,
        and never echoes report bytes: failures emit one fixed category.
        """
        self.assertEqual(tuple(controller_validator.CASE_IDS), EXPECTED_CASES)
        self.assertEqual(len(controller_validator.FIXED_LINES), 16)
        validator_source = VALIDATOR_PATH.read_text(encoding="utf-8")
        self.assertNotIn("import run", validator_source)
        self.assertNotIn("exec_module", validator_source)
        self.assertNotIn("importlib", validator_source)
        gate = mock_gate()
        gate.results = [(case_id, "pass") for case_id in EXPECTED_CASES]
        gate.execution_complete = True
        gate.cleanup_ok = True
        success, text = gate.report_contents()
        self.assertTrue(success)
        marker = "credential-like-output-marker-that-must-never-be-echoed"
        fixed, cases = text.splitlines()[:16], text.splitlines()[16:]
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.txt"

            def write(content: str, mode: int = 0o600) -> None:
                if report_path.exists():
                    os.chmod(report_path, 0o600)
                report_path.write_text(content, encoding="utf-8")
                os.chmod(report_path, mode)

            def rejected(content: str, label: str) -> None:
                with self.subTest(label=label):
                    write(content)
                    self.assertFalse(controller_validator.report_is_valid(report_path))

            write(text)
            self.assertTrue(controller_validator.report_is_valid(report_path))
            completed = subprocess.run(
                [sys.executable, str(VALIDATOR_PATH), str(report_path)],
                check=False, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")

            joined = "\n".join
            rejected(joined(fixed + cases[:-1]) + "\n", "missing case record")
            rejected(joined(fixed + cases + ["case: extra-case=pass"]) + "\n", "extra case record")
            rejected(joined(fixed + cases[:-1] + [cases[0]]) + "\n", "duplicate case id")
            rejected(joined(fixed + [f"case: postgres-query-unknown-case=pass"] + cases[1:]) + "\n",
                     "unknown case id")
            swapped = list(cases)
            swapped[3], swapped[4] = swapped[4], swapped[3]
            rejected(joined(fixed + swapped) + "\n", "reordered case ids")
            failed = list(fixed)
            failed[5], failed[6], failed[8] = "cases_passed: 19", "cases_failed: 1", "status: fail"
            rejected(joined(failed + [cases[0].replace("=pass", "=fail")] + cases[1:]) + "\n",
                     "failed case status")
            skipped = list(fixed)
            skipped[7] = "cases_skipped: 1"
            rejected(joined(skipped + [cases[0].replace("=pass", "=skip")] + cases[1:]) + "\n",
                     "skipped case status")
            rejected(joined(fixed + [cases[0] + f"; {marker}"] + cases[1:]) + "\n",
                     "value-bearing case line")
            rejected(joined(fixed + cases + [marker]) + "\n", "appended raw output")
            rejected(joined([f"password: {marker}"] + fixed + cases) + "\n", "credential field")
            rejected(joined(fixed + ["query: SELECT * FROM observations"] + cases) + "\n",
                     "query-bearing field")
            rejected(json.dumps({"status": "pass", "cases": cases}) + "\n", "json-shaped content")
            rejected(text.replace("execution: complete", "execution: incomplete"),
                     "incomplete execution")
            rejected(text.replace("cleanup: pass", "cleanup: fail"), "cleanup failure")
            rejected(text.replace("postgres_major: 16", "postgres_major: 17"), "wrong major")
            rejected(text.replace("postgres_version: 16.15", "postgres_version: 16.16"),
                     "wrong minor")
            write(text)
            report_path.write_bytes(text.encode("utf-8")[:-1])
            self.assertFalse(controller_validator.report_is_valid(report_path))
            report_path.write_bytes(b"\xff\xfe" + text.encode("utf-8")[:64])
            os.chmod(report_path, 0o600)
            self.assertFalse(controller_validator.report_is_valid(report_path))
            write(text + "x" * (controller_validator.MAX_BYTES + 1), mode=0o600)
            self.assertGreater(report_path.stat().st_size, controller_validator.MAX_BYTES)
            self.assertFalse(controller_validator.report_is_valid(report_path))
            write("", mode=0o600)
            self.assertFalse(controller_validator.report_is_valid(report_path))
            write(text, mode=0o644)
            self.assertFalse(controller_validator.report_is_valid(report_path))
            write(text, mode=0o400)
            self.assertFalse(controller_validator.report_is_valid(report_path))
            hardlink = Path(directory) / "report-hardlink"
            write(text)
            os.link(report_path, hardlink)
            self.assertFalse(controller_validator.report_is_valid(report_path))
            hardlink.unlink()
            report_path.unlink()
            report_path.symlink_to(Path(directory) / "elsewhere")
            self.assertFalse(controller_validator.report_is_valid(report_path))
            report_path.unlink()
            write(text)
            with mock.patch.object(controller_validator.os, "geteuid",
                                   return_value=os.geteuid() + 1):
                self.assertFalse(controller_validator.report_is_valid(report_path))
            # Failure output is exactly one fixed category: no report bytes.
            write(joined(fixed + cases + [marker]) + "\n")
            completed = subprocess.run(
                [sys.executable, str(VALIDATOR_PATH), str(report_path)],
                check=False, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, f"{controller_validator.FIXED_CATEGORY}\n")
            self.assertNotIn(marker, completed.stderr)
            self.assertNotIn(EXPECTED_CASES[0], completed.stderr)
            completed = subprocess.run(
                [sys.executable, str(VALIDATOR_PATH)],
                check=False, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, f"{controller_validator.FIXED_CATEGORY}\n")

    def test_firewall_policy_install_verify_and_cleanup_are_behaviorally_closed(self) -> None:
        """SEC behavioral check with a mocked iptables/ip6tables backend.

        The simulator stores canonical `iptables -S` text (adding the `-m
        tcp`/`-m udp` module and `/32`/`/128` suffixes exactly as real
        iptables serializes them), proving the verifier is structural
        rather than a raw string comparison. Scenarios cover the empty
        IPv6 set default drop, unexpected ACCEPT/RETURN, altered ordering,
        wrong DNS/port/source, first-owner-jump position, duplicate jumps,
        ownership recorded immediately after chain creation with failures
        before and after the hook, and idempotent bounded cleanup.
        """
        controller = CI_SCRIPT.read_text(encoding="utf-8")
        definitions = "readonly ROOT" + controller.split("readonly ROOT", 1)[1].split(
            '\ncase "$self_test_mode" in', 1
        )[0]
        definitions = definitions.replace("/usr/bin/python3", shlex.quote(sys.executable))
        mocks = r'''
test_uid=2001
firewall_fetch_chain=SKPFtestfirewallchain00
firewall_chain=SKPGtestfirewallchain00
FIXTURE_DIR="${FIXTURE:?}"
fw_canon() {
  local binary="$1" chain="$2"
  shift 2
  local proto='' has_port=0 has_module=0 dst=''
  local -a spec=() canon=()
  local index=0
  while (( $# > 0 )); do
    case "$1" in
      -p) proto="$2"; spec+=("-p" "$2"); shift 2 ;;
      -m)
        if [[ "$2" == tcp || "$2" == udp ]]; then has_module=1; fi
        spec+=("-m" "$2"); shift 2
        ;;
      --dport) has_port=1; spec+=("--dport" "$2"); shift 2 ;;
      -d)
        dst="$2"
        case "$dst" in
          */*) spec+=("-d" "$dst") ;;
          *)
            if [[ "$binary" == ip6tables ]]; then
              spec+=("-d" "$dst/128")
            else
              spec+=("-d" "$dst/32")
            fi
            ;;
        esac
        shift 2
        ;;
      *) spec+=("$1"); shift ;;
    esac
  done
  while (( index < ${#spec[@]} )); do
    canon+=("${spec[index]}")
    if [[ "${spec[index]}" == "-p" ]]; then
      canon+=("${spec[index + 1]}")
      if (( has_port == 1 && has_module == 0 )); then
        canon+=("-m" "${spec[index + 1]}")
      fi
      index=$(( index + 2 ))
      continue
    fi
    index=$(( index + 1 ))
  done
  printf '%s %s\n' "-A $chain" "${canon[*]}"
}
sudo_bounded() {
  case "$1" in
    iptables|ip6tables) fw_exec "$@" ;;
    *) return 1 ;;
  esac
}
fw_exec() {
  local binary="$1"
  shift
  local dir="$FIXTURE_DIR/$binary/rules" chain="$2" spec='' file='' line=''
  local found=1 removed=0
  local -a kept=() existing=() lines=()
  case "$1" in
    -N)
      chain="$2"
      if [[ -e "$dir/$chain" ]]; then return 1; fi
      : > "$dir/$chain"
      return 0
      ;;
    -S)
      chain="$2"
      if [[ "$chain" == OUTPUT ]]; then
        printf '%s\n' '-P OUTPUT ACCEPT'
        file="$dir/OUTPUT"
        if [[ -f "$file" ]]; then
          while IFS= read -r line; do printf '%s\n' "$line"; done < "$file"
        fi
        return 0
      fi
      if [[ ! -f "$dir/$chain" ]]; then return 1; fi
      printf '%s\n' "-N $chain"
      while IFS= read -r line; do printf '%s\n' "$line"; done < "$dir/$chain"
      return 0
      ;;
    -A)
      if [[ "${FAIL_STAGE:-}" == rule ]]; then return 1; fi
      chain="$2"; shift 2
      fw_canon "$binary" "$chain" "$@" >> "$dir/$chain"
      return 0
      ;;
    -I)
      if [[ "${FAIL_STAGE:-}" == hook ]]; then return 1; fi
      chain="$2"; shift 3
      spec="$(fw_canon "$binary" "$chain" "$@")"
      if [[ -f "$dir/OUTPUT" ]]; then
        mapfile -t existing < "$dir/OUTPUT"
      fi
      lines=("$spec" "${existing[@]}")
      printf '%s\n' "${lines[@]}" > "$dir/OUTPUT"
      return 0
      ;;
    -C)
      chain="$2"; shift 2
      spec="$(fw_canon "$binary" "$chain" "$@")"
      file="$dir/$chain"
      if [[ ! -f "$file" ]]; then return 1; fi
      while IFS= read -r line; do
        if [[ "$line" == "$spec" ]]; then found=0; break; fi
      done < "$file"
      return "$found"
      ;;
    -D)
      chain="$2"; shift 2
      spec="$(fw_canon "$binary" "$chain" "$@")"
      file="$dir/$chain"
      if [[ ! -f "$file" ]]; then return 1; fi
      while IFS= read -r line; do
        if [[ "$removed" == 0 && "$line" == "$spec" ]]; then removed=1; continue; fi
        kept+=("$line")
      done < "$file"
      if [[ "$removed" != 1 ]]; then return 1; fi
      if (( ${#kept[@]} == 0 )); then
        : > "$file"
      else
        printf '%s\n' "${kept[@]}" > "$file"
      fi
      return 0
      ;;
    -F)
      chain="$2"
      if [[ ! -f "$dir/$chain" ]]; then return 1; fi
      : > "$dir/$chain"
      return 0
      ;;
    -X)
      chain="$2"
      if [[ ! -f "$dir/$chain" ]]; then return 1; fi
      if [[ -s "$dir/$chain" ]]; then return 1; fi
      rm -f -- "$dir/$chain"
      return 0
      ;;
  esac
  return 1
}
'''

        def run(body: str, fixture: Path, **extra_env: str) -> subprocess.CompletedProcess[str]:
            # The controller's mock container stages only bash/python and a
            # small fixed utility set, so the simulator directories are
            # prepared here instead of calling unstaged mkdir from bash.
            (fixture / "iptables/rules").mkdir(parents=True, exist_ok=True)
            (fixture / "ip6tables/rules").mkdir(parents=True, exist_ok=True)
            return subprocess.run(
                ["bash", "-c", "set -euo pipefail\n" + definitions + mocks + body],
                cwd=fixture,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
                     "FIXTURE": str(fixture), **extra_env},
                capture_output=True, text=True, timeout=90,
            )

        def assert_ok(completed: subprocess.CompletedProcess[str], label: str) -> None:
            self.assertEqual(completed.returncode, 0, f"{label}: {completed.stderr}")

        chain_v4 = "iptables/rules/SKPFtestfirewallchain00"
        chain_v6 = "ip6tables/rules/SKPFtestfirewallchain00"

        # Dual-family install (empty IPv6 set) verifies structurally against
        # the canonicalized backend and survives deliberate bypass rules.
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            first = run('''
proxy_addresses_v4=(192.0.2.10 192.0.2.20)
firewall_fetch4_created=0
install_fetch_firewall_family iptables 127.0.0.53/32 firewall_fetch4_created "${proxy_addresses_v4[@]}"
[[ "$firewall_fetch4_created" == 1 ]]
verify_effective_fetch_firewall_family iptables 127.0.0.53/32 "${proxy_addresses_v4[@]}"
firewall_fetch6_created=0
install_fetch_firewall_family ip6tables ::1/128 firewall_fetch6_created
[[ "$firewall_fetch6_created" == 1 ]]
verify_effective_fetch_firewall_family ip6tables ::1/128
''', fixture)
            assert_ok(first, "dual-family install")
            rules_v4 = (fixture / chain_v4).read_text(encoding="utf-8").splitlines()
            self.assertEqual(rules_v4, [
                "-A SKPFtestfirewallchain00 -o lo -d 127.0.0.53/32 -p udp -m udp --dport 53 -j ACCEPT",
                "-A SKPFtestfirewallchain00 -o lo -d 127.0.0.53/32 -p tcp -m tcp --dport 53 -j ACCEPT",
                "-A SKPFtestfirewallchain00 -d 192.0.2.10/32 -p tcp -m tcp --dport 443 -j ACCEPT",
                "-A SKPFtestfirewallchain00 -d 192.0.2.20/32 -p tcp -m tcp --dport 443 -j ACCEPT",
                "-A SKPFtestfirewallchain00 -j DROP",
            ])
            rules_v6 = (fixture / chain_v6).read_text(encoding="utf-8").splitlines()
            self.assertEqual(rules_v6, [
                "-A SKPFtestfirewallchain00 -o lo -d ::1/128 -p udp -m udp --dport 53 -j ACCEPT",
                "-A SKPFtestfirewallchain00 -o lo -d ::1/128 -p tcp -m tcp --dport 53 -j ACCEPT",
                "-A SKPFtestfirewallchain00 -j DROP",
            ])
            for family in ("iptables", "ip6tables"):
                output = (fixture / family / "rules/OUTPUT").read_text(encoding="utf-8")
                self.assertIn("-m owner --uid-owner 2001 -j SKPFtestfirewallchain00", output)
            second = run('''
proxy_addresses_v4=(192.0.2.10 192.0.2.20)
sudo_bounded ip6tables -A "$firewall_fetch_chain" -d 2001:db8::1 -p tcp --dport 443 -j ACCEPT
if verify_effective_fetch_firewall_family ip6tables ::1/128; then exit 9; fi
sudo_bounded iptables -A "$firewall_fetch_chain" -j RETURN
if verify_effective_fetch_firewall_family iptables 127.0.0.53/32 "${proxy_addresses_v4[@]}"; then exit 9; fi
sudo_bounded iptables -A "$firewall_fetch_chain" -p tcp -j ACCEPT
if verify_effective_fetch_firewall_family iptables 127.0.0.53/32 "${proxy_addresses_v4[@]}"; then exit 9; fi
remove_firewall_family ip6tables 1 "$firewall_fetch_chain"
remove_firewall_family iptables 1 "$firewall_fetch_chain"
firewall_chain_is_absent iptables "$firewall_fetch_chain"
firewall_chain_is_absent ip6tables "$firewall_fetch_chain"
if [[ -s "$FIXTURE/iptables/rules/OUTPUT" || -s "$FIXTURE/ip6tables/rules/OUTPUT" ]]; then exit 10; fi
''', fixture)
            assert_ok(second, "bypass rejection and cleanup")

        # Rule mutations between install and verification are rejected and
        # cleanup still removes the mutated chain and hook.
        def mutation_pair(label: str, mutator, verify_dns: str = "127.0.0.53/32",
                          install_addresses: tuple[str, ...] = ("192.0.2.10", "192.0.2.20"),
                          output_empty_after_cleanup: bool = True) -> None:
            with self.subTest(mutation=label), tempfile.TemporaryDirectory() as directory:
                fixture = Path(directory)
                addresses = " ".join(f'"{item}"' for item in install_addresses)
                first = run(f'''
proxy_addresses_v4=({addresses})
firewall_fetch4_created=0
install_fetch_firewall_family iptables 127.0.0.53/32 firewall_fetch4_created "${{proxy_addresses_v4[@]}}"
verify_effective_fetch_firewall_family iptables 127.0.0.53/32 "${{proxy_addresses_v4[@]}}"
''', fixture)
                assert_ok(first, f"{label}: install")
                mutator(fixture)
                output_check = ""
                if output_empty_after_cleanup:
                    output_check = '\nif [[ -s "$FIXTURE/iptables/rules/OUTPUT" ]]; then exit 10; fi'
                second = run(f'''
proxy_addresses_v4=({addresses})
if verify_effective_fetch_firewall_family iptables {verify_dns} "${{proxy_addresses_v4[@]}}"; then exit 9; fi
remove_firewall_family iptables 1 "$firewall_fetch_chain"
firewall_chain_is_absent iptables "$firewall_fetch_chain"{output_check}
''', fixture)
                assert_ok(second, f"{label}: rejection and cleanup")

        def rewrite_chain(fixture: Path, transform) -> None:
            path = fixture / chain_v4
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join(transform(lines)) + "\n", encoding="utf-8")

        mutation_pair("wrong resolver", lambda _fixture: None, verify_dns="127.0.0.54/32")
        mutation_pair("altered dns port",
                      lambda fixture: rewrite_chain(fixture, lambda lines: [
                          line.replace("--dport 53", "--dport 5353") if index == 0 else line
                          for index, line in enumerate(lines)]))
        mutation_pair("reordered rules",
                      lambda fixture: rewrite_chain(fixture, lambda lines: [
                          lines[1], lines[0], *lines[2:]]))
        mutation_pair("wrong proxy port",
                      lambda fixture: rewrite_chain(fixture, lambda lines: [
                          line.replace("--dport 443", "--dport 8443") if index == 2 else line
                          for index, line in enumerate(lines)]))
        mutation_pair("unapproved pinned address",
                      lambda fixture: rewrite_chain(fixture, lambda lines: [
                          *lines[:-1],
                          "-A SKPFtestfirewallchain00 -d 203.0.113.9/32 -p tcp -m tcp --dport 443 -j ACCEPT",
                          lines[-1]]))
        mutation_pair("source-constrained accept",
                      lambda fixture: rewrite_chain(fixture, lambda lines: [
                          line.replace("-d 192.0.2.10/32",
                                       "-s 127.0.0.1/32 -d 192.0.2.10/32")
                          if index == 2 else line
                          for index, line in enumerate(lines)]))

        def mutate_output(fixture: Path, transform) -> None:
            path = fixture / "iptables/rules/OUTPUT"
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join(transform(lines)) + "\n", encoding="utf-8")

        mutation_pair("foreign rule before owner jump",
                      lambda fixture: mutate_output(fixture, lambda lines: [
                          "-A OUTPUT -j DROP", *lines]),
                      output_empty_after_cleanup=False)
        mutation_pair("duplicate owner jump",
                      lambda fixture: mutate_output(fixture, lambda lines: [
                          *lines, lines[0]]))
        mutation_pair("dropped terminal rule",
                      lambda fixture: rewrite_chain(fixture, lambda lines: lines[:-1]))

        # Live family: no IPv6 loopback listener means no ACCEPT at all; an
        # injected loopback allow is rejected, and a bound service installs
        # exactly one loopback allow. Partial hook removal stays idempotent.
        # R92T-BACKEND-FINAL-01: the IPv6 family must never carry a 5433
        # rule (no case dials ::1:5433), not even a tcp-reset REJECT.
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            completed = run('''
firewall6_created=0
install_live_firewall_family ip6tables firewall6_created '' ''
[[ "$firewall6_created" == 1 ]]
verify_effective_live_firewall_family ip6tables '' ''
sudo_bounded ip6tables -A "$firewall_chain" -o lo -d ::1/128 -p tcp --dport 5432 -j ACCEPT
if verify_effective_live_firewall_family ip6tables '' ''; then exit 9; fi
sudo_bounded ip6tables -F "$firewall_chain"
sudo_bounded ip6tables -A "$firewall_chain" -o lo -d ::1/128 -p tcp --dport 5433 -j REJECT --reject-with tcp-reset
if verify_effective_live_firewall_family ip6tables '' ''; then exit 9; fi
sudo_bounded ip6tables -F "$firewall_chain"
sudo_bounded ip6tables -A "$firewall_chain" -j REJECT
if verify_effective_live_firewall_family ip6tables '' ''; then exit 9; fi
remove_firewall_family ip6tables 1
firewall_chain_is_absent ip6tables "$firewall_chain"
firewall4_created=0
install_live_firewall_family iptables firewall4_created 127.0.0.1/32 127.0.0.1/32
verify_effective_live_firewall_family iptables 127.0.0.1/32 127.0.0.1/32
if verify_effective_live_firewall_family iptables 127.0.0.1/32 ''; then exit 9; fi
if verify_effective_live_firewall_family iptables '' 127.0.0.1/32; then exit 9; fi
sudo_bounded iptables -D OUTPUT -m owner --uid-owner "$test_uid" -j "$firewall_chain"
remove_firewall_family iptables 1
firewall_chain_is_absent iptables "$firewall_chain"
if [[ -s "$FIXTURE/iptables/rules/OUTPUT" ]]; then exit 10; fi
''', fixture)
            assert_ok(completed, "live no-ipv6 default drop")
            rules_v6 = (fixture / "ip6tables/rules/SKPGtestfirewallchain00")
            self.assertFalse(rules_v6.exists())

        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            completed = run('''
firewall6_created=0
install_live_firewall_family ip6tables firewall6_created '::1/128' ''
[[ "$firewall6_created" == 1 ]]
verify_effective_live_firewall_family ip6tables '::1/128' ''
if verify_effective_live_firewall_family ip6tables '' ''; then exit 9; fi
if verify_effective_live_firewall_family ip6tables '::1/128' '::1/128'; then exit 9; fi
remove_firewall_family ip6tables 1
firewall_chain_is_absent ip6tables "$firewall_chain"
''', fixture)
            assert_ok(completed, "live ipv6 loopback allow")

        # R92T-BACKEND-FINAL-01: the unavailable loopback endpoint receives
        # exactly one owner-scoped tcp-reset REJECT ahead of the terminal
        # DROP. The exact ordered parser proves the reset is loopback-only,
        # that 5433 is never ACCEPTed, that no other port or address is
        # REJECTed, and that every drift - a missing, moved, malformed, or
        # duplicated reset, or an extra accept - fails closed while bounded
        # cleanup still removes the mutated chain and hook.
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            completed = run('''
firewall4_created=0
install_live_firewall_family iptables firewall4_created 127.0.0.1/32 127.0.0.1/32
verify_effective_live_firewall_family iptables 127.0.0.1/32 127.0.0.1/32
''', fixture)
            assert_ok(completed, "live v4 reset refusal install")
            chain_path = fixture / "iptables/rules/SKPGtestfirewallchain00"
            self.assertEqual(chain_path.read_text(encoding="utf-8").splitlines(), [
                "-A SKPGtestfirewallchain00 -o lo -d 127.0.0.1/32 -p tcp -m tcp --dport 5432 -j ACCEPT",
                "-A SKPGtestfirewallchain00 -o lo -d 127.0.0.1/32 -p tcp -m tcp "
                "--dport 5433 -j REJECT --reject-with tcp-reset",
                "-A SKPGtestfirewallchain00 -j DROP",
            ])

        def live_reset_mutation(label: str, transform) -> None:
            with self.subTest(live_reset_mutation=label), tempfile.TemporaryDirectory() as directory:
                fixture = Path(directory)
                first = run('''
firewall4_created=0
install_live_firewall_family iptables firewall4_created 127.0.0.1/32 127.0.0.1/32
verify_effective_live_firewall_family iptables 127.0.0.1/32 127.0.0.1/32
''', fixture)
                assert_ok(first, f"{label}: install")
                path = fixture / "iptables/rules/SKPGtestfirewallchain00"
                lines = path.read_text(encoding="utf-8").splitlines()
                path.write_text("\n".join(transform(lines)) + "\n", encoding="utf-8")
                second = run('''
if verify_effective_live_firewall_family iptables 127.0.0.1/32 127.0.0.1/32; then exit 9; fi
remove_firewall_family iptables 1
firewall_chain_is_absent iptables "$firewall_chain"
''', fixture)
                assert_ok(second, f"{label}: rejection and cleanup")

        live_reset_mutation("reset rule removed", lambda lines: [lines[0], lines[2]])
        live_reset_mutation("reset moved before allow", lambda lines: [lines[1], lines[0], lines[2]])
        live_reset_mutation("reset moved after terminal drop", lambda lines: [lines[0], lines[2], lines[1]])
        live_reset_mutation("reset on the postgresql port", lambda lines: [
            lines[0], lines[1].replace("--dport 5433", "--dport 5432"), lines[2]])
        live_reset_mutation("allow moved onto the reset port", lambda lines: [
            lines[0].replace("--dport 5432", "--dport 5433"), lines[1], lines[2]])
        live_reset_mutation("reset for a non-loopback destination", lambda lines: [
            lines[0], lines[1].replace("-d 127.0.0.1/32", "-d 203.0.113.9/32"), lines[2]])
        live_reset_mutation("reset without the loopback interface", lambda lines: [
            lines[0], lines[1].replace("-o lo ", ""), lines[2]])
        live_reset_mutation("bare reject without tcp-reset", lambda lines: [
            lines[0], lines[1].replace(" --reject-with tcp-reset", ""), lines[2]])
        live_reset_mutation("wrong reject-with type", lambda lines: [
            lines[0], lines[1].replace("tcp-reset", "icmp-port-unreachable"), lines[2]])
        live_reset_mutation("5433 accepted instead of reset", lambda lines: [
            lines[0], lines[1].replace("-j REJECT", "-j ACCEPT"), lines[2]])
        live_reset_mutation("extra 5433 accept alongside the reset", lambda lines: [
            lines[0], lines[1],
            "-A SKPGtestfirewallchain00 -o lo -d 127.0.0.1/32 -p tcp -m tcp --dport 5433 -j ACCEPT",
            lines[2]])
        live_reset_mutation("extra non-loopback reject", lambda lines: [
            lines[0], lines[1],
            "-A SKPGtestfirewallchain00 -d 203.0.113.9/32 -p tcp -m tcp "
            "--dport 8443 -j REJECT --reject-with tcp-reset",
            lines[2]])
        live_reset_mutation("duplicate reset rule", lambda lines: [
            lines[0], lines[1], lines[1], lines[2]])

        # Ownership is recorded immediately after chain creation: failures
        # before the hook (or mid-rule) and verification drift after the
        # hook still clean up every owned resource.
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            completed = run('''
firewall_fetch6_created=0
if install_fetch_firewall_family ip6tables ::1/128 firewall_fetch6_created; then exit 9; fi
[[ "$firewall_fetch6_created" == 1 ]]
[[ -f "$FIXTURE/ip6tables/rules/$firewall_fetch_chain" ]]
if [[ -e "$FIXTURE/ip6tables/rules/OUTPUT" ]]; then exit 10; fi
remove_firewall_family ip6tables 1 "$firewall_fetch_chain"
firewall_chain_is_absent ip6tables "$firewall_fetch_chain"
''', fixture, FAIL_STAGE="hook")
            assert_ok(completed, "failure after chain creation before hook")
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            completed = run('''
firewall_fetch4_created=0
if install_fetch_firewall_family iptables 127.0.0.53/32 firewall_fetch4_created 192.0.2.10; then exit 9; fi
[[ "$firewall_fetch4_created" == 1 ]]
[[ -f "$FIXTURE/iptables/rules/$firewall_fetch_chain" ]]
if [[ -e "$FIXTURE/iptables/rules/OUTPUT" ]]; then exit 10; fi
remove_firewall_family iptables 1 "$firewall_fetch_chain"
firewall_chain_is_absent iptables "$firewall_fetch_chain"
''', fixture, FAIL_STAGE="rule")
            assert_ok(completed, "failure during rule append")

    def test_rootfs_verify_and_preflight_entrypoint(self) -> None:
        """SEC-02 mock success plus missing/mismatch negatives.

        verify_staged_rootfs must independently revalidate the manifest and
        the whole staged tree, and the generated in-rootfs preflight must
        fail closed on absent or mismatched privilege/mount/manifest state.
        Both run against synthetic fixtures; no live rootfs is claimed.
        """
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            runner = fixture / "runner"
            go_root = runner / "go/1.26.8/x64"
            bash_bin = runner / "usr/bin/bash"
            dash_bin = runner / "usr/bin/dash"
            sh_bin = runner / "usr/bin/sh"
            certs_dir = runner / "etc/ssl/certs"
            resolv = runner / "etc/resolv.conf"
            fake_files = {
                go_root / "bin/go": "go-tool-fixture",
                go_root / "bin/gofmt": "gofmt-fixture",
                go_root / "VERSION": "go1.26.8\n",
                bash_bin: "bash-fixture",
                dash_bin: "sh-fixture",
                certs_dir / "ca-certificates.crt": "ca-fixture",
                resolv: "nameserver 127.0.0.53\n",
            }
            for path, contents in fake_files.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
                if path in (go_root / "bin/go", go_root / "bin/gofmt", bash_bin, dash_bin):
                    path.chmod(0o755)
            sh_bin.symlink_to("dash")

            # Test-only: build the fetch staging profile without a live exec
            # mount (mount enforcement is covered by the mount-policy tests).
            builder = rootfs_builder.RootfsBuilder(
                fixture / "fetch-rootfs", uid=2001, gid=2001,
                require_exec_mount=False, ldd=lambda _binary: (),
                test_source_roots=(runner,),
            )
            builder.require_exec_mount = True
            builder.build(
                python_executable=None, bash_executable=bash_bin, sh_executable=sh_bin,
                go_root=go_root, require_full_runtime=True,
                runtime_profile="dependency-fetch",
                resolv_source=resolv, certs_source=certs_dir,
            )
            fetch_rootfs = fixture / "fetch-rootfs"
            fetch_manifest_path = fetch_rootfs / "etc/statekit-rootfs.manifest"
            fetch_manifest_bytes = fetch_manifest_path.read_bytes()
            fetch_manifest = json.loads(fetch_manifest_bytes)
            self.assertEqual(fetch_manifest["runtime_profile"], "dependency-fetch")
            self.assertEqual(fetch_manifest["go_version"], "go1.26.8")
            self.assertIsNone(fetch_manifest["postgres_version"])
            fetch_paths = {item["path"] for item in fetch_manifest["entries"]}
            self.assertTrue({
                "/opt/go/bin/go", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/sh",
                "/etc/resolv.conf", "/etc/ssl/certs/ca-certificates.crt",
                "/usr/bin/statekit-rootfs-preflight",
            } <= fetch_paths)
            self.assertFalse(any(path.startswith("/usr/bin/python") for path in fetch_paths))
            self.assertFalse(any("postgresql" in path for path in fetch_paths))
            fetch_digest = hashlib.sha256(fetch_manifest_bytes).hexdigest()

            # Positive: independent revalidation accepts the untouched tree.
            rootfs_builder.verify_staged_rootfs(
                fetch_rootfs, manifest_sha256=fetch_digest,
                profile="dependency-fetch",
            )

            def rewrite_manifest(root: Path, mutate) -> str:
                manifest = json.loads((root / "etc/statekit-rootfs.manifest").read_bytes())
                mutate(manifest)
                payload = (json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                           + "\n").encode()
                (root / "etc/statekit-rootfs.manifest").write_bytes(payload)
                return hashlib.sha256(payload).hexdigest()

            def restore() -> None:
                fetch_manifest_path.write_bytes(fetch_manifest_bytes)

            # Digest mismatch fails before any tree inspection.
            with self.assertRaisesRegex(rootfs_builder.RootfsError,
                                        "rootfs-manifest-digest-mismatch"):
                rootfs_builder.verify_staged_rootfs(
                    fetch_rootfs, manifest_sha256="b" * 64,
                    profile="dependency-fetch",
                )
            # Unlisted file, socket, mode drift, content drift, removed entry.
            unlisted = fetch_rootfs / "opt/go/bin/rogue"
            unlisted.write_text("rogue", encoding="utf-8")
            with self.assertRaisesRegex(rootfs_builder.RootfsError, "rootfs-unlisted-entry"):
                rootfs_builder.verify_staged_rootfs(
                    fetch_rootfs, manifest_sha256=fetch_digest,
                    profile="dependency-fetch",
                )
            unlisted_socket = fetch_rootfs / "run/rogue.sock"
            import socket as socket_module
            listener = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
            try:
                listener.bind(str(unlisted_socket))
                with self.assertRaisesRegex(rootfs_builder.RootfsError,
                                            "rootfs-unlisted-node-type"):
                    rootfs_builder.verify_staged_rootfs(
                        fetch_rootfs, manifest_sha256=fetch_digest,
                        profile="dependency-fetch",
                    )
            finally:
                listener.close()
                unlisted_socket.unlink(missing_ok=True)
            unlisted.unlink()
            go_binary = fetch_rootfs / "opt/go/bin/go"
            go_binary.chmod(0o777)
            with self.assertRaisesRegex(rootfs_builder.RootfsError,
                                        "rootfs-staged-node-mismatch"):
                rootfs_builder.verify_staged_rootfs(
                    fetch_rootfs, manifest_sha256=fetch_digest,
                    profile="dependency-fetch",
                )
            go_binary.chmod(0o755)
            go_binary.write_bytes(b"tampered")
            with self.assertRaisesRegex(rootfs_builder.RootfsError,
                                        "rootfs-file-hash-mismatch"):
                rootfs_builder.verify_staged_rootfs(
                    fetch_rootfs, manifest_sha256=fetch_digest,
                    profile="dependency-fetch",
                )
            go_binary.write_bytes(b"go-tool-fixture")
            go_binary.chmod(0o755)
            restore()
            removed = fetch_rootfs / "opt/go/VERSION"
            removed.unlink()
            with self.assertRaisesRegex(rootfs_builder.RootfsError,
                                        "rootfs-missing-entry"):
                rootfs_builder.verify_staged_rootfs(
                    fetch_rootfs, manifest_sha256=fetch_digest,
                    profile="dependency-fetch",
                )
            removed.write_text("go1.26.8\n")
            # Manifest structure negatives: unsorted entries, symlink escape.
            digest_unsorted = rewrite_manifest(
                fetch_rootfs,
                lambda manifest: manifest.__setitem__(
                    "entries", list(reversed(manifest["entries"]))),
            )
            with self.assertRaisesRegex(rootfs_builder.RootfsError,
                                        "rootfs-manifest-invalid"):
                rootfs_builder.verify_staged_rootfs(
                    fetch_rootfs, manifest_sha256=digest_unsorted,
                    profile="dependency-fetch",
                )
            restore()
            escape_target = fixture / "escape-outside"
            escape_target.mkdir()
            staged_sh = fetch_rootfs / "usr/bin/sh"
            staged_sh.unlink()
            staged_sh.symlink_to(os.path.relpath(escape_target, fetch_rootfs / "usr/bin"))
            escape_digest = rewrite_manifest(
                fetch_rootfs,
                lambda manifest: next(
                    entry for entry in manifest["entries"]
                    if entry["path"] == "/usr/bin/sh"
                ).__setitem__("target", os.path.relpath(escape_target,
                                                        fetch_rootfs / "usr/bin")),
            )
            with self.assertRaisesRegex(rootfs_builder.RootfsError, "rootfs-symlink"):
                rootfs_builder.verify_staged_rootfs(
                    fetch_rootfs, manifest_sha256=escape_digest,
                    profile="dependency-fetch",
                )
            restore()
            staged_sh.unlink()
            staged_sh.symlink_to("dash")
            rootfs_builder.verify_staged_rootfs(
                fetch_rootfs, manifest_sha256=fetch_digest,
                profile="dependency-fetch",
            )

            # In-rootfs preflight entrypoint: run the generated script against
            # synthetic /proc fixtures by patching only its input paths.
            preflight = (fetch_rootfs / "usr/bin/statekit-rootfs-preflight")
            script_text = preflight.read_text(encoding="utf-8")
            self.assertIn("/proc/self/status", script_text)
            self.assertIn("/proc/self/mountinfo", script_text)
            status_fixture = fixture / "status"
            mountinfo_fixture = fixture / "mountinfo"
            manifest_fixture = fixture / "manifest"
            artifact_fixture = fixture / "artifact-file"
            artifact_fixture.write_bytes(b"executable-fixture")
            artifact_fixture.chmod(0o555)
            manifest_fixture.write_bytes(fetch_manifest_bytes)
            patched = script_text.replace("/proc/self/status", str(status_fixture))
            patched = patched.replace("/proc/self/mountinfo", str(mountinfo_fixture))
            patched = patched.replace("/etc/statekit-rootfs.manifest", str(manifest_fixture))
            patched = patched.replace("artifact_path=/artifact/statekit",
                                      f"artifact_path={shlex.quote(str(artifact_fixture))}")
            self.assertEqual(patched.count(str(status_fixture)), 1)
            self.assertEqual(patched.count(str(mountinfo_fixture)), 1)
            self.assertEqual(patched.count(str(manifest_fixture)), 1)
            preflight_copy = fixture / "preflight-test.sh"
            preflight_copy.write_text(patched, encoding="utf-8")
            preflight_copy.chmod(0o755)

            nonce = "a" * 20
            suffix = "abcd1234"
            status_ok = (
                f"Name:\tstatekit\nUid:\t2001\t2001\t2001\t2001\n"
                f"Gid:\t2001\t2001\t2001\t2001\nGroups:\t\n"
                f"NoNewPrivs:\t1\nCapInh:\t0000000000000000\n"
                f"CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"
                f"CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n"
            )
            root_mount = (
                "30 21 0:36 /rootfs / ro,nosuid,nodev,relatime"
                " - tmpfs tmpfs rw,nosuid,nodev"
            )
            deps_mount = (
                f"31 21 0:35 /statekit-pg-{nonce}.{suffix}/manifests /deps"
                " ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw"
            )
            modules_mount = (
                f"32 21 0:35 /statekit-pg-{nonce}.{suffix}/run/gomodcache /modules"
                " rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw"
            )
            tmp_mount = "33 21 0:37 / /tmp rw,nosuid,nodev,relatime,size=2097152k - tmpfs tmpfs rw"
            shm_mount = "34 21 0:38 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw"
            workspace_mount = (
                "35 21 0:39 / /workspace ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw"
            )
            artifact_mount = (
                # File bind: root is relative to the separate exec tmpfs,
                # mountpoint is the file; Linux omits the default exec option.
                "36 30 0:36 /artifacts/statekit /artifact/statekit"
                " ro,nosuid,nodev,relatime - tmpfs tmpfs rw"
            )
            out_mount = (
                f"38 21 0:35 /statekit-pg-{nonce}.{suffix}/run/live-output /out"
                " rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw"
            )
            proc_mount = "39 21 0:40 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw"
            sys_mount = "40 21 0:41 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw"
            common_mounts = (root_mount, tmp_mount, shm_mount, proc_mount, sys_mount)
            fetch_mountinfo = "\n".join(
                common_mounts + (deps_mount, modules_mount)
            ).replace("/rootfs /", "/rootfs-fetch /") + "\n"
            mountinfo_live = "\n".join(
                common_mounts
                + (artifact_mount, out_mount)
            ) + "\n"

            def run_preflight(role: str, *, digest: str | None = None) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(preflight_copy), "/usr/bin/id"],
                    env={
                        "PATH": "/usr/bin:/bin", "STATEKIT_TEST_UID": "2001",
                        "STATEKIT_TEST_GID": "2001",
                        "STATEKIT_ROOTFS_MANIFEST_SHA256": digest or fetch_digest,
                        "STATEKIT_ROOTFS_ROLE": role,
                    },
                    capture_output=True, text=True, check=False, timeout=15,
                )

            # Success: fetch role with its exact mount set.
            status_fixture.write_text(status_ok, encoding="utf-8")
            mountinfo_fixture.write_text(fetch_mountinfo, encoding="utf-8")
            completed = run_preflight("fetch")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            # Live role has only the artifact and dedicated report binds.
            status_fixture.write_text(status_ok, encoding="utf-8")
            mountinfo_fixture.write_text(mountinfo_live, encoding="utf-8")
            completed = run_preflight("live")
            self.assertEqual(completed.returncode, 0, completed.stderr)

            for role, mounts in (
                ("mock", common_mounts + (workspace_mount,)),
                ("build", common_mounts + (
                    workspace_mount, modules_mount.replace("/modules rw,", "/modules ro,"),
                    "38 30 0:36 /artifacts /out rw,nosuid,nodev,noexec - tmpfs tmpfs rw",
                )),
            ):
                mountinfo_fixture.write_text("\n".join(mounts) + "\n", encoding="utf-8")
                completed = run_preflight(role)
                self.assertEqual(completed.returncode, 0, completed.stderr)

            mountinfo_fixture.write_text(mountinfo_live, encoding="utf-8")
            for substitute in ("nonexecutable", "directory", "symlink"):
                with self.subTest(artifact_substitute=substitute):
                    artifact_fixture.unlink()
                    if substitute == "directory":
                        artifact_fixture.mkdir()
                    elif substitute == "symlink":
                        artifact_fixture.symlink_to(manifest_fixture)
                    else:
                        artifact_fixture.write_bytes(b"not-executable")
                        artifact_fixture.chmod(0o444)
                    completed = run_preflight("live")
                    self.assertEqual(completed.returncode, 1)
                    self.assertEqual(completed.stderr.strip(), "preflight-artifact-file-invalid")
                    if substitute == "directory":
                        artifact_fixture.rmdir()
                        artifact_fixture.touch()

            artifact_fixture.unlink()
            artifact_fixture.write_bytes(b"executable-fixture")
            artifact_fixture.chmod(0o555)

            negatives = (
                ("missing CapEff line",
                 status_ok.replace("CapEff:\t0000000000000000\n", ""),
                 mountinfo_live, "live", None,
                 "preflight-capability-fields-missing"),
                ("nonzero CapEff",
                 status_ok.replace("CapEff:\t0000000000000000",
                                   "CapEff:\t0000000000000001"),
                 mountinfo_live, "live", None,
                 "preflight-capabilities-invalid"),
                ("uid mismatch",
                 status_ok.replace("Uid:\t2001\t2001\t2001\t2001",
                                   "Uid:\t2001\t2001\t0\t2001"),
                 mountinfo_live, "live", None, "preflight-uid-invalid"),
                ("groups populated",
                 status_ok.replace("Groups:\t\n", "Groups:\t27\n"),
                 mountinfo_live, "live", None, "preflight-groups-invalid"),
                ("no-new-privs off",
                 status_ok.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
                 mountinfo_live, "live", None, "preflight-no-new-privs-invalid"),
                ("manifest digest mismatch",
                 status_ok, mountinfo_live, "live", "c" * 64,
                 "preflight-manifest-mismatch"),
                ("manifest missing",
                 status_ok, mountinfo_live, "live", None, "preflight-manifest-unavailable"),
                ("unexpected mount",
                 status_ok, mountinfo_live + "50 21 0:99 / /host rw,relatime - tmpfs tmpfs rw\n",
                 "live", None, "preflight-unexpected-mount"),
                ("artifact mounted noexec",
                 status_ok,
                  mountinfo_live.replace(
                      "/artifact/statekit ro,nosuid,nodev,relatime",
                      "/artifact/statekit ro,nosuid,nodev,noexec,relatime",
                 ),
                 "live", None, "preflight-artifact-mount-policy-invalid"),
                ("artifact mount missing for live",
                 status_ok,
                  mountinfo_live.replace(artifact_mount + "\n", ""),
                 "live", None, "preflight-required-mount-missing"),
                ("tmpfs noexec",
                 status_ok,
                 mountinfo_live.replace(
                     "/ /tmp rw,nosuid,nodev,relatime",
                     "/ /tmp rw,nosuid,nodev,noexec,relatime"),
                 "live", None, "preflight-tmp-mount-policy-invalid"),
                ("root mount identity",
                 status_ok,
                 mountinfo_live.replace(
                      "/rootfs / ro", "/elsewhere / ro"),
                 "live", None, "preflight-root-mount-identity-invalid"),
                ("modules mounted ro in fetch role",
                 status_ok, fetch_mountinfo.replace(
                     "/modules rw,nosuid,nodev,noexec",
                     "/modules ro,nosuid,nodev,noexec"),
                 "fetch", None, "preflight-modules-mount-policy-invalid"),
            )
            for before, after, category in (
                (artifact_mount, artifact_mount + "\n" + workspace_mount, "preflight-unexpected-mount"),
                (artifact_mount, artifact_mount + "\n37 21 0:35 /.pgpass /run/pgpass ro,nosuid,nodev,noexec - tmpfs tmpfs rw",
                 "preflight-unexpected-mount"),
                ("/artifact/statekit ro,", "/artifact ro,", "preflight-unexpected-mount"),
                ("/artifact/statekit ro,", "/unknown ro,", "preflight-unexpected-mount"),
                ("/artifact/statekit ro,", "/artifact/statekit rw,", "preflight-artifact-mount-policy-invalid"),
                ("/artifacts/statekit /artifact", "/artifacts /artifact", "preflight-artifact-mount-identity-invalid"),
                ("36 30 0:36", "36 30 0:99", "preflight-artifact-mount-identity-invalid"),
                ("- tmpfs tmpfs rw", "- tmpfs wrong-source rw", "preflight-root-mount-identity-invalid"),
                ("/artifact/statekit ro,nosuid,nodev,", "/artifact/statekit ro,nodev,", "preflight-artifact-mount-policy-invalid"),
                ("/artifact/statekit ro,nosuid,nodev,", "/artifact/statekit ro,nosuid,", "preflight-artifact-mount-policy-invalid"),
                (artifact_mount, artifact_mount.replace("- tmpfs tmpfs", "- tmpfs wrong-source"),
                 "preflight-artifact-mount-identity-invalid"),
                (artifact_mount, artifact_mount + "\n" + artifact_mount,
                 "preflight-artifact-mount-identity-invalid"),
                ("/rootfs / ro", "/rootfs-fetch / ro", "preflight-root-mount-identity-invalid"),
            ):
                negatives += ((after, status_ok, mountinfo_live.replace(before, after),
                               "live", None, category),)
            for label, status_text, mountinfo_text, role, digest, category in negatives:
                with self.subTest(label=label):
                    if label == "manifest missing":
                        manifest_fixture.unlink(missing_ok=True)
                    else:
                        manifest_fixture.write_bytes(fetch_manifest_bytes)
                    status_fixture.write_text(status_text, encoding="utf-8")
                    mountinfo_fixture.write_text(mountinfo_text, encoding="utf-8")
                    completed = run_preflight(role, digest=digest)
                    self.assertEqual(completed.returncode, 1, completed.stderr)
                    self.assertEqual(completed.stderr.strip(), category)


if __name__ == "__main__":
    unittest.main()
