#!/usr/bin/env python3
"""Deterministic, non-live checks for the E5.2 orchestration boundary."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tests/live/mysql/run.sh"
CONTAINERFILE = ROOT / "tests/live/mysql/Containerfile"
WORKFLOW = ROOT / ".github/workflows/integration-services.yml"
IMAGE_DIGEST = "sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a"
EXPECTED_CASES = (
    "mysql-readiness-authenticated-select-1",
    "mysql-version-live",
    "mysql-db-list-seeded",
    "mysql-db-exists-seeded",
    "mysql-db-exists-absent",
    "mysql-plugins-list-installed",
    "mysql-plugin-status-installed",
    "mysql-plugin-status-absent",
    "mysql-auth-negative-native-client",
    "mysql-auth-negative-statekit",
    "mysql-connection-negative-native-client",
    "mysql-connection-negative-statekit",
    "mysql-db-native-postcondition",
    "mysql-plugin-native-postcondition",
    "mysql-db-lifecycle-native-absent-before-create",
    "mysql-db-create-success",
    "mysql-db-create-repeat-false",
    "mysql-db-native-created-postcondition",
    "mysql-db-remove-success",
    "mysql-db-native-removed-postcondition",
    "mysql-db-negative-invalid-identifier",
    "mysql-db-negative-auth",
    "mysql-db-negative-connection",
    "mysql-alter-db-native-absent-before-create",
    "mysql-alter-db-create-and-seed",
    "mysql-alter-db-native-defaults-before",
    "mysql-alter-db-statekit-explicit",
    "mysql-alter-db-native-explicit-readback",
    "mysql-alter-db-statekit-explicit-readback",
    "mysql-alter-db-statekit-default-preservation",
    "mysql-alter-db-native-default-preserved-readback",
    "mysql-alter-db-statekit-default-preserved-readback",
    "mysql-alter-db-negative-auth",
    "mysql-alter-db-negative-connection",
    "mysql-alter-db-negative-invalid-identifier",
    "mysql-alter-db-negative-invalid-option",
    "mysql-processlist-statekit",
    "mysql-processlist-native-observation",
    "mysql-processlist-negative-auth",
    "mysql-processlist-negative-connection",
    "mysql-get-master-status-statekit",
    "mysql-get-master-status-native-observation",
    "mysql-get-master-status-negative-auth",
    "mysql-get-master-status-negative-connection",
    "mysql-get-slave-status-statekit",
    "mysql-get-slave-status-native-observation",
    "mysql-get-slave-status-negative-auth",
    "mysql-get-slave-status-negative-connection",
)


class E52OrchestrationTests(unittest.TestCase):
    def _classify_status_result(
        self,
        kind: str,
        execution_class: str,
        return_code: int,
        stdout: str,
        stderr: str,
    ) -> str:
        command = """
script_path="$1"
kind="$2"
execution_class="$3"
return_code="$4"
stdout_path="$5"
stderr_path="$6"
set --
source "$script_path"
native_status_classification "$kind" "$execution_class" "$return_code" "$stdout_path" "$stderr_path"
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            stdout_path = temporary / "stdout"
            stderr_path = temporary / "stderr"
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text(stderr, encoding="utf-8")
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    command,
                    "status-classifier",
                    str(SCRIPT),
                    kind,
                    execution_class,
                    str(return_code),
                    str(stdout_path),
                    str(stderr_path),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.stderr, "")
        return result.stdout.strip()

    def _status_correlates(self, kind: str, statekit_class: str, native_class: str) -> bool:
        command = """
script_path="$1"
kind="$2"
statekit_class="$3"
native_class="$4"
set --
source "$script_path"
status_observation_correlates "$kind" "$statekit_class" "$native_class"
"""
        result = subprocess.run(
            [
                "bash",
                "-c",
                command,
                "status-correlation",
                str(SCRIPT),
                kind,
                statekit_class,
                native_class,
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        return result.returncode == 0

    def _classify_status_json(self, kind: str, value: object) -> str:
        command = """
script_path="$1"
kind="$2"
json_path="$3"
set --
source "$script_path"
status_json_classification "$kind" "$json_path"
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            json_path = Path(temporary_directory) / "status.json"
            json_path.write_text(json.dumps(value), encoding="utf-8")
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    command,
                    "status-json-classifier",
                    str(SCRIPT),
                    kind,
                    str(json_path),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.stderr, "")
        return result.stdout.strip()

    def _classify_native_result(
        self,
        kind: str,
        execution_class: str,
        return_code: int,
        stdout_path: Path,
        stderr_path: Path,
    ) -> str:
        command = """
script_path="$1"
kind="$2"
execution_class="$3"
return_code="$4"
stdout_path="$5"
stderr_path="$6"
set --
source "$script_path"
native_failure_classification "$kind" "$execution_class" "$return_code" "$stdout_path" "$stderr_path"
"""
        result = subprocess.run(
            [
                "bash",
                "-c",
                command,
                "e51-classifier",
                str(SCRIPT),
                kind,
                execution_class,
                str(return_code),
                str(stdout_path),
                str(stderr_path),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stderr, "")
        return result.stdout.strip()

    def test_case_inventory_is_deterministic_without_a_runtime(self) -> None:
        result = subprocess.run(
            [str(SCRIPT), "--list-cases"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(tuple(result.stdout.splitlines()), EXPECTED_CASES)
        self.assertEqual(result.stderr, "")

    def test_image_digest_and_runtime_secret_boundary(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(IMAGE_DIGEST, source)
        self.assertNotIn("--env-file", source)
        self.assertIn("--secret", source)
        self.assertIn("MYSQL_ROOT_PASSWORD_FILE", source)
        self.assertIn("MYSQL_PASSWORD_FILE", source)
        self.assertIn("--defaults-extra-file", source)
        self.assertIn("/tmp/mysql-client.cnf", source)
        self.assertIn("--internal", source)
        self.assertIn("--cap-drop ALL", source)
        self.assertIn("--security-opt no-new-privileges", source)
        self.assertIn("no-new-privileges=true", source)
        self.assertIn("--ipc private", source)
        self.assertIn("--pid private", source)
        self.assertIn("--uts private", source)
        self.assertIn("--user \"$MYSQL_SERVICE_USER\"", source)
        self.assertIn("--user \"$CLIENT_USER\"", source)
        self.assertIn("runtime_preflight()", source)
        self.assertIn("verify_created_container_policy()", source)
        self.assertIn("verify_python_mock_container_policy()", source)
        self.assertIn("PYTHON_MOCK_TMPFS_DESTINATION", source)
        self.assertIn("PYTHON_MOCK_TMPFS_OPTIONS", source)
        self.assertIn("canonical_csv_set", source)
        self.assertIn("container inspect", source)
        self.assertIn("--format", source)
        self.assertIn("Config.Secrets", source)
        self.assertIn("Config.Env", source)
        self.assertNotIn("inspect_path", source)
        self.assertNotIn("json.load(inspect", source)
        self.assertIn("container exists", source)
        self.assertIn("network exists", source)
        self.assertIn("generate_resource_nonce()", source)
        self.assertIn("secrets.token_hex(12)", source)
        self.assertIn("RESOURCE_NONCE", source)
        self.assertIn("DB_OWNED=1", source)
        self.assertIn("NETWORK_OWNED=1", source)
        self.assertIn("CLIENT_IMAGE_OWNED=1", source)
        self.assertIn("cleanup_container()", source)
        self.assertIn("bounded_timeout()", source)
        self.assertIn("--kill-after", source)
        self.assertIn("stop --time 5", source)
        self.assertIn("secret rm", source)
        self.assertIn("CLEANUP_FAILED=1", source)
        self.assertIn("REPORT_PREPARED=1", source)
        self.assertIn("--force --volumes", source)
        self.assertIn("trap '' INT TERM", source)
        self.assertIn("execution_rc:", source)
        self.assertIn("final_rc:", source)
        self.assertIn("LIFECYCLE_DB=", source)
        self.assertIn("ALTER_DB=", source)
        self.assertIn("ALTER_TABLE=", source)
        self.assertIn("DROP DATABASE IF EXISTS", source)
        self.assertIn("mysql.db_create", source)
        self.assertIn("mysql.db_remove", source)
        self.assertIn("mysql.alter_db", source)
        self.assertIn("mysql.db_get", source)
        self.assertIn("utf8mb4_general_ci", source)
        self.assertIn("external_ci: pending", source)
        self.assertNotIn("statekit-e51-mysql-$$", source)
        self.assertNotIn("statekit-e51-net-$$", source)
        self.assertNotIn("statekit-e51-client:$$", source)
        self.assertNotIn("--privileged", source)
        self.assertNotIn("--device", source)
        self.assertNotIn("--volume ", source)
        self.assertNotIn("--cap-add", source)
        self.assertNotIn("run --rm", source)
        self.assertNotIn("docker.sock", source)
        self.assertIn(IMAGE_DIGEST, CONTAINERFILE.read_text(encoding="utf-8"))
        self.assertIn("USER 65532:65532", CONTAINERFILE.read_text(encoding="utf-8"))
        report_function = source.split("write_report()", 1)[1].split("prepare_report()", 1)[0]
        for secret_name in ("ROOT_PASSWORD", "LIVE_PASSWORD", "BAD_PASSWORD", "MYSQL_PWD"):
            self.assertNotIn(f"${secret_name}", report_function)

    def test_preflight_precedes_all_pull_build_and_resource_creation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        preflight = source.index("if ! select_runtime || ! runtime_preflight; then")
        main = source.index("main() {")
        for operation in (
            "pull_and_verify_image",
            "build_client_image",
            "create_private_network",
            "create_runtime_secrets",
            "start_mysql",
        ):
            self.assertGreater(source.index(operation, main), preflight, operation)

    def test_report_and_runtime_metadata_are_value_free(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("MYSQL_ROOT_PASSWORD=$", source)
        self.assertNotIn("MYSQL_PASSWORD=$", source)
        self.assertNotIn("MYSQL_PWD", source)
        self.assertIn('MYSQL_ROOT_PASSWORD_FILE=$SERVER_ROOT_SECRET_TARGET', source)
        self.assertIn('MYSQL_PASSWORD_FILE=$SERVER_USER_SECRET_TARGET', source)
        self.assertIn("split . \"=\"", source)
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            report_directory = temporary / "report"
            command = """
script_path="$1"
report_directory="$2"
set --
source "$script_path"
REPORT_DIR="$report_directory"
REPORT_PATH="$REPORT_DIR/report.txt"
mkdir -p "$REPORT_DIR"
REPORT_PREPARED=1
ROOT_PASSWORD='root-secret-marker'
LIVE_PASSWORD='live-secret-marker'
BAD_PASSWORD='bad-secret-marker'
FINAL_RC=1
EXECUTION_RC=1
write_report
"""
            result = subprocess.run(
                ["bash", "-c", command, "value-free-report", str(SCRIPT), str(report_directory)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            report = (report_directory / "report.txt").read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("root-secret-marker", report)
        self.assertNotIn("live-secret-marker", report)
        self.assertNotIn("bad-secret-marker", report)
        self.assertIn("execution_rc: 1", report)
        self.assertIn("final_rc: 1", report)
        self.assertIn("status: fail", report)

    def test_workflow_keeps_build_and_python_checks_inside_pinned_sandboxes(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("e5.2 live mysql read-only/catalog/plugin/database-lifecycle/alter-db/process-replication-status", workflow)
        self.assertIn("sqlite-live:", workflow)
        self.assertIn("e5-2-mysql-live-report", workflow)
        self.assertIn("run.sh --preflight-only", workflow)
        self.assertIn("golang:1.26.6@sha256:", workflow)
        self.assertIn("python:3.14.7@sha256:", workflow)
        self.assertIn("podman network create", workflow)
        self.assertIn("--network=\"$fetch_network\"", workflow)
        self.assertGreaterEqual(workflow.count("--network=none"), 2)
        self.assertIn("--read-only", workflow)
        self.assertIn("--cap-drop ALL", workflow)
        self.assertNotIn("python3 tests/live/mysql/test_orchestration.py", workflow)
        self.assertNotIn("CGO_ENABLED=0 go build", workflow)
        self.assertNotIn("actions/setup-go", workflow)
        mysql_job = workflow.split("  sqlite-live:", 1)[0]
        self.assertIn('run_suffix="${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-0}"', mysql_job)
        self.assertIn("reserve_resource_name network", mysql_job)
        self.assertIn("reserve_resource_name image", mysql_job)
        self.assertIn("reserve_resource_name container", mysql_job)
        self.assertIn("fetch_network_owned=0", mysql_job)
        self.assertIn("deps_image_owned=0", mysql_job)
        self.assertIn("python_container_owned=0", mysql_job)
        self.assertIn('cleanup_container "$python_container" "$python_container_owned"', mysql_job)
        self.assertIn("cleanup_isolated_resources", mysql_job)
        self.assertIn("resource_is_absent", mysql_job)
        self.assertIn("--kill-after", mysql_job)
        self.assertIn("verify_python_mock_container_policy", mysql_job)
        self.assertIn("source tests/live/mysql/run.sh", mysql_job)
        self.assertIn("EffectiveCaps", SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("BoundingCaps", SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("python check container effective policy failed before start", mysql_job)
        self.assertLess(
            mysql_job.index("verify_python_mock_container_policy \"$python_container\""),
            mysql_job.index('podman start --attach "$python_container"'),
        )

    def _run_python_mock_policy_fixture(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        defaults = {
            "user": "65532:65532",
            "privileged": "false",
            "readonly": "true",
            "nnp": "no-new-privileges=true",
            "effective": "",
            "bounding": "",
            "network": "none",
            "ipc": "private",
            "pid": "private",
            "uts": "private",
            "tmpfs": "/tmp|rw,nosuid,nodev,noexec,size=64m,mode=1777,rprivate,tmpcopyup",
            "mounts": "0",
            "mount_layout": "",
            "binds": "0",
            "volumes": "0",
            "volumes_from": "0",
            "devices": "0",
            "ports": "0",
            "extra_hosts": "0",
            "group_add": "0",
            "links": "0",
            "secret_state": "absent",
            "env_keys": "container\nPATH\nPYTHONDONTWRITEBYTECODE\nPYTHON_SHA256\nPYTHON_VERSION",
        }
        defaults.update(overrides)
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            runtime = temporary / "container"
            runtime.write_text(
                """#!/usr/bin/env bash
set -u
format="${3:-}"
case "$format" in
  *'.Config.User}}'*) printf '%s\\n' "$MOCK_user" ;;
  *'.HostConfig.Privileged}}'*) printf '%s\\n' "$MOCK_privileged" ;;
  *'.HostConfig.ReadonlyRootfs}}'*) printf '%s\\n' "$MOCK_readonly" ;;
  *'.HostConfig.SecurityOpt}}'*) printf '%s\\n' "$MOCK_nnp" ;;
  *'.EffectiveCaps}}'*) printf '%s\\n' "$MOCK_effective" ;;
  *'.BoundingCaps}}'*) printf '%s\\n' "$MOCK_bounding" ;;
  *'.HostConfig.NetworkMode}}'*) printf '%s\\n' "$MOCK_network" ;;
  *'.HostConfig.IpcMode}}'*) printf '%s\\n' "$MOCK_ipc" ;;
  *'.HostConfig.PidMode}}'*) printf '%s\\n' "$MOCK_pid" ;;
  *'.HostConfig.UTSMode}}'*) printf '%s\\n' "$MOCK_uts" ;;
  *'.HostConfig.Tmpfs}}'*) printf '%s\\n' "$MOCK_tmpfs" ;;
  *'len .Mounts}}'*) printf '%s\\n' "$MOCK_mounts" ;;
  *'.Mounts}}'*) printf '%s\\n' "$MOCK_mount_layout" ;;
  *'len .HostConfig.Binds}}'*) printf '%s\\n' "$MOCK_binds" ;;
  *'len .Config.Volumes}}'*) printf '%s\\n' "$MOCK_volumes" ;;
  *'len .HostConfig.VolumesFrom}}'*) printf '%s\\n' "$MOCK_volumes_from" ;;
  *'len .HostConfig.Devices}}'*) printf '%s\\n' "$MOCK_devices" ;;
  *'len .HostConfig.PortBindings}}'*) printf '%s\\n' "$MOCK_ports" ;;
  *'len .HostConfig.ExtraHosts}}'*) printf '%s\\n' "$MOCK_extra_hosts" ;;
  *'len .HostConfig.GroupAdd}}'*) printf '%s\\n' "$MOCK_group_add" ;;
  *'len .HostConfig.Links}}'*) printf '%s\\n' "$MOCK_links" ;;
  *'.Config.Secrets}}'*) printf '%s\\n' "$MOCK_secret_state" ;;
  *'.Config.Env}}'*) printf '%s\\n' "$MOCK_env_keys" ;;
  *) exit 2 ;;
esac
""",
                encoding="utf-8",
            )
            start = temporary / "start"
            start.write_text("printf 'start\\n' >> \"$MOCK_START_LOG\"\n", encoding="utf-8")
            environment = os.environ.copy()
            for key, value in defaults.items():
                environment[f"MOCK_{key}"] = value
            start_log = temporary / "starts"
            environment["MOCK_START_LOG"] = str(start_log)
            command = r'''
script_path="$1"
runtime_directory="$2"
cd "$runtime_directory"
set --
source "$script_path"
RUNTIME=/bin/bash
set +e
if verify_python_mock_container_policy mock-container; then
  policy_rc=0
  /bin/bash start mock-container
  start_rc=$?
else
  policy_rc=$?
  start_rc=blocked
fi
starts=0
[[ -f "$MOCK_START_LOG" ]] && starts=$(wc -l < "$MOCK_START_LOG")
printf 'policy_rc=%s start_rc=%s starts=%s\n' "$policy_rc" "$start_rc" "$starts"
'''
            result = subprocess.run(
                ["bash", "-c", command, "python-mock-policy", str(SCRIPT), str(temporary)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            return result

    def test_python_mock_policy_accepts_exact_inspection_and_allows_start(self) -> None:
        result = self._run_python_mock_policy_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("policy_rc=0 start_rc=0 starts=1", result.stdout)

    def test_python_mock_policy_blocks_negative_inspection_variants(self) -> None:
        cases = {
            "extra-tmpfs-destination": {
                "tmpfs": "/tmp|rw,nosuid,nodev,noexec,size=64m,mode=1777,rprivate,tmpcopyup\n/run|rw,nosuid,nodev,noexec,size=16m,mode=1777,rprivate,tmpcopyup",
            },
            "extra-tmpfs-option": {
                "tmpfs": "/tmp|rw,nosuid,nodev,noexec,size=64m,mode=1777,rprivate,tmpcopyup,exec",
            },
            "unexpected-effective-mount": {
                "mounts": "1",
                "mount_layout": "bind|/workspace|rw||true|[]",
            },
            "unexpected-bind": {"binds": "1"},
            "unexpected-volume": {"volumes": "1"},
            "unexpected-secret": {"secret_state": "present"},
            "unexpected-environment-key": {
                "env_keys": "container\nPATH\nPYTHONDONTWRITEBYTECODE\nPYTHON_SHA256\nPYTHON_VERSION\nUNREVIEWED_KEY",
            },
        }
        for name, overrides in cases.items():
            with self.subTest(name=name):
                result = self._run_python_mock_policy_fixture(**overrides)
                self.assertEqual(result.returncode, 0, (name, result.stderr))
                self.assertRegex(result.stdout, r"policy_rc=[1-9][0-9]* start_rc=blocked starts=0")

    def test_native_negative_checks_reject_timeout_and_unrelated_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            stdout_path = temporary / "stdout"
            stderr_path = temporary / "stderr"
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text(
                "ERROR 1045 (28000): Access denied for user\n",
                encoding="utf-8",
            )
            self.assertEqual(
                self._classify_native_result(
                    "auth", "timeout", 124, stdout_path, stderr_path
                ),
                "timeout",
            )
            stderr_path.write_text(
                "ERROR 1045 (28000): unrelated wrapper failure\n", encoding="utf-8"
            )
            self.assertEqual(
                self._classify_native_result(
                    "auth", "runtime", 125, stdout_path, stderr_path
                ),
                "runtime",
            )
            stderr_path.write_text("ERROR 9999 (HY000): unrelated failure\n", encoding="utf-8")
            self.assertEqual(
                self._classify_native_result(
                    "auth", "exited", 125, stdout_path, stderr_path
                ),
                "unexpected-error",
            )
            stderr_path.write_text(
                "ERROR 2003 (HY000): Can't connect to MySQL server\n",
                encoding="utf-8",
            )
            self.assertEqual(
                self._classify_native_result(
                    "connection", "exited", 1, stdout_path, stderr_path
                ),
                "expected",
            )

    def test_status_classification_accepts_only_pinned_unsupported_diagnostics(self) -> None:
        positive_fixtures = {
            "master-batch": (
                "ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; "
                "check the manual that corresponds to your MySQL server version for the "
                "right syntax to use near 'MASTER STATUS' at line 1\n"
            ),
            "slave-client": (
                "ERROR 1064 (42000): You have an error in your SQL syntax; "
                "check the manual that corresponds to your MySQL server version for the "
                "right syntax to use near 'slave status' at line 1\n"
            ),
        }
        for fixture_name, diagnostic in positive_fixtures.items():
            kind = "master" if fixture_name.startswith("master") else "slave"
            with self.subTest(fixture_name=fixture_name):
                self.assertEqual(
                    self._classify_status_result(kind, "exited", 1, "", diagnostic),
                    "unsupported-sql",
                )

        negative_fixtures = {
            "generic-unknown-error": (
                "ERROR 1105 (HY000): Unknown error while executing SHOW MASTER STATUS\n"
            ),
            "unrelated-diagnostic-with-separate-marker": (
                "ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; "
                "check the manual near 'OTHER STATUS' at line 1\n"
                "SHOW MASTER STATUS\n"
            ),
            "wrong-statement": (
                "ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; "
                "check the manual near 'SLAVE STATUS' at line 1\n"
            ),
            "mixed-expected-and-unexpected": (
                "ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; "
                "check the manual near 'MASTER STATUS' at line 1\n"
                "ERROR 1105 (HY000): Unknown error\n"
            ),
        }
        for fixture_name, diagnostic in negative_fixtures.items():
            with self.subTest(fixture_name=fixture_name):
                self.assertEqual(
                    self._classify_status_result("master", "exited", 1, "", diagnostic),
                    "unexpected-error",
                )

        self.assertEqual(self._classify_status_result("master", "exited", 0, "", ""), "empty-output")
        self.assertEqual(
            self._classify_status_result("master", "exited", 0, "mysql-bin.000001\t4\n", ""),
            "available",
        )
        self.assertEqual(
            self._classify_status_result(
                "master",
                "exited",
                1,
                "",
                "ERROR 1045 (28000): Access denied for user while running SHOW MASTER STATUS\n",
            ),
            "auth-failure",
        )
        self.assertEqual(
            self._classify_status_result(
                "master",
                "exited",
                1,
                "",
                "ERROR 2003 (HY000): Can't connect to MySQL server for SHOW MASTER STATUS\n",
            ),
            "connection-failure",
        )
        self.assertEqual(
            self._classify_status_result(
                "master", "exited", 1, "", "ERROR 1064 (42000): syntax error near 'OTHER'\n"
            ),
            "unexpected-error",
        )
        self.assertEqual(
            self._classify_status_result("master", "runtime", 125, "", positive_fixtures["master-batch"]),
            "runtime",
        )
        self.assertEqual(self._classify_status_result("master", "timeout", 124, "", ""), "timeout")

        self.assertTrue(
            self._status_correlates("master", "compatibility-empty-list", "unsupported-sql")
        )
        self.assertFalse(
            self._status_correlates("master", "compatibility-empty-list", "empty-output")
        )
        self.assertTrue(self._status_correlates("processlist", "available", "available"))
        self.assertFalse(self._status_correlates("processlist", "available", "auth-failure"))

    def test_status_shape_distinguishes_missing_key_from_present_null(self) -> None:
        self.assertEqual(
            self._classify_status_json(
                "slave", {"Master_Port": 3306, "Seconds_Behind_Master": None}
            ),
            "available",
        )
        self.assertEqual(
            self._classify_status_json("slave", {"Master_Port": 3306}),
            "missing-key",
        )
        self.assertEqual(
            self._classify_status_json("master", {"File": "mysql-bin.000001"}),
            "missing-key",
        )
        self.assertEqual(
            self._classify_status_json(
                "master", {"File": "mysql-bin.000001", "Position": None}
            ),
            "invalid-type",
        )

    def test_lifecycle_mutations_fail_closed_on_precheck_and_ownership(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
LIFECYCLE_DB=statekit_r93j_1_2
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
CALLS="$work_dir/calls"
statekit_call() {
  printf 'dispatched\n' >> "$CALLS"
  return 0
}
LIFECYCLE_DB_RESERVED=0
if check_statekit_db_create; then
  create_rc=0
else
  create_rc=$?
fi
LIFECYCLE_DB_RESERVED=1
LIFECYCLE_DB_OWNED=0
if check_statekit_db_remove; then
  remove_rc=0
else
  remove_rc=$?
fi
call_count=0
[[ -f "$CALLS" ]] && call_count=$(wc -l < "$CALLS")
printf 'create_rc=%s remove_rc=%s call_count=%s\n' "$create_rc" "$remove_rc" "$call_count"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "lifecycle-prechecks", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("create_rc=1 remove_rc=1 call_count=0", result.stdout)

    def test_interrupted_create_is_reconciled_inside_the_reservation(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
LIFECYCLE_DB=statekit_r93j_1_2
LIFECYCLE_DB_RESERVED=1
LIFECYCLE_DB_OWNED=0
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
STATEKIT_CALLS="$work_dir/statekit-calls"
NATIVE_CALLS="$work_dir/native-calls"
statekit_call() {
  : > "$6"
  : > "$7"
  printf 'statekit\n' >> "$STATEKIT_CALLS"
  LAST_CLIENT_CLASS=timeout
  LAST_CLIENT_EXIT_RC=124
  return 124
}
native_mysql_as_user() {
  printf 'native\n' >> "$NATIVE_CALLS"
  printf '%s\n' "$LIFECYCLE_DB" > "$6"
  : > "$7"
  return 0
}
if check_statekit_db_create; then
  create_rc=0
else
  create_rc=$?
fi
statekit_count=$(wc -l < "$STATEKIT_CALLS")
native_count=$(wc -l < "$NATIVE_CALLS")
printf 'create_rc=%s owned=%s reserved=%s statekit_count=%s native_count=%s\n' \
  "$create_rc" "$LIFECYCLE_DB_OWNED" "$LIFECYCLE_DB_RESERVED" "$statekit_count" "$native_count"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "interrupted-create", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "create_rc=1 owned=1 reserved=1 statekit_count=1 native_count=1",
            result.stdout,
        )

    def test_alter_unreserved_target_has_zero_dispatch(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
ALTER_DB=statekit_r93l_1_2
ALTER_DB_RESERVED=0
ALTER_DB_OWNED=0
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
CALL_COUNT=0
statekit_call() {
  CALL_COUNT=$((CALL_COUNT + 1))
  return 0
}
if check_statekit_alter_explicit; then
  alter_rc=0
else
  alter_rc=$?
fi
printf 'alter_rc=%s call_count=%s note=%s' "$alter_rc" "$CALL_COUNT" "$SETUP_NOTE"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "alter-unreserved", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "alter_rc=1 call_count=0 note=alter-absence-reservation-required",
            result.stdout,
        )

    def test_alter_interrupted_seed_keeps_cleanup_ownership(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
ALTER_DB=statekit_r93l_1_2
ALTER_DB_RESERVED=1
ALTER_DB_OWNED=0
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
NATIVE_COUNT=0
native_mysql_as_user() {
  NATIVE_COUNT=$((NATIVE_COUNT + 1))
  : > "$6"
  : > "$7"
  if (( NATIVE_COUNT == 2 )); then
    printf '%s' '1' > "$6"
  fi
  if (( NATIVE_COUNT == 1 )); then
    return 124
  fi
  return 0
}
if check_native_alter_create_seed; then
  seed_rc=0
else
  seed_rc=$?
fi
printf 'seed_rc=%s owned=%s reserved=%s native_count=%s note=%s' \
  "$seed_rc" "$ALTER_DB_OWNED" "$ALTER_DB_RESERVED" "$NATIVE_COUNT" "$SETUP_NOTE"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "alter-interrupted-seed", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "seed_rc=1 owned=1 reserved=1 native_count=2 note=alter-create-or-seed-failed",
            result.stdout,
        )

    def test_alter_reserved_cleanup_drop_failure_propagates(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
ALTER_DB=statekit_r93l_1_2
ALTER_DB_RESERVED=1
ALTER_DB_OWNED=1
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
native_mysql_as_user() {
  : > "$6"
  : > "$7"
  if [[ "$5" == DROP* ]]; then
    return 9
  fi
  return 0
}
if cleanup_alter_database; then
  cleanup_rc=0
else
  cleanup_rc=$?
fi
printf 'cleanup_rc=%s cleanup_failed=%s reserved=%s owned=%s note=%s' \
  "$cleanup_rc" "$CLEANUP_FAILED" "$ALTER_DB_RESERVED" "$ALTER_DB_OWNED" "$CLEANUP_NOTE"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "alter-drop-failure", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "cleanup_rc=1 cleanup_failed=1 reserved=1 owned=1 note=alter-cleanup-drop-failed",
            result.stdout,
        )

    def test_alter_reserved_cleanup_uncertain_absence_fails_closed(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
ALTER_DB=statekit_r93l_1_2
ALTER_DB_RESERVED=1
ALTER_DB_OWNED=1
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
native_mysql_as_user() {
  : > "$6"
  : > "$7"
  if [[ "$5" != DROP* ]]; then
    printf '%s' 'uncertain-result' > "$6"
  fi
  return 0
}
if cleanup_alter_database; then
  cleanup_rc=0
else
  cleanup_rc=$?
fi
printf 'cleanup_rc=%s cleanup_failed=%s reserved=%s owned=%s note=%s' \
  "$cleanup_rc" "$CLEANUP_FAILED" "$ALTER_DB_RESERVED" "$ALTER_DB_OWNED" "$CLEANUP_NOTE"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "alter-uncertain-absence", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "cleanup_rc=1 cleanup_failed=1 reserved=1 owned=1 note=alter-cleanup-absence-uncertain",
            result.stdout,
        )

    def test_alter_cleanup_cancellation_fails_closed(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
ALTER_DB=statekit_r93l_1_2
ALTER_DB_RESERVED=1
ALTER_DB_OWNED=1
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
native_mysql_as_user() {
  : > "$6"
  : > "$7"
  return 130
}
if cleanup_alter_database; then
  cleanup_rc=0
else
  cleanup_rc=$?
fi
printf 'cleanup_rc=%s cleanup_failed=%s reserved=%s owned=%s note=%s' \
  "$cleanup_rc" "$CLEANUP_FAILED" "$ALTER_DB_RESERVED" "$ALTER_DB_OWNED" "$CLEANUP_NOTE"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "alter-cancellation", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "cleanup_rc=1 cleanup_failed=1 reserved=1 owned=1 note=alter-cleanup-drop-failed",
            result.stdout,
        )

    def test_invalid_identifier_requires_completed_expected_validation_rejection(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
LIFECYCLE_DB=statekit_r93j_1_2
LIFECYCLE_DB_RESERVED=1
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
statekit_call() {
  : > "$6"
  : > "$7"
  case "$FAULT_MODE" in
    expected)
      printf '%s\n' "$STATEKIT_INVALID_IDENTIFIER_DIAGNOSTIC" > "$7"
      LAST_CLIENT_CLASS=exited
      LAST_CLIENT_EXIT_RC=1
      return 1
      ;;
    setup)
      LAST_CLIENT_CLASS=setup
      LAST_CLIENT_EXIT_RC=125
      return 125
      ;;
    runtime)
      LAST_CLIENT_CLASS=runtime
      LAST_CLIENT_EXIT_RC=125
      return 125
      ;;
    timeout)
      LAST_CLIENT_CLASS=timeout
      LAST_CLIENT_EXIT_RC=124
      return 124
      ;;
    cleanup)
      LAST_CLIENT_CLASS=cleanup
      LAST_CLIENT_EXIT_RC=125
      return 125
      ;;
    unrelated)
      printf '%s\n' 'statekit: mysql: invalid argument: unsupported value in collate' > "$7"
      LAST_CLIENT_CLASS=exited
      LAST_CLIENT_EXIT_RC=1
      return 1
      ;;
  esac
}
if check_statekit_invalid_identifier_negative; then
  printf 'rc=0\n'
else
  printf 'rc=%s\n' "$?"
fi
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            for mode in ("expected", "setup", "runtime", "timeout", "cleanup", "unrelated"):
                environment = os.environ.copy()
                environment["FAULT_MODE"] = mode
                result = subprocess.run(
                    ["bash", "-c", command, "invalid-identifier", str(SCRIPT), str(Path(temporary_directory))],
                    cwd=ROOT,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, (mode, result.stderr))
                if mode == "expected":
                    self.assertEqual(result.stdout.strip(), "rc=0")
                else:
                    self.assertRegex(result.stdout, r"^rc=[1-9][0-9]*$")

    def test_cleanup_uncertainty_fails_closed(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
ROOT_CLIENT_SECRET=root-secret
DB_HOST=mysql-host
LIFECYCLE_DB=statekit_r93j_1_2
LIFECYCLE_DB_RESERVED=1
LIFECYCLE_DB_OWNED=1
ROOT_PASSWORD=root-marker
LIVE_PASSWORD=live-marker
BAD_PASSWORD=bad-marker
native_mysql_as_user() {
  if [[ "$5" == DROP* ]]; then
    : > "$6"
  else
    printf 'unexpected-output\n' > "$6"
  fi
  : > "$7"
  return 0
}
if cleanup_lifecycle_database; then
  cleanup_rc=0
else
  cleanup_rc=$?
fi
printf 'cleanup_rc=%s cleanup_failed=%s note=%s\n' "$cleanup_rc" "$CLEANUP_FAILED" "$CLEANUP_NOTE"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "cleanup-uncertainty", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cleanup_rc=1 cleanup_failed=1", result.stdout)
        self.assertIn("lifecycle-cleanup-absence-uncertain", result.stdout)

    def test_case_result_integrity_rejects_duplicate_unknown_missing_and_substituted(self) -> None:
        command = r'''
script_path="$1"
report_root="$2"
set --
source "$script_path"
set +e
setup_report() {
  REPORT_DIR="$1"
  REPORT_PATH="$REPORT_DIR/report.txt"
  mkdir -p "$REPORT_DIR"
  REPORT_PREPARED=1
  REPORT_WRITTEN=0
  EXECUTION_COMPLETE=1
  EXECUTION_RC=0
  FINAL_RC=0
  CANCELLED=0
  CLEANUP_FAILED=0
  PASSED=0
  FAILED=0
  SKIPPED=0
  CASE_RESULT_INTEGRITY_FAILED=0
  SETUP_NOTE=none
  CLEANUP_NOTE=none
  CASE_RESULTS=()
}
setup_report "$report_root/duplicate"
record_case "${CASE_IDS[0]}" pass
if record_case "${CASE_IDS[0]}" pass; then duplicate_rc=0; else duplicate_rc=$?; fi
if record_case unknown-case pass; then unknown_rc=0; else unknown_rc=$?; fi
write_report
duplicate_status=$(awk -F': ' '$1 == "status" {print $2}' "$REPORT_PATH")
setup_report "$report_root/missing"
for ((index=0; index<${#CASE_IDS[@]}-1; index++)); do
  record_case "${CASE_IDS[index]}" pass
done
write_report
missing_status=$(awk -F': ' '$1 == "status" {print $2}' "$REPORT_PATH")
setup_report "$report_root/substituted"
for case_id in "${CASE_IDS[@]}"; do
  CASE_RESULTS+=("$case_id=pass")
done
CASE_RESULTS[0]='substituted-case=pass'
PASSED=${#CASE_IDS[@]}
write_report
substituted_status=$(awk -F': ' '$1 == "status" {print $2}' "$REPORT_PATH")
printf 'duplicate_rc=%s unknown_rc=%s duplicate_status=%s missing_status=%s substituted_status=%s\n' \
  "$duplicate_rc" "$unknown_rc" "$duplicate_status" "$missing_status" "$substituted_status"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "case-integrity", str(SCRIPT), str(Path(temporary_directory))],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "duplicate_rc=1 unknown_rc=1 duplicate_status=fail missing_status=fail substituted_status=fail",
            result.stdout,
        )

    def test_incomplete_execution_is_reported_as_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            report_directory = temporary / "report"
            environment = os.environ.copy()
            environment.update(
                {
                    "REPORT_DIR": str(report_directory),
                    "STATEKIT_BIN": str(temporary / "missing-statekit"),
                    "CONTAINER_RUNTIME": "podman",
                }
            )
            result = subprocess.run(
                [str(SCRIPT)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            report = (report_directory / "report.txt").read_text(encoding="utf-8")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("status: fail", report)
            self.assertIn("execution: incomplete", report)
            self.assertIn("cases_total: 48", report)
            self.assertIn("cases_skipped: 47", report)

    def test_stale_or_unwritable_report_is_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            report_directory = temporary / "report"
            report_directory.mkdir()
            report_path = report_directory / "report.txt"
            report_path.write_text("status: pass\nstale-marker\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                {
                    "REPORT_DIR": str(report_directory),
                    "STATEKIT_BIN": str(temporary / "missing-statekit"),
                }
            )
            result = subprocess.run(
                [str(SCRIPT)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            fresh_report = report_path.read_text(encoding="utf-8")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("status: fail", fresh_report)
            self.assertNotIn("stale-marker", fresh_report)

            report_path.unlink()
            report_path.mkdir()
            blocked_environment = os.environ.copy()
            blocked_environment.update(
                {
                    "REPORT_DIR": str(report_directory),
                    "STATEKIT_BIN": str(temporary / "missing-statekit"),
                }
            )
            blocked = subprocess.run(
                [str(SCRIPT)],
                cwd=ROOT,
                env=blocked_environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("e5.2: report write failed", blocked.stderr)

    def test_workflow_is_fork_safe_and_uses_immutable_actions(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("types: [opened, synchronize, reopened, ready_for_review]", workflow)
        self.assertIn("branches:\n      - main", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("schedule:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("issues: write", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertIn("persist-credentials: false", workflow)
        action_refs = re.findall(r"^\s*(?:- )?uses: ([^\s#]+)$", workflow, re.MULTILINE)
        self.assertGreaterEqual(len(action_refs), 2)
        for action_ref in action_refs:
            self.assertRegex(action_ref, r"@[0-9a-f]{40}$")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("permissions:\n      contents: read", workflow)

    def _run_cleanup_fault(self, mode: str, container_id: str = "container-id") -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            state = temporary / "removed"
            log = temporary / "runtime.log"
            runtime_script = """#!/usr/bin/env bash
set -u
command_name="${0##*/}"
printf '%s %s\n' "$command_name" "$*" >> "$FAKE_LOG"
if [[ "$command_name" == container && "${1:-}" == exists ]]; then
  [[ ! -e "$FAKE_STATE" ]]
  exit $?
fi
if [[ "$command_name" == stop ]]; then
  if [[ "$FAKE_MODE" == timeout ]]; then
    exit 124
  fi
  exit 0
fi
if [[ "$command_name" == kill ]]; then
  exit 0
fi
if [[ "$command_name" == rm ]]; then
  if [[ "$FAKE_MODE" == remove-failure ]]; then
    exit 1
  fi
  : > "$FAKE_STATE"
  exit 0
fi
exit 0
"""
            for runtime_command in ("container", "stop", "kill", "rm"):
                (temporary / runtime_command).write_text(runtime_script, encoding="utf-8")
            command = """
script_path="$1"
set --
source "$script_path"
cd "$FAKE_RUNTIME_DIR"
RUNTIME=/bin/bash
CLEANUP_FAILED=0
SETUP_NOTE=none
if cleanup_container "$FAKE_NAME" "$FAKE_ID"; then
  cleanup_rc=0
else
  cleanup_rc=$?
fi
printf 'cleanup_rc=%s cleanup_failed=%s\\n' "$cleanup_rc" "$CLEANUP_FAILED"
"""
            environment = os.environ.copy()
            environment.update(
                {
                    "FAKE_LOG": str(log),
                    "FAKE_STATE": str(state),
                    "FAKE_MODE": mode,
                    "FAKE_NAME": "client-name",
                    "FAKE_ID": container_id,
                    "FAKE_RUNTIME_DIR": str(temporary),
                }
            )
            result = subprocess.run(
                ["bash", "-c", command, "cleanup-fault", str(SCRIPT)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            runtime_log = log.read_text(encoding="utf-8") if log.exists() else (
                f"<missing log> stdout={result.stdout!r} stderr={result.stderr!r}"
            )
            return result, runtime_log

    def test_cleanup_timeout_escalates_term_then_kill_and_verifies_removal(self) -> None:
        started = time.monotonic()
        result, log = self._run_cleanup_fault("timeout")
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cleanup_rc=0 cleanup_failed=0", result.stdout)
        self.assertLess(elapsed, 4.0)
        self.assertIn("stop --time 5", log)
        self.assertIn("kill", log)
        self.assertIn("rm --force --volumes", log)

    def test_cleanup_partial_create_tracks_name_without_id(self) -> None:
        result, log = self._run_cleanup_fault("normal", container_id="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cleanup_rc=0 cleanup_failed=0", result.stdout)
        self.assertIn("container exists client-name", log)
        self.assertIn("rm --force --volumes client-name", log)

    def test_cleanup_remove_failure_changes_cleanup_result(self) -> None:
        result, log = self._run_cleanup_fault("remove-failure")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cleanup_failed=1", result.stdout)
        self.assertIn("rm --force --volumes", log)

    def test_repeated_term_is_ignored_during_cleanup_and_cannot_claim_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            state = temporary / "removed"
            log = temporary / "runtime.log"
            report_directory = temporary / "report"
            report_directory.mkdir()
            runtime_script = """#!/usr/bin/env bash
set -u
command_name="${0##*/}"
printf '%s %s\n' "$command_name" "$*" >> "$FAKE_LOG"
if [[ "$command_name" == container && "${1:-}" == exists ]]; then
  [[ ! -e "$FAKE_STATE" ]]
  exit $?
fi
if [[ "$command_name" == stop ]]; then
  sleep 0.3
  exit 0
fi
if [[ "$command_name" == rm ]]; then
  : > "$FAKE_STATE"
  exit 0
fi
exit 0
"""
            for runtime_command in ("container", "stop", "kill", "rm"):
                (temporary / runtime_command).write_text(runtime_script, encoding="utf-8")
            command = """
script_path="$1"
set --
source "$script_path"
cd "$FAKE_RUNTIME_DIR"
RUNTIME=/bin/bash
REPORT_DIR="$FAKE_REPORT_DIR"
REPORT_PATH="$REPORT_DIR/report.txt"
REPORT_PREPARED=1
OWNED_CLIENT_NAMES=(client-name)
OWNED_CLIENT_IDS=(container-id)
trap cleanup EXIT
trap 'CANCELLED=1; CANCEL_SIGNAL=TERM; CANCEL_RC=143; exit 143' TERM
( sleep 0.05; kill -TERM "$$" ) &
kill -TERM "$$"
"""
            environment = os.environ.copy()
            environment.update(
                {
                    "FAKE_LOG": str(log),
                    "FAKE_STATE": str(state),
                    "FAKE_REPORT_DIR": str(report_directory),
                    "FAKE_RUNTIME_DIR": str(temporary),
                }
            )
            result = subprocess.run(
                ["bash", "-c", command, "repeated-term", str(SCRIPT)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            report = (report_directory / "report.txt").read_text(encoding="utf-8")
            log_contents = log.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertIn("final_rc: 143", report)
        self.assertIn("status: fail", report)
        self.assertIn("rm --force --volumes", log_contents)


if __name__ == "__main__":
    unittest.main()
