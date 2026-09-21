#!/usr/bin/env python3
"""Deterministic, non-live checks for the E5.2 orchestration boundary."""

from __future__ import annotations

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
)


class E52OrchestrationTests(unittest.TestCase):
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
        self.assertIn("container inspect", source)
        self.assertIn("--format", source)
        self.assertIn("Config.Secrets", source)
        self.assertIn("Config.Env", source)
        self.assertNotIn("inspect_path", source)
        self.assertNotIn("json.load(inspect", source)
        self.assertIn("container exists", source)
        self.assertIn("network exists", source)
        self.assertIn("cleanup_container()", source)
        self.assertIn("stop --time 5", source)
        self.assertIn("secret rm", source)
        self.assertIn("CLEANUP_FAILED=1", source)
        self.assertIn("REPORT_PREPARED=1", source)
        self.assertIn("--force --volumes", source)
        self.assertIn("trap '' INT TERM", source)
        self.assertIn("execution_rc:", source)
        self.assertIn("final_rc:", source)
        self.assertIn("LIFECYCLE_DB=", source)
        self.assertIn("DROP DATABASE IF EXISTS", source)
        self.assertIn("mysql.db_create", source)
        self.assertIn("mysql.db_remove", source)
        self.assertIn("external_ci: pending", source)
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
        self.assertIn("e5.2 live mysql read-only/catalog/plugin/database-lifecycle", workflow)
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
            self.assertIn("cases_total: 23", report)
            self.assertIn("cases_skipped: 22", report)

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
