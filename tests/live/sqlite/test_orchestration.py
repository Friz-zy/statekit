#!/usr/bin/env python3
"""Static, non-live checks for the E5.3 SQLite gate boundary."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tests/live/sqlite/run.sh"
WORKFLOW = ROOT / ".github/workflows/integration-services.yml"
EXPECTED_CASES = (
    "sqlite-version-live",
    "sqlite-sqlite-version-live",
    "sqlite-modify-create-live",
    "sqlite-modify-insert-live",
    "sqlite-fetch-live",
    "sqlite-tables-live",
    "sqlite-indices-live",
    "sqlite-indexes-alias-live",
    "sqlite-native-row-postcondition",
    "sqlite-native-schema-postcondition",
    "sqlite-native-index-postcondition",
    "sqlite-invalid-path",
    "sqlite-invalid-sql",
    "sqlite-missing-db",
)


class E53OrchestrationTests(unittest.TestCase):
    def test_case_inventory_is_exact_without_a_runtime(self) -> None:
        result = subprocess.run(
            [str(SCRIPT), "--list-cases"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(tuple(result.stdout.splitlines()), EXPECTED_CASES)
        self.assertEqual(result.stderr, "")

    def test_gate_uses_production_binary_and_independent_native_observer(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"$STATEKIT_BIN" exec', source)
        self.assertIn("sqlite3 -batch -noheader", source)
        self.assertIn("python3-sqlite", source)
        self.assertIn("json.load", source)
        self.assertIn("NATIVE_AVAILABLE", source)
        self.assertIn("external_ci: pending_external_ci", source)
        self.assertIn("cases_skipped:", source)
        self.assertIn("case_results_are_exact", source)
        self.assertIn("cleanup_workdir", source)
        self.assertIn("bounded_timeout", source)
        self.assertIn("--kill-after", source)
        self.assertIn("CLEANUP_RUNNING", source)
        self.assertIn("REPORT_TMP_PATH", source)
        self.assertIn("WORK_DIR_RESERVED", source)
        self.assertNotIn("FakeRunner", source)

    def test_report_is_value_free_and_skip_or_zero_is_not_success(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        report_function = source.split("write_report()", 1)[1].split("prepare_report()", 1)[0]
        for value in ("DB_PATH", "LAST_OUTPUT_PATH", "LAST_ERROR_PATH", "LAST_NATIVE", "marker"):
            self.assertNotIn(f"${value}", report_function)
        self.assertIn("passed == ${#CASE_IDS[@]}", source)
        self.assertIn("skipped == 0", source)
        self.assertIn("cases_total:", report_function)
        self.assertIn("FINAL_RC == 0", report_function)

    def test_index_setup_is_checked_before_both_index_cases(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        setup = source.index("if ! prepare_index; then")
        indices_case = source.index("run_case sqlite-indices-live")
        alias_case = source.index("run_case sqlite-indexes-alias-live")
        self.assertLess(setup, indices_case)
        self.assertLess(setup, alias_case)
        self.assertIn("CREATE INDEX observations_value ON observations(value)", source)
        self.assertIn("INDEX_SETUP_OK=1", source)
        self.assertIn("require_index_setup", source)

    def test_missing_index_setup_cannot_pass_any_index_case(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
mkdir -p "$WORK_DIR"
INDEX_SETUP_OK=0
case_indices; indices_rc=$?
case_indexes_alias; alias_rc=$?
case_native_index; native_rc=$?
printf 'indices_rc=%s alias_rc=%s native_rc=%s note=%s\n' \
  "$indices_rc" "$alias_rc" "$native_rc" "$SETUP_NOTE"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "missing-index-setup", str(SCRIPT), temporary_directory],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("indices_rc=1 alias_rc=1 native_rc=1", result.stdout)
        self.assertIn("index-setup-not-confirmed", result.stdout)

    def test_failed_index_setup_cannot_pass_or_mark_setup_ready(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
mkdir -p "$WORK_DIR"
DB_PATH="$WORK_DIR/catalog.sqlite"
statekit_call() {
  return 1
}
if prepare_index; then
  setup_rc=0
else
  setup_rc=$?
fi
case_indices; indices_rc=$?
case_indexes_alias; alias_rc=$?
case_native_index; native_rc=$?
printf 'setup_rc=%s index_ready=%s indices_rc=%s alias_rc=%s native_rc=%s note=%s\n' \
  "$setup_rc" "$INDEX_SETUP_OK" "$indices_rc" "$alias_rc" "$native_rc" "$SETUP_NOTE"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "failed-index-setup", str(SCRIPT), temporary_directory],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "setup_rc=1 index_ready=0 indices_rc=1 alias_rc=1 native_rc=1",
            result.stdout,
        )
        self.assertIn("index-setup-failed", result.stdout)

    def test_json_comparison_accepts_pretty_and_compact_values(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
actual="$work_dir/actual.json"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
mkdir -p "$WORK_DIR"
printf '[\n  [1, "live"]\n]\n' > "$actual"
if json_value_equals '[[1,"live"]]' "$actual"; then
  printf 'compact=pass\n'
else
  printf 'compact=fail\n'
fi
printf '{\n  "enabled": true,\n  "items": [1, {"ready": false}]\n}\n' > "$actual"
if json_value_equals '{"enabled":true,"items":[1,{"ready":false}]}' "$actual"; then
  printf 'nested=pass\n'
else
  printf 'nested=fail\n'
fi
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "json-decode", str(SCRIPT), temporary_directory],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["compact=pass", "nested=pass"])

    def test_json_comparison_rejects_top_level_bool_number_mismatches(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
actual="$work_dir/actual.json"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
mkdir -p "$WORK_DIR"
check_mismatch() {
  local label="$1" expected="$2" actual_json="$3"
  printf '%s' "$actual_json" > "$actual"
  if json_value_equals "$expected" "$actual"; then
    printf '%s=pass\n' "$label"
  else
    printf '%s=fail\n' "$label"
  fi
}
check_mismatch true true 1
check_mismatch false false 0
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "json-top-level-types", str(SCRIPT), temporary_directory],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["true=fail", "false=fail"])

    def test_json_comparison_rejects_nested_bool_number_mismatches(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
actual="$work_dir/actual.json"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir"
mkdir -p "$WORK_DIR"
check_mismatch() {
  local label="$1" expected="$2" actual_json="$3"
  printf '%s' "$actual_json" > "$actual"
  if json_value_equals "$expected" "$actual"; then
    printf '%s=pass\n' "$label"
  else
    printf '%s=fail\n' "$label"
  fi
}
check_mismatch nested-one '{"enabled":true,"items":[{"ready":false}]}' '{"enabled":1,"items":[{"ready":false}]}'
check_mismatch nested-zero '{"enabled":true,"items":[{"ready":false}]}' '{"enabled":true,"items":[{"ready":0}]}'
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "json-nested-types", str(SCRIPT), temporary_directory],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["nested-one=fail", "nested-zero=fail"])

    def test_report_is_fresh_ordered_and_pass_requires_zero_skips(self) -> None:
        command = r'''
script_path="$1"
report_directory="$2"
set --
source "$script_path"
set +e
REPORT_DIR="$report_directory"
REPORT_PATH="$REPORT_DIR/report.txt"
mkdir -p "$REPORT_DIR"
printf 'status: pass\nstale-marker\n' > "$REPORT_PATH"
prepare_report || exit 1
EXECUTION_COMPLETE=1
EXECUTION_RC=0
FINAL_RC=0
CANCELLED=0
CLEANUP_FAILED=0
for case_id in "${CASE_IDS[@]}"; do
  record_case "$case_id" pass || exit 1
done
write_report || exit 1
printf 'status=%s\n' "$(awk -F': ' '$1 == "status" { print $2 }' "$REPORT_PATH")"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "fresh-report", str(SCRIPT), temporary_directory],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            report = (Path(temporary_directory) / "report.txt").read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "status=pass")
        self.assertNotIn("stale-marker", report)
        self.assertNotIn("1|live", report)
        self.assertEqual(
            [line.removeprefix("case: ") for line in report.splitlines() if line.startswith("case: ")],
            [f"{case_id}=pass" for case_id in EXPECTED_CASES],
        )
        self.assertIn("cases_skipped: 0", report)

    def test_workflow_has_separate_sqlite_job_and_does_not_change_mysql_job_name(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        sqlite_job = workflow.split("  sqlite-live:", 1)[1]
        self.assertIn("sqlite-live:", workflow)
        self.assertIn("e5.3 live sqlite catalog", workflow)
        self.assertIn("tests/live/sqlite/run.sh --preflight-only", workflow)
        self.assertIn("podman start --attach \"$live_container\"", sqlite_job)
        self.assertIn('podman cp "$extract_container:/out/statekit" "$live_container:/workspace/statekit"', sqlite_job)
        self.assertIn("--network=none", sqlite_job)
        self.assertIn("live_container", sqlite_job)
        self.assertNotIn("STATEKIT_BIN: ${{ github.workspace }}/dist/statekit", sqlite_job)
        self.assertIn("e5-3-sqlite-live-report", workflow)
        self.assertIn("mysql-live:", workflow)
        self.assertIn("e5.2 live mysql read-only/catalog/plugin/database-lifecycle", workflow)

    def test_workflow_owns_durable_value_free_report_volume_and_verifies_copy(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        sqlite_job = workflow.split("  sqlite-live:", 1)[1]

        self.assertIn('report_volume="statekit-e53-sqlite-report-${run_suffix}"', sqlite_job)
        self.assertIn("report_volume_reserved=0", sqlite_job)
        self.assertIn('reserve_resource_name volume "$report_volume"', sqlite_job)
        self.assertIn('podman volume create "$report_volume"', sqlite_job)
        self.assertIn(
            '--volume "${report_volume}:/tmp/sqlite-live-report:rw,U,nocreate"',
            sqlite_job,
        )
        self.assertIn('verify_sandbox_policy "$live_container" report-volume', sqlite_job)
        self.assertIn('podman volume rm "$report_volume"', sqlite_job)
        self.assertIn("cleanup_volume", sqlite_job)
        self.assertIn("workflow-resource-cleanup-failed", sqlite_job)
        self.assertIn('[[ -f "$report_path" ]]', sqlite_job)
        self.assertIn(
            '[[ -f "$report_path" && ! -L "$report_path" && -s "$report_path" ]]',
            sqlite_job,
        )
        self.assertIn("report_copy_rc != 0", sqlite_job)
        self.assertNotIn('--volume "$GITHUB_WORKSPACE', sqlite_job)

        live_start = sqlite_job.index('podman start --attach "$live_container"')
        report_copy = sqlite_job.index('"$live_container:/tmp/sqlite-live-report/report.txt"')
        run_exit = sqlite_job.index("if (( run_rc != 0 || report_copy_rc != 0 )); then")
        self.assertLess(live_start, report_copy)
        self.assertLess(report_copy, run_exit)
        self.assertIn("trap cleanup_isolated_resources EXIT INT TERM", sqlite_job)

    def test_workflow_rejects_stale_host_report_before_external_execution(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        report_setup = workflow.split(
            "      - name: create fresh value-free live report directory", 1
        )[1].split(
            "      - name: isolated dependency fetch, build, checks, and live file gate", 1
        )[0]
        self.assertIn("rm -f -- artifacts/sqlite-live/report.txt", report_setup)
        self.assertIn(
            "[[ -e artifacts/sqlite-live/report.txt || -L artifacts/sqlite-live/report.txt ]]",
            report_setup,
        )

    def test_harness_cleanup_failure_is_reported(self) -> None:
        command = r'''
script_path="$1"
work_dir="$2"
set --
source "$script_path"
set +e
WORK_DIR="$work_dir/owned"
DB_PATH="$WORK_DIR/catalog.sqlite"
WORK_DIR_RESERVED=1
DB_FILE_RESERVED=1
mkdir -p "$WORK_DIR"
bounded_timeout() {
  return 42
}
if cleanup_workdir; then
  cleanup_rc=0
else
  cleanup_rc=$?
fi
printf 'cleanup_rc=%s cleanup_failed=%s note=%s remains=%s\n' \
  "$cleanup_rc" "$CLEANUP_FAILED" "$CLEANUP_NOTE" \
  "$([[ -e "$WORK_DIR" ]] && printf true || printf false)"
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = subprocess.run(
                ["bash", "-c", command, "cleanup-failure", str(SCRIPT), temporary_directory],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "cleanup_rc=1 cleanup_failed=1 note=temporary-directory-remove-failed-or-timeout remains=true",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
