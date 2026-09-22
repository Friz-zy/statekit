#!/usr/bin/env bash
# E5.3 live SQLite gate for the production sqlite3 catalog family.
#
# The binary is invoked directly, never through a fake Runner.  The database is
# created in an owned disposable directory and an independent native SQLite
# observer observes the same file after StateKit mutations.  All command output stays in
# private temporary files and is discarded; the report contains only fixed
# case IDs, counts, and status metadata.
set -euo pipefail

readonly DRIVER_VERSION='1.58.0'
readonly SQLITE_VERSION='3.53.4'
readonly CLIENT_TIMEOUT_SECONDS=35
readonly CLEANUP_TIMEOUT_SECONDS=10
readonly TERMINATION_GRACE_SECONDS=5
readonly CASE_IDS=(
  'sqlite-version-live'
  'sqlite-sqlite-version-live'
  'sqlite-modify-create-live'
  'sqlite-modify-insert-live'
  'sqlite-fetch-live'
  'sqlite-tables-live'
  'sqlite-indices-live'
  'sqlite-indexes-alias-live'
  'sqlite-native-row-postcondition'
  'sqlite-native-schema-postcondition'
  'sqlite-native-index-postcondition'
  'sqlite-invalid-path'
  'sqlite-invalid-sql'
  'sqlite-missing-db'
)

if [[ "${1:-}" == '--list-cases' ]]; then
  printf '%s\n' "${CASE_IDS[@]}"
  exit 0
fi

PREFLIGHT_ONLY=0
if [[ "${1:-}" == '--preflight-only' ]]; then
  PREFLIGHT_ONLY=1
  shift
fi
if (( $# != 0 )); then
  printf '%s\n' 'usage: tests/live/sqlite/run.sh [--list-cases|--preflight-only]' >&2
  exit 2
fi

REPORT_DIR="${REPORT_DIR:-artifacts/sqlite-live}"
REPORT_PATH="$REPORT_DIR/report.txt"
STATEKIT_BIN="${STATEKIT_BIN:-dist/statekit}"
WORK_DIR=''
DB_PATH=''
WORK_DIR_RESERVED=0
DB_FILE_RESERVED=0
REPORT_PREPARED=0
REPORT_WRITTEN=0
REPORT_TMP_PATH=''
EXECUTION_COMPLETE=0
EXECUTION_RC=125
FINAL_RC=125
CANCELLED=0
CANCEL_SIGNAL='none'
CANCEL_RC=125
CLEANUP_FAILED=0
CLEANUP_RUNNING=0
SETUP_NOTE='none'
CLEANUP_NOTE='none'
NATIVE_AVAILABLE=0
NATIVE_OBSERVER='none'
CLIENT_SEQUENCE=0
LAST_NATIVE=''
LAST_OUTPUT_PATH=''
LAST_ERROR_PATH=''
LAST_NATIVE_PATH=''
JSON_COMPARE_SEQUENCE=0
INDEX_SETUP_OK=0
CASE_RESULT_INTEGRITY_FAILED=0
declare -a CASE_RESULTS=()

set_note() {
  if [[ "$SETUP_NOTE" == 'none' ]]; then
    SETUP_NOTE="$1"
  fi
}

set_cleanup_note() {
  if [[ "$CLEANUP_NOTE" == 'none' ]]; then
    CLEANUP_NOTE="$1"
  fi
}

case_id_is_known() {
  local case_id="$1" expected
  for expected in "${CASE_IDS[@]}"; do
    if [[ "$case_id" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

case_id_is_recorded() {
  local case_id="$1" entry
  for entry in "${CASE_RESULTS[@]}"; do
    [[ "${entry%%=*}" == "$case_id" ]] && return 0
  done
  return 1
}

record_case() {
  local case_id="$1" result="$2"
  if ! case_id_is_known "$case_id" || case_id_is_recorded "$case_id"; then
    CASE_RESULT_INTEGRITY_FAILED=1
    set_note 'case-inventory-integrity-failed'
    return 1
  fi
  case "$result" in
    pass|fail|skipped) ;;
    *)
      CASE_RESULT_INTEGRITY_FAILED=1
      set_note 'invalid-case-result'
      return 1
      ;;
  esac
  CASE_RESULTS+=("$case_id=$result")
}

run_case() {
  local case_id="$1"
  shift
  if "$@"; then
    record_case "$case_id" pass
  else
    record_case "$case_id" fail
  fi
}

mark_remaining_skipped() {
  local case_id
  for case_id in "${CASE_IDS[@]}"; do
    if ! case_id_is_recorded "$case_id"; then
      record_case "$case_id" skipped || return 1
    fi
  done
}

case_results_are_exact() {
  local index entry case_id result
  (( CASE_RESULT_INTEGRITY_FAILED == 0 )) || return 1
  if (( ${#CASE_RESULTS[@]} != ${#CASE_IDS[@]} )); then
    return 1
  fi
  for index in "${!CASE_IDS[@]}"; do
    entry="${CASE_RESULTS[index]:-}"
    case_id="${entry%%=*}"
    result="${entry#*=}"
    [[ "$case_id" == "${CASE_IDS[index]}" ]] || return 1
    case "$result" in pass|fail|skipped) ;; *) return 1 ;; esac
  done
}

count_result() {
  local wanted="$1" count=0 entry
  for entry in "${CASE_RESULTS[@]}"; do
    [[ "${entry#*=}" == "$wanted" ]] && count=$((count + 1))
  done
  printf '%d' "$count"
}

write_report() {
  (( REPORT_PREPARED == 1 && REPORT_WRITTEN == 0 )) || return 0
  local report_tmp passed failed skipped status exact
  passed=$(count_result pass)
  failed=$(count_result fail)
  skipped=$(count_result skipped)
  exact=0
  case_results_are_exact && exact=1
  status='fail'
  if (( EXECUTION_COMPLETE == 1 && EXECUTION_RC == 0 && FINAL_RC == 0 &&
    CANCELLED == 0 && CLEANUP_FAILED == 0 && CASE_RESULT_INTEGRITY_FAILED == 0 &&
    exact == 1 && passed == ${#CASE_IDS[@]} &&
    failed == 0 && skipped == 0 )); then
    status='pass'
  fi
   report_tmp=$(mktemp "$REPORT_DIR/.report.tmp.XXXXXX") || return 1
   REPORT_TMP_PATH="$report_tmp"
   if ! {
    printf '%s\n' 'schema: e5.3-sqlite-live-v1'
    printf 'cases_total: %d\n' "${#CASE_IDS[@]}"
    printf 'cases_passed: %d\n' "$passed"
    printf 'cases_failed: %d\n' "$failed"
    printf 'cases_skipped: %d\n' "$skipped"
    printf 'status: %s\n' "$status"
    printf 'execution: %s\n' "$([[ "$EXECUTION_COMPLETE" == 1 ]] && printf complete || printf incomplete)"
    printf 'execution_rc: %d\n' "$EXECUTION_RC"
    printf 'final_rc: %d\n' "$FINAL_RC"
    printf 'cancelled: %s\n' "$([[ "$CANCELLED" == 1 ]] && printf true || printf false)"
    printf 'cancellation_signal: %s\n' "$CANCEL_SIGNAL"
    printf 'setup_note: %s\n' "$SETUP_NOTE"
    printf 'cleanup: %s\n' "$([[ "$CLEANUP_FAILED" == 1 ]] && printf fail || printf pass)"
    printf 'cleanup_note: %s\n' "$CLEANUP_NOTE"
    printf 'scope: sqlite3.version/sqlite_version/modify/fetch/tables/indices/indexes'
    printf '%s\n' ' against a disposable actual SQLite file'
     printf '%s\n' 'independent_observer: native SQLite observer against the same file'
    printf 'driver_version: %s\n' "$DRIVER_VERSION"
    printf 'sqlite_version: %s\n' "$SQLITE_VERSION"
    printf '%s\n' 'external_ci: pending_external_ci'
    printf '%s\n' 'limitations: no live Salt differential parity; native observer availability is a required preflight; GitHub execution is not claimed here'
    local result
    for result in "${CASE_RESULTS[@]}"; do
      printf 'case: %s\n' "$result"
    done
   } >"$report_tmp"; then
     rm -f -- "$report_tmp"
     REPORT_TMP_PATH=''
     return 1
   fi
   if ! mv -f -- "$report_tmp" "$REPORT_PATH" || [[ ! -s "$REPORT_PATH" ]]; then
     rm -f -- "$report_tmp"
     REPORT_TMP_PATH=''
     return 1
   fi
   REPORT_TMP_PATH=''
   REPORT_WRITTEN=1
}

prepare_report() {
  mkdir -p -- "$REPORT_DIR" || return 1
  if [[ -e "$REPORT_PATH" || -L "$REPORT_PATH" ]]; then
    rm -f -- "$REPORT_PATH" || return 1
    [[ ! -e "$REPORT_PATH" && ! -L "$REPORT_PATH" ]] || return 1
  fi
  REPORT_PREPARED=1
}

cleanup_workdir() {
  if [[ -z "$WORK_DIR" ]]; then
    return 0
  fi
  if ! bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" rm -rf -- "$WORK_DIR"; then
    CLEANUP_FAILED=1
    set_cleanup_note 'temporary-directory-remove-failed-or-timeout'
    return 1
  fi
  if [[ -e "$WORK_DIR" || -L "$WORK_DIR" ]]; then
    CLEANUP_FAILED=1
    set_cleanup_note 'temporary-directory-remains'
    return 1
  fi
  if (( DB_FILE_RESERVED == 1 )) && [[ -n "$DB_PATH" && ( -e "$DB_PATH" || -L "$DB_PATH" ) ]]; then
    CLEANUP_FAILED=1
    set_cleanup_note 'database-file-remains'
    return 1
  fi
  WORK_DIR=''
  DB_PATH=''
  WORK_DIR_RESERVED=0
  DB_FILE_RESERVED=0
}

finalize() {
  local observed_rc=$?
  if (( CLEANUP_RUNNING == 1 )); then
    trap - EXIT
    exit 1
  fi
  CLEANUP_RUNNING=1
  # Cleanup is bounded and must not be interrupted by a repeated signal.  A
  # cancellation remains a failure even when every disposable resource is
  # removed successfully.
  trap '' INT TERM
  set +e
  if (( EXECUTION_COMPLETE == 0 )); then
    EXECUTION_RC=$observed_rc
  fi
  if ! case_results_are_exact; then
    mark_remaining_skipped || true
  fi
  cleanup_workdir || true
  FINAL_RC=1
  if (( EXECUTION_COMPLETE == 1 && EXECUTION_RC == 0 && CANCELLED == 0 &&
    CLEANUP_FAILED == 0 && REPORT_PREPARED == 1 )); then
    if case_results_are_exact && [[ "$(count_result pass)" == "${#CASE_IDS[@]}" ]] &&
      [[ "$(count_result fail)" == 0 && "$(count_result skipped)" == 0 ]]; then
      FINAL_RC=0
    fi
  fi
  write_report || FINAL_RC=1
  set +e
  if [[ -n "$REPORT_TMP_PATH" ]]; then
    bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" rm -f -- "$REPORT_TMP_PATH" || true
    REPORT_TMP_PATH=''
  fi
  trap - EXIT
  exit "$FINAL_RC"
}

on_signal() {
  CANCELLED=1
  CANCEL_SIGNAL="$1"
  if [[ "$1" == 'TERM' ]]; then
    CANCEL_RC=143
  else
    CANCEL_RC=130
  fi
  EXECUTION_RC="$CANCEL_RC"
  exit "$CANCEL_RC"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  trap finalize EXIT
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
fi

preflight() {
  command -v timeout >/dev/null 2>&1 || { set_note 'timeout-command-unavailable'; return 1; }
  timeout --help 2>&1 | grep -F -- '--kill-after' >/dev/null 2>&1 || {
    set_note 'bounded-timeout-unsupported'
    return 1
  }
  command -v python3 >/dev/null 2>&1 || { set_note 'python3-command-unavailable'; return 1; }
  python3 -c 'import sqlite3' >/dev/null 2>&1 || {
    set_note 'native-sqlite-observer-unavailable'
    return 1
  }
  if command -v sqlite3 >/dev/null 2>&1; then
    NATIVE_AVAILABLE=1
    NATIVE_OBSERVER='sqlite3'
  else
    # The Python image used by the external job may not ship the sqlite3 CLI,
    # but its stdlib sqlite3 extension is still an independent native SQLite
    # observer.  The StateKit binary remains the production executable under
    # test; this fallback never mocks its calls.
    NATIVE_AVAILABLE=1
    NATIVE_OBSERVER='python3-sqlite'
  fi
  if (( PREFLIGHT_ONLY == 0 )) && [[ ! -x "$STATEKIT_BIN" ]]; then
    set_note 'statekit-binary-unavailable'
    return 1
  fi
}

statekit_call() {
  local function="$1" output error rc
  shift
  CLIENT_SEQUENCE=$((CLIENT_SEQUENCE + 1))
  output="$WORK_DIR/statekit-${CLIENT_SEQUENCE}.stdout"
  error="$WORK_DIR/statekit-${CLIENT_SEQUENCE}.stderr"
  LAST_OUTPUT_PATH="$output"
  LAST_ERROR_PATH="$error"
  if bounded_timeout "$CLIENT_TIMEOUT_SECONDS" "$STATEKIT_BIN" exec "$function" "$@" -o json >"$output" 2>"$error"; then
    rc=0
  else
    rc=$?
  fi
  return "$rc"
}

json_value_equals() {
  local expected_json="$1" actual_path="$2" expected_path
  [[ -n "$WORK_DIR" && -f "$actual_path" ]] || return 1
  JSON_COMPARE_SEQUENCE=$((JSON_COMPARE_SEQUENCE + 1))
  expected_path="$WORK_DIR/json-expected-${JSON_COMPARE_SEQUENCE}.json"
  printf '%s' "$expected_json" >"$expected_path" || return 1
  python3 - "$expected_path" "$actual_path" >/dev/null 2>/dev/null <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as expected_file:
        expected = json.load(expected_file)
    with open(sys.argv[2], encoding="utf-8") as actual_file:
        actual = json.load(actual_file)
except (OSError, ValueError, TypeError):
    raise SystemExit(1)

def json_values_equal(left, right):
    # bool is an int subclass in Python, but JSON booleans are not numbers.
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, dict) or isinstance(right, dict):
        if not isinstance(left, dict) or not isinstance(right, dict):
            return False
        return left.keys() == right.keys() and all(
            json_values_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) or isinstance(right, list):
        if not isinstance(left, list) or not isinstance(right, list):
            return False
        return len(left) == len(right) and all(
            json_values_equal(expected_value, actual_value)
            for expected_value, actual_value in zip(left, right)
        )
    return left == right

raise SystemExit(0 if json_values_equal(expected, actual) else 1)
PY
}

expect_json() {
  local function="$1" expected="$2"
  shift 2
  statekit_call "$function" "$@" || return 1
  json_value_equals "$expected" "$LAST_OUTPUT_PATH" && [[ ! -s "$LAST_ERROR_PATH" ]]
}

expect_failed_without_marker() {
  local marker="$1" function="$2"
  shift 2
  if statekit_call "$function" "$@"; then
    return 1
  fi
  ! grep -F -q -- "$marker" "$LAST_OUTPUT_PATH" "$LAST_ERROR_PATH" 2>/dev/null
}

native_query() {
  local query="$1" output error query_path rc
  (( NATIVE_AVAILABLE == 1 )) || return 1
  CLIENT_SEQUENCE=$((CLIENT_SEQUENCE + 1))
  output="$WORK_DIR/native-${CLIENT_SEQUENCE}.stdout"
  error="$WORK_DIR/native-${CLIENT_SEQUENCE}.stderr"
  query_path="$WORK_DIR/native-${CLIENT_SEQUENCE}.sql"
  printf '%s' "$query" >"$query_path" || return 1
  case "$NATIVE_OBSERVER" in
    sqlite3)
      if bounded_timeout "$CLIENT_TIMEOUT_SECONDS" sqlite3 -batch -noheader "$DB_PATH" "$query" >"$output" 2>"$error"; then
        rc=0
      else
        rc=$?
      fi
      ;;
    python3-sqlite)
      if bounded_timeout "$CLIENT_TIMEOUT_SECONDS" python3 - "$DB_PATH" "$query_path" >"$output" 2>"$error" <<'PY'
import sqlite3
import sys

try:
    with sqlite3.connect(sys.argv[1]) as connection:
        with open(sys.argv[2], encoding="utf-8") as query_file:
            query = query_file.read()
        for row in connection.execute(query):
            print("|".join("" if value is None else str(value) for value in row))
except (OSError, sqlite3.Error, UnicodeError, TypeError, ValueError):
    raise SystemExit(1)
PY
      then
        rc=0
      else
        rc=$?
      fi
      ;;
    *)
      return 1
      ;;
  esac
  LAST_NATIVE=$(<"$output")
  LAST_NATIVE_PATH="$output"
  return "$rc"
}

bounded_timeout() {
  timeout --signal=TERM --kill-after="${TERMINATION_GRACE_SECONDS}s" "$@"
}

case_version() { expect_json sqlite3.version '"1.58.0"'; }
case_sqlite_version() { expect_json sqlite3.sqlite_version '"3.53.4"'; }
case_create() { expect_json sqlite3.modify true --db "$DB_PATH" --sql 'CREATE TABLE observations(id INTEGER, value TEXT)'; }
case_insert() { expect_json sqlite3.modify true --db "$DB_PATH" --sql "INSERT INTO observations(id, value) VALUES (1, 'live')"; }
case_fetch() { expect_json sqlite3.fetch '[[1,"live"]]' --db "$DB_PATH" --sql 'SELECT id, value FROM observations ORDER BY id'; }
case_tables() { expect_json sqlite3.tables '[["observations"]]' --db "$DB_PATH"; }
require_index_setup() {
  if (( INDEX_SETUP_OK != 1 )); then
    set_note 'index-setup-not-confirmed'
    return 1
  fi
}
case_indices() { require_index_setup && expect_json sqlite3.indices '[["observations_value"]]' --db "$DB_PATH"; }
case_indexes_alias() { require_index_setup && expect_json sqlite3.indexes '[["observations_value"]]' --db "$DB_PATH"; }
case_native_row() { native_query "SELECT id || '|' || value FROM observations ORDER BY id" && [[ "$LAST_NATIVE" == '1|live' ]]; }
case_native_schema() { native_query "SELECT name FROM sqlite_master WHERE type='table' AND name='observations'" && [[ "$LAST_NATIVE" == 'observations' ]]; }
case_native_index() { require_index_setup && native_query "SELECT name FROM sqlite_master WHERE type='index' AND name='observations_value'" && [[ "$LAST_NATIVE" == 'observations_value' ]]; }
case_invalid_path() {
  local marker='sqlite-live-path-marker'
  expect_failed_without_marker "$marker" sqlite3.tables --db "$WORK_DIR/$marker?mode=memory"
}
case_invalid_sql() {
  local marker='sqlite-live-sql-marker'
  expect_failed_without_marker "$marker" sqlite3.fetch --db "$DB_PATH" --sql "SELECT missing FROM absent WHERE value='$marker'"
}
case_missing_db() { expect_json sqlite3.fetch false --sql 'SELECT 1'; }

prepare_index() {
  INDEX_SETUP_OK=0
  if expect_json sqlite3.modify true --db "$DB_PATH" --sql \
    'CREATE INDEX observations_value ON observations(value)'; then
    INDEX_SETUP_OK=1
    return 0
  fi
  set_note 'index-setup-failed'
  return 1
}

main() {
  prepare_report || { set_note 'report-preparation-failed'; return 1; }
  if ! preflight; then
    return 1
  fi
  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/statekit-sqlite-live.XXXXXX") || {
    set_note 'temporary-directory-create-failed'
    return 1
  }
  WORK_DIR_RESERVED=1
  DB_PATH="$WORK_DIR/catalog.sqlite"
  DB_FILE_RESERVED=1

  run_case sqlite-version-live case_version
  run_case sqlite-sqlite-version-live case_sqlite_version
  run_case sqlite-modify-create-live case_create
  run_case sqlite-modify-insert-live case_insert
  run_case sqlite-fetch-live case_fetch
  run_case sqlite-tables-live case_tables
  if ! prepare_index; then
    return 1
  fi
  run_case sqlite-indices-live case_indices
  run_case sqlite-indexes-alias-live case_indexes_alias
  run_case sqlite-native-row-postcondition case_native_row
  run_case sqlite-native-schema-postcondition case_native_schema
  run_case sqlite-native-index-postcondition case_native_index
  run_case sqlite-invalid-path case_invalid_path
  run_case sqlite-invalid-sql case_invalid_sql
  run_case sqlite-missing-db case_missing_db
  EXECUTION_COMPLETE=1
  EXECUTION_RC=0
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

if (( PREFLIGHT_ONLY == 1 )); then
  trap - EXIT INT TERM
  if preflight; then
    exit 0
  fi
  exit 1
fi
main
