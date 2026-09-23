#!/usr/bin/env bash
# E5.2 live MySQL gate extending the E5.1 read-only/catalog/plugin surface
# with the already-ported R9.3j database lifecycle, R9.3l alter_db, R9.3m
# process/replication status readers, R9.3n slave_lag, R9.3o plugin
# add/remove lifecycle negatives and idempotence, R9.3p mysql.query, and R9.3q
# mysql.file_query.
# The gate deliberately runs
# the production statekit binary and the official image's native mysql client;
# it does not use the Go fake Runner. Every E5.1 case remains in the inventory.
#
# Runtime-generated credentials are created from stdin as Podman-managed
# ephemeral secrets.  MySQL consumes *_FILE paths and client processes copy a
# secret-backed defaults file onto a tmpfs for the lifetime of one process.
# No captured command output is printed or copied to the value-free report.
# The only supported execution environment is a local rootless Podman runtime.
set -euo pipefail

readonly MYSQL_IMAGE='mysql:8.4@sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a'
readonly MYSQL_DIGEST='sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a'
readonly SEED_DB='statekit_e51_seed'
readonly TEST_USER='statekit_e51_reader'
readonly DB_PORT='3306'
readonly INSTALLED_PLUGIN='caching_sha2_password'
readonly ABSENT_PLUGIN='statekit_e51_absent_plugin'
readonly READINESS_TIMEOUT_SECONDS=120
readonly POLL_INTERVAL_SECONDS=2
readonly CLIENT_TIMEOUT_SECONDS=60
readonly CLIENT_CREATE_TIMEOUT_SECONDS=30
readonly CLIENT_START_TIMEOUT_SECONDS=60
readonly NATIVE_CONNECT_TIMEOUT_SECONDS=3
readonly CLEANUP_TIMEOUT_SECONDS=20
readonly TERMINATION_GRACE_SECONDS=5
readonly PREFLIGHT_TIMEOUT_SECONDS=30
readonly MYSQL_SERVICE_USER='999:999'
readonly CLIENT_USER='65532:65532'
readonly ALTER_TABLE='statekit_r93l_seed'
readonly QUERY_TABLE='statekit_r93p_query'
readonly PYTHON_MOCK_TMPFS_DESTINATION='/tmp'
readonly PYTHON_MOCK_TMPFS_OPTIONS='rw,nosuid,nodev,noexec,size=64m,mode=1777,rprivate,tmpcopyup'
NATIVE_CLIENT_USER="$TEST_USER"
readonly SERVER_ROOT_SECRET_TARGET='/run/secrets/mysql-root-password'
readonly SERVER_USER_SECRET_TARGET='/run/secrets/mysql-user-password'
readonly CLIENT_SECRET_TARGET='/run/secrets/mysql-client.cnf'
readonly NATIVE_AUTH_FAILURE_MARKER='ERROR 1045 (28000): Access denied for user'
readonly NATIVE_CONNECTION_FAILURE_MARKER="ERROR 2003 (HY000): Can't connect to MySQL server"
readonly NATIVE_UNSUPPORTED_STATUS_ERROR_CODE='1064'
readonly NATIVE_UNSUPPORTED_STATUS_SQLSTATE='42000'
readonly NATIVE_UNSUPPORTED_STATUS_SIGNATURE='You have an error in your SQL syntax;'
readonly NATIVE_PLUGIN_INSTALL_FAILURE_MARKER="ERROR 1126 (HY000): Can't open shared library"
readonly NATIVE_PLUGIN_INSTALL_MISSING_SUFFIX='(errno: 2 No such file or directory)'
readonly MAX_COMMAND_INPUT_BYTES=$((1024 * 1024))
readonly STATEKIT_REQUEST_MAX_BYTES=$((MAX_COMMAND_INPUT_BYTES + 65536))
readonly QUERY_EXPECTED_NOTE='quote; value;'
readonly FILE_QUERY_DML_NOTE='file; dml;'
readonly FILE_QUERY_PATH='/tmp/statekit-file-query.sql'
readonly STATEKIT_FILE_QUERY_INVALID_PATH_DIAGNOSTIC='statekit: mysql: invalid file path'
readonly STATEKIT_FILE_QUERY_CONTENT_DIAGNOSTIC='statekit: mysql: invalid query'
readonly STATEKIT_QUERY_INPUT_LIMIT_DIAGNOSTIC='statekit: runtime: command input exceeds limit'
readonly STATEKIT_QUERY_TIMEOUT_DIAGNOSTIC='statekit: context deadline exceeded'
readonly NATIVE_QUERY_DIAGNOSTIC_SIGNATURE='You have an error in your SQL syntax;'
readonly NATIVE_QUERY_DIAGNOSTIC_STATEMENT='THIS IS NOT VALID SQL'
readonly STATEKIT_PROOF_MARKER='statekit: production-binary-completed'
readonly STATEKIT_INVALID_IDENTIFIER_CATEGORY='mysql: invalid argument'
readonly STATEKIT_INVALID_IDENTIFIER_DIAGNOSTIC='statekit: mysql: invalid argument: unsupported identifier in name'
readonly STATEKIT_INVALID_SONAME_DIAGNOSTIC='statekit: mysql: invalid argument: unsupported identifier in soname'
readonly STATEKIT_INVALID_OPTION_DIAGNOSTIC='statekit: mysql: invalid argument: unsupported value in character_set'
readonly CASE_IDS=(
  'mysql-readiness-authenticated-select-1'
  'mysql-version-live'
  'mysql-db-list-seeded'
  'mysql-db-exists-seeded'
  'mysql-db-exists-absent'
  'mysql-plugins-list-installed'
  'mysql-plugin-status-installed'
  'mysql-plugin-status-absent'
  'mysql-auth-negative-native-client'
  'mysql-auth-negative-statekit'
  'mysql-connection-negative-native-client'
  'mysql-connection-negative-statekit'
  'mysql-db-native-postcondition'
  'mysql-plugin-native-postcondition'
  'mysql-db-lifecycle-native-absent-before-create'
  'mysql-db-create-success'
  'mysql-db-create-repeat-false'
  'mysql-db-native-created-postcondition'
  'mysql-db-remove-success'
  'mysql-db-native-removed-postcondition'
  'mysql-db-negative-invalid-identifier'
  'mysql-db-negative-auth'
  'mysql-db-negative-connection'
  'mysql-alter-db-native-absent-before-create'
  'mysql-alter-db-create-and-seed'
  'mysql-alter-db-native-defaults-before'
  'mysql-alter-db-statekit-explicit'
  'mysql-alter-db-native-explicit-readback'
  'mysql-alter-db-statekit-explicit-readback'
  'mysql-alter-db-statekit-default-preservation'
  'mysql-alter-db-native-default-preserved-readback'
  'mysql-alter-db-statekit-default-preserved-readback'
  'mysql-alter-db-negative-auth'
  'mysql-alter-db-negative-connection'
  'mysql-alter-db-negative-invalid-identifier'
  'mysql-alter-db-negative-invalid-option'
  'mysql-processlist-statekit'
  'mysql-processlist-native-observation'
  'mysql-processlist-negative-auth'
  'mysql-processlist-negative-connection'
  'mysql-get-master-status-statekit'
  'mysql-get-master-status-native-observation'
  'mysql-get-master-status-negative-auth'
  'mysql-get-master-status-negative-connection'
  'mysql-get-slave-status-statekit'
  'mysql-get-slave-status-native-observation'
  'mysql-get-slave-status-negative-auth'
  'mysql-get-slave-status-negative-connection'
  'mysql-slave-lag-statekit'
  'mysql-slave-lag-native-observation'
  'mysql-slave-lag-negative-auth'
  'mysql-slave-lag-negative-connection'
  'mysql-plugin-add-installed-idempotent'
  'mysql-plugin-add-installed-native-status'
  'mysql-plugin-status-case-sensitive'
  'mysql-plugin-remove-absent-idempotent'
  'mysql-plugin-remove-absent-native-status'
  'mysql-plugin-add-default-soname-failure'
  'mysql-plugin-add-default-soname-native-failure'
  'mysql-plugin-add-custom-soname-failure'
  'mysql-plugin-add-custom-soname-native-failure'
  'mysql-plugin-add-invalid-name'
  'mysql-plugin-add-invalid-soname'
  'mysql-plugin-add-negative-auth'
  'mysql-plugin-remove-negative-connection'
  'mysql-query-select-scalar-statekit'
  'mysql-query-select-scalar-native-observation'
  'mysql-query-select-table-statekit'
  'mysql-query-select-table-native-observation'
  'mysql-query-database-native-absent-before-create'
  'mysql-query-create-database'
  'mysql-query-create-table'
  'mysql-query-insert-dml'
  'mysql-query-dml-native-postcondition'
  'mysql-file-query-select-statekit'
  'mysql-file-query-select-native-observation'
  'mysql-file-query-dml-statekit'
  'mysql-file-query-dml-native-postcondition'
  'mysql-file-query-multiline-quoted-statekit'
  'mysql-file-query-multiline-quoted-native-observation'
  'mysql-file-query-negative-invalid-path'
  'mysql-file-query-negative-oversize'
  'mysql-file-query-negative-invalid-content'
  'mysql-file-query-negative-auth'
  'mysql-file-query-negative-connection'
  'mysql-query-multiline-quoted-statekit'
  'mysql-query-multiline-quoted-native-observation'
  'mysql-query-drop-database'
  'mysql-query-database-native-removed-postcondition'
  'mysql-query-negative-invalid-database'
  'mysql-query-negative-auth'
  'mysql-query-negative-connection'
  'mysql-query-negative-timeout'
  'mysql-query-negative-oversize'
  'mysql-query-negative-diagnostic-statekit'
  'mysql-query-negative-diagnostic-native-classification'
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
  printf '%s\n' 'usage: tests/live/mysql/run.sh [--list-cases|--preflight-only]' >&2
  exit 2
fi

REPORT_DIR="${REPORT_DIR:-artifacts/mysql-live}"
REPORT_PATH="$REPORT_DIR/report.txt"
STATEKIT_BIN="${STATEKIT_BIN:-dist/statekit}"
RUNTIME="${CONTAINER_RUNTIME:-}"
WORK_DIR=''
RESOURCE_NONCE=''
NETWORK=''
DB_CONTAINER=''
DB_CONTAINER_ID=''
DB_HOST=''
DB_RESERVED=0
DB_OWNED=0
LIFECYCLE_DB=''
LIFECYCLE_DB_RESERVED=0
LIFECYCLE_DB_OWNED=0
QUERY_DB=''
QUERY_DB_RESERVED=0
QUERY_DB_OWNED=0
ALTER_DB=''
ALTER_DB_RESERVED=0
ALTER_DB_OWNED=0
PLUGIN_DEFAULT_FAILURE=''
PLUGIN_CUSTOM_FAILURE=''
NETWORK_RESERVED=0
NETWORK_OWNED=0
CLIENT_IMAGE_RESERVED=0
CLIENT_IMAGE_OWNED=0
SECRET_RESOURCE_RESERVED=0
REPORT_WRITTEN=0
REPORT_PREPARED=0
EXECUTION_COMPLETE=0
CLEANUP_FAILED=0
CLEANUP_RUNNING=0
CANCELLED=0
CANCEL_SIGNAL='none'
CANCEL_RC=125
EXECUTION_RC=125
FINAL_RC=125
PASSED=0
FAILED=0
SKIPPED=0
SETUP_NOTE='none'
CLEANUP_NOTE='none'
CLIENT_SEQUENCE=0
LAST_CLIENT_CLASS='not-run'
LAST_CLIENT_EXIT_RC=125
LAST_STATEKIT_BINARY_LAUNCHED=0
CLIENT_EXPECT_STATEKIT_PROOF=0
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_PASSWORD=''
LIVE_PASSWORD=''
BAD_PASSWORD=''
CLIENT_IMAGE=''
SERVER_ROOT_SECRET=''
SERVER_USER_SECRET=''
CLIENT_SECRET=''
BAD_CLIENT_SECRET=''
ROOT_CLIENT_SECRET=''
declare -a CASE_RESULTS=()
declare -a OWNED_CLIENT_NAMES=()
declare -a OWNED_CLIENT_IDS=()
declare -a OWNED_SECRET_NAMES=()
CASE_RESULT_INTEGRITY_FAILED=0

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
    if [[ "${entry%%=*}" == "$case_id" ]]; then
      return 0
    fi
  done
  return 1
}

record_case() {
  local case_id="$1"
  local result="$2"
  if ! case_id_is_known "$case_id"; then
    CASE_RESULT_INTEGRITY_FAILED=1
    set_note 'unknown-case-id-rejected'
    return 1
  fi
  if case_id_is_recorded "$case_id"; then
    CASE_RESULT_INTEGRITY_FAILED=1
    set_note 'duplicate-case-id-rejected'
    return 1
  fi
  case "$result" in
    pass|fail|skipped) ;;
    *)
      CASE_RESULT_INTEGRITY_FAILED=1
      set_note 'invalid-case-result-rejected'
      return 1
      ;;
  esac
  CASE_RESULTS+=("$case_id=$result")
  case "$result" in
    pass) PASSED=$((PASSED + 1)) ;;
    fail) FAILED=$((FAILED + 1)) ;;
    skipped) SKIPPED=$((SKIPPED + 1)) ;;
  esac
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

mark_remaining_failed() {
  local case_id
  for case_id in "${CASE_IDS[@]}"; do
    if ! case_id_is_recorded "$case_id"; then
      # A setup/start failure is evidence of a failed gate, not a reason to
      # manufacture skips.  Keep the ordered inventory complete and make the
      # failure visible in the value-free report.
      record_case "$case_id" fail || return 1
    fi
  done
}

case_results_are_exact() {
  local index entry case_id result
  if (( ${#CASE_RESULTS[@]} != ${#CASE_IDS[@]} )); then
    return 1
  fi
  for index in "${!CASE_IDS[@]}"; do
    entry="${CASE_RESULTS[index]:-}"
    case_id="${entry%%=*}"
    result="${entry#*=}"
    if [[ "$case_id" != "${CASE_IDS[index]}" ]]; then
      return 1
    fi
    case "$result" in
      pass|fail|skipped) ;;
      *) return 1 ;;
    esac
  done
  return 0
}

write_report() {
  if (( REPORT_WRITTEN == 1 )); then
    return 0
  fi
  if (( REPORT_PREPARED != 1 )); then
    return 1
  fi
  local report_tmp
  local exact_results=0
  if case_results_are_exact; then
    exact_results=1
  fi
  if ! report_tmp=$(mktemp "$REPORT_DIR/.report.tmp.XXXXXX"); then
    return 1
  fi
  if ! {
    printf '%s\n' 'schema: e5.2-mysql-live-v1'
    printf 'image: %s\n' "$MYSQL_IMAGE"
    printf 'cases_total: %d\n' "${#CASE_IDS[@]}"
    printf 'cases_passed: %d\n' "$PASSED"
    printf 'cases_failed: %d\n' "$FAILED"
    printf 'cases_skipped: %d\n' "$SKIPPED"
    if (( EXECUTION_COMPLETE == 1 && EXECUTION_RC == 0 && FINAL_RC == 0 && CANCELLED == 0 && exact_results == 1 && CASE_RESULT_INTEGRITY_FAILED == 0 && PASSED == ${#CASE_IDS[@]} && FAILED == 0 && SKIPPED == 0 && CLEANUP_FAILED == 0 )); then
      printf '%s\n' 'status: pass'
    else
      printf '%s\n' 'status: fail'
    fi
    if (( EXECUTION_COMPLETE == 1 )); then
      printf '%s\n' 'execution: complete'
    else
      printf '%s\n' 'execution: incomplete'
    fi
    printf 'execution_rc: %d\n' "$EXECUTION_RC"
    printf 'final_rc: %d\n' "$FINAL_RC"
    printf 'cancelled: %s\n' "$([[ "$CANCELLED" == 1 ]] && printf true || printf false)"
    printf 'cancellation_signal: %s\n' "$CANCEL_SIGNAL"
    printf 'setup_note: %s\n' "$SETUP_NOTE"
    if (( CLEANUP_FAILED == 1 )); then
      printf '%s\n' 'cleanup: fail'
    else
      printf '%s\n' 'cleanup: pass'
    fi
    printf 'cleanup_note: %s\n' "$CLEANUP_NOTE"
    printf '%s\n' 'scope: E5.1 mysql.version/db_list/db_exists/plugins_list/plugin_status plus R9.3j lifecycle, R9.3l mysql.alter_db create/seed/alter/read-back, R9.3m process/replication status, R9.3n mysql.slave_lag, R9.3o plugin_add/plugin_remove lifecycle cases, and R9.3p mysql.query SELECT/DDL/DML/stdin-boundary cases'
    printf '%s\n' 'independent_checks: native mysql client database/plugin/charset/collation/seed postconditions, exact plugin status/case observations, missing-shared-object INSTALL failure classifications, available SHOW FULL PROCESSLIST correlation, MySQL 8.4 unsupported SHOW MASTER STATUS/SHOW SLAVE STATUS classifications including slave_lag, and independent scalar/table/query-database/multiline/diagnostic observations; no positive plugin installation or replication retrieval is claimed'
    printf '%s\n' 'status_classification: StateKit [] compatibility output is accepted only when the matching native legacy SHOW statement is classified unsupported-sql, mysql.slave_lag -3 is accepted only with the matching native unsupported-sql classification, and missing-plugin INSTALL exits are accepted only with the exact ER_CANT_OPEN_LIBRARY errno=2 diagnostic bound to the requested basename; path, permission, loader/interface, mixed, unrelated, auth, connection, runtime/setup/cleanup, or StateKit/native mismatch fails'
    printf '%s\n' 'external_ci: pending'
    printf '%s\n' 'limitations: no full R9 live coverage, no broker/PostgreSQL/SQLite coverage, no live Salt differential parity; mysql.query is an explicitly privileged fixed-case live probe, never arbitrary PR SQL, and its generated credentials are disposable rather than repository secrets; DB-API exception/rowcount and bare-NULL parity remain CLI ceilings; MySQL 8.4 positive plugin installation is not claimed because no test plugin .so is bundled, and built-in plugins are never uninstalled; GitHub live execution is not claimed here; SIGKILL or runner loss can prevent cleanup/reporting'
    printf '%s\n' 'credentials: runtime-generated disposable values are delivered through ephemeral secret mounts only; not included in this report'
    local result
    for result in "${CASE_RESULTS[@]}"; do
      printf 'case: %s\n' "$result"
    done
  } >"$report_tmp"; then
    rm -f -- "$report_tmp"
    return 1
  fi
  if ! mv -f -- "$report_tmp" "$REPORT_PATH"; then
    rm -f -- "$report_tmp"
    return 1
  fi
  if [[ ! -s "$REPORT_PATH" ]]; then
    return 1
  fi
  REPORT_WRITTEN=1
}

prepare_report() {
  if ! mkdir -p -- "$REPORT_DIR"; then
    set_note 'report-directory-create-failed'
    return 1
  fi
  if [[ -e "$REPORT_PATH" || -L "$REPORT_PATH" ]]; then
    if ! rm -f -- "$REPORT_PATH" >/dev/null 2>&1 || [[ -e "$REPORT_PATH" || -L "$REPORT_PATH" ]]; then
      set_note 'stale-report-rejected'
      return 1
    fi
  fi
  REPORT_PREPARED=1
}

mark_cleanup_failure() {
  CLEANUP_FAILED=1
  if [[ "$CLEANUP_NOTE" == 'none' ]]; then
    CLEANUP_NOTE='resource-cleanup-failed'
  fi
}

bounded_timeout() {
  timeout --signal=TERM --kill-after="${TERMINATION_GRACE_SECONDS}s" "$@"
}

container_exists_state() {
  local ref="$1" rc=0
  if bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" container exists "$ref" >/dev/null 2>/dev/null; then
    return 0
  else
    rc=$?
  fi
  if (( rc == 1 )); then
    return 1
  fi
  return 2
}

network_exists_state() {
  local ref="$1" rc=0
  if bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" network exists "$ref" >/dev/null 2>/dev/null; then
    return 0
  else
    rc=$?
  fi
  if (( rc == 1 )); then
    return 1
  fi
  return 2
}

image_exists_state() {
  local ref="$1" rc=0
  if bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" image exists "$ref" >/dev/null 2>/dev/null; then
    return 0
  else
    rc=$?
  fi
  if (( rc == 1 )); then
    return 1
  fi
  return 2
}

reserve_container_name() {
  local name="$1" state=0
  if container_exists_state "$name"; then
    state=0
  else
    state=$?
  fi
  case "$state" in
    1)
      return 0
      ;;
    0)
      set_note 'container-name-collision'
      return 1
      ;;
    *)
      set_note 'container-existence-preflight-failed'
      return 1
      ;;
  esac
}

cleanup_container() {
  local name="$1" id="$2" candidate ref='' state=0 stop_rc=0 kill_rc=0 rm_rc=0
  local -a candidates=()
  [[ -n "$id" ]] && candidates+=("$id")
  [[ -n "$name" ]] && candidates+=("$name")
  [[ -n "$RUNTIME" && ${#candidates[@]} -gt 0 ]] || return 0

  for candidate in "${candidates[@]}"; do
    if container_exists_state "$candidate"; then
      ref="$candidate"
      break
    else
      state=$?
    fi
    if (( state != 1 )); then
      mark_cleanup_failure
      return 1
    fi
  done
  [[ -n "$ref" ]] || return 0

  bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" stop --time 5 "$ref" >/dev/null 2>/dev/null || stop_rc=$?
  if (( stop_rc != 0 )); then
    bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" kill "$ref" >/dev/null 2>/dev/null || kill_rc=$?
  fi
  bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" rm --force --volumes "$ref" >/dev/null 2>/dev/null || rm_rc=$?
  if (( rm_rc != 0 )); then
    mark_cleanup_failure
    return 1
  fi

  for candidate in "${candidates[@]}"; do
    if container_exists_state "$candidate"; then
      mark_cleanup_failure
      return 1
    else
      state=$?
    fi
    if (( state != 1 )); then
      mark_cleanup_failure
      return 1
    fi
  done
  # A successful final removal is authoritative; stop/kill can race with an
  # already-exited process without leaving a residual container.  A failed
  # remove or an unverifiable final state is never hidden by a successful kill.
  : "$stop_rc" "$kill_rc"
  return 0
}

cleanup_network() {
  local state=0 rm_rc=0
  [[ -n "$RUNTIME" && -n "$NETWORK" && "$NETWORK_RESERVED" == 1 && "$NETWORK_OWNED" == 1 ]] || return 0
  if network_exists_state "$NETWORK"; then
    state=0
  else
    state=$?
  fi
  if (( state == 1 )); then
    return 0
  fi
  if (( state != 0 )); then
    mark_cleanup_failure
    return 1
  fi
  bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" network rm "$NETWORK" >/dev/null 2>/dev/null || rm_rc=$?
  if (( rm_rc != 0 )); then
    mark_cleanup_failure
    return 1
  fi
  if network_exists_state "$NETWORK"; then
    mark_cleanup_failure
    return 1
  else
    state=$?
  fi
  if (( state != 1 )); then
    mark_cleanup_failure
    return 1
  fi
  return 0
}

cleanup_image() {
  local state=0 rm_rc=0
  [[ -n "$RUNTIME" && -n "$CLIENT_IMAGE" && "$CLIENT_IMAGE_RESERVED" == 1 && "$CLIENT_IMAGE_OWNED" == 1 ]] || return 0
  if image_exists_state "$CLIENT_IMAGE"; then
    state=0
  else
    state=$?
  fi
  if (( state == 1 )); then
    return 0
  fi
  if (( state != 0 )); then
    mark_cleanup_failure
    return 1
  fi
  bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" rmi --force "$CLIENT_IMAGE" >/dev/null 2>/dev/null || rm_rc=$?
  if (( rm_rc != 0 )); then
    mark_cleanup_failure
    return 1
  fi
  if image_exists_state "$CLIENT_IMAGE"; then
    mark_cleanup_failure
    return 1
  else
    state=$?
  fi
  if (( state != 1 )); then
    mark_cleanup_failure
    return 1
  fi
  return 0
}

secret_exists_state() {
  local ref="$1" rc=0
  if bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" secret exists "$ref" >/dev/null 2>/dev/null; then
    return 0
  else
    rc=$?
  fi
  if (( rc == 1 )); then
    return 1
  fi
  return 2
}

cleanup_secret() {
  local name="$1" state=0 rm_rc=0
  [[ -n "$RUNTIME" && -n "$name" ]] || return 0
  if secret_exists_state "$name"; then
    state=0
  else
    state=$?
  fi
  if (( state == 1 )); then
    return 0
  fi
  if (( state != 0 )); then
    mark_cleanup_failure
    return 1
  fi
  bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" secret rm "$name" >/dev/null 2>/dev/null || rm_rc=$?
  if (( rm_rc != 0 )); then
    mark_cleanup_failure
    return 1
  fi
  if secret_exists_state "$name"; then
    mark_cleanup_failure
    return 1
  else
    state=$?
  fi
  if (( state != 1 )); then
    mark_cleanup_failure
    return 1
  fi
  return 0
}

cleanup_work_dir() {
  if [[ -n "$WORK_DIR" && ( -e "$WORK_DIR" || -L "$WORK_DIR" ) ]]; then
    if ! bounded_timeout "$CLEANUP_TIMEOUT_SECONDS" rm -rf -- "$WORK_DIR"; then
      mark_cleanup_failure
      return 1
    fi
    [[ ! -e "$WORK_DIR" && ! -L "$WORK_DIR" ]] || mark_cleanup_failure
  fi
}

cleanup() {
  local rc=$? index=0 final_rc=0
  if (( CLEANUP_RUNNING == 1 )); then
    return 0
  fi
  CLEANUP_RUNNING=1
  # Ignore repeated cancellation while teardown is in progress.  Removing the
  # traps would let a second TERM interrupt the bounded cleanup sequence.
  trap '' INT TERM
  set +e
  cleanup_lifecycle_database || true
  cleanup_query_database || true
  cleanup_alter_database || true
  while (( index < ${#OWNED_CLIENT_NAMES[@]} )); do
    cleanup_container "${OWNED_CLIENT_NAMES[index]}" "${OWNED_CLIENT_IDS[index]}" || true
    index=$((index + 1))
  done
  if (( DB_RESERVED == 1 && DB_OWNED == 1 )); then
    cleanup_container "$DB_CONTAINER" "$DB_CONTAINER_ID" || true
  fi
  cleanup_network || true
  index=0
  while (( index < ${#OWNED_SECRET_NAMES[@]} )); do
    cleanup_secret "${OWNED_SECRET_NAMES[index]}" || true
    index=$((index + 1))
  done
  cleanup_image || true
  cleanup_work_dir
  unset ROOT_PASSWORD LIVE_PASSWORD BAD_PASSWORD
  EXECUTION_RC="$rc"
  final_rc="$rc"
  if (( CLEANUP_FAILED == 1 )); then
    final_rc=1
  fi
  if (( CANCELLED == 1 && final_rc == 0 )); then
    final_rc="${CANCEL_RC:-143}"
  fi
  FINAL_RC="$final_rc"
  if ! write_report >/dev/null 2>/dev/null; then
    final_rc=1
    FINAL_RC=1
    printf '%s\n' 'e5.2: report write failed' >&2
  fi
  trap - EXIT
  exit "$final_rc"
}

if [[ "${BASH_SOURCE[0]}" == "$0" && "$PREFLIGHT_ONLY" == 0 ]]; then
  trap cleanup EXIT
  trap 'CANCELLED=1; CANCEL_SIGNAL=INT; CANCEL_RC=130; exit 130' INT
  trap 'CANCELLED=1; CANCEL_SIGNAL=TERM; CANCEL_RC=143; exit 143' TERM
fi

select_runtime() {
  if [[ -z "$RUNTIME" ]]; then
    if ! command -v podman >/dev/null 2>&1; then
      set_note 'container-runtime-unavailable'
      return 1
    fi
    RUNTIME='podman'
  fi
  case "$(basename "$RUNTIME")" in
    podman) ;;
    *)
      set_note 'unsupported-container-runtime'
      return 1
      ;;
  esac
  if ! command -v "$RUNTIME" >/dev/null 2>&1 || [[ "$(id -u)" == '0' ]]; then
    set_note 'runtime-is-not-non-root'
    return 1
  fi
  RUNTIME="$(command -v "$RUNTIME")"
}

runtime_preflight() {
  local rootless service_remote version help required flag
  if [[ "$(basename "$RUNTIME")" != 'podman' || "$(id -u)" == '0' ]]; then
    set_note 'runtime-preflight-identity-failed'
    return 1
  fi
  if ! timeout --help 2>&1 | grep -F -- '--kill-after' >/dev/null 2>&1; then
    set_note 'runtime-preflight-bounded-timeout-missing'
    return 1
  fi
  for flag in CONTAINER_HOST DOCKER_HOST PODMAN_HOST CONTAINER_CONNECTION \
    DOCKER_CONFIG DOCKER_AUTH_CONFIG REGISTRY_AUTH_FILE CONTAINERS_AUTH_FILE SSH_AUTH_SOCK; do
    if [[ -n "${!flag:-}" ]]; then
      set_note 'runtime-preflight-remote-or-host-credential-environment'
      return 1
    fi
  done
  rootless=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)
  service_remote=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" info --format '{{.Host.ServiceIsRemote}}' 2>/dev/null || true)
  if [[ "$rootless" != 'true' ]]; then
    set_note 'runtime-preflight-not-rootless'
    return 1
  fi
  if [[ "$service_remote" != 'false' ]]; then
    set_note 'runtime-preflight-remote-service'
    return 1
  fi
  version=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" version --format '{{.Client.Version}}' 2>/dev/null || true)
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][[:alnum:].-]+)?$ ]]; then
    set_note 'runtime-preflight-version-unverifiable'
    return 1
  fi
  help=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" create --help 2>/dev/null || true)
  for required in '--secret' '--read-only' '--tmpfs' '--user' '--cap-drop' \
    '--security-opt' '--network' '--pids-limit' '--memory' '--cpus'; do
    if [[ "$help" != *"$required"* ]]; then
      set_note 'runtime-preflight-isolation-capability-missing'
      return 1
    fi
  done
  help=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" build --help 2>/dev/null || true)
  if [[ "$help" != *'--network'* || "$help" != *'--pull'* || "$help" != *'--isolation'* ]]; then
    set_note 'runtime-preflight-build-isolation-capability-missing'
    return 1
  fi
  help=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" network create --help 2>/dev/null || true)
  if [[ "$help" != *'--internal'* ]]; then
    set_note 'runtime-preflight-network-isolation-capability-missing'
    return 1
  fi
  help=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" secret create --help 2>/dev/null || true)
  if [[ "$help" != *'stdin'* && "$help" != *'FILE'* && "$help" != *'PATH'* ]]; then
    set_note 'runtime-preflight-secret-stdin-capability-missing'
    return 1
  fi
  return 0
}

policy_field() {
  local container_id="$1" format="$2"
  timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" container inspect \
    --format "$format" "$container_id" 2>/dev/null
}

policy_count_is_zero() {
  local container_id="$1" format="$2" value
  value=$(policy_field "$container_id" "$format") || return 1
  [[ "$value" == '0' ]]
}

canonical_csv_set() {
  local value="$1" option
  local -a options=()
  [[ -n "$value" ]] || return 1
  IFS=',' read -r -a options <<< "$value"
  ((${#options[@]} > 0)) || return 1
  for option in "${options[@]}"; do
    [[ -n "$option" ]] || return 1
  done
  printf '%s\n' "${options[@]}" | LC_ALL=C sort | paste -sd, -
}

verify_exact_tmpfs_spec() {
  local specs="$1" expected_destination="$2" expected_options="$3"
  local destination options actual_options canonical_expected spec_count=0
  [[ -n "$specs" ]] || return 1
  while IFS='|' read -r destination options; do
    [[ -n "$destination" && -n "$options" ]] || return 1
    spec_count=$((spec_count + 1))
    ((spec_count == 1)) || return 1
    [[ "$destination" == "$expected_destination" ]] || return 1
    actual_options=$(canonical_csv_set "$options") || return 1
    canonical_expected=$(canonical_csv_set "$expected_options") || return 1
    [[ "$actual_options" == "$canonical_expected" ]] || return 1
  done <<< "$specs"
  [[ "$spec_count" == '1' ]]
}

verify_python_mock_container_policy() {
  local container_id="$1"
  local user privileged readonly nnp effective bounding network ipc pid uts
  local tmpfs mounts mount_layout binds volumes volumes_from devices ports
  local extra_hosts group_add links secret_state env_keys expected_env_keys
  user=$(policy_field "$container_id" '{{.Config.User}}') || return 1
  privileged=$(policy_field "$container_id" '{{.HostConfig.Privileged}}') || return 1
  readonly=$(policy_field "$container_id" '{{.HostConfig.ReadonlyRootfs}}') || return 1
  nnp=$(policy_field "$container_id" '{{range .HostConfig.SecurityOpt}}{{if or (eq . "no-new-privileges") (eq . "no-new-privileges=true")}}no-new-privileges=true{{end}}{{end}}') || return 1
  effective=$(policy_field "$container_id" '{{range .EffectiveCaps}}{{println .}}{{end}}') || return 1
  bounding=$(policy_field "$container_id" '{{range .BoundingCaps}}{{println .}}{{end}}') || return 1
  network=$(policy_field "$container_id" '{{.HostConfig.NetworkMode}}') || return 1
  ipc=$(policy_field "$container_id" '{{.HostConfig.IpcMode}}') || return 1
  pid=$(policy_field "$container_id" '{{.HostConfig.PidMode}}') || return 1
  uts=$(policy_field "$container_id" '{{.HostConfig.UTSMode}}') || return 1
  tmpfs=$(policy_field "$container_id" '{{range $path, $opts := .HostConfig.Tmpfs}}{{printf "%s|%s\n" $path $opts}}{{end}}') || return 1
  mounts=$(policy_field "$container_id" '{{len .Mounts}}') || return 1
  mount_layout=$(policy_field "$container_id" '{{range .Mounts}}{{printf "%s|%s|%s|%s|%t|%v\n" .Type .Destination .Mode .Propagation .RW .Options}}{{end}}') || return 1
  binds=$(policy_field "$container_id" '{{len .HostConfig.Binds}}') || return 1
  volumes=$(policy_field "$container_id" '{{len .Config.Volumes}}') || return 1
  volumes_from=$(policy_field "$container_id" '{{len .HostConfig.VolumesFrom}}') || return 1
  devices=$(policy_field "$container_id" '{{len .HostConfig.Devices}}') || return 1
  ports=$(policy_field "$container_id" '{{len .HostConfig.PortBindings}}') || return 1
  extra_hosts=$(policy_field "$container_id" '{{len .HostConfig.ExtraHosts}}') || return 1
  group_add=$(policy_field "$container_id" '{{len .HostConfig.GroupAdd}}') || return 1
  links=$(policy_field "$container_id" '{{len .HostConfig.Links}}') || return 1
  secret_state=$(policy_field "$container_id" '{{if .Config.Secrets}}present{{else}}absent{{end}}') || return 1
  # Only key names are emitted from Config.Env; values never enter a shell
  # variable, log, report, or test fixture.
  env_keys=$(policy_field "$container_id" '{{range .Config.Env}}{{println (index (split . "=") 0)}}{{end}}' |
    awk 'NF { print }' | LC_ALL=C sort) || return 1
  expected_env_keys=$(printf '%s\n' container PATH PYTHONDONTWRITEBYTECODE PYTHON_SHA256 PYTHON_VERSION |
    LC_ALL=C sort)
  [[ "$user" == '65532:65532' && "$privileged" == 'false' &&
    "$readonly" == 'true' && "$nnp" == 'no-new-privileges=true' &&
    -z "$effective" && -z "$bounding" && "$network" == 'none' &&
    "$ipc" == 'private' && "$pid" == 'private' && "$uts" == 'private' &&
    "$mounts" == '0' && -z "$mount_layout" && "$binds" == '0' &&
    "$volumes" == '0' && "$volumes_from" == '0' && "$devices" == '0' &&
    "$ports" == '0' && "$extra_hosts" == '0' && "$group_add" == '0' &&
    "$links" == '0' && "$secret_state" == 'absent' &&
    "$env_keys" == "$expected_env_keys" ]] || return 1
  verify_exact_tmpfs_spec "$tmpfs" "$PYTHON_MOCK_TMPFS_DESTINATION" \
    "$PYTHON_MOCK_TMPFS_OPTIONS"
}

verify_non_secret_env_keys() {
  local container_id="$1" kind="$2" keys expected
  # split is evaluated by Podman's formatter, so the direct output contains
  # key names only; no Config.Env value enters a shell variable or file.
  keys=$(policy_field "$container_id" '{{range .Config.Env}}{{println (index (split . "=") 0)}}{{end}}' |
    awk 'NF { print }' | LC_ALL=C sort) || return 1
  case "$kind" in
    server)
      expected=$(printf '%s\n' GOSU_VERSION MYSQL_DATABASE MYSQL_MAJOR \
        MYSQL_PASSWORD_FILE MYSQL_ROOT_PASSWORD_FILE MYSQL_SHELL_VERSION MYSQL_USER MYSQL_VERSION PATH |
        LC_ALL=C sort)
      expected=$(printf '%s\n%s' "$expected" container | LC_ALL=C sort)
      ;;
    client)
      expected=$(printf '%s\n' GOSU_VERSION MYSQL_MAJOR MYSQL_SHELL_VERSION MYSQL_VERSION PATH |
        LC_ALL=C sort)
      expected=$(printf '%s\n%s' "$expected" container | LC_ALL=C sort)
      ;;
    *) return 1 ;;
  esac
  [[ "$keys" == "$expected" ]]
}

verify_tmpfs_policy() {
  local container_id="$1" kind="$2" specs destinations destination options size
  local expected_destinations
  specs=$(policy_field "$container_id" '{{range $path, $opts := .HostConfig.Tmpfs}}{{printf "%s|%s\n" $path $opts}}{{end}}') || return 1
  case "$kind" in
    server) expected_destinations=$'/run\n/tmp\n/var/lib/mysql' ;;
    client) expected_destinations=$'/tmp\n/var/lib/mysql' ;;
    *) return 1 ;;
  esac
  destinations=$(printf '%s' "$specs" | awk -F'|' 'NF { print $1 }' | LC_ALL=C sort)
  if [[ "$destinations" != "$expected_destinations" ]]; then
    return 1
  fi
  while IFS='|' read -r destination options; do
    [[ -n "$destination" && -n "$options" ]] || return 1
    case "$destination" in
      /var/lib/mysql) [[ "$kind" == server ]] && size='size=512m' || size='size=16m' ;;
      /run) size='size=16m' ;;
      /tmp) [[ "$kind" == server ]] && size='size=64m' || size='size=16m' ;;
      *) return 1 ;;
    esac
    [[ ",$options," == *',rw,'* && ",$options," == *',nosuid,'* &&
      ",$options," == *',nodev,'* && ",$options," == *',noexec,'* &&
      ",$options," == *",$size,"* && ",$options," == *',mode=1777,'* ]] || return 1
    local option
    IFS=',' read -r -a option_list <<< "$options"
    for option in "${option_list[@]}"; do
      case "$option" in
        rw|nosuid|nodev|noexec|rprivate|tmpcopyup|"$size"|mode=1777) ;;
        *) return 1 ;;
      esac
    done
  done <<< "$specs"
}

verify_secret_policy() {
  local container_id="$1" kind="$2" secret_lines expected
  secret_lines=$(policy_field "$container_id" '{{range .Config.Secrets}}{{printf "%s|%d|%d|%o\n" .Name .UID .GID .Mode}}{{end}}') || return 1
  case "$kind" in
    server)
      expected=$(printf '%s\n%s' \
        "$SERVER_ROOT_SECRET|999|999|400" "$SERVER_USER_SECRET|999|999|400" | LC_ALL=C sort)
      ;;
    client)
      expected=$(printf '%s\n%s' \
        "$CLIENT_SECRET|65532|65532|400" "$BAD_CLIENT_SECRET|65532|65532|400" | LC_ALL=C sort)
      ;;
    *) return 1 ;;
  esac
  secret_lines=$(printf '%s' "$secret_lines" | LC_ALL=C sort)
  if [[ "$kind" == client ]]; then
    [[ "$secret_lines" == "$CLIENT_SECRET|65532|65532|400" ||
      "$secret_lines" == "$BAD_CLIENT_SECRET|65532|65532|400" ||
      "$secret_lines" == "$ROOT_CLIENT_SECRET|65532|65532|400" ]]
  else
    [[ "$secret_lines" == "$expected" ]]
  fi
}

verify_created_container_policy() {
  local container_id="$1" kind="$2" expected_user expected_network
  local user privileged readonly nnp cap_add cap_drop effective bounding network_mode expected_cap_drop
  local ipc_mode pid_mode uts_mode networks secret_count
  case "$kind" in
    server) expected_user="$MYSQL_SERVICE_USER"; expected_network="$NETWORK" ;;
    client) expected_user="$CLIENT_USER"; expected_network="$NETWORK" ;;
    *) set_note 'runtime-preflight-container-kind-failed'; return 1 ;;
  esac
  user=$(policy_field "$container_id" '{{.Config.User}}') || return 1
  privileged=$(policy_field "$container_id" '{{.HostConfig.Privileged}}') || return 1
  readonly=$(policy_field "$container_id" '{{.HostConfig.ReadonlyRootfs}}') || return 1
  nnp=$(policy_field "$container_id" '{{range .HostConfig.SecurityOpt}}{{if or (eq . "no-new-privileges") (eq . "no-new-privileges=true")}}no-new-privileges=true{{end}}{{end}}') || return 1
  cap_add=$(policy_field "$container_id" '{{range .HostConfig.CapAdd}}{{println .}}{{end}}') || return 1
  cap_drop=$(policy_field "$container_id" '{{range .HostConfig.CapDrop}}{{println .}}{{end}}') || return 1
  effective=$(policy_field "$container_id" '{{range .EffectiveCaps}}{{println .}}{{end}}') || return 1
  bounding=$(policy_field "$container_id" '{{range .BoundingCaps}}{{println .}}{{end}}') || return 1
  network_mode=$(policy_field "$container_id" '{{.HostConfig.NetworkMode}}') || return 1
  ipc_mode=$(policy_field "$container_id" '{{.HostConfig.IpcMode}}') || return 1
  pid_mode=$(policy_field "$container_id" '{{.HostConfig.PidMode}}') || return 1
  uts_mode=$(policy_field "$container_id" '{{.HostConfig.UTSMode}}') || return 1
  networks=$(policy_field "$container_id" '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}') || return 1
  networks=$(printf '%s' "$networks" | LC_ALL=C sort)
  # Podman renders --cap-drop ALL as the exact rootless capability list in
  # CapDrop; the effective and bounding sets must still be empty.
  expected_cap_drop=$'CAP_CHOWN\nCAP_DAC_OVERRIDE\nCAP_FOWNER\nCAP_FSETID\nCAP_KILL\nCAP_NET_BIND_SERVICE\nCAP_SETFCAP\nCAP_SETGID\nCAP_SETPCAP\nCAP_SETUID\nCAP_SYS_CHROOT'
  if [[ "$user" != "$expected_user" ]]; then set_note 'container-policy-user'; return 1; fi
  if [[ "$privileged" != 'false' ]]; then set_note 'container-policy-privileged'; return 1; fi
  if [[ "$readonly" != 'true' ]]; then set_note 'container-policy-readonly-root'; return 1; fi
  if [[ "$nnp" != 'no-new-privileges=true' ]]; then set_note 'container-policy-no-new-privileges'; return 1; fi
  if [[ -n "$cap_add" || "$cap_drop" != "$expected_cap_drop" || -n "$effective" || -n "$bounding" ]]; then
    set_note 'container-policy-capabilities'
    return 1
  fi
  # Rootless Podman reports the bridge network mode while the authoritative
  # membership map carries the named network.  Require both a non-host bridge
  # mode and exactly the intended membership.
  if [[ "$network_mode" != 'bridge' || "$networks" != "$expected_network" ]]; then
    set_note 'container-policy-exclusive-network'
    return 1
  fi
  if [[ "$ipc_mode" != 'private' || "$pid_mode" != 'private' || "$uts_mode" != 'private' ]]; then
    set_note 'container-policy-namespace'
    return 1
  fi
  policy_count_is_zero "$container_id" '{{len .HostConfig.Binds}}' || { set_note 'container-policy-binds'; return 1; }
  policy_count_is_zero "$container_id" '{{len .HostConfig.Devices}}' || { set_note 'container-policy-devices'; return 1; }
  policy_count_is_zero "$container_id" '{{len .HostConfig.PortBindings}}' || { set_note 'container-policy-ports'; return 1; }
  policy_count_is_zero "$container_id" '{{len .HostConfig.VolumesFrom}}' || { set_note 'container-policy-volumes-from'; return 1; }
  policy_count_is_zero "$container_id" '{{len .Mounts}}' || { set_note 'container-policy-mounts'; return 1; }
  policy_count_is_zero "$container_id" '{{len .HostConfig.ExtraHosts}}' || { set_note 'container-policy-extra-hosts'; return 1; }
  policy_count_is_zero "$container_id" '{{len .HostConfig.GroupAdd}}' || { set_note 'container-policy-group-add'; return 1; }
  policy_count_is_zero "$container_id" '{{len .HostConfig.Links}}' || { set_note 'container-policy-links'; return 1; }
  secret_count=$(policy_field "$container_id" '{{len .Config.Secrets}}') || return 1
  if ! [[ "$kind" == server && "$secret_count" == '2' || "$kind" == client && "$secret_count" == '1' ]]; then
    set_note 'container-policy-secret-count'
    return 1
  fi
  verify_tmpfs_policy "$container_id" "$kind" || { set_note 'container-policy-tmpfs'; return 1; }
  verify_secret_policy "$container_id" "$kind" || { set_note 'container-policy-secret-metadata'; return 1; }
  verify_non_secret_env_keys "$container_id" "$kind" || { set_note 'container-policy-env-keys'; return 1; }
  return 0
}

generate_resource_nonce() {
  local nonce
  nonce=$(python3 -c 'import secrets; print(secrets.token_hex(12))') || {
    set_note 'resource-name-nonce-generation-failed'
    return 1
  }
  if [[ ! "$nonce" =~ ^[0-9a-f]{24}$ ]]; then
    set_note 'resource-name-nonce-invalid'
    return 1
  fi
  RESOURCE_NONCE="$nonce"
}

generate_credentials() {
  local root live bad
  root=$(python3 -c 'import secrets; print(secrets.token_hex(24))') || return 1
  live=$(python3 -c 'import secrets; print(secrets.token_hex(24))') || return 1
  bad=$(python3 -c 'import secrets; print(secrets.token_hex(24))') || return 1
  [[ -n "$root" && -n "$live" && -n "$bad" ]] || return 1
  ROOT_PASSWORD="$root"
  LIVE_PASSWORD="$live"
  BAD_PASSWORD="$bad"
}

reserve_secret_name() {
  local name="$1" state=0
  if secret_exists_state "$name"; then
    state=0
  else
    state=$?
  fi
  if (( state == 0 )); then
    set_note 'secret-name-collision'
    return 1
  fi
  if (( state != 1 )); then
    set_note 'secret-existence-preflight-failed'
    return 1
  fi
  OWNED_SECRET_NAMES+=("$name")
  SECRET_RESOURCE_RESERVED=1
}

create_secret_from_stdin() {
  local name="$1"
  if ! timeout "$CLIENT_CREATE_TIMEOUT_SECONDS" "$RUNTIME" secret create "$name" - >/dev/null 2>/dev/null; then
    set_note 'ephemeral-secret-create-failed'
    return 1
  fi
  if ! secret_exists_state "$name"; then
    set_note 'ephemeral-secret-verification-failed'
    return 1
  fi
}

create_runtime_secrets() {
  if [[ ! "$RESOURCE_NONCE" =~ ^[0-9a-f]{24}$ ]]; then
    set_note 'resource-name-nonce-unavailable'
    return 1
  fi
  SERVER_ROOT_SECRET="statekit-e51-root-$RESOURCE_NONCE"
  SERVER_USER_SECRET="statekit-e51-user-$RESOURCE_NONCE"
  CLIENT_SECRET="statekit-e51-client-$RESOURCE_NONCE"
  BAD_CLIENT_SECRET="statekit-e51-bad-client-$RESOURCE_NONCE"
  ROOT_CLIENT_SECRET="statekit-e51-root-client-$RESOURCE_NONCE"
  reserve_secret_name "$SERVER_ROOT_SECRET" || return 1
  printf '%s' "$ROOT_PASSWORD" | create_secret_from_stdin "$SERVER_ROOT_SECRET" || return 1
  reserve_secret_name "$SERVER_USER_SECRET" || return 1
  printf '%s' "$LIVE_PASSWORD" | create_secret_from_stdin "$SERVER_USER_SECRET" || return 1
  reserve_secret_name "$CLIENT_SECRET" || return 1
  printf '[client]\nuser=%s\npassword=%s\n' "$TEST_USER" "$LIVE_PASSWORD" |
    create_secret_from_stdin "$CLIENT_SECRET" || return 1
  reserve_secret_name "$BAD_CLIENT_SECRET" || return 1
  printf '[client]\nuser=%s\npassword=%s\n' "$TEST_USER" "$BAD_PASSWORD" |
    create_secret_from_stdin "$BAD_CLIENT_SECRET" || return 1
  reserve_secret_name "$ROOT_CLIENT_SECRET" || return 1
  printf '[client]\nuser=root\npassword=%s\n' "$ROOT_PASSWORD" |
    create_secret_from_stdin "$ROOT_CLIENT_SECRET" || return 1
}

verify_private_network_policy() {
  local policy name internal attached
  policy=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" network inspect \
    --format '{{.Name}}|{{.Internal}}|{{len .Containers}}' "$NETWORK" 2>/dev/null) || {
    set_note 'runtime-preflight-network-inspect-failed'
    return 1
  }
  IFS='|' read -r name internal attached <<< "$policy"
  if [[ "$name" != "$NETWORK" || "$internal" != 'true' || "$attached" != '0' ]]; then
    set_note 'runtime-preflight-network-policy-failed'
    return 1
  fi
}

pull_and_verify_image() {
  if ! timeout 180 "$RUNTIME" pull --quiet "$MYSQL_IMAGE" >/dev/null 2>/dev/null; then
    set_note 'pinned-mysql-image-pull-failed'
    return 1
  fi
  local refs ref found=0
  refs=$(timeout "$PREFLIGHT_TIMEOUT_SECONDS" "$RUNTIME" image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' "$MYSQL_IMAGE" 2>/dev/null || true)
  while IFS= read -r ref; do
    if [[ "$ref" == *"@$MYSQL_DIGEST" ]]; then
      found=1
    fi
  done <<< "$refs"
  if (( found != 1 )); then
    set_note 'pinned-mysql-image-digest-mismatch'
    return 1
  fi
}

create_private_network() {
  if [[ ! "$RESOURCE_NONCE" =~ ^[0-9a-f]{24}$ ]]; then
    set_note 'resource-name-nonce-unavailable'
    return 1
  fi
  NETWORK="statekit-e51-net-$RESOURCE_NONCE"
  local state=0
  if network_exists_state "$NETWORK"; then
    state=0
  else
    state=$?
  fi
  if (( state != 1 )); then
    set_note 'private-network-name-not-available'
    return 1
  fi
  NETWORK_RESERVED=1
  NETWORK_OWNED=1
  if ! timeout 30 "$RUNTIME" network create --internal "$NETWORK" >"$WORK_DIR/network.out" 2>"$WORK_DIR/network.err"; then
    set_note 'private-network-create-failed'
    return 1
  fi
  verify_private_network_policy
}

start_mysql() {
  local id_path="$WORK_DIR/server.id" container_id
  DB_OWNED=1
  if ! timeout "$CLIENT_CREATE_TIMEOUT_SECONDS" "$RUNTIME" create \
    --name "$DB_CONTAINER" \
    --network "$NETWORK" \
    --env "MYSQL_ROOT_PASSWORD_FILE=$SERVER_ROOT_SECRET_TARGET" \
    --env "MYSQL_PASSWORD_FILE=$SERVER_USER_SECRET_TARGET" \
    --env "MYSQL_DATABASE=$SEED_DB" \
    --env "MYSQL_USER=$TEST_USER" \
    --secret "source=$SERVER_ROOT_SECRET,type=mount,target=$SERVER_ROOT_SECRET_TARGET,uid=999,gid=999,mode=400" \
    --secret "source=$SERVER_USER_SECRET,type=mount,target=$SERVER_USER_SECRET_TARGET,uid=999,gid=999,mode=400" \
    --user "$MYSQL_SERVICE_USER" \
    --read-only \
    --tmpfs /var/lib/mysql:rw,nosuid,nodev,noexec,size=512m,mode=1777 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    --memory 768m \
    --cpus 2 \
    --pids-limit 256 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --ipc private \
    --pid private \
    --uts private \
    "$MYSQL_IMAGE" >"$id_path" 2>"$WORK_DIR/server.err"; then
    set_note 'mysql-container-start-failed'
    return 1
  fi
  container_id=$(tr -d '[:space:]' <"$id_path")
  if [[ ! "$container_id" =~ ^[[:alnum:]_.-]+$ ]]; then
    set_note 'mysql-container-id-unavailable'
    return 1
  fi
  DB_CONTAINER_ID="$container_id"
  if ! verify_created_container_policy "$DB_CONTAINER_ID" server; then
    return 1
  fi
  if ! timeout "$CLIENT_START_TIMEOUT_SECONDS" "$RUNTIME" start "$DB_CONTAINER_ID" >"$WORK_DIR/server-start.out" 2>"$WORK_DIR/server-start.err"; then
    set_note 'mysql-container-start-failed'
    return 1
  fi
}

build_client_image() {
  local context="$WORK_DIR/client-context"
  local state=0
  if ! mkdir -m 700 "$context"; then
    set_note 'statekit-client-context-create-failed'
    return 1
  fi
  if ! cp "$STATEKIT_BIN" "$context/statekit" || ! cp "$SCRIPT_DIR/Containerfile" "$context/Containerfile"; then
    set_note 'statekit-client-context-copy-failed'
    return 1
  fi
  if ! chmod 755 "$context/statekit"; then
    set_note 'statekit-client-binary-permission-failed'
    return 1
  fi
  if [[ ! "$RESOURCE_NONCE" =~ ^[0-9a-f]{24}$ ]]; then
    set_note 'resource-name-nonce-unavailable'
    return 1
  fi
  CLIENT_IMAGE="statekit-e51-client:$RESOURCE_NONCE"
  if image_exists_state "$CLIENT_IMAGE"; then
    set_note 'statekit-client-image-name-collision'
    return 1
  else
    state=$?
  fi
  if (( state != 1 )); then
    set_note 'statekit-client-image-preflight-failed'
    return 1
  fi
  CLIENT_IMAGE_RESERVED=1
  CLIENT_IMAGE_OWNED=1
  # This COPY-only build has no network-capable instruction.  Network denial
  # is still explicit so a changed Containerfile cannot silently fetch code.
  if ! timeout 120 "$RUNTIME" build --pull=never --isolation=oci --network=none \
    --file "$context/Containerfile" \
    --tag "$CLIENT_IMAGE" \
    "$context" >"$WORK_DIR/client-build.out" 2>"$WORK_DIR/client-build.err"; then
    set_note 'statekit-client-image-build-failed'
    return 1
  fi
}

create_owned_input_file() {
  local content="$1" max_bytes="$2" path bytes
  [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] || return 125
  path=$(mktemp "$WORK_DIR/input.XXXXXX") || return 125
  if ! chmod 600 "$path" || ! printf '%s' "$content" >"$path"; then
    rm -f -- "$path"
    return 125
  fi
  if ! owned_private_file "$path"; then
    rm -f -- "$path"
    return 125
  fi
  bytes=$(wc -c <"$path") || {
    rm -f -- "$path"
    return 125
  }
  if (( bytes > max_bytes )); then
    rm -f -- "$path"
    return 2
  fi
  printf '%s\n' "$path"
}

create_query_spec_file() {
  local database="$1" sql="$2" path bytes
  [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] || return 125
  path=$(mktemp "$WORK_DIR/query-spec.XXXXXX") || return 125
  if ! chmod 600 "$path" || ! printf '%s\0%s' "$database" "$sql" >"$path"; then
    rm -f -- "$path"
    return 125
  fi
  if ! owned_private_file "$path"; then
    rm -f -- "$path"
    return 125
  fi
  bytes=$(wc -c <"$path") || {
    rm -f -- "$path"
    return 125
  }
  if (( bytes > STATEKIT_REQUEST_MAX_BYTES )); then
    rm -f -- "$path"
    return 2
  fi
  printf '%s\n' "$path"
}

owned_private_file() {
  local path="$1" mode
  [[ -f "$path" && ! -L "$path" && -O "$path" ]] || return 1
  mode=$(stat -c '%a' -- "$path" 2>/dev/null) || return 1
  [[ "$mode" == '600' ]]
}

strip_statekit_proof() {
  local path="$1" temporary count
  [[ -f "$path" && ! -L "$path" ]] || return 1
  count=$(awk -v marker="$STATEKIT_PROOF_MARKER" \
    '$0 == marker { count++ } END { print count + 0 }' "$path" 2>/dev/null) || return 1
  [[ "$count" == '1' ]] || return 1
  temporary="${path}.proof"
  if ! awk -v marker="$STATEKIT_PROOF_MARKER" '$0 != marker { print }' "$path" >"$temporary" ||
    ! chmod 600 "$temporary" || ! mv -f -- "$temporary" "$path"; then
    rm -f -- "$temporary"
    return 1
  fi
}

discard_client_input() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    rm -f -- "$path" || return 1
  fi
  [[ ! -e "$path" && ! -L "$path" ]]
}

run_client_container() {
  local stdout_path="$1" stderr_path="$2" input_path="$3"
  shift 3
  local name="statekit-e51-client-${RESOURCE_NONCE:-local}-$CLIENT_SEQUENCE" id_path wait_path create_rc=0 attach_rc=0 wait_rc=0
  local container_id='' wait_value='' index
  CLIENT_SEQUENCE=$((CLIENT_SEQUENCE + 1))
  LAST_CLIENT_CLASS='setup'
  LAST_CLIENT_EXIT_RC=125
  : >"$stdout_path"
  : >"$stderr_path"
  if [[ -z "$WORK_DIR" || -z "$input_path" || "$input_path" != "$WORK_DIR"/* ]] ||
    ! owned_private_file "$input_path"; then
    LAST_CLIENT_CLASS='setup'
    return 125
  fi
  if ! reserve_container_name "$name"; then
    if ! discard_client_input "$input_path"; then
      LAST_CLIENT_CLASS='cleanup'
      mark_cleanup_failure
    fi
    return 125
  fi
  index=${#OWNED_CLIENT_NAMES[@]}
  OWNED_CLIENT_NAMES+=("$name")
  OWNED_CLIENT_IDS+=('')
  id_path="$WORK_DIR/client-${CLIENT_SEQUENCE}.id"
  wait_path="$WORK_DIR/client-${CLIENT_SEQUENCE}.wait"
  timeout "$CLIENT_CREATE_TIMEOUT_SECONDS" "$RUNTIME" create --interactive --name "$name" "$@" >"$id_path" 2>"$WORK_DIR/client-${CLIENT_SEQUENCE}.create.err" || create_rc=$?
  if (( create_rc != 0 )); then
    if discard_client_input "$input_path"; then
      LAST_CLIENT_CLASS='setup'
    else
      LAST_CLIENT_CLASS='cleanup'
      mark_cleanup_failure
    fi
    if ! cleanup_container "$name" ''; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  container_id=$(tr -d '[:space:]' <"$id_path")
  if [[ ! "$container_id" =~ ^[[:alnum:]_.-]+$ ]]; then
    if discard_client_input "$input_path"; then
      LAST_CLIENT_CLASS='setup'
    else
      LAST_CLIENT_CLASS='cleanup'
      mark_cleanup_failure
    fi
    if ! cleanup_container "$name" ''; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  OWNED_CLIENT_IDS[index]="$container_id"
  if ! verify_created_container_policy "$container_id" client; then
    if discard_client_input "$input_path"; then
      LAST_CLIENT_CLASS='setup'
    else
      LAST_CLIENT_CLASS='cleanup'
      mark_cleanup_failure
    fi
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  # Attach at start so the request is delivered over the container's stdin.
  # The request path is host-owned and ephemeral; its contents never occur in
  # the create/start argv or in a bind mount.
  timeout "$CLIENT_START_TIMEOUT_SECONDS" "$RUNTIME" start --attach --interactive "$container_id" \
    <"$input_path" >"$stdout_path" 2>"$stderr_path" || attach_rc=$?
  if ! discard_client_input "$input_path"; then
    LAST_CLIENT_CLASS='cleanup'
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  if (( attach_rc == 124 )); then
    LAST_CLIENT_CLASS='timeout'
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 124
  fi
  if (( attach_rc >= 125 )); then
    # Podman reserves 125+ for a start/exec/runtime failure.  A normal
    # production process exit is carried by wait and may be 1, so do not use
    # every nonzero attach status as a setup failure.
    LAST_CLIENT_CLASS='runtime'
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  timeout "$CLIENT_TIMEOUT_SECONDS" "$RUNTIME" wait "$container_id" >"$wait_path" 2>"$WORK_DIR/client-${CLIENT_SEQUENCE}.wait.err" || wait_rc=$?
  if (( wait_rc != 0 )); then
    if (( wait_rc == 124 )); then
      LAST_CLIENT_CLASS='timeout'
    else
      LAST_CLIENT_CLASS='runtime'
    fi
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return "$wait_rc"
  fi
  wait_value=$(tr -d '[:space:]' <"$wait_path")
  if [[ ! "$wait_value" =~ ^[0-9]+$ || "$wait_value" -gt 255 ]]; then
    LAST_CLIENT_CLASS='runtime'
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  if (( CLIENT_EXPECT_STATEKIT_PROOF == 1 )); then
    if ! strip_statekit_proof "$stderr_path"; then
      LAST_CLIENT_CLASS='runtime'
      if ! cleanup_container "$name" "$container_id"; then
        LAST_CLIENT_CLASS='cleanup'
      fi
      return 125
    fi
    LAST_STATEKIT_BINARY_LAUNCHED=1
  fi
  if (( attach_rc != 0 && wait_value == 0 )); then
    LAST_CLIENT_CLASS='runtime'
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  LAST_CLIENT_EXIT_RC="$wait_value"
  if ! cleanup_container "$name" "$container_id"; then
    LAST_CLIENT_CLASS='cleanup'
    return 125
  fi
  LAST_CLIENT_CLASS='exited'
  return "$LAST_CLIENT_EXIT_RC"
}

readonly MYSQL_CLIENT_SCRIPT='set -eu
secret_source="$1"
shift
credentials_file=/tmp/mysql-client.cnf
cp -- "$secret_source" "$credentials_file"
chmod 600 "$credentials_file"
trap '\''rm -f -- "$credentials_file"'\'' EXIT
exec mysql --defaults-extra-file="$credentials_file" "$@"'

native_mysql() {
  local secret_name="$1" host="$2" port="$3" sql="$4" stdout_path="$5" stderr_path="$6" input_path
  if ! input_path=$(create_owned_input_file "$sql" "$STATEKIT_REQUEST_MAX_BYTES"); then
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  fi
  CLIENT_EXPECT_STATEKIT_PROOF=0
  LAST_STATEKIT_BINARY_LAUNCHED=0
  run_client_container "$stdout_path" "$stderr_path" "$input_path" \
    --network "$NETWORK" \
    --secret "source=$secret_name,type=mount,target=$CLIENT_SECRET_TARGET,uid=65532,gid=65532,mode=400" \
    --read-only \
    --tmpfs /var/lib/mysql:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    --memory 256m \
    --cpus 1 \
    --pids-limit 64 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --ipc private \
    --pid private \
    --uts private \
    --user "$CLIENT_USER" \
    --entrypoint /bin/sh \
    "$MYSQL_IMAGE" \
    -c "$MYSQL_CLIENT_SCRIPT" \
    -- "$CLIENT_SECRET_TARGET" \
    --protocol=TCP \
    --connect-timeout="$NATIVE_CONNECT_TIMEOUT_SECONDS" \
    --host="$host" \
    --port="$port" \
    --user="$NATIVE_CLIENT_USER" \
    --database="$SEED_DB" \
    --batch \
    --binary-mode \
    --skip-column-names
}

native_mysql_as_user() {
  local user="$1" previous_user="$NATIVE_CLIENT_USER" rc=0
  shift
  NATIVE_CLIENT_USER="$user"
  if native_mysql "$@"; then
    rc=0
  else
    rc=$?
  fi
  NATIVE_CLIENT_USER="$previous_user"
  return "$rc"
}

lifecycle_mutation_precheck() {
  if (( LIFECYCLE_DB_RESERVED != 1 )); then
    set_note 'lifecycle-absence-reservation-required'
    return 1
  fi
  if [[ -z "$WORK_DIR" || -z "$ROOT_CLIENT_SECRET" || -z "$DB_HOST" ||
    ! "$LIFECYCLE_DB" =~ ^statekit_r93j_[[:alnum:]_-]+$ ]]; then
    set_note 'lifecycle-mutation-precheck-failed'
    return 1
  fi
  return 0
}

lifecycle_database_presence() {
  local stdout_path="$1" stderr_path="$2" rc=0 value
  : >"$stdout_path"
  : >"$stderr_path"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '$LIFECYCLE_DB'" \
    "$stdout_path" "$stderr_path" || rc=$?
  if (( rc != 0 )) || ! value_free_files "$stdout_path" "$stderr_path"; then
    return 2
  fi
  value=$(<"$stdout_path")
  if [[ "$value" == "$LIFECYCLE_DB" ]]; then
    return 0
  fi
  if [[ -z "$value" ]]; then
    return 1
  fi
  return 2
}

reconcile_ambiguous_lifecycle_create() {
  local stdout_path="$WORK_DIR/lifecycle-create-reconcile.out"
  local stderr_path="$WORK_DIR/lifecycle-create-reconcile.err"
  local presence=2
  if (( LIFECYCLE_DB_RESERVED != 1 )); then
    set_note 'lifecycle-create-reconciliation-without-reservation'
    return 1
  fi
  if lifecycle_database_presence "$stdout_path" "$stderr_path"; then
    presence=0
  else
    presence=$?
  fi
  rm -f -- "$stdout_path" "$stderr_path"
  case "$presence" in
    0)
      # The CREATE may have completed before its client was interrupted.  The
      # reservation makes this database ours even when no result was returned.
      LIFECYCLE_DB_OWNED=1
      return 0
      ;;
    1)
      # Keep the cleanup obligation until the final DROP/absence check.  A
      # missing readback is not permission to dispatch another mutation.
      set_note 'lifecycle-create-reconciled-absent'
      return 1
      ;;
    *)
      set_note 'lifecycle-create-reconciliation-uncertain'
      return 1
      ;;
  esac
}

cleanup_lifecycle_database() {
  local stdout_path stderr_path verify_stdout verify_stderr
  local rc=0 value presence=2
  if (( LIFECYCLE_DB_RESERVED != 1 || LIFECYCLE_DB_OWNED != 1 )); then
    if (( LIFECYCLE_DB_OWNED == 1 && LIFECYCLE_DB_RESERVED != 1 )); then
      set_cleanup_note 'lifecycle-owned-without-absence-reservation'
      mark_cleanup_failure
      return 1
    fi
    return 0
  fi
  if [[ -z "$WORK_DIR" || -z "$ROOT_CLIENT_SECRET" || -z "$DB_HOST" ||
    ! "$LIFECYCLE_DB" =~ ^statekit_r93j_[[:alnum:]_-]+$ ]]; then
    set_cleanup_note 'lifecycle-cleanup-precheck-failed'
    mark_cleanup_failure
    return 1
  fi
  stdout_path="$WORK_DIR/lifecycle-cleanup.out"
  stderr_path="$WORK_DIR/lifecycle-cleanup.err"
  verify_stdout="$WORK_DIR/lifecycle-cleanup-verify.out"
  verify_stderr="$WORK_DIR/lifecycle-cleanup-verify.err"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "DROP DATABASE IF EXISTS \`$LIFECYCLE_DB\`" "$stdout_path" "$stderr_path" || rc=$?
  value=''
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc != 0 )) || [[ -n "$value" ]] || ! value_free_files "$stdout_path" "$stderr_path"; then
    set_cleanup_note 'lifecycle-cleanup-drop-failed'
    mark_cleanup_failure
    rm -f -- "$stdout_path" "$stderr_path" "$verify_stdout" "$verify_stderr"
    return 1
  fi
  if lifecycle_database_presence "$verify_stdout" "$verify_stderr"; then
    presence=0
  else
    presence=$?
  fi
  case "$presence" in
    1)
      LIFECYCLE_DB_OWNED=0
      LIFECYCLE_DB_RESERVED=0
      rc=0
      ;;
    0)
      set_cleanup_note 'lifecycle-cleanup-residual-database'
      mark_cleanup_failure
      rc=1
      ;;
    *)
      set_cleanup_note 'lifecycle-cleanup-absence-uncertain'
      mark_cleanup_failure
      rc=1
      ;;
  esac
  rm -f -- "$stdout_path" "$stderr_path" "$verify_stdout" "$verify_stderr"
  return "$rc"
}

query_database_presence() {
  local stdout_path="$1" stderr_path="$2" rc=0 value
  : >"$stdout_path"
  : >"$stderr_path"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '$QUERY_DB'" \
    "$stdout_path" "$stderr_path" || rc=$?
  if (( rc != 0 )) || ! value_free_files "$stdout_path" "$stderr_path"; then
    return 2
  fi
  value=$(<"$stdout_path")
  if [[ "$value" == "$QUERY_DB" ]]; then
    return 0
  fi
  if [[ -z "$value" ]]; then
    return 1
  fi
  return 2
}

cleanup_query_database() {
  local stdout_path stderr_path verify_stdout verify_stderr
  local rc=0 value='' presence=2
  if (( QUERY_DB_RESERVED != 1 || QUERY_DB_OWNED != 1 )); then
    if (( QUERY_DB_OWNED == 1 && QUERY_DB_RESERVED != 1 )); then
      set_cleanup_note 'query-owned-without-absence-reservation'
      mark_cleanup_failure
      return 1
    fi
    return 0
  fi
  if [[ -z "$WORK_DIR" || -z "$ROOT_CLIENT_SECRET" || -z "$DB_HOST" ||
    ! "$QUERY_DB" =~ ^statekit_r93p_[[:alnum:]_-]+$ ]]; then
    set_cleanup_note 'query-cleanup-precheck-failed'
    mark_cleanup_failure
    return 1
  fi
  stdout_path="$WORK_DIR/query-cleanup.out"
  stderr_path="$WORK_DIR/query-cleanup.err"
  verify_stdout="$WORK_DIR/query-cleanup-verify.out"
  verify_stderr="$WORK_DIR/query-cleanup-verify.err"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "DROP DATABASE IF EXISTS \`$QUERY_DB\`" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc != 0 )) || [[ -n "$value" ]] || ! value_free_files "$stdout_path" "$stderr_path"; then
    set_cleanup_note 'query-cleanup-drop-failed'
    mark_cleanup_failure
    rm -f -- "$stdout_path" "$stderr_path" "$verify_stdout" "$verify_stderr"
    return 1
  fi
  if query_database_presence "$verify_stdout" "$verify_stderr"; then
    presence=0
  else
    presence=$?
  fi
  case "$presence" in
    1)
      QUERY_DB_OWNED=0
      QUERY_DB_RESERVED=0
      rc=0
      ;;
    0)
      set_cleanup_note 'query-cleanup-residual-database'
      mark_cleanup_failure
      rc=1
      ;;
    *)
      set_cleanup_note 'query-cleanup-absence-uncertain'
      mark_cleanup_failure
      rc=1
      ;;
  esac
  rm -f -- "$stdout_path" "$stderr_path" "$verify_stdout" "$verify_stderr"
  return "$rc"
}

alter_database_presence() {
  local stdout_path="$1" stderr_path="$2" rc=0 value
  : >"$stdout_path"
  : >"$stderr_path"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '$ALTER_DB'" \
    "$stdout_path" "$stderr_path" || rc=$?
  if (( rc != 0 )) || ! value_free_files "$stdout_path" "$stderr_path"; then
    return 2
  fi
  value=$(<"$stdout_path")
  if [[ "$value" == "$ALTER_DB" ]]; then
    return 0
  fi
  if [[ -z "$value" ]]; then
    return 1
  fi
  return 2
}

cleanup_alter_database() {
  local stdout_path stderr_path verify_stdout verify_stderr
  local rc=0 value presence=2
  if (( ALTER_DB_RESERVED != 1 || ALTER_DB_OWNED != 1 )); then
    if (( ALTER_DB_OWNED == 1 && ALTER_DB_RESERVED != 1 )); then
      set_cleanup_note 'alter-owned-without-absence-reservation'
      mark_cleanup_failure
      return 1
    fi
    return 0
  fi
  if [[ -z "$WORK_DIR" || -z "$ROOT_CLIENT_SECRET" || -z "$DB_HOST" ||
    ! "$ALTER_DB" =~ ^statekit_r93l_[[:alnum:]_-]+$ ]]; then
    set_cleanup_note 'alter-cleanup-precheck-failed'
    mark_cleanup_failure
    return 1
  fi
  stdout_path="$WORK_DIR/alter-cleanup.out"
  stderr_path="$WORK_DIR/alter-cleanup.err"
  verify_stdout="$WORK_DIR/alter-cleanup-verify.out"
  verify_stderr="$WORK_DIR/alter-cleanup-verify.err"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "DROP DATABASE IF EXISTS \`$ALTER_DB\`" "$stdout_path" "$stderr_path" || rc=$?
  value=''
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc != 0 )) || [[ -n "$value" ]] || ! value_free_files "$stdout_path" "$stderr_path"; then
    set_cleanup_note 'alter-cleanup-drop-failed'
    mark_cleanup_failure
    rm -f -- "$stdout_path" "$stderr_path" "$verify_stdout" "$verify_stderr"
    return 1
  fi
  if alter_database_presence "$verify_stdout" "$verify_stderr"; then
    presence=0
  else
    presence=$?
  fi
  case "$presence" in
    1)
      ALTER_DB_OWNED=0
      ALTER_DB_RESERVED=0
      rc=0
      ;;
    0)
      set_cleanup_note 'alter-cleanup-residual-database'
      mark_cleanup_failure
      rc=1
      ;;
    *)
      set_cleanup_note 'alter-cleanup-absence-uncertain'
      mark_cleanup_failure
      rc=1
      ;;
  esac
  rm -f -- "$stdout_path" "$stderr_path" "$verify_stdout" "$verify_stderr"
  return "$rc"
}

statekit_secret_password() {
  case "$1" in
    "$CLIENT_SECRET") printf '%s' "$LIVE_PASSWORD" ;;
    "$BAD_CLIENT_SECRET") printf '%s' "$BAD_PASSWORD" ;;
    "$ROOT_CLIENT_SECRET") printf '%s' "$ROOT_PASSWORD" ;;
    *) return 1 ;;
  esac
}

statekit_secret_user() {
  if [[ "$1" == "$ROOT_CLIENT_SECRET" ]]; then
    printf '%s' 'root'
  else
    printf '%s' "$TEST_USER"
  fi
}

create_statekit_request_file() {
  local secret_name="$1" function_name="$2" extra_json="$3" host="$4" port="$5" path spec_path password user rc=0 bytes
  [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] || return 125
  password=$(statekit_secret_password "$secret_name") || return 125
  user=$(statekit_secret_user "$secret_name") || return 125
  spec_path=$(mktemp "$WORK_DIR/statekit-spec.XXXXXX") || return 125
  path=$(mktemp "$WORK_DIR/statekit-request.XXXXXX") || {
    rm -f -- "$spec_path"
    return 125
  }
  if ! chmod 600 "$spec_path" "$path" ||
    ! printf '%s\0%s\0%s\0%s\0%s\0%s\0%s' \
      "$user" "$password" "$host" "$port" "$SEED_DB" "$function_name" "$extra_json" >"$spec_path"; then
    rm -f -- "$spec_path" "$path"
    return 125
  fi
  python3 - "$spec_path" "$path" <<'PY' || rc=$?
import json
import sys

spec_path, output_path = sys.argv[1:]
parts = open(spec_path, "rb").read().split(b"\0")
if len(parts) != 7:
    raise SystemExit(2)
user, password, host, port, database, _function_name, fragment = [part.decode("utf-8") for part in parts]
try:
    extras = json.loads("{" + fragment[1:] + "}") if fragment else {}
except (TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
if not isinstance(extras, dict):
    raise SystemExit(2)
payload = {
    "connection_user": user,
    "connection_pass": password,
    "connection_host": host,
    "connection_port": port,
    "connection_db": database,
}
if set(extras).intersection(payload):
    raise SystemExit(2)
payload.update(extras)
with open(output_path, "w", encoding="utf-8") as stream:
    json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"))
PY
  rm -f -- "$spec_path"
  if (( rc != 0 )); then
    rm -f -- "$path"
    return "$rc"
  fi
  bytes=$(wc -c <"$path") || {
    rm -f -- "$path"
    return 125
  }
  if (( bytes > STATEKIT_REQUEST_MAX_BYTES )) || ! owned_private_file "$path"; then
    rm -f -- "$path"
    return 2
  fi
  printf '%s\n' "$path"
}

# The single-quoted value is intentionally expanded by /bin/sh in the client.
# shellcheck disable=SC2016
readonly STATEKIT_SCRIPT='set -eu
secret_source="$1"
function_name="$2"
test -r "$secret_source"
proof_file=/tmp/statekit-version.json
trap '\''rm -f -- "$proof_file"'\'' EXIT
/usr/local/bin/statekit version --output json >"$proof_file"
grep -Eq '\''"version"[[:space:]]*:'\'' "$proof_file"
set +e
/usr/local/bin/statekit exec "$function_name" --stdin --output json
statekit_rc=$?
set -e
printf '\''%s\n'\'' '\''statekit: production-binary-completed'\'' >&2
exit "$statekit_rc"'

statekit_call() {
  local secret_name="$1" function_name="$2" extra_json="$3" host="$4" port="$5" stdout_path="$6" stderr_path="$7"
  local input_path rc=0
  LAST_STATEKIT_BINARY_LAUNCHED=0
  input_path=$(create_statekit_request_file "$secret_name" "$function_name" "$extra_json" "$host" "$port") || {
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  }
  CLIENT_EXPECT_STATEKIT_PROOF=1
  if run_client_container "$stdout_path" "$stderr_path" "$input_path" \
    --network "$NETWORK" \
    --secret "source=$secret_name,type=mount,target=$CLIENT_SECRET_TARGET,uid=65532,gid=65532,mode=400" \
    --read-only \
    --tmpfs /var/lib/mysql:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    --memory 256m \
    --cpus 1 \
    --pids-limit 64 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --ipc private \
    --pid private \
    --uts private \
    --user "$CLIENT_USER" \
    --entrypoint /bin/sh \
    "$CLIENT_IMAGE" \
    -c "$STATEKIT_SCRIPT" \
    -- "$CLIENT_SECRET_TARGET" "$function_name"; then
    rc=0
  else
    rc=$?
  fi
  CLIENT_EXPECT_STATEKIT_PROOF=0
  return "$rc"
}

# The first stdin frame is a decimal byte count followed by the owned SQL file
# bytes. The remaining bytes are the ordinary JSON request consumed by the
# production binary. Keeping the SQL in this pipe, rather than in a Podman
# argv or shell fragment, exercises the actual file_query filesystem boundary.
# shellcheck disable=SC2016
readonly FILE_QUERY_SCRIPT='set -eu
secret_source="$1"
test -r "$secret_source"
sql_file=/tmp/statekit-file-query.sql
proof_file=/tmp/statekit-version.json
trap '\''rm -f -- "$sql_file" "$proof_file"'\'' EXIT
IFS= read -r sql_bytes
case "$sql_bytes" in
  ""|*[!0-9]*) exit 125 ;;
esac
umask 077
: >"$sql_file"
dd if=/dev/stdin of="$sql_file" bs=1 count="$sql_bytes" 2>/dev/null
actual_bytes=$(wc -c <"$sql_file")
[ "$actual_bytes" = "$sql_bytes" ]
chmod 600 "$sql_file"
/usr/local/bin/statekit version --output json >"$proof_file"
grep -Eq '\''"version"[[:space:]]*:'\'' "$proof_file"
set +e
/usr/local/bin/statekit exec mysql.file_query --stdin --output json
statekit_rc=$?
set -e
printf '\''%s\n'\'' '\''statekit: production-binary-completed'\'' >&2
exit "$statekit_rc"'

statekit_file_query_call_path() {
  local secret_name="$1" database="$2" sql="$3" file_name="$4" stdout_path="$5" stderr_path="$6" connection_host="${7:-$DB_HOST}" connection_port="${8:-$DB_PORT}" extra_json sql_path request_path input_path sql_bytes input_bytes rc=0
  LAST_STATEKIT_BINARY_LAUNCHED=0
  if ! extra_json=$(file_query_extra_json "$database" "$file_name"); then
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  fi
  sql_path=$(create_owned_input_file "$sql" "$STATEKIT_REQUEST_MAX_BYTES") || {
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  }
  request_path=$(create_statekit_request_file "$secret_name" 'mysql.file_query' "$extra_json" "$connection_host" "$connection_port") || {
    rm -f -- "$sql_path"
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  }
  input_path=$(mktemp "$WORK_DIR/statekit-file-query-input.XXXXXX") || {
    rm -f -- "$sql_path" "$request_path"
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  }
  if ! chmod 600 "$input_path" || ! owned_private_file "$input_path"; then
    rm -f -- "$sql_path" "$request_path" "$input_path"
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  fi
  sql_bytes=$(wc -c <"$sql_path") || {
    rm -f -- "$sql_path" "$request_path" "$input_path"
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  }
  if ! printf '%s\n' "$sql_bytes" >"$input_path" || ! cat "$sql_path" "$request_path" >>"$input_path"; then
    rm -f -- "$sql_path" "$request_path" "$input_path"
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  fi
  input_bytes=$(wc -c <"$input_path") || {
    rm -f -- "$sql_path" "$request_path" "$input_path"
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  }
  if (( input_bytes > STATEKIT_REQUEST_MAX_BYTES )) || ! owned_private_file "$input_path"; then
    rm -f -- "$sql_path" "$request_path" "$input_path"
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  fi
  CLIENT_EXPECT_STATEKIT_PROOF=1
  if run_client_container "$stdout_path" "$stderr_path" "$input_path" \
    --network "$NETWORK" \
    --secret "source=$secret_name,type=mount,target=$CLIENT_SECRET_TARGET,uid=65532,gid=65532,mode=400" \
    --read-only \
    --tmpfs /var/lib/mysql:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    --memory 256m \
    --cpus 1 \
    --pids-limit 64 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --ipc private \
    --pid private \
    --uts private \
    --user "$CLIENT_USER" \
    --entrypoint /bin/sh \
    "$CLIENT_IMAGE" \
    -c "$FILE_QUERY_SCRIPT" \
    -- "$CLIENT_SECRET_TARGET"; then
    rc=0
  else
    rc=$?
  fi
  CLIENT_EXPECT_STATEKIT_PROOF=0
  rm -f -- "$sql_path" "$request_path"
  return "$rc"
}

statekit_file_query_call() {
  statekit_file_query_call_path "$1" "$2" "$3" "$FILE_QUERY_PATH" "$4" "$5"
}

value_free_files() {
  local path content
  for path in "$@"; do
    [[ -f "$path" ]] || continue
    content=$(<"$path")
    if [[ -n "$ROOT_PASSWORD" && "$content" == *"$ROOT_PASSWORD"* ]] ||
      [[ -n "$LIVE_PASSWORD" && "$content" == *"$LIVE_PASSWORD"* ]] ||
      [[ -n "$BAD_PASSWORD" && "$content" == *"$BAD_PASSWORD"* ]]; then
      return 1
    fi
  done
}

native_failure_classification() {
  local kind="$1" execution_class="$2" rc="$3" stdout_path="$4" stderr_path="$5" marker='' nonempty_count
  case "$execution_class" in
    timeout|runtime|setup|cleanup)
      printf '%s\n' "$execution_class"
      return 0
      ;;
    exited) ;;
    *)
      printf '%s\n' 'runtime'
      return 0
      ;;
  esac
  if [[ "$rc" != '1' ]]; then
    if [[ "$rc" == '0' ]]; then
      printf '%s\n' 'unexpected-success'
    else
      printf '%s\n' 'unexpected-error'
    fi
    return 0
  fi
  case "$kind" in
    auth) marker="$NATIVE_AUTH_FAILURE_MARKER" ;;
    connection) marker="$NATIVE_CONNECTION_FAILURE_MARKER" ;;
    *)
      printf '%s\n' 'setup'
      return 0
      ;;
  esac
  nonempty_count=$(awk 'NF { count++ } END { print count + 0 }' "$stdout_path" "$stderr_path" 2>/dev/null) || {
    printf '%s\n' 'unexpected-error'
    return 0
  }
  if [[ "$nonempty_count" == '1' ]] &&
    { grep -F -q -- "$marker" "$stdout_path" 2>/dev/null || grep -F -q -- "$marker" "$stderr_path" 2>/dev/null; }; then
    printf '%s\n' 'expected'
  else
    printf '%s\n' 'unexpected-error'
  fi
}

native_plugin_install_classification() {
  local requested_soname="$1" execution_class="$2" rc="$3" stdout_path="$4" stderr_path="$5"
  local counts nonempty_count expected_count
  case "$execution_class" in
    timeout|runtime|setup|cleanup)
      printf '%s\n' "$execution_class"
      return 0
      ;;
    exited) ;;
    *)
      printf '%s\n' 'runtime'
      return 0
      ;;
  esac
  if [[ "$rc" != '1' ]]; then
    if [[ "$rc" == '0' ]]; then
      printf '%s\n' 'unexpected-success'
    else
      printf '%s\n' 'unexpected-error'
    fi
    return 0
  fi
  # Only a caller-provided SONAME basename may satisfy the missing-library
  # observation.  A path must never be turned into evidence for a missing
  # shared object, and rejecting unsafe input here also keeps the exact-match
  # classifier independent of plugin-directory resolution details.
  if [[ ! "$requested_soname" =~ ^[[:alnum:]_.+$-]+$ ]]; then
    printf '%s\n' 'unexpected-error'
    return 0
  fi

  # MySQL uses ER_CANT_OPEN_LIBRARY (1126) for several distinct failures.  A
  # substring marker is insufficient: require exactly one non-empty output
  # line, and require that line to be the complete errno=2 diagnostic for the
  # requested basename.  Any permission/loader/interface/wrong-library or
  # mixed diagnostic therefore stays an unexpected error.
  counts=$(awk \
    -v expected_marker="$NATIVE_PLUGIN_INSTALL_FAILURE_MARKER" \
    -v missing_suffix="$NATIVE_PLUGIN_INSTALL_MISSING_SUFFIX" \
    -v requested_soname="$requested_soname" \
    -v quote="'" '
BEGIN {
  expected = expected_marker " " quote requested_soname quote " " missing_suffix
}
{
  if ($0 != "")
    nonempty_count++
  if ($0 == expected)
    expected_count++
}
END {
  printf "%d %d\n", nonempty_count + 0, expected_count + 0
}' "$stdout_path" "$stderr_path" 2>/dev/null) || {
    printf '%s\n' 'unexpected-error'
    return 0
  }
  read -r nonempty_count expected_count <<<"$counts"
  if [[ "$nonempty_count" == '1' && "$expected_count" == '1' ]]; then
    printf '%s\n' 'install-failure'
    return 0
  fi

  # Keep the existing useful labels for single, unambiguous authentication or
  # connection failures, but never let them accept a mixed diagnostic.
  if [[ "$nonempty_count" == '1' ]] &&
    { grep -F -q -- "$NATIVE_AUTH_FAILURE_MARKER" "$stdout_path" 2>/dev/null ||
      grep -F -q -- "$NATIVE_AUTH_FAILURE_MARKER" "$stderr_path" 2>/dev/null; }; then
    printf '%s\n' 'auth-failure'
    return 0
  fi
  if [[ "$nonempty_count" == '1' ]] &&
    { grep -F -q -- "$NATIVE_CONNECTION_FAILURE_MARKER" "$stdout_path" 2>/dev/null ||
      grep -F -q -- "$NATIVE_CONNECTION_FAILURE_MARKER" "$stderr_path" 2>/dev/null; }; then
    printf '%s\n' 'connection-failure'
    return 0
  fi
  printf '%s\n' 'unexpected-error'
}

native_status_statement_marker() {
  case "$1" in
    master) printf '%s\n' 'MASTER STATUS' ;;
    slave|slave_lag) printf '%s\n' 'SLAVE STATUS' ;;
    processlist) printf '%s\n' 'FULL PROCESSLIST' ;;
    *) return 1 ;;
  esac
}

status_sql() {
  case "$1" in
    processlist) printf '%s\n' 'SHOW FULL PROCESSLIST' ;;
    master) printf '%s\n' 'SHOW MASTER STATUS' ;;
    slave|slave_lag) printf '%s\n' 'SHOW SLAVE STATUS' ;;
    *) return 1 ;;
  esac
}

native_status_is_unsupported() {
  local kind="$1" stdout_path="$2" stderr_path="$3" statement_marker counts
  local error_count expected_count
  case "$kind" in
    master|slave|slave_lag) ;;
    *) return 1 ;;
  esac
  statement_marker=$(native_status_statement_marker "$kind") || return 1
  statement_marker=${statement_marker,,}

  # MySQL 8.4 reports the removed legacy statements as ER_PARSE_ERROR
  # (1064/42000), with the stable syntax-error signature and the offending
  # statement fragment in one diagnostic line.  Count all error diagnostics so
  # an expected line cannot hide an additional unrelated failure.
  counts=$(awk \
    -v error_code="$NATIVE_UNSUPPORTED_STATUS_ERROR_CODE" \
    -v sqlstate="$NATIVE_UNSUPPORTED_STATUS_SQLSTATE" \
    -v signature="$NATIVE_UNSUPPORTED_STATUS_SIGNATURE" \
    -v statement_marker="$statement_marker" '
BEGIN {
  quote = sprintf("%c", 39)
  split(statement_marker, marker_words, /[[:space:]]+/)
  error_pattern = "^[[:space:]]*error[[:space:]]+[0-9]+[[:space:]]+\\([[:alnum:]]+\\)([[:space:]]+at[[:space:]]+line[[:space:]]+[0-9]+)?[[:space:]]*:"
  expected_pattern = "^[[:space:]]*error[[:space:]]+" error_code \
    "[[:space:]]+\\(" sqlstate "\\)([[:space:]]+at[[:space:]]+line[[:space:]]+[0-9]+)?[[:space:]]*:[[:space:]]+" \
    tolower(signature) \
    ".*near[[:space:]]+" quote tolower(marker_words[1]) "[[:space:]]+" \
    tolower(marker_words[2]) quote "[[:space:]]+at[[:space:]]+line[[:space:]]+1[[:space:]]*$"
}
{
  line = tolower($0)
  if (line ~ error_pattern)
    error_count++
  if (line ~ expected_pattern)
    expected_count++
}
END {
  printf "%d %d\n", error_count + 0, expected_count + 0
}' \
    "$stdout_path" "$stderr_path" 2>/dev/null) || return 1
  read -r error_count expected_count <<<"$counts"
  [[ "$error_count" == '1' && "$expected_count" == '1' ]]
}

native_status_classification() {
  local kind="$1" execution_class="$2" rc="$3" stdout_path="$4" stderr_path="$5" nonempty_count
  case "$execution_class" in
    timeout|runtime|setup|cleanup)
      printf '%s\n' "$execution_class"
      return 0
      ;;
    exited) ;;
    *)
      printf '%s\n' 'runtime'
      return 0
      ;;
  esac
  if [[ "$rc" == '0' ]]; then
    if [[ -s "$stdout_path" ]]; then
      printf '%s\n' 'available'
    else
      printf '%s\n' 'empty-output'
    fi
    return 0
  fi
  if [[ "$rc" != '1' ]]; then
    printf '%s\n' 'unexpected-error'
    return 0
  fi
  nonempty_count=$(awk 'NF { count++ } END { print count + 0 }' "$stdout_path" "$stderr_path" 2>/dev/null) || {
    printf '%s\n' 'unexpected-error'
    return 0
  }
  if [[ "$nonempty_count" == '1' ]] &&
    { grep -F -q -- "$NATIVE_AUTH_FAILURE_MARKER" "$stdout_path" 2>/dev/null ||
      grep -F -q -- "$NATIVE_AUTH_FAILURE_MARKER" "$stderr_path" 2>/dev/null; }; then
    printf '%s\n' 'auth-failure'
    return 0
  fi
  if [[ "$nonempty_count" == '1' ]] &&
    { grep -F -q -- "$NATIVE_CONNECTION_FAILURE_MARKER" "$stdout_path" 2>/dev/null ||
      grep -F -q -- "$NATIVE_CONNECTION_FAILURE_MARKER" "$stderr_path" 2>/dev/null; }; then
    printf '%s\n' 'connection-failure'
    return 0
  fi
  if [[ "$kind" != 'processlist' ]] && native_status_is_unsupported "$kind" "$stdout_path" "$stderr_path"; then
    printf '%s\n' 'unsupported-sql'
    return 0
  fi
  printf '%s\n' 'unexpected-error'
}

status_json_classification() {
  local kind="$1" path="$2"
  python3 - "$kind" "$path" <<'PY'
import json
import sys

kind, path = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as stream:
        value = json.load(stream)
except (OSError, ValueError, TypeError):
    print("invalid-json")
    raise SystemExit(0)

if kind == "processlist":
    if not isinstance(value, list):
        print("unexpected-shape")
    elif not value:
        print("empty-output")
    elif all(
        isinstance(row, dict)
        and isinstance(row.get("Id"), int)
        and not isinstance(row.get("Id"), bool)
        and isinstance(row.get("Time"), int)
        and not isinstance(row.get("Time"), bool)
        and isinstance(row.get("User"), str)
        and isinstance(row.get("Command"), str)
        for row in value
    ):
        print("available")
    else:
        print("invalid-type")
    raise SystemExit(0)

if kind == "slave_lag":
    # The scalar Salt contract uses -3 for the native query/connection exit.
    # The live native observation remains the authority for distinguishing that
    # compatibility value from MySQL 8.4's removed statement.
    if isinstance(value, int) and not isinstance(value, bool):
        if value == -3:
            print("compatibility-query-failure")
        elif value == -1:
            print("non-slave")
        elif value == -2:
            print("broken-io")
        elif value >= 0:
            print("available")
        else:
            print("invalid-value")
    elif value is None:
        print("available-null")
    else:
        print("invalid-type")
    raise SystemExit(0)

if value == []:
    print("compatibility-empty-list")
    raise SystemExit(0)
if not isinstance(value, dict):
    print("unexpected-shape")
    raise SystemExit(0)

if kind == "master":
    for key in ("File", "Position"):
        if key not in value:
            print("missing-key")
            raise SystemExit(0)
    if not isinstance(value["File"], str) or (
        not isinstance(value["Position"], int) or isinstance(value["Position"], bool)
    ):
        print("invalid-type")
        raise SystemExit(0)
    print("available")
    raise SystemExit(0)

if kind == "slave":
    port_key = next((key for key in ("Master_Port", "Source_Port") if key in value), None)
    lag_key = next(
        (key for key in ("Seconds_Behind_Master", "Seconds_Behind_Source") if key in value),
        None,
    )
    if port_key is None or lag_key is None:
        print("missing-key")
        raise SystemExit(0)
    port = value[port_key]
    lag = value[lag_key]
    if not isinstance(port, int) or isinstance(port, bool):
        print("invalid-type")
        raise SystemExit(0)
    # A present SQL NULL is a valid replication lag value. It is not the same
    # shape as an omitted key, which is a malformed/mismatched observation.
    if lag is not None and (not isinstance(lag, int) or isinstance(lag, bool)):
        print("invalid-type")
        raise SystemExit(0)
    print("available")
    raise SystemExit(0)

print("invalid-kind")
PY
}

status_observation_correlates() {
  local kind="$1" statekit_class="$2" native_class="$3"
  case "$kind" in
    processlist)
      [[ "$statekit_class" == 'available' && "$native_class" == 'available' ]]
      ;;
    master|slave)
      # StateKit intentionally retains Salt's [] compatibility shape for the
      # exact legacy SHOW query; MySQL 8.4's native client must independently
      # prove that the statement itself is unsupported. Neither side claims a
      # successful replication-status retrieval.
      [[ "$statekit_class" == 'compatibility-empty-list' && "$native_class" == 'unsupported-sql' ]]
      ;;
    slave_lag)
      [[ "$statekit_class" == 'compatibility-query-failure' && "$native_class" == 'unsupported-sql' ]]
      ;;
    *) return 1 ;;
  esac
}

status_negative_correlates() {
  local statekit_class="$1" native_class="$2" expected_native_class="$3" kind="${4:-}"
  local expected_statekit_class='compatibility-empty-list'
  if [[ "$kind" == 'slave_lag' ]]; then
    expected_statekit_class='compatibility-query-failure'
  fi
  [[ "$statekit_class" == "$expected_statekit_class" && "$native_class" == "$expected_native_class" ]]
}

status_classification_path() {
  printf '%s/status-%s.classification\n' "$WORK_DIR" "$1"
}

write_status_classification() {
  local label="$1" classification="$2" path
  path=$(status_classification_path "$label") || return 1
  printf '%s\n' "$classification" >"$path"
}

read_status_classification() {
  local label="$1" path
  path=$(status_classification_path "$label") || return 1
  [[ -s "$path" ]] || return 1
  tr -d '\r\n' <"$path"
}

expect_native_rejection() {
  local kind="$1" rc="$2" stdout_path="$3" stderr_path="$4" classification
  classification=$(native_failure_classification "$kind" "$LAST_CLIENT_CLASS" "$rc" "$stdout_path" "$stderr_path")
  if [[ "$classification" == 'expected' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    return 0
  fi
  case "$classification" in
    timeout) set_note "native-${kind}-negative-timeout" ;;
    runtime) set_note "native-${kind}-negative-runtime-failure" ;;
    setup) set_note "native-${kind}-negative-setup-failure" ;;
    cleanup) set_note "native-${kind}-negative-cleanup-failure" ;;
    unexpected-success) set_note "native-${kind}-negative-unexpected-success" ;;
    unexpected-error) set_note "native-${kind}-negative-unexpected-error" ;;
    expected) set_note "native-${kind}-negative-secret-diagnostic" ;;
    *) set_note "native-${kind}-negative-classification-failure" ;;
  esac
  return 1
}

check_readiness() {
  local stdout_path="$WORK_DIR/readiness.out" stderr_path="$WORK_DIR/readiness.err"
  local deadline=$((SECONDS + READINESS_TIMEOUT_SECONDS)) value
  while (( SECONDS < deadline )); do
    : >"$stdout_path"
    : >"$stderr_path"
    if native_mysql "$CLIENT_SECRET" "$DB_HOST" "$DB_PORT" 'SELECT 1' "$stdout_path" "$stderr_path"; then
      value=$(<"$stdout_path")
      if [[ "$value" == '1' ]] && value_free_files "$stdout_path" "$stderr_path"; then
        rm -f "$stdout_path" "$stderr_path"
        return 0
      fi
    fi
    sleep "$POLL_INTERVAL_SECONDS"
  done
  rm -f "$stdout_path" "$stderr_path"
  set_note 'authenticated-readiness-timeout'
  return 1
}

check_statekit_version() {
  local stdout_path="$WORK_DIR/version.out" stderr_path="$WORK_DIR/version.err"
  local value rc=0 ok=1
  local version_re='^"8\.4\.[0-9]+([.-][^"]*)?"$'
  statekit_call "$CLIENT_SECRET" 'mysql.version' '' "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" =~ $version_re ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

json_contains() {
  local path="$1" needle="$2" kind="$3"
  python3 -c '
import json
import sys

needle, kind = sys.argv[1:]
value = json.load(sys.stdin)
if kind == "database":
    ok = isinstance(value, list) and needle in value
elif kind == "plugin":
    ok = isinstance(value, list) and any(
        isinstance(row, dict) and row.get("name") == needle and row.get("status") == "ACTIVE"
        for row in value
    )
else:
    ok = False
raise SystemExit(0 if ok else 1)
' "$needle" "$kind" <"$path"
}

check_statekit_db_list() {
  local stdout_path="$WORK_DIR/db-list.out" stderr_path="$WORK_DIR/db-list.err" rc=0 ok=1
  statekit_call "$CLIENT_SECRET" 'mysql.db_list' '' "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && json_contains "$stdout_path" "$SEED_DB" database && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_db_exists() {
  local expected="$1" extra_json="$2" label="$3"
  local stdout_path="$WORK_DIR/db-exists-${label}.out" stderr_path="$WORK_DIR/db-exists-${label}.err"
  local rc=0 value ok=1
  statekit_call "$CLIENT_SECRET" 'mysql.db_exists' "$extra_json" "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == "$expected" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_plugins_list() {
  local stdout_path="$WORK_DIR/plugins-list.out" stderr_path="$WORK_DIR/plugins-list.err" rc=0 ok=1
  statekit_call "$CLIENT_SECRET" 'mysql.plugins_list' '' "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && json_contains "$stdout_path" "$INSTALLED_PLUGIN" plugin && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_plugin_status() {
  local plugin="$1" expected="$2" label="$3"
  local stdout_path="$WORK_DIR/plugin-status-${label}.out" stderr_path="$WORK_DIR/plugin-status-${label}.err"
  local rc=0 value ok=1
  statekit_call "$CLIENT_SECRET" 'mysql.plugin_status' ",\"name\":\"$plugin\"" "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == "\"$expected\"" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_plugin_add() {
  local plugin="$1" soname="$2" expected="$3" label="$4" secret_name="${5:-$ROOT_CLIENT_SECRET}" port="${6:-$DB_PORT}"
  local stdout_path="$WORK_DIR/plugin-add-${label}.out" stderr_path="$WORK_DIR/plugin-add-${label}.err"
  local extra_json=",\"name\":\"$plugin\"" rc=0 value='' ok=1
  if [[ -n "$soname" ]]; then
    extra_json="$extra_json,\"soname\":\"$soname\""
  fi
  statekit_call "$secret_name" 'mysql.plugin_add' "$extra_json" "$DB_HOST" "$port" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == "$expected" ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_plugin_remove() {
  local plugin="$1" expected="$2" label="$3" secret_name="${4:-$ROOT_CLIENT_SECRET}" port="${5:-$DB_PORT}"
  local stdout_path="$WORK_DIR/plugin-remove-${label}.out" stderr_path="$WORK_DIR/plugin-remove-${label}.err"
  local rc=0 value='' ok=1
  statekit_call "$secret_name" 'mysql.plugin_remove' ",\"name\":\"$plugin\"" "$DB_HOST" "$port" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == "$expected" ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_plugin_status() {
  local plugin="$1" expected="$2" label="$3"
  local stdout_path="$WORK_DIR/plugin-native-status-${label}.out" stderr_path="$WORK_DIR/plugin-native-status-${label}.err"
  local rc=0 value='' ok=1
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME = '$plugin'" \
    "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == "$expected" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_plugin_install_failure() {
  local plugin="$1" soname="$2" label="$3"
  local stdout_path="$WORK_DIR/plugin-native-install-${label}.out" stderr_path="$WORK_DIR/plugin-native-install-${label}.err"
  local rc=0 classification='' ok=1
  if [[ ! "$soname" =~ ^[[:alnum:]_.+$-]+$ ]]; then
    set_note "plugin-${label}-native-soname-not-basename"
    return 1
  fi
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "INSTALL PLUGIN $plugin SONAME \"$soname\"" "$stdout_path" "$stderr_path" || rc=$?
  classification=$(native_plugin_install_classification "$soname" "$LAST_CLIENT_CLASS" "$rc" "$stdout_path" "$stderr_path") || classification='classification-failure'
  if [[ "$classification" == 'install-failure' ]] && [[ ! -s "$stdout_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note "plugin-${label}-native-${classification}"
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_plugin_invalid_name() {
  local stdout_path="$WORK_DIR/plugin-invalid-name.out" stderr_path="$WORK_DIR/plugin-invalid-name.err"
  local rc=0 ok=1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.plugin_add' ',"name":"bad\nname"' \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 1 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    [[ ! -s "$stdout_path" ]] && grep -F -q -- "$STATEKIT_INVALID_IDENTIFIER_CATEGORY" "$stderr_path" 2>/dev/null &&
    grep -F -q -- "$STATEKIT_INVALID_IDENTIFIER_DIAGNOSTIC" "$stderr_path" 2>/dev/null &&
    ! grep -F -q -- 'bad' "$stderr_path" 2>/dev/null && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'plugin-invalid-name-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_plugin_invalid_soname() {
  local stdout_path="$WORK_DIR/plugin-invalid-soname.out" stderr_path="$WORK_DIR/plugin-invalid-soname.err"
  local rc=0 ok=1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.plugin_add' \
    ",\"name\":\"$PLUGIN_DEFAULT_FAILURE\",\"soname\":\"bad;DROP.so\"" \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 1 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    [[ ! -s "$stdout_path" ]] && grep -F -q -- "$STATEKIT_INVALID_IDENTIFIER_CATEGORY" "$stderr_path" 2>/dev/null &&
    grep -F -q -- "$STATEKIT_INVALID_SONAME_DIAGNOSTIC" "$stderr_path" 2>/dev/null &&
    ! grep -F -q -- 'bad;DROP.so' "$stderr_path" 2>/dev/null && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'plugin-invalid-soname-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_positive() {
  local stdout_path="$WORK_DIR/native-positive.out" stderr_path="$WORK_DIR/native-positive.err"
  local rc=0 value ok=1
  native_mysql "$CLIENT_SECRET" "$DB_HOST" "$DB_PORT" 'SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '\''statekit_e51_seed'\''' "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == "$SEED_DB" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_plugin() {
  local stdout_path="$WORK_DIR/native-plugin.out" stderr_path="$WORK_DIR/native-plugin.err"
  local rc=0 value ok=1
  native_mysql "$CLIENT_SECRET" "$DB_HOST" "$DB_PORT" 'SELECT PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME = '\''caching_sha2_password'\''' "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == 'ACTIVE' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_auth_negative() {
  local stdout_path="$WORK_DIR/native-auth-negative.out" stderr_path="$WORK_DIR/native-auth-negative.err" rc=0 ok=1
  native_mysql "$BAD_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" 'SELECT 1' "$stdout_path" "$stderr_path" || rc=$?
  if expect_native_rejection auth "$rc" "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_auth_negative() {
  local stdout_path="$WORK_DIR/statekit-auth-negative.out" stderr_path="$WORK_DIR/statekit-auth-negative.err"
  local rc=0 value ok=1
  statekit_call "$BAD_CLIENT_SECRET" 'mysql.version' '' "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == '""' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_connection_negative() {
  local stdout_path="$WORK_DIR/native-connection-negative.out" stderr_path="$WORK_DIR/native-connection-negative.err" rc=0 ok=1
  native_mysql "$CLIENT_SECRET" "$DB_HOST" '1' 'SELECT 1' "$stdout_path" "$stderr_path" || rc=$?
  if expect_native_rejection connection "$rc" "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_connection_negative() {
  local stdout_path="$WORK_DIR/statekit-connection-negative.out" stderr_path="$WORK_DIR/statekit-connection-negative.err"
  local rc=0 value ok=1
  statekit_call "$CLIENT_SECRET" 'mysql.version' '' "$DB_HOST" '1' "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == '""' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

query_extra_json() {
  local database="$1" sql="$2" spec_path rc=0
  spec_path=$(create_query_spec_file "$database" "$sql") || return $?
  python3 - "$spec_path" <<'PY' || rc=$?
import json
from pathlib import Path
import sys

database, sql = Path(sys.argv[1]).read_bytes().split(b"\0", 1)
fragment = {"database": database.decode("utf-8"), "query": sql.decode("utf-8")}
encoded = json.dumps(fragment, ensure_ascii=False, separators=(",", ":"))
print("," + encoded[1:-1], end="")
PY
  rm -f -- "$spec_path"
  return "$rc"
}

file_query_extra_json() {
  local database="$1" file_name="$2" spec_path rc=0
  spec_path=$(create_query_spec_file "$database" "$file_name") || return $?
  python3 - "$spec_path" <<'PY' || rc=$?
import json
from pathlib import Path
import sys

database, file_name = Path(sys.argv[1]).read_bytes().split(b"\0", 1)
fragment = {"database": database.decode("utf-8"), "file_name": file_name.decode("utf-8")}
encoded = json.dumps(fragment, ensure_ascii=False, separators=(",", ":"))
print("," + encoded[1:-1], end="")
PY
  rm -f -- "$spec_path"
  return "$rc"
}

query_frame_fixture() {
  case "$1" in
    terminated) printf '%s' 'SELECT 7 AS value;' ;;
    unterminated) printf '%s' 'SELECT 7 AS value' ;;
    trailing-comment) printf '%s' 'SELECT 7 AS value; -- trailing comment' ;;
    quoted-semicolon) printf '%s' "SELECT 'quoted; semicolon' AS value" ;;
    *) return 1 ;;
  esac
}

write_query_frame_fixture() {
  local fixture="$1" path="$2"
  [[ -n "$path" && "$path" == "$WORK_DIR"/* ]] || return 125
  (umask 077; query_frame_fixture "$fixture" >"$path") || return 125
  chmod 600 "$path" && owned_private_file "$path"
}

statekit_query_call() {
  local secret_name="$1" database="$2" sql="$3" stdout_path="$4" stderr_path="$5" extra_json
  if ! extra_json=$(query_extra_json "$database" "$sql"); then
    LAST_CLIENT_CLASS='setup'
    LAST_CLIENT_EXIT_RC=125
    return 125
  fi
  statekit_call "$secret_name" 'mysql.query' "$extra_json" "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path"
}

query_result_matches() {
  local kind="$1" path="$2"
  QUERY_EXPECTED_NOTE_VALUE="$QUERY_EXPECTED_NOTE" python3 - "$kind" "$path" <<'PY'
import json
import os
import sys

kind, path = sys.argv[1:]
expected_note = os.environ["QUERY_EXPECTED_NOTE_VALUE"]
try:
    with open(path, encoding="utf-8") as stream:
        value = json.load(stream)
except (OSError, UnicodeError, ValueError, TypeError):
    raise SystemExit(1)

def query_time_ok(candidate):
    return (
        isinstance(candidate, dict)
        and isinstance(candidate.get("human"), str)
        and isinstance(candidate.get("raw"), str)
    )

def exact_keys(candidate, keys):
    return isinstance(candidate, dict) and set(candidate) == set(keys)

if kind == "false":
    raise SystemExit(0 if value is False else 1)
if not isinstance(value, dict) or not query_time_ok(value.get("query time")):
    raise SystemExit(1)
if kind == "scalar":
    ok = exact_keys(value, ("columns", "results", "rows returned", "query time"))
    ok = ok and value.get("columns") == ["value"] and value.get("results") == [["7"]]
    ok = ok and value.get("rows returned") == 1
elif kind == "table":
    ok = exact_keys(value, ("columns", "results", "rows returned", "query time"))
    ok = ok and value.get("columns") == ["id", "note"] and value.get("rows returned") == 2
    ok = ok and value.get("results") == [["1", "alpha"], ["2", "beta"]]
elif kind == "multiline":
    ok = exact_keys(value, ("columns", "results", "rows returned", "query time"))
    ok = ok and value.get("columns") == ["id", "note"] and value.get("rows returned") == 2
    ok = ok and value.get("results") == [["1", "line one"], ["2", expected_note]]
elif kind.startswith("affected:"):
    try:
        expected = int(kind.split(":", 1)[1])
    except (TypeError, ValueError):
        raise SystemExit(1)
    ok = exact_keys(value, ("rows affected", "query time"))
    ok = ok and value.get("rows affected") == expected
else:
    ok = False
raise SystemExit(0 if ok else 1)
PY
}

file_query_result_matches() {
  local kind="$1" path="$2"
  QUERY_EXPECTED_NOTE_VALUE="$QUERY_EXPECTED_NOTE" python3 - "$kind" "$path" <<'PY'
import json
import os
import sys

kind, path = sys.argv[1:]
expected_note = os.environ["QUERY_EXPECTED_NOTE_VALUE"]
try:
    with open(path, encoding="utf-8") as stream:
        value = json.load(stream)
except (OSError, UnicodeError, ValueError, TypeError):
    raise SystemExit(1)

def query_time_ok(candidate):
    return (
        isinstance(candidate, dict)
        and isinstance(candidate.get("human"), str)
        and isinstance(candidate.get("raw"), (int, float))
    )

def exact_keys(candidate, keys):
    return isinstance(candidate, dict) and set(candidate) == set(keys)

if kind == "false":
    raise SystemExit(0 if value is False else 1)
if not isinstance(value, dict) or not query_time_ok(value.get("query time")):
    raise SystemExit(1)
if kind == "select":
    ok = exact_keys(value, ("columns", "results", "rows returned", "query time"))
    ok = ok and value.get("columns") == [["id", "note"]]
    ok = ok and value.get("results") == [[["1", "line one"], ["2", expected_note]]]
    ok = ok and value.get("rows returned") == 2
elif kind == "dml":
    ok = exact_keys(value, ("rows affected", "query time"))
    ok = ok and value.get("rows affected") == 1
elif kind == "multiline":
    ok = exact_keys(value, ("columns", "results", "rows returned", "query time"))
    ok = ok and value.get("columns") == [["id", "note"], ["note"]]
    ok = ok and value.get("results") == [[ ["1", "line one"] ], [[expected_note]]]
    ok = ok and value.get("rows returned") == 2
else:
    ok = False
raise SystemExit(0 if ok else 1)
PY
}

query_files_are_value_free() {
  local sql="$1" path content
  for path in "${@:2}"; do
    [[ -f "$path" ]] || continue
    content=$(<"$path")
    if [[ -n "$sql" && "$content" == *"$sql"* ]]; then
      return 1
    fi
  done
  value_free_files "${@:2}"
}

statekit_query_failure_classification() {
  local execution_class="$1" rc="$2" stdout_path="$3" stderr_path="$4" diagnostic=''
  case "$execution_class" in
    setup) printf '%s\n' 'setup' ; return 0 ;;
    runtime) printf '%s\n' 'exec' ; return 0 ;;
    cleanup) printf '%s\n' 'cleanup' ; return 0 ;;
    timeout) printf '%s\n' 'outer-timeout' ; return 0 ;;
    exited) ;;
    *) printf '%s\n' 'runtime' ; return 0 ;;
  esac
  if [[ "$rc" != '1' || -s "$stdout_path" || ! -f "$stderr_path" ]]; then
    printf '%s\n' 'unexpected-diagnostic'
    return 0
  fi
  diagnostic=$(<"$stderr_path")
  case "$diagnostic" in
    "$STATEKIT_QUERY_INPUT_LIMIT_DIAGNOSTIC") printf '%s\n' 'input-limit' ;;
    "$STATEKIT_QUERY_TIMEOUT_DIAGNOSTIC") printf '%s\n' 'timeout' ;;
    *) printf '%s\n' 'unexpected-diagnostic' ;;
  esac
}

statekit_query_expected_failure() {
  local expected="$1" rc="$2" stdout_path="$3" stderr_path="$4" classification
  classification=$(statekit_query_failure_classification \
    "$LAST_CLIENT_CLASS" "$rc" "$stdout_path" "$stderr_path")
  [[ "$LAST_STATEKIT_BINARY_LAUNCHED" == '1' && "$LAST_CLIENT_CLASS" == 'exited' &&
    "$LAST_CLIENT_EXIT_RC" == '1' && "$rc" == '1' && "$classification" == "$expected" ]]
}

native_query_diagnostic_classification() {
  local execution_class="$1" rc="$2" stdout_path="$3" stderr_path="$4" counts nonempty_count expected_count
  case "$execution_class" in
    setup) printf '%s\n' 'setup' ; return 0 ;;
    runtime) printf '%s\n' 'exec' ; return 0 ;;
    cleanup) printf '%s\n' 'cleanup' ; return 0 ;;
    timeout) printf '%s\n' 'outer-timeout' ; return 0 ;;
    exited) ;;
    *) printf '%s\n' 'runtime' ; return 0 ;;
  esac
  if [[ "$rc" != '1' || -s "$stdout_path" ]]; then
    printf '%s\n' 'unexpected-diagnostic'
    return 0
  fi
  counts=$(awk \
    -v signature="$NATIVE_QUERY_DIAGNOSTIC_SIGNATURE" \
    -v statement="$NATIVE_QUERY_DIAGNOSTIC_STATEMENT" '
BEGIN {
  quote = sprintf("%c", 39)
  expected = "^ERROR 1064 \\(42000\\) at line 1: " signature \
    " check the manual .*near " quote statement quote " at line 1$"
}
{
  if ($0 != "")
    nonempty_count++
  if ($0 ~ expected)
    expected_count++
}
END { printf "%d %d\n", nonempty_count + 0, expected_count + 0 }
' "$stdout_path" "$stderr_path" 2>/dev/null) || {
    printf '%s\n' 'unexpected-diagnostic'
    return 0
  }
  read -r nonempty_count expected_count <<<"$counts"
  if [[ "$nonempty_count" == '1' && "$expected_count" == '1' ]]; then
    printf '%s\n' 'syntax-error'
  else
    printf '%s\n' 'unexpected-diagnostic'
  fi
}

check_statekit_query_scalar() {
  local stdout_path="$WORK_DIR/query-scalar-statekit.out" stderr_path="$WORK_DIR/query-scalar-statekit.err"
  local sql rc=0 ok=1
  sql=$(query_frame_fixture terminated)
  statekit_query_call "$CLIENT_SECRET" "$SEED_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    query_result_matches scalar "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-scalar-statekit-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_query_scalar() {
  local stdout_path="$WORK_DIR/query-scalar-native.out" stderr_path="$WORK_DIR/query-scalar-native.err"
  local sql rc=0 value='' ok=1
  sql=$(query_frame_fixture terminated)
  native_mysql "$CLIENT_SECRET" "$DB_HOST" "$DB_PORT" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == '7' ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-scalar-native-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_table() {
  local stdout_path="$WORK_DIR/query-table-statekit.out" stderr_path="$WORK_DIR/query-table-statekit.err"
  local sql='SELECT 1 AS id, '\''alpha'\'' AS note UNION ALL SELECT 2, '\''beta'\''' rc=0 ok=1
  statekit_query_call "$CLIENT_SECRET" "$SEED_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    query_result_matches table "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-table-statekit-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_query_table() {
  local stdout_path="$WORK_DIR/query-table-native.out" stderr_path="$WORK_DIR/query-table-native.err"
  local rc=0 value='' ok=1
  native_mysql "$CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    'SELECT 1 AS id, '\''alpha'\'' AS note UNION ALL SELECT 2, '\''beta'\''' "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == $'1\talpha\n2\tbeta' ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-table-native-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_query_database_absent() {
  local stdout_path="$WORK_DIR/query-before.out" stderr_path="$WORK_DIR/query-before.err"
  local presence=2 ok=1
  QUERY_DB_RESERVED=0
  if [[ ! "$QUERY_DB" =~ ^statekit_r93p_[[:alnum:]_-]+$ ]]; then
    set_note 'query-database-name-invalid'
  else
    if query_database_presence "$stdout_path" "$stderr_path"; then
      presence=0
    else
      presence=$?
    fi
    if (( presence == 1 )); then
      QUERY_DB_RESERVED=1
      ok=0
    elif (( presence == 0 )); then
      set_note 'query-database-not-absent'
    else
      set_note 'query-database-absence-uncertain'
    fi
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_create_database() {
  local stdout_path="$WORK_DIR/query-create-database.out" stderr_path="$WORK_DIR/query-create-database.err"
  local sql="CREATE DATABASE \`$QUERY_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci" rc=0 ok=1
  if (( QUERY_DB_RESERVED != 1 )); then
    set_note 'query-create-absence-reservation-required'
    return 1
  fi
  QUERY_DB_OWNED=1
  statekit_query_call "$ROOT_CLIENT_SECRET" "$SEED_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    query_result_matches affected:0 "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-create-database-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_create_table() {
  local stdout_path="$WORK_DIR/query-create-table.out" stderr_path="$WORK_DIR/query-create-table.err"
  local sql="CREATE TABLE \`$QUERY_DB\`.\`$QUERY_TABLE\` (id INT PRIMARY KEY, note VARCHAR(64) NOT NULL)" rc=0 ok=1
  if (( QUERY_DB_RESERVED != 1 || QUERY_DB_OWNED != 1 )); then
    set_note 'query-create-table-ownership-required'
    return 1
  fi
  statekit_query_call "$ROOT_CLIENT_SECRET" "$QUERY_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    query_result_matches affected:0 "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-create-table-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_insert() {
  local stdout_path="$WORK_DIR/query-insert.out" stderr_path="$WORK_DIR/query-insert.err"
  local sql="INSERT INTO \`$QUERY_TABLE\` (id, note) VALUES (1, 'line one'), (2, '$QUERY_EXPECTED_NOTE')" rc=0 ok=1
  if (( QUERY_DB_RESERVED != 1 || QUERY_DB_OWNED != 1 )); then
    set_note 'query-insert-ownership-required'
    return 1
  fi
  statekit_query_call "$ROOT_CLIENT_SECRET" "$QUERY_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    query_result_matches affected:2 "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-insert-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_file_query_select() {
  local stdout_path="$WORK_DIR/file-query-select.out" stderr_path="$WORK_DIR/file-query-select.err"
  local sql="SELECT id, note FROM \`$QUERY_DB\`.\`$QUERY_TABLE\` ORDER BY id" rc=0 ok=1
  if (( QUERY_DB_RESERVED != 1 || QUERY_DB_OWNED != 1 )); then
    set_note 'file-query-select-ownership-required'
    return 1
  fi
  statekit_file_query_call "$ROOT_CLIENT_SECRET" "$QUERY_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    file_query_result_matches select "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-select-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_file_query_select() {
  local stdout_path="$WORK_DIR/file-query-select-native.out" stderr_path="$WORK_DIR/file-query-select-native.err"
  local sql="SELECT id, note FROM \`$QUERY_DB\`.\`$QUERY_TABLE\` ORDER BY id" rc=0 value='' ok=1 expected_value
  expected_value=$'1\tline one\n2\t'"$QUERY_EXPECTED_NOTE"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == "$expected_value" ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-select-native-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_file_query_dml() {
  local stdout_path="$WORK_DIR/file-query-dml.out" stderr_path="$WORK_DIR/file-query-dml.err"
  local sql="INSERT INTO \`$QUERY_TABLE\` (id, note) VALUES (3, '$FILE_QUERY_DML_NOTE')" rc=0 ok=1
  if (( QUERY_DB_RESERVED != 1 || QUERY_DB_OWNED != 1 )); then
    set_note 'file-query-dml-ownership-required'
    return 1
  fi
  statekit_file_query_call "$ROOT_CLIENT_SECRET" "$QUERY_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    file_query_result_matches dml "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-dml-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_file_query_dml() {
  local stdout_path="$WORK_DIR/file-query-dml-native.out" stderr_path="$WORK_DIR/file-query-dml-native.err"
  local sql="SELECT id, note FROM \`$QUERY_DB\`.\`$QUERY_TABLE\` ORDER BY id" rc=0 value='' ok=1 expected_value
  expected_value=$'1\tline one\n2\t'"$QUERY_EXPECTED_NOTE"$'\n3\t'"$FILE_QUERY_DML_NOTE"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == "$expected_value" ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-dml-native-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

file_query_multiline_sql() {
  printf '%s\n' \
    '-- file query comment' \
    'SELECT id, note' \
    "FROM \`$QUERY_DB\`.\`$QUERY_TABLE\`" \
    'WHERE id = 1;' \
    '/* quoted semicolon */' \
    "SELECT '$QUERY_EXPECTED_NOTE' AS note"
}

check_statekit_file_query_multiline() {
  local stdout_path="$WORK_DIR/file-query-multiline.out" stderr_path="$WORK_DIR/file-query-multiline.err"
  local sql rc=0 ok=1
  sql=$(file_query_multiline_sql)
  statekit_file_query_call "$ROOT_CLIENT_SECRET" "$QUERY_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    file_query_result_matches multiline "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-multiline-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_file_query_multiline() {
  local stdout_path="$WORK_DIR/file-query-multiline-native.out" stderr_path="$WORK_DIR/file-query-multiline-native.err"
  local sql rc=0 value='' ok=1 expected_value
  sql=$(file_query_multiline_sql)
  expected_value=$'1\tline one\n'"$QUERY_EXPECTED_NOTE"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == "$expected_value" ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-multiline-native-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_file_query_invalid_path() {
  local stdout_path="$WORK_DIR/file-query-invalid-path.out" stderr_path="$WORK_DIR/file-query-invalid-path.err"
  local invalid_path=$'/tmp/statekit-file-query-\n-invalid.sql' rc=0 ok=1 sql='SELECT 1'
  statekit_file_query_call_path "$CLIENT_SECRET" "$SEED_DB" "$sql" "$invalid_path" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 1 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    [[ ! -s "$stdout_path" ]] && [[ "$(<"$stderr_path")" == "$STATEKIT_FILE_QUERY_INVALID_PATH_DIAGNOSTIC" ]] &&
    [[ "$(<"$stderr_path")" != *"$invalid_path"* ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-invalid-path-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_file_query_oversize() {
  local stdout_path="$WORK_DIR/file-query-oversize.out" stderr_path="$WORK_DIR/file-query-oversize.err"
  local sql rc=0 ok=1
  sql=$(python3 - "$MAX_COMMAND_INPUT_BYTES" <<'PY'
import sys
print("x" * (int(sys.argv[1]) + 1), end="")
PY
  ) || return 1
  statekit_file_query_call "$CLIENT_SECRET" "$SEED_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 1 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    [[ ! -s "$stdout_path" ]] && [[ "$(<"$stderr_path")" == 'statekit: runtime: file exceeds read limit' ]] &&
    value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-oversize-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_file_query_invalid_content() {
  local stdout_path="$WORK_DIR/file-query-invalid-content.out" stderr_path="$WORK_DIR/file-query-invalid-content.err"
  local rc=0 ok=1 sql="SELECT 'unterminated"
  statekit_file_query_call "$CLIENT_SECRET" "$SEED_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 1 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    [[ ! -s "$stdout_path" ]] && [[ "$(<"$stderr_path")" == "$STATEKIT_FILE_QUERY_CONTENT_DIAGNOSTIC" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'file-query-invalid-content-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_file_query_negative_false() {
  local label="$1" secret_name="$2" database="$3" host="$4" port="$5" sql="$6"
  local stdout_path="$WORK_DIR/file-query-negative-${label}.out" stderr_path="$WORK_DIR/file-query-negative-${label}.err"
  local rc=0 ok=1
  statekit_file_query_call_path "$secret_name" "$database" "$sql" "$FILE_QUERY_PATH" "$stdout_path" "$stderr_path" "$host" "$port" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    file_query_result_matches false "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note "file-query-negative-${label}-unexpected-result"
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_file_query_auth_negative() {
  check_statekit_file_query_negative_false auth "$BAD_CLIENT_SECRET" "$SEED_DB" "$DB_HOST" "$DB_PORT" 'SELECT 1'
}

check_statekit_file_query_connection_negative() {
  check_statekit_file_query_negative_false connection "$ROOT_CLIENT_SECRET" "$SEED_DB" "$DB_HOST" '1' 'SELECT 1'
}

check_native_query_dml_postcondition() {
  local stdout_path="$WORK_DIR/query-dml-postcondition.out" stderr_path="$WORK_DIR/query-dml-postcondition.err"
  local rc=0 value='' ok=1 expected_value
  expected_value=$'1\tline one\n2\t'"$QUERY_EXPECTED_NOTE"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT id, note FROM \`$QUERY_DB\`.\`$QUERY_TABLE\` ORDER BY id" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == "$expected_value" ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-dml-postcondition-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_multiline_quoted() {
  local stdout_path="$WORK_DIR/query-multiline-statekit.out" stderr_path="$WORK_DIR/query-multiline-statekit.err"
  local sql="/* stdin-only multiline query */"$'\n'"SELECT id, note"$'\n'"FROM \`$QUERY_DB\`.\`$QUERY_TABLE\`"$'\n'"WHERE note IN ('line one', '$QUERY_EXPECTED_NOTE')"$'\n'"ORDER BY id; -- trailing comment" rc=0 ok=1
  if (( QUERY_DB_RESERVED != 1 || QUERY_DB_OWNED != 1 )); then
    set_note 'query-multiline-ownership-required'
    return 1
  fi
  statekit_query_call "$ROOT_CLIENT_SECRET" "$QUERY_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    query_result_matches multiline "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-multiline-statekit-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_query_multiline_quoted() {
  local stdout_path="$WORK_DIR/query-multiline-native.out" stderr_path="$WORK_DIR/query-multiline-native.err"
  local rc=0 value='' ok=1 expected_value
  expected_value=$'1\tline one\n2\t'"$QUERY_EXPECTED_NOTE"
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT id, note FROM \`$QUERY_DB\`.\`$QUERY_TABLE\` WHERE note IN ('line one', '$QUERY_EXPECTED_NOTE') ORDER BY id; -- trailing comment" \
    "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$value" == "$expected_value" ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-multiline-native-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_drop_database() {
  local stdout_path="$WORK_DIR/query-drop-database.out" stderr_path="$WORK_DIR/query-drop-database.err"
  local sql="DROP DATABASE \`$QUERY_DB\`" rc=0 ok=1
  if (( QUERY_DB_RESERVED != 1 || QUERY_DB_OWNED != 1 )); then
    set_note 'query-drop-ownership-required'
    return 1
  fi
  statekit_query_call "$ROOT_CLIENT_SECRET" "$SEED_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    query_result_matches affected:0 "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-drop-database-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_query_database_removed() {
  local stdout_path="$WORK_DIR/query-after.out" stderr_path="$WORK_DIR/query-after.err"
  local presence=2 ok=1
  if query_database_presence "$stdout_path" "$stderr_path"; then
    presence=0
  else
    presence=$?
  fi
  if (( presence == 1 )); then
    ok=0
  else
    set_note 'query-database-removal-postcondition-failed'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_negative_false() {
  local label="$1" secret_name="$2" database="$3" host="$4" port="$5" sql="$6"
  local stdout_path="$WORK_DIR/query-negative-${label}.out" stderr_path="$WORK_DIR/query-negative-${label}.err"
  local rc=0 ok=1
  statekit_call "$secret_name" 'mysql.query' "$(query_extra_json "$database" "$sql")" "$host" "$port" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    query_result_matches false "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note "query-negative-${label}-unexpected-result"
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_invalid_database() {
  check_statekit_query_negative_false invalid-database "$CLIENT_SECRET" "${QUERY_DB}_missing" "$DB_HOST" "$DB_PORT" 'SELECT 1'
}

check_statekit_query_auth_negative() {
  check_statekit_query_negative_false auth "$BAD_CLIENT_SECRET" "$SEED_DB" "$DB_HOST" "$DB_PORT" 'SELECT 1'
}

check_statekit_query_connection_negative() {
  check_statekit_query_negative_false connection "$ROOT_CLIENT_SECRET" "$SEED_DB" "$DB_HOST" '1' 'SELECT 1'
}

check_statekit_query_timeout() {
  local stdout_path="$WORK_DIR/query-negative-timeout.out" stderr_path="$WORK_DIR/query-negative-timeout.err"
  local sql='SELECT SLEEP(31)' rc=0 ok=1
  statekit_query_call "$CLIENT_SECRET" "$SEED_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if statekit_query_expected_failure timeout "$rc" "$stdout_path" "$stderr_path" &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-negative-timeout-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_oversize() {
  local stdout_path="$WORK_DIR/query-negative-oversize.out" stderr_path="$WORK_DIR/query-negative-oversize.err"
  local oversized rc=0 ok=1
  oversized=$(python3 -c 'import sys; sys.stdout.write("x" * (1024 * 1024 + 1))') || return 1
  statekit_query_call "$CLIENT_SECRET" "$SEED_DB" "$oversized" "$stdout_path" "$stderr_path" || rc=$?
  if statekit_query_expected_failure input-limit "$rc" "$stdout_path" "$stderr_path" &&
    query_files_are_value_free "$oversized" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-negative-oversize-unexpected-result'
  fi
  unset oversized
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_query_diagnostic() {
  local stdout_path="$WORK_DIR/query-negative-diagnostic-statekit.out" stderr_path="$WORK_DIR/query-negative-diagnostic-statekit.err"
  local sql='THIS IS NOT VALID SQL' rc=0 ok=1
  statekit_query_call "$ROOT_CLIENT_SECRET" "$SEED_DB" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && query_result_matches false "$stdout_path" && [[ ! -s "$stderr_path" ]] &&
    query_files_are_value_free "$sql" "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-negative-diagnostic-statekit-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_query_diagnostic() {
  local stdout_path="$WORK_DIR/query-negative-diagnostic-native.out" stderr_path="$WORK_DIR/query-negative-diagnostic-native.err"
  local sql='THIS IS NOT VALID SQL' rc=0 ok=1 classification=''
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" "$sql" "$stdout_path" "$stderr_path" || rc=$?
  classification=$(native_query_diagnostic_classification "$LAST_CLIENT_CLASS" "$rc" "$stdout_path" "$stderr_path")
  if [[ "$classification" == 'syntax-error' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'query-negative-diagnostic-native-unexpected-classification'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_lifecycle_absent() {
  local stdout_path="$WORK_DIR/lifecycle-before.out" stderr_path="$WORK_DIR/lifecycle-before.err"
  local presence=2 ok=1
  LIFECYCLE_DB_RESERVED=0
  if [[ ! "$LIFECYCLE_DB" =~ ^statekit_r93j_[[:alnum:]_-]+$ ]]; then
    set_note 'lifecycle-database-name-invalid'
  else
    if lifecycle_database_presence "$stdout_path" "$stderr_path"; then
      presence=0
    else
      presence=$?
    fi
    if (( presence == 1 )); then
      # This is the reservation boundary.  No lifecycle mutation may be
      # dispatched unless this exact absence read completed successfully.
      LIFECYCLE_DB_RESERVED=1
      ok=0
    elif (( presence == 0 )); then
      set_note 'lifecycle-database-not-absent'
    else
      set_note 'lifecycle-absence-check-uncertain'
    fi
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_db_create() {
  local stdout_path="$WORK_DIR/db-create.out" stderr_path="$WORK_DIR/db-create.err"
  local rc=0 value='' ok=1
  local extra_json=",\"name\":\"$LIFECYCLE_DB\",\"character_set\":\"utf8mb4\",\"collate\":\"utf8mb4_0900_ai_ci\""
  lifecycle_mutation_precheck || return 1
  # Take ownership before dispatch.  A timeout or interrupted client can
  # leave CREATE applied even when no successful result reaches this shell.
  LIFECYCLE_DB_OWNED=1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.db_create' "$extra_json" "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == 'true' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    reconcile_ambiguous_lifecycle_create || true
    case "$LAST_CLIENT_CLASS" in
      setup) set_note 'lifecycle-create-setup-failed' ;;
      timeout) set_note 'lifecycle-create-timeout' ;;
      cleanup) set_note 'lifecycle-create-cleanup-failed' ;;
      runtime) set_note 'lifecycle-create-runtime-failed' ;;
      exited) set_note 'lifecycle-create-rejected-or-unexpected-result' ;;
      *) set_note 'lifecycle-create-execution-incomplete' ;;
    esac
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_db_create_repeat() {
  local stdout_path="$WORK_DIR/db-create-repeat.out" stderr_path="$WORK_DIR/db-create-repeat.err"
  local rc=0 value='' ok=1
  local extra_json=",\"name\":\"$LIFECYCLE_DB\",\"character_set\":\"utf8mb4\",\"collate\":\"utf8mb4_0900_ai_ci\""
  lifecycle_mutation_precheck || return 1
  LIFECYCLE_DB_OWNED=1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.db_create' "$extra_json" "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == 'false' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    reconcile_ambiguous_lifecycle_create || true
    set_note 'lifecycle-create-repeat-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_lifecycle_present() {
  local stdout_path="$WORK_DIR/lifecycle-present.out" stderr_path="$WORK_DIR/lifecycle-present.err"
  local presence=2 ok=1
  if lifecycle_database_presence "$stdout_path" "$stderr_path"; then
    presence=0
  else
    presence=$?
  fi
  if (( presence == 0 )); then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_db_remove() {
  local stdout_path="$WORK_DIR/db-remove.out" stderr_path="$WORK_DIR/db-remove.err"
  local rc=0 value='' ok=1
  lifecycle_mutation_precheck || return 1
  if (( LIFECYCLE_DB_OWNED != 1 )); then
    set_note 'lifecycle-remove-requires-owned-database'
    return 1
  fi
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.db_remove' \
    ",\"name\":\"$LIFECYCLE_DB\"" "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == 'true' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'lifecycle-remove-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_lifecycle_removed() {
  local stdout_path="$WORK_DIR/lifecycle-removed.out" stderr_path="$WORK_DIR/lifecycle-removed.err"
  local presence=2 ok=1
  if lifecycle_database_presence "$stdout_path" "$stderr_path"; then
    presence=0
  else
    presence=$?
  fi
  if (( presence == 1 )); then
    ok=0
    # Keep ownership until cleanup has issued and verified its final DROP.
    # This also gates the later negative remove call without losing cleanup
    # responsibility after an ambiguous earlier mutation.
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

alter_mutation_precheck() {
  if (( ALTER_DB_RESERVED != 1 )); then
    set_note 'alter-absence-reservation-required'
    return 1
  fi
  if [[ -z "$WORK_DIR" || -z "$ROOT_CLIENT_SECRET" || -z "$DB_HOST" ||
    ! "$ALTER_DB" =~ ^statekit_r93l_[[:alnum:]_-]+$ ]]; then
    set_note 'alter-mutation-precheck-failed'
    return 1
  fi
  return 0
}

check_native_alter_absent() {
  local stdout_path="$WORK_DIR/alter-before.out" stderr_path="$WORK_DIR/alter-before.err"
  local presence=2 ok=1
  ALTER_DB_RESERVED=0
  ALTER_DB_OWNED=0
  if [[ ! "$ALTER_DB" =~ ^statekit_r93l_[[:alnum:]_-]+$ ]]; then
    set_note 'alter-database-name-invalid'
  else
    if alter_database_presence "$stdout_path" "$stderr_path"; then
      presence=0
    else
      presence=$?
    fi
    if (( presence == 1 )); then
      # This reservation is the cleanup/mutation ownership boundary. Nothing
      # is created until this exact native absence read succeeds.
      ALTER_DB_RESERVED=1
      ok=0
    elif (( presence == 0 )); then
      set_note 'alter-database-not-absent'
    else
      set_note 'alter-absence-check-uncertain'
    fi
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_alter_create_seed() {
  local stdout_path="$WORK_DIR/alter-create.out" stderr_path="$WORK_DIR/alter-create.err"
  local verify_stdout="$WORK_DIR/alter-seed-verify.out" verify_stderr="$WORK_DIR/alter-seed-verify.err"
  local rc=0 verify_rc=0 value='' verify_value='' ok=1
  alter_mutation_precheck || return 1
  # Reserve cleanup responsibility before dispatch because a client timeout
  # can occur after CREATE DATABASE/seed statements have committed.
  ALTER_DB_OWNED=1
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "CREATE DATABASE \`$ALTER_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci; CREATE TABLE \`$ALTER_DB\`.\`$ALTER_TABLE\` (id INT PRIMARY KEY, note VARCHAR(32) NOT NULL); INSERT INTO \`$ALTER_DB\`.\`$ALTER_TABLE\` (id, note) VALUES (1, 'seeded')" \
    "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT COUNT(*) FROM \`$ALTER_DB\`.\`$ALTER_TABLE\` WHERE id = 1 AND note = 'seeded'" \
    "$verify_stdout" "$verify_stderr" || verify_rc=$?
  [[ -f "$verify_stdout" ]] && verify_value=$(<"$verify_stdout")
  if (( rc == 0 && verify_rc == 0 )) && [[ -z "$value" && "$verify_value" == '1' ]] &&
    value_free_files "$stdout_path" "$stderr_path" "$verify_stdout" "$verify_stderr"; then
    ok=0
  else
    set_note 'alter-create-or-seed-failed'
  fi
  rm -f "$stdout_path" "$stderr_path" "$verify_stdout" "$verify_stderr"
  return "$ok"
}

native_alter_defaults_match() {
  local expected_charset="$1" expected_collate="$2" stdout_path="$3" stderr_path="$4"
  local rc=0 value
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '$ALTER_DB'" \
    "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  [[ "$rc" == '0' && "$value" == "${expected_charset}"$'\t'"${expected_collate}" ]] &&
    value_free_files "$stdout_path" "$stderr_path"
}

native_alter_transition_supported() {
  local stdout_path="$1" stderr_path="$2" rc=0 value
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT CHARACTER_SET_NAME, DEFAULT_COLLATE_NAME FROM information_schema.CHARACTER_SETS WHERE CHARACTER_SET_NAME = 'latin1'" \
    "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  [[ "$rc" == '0' && "$value" == $'latin1\tlatin1_swedish_ci' ]] &&
    value_free_files "$stdout_path" "$stderr_path"
}

native_alter_seed_present() {
  local stdout_path="$1" stderr_path="$2" rc=0 value
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "SELECT COUNT(*) FROM \`$ALTER_DB\`.\`$ALTER_TABLE\` WHERE id = 1 AND note = 'seeded'" \
    "$stdout_path" "$stderr_path" || rc=$?
  value=$(<"$stdout_path")
  [[ "$rc" == '0' && "$value" == '1' ]] && value_free_files "$stdout_path" "$stderr_path"
}

check_native_alter_defaults_before() {
  local stdout_path="$WORK_DIR/alter-defaults-before.out" stderr_path="$WORK_DIR/alter-defaults-before.err"
  local transition_stdout="$WORK_DIR/alter-transition-supported.out" transition_stderr="$WORK_DIR/alter-transition-supported.err" ok=1
  alter_mutation_precheck || return 1
  if native_alter_transition_supported "$transition_stdout" "$transition_stderr" &&
    native_alter_defaults_match utf8mb4 utf8mb4_0900_ai_ci "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'alter-charset-transition-unsupported'
  fi
  rm -f "$stdout_path" "$stderr_path" "$transition_stdout" "$transition_stderr"
  return "$ok"
}

check_statekit_alter_explicit() {
  local stdout_path="$WORK_DIR/alter-explicit.out" stderr_path="$WORK_DIR/alter-explicit.err"
  local rc=0 value='' ok=1
  alter_mutation_precheck || return 1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.alter_db' \
    ",\"name\":\"$ALTER_DB\",\"character_set\":\"latin1\",\"collate\":\"latin1_swedish_ci\"" \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == 'true' ]] &&
    value_free_files "$stdout_path" "$stderr_path"; then
    local seed_stdout="$WORK_DIR/alter-explicit-seed.out" seed_stderr="$WORK_DIR/alter-explicit-seed.err"
    if native_alter_seed_present "$seed_stdout" "$seed_stderr"; then
      ok=0
    else
      set_note 'alter-explicit-seed-not-preserved'
    fi
    rm -f "$seed_stdout" "$seed_stderr"
  else
    set_note 'alter-explicit-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_alter_explicit_readback() {
  local stdout_path="$WORK_DIR/alter-explicit-native.out" stderr_path="$WORK_DIR/alter-explicit-native.err"
  local seed_stdout="$WORK_DIR/alter-explicit-native-seed.out" seed_stderr="$WORK_DIR/alter-explicit-native-seed.err" ok=1
  alter_mutation_precheck || return 1
  if native_alter_defaults_match latin1 latin1_swedish_ci "$stdout_path" "$stderr_path" &&
    native_alter_seed_present "$seed_stdout" "$seed_stderr"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path" "$seed_stdout" "$seed_stderr"
  return "$ok"
}

statekit_alter_db_get_matches() {
  local expected_charset="$1" expected_collate="$2" stdout_path="$3" stderr_path="$4"
  local rc=0
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.db_get' ",\"name\":\"$ALTER_DB\"" \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc != 0 )) || ! value_free_files "$stdout_path" "$stderr_path"; then
    return 1
  fi
  python3 -c 'import json, sys
data = json.load(sys.stdin)
raise SystemExit(0 if data == {"character_set": sys.argv[1], "collate": sys.argv[2]} else 1)' \
    "$expected_charset" "$expected_collate" <"$stdout_path" >/dev/null 2>&1
}

check_statekit_alter_explicit_readback() {
  local stdout_path="$WORK_DIR/alter-explicit-statekit.out" stderr_path="$WORK_DIR/alter-explicit-statekit.err" ok=1
  alter_mutation_precheck || return 1
  if statekit_alter_db_get_matches latin1 latin1_swedish_ci "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_alter_default_preservation() {
  local stdout_path="$WORK_DIR/alter-default-preserve.out" stderr_path="$WORK_DIR/alter-default-preserve.err"
  local rc=0 value='' ok=1
  alter_mutation_precheck || return 1
  # The explicit empty character_set exercises Salt's truthiness fallback;
  # db_get must supply latin1 while the requested collation changes.
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.alter_db' \
    ",\"name\":\"$ALTER_DB\",\"character_set\":\"\",\"collate\":\"latin1_general_ci\"" \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == 'true' ]] &&
    value_free_files "$stdout_path" "$stderr_path"; then
    local seed_stdout="$WORK_DIR/alter-default-seed.out" seed_stderr="$WORK_DIR/alter-default-seed.err"
    if native_alter_seed_present "$seed_stdout" "$seed_stderr"; then
      ok=0
    else
      set_note 'alter-default-seed-not-preserved'
    fi
    rm -f "$seed_stdout" "$seed_stderr"
  else
    set_note 'alter-default-preservation-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_alter_default_preserved_readback() {
  local stdout_path="$WORK_DIR/alter-default-native.out" stderr_path="$WORK_DIR/alter-default-native.err"
  local seed_stdout="$WORK_DIR/alter-default-native-seed.out" seed_stderr="$WORK_DIR/alter-default-native-seed.err" ok=1
  alter_mutation_precheck || return 1
  if native_alter_defaults_match latin1 latin1_general_ci "$stdout_path" "$stderr_path" &&
    native_alter_seed_present "$seed_stdout" "$seed_stderr"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path" "$seed_stdout" "$seed_stderr"
  return "$ok"
}

check_statekit_alter_default_preserved_readback() {
  local stdout_path="$WORK_DIR/alter-default-statekit.out" stderr_path="$WORK_DIR/alter-default-statekit.err" ok=1
  alter_mutation_precheck || return 1
  if statekit_alter_db_get_matches latin1 latin1_general_ci "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_alter_auth_negative() {
  local stdout_path="$WORK_DIR/alter-auth-negative.out" stderr_path="$WORK_DIR/alter-auth-negative.err"
  local rc=0 value='' ok=1
  alter_mutation_precheck || return 1
  statekit_call "$BAD_CLIENT_SECRET" 'mysql.alter_db' \
    ",\"name\":\"$ALTER_DB\",\"character_set\":\"utf8mb4\",\"collate\":\"utf8mb4_general_ci\"" \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == '[]' ]] &&
    value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_alter_connection_negative() {
  local stdout_path="$WORK_DIR/alter-connection-negative.out" stderr_path="$WORK_DIR/alter-connection-negative.err"
  local rc=0 value='' ok=1
  alter_mutation_precheck || return 1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.alter_db' \
    ",\"name\":\"$ALTER_DB\",\"character_set\":\"utf8mb4\",\"collate\":\"utf8mb4_general_ci\"" \
    "$DB_HOST" '1' "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == '[]' ]] &&
    value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_alter_invalid_identifier() {
  local stdout_path="$WORK_DIR/alter-invalid-identifier.out" stderr_path="$WORK_DIR/alter-invalid-identifier.err"
  local rc=0 ok=1
  alter_mutation_precheck || return 1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.alter_db' ',"name":"bad\nname"' \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 1 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    [[ ! -s "$stdout_path" ]] && grep -F -q -- "$STATEKIT_INVALID_IDENTIFIER_CATEGORY" "$stderr_path" 2>/dev/null &&
    grep -F -q -- "$STATEKIT_INVALID_IDENTIFIER_DIAGNOSTIC" "$stderr_path" 2>/dev/null &&
    value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'alter-invalid-identifier-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_alter_invalid_option() {
  local stdout_path="$WORK_DIR/alter-invalid-option.out" stderr_path="$WORK_DIR/alter-invalid-option.err"
  local rc=0 ok=1
  alter_mutation_precheck || return 1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.alter_db' \
    ",\"name\":\"$ALTER_DB\",\"character_set\":\"utf8;DROP\",\"collate\":\"utf8mb4_general_ci\"" \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 1 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    [[ ! -s "$stdout_path" ]] && grep -F -q -- "$STATEKIT_INVALID_OPTION_DIAGNOSTIC" "$stderr_path" 2>/dev/null &&
    ! grep -F -q -- 'utf8;DROP' "$stderr_path" 2>/dev/null && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    set_note 'alter-invalid-option-unexpected-result'
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_processlist() {
  local stdout_path="$WORK_DIR/processlist-statekit.out" stderr_path="$WORK_DIR/processlist-statekit.err"
  local rc=0 ok=1 classification='invalid-execution'
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.processlist' '' "$DB_HOST" "$DB_PORT" \
    "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    classification=$(status_json_classification processlist "$stdout_path") || classification='invalid-json'
    if [[ "$classification" == 'available' ]] && write_status_classification processlist "$classification"; then
      ok=0
    fi
  fi
  if (( ok != 0 )); then
    write_status_classification processlist "$classification" || true
    set_note "processlist-statekit-${classification}"
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_processlist() {
  local stdout_path="$WORK_DIR/processlist-native.out" stderr_path="$WORK_DIR/processlist-native.err"
  local rc=0 ok=1 native_classification='invalid-execution' statekit_classification='missing'
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    'SHOW FULL PROCESSLIST' "$stdout_path" "$stderr_path" || rc=$?
  native_classification=$(native_status_classification processlist "$LAST_CLIENT_CLASS" "$rc" \
    "$stdout_path" "$stderr_path") || native_classification='classification-failure'
  statekit_classification=$(read_status_classification processlist 2>/dev/null || printf '%s' 'missing')
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    [[ "$native_classification" == 'available' ]] && [[ ! -s "$stderr_path" ]] &&
    value_free_files "$stdout_path" "$stderr_path" &&
    python3 -c 'import sys
lines = [line.rstrip("\r") for line in open(sys.argv[1], encoding="utf-8") if line.rstrip("\r")]
ok = bool(lines)
for line in lines:
    fields = line.split("\t")
    if len(fields) < 8 or not fields[0].isdigit() or not fields[5].isdigit():
        ok = False
        break
raise SystemExit(0 if ok else 1)' "$stdout_path" &&
    status_observation_correlates processlist "$statekit_classification" "$native_classification"; then
    ok=0
  else
    if ! status_observation_correlates processlist "$statekit_classification" "$native_classification"; then
      set_note 'processlist-classification-mismatch'
    else
      set_note 'processlist-native-unexpected-result'
    fi
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_status_unsupported() {
  local function_name="$1" kind="$2" label="$3"
  local stdout_path="$WORK_DIR/${label}-statekit.out" stderr_path="$WORK_DIR/${label}-statekit.err"
  local rc=0 ok=1 classification='invalid-execution' expected_class='compatibility-empty-list'
  if [[ "$kind" == 'slave_lag' ]]; then
    expected_class='compatibility-query-failure'
  fi
  statekit_call "$ROOT_CLIENT_SECRET" "$function_name" '' "$DB_HOST" "$DB_PORT" \
    "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    classification=$(status_json_classification "$kind" "$stdout_path") || classification='invalid-json'
    if [[ "$classification" == "$expected_class" ]] && write_status_classification "$label" "$classification"; then
      ok=0
    fi
  fi
  if (( ok != 0 )); then
    write_status_classification "$label" "$classification" || true
    set_note "${label}-statekit-${classification}"
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_native_status_unsupported() {
  local sql="$1" kind="$2" label="$3"
  local stdout_path="$WORK_DIR/${label}-native.out" stderr_path="$WORK_DIR/${label}-native.err"
  local rc=0 ok=1 native_classification='invalid-execution' statekit_classification='missing'
  native_mysql_as_user root "$ROOT_CLIENT_SECRET" "$DB_HOST" "$DB_PORT" \
    "$sql" "$stdout_path" "$stderr_path" || rc=$?
  native_classification=$(native_status_classification "$kind" "$LAST_CLIENT_CLASS" "$rc" \
    "$stdout_path" "$stderr_path") || native_classification='classification-failure'
  statekit_classification=$(read_status_classification "$label" 2>/dev/null || printf '%s' 'missing')
  if [[ "$native_classification" == 'unsupported-sql' ]] &&
    [[ ! -s "$stdout_path" ]] && value_free_files "$stdout_path" "$stderr_path" &&
    status_observation_correlates "$kind" "$statekit_classification" "$native_classification"; then
    ok=0
  else
    if ! status_observation_correlates "$kind" "$statekit_classification" "$native_classification"; then
      set_note "${label}-classification-mismatch"
    else
      set_note "${label}-native-${native_classification}"
    fi
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_status_negative() {
  local function_name="$1" kind="$2" expected_native_class="$3"
  local secret_name="$4" port="$5" label="$6"
  local stdout_path="$WORK_DIR/${label}.out" stderr_path="$WORK_DIR/${label}.err"
  local native_stdout_path="$WORK_DIR/${label}-native.out" native_stderr_path="$WORK_DIR/${label}-native.err"
  local rc=0 native_rc=0 value='' ok=1 statekit_classification='invalid-execution' native_classification='invalid-execution'
  local expected_value='[]' expected_class='compatibility-empty-list'
  if [[ "$kind" == 'slave_lag' ]]; then
    expected_value='-3'
    expected_class='compatibility-query-failure'
  fi
  statekit_call "$secret_name" "$function_name" '' "$DB_HOST" "$port" \
    "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' ]] &&
    [[ "$value" == "$expected_value" ]] && [[ ! -s "$stderr_path" ]] && value_free_files "$stdout_path" "$stderr_path"; then
    statekit_classification="$expected_class"
    native_mysql_as_user root "$secret_name" "$DB_HOST" "$port" "$(status_sql "$kind")" \
      "$native_stdout_path" "$native_stderr_path" || native_rc=$?
    native_classification=$(native_status_classification "$kind" "$LAST_CLIENT_CLASS" "$native_rc" \
      "$native_stdout_path" "$native_stderr_path") || native_classification='classification-failure'
    if status_negative_correlates "$statekit_classification" "$native_classification" "$expected_native_class" "$kind" &&
      value_free_files "$native_stdout_path" "$native_stderr_path"; then
      ok=0
    else
      set_note "${label}-classification-mismatch"
    fi
  else
    set_note "${label}-unexpected-result"
  fi
  rm -f "$stdout_path" "$stderr_path" "$native_stdout_path" "$native_stderr_path"
  return "$ok"
}

check_statekit_invalid_identifier_negative() {
  local stdout_path="$WORK_DIR/db-invalid-identifier.out" stderr_path="$WORK_DIR/db-invalid-identifier.err"
  local rc=0 ok=1
  lifecycle_mutation_precheck || return 1
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.db_create' ',"name":"bad\nname"' \
    "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  if (( rc == 1 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '1' ]] &&
    [[ ! -s "$stdout_path" ]] &&
    grep -F -q -- "$STATEKIT_INVALID_IDENTIFIER_CATEGORY" "$stderr_path" 2>/dev/null &&
    grep -F -q -- "$STATEKIT_INVALID_IDENTIFIER_DIAGNOSTIC" "$stderr_path" 2>/dev/null &&
    value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  else
    case "$LAST_CLIENT_CLASS" in
      setup) set_note 'invalid-identifier-setup-failed' ;;
      timeout) set_note 'invalid-identifier-timeout' ;;
      cleanup) set_note 'invalid-identifier-cleanup-failed' ;;
      runtime) set_note 'invalid-identifier-runtime-failed' ;;
      exited) set_note 'invalid-identifier-unexpected-rejection' ;;
      *) set_note 'invalid-identifier-execution-incomplete' ;;
    esac
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_lifecycle_auth_negative() {
  local stdout_path="$WORK_DIR/db-auth-negative.out" stderr_path="$WORK_DIR/db-auth-negative.err"
  local rc=0 value='' ok=1
  lifecycle_mutation_precheck || return 1
  LIFECYCLE_DB_OWNED=1
  statekit_call "$BAD_CLIENT_SECRET" 'mysql.db_create' \
    ",\"name\":\"$LIFECYCLE_DB\"" "$DB_HOST" "$DB_PORT" "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == 'false' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

check_statekit_lifecycle_connection_negative() {
  local stdout_path="$WORK_DIR/db-connection-negative.out" stderr_path="$WORK_DIR/db-connection-negative.err"
  local rc=0 value='' ok=1
  lifecycle_mutation_precheck || return 1
  if (( LIFECYCLE_DB_OWNED != 1 )); then
    set_note 'lifecycle-negative-remove-requires-owned-database'
    return 1
  fi
  statekit_call "$ROOT_CLIENT_SECRET" 'mysql.db_remove' \
    ",\"name\":\"$LIFECYCLE_DB\"" "$DB_HOST" '1' "$stdout_path" "$stderr_path" || rc=$?
  [[ -f "$stdout_path" ]] && value=$(<"$stdout_path")
  if (( rc == 0 )) && [[ "$LAST_CLIENT_CLASS" == 'exited' && "$LAST_CLIENT_EXIT_RC" == '0' && "$value" == 'false' ]] && value_free_files "$stdout_path" "$stderr_path"; then
    ok=0
  fi
  rm -f "$stdout_path" "$stderr_path"
  return "$ok"
}

main() {
  if ! prepare_report; then
    return 1
  fi
  if [[ "$STATEKIT_BIN" != /* ]]; then
    STATEKIT_BIN="$PWD/$STATEKIT_BIN"
  fi
  if [[ ! -x "$STATEKIT_BIN" ]]; then
    set_note 'production-statekit-binary-missing'
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_failed
    return 1
  fi
  if ! command -v timeout >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    set_note 'required-local-tool-missing'
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_failed
    return 1
  fi
  if ! select_runtime || ! runtime_preflight; then
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_failed
    return 1
  fi
  if ! WORK_DIR=$(mktemp -d); then
    set_note 'temporary-work-directory-create-failed'
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_failed
    return 1
  fi
  if ! generate_resource_nonce; then
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_failed
    return 1
  fi
  DB_CONTAINER="statekit-e51-mysql-$RESOURCE_NONCE"
  DB_HOST="$DB_CONTAINER"
  LIFECYCLE_DB="statekit_r93j_$RESOURCE_NONCE"
  QUERY_DB="statekit_r93p_$RESOURCE_NONCE"
  ALTER_DB="statekit_r93l_$RESOURCE_NONCE"
  PLUGIN_DEFAULT_FAILURE="statekit_r93o_default_$RESOURCE_NONCE"
  PLUGIN_CUSTOM_FAILURE="statekit_r93o_custom_$RESOURCE_NONCE"
  if ! pull_and_verify_image || ! build_client_image || ! create_private_network ||
    ! generate_credentials || ! create_runtime_secrets; then
    set_note 'runtime-or-resource-setup-failed'
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_failed
    return 1
  fi
  if ! reserve_container_name "$DB_CONTAINER"; then
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_failed
    return 1
  fi
  DB_RESERVED=1
  if ! start_mysql; then
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_failed
    return 1
  fi

  run_case 'mysql-readiness-authenticated-select-1' check_readiness
  if (( PASSED != 1 )); then
    mark_remaining_failed
    return 1
  fi
  run_case 'mysql-version-live' check_statekit_version
  run_case 'mysql-db-list-seeded' check_statekit_db_list
  run_case 'mysql-db-exists-seeded' check_statekit_db_exists true ",\"name\":\"$SEED_DB\"" seeded
  run_case 'mysql-db-exists-absent' check_statekit_db_exists false ',"name":"statekit_e51_missing"' absent
  run_case 'mysql-plugins-list-installed' check_statekit_plugins_list
  run_case 'mysql-plugin-status-installed' check_statekit_plugin_status "$INSTALLED_PLUGIN" ACTIVE installed
  run_case 'mysql-plugin-status-absent' check_statekit_plugin_status "$ABSENT_PLUGIN" '' absent
  run_case 'mysql-auth-negative-native-client' check_native_auth_negative
  run_case 'mysql-auth-negative-statekit' check_statekit_auth_negative
  run_case 'mysql-connection-negative-native-client' check_native_connection_negative
  run_case 'mysql-connection-negative-statekit' check_statekit_connection_negative
  run_case 'mysql-db-native-postcondition' check_native_positive
  run_case 'mysql-plugin-native-postcondition' check_native_plugin
  run_case 'mysql-db-lifecycle-native-absent-before-create' check_native_lifecycle_absent
  run_case 'mysql-db-create-success' check_statekit_db_create
  run_case 'mysql-db-create-repeat-false' check_statekit_db_create_repeat
  run_case 'mysql-db-native-created-postcondition' check_native_lifecycle_present
  run_case 'mysql-db-remove-success' check_statekit_db_remove
  run_case 'mysql-db-native-removed-postcondition' check_native_lifecycle_removed
  run_case 'mysql-db-negative-invalid-identifier' check_statekit_invalid_identifier_negative
  run_case 'mysql-db-negative-auth' check_statekit_lifecycle_auth_negative
  run_case 'mysql-db-negative-connection' check_statekit_lifecycle_connection_negative
  run_case 'mysql-alter-db-native-absent-before-create' check_native_alter_absent
  run_case 'mysql-alter-db-create-and-seed' check_native_alter_create_seed
  run_case 'mysql-alter-db-native-defaults-before' check_native_alter_defaults_before
  run_case 'mysql-alter-db-statekit-explicit' check_statekit_alter_explicit
  run_case 'mysql-alter-db-native-explicit-readback' check_native_alter_explicit_readback
  run_case 'mysql-alter-db-statekit-explicit-readback' check_statekit_alter_explicit_readback
  run_case 'mysql-alter-db-statekit-default-preservation' check_statekit_alter_default_preservation
  run_case 'mysql-alter-db-native-default-preserved-readback' check_native_alter_default_preserved_readback
  run_case 'mysql-alter-db-statekit-default-preserved-readback' check_statekit_alter_default_preserved_readback
  run_case 'mysql-alter-db-negative-auth' check_statekit_alter_auth_negative
  run_case 'mysql-alter-db-negative-connection' check_statekit_alter_connection_negative
  run_case 'mysql-alter-db-negative-invalid-identifier' check_statekit_alter_invalid_identifier
  run_case 'mysql-alter-db-negative-invalid-option' check_statekit_alter_invalid_option
  run_case 'mysql-processlist-statekit' check_statekit_processlist
  run_case 'mysql-processlist-native-observation' check_native_processlist
  run_case 'mysql-processlist-negative-auth' check_statekit_status_negative 'mysql.processlist' processlist auth-failure "$BAD_CLIENT_SECRET" "$DB_PORT" processlist-negative-auth
  run_case 'mysql-processlist-negative-connection' check_statekit_status_negative 'mysql.processlist' processlist connection-failure "$ROOT_CLIENT_SECRET" '1' processlist-negative-connection
  run_case 'mysql-get-master-status-statekit' check_statekit_status_unsupported 'mysql.get_master_status' master get-master-status
  run_case 'mysql-get-master-status-native-observation' check_native_status_unsupported 'SHOW MASTER STATUS' master get-master-status
  run_case 'mysql-get-master-status-negative-auth' check_statekit_status_negative 'mysql.get_master_status' master auth-failure "$BAD_CLIENT_SECRET" "$DB_PORT" get-master-status-negative-auth
  run_case 'mysql-get-master-status-negative-connection' check_statekit_status_negative 'mysql.get_master_status' master connection-failure "$ROOT_CLIENT_SECRET" '1' get-master-status-negative-connection
  run_case 'mysql-get-slave-status-statekit' check_statekit_status_unsupported 'mysql.get_slave_status' slave get-slave-status
  run_case 'mysql-get-slave-status-native-observation' check_native_status_unsupported 'SHOW SLAVE STATUS' slave get-slave-status
  run_case 'mysql-get-slave-status-negative-auth' check_statekit_status_negative 'mysql.get_slave_status' slave auth-failure "$BAD_CLIENT_SECRET" "$DB_PORT" get-slave-status-negative-auth
  run_case 'mysql-get-slave-status-negative-connection' check_statekit_status_negative 'mysql.get_slave_status' slave connection-failure "$ROOT_CLIENT_SECRET" '1' get-slave-status-negative-connection
  run_case 'mysql-slave-lag-statekit' check_statekit_status_unsupported 'mysql.slave_lag' slave_lag slave-lag
  run_case 'mysql-slave-lag-native-observation' check_native_status_unsupported 'SHOW SLAVE STATUS' slave_lag slave-lag
  run_case 'mysql-slave-lag-negative-auth' check_statekit_status_negative 'mysql.slave_lag' slave_lag auth-failure "$BAD_CLIENT_SECRET" "$DB_PORT" slave-lag-negative-auth
  run_case 'mysql-slave-lag-negative-connection' check_statekit_status_negative 'mysql.slave_lag' slave_lag connection-failure "$ROOT_CLIENT_SECRET" '1' slave-lag-negative-connection
  run_case 'mysql-plugin-add-installed-idempotent' check_statekit_plugin_add "$INSTALLED_PLUGIN" '' true plugin-add-installed
  run_case 'mysql-plugin-add-installed-native-status' check_native_plugin_status "$INSTALLED_PLUGIN" ACTIVE installed-after-add
  run_case 'mysql-plugin-status-case-sensitive' check_statekit_plugin_status 'CACHING_SHA2_PASSWORD' '' case-sensitive
  run_case 'mysql-plugin-remove-absent-idempotent' check_statekit_plugin_remove "$ABSENT_PLUGIN" true remove-absent
  run_case 'mysql-plugin-remove-absent-native-status' check_native_plugin_status "$ABSENT_PLUGIN" '' absent-after-remove
  run_case 'mysql-plugin-add-default-soname-failure' check_statekit_plugin_add "$PLUGIN_DEFAULT_FAILURE" '' false add-default-failure
  run_case 'mysql-plugin-add-default-soname-native-failure' check_native_plugin_install_failure "$PLUGIN_DEFAULT_FAILURE" "$PLUGIN_DEFAULT_FAILURE.so" add-default-failure
  run_case 'mysql-plugin-add-custom-soname-failure' check_statekit_plugin_add "$PLUGIN_CUSTOM_FAILURE" "$PLUGIN_CUSTOM_FAILURE.so" false add-custom-failure
  run_case 'mysql-plugin-add-custom-soname-native-failure' check_native_plugin_install_failure "$PLUGIN_CUSTOM_FAILURE" "$PLUGIN_CUSTOM_FAILURE.so" add-custom-failure
  run_case 'mysql-plugin-add-invalid-name' check_statekit_plugin_invalid_name
  run_case 'mysql-plugin-add-invalid-soname' check_statekit_plugin_invalid_soname
  run_case 'mysql-plugin-add-negative-auth' check_statekit_plugin_add "$PLUGIN_DEFAULT_FAILURE" '' false add-auth-failure "$BAD_CLIENT_SECRET"
  run_case 'mysql-plugin-remove-negative-connection' check_statekit_plugin_remove "$ABSENT_PLUGIN" false remove-connection "$ROOT_CLIENT_SECRET" '1'

  if [[ "${MYSQL_QUERY_LIVE_ENABLED:-0}" != '1' ]]; then
    set_note 'query-live-control-not-enabled'
    local query_case
    # Keep the ordered 96-case report total and make the control decision
    # visible as failures rather than silently converting unexecuted cases to
    # skips.  No query is dispatched without the explicit live opt-in.
    for query_case in "${CASE_IDS[@]}"; do
      if [[ "$query_case" == mysql-query-* || "$query_case" == mysql-file-query-* ]]; then
        record_case "$query_case" fail
      fi
    done
    EXECUTION_COMPLETE=1
    return 1
  fi
  run_case 'mysql-query-select-scalar-statekit' check_statekit_query_scalar
  run_case 'mysql-query-select-scalar-native-observation' check_native_query_scalar
  run_case 'mysql-query-select-table-statekit' check_statekit_query_table
  run_case 'mysql-query-select-table-native-observation' check_native_query_table
  run_case 'mysql-query-database-native-absent-before-create' check_native_query_database_absent
  run_case 'mysql-query-create-database' check_statekit_query_create_database
  run_case 'mysql-query-create-table' check_statekit_query_create_table
  run_case 'mysql-query-insert-dml' check_statekit_query_insert
  run_case 'mysql-query-dml-native-postcondition' check_native_query_dml_postcondition
  run_case 'mysql-file-query-select-statekit' check_statekit_file_query_select
  run_case 'mysql-file-query-select-native-observation' check_native_file_query_select
  run_case 'mysql-file-query-dml-statekit' check_statekit_file_query_dml
  run_case 'mysql-file-query-dml-native-postcondition' check_native_file_query_dml
  run_case 'mysql-file-query-multiline-quoted-statekit' check_statekit_file_query_multiline
  run_case 'mysql-file-query-multiline-quoted-native-observation' check_native_file_query_multiline
  run_case 'mysql-file-query-negative-invalid-path' check_statekit_file_query_invalid_path
  run_case 'mysql-file-query-negative-oversize' check_statekit_file_query_oversize
  run_case 'mysql-file-query-negative-invalid-content' check_statekit_file_query_invalid_content
  run_case 'mysql-file-query-negative-auth' check_statekit_file_query_auth_negative
  run_case 'mysql-file-query-negative-connection' check_statekit_file_query_connection_negative
  run_case 'mysql-query-multiline-quoted-statekit' check_statekit_query_multiline_quoted
  run_case 'mysql-query-multiline-quoted-native-observation' check_native_query_multiline_quoted
  run_case 'mysql-query-drop-database' check_statekit_query_drop_database
  run_case 'mysql-query-database-native-removed-postcondition' check_native_query_database_removed
  run_case 'mysql-query-negative-invalid-database' check_statekit_query_invalid_database
  run_case 'mysql-query-negative-auth' check_statekit_query_auth_negative
  run_case 'mysql-query-negative-connection' check_statekit_query_connection_negative
  run_case 'mysql-query-negative-timeout' check_statekit_query_timeout
  run_case 'mysql-query-negative-oversize' check_statekit_query_oversize
  run_case 'mysql-query-negative-diagnostic-statekit' check_statekit_query_diagnostic
  run_case 'mysql-query-negative-diagnostic-native-classification' check_native_query_diagnostic

  EXECUTION_COMPLETE=1
  if ! case_results_are_exact || (( CASE_RESULT_INTEGRITY_FAILED != 0 || PASSED != ${#CASE_IDS[@]} || FAILED != 0 || SKIPPED != 0 )); then
    set_note 'one-or-more-live-cases-failed-or-were-skipped'
    return 1
  fi
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" && "$PREFLIGHT_ONLY" == 1 ]]; then
  if ! select_runtime || ! runtime_preflight; then
    exit 1
  fi
  exit 0
fi

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
